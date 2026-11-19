//! `AgentService` over mutual TLS.
//!
//! The agent identity is taken from the verified client certificate (CN),
//! never from message fields. `Enroll` is the only RPC that accepts a
//! connection without client certificate; it is authenticated by the token.

// tonic::Status is large; boxing it would only fight the framework
#![allow(clippy::result_large_err)]

use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use df2b_core::{AgentId, DecisionKind, Origin, Scope};
use df2b_proto::from_unix_ms;
use df2b_proto::v1::agent_service_server::AgentService;
use df2b_proto::v1::{self, decision_event::Event};
use df2b_tls::{CertInfo, EnrollToken};
use ipnet::IpNet;
use tokio::sync::{broadcast, mpsc};
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status};
use tracing::{info, warn};

use crate::files;
use crate::state::{applies, AuthError, Controller, Initial, NewDecision, Propagate};
use crate::store::AgentRecord;

/// Maximum observations per Report call.
const MAX_REPORT: usize = 10_000;
/// How often open streams re-check revocation.
const REVOCATION_CHECK: Duration = Duration::from_secs(5);

pub struct Service {
    ctl: Arc<Controller>,
}

impl Service {
    pub fn new(ctl: Arc<Controller>) -> Self {
        Self { ctl }
    }

    fn auth<T>(&self, req: &Request<T>) -> Result<(AgentRecord, CertInfo), Status> {
        let certs = req.peer_certs();
        let cert = certs.as_ref().and_then(|c| c.first());
        let record = self
            .ctl
            .authenticate(cert.map(|c| c.as_ref()))
            .map_err(|e| match e {
                AuthError::NoCertificate => Status::unauthenticated(e.to_string()),
                _ => Status::permission_denied(e.to_string()),
            })?;
        let info = CertInfo::parse(cert.expect("authenticated")).map_err(internal)?;
        Ok((record, info))
    }
}

fn internal(e: impl std::fmt::Display) -> Status {
    tracing::error!(error = %e, "internal error");
    Status::internal("internal error")
}

fn invalid_token() -> Status {
    // one message for unknown, used, expired and foreign tokens
    Status::permission_denied("invalid or expired enrollment token")
}

/// Agents report /32 and /64 keys by default; anything much broader from a
/// single agent is suspicious (DESIGN.md §4.5).
fn too_broad(net: &IpNet) -> bool {
    match net {
        IpNet::V4(n) => n.prefix_len() < 24,
        IpNet::V6(n) => n.prefix_len() < 48,
    }
}

fn event(e: Event) -> v1::DecisionEvent {
    v1::DecisionEvent { event: Some(e) }
}

#[tonic::async_trait]
impl AgentService for Service {
    async fn enroll(
        &self,
        req: Request<v1::EnrollRequest>,
    ) -> Result<Response<v1::EnrollResponse>, Status> {
        let peer = req.remote_addr();
        let r = req.into_inner();
        let token: EnrollToken = r.token.parse().map_err(|_| invalid_token())?;
        if token.ca_fingerprint != self.ctl.ca.fingerprint() {
            return Err(invalid_token());
        }
        let ctl = self.ctl.clone();
        let resp = tokio::task::spawn_blocking(move || {
            let id = files::new_agent_id(&r.hostname);
            // check the CSR before using up the token
            let cert = ctl
                .ca
                .sign_agent_csr(&r.csr_der, &id, ctl.settings.cert_lifetime)
                .map_err(|e| Status::invalid_argument(format!("{e:#}")))?;
            let token_file = files::redeem_token(&ctl.settings.state_dir, &token)
                .map_err(internal)?
                .ok_or_else(invalid_token)?;
            let info = CertInfo::parse(&cert).map_err(internal)?;
            ctl.put_agent(AgentRecord {
                id: id.clone(),
                hostname: r.hostname.chars().take(255).collect(),
                group: token_file.group.clone(),
                enrolled_at: Utc::now(),
                serials: vec![info.serial],
                cert_not_after: info.not_after,
            })
            .map_err(internal)?;
            info!(agent = %id, group = %token_file.group, ?peer, version = %r.agent_version, "agent enrolled");
            ctl.audit(
                &format!("agent:{id}"),
                peer.map(|p| p.to_string()),
                "agent.enroll",
                serde_json::json!({ "group": token_file.group, "hostname": r.hostname }),
            )
            .map_err(internal)?;
            Ok::<_, Status>(v1::EnrollResponse {
                agent_id: id,
                certificate_der: cert.to_vec(),
                ca_certificate_der: ctl.ca.cert_der().to_vec(),
                group: token_file.group,
            })
        })
        .await
        .map_err(internal)??;
        Ok(Response::new(resp))
    }

    async fn renew(
        &self,
        req: Request<v1::RenewRequest>,
    ) -> Result<Response<v1::RenewResponse>, Status> {
        let (mut record, used) = self.auth(&req)?;
        let csr = req.into_inner().csr_der;
        let ctl = self.ctl.clone();
        let resp = tokio::task::spawn_blocking(move || {
            let cert = ctl
                .ca
                .sign_agent_csr(&csr, &record.id, ctl.settings.cert_lifetime)
                .map_err(|e| Status::invalid_argument(format!("{e:#}")))?;
            let info = CertInfo::parse(&cert).map_err(internal)?;
            // new certificate + the one used for this call (in case the
            // response is lost); anything older is no longer accepted
            record.serials = vec![info.serial, used.serial];
            record.cert_not_after = info.not_after;
            let id = record.id.clone();
            ctl.put_agent(record).map_err(internal)?;
            info!(agent = %id, not_after = %info.not_after, "agent certificate renewed");
            Ok::<_, Status>(v1::RenewResponse {
                certificate_der: cert.to_vec(),
                ca_certificate_der: ctl.ca.cert_der().to_vec(),
            })
        })
        .await
        .map_err(internal)??;
        Ok(Response::new(resp))
    }

    async fn heartbeat(
        &self,
        req: Request<v1::HeartbeatRequest>,
    ) -> Result<Response<v1::HeartbeatResponse>, Status> {
        let (record, _) = self.auth(&req)?;
        let h = req.into_inner();
        let now_ms = Utc::now().timestamp_millis();
        self.ctl.update_status(&record.id, |s| {
            s.agent_version = h.agent_version;
            s.active_bans = h.active_bans;
            s.clock_skew_ms = now_ms - h.agent_time_unix_ms;
            s.firewall_backend = h.firewall_backend;
            s.firewall_healthy = h.firewall_healthy;
            s.last_applied_seq = h.last_applied_seq;
        });
        Ok(Response::new(v1::HeartbeatResponse {
            controller_time_unix_ms: now_ms,
            groups: vec![record.group],
        }))
    }

    async fn report(
        &self,
        req: Request<v1::ObservationBatch>,
    ) -> Result<Response<v1::ReportAck>, Status> {
        let (record, _) = self.auth(&req)?;
        let batch = req.into_inner().observations;
        if batch.len() > MAX_REPORT {
            return Err(Status::invalid_argument(format!(
                "at most {MAX_REPORT} observations per report"
            )));
        }
        self.ctl.update_status(&record.id, |_| {});
        let now = Utc::now();
        let scope = match self.ctl.settings.propagate {
            Propagate::Global => Some(Scope::Global),
            Propagate::Group => Some(Scope::Group(record.group.clone())),
            Propagate::Off => None,
        };
        let mut new = Vec::new();
        // TODO: aggregate non-ban observations for correlation (§4.2)
        for o in batch.iter().filter(|o| o.locally_banned) {
            let Some(scope) = scope.clone() else { break };
            let Ok(net) = o.key.parse::<IpNet>().map(|n| n.trunc()) else {
                warn!(agent = %record.id, key = %o.key, "ignoring malformed key");
                continue;
            };
            if too_broad(&net) {
                warn!(agent = %record.id, %net, "ignoring overly broad ban");
                continue;
            }
            if self.ctl.settings.allowlist.overlaps(&net) {
                warn!(agent = %record.id, %net, "ignoring ban overlapping the allowlist");
                continue;
            }
            let expires_at = from_unix_ms(o.local_ban_expires_unix_ms);
            if expires_at.is_some_and(|e| e <= now) {
                continue;
            }
            new.push(NewDecision {
                kind: DecisionKind::Ban,
                target: net,
                scope,
                jail: (!o.jail.is_empty()).then(|| o.jail.clone()),
                expires_at,
                origin: Origin::Agent(AgentId(record.id.clone())),
                reason: format!("local ban on {}: {} failures", record.id, o.count),
            });
        }
        let accepted = batch.len() as u32;
        if !new.is_empty() {
            let ctl = self.ctl.clone();
            let appended = tokio::task::spawn_blocking(move || ctl.append(new))
                .await
                .map_err(internal)?
                .map_err(internal)?;
            for d in &appended {
                info!(seq = d.seq, target = %d.target, agent = %record.id, scope = ?d.scope, "decision: ban");
            }
        }
        Ok(Response::new(v1::ReportAck {
            accepted,
            retry_after_ms: 0,
        }))
    }

    type SubscribeStream = ReceiverStream<Result<v1::DecisionEvent, Status>>;

    async fn subscribe(
        &self,
        req: Request<v1::SubscribeRequest>,
    ) -> Result<Response<Self::SubscribeStream>, Status> {
        let (record, _) = self.auth(&req)?;
        let from_seq = req.into_inner().from_seq;
        let ctl = self.ctl.clone();
        let (initial, mut live) = {
            let ctl = ctl.clone();
            let record = record.clone();
            tokio::task::spawn_blocking(move || ctl.subscribe(from_seq, &record))
                .await
                .map_err(internal)?
                .map_err(internal)?
        };
        let (tx, rx) = mpsc::channel(256);
        tokio::spawn(async move {
            let id = record.id.clone();
            ctl.update_status(&id, |s| s.streams += 1);
            info!(agent = %id, from_seq, "agent connected");
            let last = match initial {
                Initial::Snapshot { seq, active } => {
                    let snap = v1::Snapshot {
                        seq,
                        active: active.iter().map(Into::into).collect(),
                    };
                    let _ = tx.send(Ok(event(Event::Snapshot(snap)))).await;
                    seq
                }
                Initial::Backlog { seq, decisions } => {
                    for d in &decisions {
                        if tx.send(Ok(event(Event::Decision(d.into())))).await.is_err() {
                            break;
                        }
                    }
                    seq
                }
            };
            let mut check = tokio::time::interval(REVOCATION_CHECK);
            loop {
                tokio::select! {
                    ev = live.recv() => match ev {
                        Ok(d) => {
                            if d.seq <= last || !applies(&d, &record) {
                                continue;
                            }
                            if tx.send(Ok(event(Event::Decision((&*d).into())))).await.is_err() {
                                break;
                            }
                        }
                        Err(broadcast::error::RecvError::Lagged(n)) => {
                            warn!(agent = %id, missed = n, "subscriber lagged, closing stream");
                            let _ = tx.send(Err(Status::aborted("stream lagged; resubscribe"))).await;
                            break;
                        }
                        Err(broadcast::error::RecvError::Closed) => break,
                    },
                    _ = check.tick() => {
                        if ctl.is_revoked(&id) {
                            warn!(agent = %id, "agent revoked, closing stream");
                            let _ = tx.send(Err(Status::permission_denied("agent revoked"))).await;
                            break;
                        }
                    }
                    _ = tx.closed() => break,
                }
            }
            ctl.update_status(&id, |s| s.streams = s.streams.saturating_sub(1));
            info!(agent = %id, "agent disconnected");
        });
        Ok(Response::new(ReceiverStream::new(rx)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::Settings;
    use crate::store::Store;
    use df2b_core::Allowlist;
    use df2b_proto::v1::agent_service_client::AgentServiceClient;
    use df2b_proto::v1::agent_service_server::AgentServiceServer;
    use df2b_tls::pki::key_from_pem;
    use df2b_tls::{transport, AgentKey, ClientConfig};
    use tonic::transport::Channel;
    use tonic::Code;

    async fn start(dir: &std::path::Path) -> (String, Arc<Controller>) {
        let ca = files::load_or_create_ca(dir).unwrap();
        let settings = Settings {
            state_dir: dir.to_owned(),
            cert_lifetime: Duration::from_secs(3600),
            propagate: Propagate::Global,
            allowlist: Allowlist::new(["10.0.0.0/8".parse().unwrap()]),
            oidc: None,
            https_internal_ca: true,
        };
        let ctl = Arc::new(Controller::open(settings, ca, Store::open(dir).unwrap()).unwrap());
        let (chain, key) = ctl.ca.issue_server(&[]).unwrap();
        let tls = transport::server_config(ctl.ca.cert_der(), chain, key).unwrap();
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap().to_string();
        tokio::spawn(
            tonic::transport::Server::builder()
                .add_service(AgentServiceServer::new(Service::new(ctl.clone())))
                .serve_with_incoming(transport::incoming(l, tls)),
        );
        (addr, ctl)
    }

    async fn client(addr: &str, cfg: Arc<ClientConfig>) -> AgentServiceClient<Channel> {
        AgentServiceClient::new(transport::connect(addr.into(), cfg).await.unwrap())
    }

    fn agent_cfg(ctl: &Controller, cert: Vec<u8>, key: &AgentKey) -> Arc<ClientConfig> {
        transport::client_config(
            ctl.ca.cert_der(),
            cert.into(),
            key_from_pem(&key.key_pem).unwrap(),
        )
        .unwrap()
    }

    fn obs(key: &str, banned: bool) -> v1::Observation {
        v1::Observation {
            key: key.into(),
            jail: "sshd".into(),
            count: 5,
            locally_banned: banned,
            local_ban_expires_unix_ms: (Utc::now() + chrono::Duration::hours(1)).timestamp_millis(),
            ..Default::default()
        }
    }

    fn heartbeat() -> v1::HeartbeatRequest {
        v1::HeartbeatRequest {
            agent_time_unix_ms: Utc::now().timestamp_millis(),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn enrollment_authentication_renewal_revocation() {
        let dir = std::env::temp_dir().join(format!("df2b-ctl-grpc-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let (addr, ctl) = start(&dir).await;
        let token = files::create_token(&dir, "web", Duration::from_secs(3600)).unwrap();

        // enroll over a connection pinned to the CA, without client cert
        let pinned = transport::enrollment_client_config(token.ca_fingerprint).unwrap();
        let mut anon = client(&addr, pinned).await;
        let k1 = AgentKey::generate("host-a").unwrap();
        let req = |csr: Vec<u8>| v1::EnrollRequest {
            token: token.to_string(),
            hostname: "host-a".into(),
            csr_der: csr,
            agent_version: "test".into(),
        };
        let resp = anon
            .enroll(req(k1.csr_der.clone()))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(resp.group, "web");
        assert!(resp.agent_id.starts_with("host-a-"));
        let id = resp.agent_id;

        // without client certificate nothing but Enroll works
        let err = anon.heartbeat(heartbeat()).await.unwrap_err();
        assert_eq!(err.code(), Code::Unauthenticated);
        let err = anon
            .subscribe(v1::SubscribeRequest::default())
            .await
            .unwrap_err();
        assert_eq!(err.code(), Code::Unauthenticated);
        // tokens are one-time
        let err = anon.enroll(req(k1.csr_der.clone())).await.unwrap_err();
        assert_eq!(err.code(), Code::PermissionDenied);

        // mutual TLS: identity from the certificate
        let cfg1 = agent_cfg(&ctl, resp.certificate_der, &k1);
        let mut a = client(&addr, cfg1.clone()).await;
        let hb = a.heartbeat(heartbeat()).await.unwrap().into_inner();
        assert_eq!(hb.groups, vec!["web".to_string()]);

        let mut stream = a
            .subscribe(v1::SubscribeRequest { from_seq: 0 })
            .await
            .unwrap()
            .into_inner();
        let Some(Event::Snapshot(s)) = stream.message().await.unwrap().unwrap().event else {
            panic!("expected snapshot first")
        };
        assert!(s.active.is_empty());

        // local ban → decision; allowlisted, too broad and non-ban ignored
        let ack = a
            .report(v1::ObservationBatch {
                observations: vec![
                    obs("203.0.113.9/32", true),
                    obs("10.1.2.3/32", true),
                    obs("198.51.0.0/16", true),
                    obs("192.0.2.1/32", false),
                ],
            })
            .await
            .unwrap()
            .into_inner();
        assert_eq!(ack.accepted, 4);
        let Some(Event::Decision(d)) = stream.message().await.unwrap().unwrap().event else {
            panic!("expected decision")
        };
        assert_eq!(
            (d.target.as_str(), d.origin.as_str(), d.seq),
            ("203.0.113.9/32", format!("agent:{id}").as_str(), 1)
        );
        assert_eq!(ctl.active_decisions().len(), 1);

        // renewal: the certificate used for the call stays valid ...
        let k2 = AgentKey::generate("host-a").unwrap();
        let r = a
            .renew(v1::RenewRequest {
                csr_der: k2.csr_der.clone(),
            })
            .await
            .unwrap()
            .into_inner();
        let cfg2 = agent_cfg(&ctl, r.certificate_der, &k2);
        a.heartbeat(heartbeat()).await.unwrap();
        let mut b = client(&addr, cfg2).await;
        b.heartbeat(heartbeat()).await.unwrap();
        // ... until the new one renews again: then the first is superseded
        let k3 = AgentKey::generate("host-a").unwrap();
        let r = b
            .renew(v1::RenewRequest {
                csr_der: k3.csr_der.clone(),
            })
            .await
            .unwrap()
            .into_inner();
        let cfg3 = agent_cfg(&ctl, r.certificate_der, &k3);
        let err = client(&addr, cfg1)
            .await
            .heartbeat(heartbeat())
            .await
            .unwrap_err();
        assert_eq!(err.code(), Code::PermissionDenied);
        let mut c = client(&addr, cfg3.clone()).await;
        c.heartbeat(heartbeat()).await.unwrap();

        // revocation: new calls refused, open streams closed
        files::revoke(&dir, &id).unwrap();
        let err = c.heartbeat(heartbeat()).await.unwrap_err();
        assert_eq!(err.code(), Code::PermissionDenied);
        let mut s3 = client(&addr, cfg3).await;
        assert!(s3.subscribe(v1::SubscribeRequest::default()).await.is_err());
        let closed = tokio::time::timeout(Duration::from_secs(10), stream.message())
            .await
            .expect("stream closed after revocation");
        assert_eq!(closed.unwrap_err().code(), Code::PermissionDenied);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
