//! Local control socket for `df2bctl --local` (DESIGN.md §8).
//!
//! A Unix socket (default `<state_dir>/agent.sock`, mode 0600), so there is
//! no network exposure; the peer's credentials (`SO_PEERCRED`) must also be
//! root or the agent's own user. One request per connection: a line of
//! JSON (`{"cmd":"status"}`), answered by one line
//! (`{"ok":true,"data":…}` or `{"ok":false,"error":"…"}`). Requests are
//! handled by the main loop, which owns the engine and the firewall.

use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::time::Duration;

use anyhow::{bail, Context};
use chrono::{DateTime, Utc};
use df2b_firewall::BanEntry;
use ipnet::IpNet;
use serde::Deserialize;
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, info, warn};

use crate::state::ManualBan;

const MAX_REQUEST: u64 = 64 * 1024;
const IO_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Deserialize, PartialEq)]
#[serde(tag = "cmd", rename_all = "snake_case", deny_unknown_fields)]
pub enum Request {
    Status,
    Jails,
    Bans,
    Ban {
        target: String,
        /// `None` = permanent.
        #[serde(default)]
        duration_secs: Option<u64>,
        #[serde(default)]
        reason: Option<String>,
    },
    Unban {
        target: String,
    },
}

pub struct Call {
    pub req: Request,
    /// "uid 0 (pid 123)"
    pub peer: String,
    pub reply: oneshot::Sender<Result<Value, String>>,
}

/// Removes the socket file when the agent stops.
pub struct Socket {
    path: PathBuf,
    pub calls: mpsc::Receiver<Call>,
}

impl Drop for Socket {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Binds the socket (replacing a stale one) and serves it.
pub fn spawn(path: &Path) -> anyhow::Result<Socket> {
    match std::fs::symlink_metadata(path) {
        Ok(m) if m.file_type().is_socket() => {
            std::fs::remove_file(path).with_context(|| format!("removing {}", path.display()))?
        }
        Ok(_) => bail!("{} exists and is not a socket", path.display()),
        Err(_) => {}
    }
    let listener =
        UnixListener::bind(path).with_context(|| format!("binding {}", path.display()))?;
    // a peer connecting before this is still checked by its credentials
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    let (tx, rx) = mpsc::channel(16);
    tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((stream, _)) => {
                    let tx = tx.clone();
                    tokio::spawn(async move {
                        if let Err(e) = serve(stream, tx).await {
                            debug!(error = %format!("{e:#}"), "control connection failed");
                        }
                    });
                }
                Err(e) => {
                    warn!(error = %e, "control socket accept failed");
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
            }
        }
    });
    info!(path = %path.display(), "control socket listening");
    Ok(Socket {
        path: path.to_owned(),
        calls: rx,
    })
}

async fn serve(stream: UnixStream, tx: mpsc::Sender<Call>) -> anyhow::Result<()> {
    let cred = stream.peer_cred()?;
    // SAFETY: plain syscall without arguments
    let own = unsafe { libc::geteuid() };
    let peer = match cred.pid() {
        Some(pid) => format!("uid {} (pid {pid})", cred.uid()),
        None => format!("uid {}", cred.uid()),
    };
    let (read, mut write) = stream.into_split();
    let answer = if cred.uid() != 0 && cred.uid() != own {
        warn!(%peer, "control socket: peer not allowed");
        Err("permission denied".to_owned())
    } else {
        let mut line = String::new();
        tokio::time::timeout(
            IO_TIMEOUT,
            BufReader::new(read.take(MAX_REQUEST)).read_line(&mut line),
        )
        .await
        .context("reading the request timed out")??;
        match serde_json::from_str::<Request>(&line) {
            Err(e) => Err(format!("bad request: {e}")),
            Ok(req) => {
                let (reply, rx) = oneshot::channel();
                tx.send(Call { req, peer, reply })
                    .await
                    .map_err(|_| anyhow::anyhow!("agent shutting down"))?;
                tokio::time::timeout(IO_TIMEOUT, rx)
                    .await
                    .map_err(|_| "the agent did not answer in time".to_owned())
                    .and_then(|r| r.map_err(|_| "agent shutting down".to_owned()))
                    .and_then(|r| r)
            }
        }
    };
    let out = match answer {
        Ok(data) => json!({ "ok": true, "data": data }),
        Err(error) => json!({ "ok": false, "error": error }),
    };
    let mut bytes = serde_json::to_vec(&out)?;
    bytes.push(b'\n');
    tokio::time::timeout(IO_TIMEOUT, write.write_all(&bytes)).await??;
    Ok(())
}

/// What the handlers work on (borrowed from the main loop).
pub struct Ctx<'a> {
    pub engine: &'a mut crate::engine::Engine,
    pub remote: &'a crate::remote::RemoteBans,
    pub backend: &'a std::sync::Arc<dyn df2b_firewall::FirewallBackend>,
    pub pending: &'a mut crate::state::Pending,
    pub state: &'a crate::state::State,
    pub stats: &'a crate::link::LinkStats,
    pub manual: &'a mut Vec<ManualBan>,
    pub controller: Option<&'a str>,
}

fn ms(t: Option<DateTime<Utc>>) -> Value {
    t.map_or(Value::Null, |t| json!(t.to_rfc3339()))
}

/// A manual ban must not be wider than this (as on the controller).
fn too_broad(net: &IpNet) -> bool {
    match net {
        IpNet::V4(n) => n.prefix_len() < 8,
        IpNet::V6(n) => n.prefix_len() < 16,
    }
}

fn parse_target(s: &str) -> Result<IpNet, String> {
    df2b_core::parse_target(s)
}

/// Runs a blocking firewall call.
async fn firewall<F>(
    backend: &std::sync::Arc<dyn df2b_firewall::FirewallBackend>,
    f: F,
) -> Result<(), String>
where
    F: FnOnce(&dyn df2b_firewall::FirewallBackend) -> anyhow::Result<()> + Send + 'static,
{
    let b = backend.clone();
    tokio::task::spawn_blocking(move || f(b.as_ref()))
        .await
        .map_err(|e| e.to_string())?
        .map_err(|e| format!("firewall: {e:#}"))
}

pub async fn handle(req: Request, peer: &str, cx: Ctx<'_>) -> Result<Value, String> {
    let now = Utc::now();
    match req {
        Request::Status => {
            let local = cx.engine.active_bans(now);
            let manual = cx
                .manual
                .iter()
                .filter(|m| m.until.map_or(true, |u| u > now))
                .count();
            let fw_error = cx.stats.firewall.error();
            Ok(json!({
                "version": env!("CARGO_PKG_VERSION"),
                "controller": cx.controller,
                "connected": cx.controller.is_some() && cx.stats.connected.load(Ordering::Relaxed),
                "firewall": {
                    "backend": cx.backend.name(),
                    "healthy": fw_error.is_none(),
                    "error": fw_error,
                },
                "bans": {
                    "local": local,
                    "manual": manual,
                    "controller": cx.remote.len(),
                },
                "jails": cx.engine.jail_count(),
                "sources": cx.stats.sources.peek().into_iter().map(|s| json!({
                    "name": s.name,
                    "lines_per_second": s.lines_per_second,
                    "lag_ms": s.lag_ms,
                    "backlog_bytes": s.backlog_bytes,
                    "error": s.error,
                })).collect::<Vec<_>>(),
            }))
        }
        Request::Jails => Ok(Value::Array(
            cx.engine
                .jail_status(now)
                .into_iter()
                .map(|j| {
                    json!({
                        "name": j.name,
                        "filter": j.filter,
                        "enabled": j.params.enabled,
                        "maxretry": j.params.maxretry,
                        "findtime_secs": j.params.findtime.as_secs(),
                        "bantime_secs": j.params.bantime.as_secs(),
                        "bantime_factor": j.params.factor,
                        "max_bantime_secs": j.params.max_bantime.map(|d| d.as_secs()),
                        "overridden": j.overridden,
                        "active_bans": j.active_bans,
                        "origin": j.origin,
                        "error": j.error,
                    })
                })
                .collect(),
        )),
        Request::Bans => {
            let mut rows = Vec::new();
            for (jail, key, offenses, until) in cx.engine.bans(now) {
                rows.push(json!({
                    "target": key.net().to_string(), "origin": format!("jail:{jail}"),
                    "expires_at": ms(Some(until)), "offenses": offenses,
                }));
            }
            for m in cx
                .manual
                .iter()
                .filter(|m| m.until.map_or(true, |u| u > now))
            {
                rows.push(json!({
                    "target": m.target.to_string(), "origin": "manual",
                    "expires_at": ms(m.until), "reason": m.reason, "by": m.by,
                }));
            }
            for (target, expires, own) in cx.remote.list(now) {
                rows.push(json!({
                    "target": target.to_string(),
                    "origin": if own { "controller (own report)" } else { "controller" },
                    "expires_at": ms(expires),
                }));
            }
            Ok(Value::Array(rows))
        }
        Request::Ban {
            target,
            duration_secs,
            reason,
        } => {
            let net = parse_target(&target)?;
            if too_broad(&net) {
                return Err(format!("{net} is too broad (at most /8 or /16)"));
            }
            if cx.engine.allowlisted(&net) {
                return Err(format!("{net} overlaps the allowlist"));
            }
            let duration = duration_secs.filter(|s| *s > 0).map(Duration::from_secs);
            let until = duration
                .map(|d| chrono::Duration::from_std(d).map(|d| now + d))
                .transpose()
                .map_err(|_| "duration too long".to_owned())?;
            let entry = BanEntry {
                net,
                timeout: duration,
            };
            firewall(cx.backend, move |b| b.ban(std::slice::from_ref(&entry))).await?;
            let ban = ManualBan {
                target: net,
                until,
                reason: reason
                    .unwrap_or_else(|| "manual".into())
                    .chars()
                    .take(256)
                    .collect(),
                created_at: now,
                by: peer.split(" (").next().unwrap_or(peer).to_owned(),
            };
            cx.manual.retain(|m| m.target != net);
            cx.manual.push(ban.clone());
            save(cx.state, cx.manual).await?;
            info!(target = %net, until = ?until, reason = %ban.reason, %peer, "manual local ban");
            Ok(json!({ "target": net.to_string(), "expires_at": ms(until) }))
        }
        Request::Unban { target } => {
            let net = parse_target(&target)?;
            let mut nets: Vec<IpNet> = Vec::new();
            for r in cx.engine.lift(&net, now) {
                info!(jail = %r.jail, target = %r.key, %peer, "local ban lifted (df2bctl --local)");
                nets.push(r.key.net());
                cx.pending.set_offender(r);
            }
            let before = cx.manual.len();
            cx.manual.retain(|m| {
                let hit = net.contains(&m.target) || m.target.contains(&net);
                if hit {
                    nets.push(m.target);
                }
                !hit
            });
            if cx.manual.len() != before {
                save(cx.state, cx.manual).await?;
            }
            nets.sort();
            nets.dedup();
            if nets.is_empty() {
                return Err(
                    if cx
                        .remote
                        .list(now)
                        .iter()
                        .any(|b| net.contains(&b.0) || b.0.contains(&net))
                    {
                        format!("{net} is banned by the controller: unban it there")
                    } else {
                        format!("no local ban overlaps {net}")
                    },
                );
            }
            let (kept, lift): (Vec<IpNet>, Vec<IpNet>) =
                nets.iter().partition(|n| cx.remote.covers(n));
            if !lift.is_empty() {
                let l = lift.clone();
                firewall(cx.backend, move |b| b.unban(&l)).await?;
            }
            info!(target = %net, lifted = lift.len(), %peer, "local unban");
            Ok(json!({
                "lifted": lift.iter().map(|n| n.to_string()).collect::<Vec<_>>(),
                "still_banned_by_controller": kept.iter().map(|n| n.to_string()).collect::<Vec<_>>(),
            }))
        }
    }
}

async fn save(state: &crate::state::State, manual: &[ManualBan]) -> Result<(), String> {
    let (st, m) = (state.clone(), manual.to_vec());
    tokio::task::spawn_blocking(move || st.save_manual_bans(&m))
        .await
        .map_err(|e| e.to_string())?
        .map_err(|e| format!("saving: {e:#}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requests() {
        let p = |s: &str| serde_json::from_str::<Request>(s);
        assert_eq!(p(r#"{"cmd":"status"}"#).unwrap(), Request::Status);
        assert_eq!(
            p(r#"{"cmd":"ban","target":"192.0.2.1","duration_secs":60}"#).unwrap(),
            Request::Ban {
                target: "192.0.2.1".into(),
                duration_secs: Some(60),
                reason: None
            }
        );
        assert!(p(r#"{"cmd":"ban"}"#).is_err(), "target required");
        assert!(
            p(r#"{"cmd":"unban","target":"192.0.2.1","x":1}"#).is_err(),
            "unknown fields"
        );
        assert!(p(r#"{"cmd":"reload"}"#).is_err());
    }

    #[tokio::test]
    async fn round_trip() {
        let dir = std::env::temp_dir().join(format!("df2b-ctl-sock-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("agent.sock");
        // a stale socket from an earlier run is replaced
        drop(std::os::unix::net::UnixListener::bind(&path).unwrap());
        let mut sock = spawn(&path).unwrap();
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        tokio::spawn(async move {
            while let Some(c) = sock.calls.recv().await {
                let r = match c.req {
                    Request::Status => Ok(json!({ "peer": c.peer })),
                    _ => Err("nope".to_owned()),
                };
                let _ = c.reply.send(r);
            }
        });
        let ask = |req: &'static str| {
            let path = path.clone();
            async move {
                let mut s = UnixStream::connect(&path).await.unwrap();
                s.write_all(req.as_bytes()).await.unwrap();
                let mut out = String::new();
                s.read_to_string(&mut out).await.unwrap();
                serde_json::from_str::<Value>(&out).unwrap()
            }
        };
        let r = ask("{\"cmd\":\"status\"}\n").await;
        assert_eq!(r["ok"], true);
        assert!(r["data"]["peer"].as_str().unwrap().starts_with("uid "));
        let r = ask("{\"cmd\":\"jails\"}\n").await;
        assert_eq!(
            (r["ok"].clone(), r["error"].clone()),
            (json!(false), json!("nope"))
        );
        let r = ask("not json\n").await;
        assert!(r["error"].as_str().unwrap().starts_with("bad request"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn refuses_to_replace_a_regular_file() {
        let dir = std::env::temp_dir().join(format!("df2b-ctl-file-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("agent.sock");
        std::fs::write(&path, "x").unwrap();
        let rt = tokio::runtime::Runtime::new().unwrap();
        let _g = rt.enter();
        assert!(spawn(&path).is_err());
        assert!(path.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
