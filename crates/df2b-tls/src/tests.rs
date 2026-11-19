use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, ServerConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{TlsAcceptor, TlsConnector};

use crate::pki::{cert_from_pem, cert_to_pem, key_from_pem};
use crate::transport::{client_config, enrollment_client_config, server_config};
use crate::*;

fn controller(ca: &Ca) -> Arc<ServerConfig> {
    let (chain, key) = ca.issue_server(&["localhost".into()]).unwrap();
    server_config(ca.cert_der(), chain, key).unwrap()
}

fn agent(ca: &Ca, id: &str) -> Arc<ClientConfig> {
    let k = AgentKey::generate("host").unwrap();
    let cert = ca
        .sign_agent_csr(&k.csr_der, id, Duration::from_secs(3600))
        .unwrap();
    client_config(ca.cert_der(), cert, key_from_pem(&k.key_pem).unwrap()).unwrap()
}

/// One TLS session; returns the client's CN as seen by the server
/// (`Some("")` = no client certificate), or the client-side error.
async fn handshake(
    server: Arc<ServerConfig>,
    client: Arc<ClientConfig>,
) -> Result<Option<String>, String> {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let srv = tokio::spawn(async move {
        let (tcp, _) = l.accept().await.unwrap();
        let mut tls = TlsAcceptor::from(server).accept(tcp).await.ok()?;
        let cn = tls
            .get_ref()
            .1
            .peer_certificates()
            .and_then(|c| c.first())
            .map(|c| CertInfo::parse(c).unwrap().common_name)
            .unwrap_or_default();
        let mut b = [0u8; 4];
        tls.read_exact(&mut b).await.ok()?;
        tls.write_all(b"pong").await.ok()?;
        Some(cn)
    });
    let tcp = TcpStream::connect(addr).await.unwrap();
    let name = ServerName::try_from(SERVER_NAME).unwrap();
    let res = async {
        let mut tls = TlsConnector::from(client)
            .connect(name, tcp)
            .await
            .map_err(|e| e.to_string())?;
        tls.write_all(b"ping").await.map_err(|e| e.to_string())?;
        let mut b = [0u8; 4];
        tls.read_exact(&mut b).await.map_err(|e| e.to_string())?;
        Ok::<_, String>(())
    }
    .await;
    let cn = srv.await.unwrap();
    res.map(|()| cn)
}

#[test]
fn ca_survives_pem_roundtrip() {
    let ca = Ca::generate("test CA").unwrap();
    let again = Ca::from_pem(ca.cert_pem(), &ca.key_pem()).unwrap();
    assert_eq!(ca.fingerprint(), again.fingerprint());
    assert_eq!(
        cert_from_pem(&cert_to_pem(ca.cert_der())).unwrap(),
        *ca.cert_der()
    );
}

#[test]
fn agent_csr_subject_is_overridden() {
    let ca = Ca::generate("test CA").unwrap();
    let k = AgentKey::generate("evil-controller").unwrap();
    let cert = ca
        .sign_agent_csr(&k.csr_der, "web-01-abc", Duration::from_secs(600))
        .unwrap();
    let info = CertInfo::parse(&cert).unwrap();
    assert_eq!(info.common_name, "web-01-abc");
    assert!(info.not_after - info.not_before <= chrono::Duration::seconds(600 + 3600));
    assert!(ca
        .sign_agent_csr(b"garbage", "x", Duration::from_secs(1))
        .is_err());
}

#[tokio::test]
async fn enrollment_pins_the_ca() {
    let ca = Ca::generate("test CA").unwrap();
    // reloaded CA (as after a controller restart) must chain to the original
    let ca = Ca::from_pem(ca.cert_pem(), &ca.key_pem()).unwrap();
    let ok = enrollment_client_config(ca.fingerprint()).unwrap();
    assert_eq!(
        handshake(controller(&ca), ok).await,
        Ok(Some(String::new()))
    );

    let other = Ca::generate("attacker CA").unwrap();
    let pinned_to_other = enrollment_client_config(other.fingerprint()).unwrap();
    let err = handshake(controller(&ca), pinned_to_other)
        .await
        .unwrap_err();
    assert!(err.contains("does not match the enrollment token"), "{err}");

    // an attacker that presents the real CA cert but signs with its own key
    let (mut chain, key) = other.issue_server(&[]).unwrap();
    chain[1] = ca.cert_der().clone();
    let fake = server_config(other.cert_der(), chain, key).unwrap();
    let ok = enrollment_client_config(ca.fingerprint()).unwrap();
    assert!(handshake(fake, ok).await.is_err());
}

#[tokio::test]
async fn mutual_tls_identifies_the_agent() {
    let ca = Ca::generate("test CA").unwrap();
    assert_eq!(
        handshake(controller(&ca), agent(&ca, "web-01-abc")).await,
        Ok(Some("web-01-abc".into()))
    );

    // agent certificate from a foreign CA: rejected by the controller
    let other = Ca::generate("other CA").unwrap();
    let k = AgentKey::generate("h").unwrap();
    let cert = other
        .sign_agent_csr(&k.csr_der, "intruder", Duration::from_secs(600))
        .unwrap();
    let client = client_config(ca.cert_der(), cert, key_from_pem(&k.key_pem).unwrap()).unwrap();
    assert!(handshake(controller(&ca), client).await.is_err());

    // controller with a certificate from a foreign CA: rejected by the agent
    assert!(handshake(controller(&other), agent(&ca, "web-01"))
        .await
        .is_err());
}

#[test]
fn agent_certificate_cannot_serve_as_controller() {
    let ca = Ca::generate("test CA").unwrap();
    let k = AgentKey::generate("h").unwrap();
    let cert: CertificateDer<'static> = ca
        .sign_agent_csr(&k.csr_der, SERVER_NAME, Duration::from_secs(600))
        .unwrap();
    let srv = server_config(
        ca.cert_der(),
        vec![cert, ca.cert_der().clone()],
        key_from_pem(&k.key_pem).unwrap(),
    )
    .unwrap();
    let rt = tokio::runtime::Runtime::new().unwrap();
    let res = rt.block_on(handshake(srv, agent(&ca, "a")));
    assert!(
        res.is_err(),
        "clientAuth-only certificate accepted as server"
    );
}
