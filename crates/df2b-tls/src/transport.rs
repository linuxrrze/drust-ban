//! TLS 1.3 configurations and the tonic plumbing for agent <-> controller.
//!
//! The TLS layer is done here with tokio-rustls instead of tonic's built-in
//! TLS options, because we need things tonic does not expose: TLS 1.3 only,
//! optional client certificates (Enroll runs before the agent has one) and a
//! verifier that pins the CA fingerprint from the enrollment token.

use std::io;
use std::sync::Arc;
use std::time::Duration;

use hyper_util::rt::TokioIo;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::WebPkiServerVerifier;
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::server::WebPkiClientVerifier;
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, ServerConfig, SignatureScheme};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::server::TlsStream;
use tokio_rustls::{TlsAcceptor, TlsConnector};
use tokio_stream::wrappers::ReceiverStream;
use tonic::transport::{Channel, Endpoint, Uri};
use tracing::debug;

use crate::{hex, pki, SERVER_NAME};

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const ALPN_H2: &[u8] = b"h2";

fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

fn roots(ca: &CertificateDer<'static>) -> anyhow::Result<Arc<RootCertStore>> {
    let mut roots = RootCertStore::empty();
    roots.add(ca.clone())?;
    Ok(Arc::new(roots))
}

/// Controller side: TLS 1.3, server chain `[server, ca]`. Client certificates
/// are verified against the CA when presented, but optional at the TLS
/// layer: every RPC except `Enroll` rejects requests without one.
pub fn server_config(
    ca: &CertificateDer<'static>,
    chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> anyhow::Result<Arc<ServerConfig>> {
    let p = provider();
    let client_verifier = WebPkiClientVerifier::builder_with_provider(roots(ca)?, p.clone())
        .allow_unauthenticated()
        .build()?;
    let mut cfg = ServerConfig::builder_with_provider(p)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_client_cert_verifier(client_verifier)
        .with_single_cert(chain, key)?;
    cfg.alpn_protocols = vec![ALPN_H2.to_vec()];
    Ok(Arc::new(cfg))
}

/// Agent side after enrollment: verify the controller against the CA, and
/// authenticate with the agent certificate.
pub fn client_config(
    ca: &CertificateDer<'static>,
    cert: CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
) -> anyhow::Result<Arc<ClientConfig>> {
    let p = provider();
    let verifier = WebPkiServerVerifier::builder_with_provider(roots(ca)?, p.clone()).build()?;
    let mut cfg = ClientConfig::builder_with_provider(p)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_webpki_verifier(verifier)
        .with_client_auth_cert(vec![cert, ca.clone()], key)?;
    cfg.alpn_protocols = vec![ALPN_H2.to_vec()];
    Ok(Arc::new(cfg))
}

/// Agent side during enrollment: no client certificate yet; the controller is
/// accepted only if its chain contains a CA with the pinned fingerprint and
/// the server certificate verifies against that CA.
pub fn enrollment_client_config(ca_fingerprint: [u8; 32]) -> anyhow::Result<Arc<ClientConfig>> {
    let p = provider();
    let verifier = Arc::new(PinnedCaVerifier {
        fingerprint: ca_fingerprint,
        provider: p.clone(),
    });
    let mut cfg = ClientConfig::builder_with_provider(p)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .dangerous() // custom verifier; it still does full WebPKI verification
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    cfg.alpn_protocols = vec![ALPN_H2.to_vec()];
    Ok(Arc::new(cfg))
}

#[derive(Debug)]
struct PinnedCaVerifier {
    fingerprint: [u8; 32],
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for PinnedCaVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        // The internal CA issues SERVER_NAME only to the controller (agent
        // certificates are clientAuth-only), so check that name instead of
        // the address the client happened to use.
        let server_name = ServerName::try_from(SERVER_NAME).expect("valid server name");
        let ca = intermediates
            .iter()
            .find(|c| pki::fingerprint(c) == self.fingerprint)
            .ok_or_else(|| {
                rustls::Error::General(format!(
                    "controller CA does not match the pinned fingerprint (expected SHA-256 {})",
                    hex(&self.fingerprint)
                ))
            })?;
        let mut roots = RootCertStore::empty();
        roots.add(ca.clone().into_owned())?;
        WebPkiServerVerifier::builder_with_provider(Arc::new(roots), self.provider.clone())
            .build()
            .map_err(|e| rustls::Error::General(e.to_string()))?
            .verify_server_cert(end_entity, &[], &server_name, ocsp_response, now)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// REST API server: TLS 1.3, no client certificates (bearer tokens).
pub fn https_server_config(
    chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> anyhow::Result<Arc<ServerConfig>> {
    let mut cfg = ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_no_client_auth()
        .with_single_cert(chain, key)?;
    cfg.alpn_protocols = vec![ALPN_H2.to_vec(), b"http/1.1".to_vec()];
    Ok(Arc::new(cfg))
}

/// How an HTTPS client (`df2bctl`) authenticates the controller.
#[derive(Debug, Clone)]
pub enum Trust {
    /// The controller's internal CA, by SHA-256 fingerprint (the name checked
    /// is always [`SERVER_NAME`]).
    PinnedCa([u8; 32]),
    /// CA certificates from a file, normal hostname verification.
    CaCerts(Vec<CertificateDer<'static>>),
    /// Mozilla's root store (operator certificate from a public CA).
    SystemRoots,
}

/// TLS 1.3 client config for HTTP/1.1 clients.
pub fn https_client_config(trust: Trust) -> anyhow::Result<Arc<ClientConfig>> {
    let p = provider();
    let builder = ClientConfig::builder_with_provider(p.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])?;
    let mut cfg = match trust {
        Trust::PinnedCa(fingerprint) => builder
            .dangerous() // full WebPKI verification against the pinned CA
            .with_custom_certificate_verifier(Arc::new(PinnedCaVerifier {
                fingerprint,
                provider: p,
            }))
            .with_no_client_auth(),
        Trust::CaCerts(certs) => {
            let mut roots = RootCertStore::empty();
            for c in certs {
                roots.add(c)?;
            }
            builder.with_root_certificates(roots).with_no_client_auth()
        }
        Trust::SystemRoots => {
            let roots = RootCertStore {
                roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
            };
            builder.with_root_certificates(roots).with_no_client_auth()
        }
    };
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(cfg))
}

/// Opens a gRPC channel to the controller at `addr` (`host:port`) over TLS
/// with `cfg`. The server name checked is always [`SERVER_NAME`]: the
/// internal CA only issues that name to the controller, so agents can reach
/// it by any address.
pub async fn connect(addr: String, cfg: Arc<ClientConfig>) -> anyhow::Result<Channel> {
    let connector = tower::service_fn(move |_: Uri| {
        let addr = addr.clone();
        let cfg = cfg.clone();
        async move {
            let tcp = TcpStream::connect(&addr).await?;
            tcp.set_nodelay(true)?;
            let name = ServerName::try_from(SERVER_NAME).expect("valid server name");
            let tls = tokio::time::timeout(
                HANDSHAKE_TIMEOUT,
                TlsConnector::from(cfg).connect(name, tcp),
            )
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "TLS handshake timed out"))??;
            Ok::<_, io::Error>(TokioIo::new(tls))
        }
    });
    // "http": TLS is done by the connector above, not by tonic
    let channel = Endpoint::from_static("http://df2b-controller")
        .connect_timeout(Duration::from_secs(10))
        .http2_keep_alive_interval(Duration::from_secs(30))
        .keep_alive_timeout(Duration::from_secs(20))
        .keep_alive_while_idle(true)
        .connect_with_connector(connector)
        .await?;
    Ok(channel)
}

/// Accepts TCP connections and completes TLS handshakes concurrently (a slow
/// client cannot block others). Feed the stream to
/// `tonic::transport::Server::serve_with_incoming`; client certificates are
/// then available via `Request::peer_certs()`.
pub fn incoming(
    listener: TcpListener,
    cfg: Arc<ServerConfig>,
) -> ReceiverStream<Result<TlsStream<TcpStream>, io::Error>> {
    let (tx, rx) = tokio::sync::mpsc::channel(64);
    let acceptor = TlsAcceptor::from(cfg);
    tokio::spawn(async move {
        loop {
            let (tcp, peer) = match listener.accept().await {
                Ok(c) => c,
                Err(e) => {
                    debug!(error = %e, "accept failed");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
            };
            let _ = tcp.set_nodelay(true);
            if tx.is_closed() {
                break;
            }
            let acceptor = acceptor.clone();
            let tx = tx.clone();
            tokio::spawn(async move {
                match tokio::time::timeout(HANDSHAKE_TIMEOUT, acceptor.accept(tcp)).await {
                    Ok(Ok(tls)) => {
                        let _ = tx.send(Ok(tls)).await;
                    }
                    Ok(Err(e)) => debug!(%peer, error = %e, "TLS handshake failed"),
                    Err(_) => debug!(%peer, "TLS handshake timed out"),
                }
            });
        }
    });
    ReceiverStream::new(rx)
}
