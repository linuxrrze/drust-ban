//! Serves the REST API over TLS 1.3 (HTTP/1.1 and HTTP/2).
//!
//! axum's own `serve` only speaks plain TCP, so connections are accepted
//! here: TLS handshake with a timeout, then hyper's auto (h1/h2) connection
//! builder. The client address is passed to handlers as `ConnectInfo`.
//!
//! The TLS configuration can be replaced while serving ([`TlsConfig`]):
//! an operator certificate (`--https-cert`/`--https-key`) is loaded again
//! when its files change ([`CertFiles`]), e.g. after a renewal; each new
//! connection uses the current one.

use std::future::Future;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use axum::extract::ConnectInfo;
use axum::Router;
use hyper::body::Incoming;
use hyper::Request;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use hyper_util::service::TowerToHyperService;
use tokio::net::TcpListener;
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::TlsAcceptor;
use tower::ServiceExt;
use tracing::{debug, info, warn};

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// A request's headers must be complete this long after it started.
const HEADER_TIMEOUT: Duration = Duration::from_secs(if cfg!(test) { 1 } else { 30 });

/// The TLS configuration new connections use; replaceable.
#[derive(Clone)]
pub struct TlsConfig(Arc<RwLock<Arc<ServerConfig>>>);

impl TlsConfig {
    pub fn get(&self) -> Arc<ServerConfig> {
        self.0.read().unwrap_or_else(|e| e.into_inner()).clone()
    }

    pub fn set(&self, cfg: Arc<ServerConfig>) {
        *self.0.write().unwrap_or_else(|e| e.into_inner()) = cfg;
    }
}

impl From<Arc<ServerConfig>> for TlsConfig {
    fn from(cfg: Arc<ServerConfig>) -> Self {
        Self(Arc::new(RwLock::new(cfg)))
    }
}

/// An operator certificate chain and key in PEM files, loaded again when
/// either file changes.
pub struct CertFiles {
    pub cert: PathBuf,
    pub key: PathBuf,
    /// SHA-256 of both files as last loaded.
    stamp: Option<[[u8; 32]; 2]>,
}

impl CertFiles {
    pub fn new(cert: PathBuf, key: PathBuf) -> Self {
        Self {
            cert,
            key,
            stamp: None,
        }
    }

    /// Content hashes of both files: small, read once a minute; unlike
    /// mtime/size/inode this also sees an in-place rewrite of the same
    /// size within the same second.
    fn stamp(&self) -> Option<[[u8; 32]; 2]> {
        let s = |p: &PathBuf| {
            std::fs::read(p)
                .ok()
                .map(|b| df2b_tls::pki::fingerprint(&b))
        };
        Some([s(&self.cert)?, s(&self.key)?])
    }

    /// Reads and checks both files (the key must match the certificate).
    pub fn load(&mut self) -> anyhow::Result<Arc<ServerConfig>> {
        use anyhow::Context;
        let stamp = self.stamp();
        let pem = std::fs::read_to_string(&self.cert)
            .with_context(|| format!("reading {}", self.cert.display()))?;
        let chain = df2b_tls::pki::certs_from_pem(&pem)?;
        if chain.is_empty() {
            anyhow::bail!("{}: no certificates", self.cert.display());
        }
        let key_pem = std::fs::read_to_string(&self.key)
            .with_context(|| format!("reading {}", self.key.display()))?;
        let cfg =
            df2b_tls::transport::https_server_config(chain, df2b_tls::pki::key_from_pem(&key_pem)?)
                .with_context(|| {
                    format!(
                        "{} and {} do not form a usable certificate",
                        self.cert.display(),
                        self.key.display()
                    )
                })?;
        self.stamp = stamp;
        Ok(cfg)
    }

    /// Loads the files again if they changed; a broken pair (e.g. caught
    /// half written) is logged and the current certificate kept, and tried
    /// again next time. True if replaced.
    pub fn reload_if_changed(&mut self, tls: &TlsConfig) -> bool {
        let now = self.stamp();
        if now.is_none() || now == self.stamp {
            return false;
        }
        match self.load() {
            Ok(cfg) => {
                tls.set(cfg);
                info!(cert = %self.cert.display(), "HTTPS certificate reloaded");
                true
            }
            Err(e) => {
                warn!(error = %format!("{e:#}"), "new HTTPS certificate not usable, keeping the current one");
                false
            }
        }
    }
}

pub async fn serve(
    listener: TcpListener,
    tls: impl Into<TlsConfig>,
    app: Router,
    shutdown: impl Future<Output = ()>,
) {
    let tls: TlsConfig = tls.into();
    let slots = Arc::new(tokio::sync::Semaphore::new(
        df2b_tls::transport::MAX_CONNECTIONS,
    ));
    tokio::pin!(shutdown);
    loop {
        let (tcp, peer) = tokio::select! {
            r = listener.accept() => match r {
                Ok(c) => c,
                Err(e) => {
                    debug!(error = %e, "accept failed");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
            },
            _ = &mut shutdown => return,
        };
        // bounded, and idle connections close (slowloris)
        let Ok(slot) = slots.clone().try_acquire_owned() else {
            debug!(%peer, "too many connections, closing");
            continue;
        };
        let tcp = df2b_tls::transport::Guarded::new(tcp, slot);
        let acceptor = TlsAcceptor::from(tls.get());
        let app = app.clone();
        tokio::spawn(async move {
            let tls = match tokio::time::timeout(HANDSHAKE_TIMEOUT, acceptor.accept(tcp)).await {
                Ok(Ok(tls)) => tls,
                Ok(Err(e)) => return debug!(%peer, error = %e, "TLS handshake failed"),
                Err(_) => return debug!(%peer, "TLS handshake timed out"),
            };
            let svc = app.map_request(move |mut req: Request<Incoming>| {
                req.extensions_mut().insert(ConnectInfo::<SocketAddr>(peer));
                req
            });
            let mut builder = auto::Builder::new(TokioExecutor::new());
            // headers trickled in byte by byte still have to arrive in time
            builder
                .http1()
                .timer(hyper_util::rt::TokioTimer::new())
                .header_read_timeout(HEADER_TIMEOUT);
            if let Err(e) = builder
                .serve_connection(TokioIo::new(tls), TowerToHyperService::new(svc))
                .await
            {
                debug!(%peer, error = %e, "HTTPS connection error");
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use df2b_tls::pki::Ca;

    #[test]
    fn reloads_changed_certificate_files() {
        let dir = std::env::temp_dir().join(format!("df2b-https-reload-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let (cert, key) = (dir.join("cert.pem"), dir.join("key.pem"));
        let a = Ca::generate("a.example").unwrap();
        let b = Ca::generate("b.example").unwrap();
        std::fs::write(&cert, a.cert_pem()).unwrap();
        std::fs::write(&key, a.key_pem()).unwrap();
        let mut files = CertFiles::new(cert.clone(), key.clone());
        let tls = TlsConfig::from(files.load().unwrap());
        let first = tls.get();
        assert!(!files.reload_if_changed(&tls), "unchanged");

        // half written: new cert, old key -> refused, old one kept
        std::fs::write(&cert, b.cert_pem()).unwrap();
        assert!(!files.reload_if_changed(&tls));
        assert!(Arc::ptr_eq(&tls.get(), &first));
        // complete: replaced
        std::fs::write(&key, b.key_pem()).unwrap();
        assert!(files.reload_if_changed(&tls));
        assert!(!Arc::ptr_eq(&tls.get(), &first));
        assert!(!files.reload_if_changed(&tls));
        // files removed: nothing happens
        std::fs::remove_file(&key).unwrap();
        assert!(!files.reload_if_changed(&tls));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Regression (security review): a client trickling request headers
    /// kept its connection (and a file descriptor) forever.
    #[tokio::test]
    async fn incomplete_headers_time_out() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let ca = Ca::generate("t").unwrap();
        let (chain, key) = ca.issue_server(&[]).unwrap();
        let tls = df2b_tls::transport::https_server_config(chain, key).unwrap();
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(serve(l, tls, Router::new(), std::future::pending()));
        let client = df2b_tls::transport::https_client_config(
            df2b_tls::transport::Trust::PinnedCa(ca.fingerprint()),
        )
        .unwrap();
        let mut cfg = (*client).clone();
        cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
        let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
        let name =
            tokio_rustls::rustls::pki_types::ServerName::try_from(df2b_tls::SERVER_NAME).unwrap();
        let mut s = tokio_rustls::TlsConnector::from(Arc::new(cfg))
            .connect(name, tcp)
            .await
            .unwrap();
        s.write_all(b"GET / HTTP/1.1\r\nHost: x\r\n").await.unwrap();
        let mut buf = Vec::new();
        let r = tokio::time::timeout(Duration::from_secs(5), s.read_to_end(&mut buf)).await;
        assert!(r.is_ok(), "the server closed the connection");
    }
}
