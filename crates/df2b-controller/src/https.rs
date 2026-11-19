//! Serves the REST API over TLS 1.3 (HTTP/1.1 and HTTP/2).
//!
//! axum's own `serve` only speaks plain TCP, so connections are accepted
//! here: TLS handshake with a timeout, then hyper's auto (h1/h2) connection
//! builder. The client address is passed to handlers as `ConnectInfo`.

use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
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
use tracing::debug;

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

pub async fn serve(
    listener: TcpListener,
    tls: Arc<ServerConfig>,
    app: Router,
    shutdown: impl Future<Output = ()>,
) {
    let acceptor = TlsAcceptor::from(tls);
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
        let acceptor = acceptor.clone();
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
            if let Err(e) = auto::Builder::new(TokioExecutor::new())
                .serve_connection(TokioIo::new(tls), TowerToHyperService::new(svc))
                .await
            {
                debug!(%peer, error = %e, "HTTPS connection error");
            }
        });
    }
}
