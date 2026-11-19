//! dist-f2b controller.
//!
//! Milestone 2 TODO:
//! - tonic `AgentService` (df2b-proto) over mTLS, internal CA, enrollment,
//! - decision log + snapshots (sqlx: SQLite / PostgreSQL),
//! - observation rollups and correlation policies,
//! - REST API (utoipa OpenAPI), SSE live updates, auth (argon2 / OIDC),
//! - embedded web UI (rust-embed of web/build).

use std::net::SocketAddr;

use axum::routing::get;
use axum::{Json, Router};
use clap::Parser;
use serde_json::{json, Value};
use tracing::info;
use tracing_subscriber::EnvFilter;

// Linked now so protocol changes are type-checked with the controller.
use df2b_proto as _;

#[derive(Debug, Parser)]
#[command(version, about = "dist-f2b controller")]
struct Args {
    /// Address for the REST API and web UI.
    #[arg(long, env = "DF2B_HTTP_LISTEN", default_value = "127.0.0.1:7080")]
    http_listen: SocketAddr,
}

async fn health() -> Json<Value> {
    Json(json!({ "status": "ok", "version": env!("CARGO_PKG_VERSION") }))
}

fn router() -> Router {
    Router::new().route("/api/v1/health", get(health))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();
    let args = Args::parse();

    let listener = tokio::net::TcpListener::bind(args.http_listen).await?;
    info!(addr = %args.http_listen, "HTTP API listening");
    axum::serve(listener, router())
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await?;
    Ok(())
}
