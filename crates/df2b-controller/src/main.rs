//! dist-f2b controller.
//!
//! Implemented: internal CA, enrollment, `AgentService` over mutual TLS 1.3
//! (heartbeats, ban reports, decision log with resumable subscriptions),
//! `propagate_local` policy, read-only REST endpoints on loopback.
//!
//! TODO (milestone 2/3): authenticated REST API over HTTPS for `df2bctl` and
//! the web UI (manual ban/unban, revoke, tokens), observation rollups and
//! correlation policies, sqlx storage, log compaction, embedded web UI.

mod files;
mod grpc;
mod state;
mod store;

use std::io::IsTerminal;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use axum::extract::State;
use axum::routing::get;
use axum::{Json, Router};
use clap::{Parser, Subcommand};
use df2b_core::Allowlist;
use df2b_proto::v1::agent_service_server::AgentServiceServer;
use ipnet::IpNet;
use serde_json::{json, Value};
use tracing::info;
use tracing_subscriber::EnvFilter;

use crate::state::{Controller, Propagate, Settings};

#[derive(Debug, Parser)]
#[command(version, about = "dist-f2b controller")]
struct Args {
    /// State directory (CA, enrollment tokens, database).
    #[arg(
        long,
        global = true,
        env = "DF2B_CONTROLLER_STATE_DIR",
        default_value = "/var/lib/df2b-controller"
    )]
    state_dir: PathBuf,

    #[command(subcommand)]
    cmd: Option<Cmd>,

    #[command(flatten)]
    serve: ServeArgs,
}

#[derive(Debug, clap::Args)]
struct ServeArgs {
    /// Address for agent connections (gRPC over mutual TLS).
    #[arg(long, env = "DF2B_GRPC_LISTEN", default_value = "[::]:7443")]
    grpc_listen: SocketAddr,

    /// Address for the REST API (plain HTTP, loopback only until the
    /// authenticated HTTPS API exists).
    #[arg(long, env = "DF2B_HTTP_LISTEN", default_value = "127.0.0.1:7080")]
    http_listen: SocketAddr,

    /// Extra DNS names / IPs for the server certificate (agents always
    /// verify the fixed name "df2b-controller", so this is optional).
    #[arg(long = "name")]
    names: Vec<String>,

    /// Lifetime of agent certificates (renewed automatically).
    #[arg(long, default_value = "30d", value_parser = humantime::parse_duration)]
    agent_cert_lifetime: Duration,

    /// What an agent's local ban turns into.
    #[arg(long, value_enum, default_value_t = Propagate::Global)]
    propagate: Propagate,

    /// Networks that are never banned centrally (repeatable).
    #[arg(long = "allow")]
    allowlist: Vec<IpNet>,
}

#[derive(Debug, Subcommand)]
enum Cmd {
    /// Run the controller (default).
    Serve,
    /// Create a one-time enrollment token for an agent.
    EnrollToken {
        /// Group the agent joins.
        #[arg(long, default_value = "default")]
        group: String,
        /// How long the token can be used.
        #[arg(long, default_value = "1h", value_parser = humantime::parse_duration)]
        ttl: Duration,
    },
    /// Revoke an agent: its connections are closed and refused.
    Revoke { agent_id: String },
}

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        // no color codes in files or the journal
        .with_ansi(std::io::stdout().is_terminal())
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .init();
    let args = Args::parse();
    match args.cmd {
        Some(Cmd::EnrollToken { group, ttl }) => {
            let token = files::create_token(&args.state_dir, &group, ttl)?;
            println!("{token}");
            eprintln!(
                "one-time token for group '{group}', valid for {}; on the agent host run:\n  \
                 df2b-agent --enroll-token <token>   (or set DF2B_ENROLL_TOKEN)",
                humantime::format_duration(ttl)
            );
            Ok(())
        }
        Some(Cmd::Revoke { agent_id }) => {
            files::revoke(&args.state_dir, &agent_id)?;
            println!("revoked {agent_id}; open connections close within a few seconds");
            Ok(())
        }
        Some(Cmd::Serve) | None => tokio::runtime::Runtime::new()?.block_on(serve(args)),
    }
}

async fn serve(args: Args) -> anyhow::Result<()> {
    let a = args.serve;
    if !a.http_listen.ip().is_loopback() {
        anyhow::bail!(
            "--http-listen must be a loopback address: the REST API has no TLS and \
             authentication yet"
        );
    }
    let dir = args.state_dir;
    let ca = files::load_or_create_ca(&dir)?;
    let store = store::Store::open(&dir)?;
    let ctl = Arc::new(Controller::open(
        Settings {
            state_dir: dir.clone(),
            cert_lifetime: a.agent_cert_lifetime,
            propagate: a.propagate,
            allowlist: Allowlist::new(a.allowlist),
        },
        ca,
        store,
    )?);

    let (chain, key) = ctl.ca.issue_server(&a.names)?;
    let tls = df2b_tls::transport::server_config(ctl.ca.cert_der(), chain, key)?;
    let listener = tokio::net::TcpListener::bind(a.grpc_listen)
        .await
        .with_context(|| format!("binding {}", a.grpc_listen))?;
    info!(
        addr = %a.grpc_listen,
        ca_fingerprint = %df2b_tls::hex(&ctl.ca.fingerprint()),
        "agent service listening (mTLS, TLS 1.3)"
    );
    let grpc = tonic::transport::Server::builder()
        .http2_keepalive_interval(Some(Duration::from_secs(30)))
        .http2_keepalive_timeout(Some(Duration::from_secs(20)))
        .add_service(AgentServiceServer::new(grpc::Service::new(ctl.clone())))
        .serve_with_incoming_shutdown(df2b_tls::transport::incoming(listener, tls), shutdown());

    let http_listener = tokio::net::TcpListener::bind(a.http_listen).await?;
    info!(addr = %a.http_listen, "HTTP API listening");
    let http = axum::serve(http_listener, router(ctl.clone())).with_graceful_shutdown(shutdown());

    let housekeeping = {
        let ctl = ctl.clone();
        async move {
            let mut t = tokio::time::interval(Duration::from_secs(60));
            loop {
                t.tick().await;
                ctl.prune();
                let dir = dir.clone();
                let _ = tokio::task::spawn_blocking(move || files::prune_tokens(&dir)).await;
            }
        }
    };

    tokio::select! {
        r = grpc => r.context("agent service")?,
        r = http => r.context("HTTP API")?,
        _ = housekeeping => {}
    }
    info!("shut down");
    Ok(())
}

async fn shutdown() {
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .expect("SIGTERM handler");
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = term.recv() => {}
    }
}

async fn health() -> Json<Value> {
    Json(json!({ "status": "ok", "version": env!("CARGO_PKG_VERSION") }))
}

async fn agents(State(ctl): State<Arc<Controller>>) -> Json<Value> {
    Json(json!({ "agents": ctl.agents() }))
}

async fn decisions(State(ctl): State<Arc<Controller>>) -> Json<Value> {
    Json(json!({ "active": ctl.active_decisions() }))
}

fn router(ctl: Arc<Controller>) -> Router {
    Router::new()
        .route("/api/v1/health", get(health))
        .route("/api/v1/agents", get(agents))
        .route("/api/v1/decisions", get(decisions))
        .with_state(ctl)
}
