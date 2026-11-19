//! dist-f2b controller.
//!
//! Implemented: internal CA, enrollment, `AgentService` over mutual TLS 1.3
//! (heartbeats, ban reports, decision log with resumable subscriptions),
//! `propagate_local` policy, authenticated REST API over HTTPS (API tokens
//! with roles, manual ban/unban, agents, audit log).
//!
//! TODO: browser sessions + web UI, observation rollups and correlation
//! policies, sqlx storage, log compaction.

mod api;
mod files;
mod grpc;
mod https;
mod state;
mod store;

use std::io::IsTerminal;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context};
use chrono::SecondsFormat;
use clap::{Parser, Subcommand};
use df2b_core::Allowlist;
use df2b_proto::v1::agent_service_server::AgentServiceServer;
use df2b_tls::pki::key_from_pem;
use df2b_tls::CertificateDer;
use ipnet::IpNet;
use tracing::info;
use tracing_subscriber::EnvFilter;

use crate::files::Role;
use crate::state::{Controller, Propagate, Settings};

#[derive(Debug, Parser)]
#[command(version, about = "dist-f2b controller")]
struct Args {
    /// State directory (CA, tokens, database).
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

    /// Address for the REST API (HTTPS, API tokens).
    #[arg(long, env = "DF2B_HTTPS_LISTEN", default_value = "[::]:7444")]
    https_listen: SocketAddr,

    /// Certificate chain (PEM) for the REST API, e.g. from a public CA.
    /// Default: a certificate from the internal CA (clients pin its
    /// fingerprint, see `api-token create`).
    #[arg(long, requires = "https_key")]
    https_cert: Option<PathBuf>,

    /// Private key (PEM) for --https-cert.
    #[arg(long, requires = "https_cert")]
    https_key: Option<PathBuf>,

    /// Extra DNS names / IPs for the internal server certificate (agents and
    /// pinned clients verify the fixed name "df2b-controller").
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
    /// Manage REST API tokens.
    #[command(subcommand)]
    ApiToken(ApiTokenCmd),
}

#[derive(Debug, Subcommand)]
enum ApiTokenCmd {
    /// Create a token (printed once; only its hash is stored).
    Create {
        /// Unique name, recorded in the audit log (e.g. the person).
        #[arg(long)]
        name: String,
        #[arg(long, value_enum)]
        role: Role,
        /// Expiry, e.g. "90d" (default: none).
        #[arg(long, value_parser = humantime::parse_duration)]
        ttl: Option<Duration>,
        /// Controller URL for the printed df2bctl configuration.
        #[arg(long, default_value = "https://<controller-host>:7444")]
        url: String,
    },
    List,
    /// Delete a token by name (takes effect immediately).
    Revoke {
        name: String,
    },
}

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        // no color codes in files or the journal
        .with_ansi(std::io::stderr().is_terminal())
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .init();
    let args = Args::parse();
    let dir = &args.state_dir;
    match args.cmd {
        Some(Cmd::EnrollToken { group, ttl }) => {
            let token = files::create_token(dir, &group, ttl)?;
            println!("{token}");
            eprintln!(
                "one-time token for group '{group}', valid for {}; on the agent host run:\n  \
                 df2b-agent --enroll-token <token>   (or set DF2B_ENROLL_TOKEN)",
                humantime::format_duration(ttl)
            );
            Ok(())
        }
        Some(Cmd::Revoke { agent_id }) => {
            files::revoke(dir, &agent_id)?;
            println!("revoked {agent_id}; open connections close within a few seconds");
            Ok(())
        }
        Some(Cmd::ApiToken(cmd)) => api_token(dir, cmd),
        Some(Cmd::Serve) | None => tokio::runtime::Runtime::new()?.block_on(serve(args)),
    }
}

fn api_token(dir: &std::path::Path, cmd: ApiTokenCmd) -> anyhow::Result<()> {
    match cmd {
        ApiTokenCmd::Create {
            name,
            role,
            ttl,
            url,
        } => {
            let ca = files::load_ca(dir)
                .context("the controller must have been started once (it creates the CA)")?;
            let token = files::create_api_token(dir, &name, role, ttl)?;
            println!("{token}");
            eprintln!(
                "\nAPI token '{name}' ({}). It is shown only once. df2bctl configuration \
                 (~/.config/df2b/df2bctl.toml, mode 0600):\n\n\
                 controller = \"{url}\"\n\
                 token = \"{token}\"\n\
                 # pins the controller's internal CA; omit when --https-cert uses a public CA\n\
                 ca_fingerprint = \"{}\"",
                format!("{role:?}").to_lowercase(),
                df2b_tls::hex(&ca.fingerprint())
            );
        }
        ApiTokenCmd::List => {
            for t in files::list_api_tokens(dir)? {
                let exp = t.expires_at.map_or_else(
                    || "never".to_owned(),
                    |e| e.to_rfc3339_opts(SecondsFormat::Secs, true),
                );
                println!(
                    "{:<24} {:<9} created {}  expires {exp}",
                    t.name,
                    format!("{:?}", t.role).to_lowercase(),
                    t.created_at.to_rfc3339_opts(SecondsFormat::Secs, true)
                );
            }
        }
        ApiTokenCmd::Revoke { name } => {
            if !files::revoke_api_token(dir, &name)? {
                bail!("no API token named {name:?}");
            }
            println!("API token {name:?} revoked");
        }
    }
    Ok(())
}

fn read_pem_chain(path: &std::path::Path) -> anyhow::Result<Vec<CertificateDer<'static>>> {
    use df2b_tls::pki::certs_from_pem;
    let pem =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let certs = certs_from_pem(&pem)?;
    if certs.is_empty() {
        bail!("{}: no certificates", path.display());
    }
    Ok(certs)
}

async fn serve(args: Args) -> anyhow::Result<()> {
    let a = args.serve;
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

    // agent service: always the internal CA
    let (chain, key) = ctl.ca.issue_server(&a.names)?;
    let grpc_tls =
        df2b_tls::transport::server_config(ctl.ca.cert_der(), chain.clone(), key.clone_key())?;
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
        .serve_with_incoming_shutdown(
            df2b_tls::transport::incoming(listener, grpc_tls),
            shutdown(),
        );

    // REST API: operator certificate or the internal one
    let https_tls = match (&a.https_cert, &a.https_key) {
        (Some(cert), Some(key)) => {
            let chain = read_pem_chain(cert)?;
            let key_pem = std::fs::read_to_string(key)
                .with_context(|| format!("reading {}", key.display()))?;
            df2b_tls::transport::https_server_config(chain, key_from_pem(&key_pem)?)?
        }
        _ => df2b_tls::transport::https_server_config(chain, key)?,
    };
    let https_listener = tokio::net::TcpListener::bind(a.https_listen)
        .await
        .with_context(|| format!("binding {}", a.https_listen))?;
    info!(
        addr = %a.https_listen,
        certificate = if a.https_cert.is_some() { "operator" } else { "internal CA" },
        "REST API listening (HTTPS, TLS 1.3)"
    );
    let rest = https::serve(
        https_listener,
        https_tls,
        api::router(ctl.clone()),
        shutdown(),
    );

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
        () = rest => {}
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
