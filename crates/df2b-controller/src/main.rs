//! dist-f2b controller.
//!
//! Implemented: internal CA, enrollment, `AgentService` over mutual TLS 1.3
//! (heartbeats, ban reports, decision log with resumable subscriptions),
//! `propagate_local` policy, authenticated REST API over HTTPS (API tokens
//! with roles, manual ban/unban, agents, audit log), web UI with local users
//! or OpenID Connect and live updates (SSE).
//!
//! Also: central policies and jails, correlation rules with escalation.
//!
//! TODO: PostgreSQL storage for several controllers (DESIGN.md §6).

mod actions;
mod api;
mod breaker;
mod central;
mod correlation;
mod files;
mod geo;
mod grpc;
mod https;
mod oidc;
mod policy;
mod ratelimit;
mod session;
mod state;
mod store;
mod ui;

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
use ipnet::IpNet;
use tracing::{error, info};
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

    /// Address for the REST API and web UI (HTTPS).
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

    /// What an agent's local ban turns into. Also changeable in the web UI
    /// (stored); when given, this flag wins at startup. Default: global.
    #[arg(long, value_enum)]
    propagate: Option<Propagate>,

    /// Networks that are never banned centrally (repeatable).
    #[arg(long = "allow")]
    allowlist: Vec<IpNet>,

    /// Web UI login with an OpenID Connect provider (TOML file; see
    /// DESIGN.md §9).
    #[arg(long, env = "DF2B_OIDC_CONFIG")]
    oidc_config: Option<PathBuf>,

    /// MaxMind DB file with ASN and/or country data (repeatable): GeoLite2
    /// ASN, Country or City, DB-IP Lite, ipinfo Lite. Reloaded when it
    /// changes. Shown in the UI; never used for decisions.
    #[arg(long = "geoip", env = "DF2B_GEOIP", value_delimiter = ',')]
    geoip: Vec<PathBuf>,

    /// REST API requests per second per client (IPv6: per /64), sustained;
    /// 0 = no limit (e.g. behind a reverse proxy, where every client has
    /// the proxy's address).
    #[arg(long, env = "DF2B_API_RATE", default_value_t = 20)]
    api_rate: u32,

    /// External actions (webhooks, programs) on decisions: TOML file, see
    /// DESIGN.md §5.
    #[arg(long, env = "DF2B_ACTIONS")]
    actions: Option<PathBuf>,

    /// How long ended decisions stay in the decision log (address history,
    /// agents resuming without a snapshot), e.g. 90d; at least 31d.
    /// Active bans always stay. "never": keep everything.
    #[arg(long, env = "DF2B_LOG_RETENTION", default_value = "90d", value_parser = parse_retention)]
    log_retention: Retention,

    /// REST API requests per client at once.
    #[arg(long, env = "DF2B_API_BURST", default_value_t = 200)]
    api_burst: u32,

    /// Circuit breaker: more automatic bans (agent propagation, correlation
    /// rules) than this within --breaker-window hold back all further ones
    /// until an admin resets it; 0 = no breaker.
    #[arg(long, env = "DF2B_BREAKER_MAX", default_value_t = 1000)]
    breaker_max: u32,

    /// Circuit breaker window, e.g. 10m.
    #[arg(long, env = "DF2B_BREAKER_WINDOW", default_value = "10m", value_parser = humantime::parse_duration)]
    breaker_window: Duration,
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
    /// Manage web UI users. Run as the controller's user: the files are
    /// private (mode 0600).
    #[command(subcommand)]
    User(UserCmd),
    /// Single sign-on user names: each is bound to the account (issuer and
    /// subject) that logged in with it first, so a name changed at the
    /// identity provider cannot take over another user's name.
    #[command(subcommand)]
    OidcName(OidcNameCmd),
}

#[derive(Debug, Subcommand)]
enum OidcNameCmd {
    List,
    /// Free a name for another account (after a rename or deletion at the
    /// identity provider); the next login with it binds it again.
    Release {
        name: String,
    },
}

#[derive(Debug, Subcommand)]
enum UserCmd {
    /// Create a user; asks for the password (or reads one line from stdin).
    Add {
        name: String,
        #[arg(long, value_enum)]
        role: Role,
    },
    /// Set a new password; the user's sessions end.
    Passwd {
        name: String,
    },
    /// Change a user's role (effective on their next request).
    SetRole {
        name: String,
        #[arg(value_enum)]
        role: Role,
    },
    List,
    /// Delete a user; their sessions end immediately.
    Delete {
        name: String,
    },
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

/// `--generate-man <DIR>` as the only arguments (hidden, for the package
/// builds): writes the manual pages of the command and its subcommands to
/// DIR instead of running.
fn generate_man() -> Option<anyhow::Result<()>> {
    use clap::CommandFactory;
    let mut args = std::env::args_os().skip(1);
    if args.next()? != "--generate-man" {
        return None;
    }
    let dir = std::path::PathBuf::from(args.next()?);
    Some((|| {
        std::fs::create_dir_all(&dir)?;
        clap_mangen::generate_to(Args::command(), &dir)?;
        Ok(())
    })())
}

fn main() -> anyhow::Result<()> {
    if let Some(r) = generate_man() {
        return r;
    }
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
        Some(Cmd::User(cmd)) => user(dir, cmd),
        Some(Cmd::OidcName(cmd)) => oidc_name(dir, cmd),
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
                    "{:<24} {:<9} created {} by {}  expires {exp}",
                    t.name,
                    format!("{:?}", t.role).to_lowercase(),
                    t.created_at.to_rfc3339_opts(SecondsFormat::Secs, true),
                    t.created_by.as_deref().unwrap_or("(host)"),
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

/// Asks twice on a terminal; otherwise reads one line from stdin.
fn read_password(prompt: &str) -> anyhow::Result<String> {
    if std::io::stdin().is_terminal() {
        let p = rpassword::prompt_password(format!("{prompt}: "))?;
        if rpassword::prompt_password("repeat: ")? != p {
            bail!("passwords differ");
        }
        Ok(p)
    } else {
        let mut line = String::new();
        std::io::stdin().read_line(&mut line)?;
        Ok(line.trim_end_matches(['\r', '\n']).to_owned())
    }
}

fn user(dir: &std::path::Path, cmd: UserCmd) -> anyhow::Result<()> {
    match cmd {
        UserCmd::Add { name, role } => {
            let pw = read_password(&format!(
                "password for {name} (at least {} characters)",
                files::MIN_PASSWORD_LEN
            ))?;
            files::create_user(dir, &name, role, &pw)?;
            println!(
                "user {name:?} ({}) created",
                format!("{role:?}").to_lowercase()
            );
        }
        UserCmd::Passwd { name } => {
            if files::load_user(dir, &name)?.is_none() {
                bail!("no user {name:?}");
            }
            let pw = read_password(&format!("new password for {name}"))?;
            files::update_user(dir, &name, None, Some(&pw))?;
            println!("password of {name:?} changed; their sessions have ended");
        }
        UserCmd::SetRole { name, role } => {
            files::update_user(dir, &name, Some(role), None)?;
            println!("{name:?} is now {}", format!("{role:?}").to_lowercase());
        }
        UserCmd::List => {
            for u in files::list_users(dir)? {
                println!(
                    "{:<24} {:<9} created {}  password changed {}",
                    u.name,
                    format!("{:?}", u.role).to_lowercase(),
                    u.created_at.to_rfc3339_opts(SecondsFormat::Secs, true),
                    u.password_changed_at
                        .to_rfc3339_opts(SecondsFormat::Secs, true),
                );
            }
        }
        UserCmd::Delete { name } => {
            if !files::delete_user(dir, &name)? {
                bail!("no user {name:?}");
            }
            println!("user {name:?} deleted");
        }
    }
    Ok(())
}

fn oidc_name(dir: &std::path::Path, cmd: OidcNameCmd) -> anyhow::Result<()> {
    match cmd {
        OidcNameCmd::List => {
            for n in files::list_oidc_names(dir)? {
                println!(
                    "{:<24} since {}  {} {}",
                    n.name,
                    n.bound_at.to_rfc3339_opts(SecondsFormat::Secs, true),
                    n.issuer,
                    n.subject,
                );
            }
        }
        OidcNameCmd::Release { name } => {
            if !files::release_oidc_name(dir, &name)? {
                bail!("{name:?} is not bound");
            }
            println!("{name:?} released");
        }
    }
    Ok(())
}

/// `--log-retention`: `None` = never compact. (A newtype: clap treats a
/// bare `Option<_>` field as "the argument is optional".)
#[derive(Debug, Clone, Copy)]
struct Retention(Option<Duration>);

fn parse_retention(s: &str) -> Result<Retention, String> {
    if s == "never" {
        return Ok(Retention(None));
    }
    let d = humantime::parse_duration(s).map_err(|e| e.to_string())?;
    if d < state::MIN_LOG_RETENTION {
        return Err("at least 31d (offense counts are rebuilt from the log)".into());
    }
    Ok(Retention(Some(d)))
}

async fn serve(args: Args) -> anyhow::Result<()> {
    let a = args.serve;
    let dir = args.state_dir;
    let oidc = match &a.oidc_config {
        Some(p) => {
            let o = oidc::Oidc::new(oidc::OidcConfig::load(p)?)
                .with_context(|| format!("OIDC configuration {}", p.display()))?;
            info!(issuer = %o.config.issuer, "web UI login via OpenID Connect");
            Some(Arc::new(o))
        }
        None => None,
    };
    let ca = files::load_or_create_ca(&dir)?;
    let store = store::Store::open(&dir)?;
    let geo = geo::Geo::open(&a.geoip)?;
    if a.breaker_max > 0 && a.breaker_window < Duration::from_secs(1) {
        bail!("--breaker-window must be at least 1s");
    }
    let ctl = Arc::new(
        Controller::open(
            Settings {
                state_dir: dir.clone(),
                cert_lifetime: a.agent_cert_lifetime,
                propagate: a.propagate.unwrap_or(Propagate::Global),
                allowlist: Allowlist::new(a.allowlist),
                oidc: oidc.clone(),
                https_internal_ca: a.https_cert.is_none(),
            },
            ca,
            store,
        )?
        .with_geo(geo)
        .with_breaker(breaker::BreakerLimit {
            max: a.breaker_max,
            window: a.breaker_window,
        }),
    );
    if let Some(p) = a.propagate {
        if ctl.propagate() != p {
            info!(propagate = ?p, "--propagate overrides the stored setting");
        }
        ctl.set_propagate(p)?;
    }

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
        // agents use a few streams each
        .max_concurrent_streams(Some(64))
        .add_service(AgentServiceServer::new(grpc::Service::new(ctl.clone())))
        .serve_with_incoming_shutdown(
            df2b_tls::transport::incoming(listener, grpc_tls),
            shutdown(),
        );

    // REST API: operator certificate or the internal one
    // (an operator certificate is loaded again when its files change)
    let mut cert_files = match (&a.https_cert, &a.https_key) {
        (Some(cert), Some(key)) => Some(https::CertFiles::new(cert.clone(), key.clone())),
        _ => None,
    };
    let https_tls = https::TlsConfig::from(match &mut cert_files {
        Some(f) => f.load()?,
        None => df2b_tls::transport::https_server_config(chain, key)?,
    });
    let https_listener = tokio::net::TcpListener::bind(a.https_listen)
        .await
        .with_context(|| format!("binding {}", a.https_listen))?;
    info!(
        addr = %a.https_listen,
        certificate = if a.https_cert.is_some() { "operator" } else { "internal CA" },
        "REST API and web UI listening (HTTPS, TLS 1.3)"
    );
    let rest = https::serve(
        https_listener,
        https_tls.clone(),
        api::router_with_limit(
            ctl.clone(),
            ratelimit::ApiLimit {
                rate: a.api_rate,
                burst: a.api_burst,
            },
        ),
        shutdown(),
    );

    if let Some(o) = oidc {
        tokio::spawn(async move { o.warm_up().await });
    }
    if let Some(p) = &a.actions {
        let cfg = actions::ActionsConfig::load(p)?;
        actions::spawn(ctl.clone(), cfg).with_context(|| format!("actions in {}", p.display()))?;
    }

    let housekeeping = {
        let ctl = ctl.clone();
        let retention = a.log_retention.0;
        async move {
            let mut t = tokio::time::interval(Duration::from_secs(60));
            // first after a minute, then daily
            let mut next_compaction = tokio::time::Instant::now() + Duration::from_secs(60);
            loop {
                t.tick().await;
                if let Some(r) =
                    retention.filter(|_| tokio::time::Instant::now() >= next_compaction)
                {
                    next_compaction = tokio::time::Instant::now() + Duration::from_secs(86400);
                    let c = ctl.clone();
                    if let Ok(Err(e)) = tokio::task::spawn_blocking(move || c.compact_log(r)).await
                    {
                        error!(error = %format!("{e:#}"), "compacting the decision log failed");
                    }
                }
                if let Some(f) = &mut cert_files {
                    f.reload_if_changed(&https_tls);
                }
                // may write (expired allowlist entries): off the runtime
                let (c, dir) = (ctl.clone(), dir.clone());
                let _ = tokio::task::spawn_blocking(move || {
                    c.prune();
                    // networks of allowlisted autonomous systems may move
                    if c.geo.reload_changed() {
                        c.refresh_asn_networks();
                    }
                    files::prune_tokens(&dir);
                })
                .await;
            }
        }
    };

    // correlation observations to the database (a restart loses at most
    // the last few seconds)
    let flush = {
        let ctl = ctl.clone();
        async move {
            let mut t = tokio::time::interval(Duration::from_secs(5));
            loop {
                t.tick().await;
                let c = ctl.clone();
                let _ = tokio::task::spawn_blocking(move || c.flush_observations()).await;
            }
        }
    };

    tokio::select! {
        r = grpc => r.context("agent service")?,
        () = rest => {}
        _ = housekeeping => {}
        _ = flush => {}
    }
    let c = ctl.clone();
    let _ = tokio::task::spawn_blocking(move || c.flush_observations()).await;
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Regression: the CLI definition was inconsistent (clap panicked at
    /// start for every subcommand).
    #[test]
    fn cli_is_consistent() {
        use clap::CommandFactory;
        Args::command().debug_assert();
        let a = Args::try_parse_from(["df2b-controller", "serve"]).unwrap();
        assert_eq!(
            a.serve.log_retention.0,
            Some(Duration::from_secs(90 * 86400))
        );
        let a = Args::try_parse_from(["df2b-controller", "--log-retention", "never"]).unwrap();
        assert!(a.serve.log_retention.0.is_none());
        assert!(Args::try_parse_from(["df2b-controller", "--log-retention", "5d"]).is_err());
    }
}
