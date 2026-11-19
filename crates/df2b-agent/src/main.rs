//! dist-f2b agent.
//!
//! sources → engine → firewall backend, with source positions and offenders
//! persisted in redb. With a controller configured: local bans are reported
//! and the controller's decisions are applied (see link.rs).
//! TODO: local control socket for `df2bctl --local`, reconcile loop.

mod config;
mod engine;
mod link;
mod remote;
mod state;
mod tracker;

use std::collections::HashMap;
use std::io::IsTerminal;
use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use chrono::Utc;
use clap::Parser;
use df2b_firewall::{BanEntry, DryRun, FirewallBackend, Nftables};
use df2b_proto::v1;
use df2b_sources::{FileTailer, Position, SourceBatch};
use df2b_tls::EnrollToken;
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::mpsc;
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

use crate::config::{AgentConfig, FirewallKind, SourceConfig, SourceKind};
use crate::engine::Engine;
use crate::link::{FromController, Link, LinkConfig, LinkStats};
use crate::remote::{Changes, RemoteBans};
use crate::state::{Pending, State};

/// How often buffered state changes are committed (one fsync each).
const FLUSH_INTERVAL: Duration = Duration::from_secs(1);

#[derive(Debug, Parser)]
#[command(version, about = "dist-f2b agent")]
struct Args {
    /// Path to the agent configuration file.
    #[arg(
        short,
        long,
        env = "DF2B_AGENT_CONFIG",
        default_value = "/etc/df2b/agent.toml"
    )]
    config: PathBuf,

    /// Validate configuration and filters, then exit.
    #[arg(long)]
    check: bool,

    /// One-time token to enroll with the controller (first start only; the
    /// certificate is then kept in <state_dir>/tls).
    #[arg(long, env = "DF2B_ENROLL_TOKEN", hide_env_values = true)]
    enroll_token: Option<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        // no color codes in files or the journal
        .with_ansi(std::io::stdout().is_terminal())
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let args = Args::parse();
    let cfg = AgentConfig::load(&args.config)?;
    let mut engine = Engine::from_config(&cfg)?;
    let enroll_token = args
        .enroll_token
        .as_deref()
        .map(str::parse::<EnrollToken>)
        .transpose()
        .context("--enroll-token")?;

    if args.check {
        println!(
            "configuration OK: {} source(s), {} jail(s)",
            cfg.source.len(),
            engine.jail_count()
        );
        return Ok(());
    }
    if cfg.agent.controller.is_none() && enroll_token.is_some() {
        warn!("--enroll-token given but no controller configured; ignoring it");
    }

    let state = State::open(&cfg.agent.state_dir)?;
    let loaded = state.load()?;
    let restored = engine.restore(loaded.offenders, Utc::now());
    info!(
        path = %state.path().display(),
        positions = loaded.positions.len(),
        active_bans = restored.len(),
        "state loaded"
    );

    let backend: Arc<dyn FirewallBackend> = match cfg.agent.firewall {
        FirewallKind::Nftables => Arc::new(Nftables::default()),
        FirewallKind::DryRun => Arc::new(DryRun),
    };
    {
        let b = backend.clone();
        tokio::task::spawn_blocking(move || b.ensure_setup())
            .await?
            .with_context(|| format!("setting up firewall backend '{}'", backend.name()))?;
    }
    info!(backend = backend.name(), "firewall ready");
    // ensure_setup starts from an empty table: re-apply still-active bans
    if !restored.is_empty() {
        let entries: Vec<_> = restored
            .iter()
            .map(|(key, remaining)| BanEntry {
                net: key.net(),
                timeout: Some(*remaining),
            })
            .collect();
        let b = backend.clone();
        tokio::task::spawn_blocking(move || b.ban(&entries))
            .await?
            .context("re-applying saved bans")?;
        info!(count = restored.len(), "re-applied saved bans");
    }

    // Bounded in batches (each up to BATCH_MAX lines): a slow engine throttles
    // the sources instead of buffering without limit.
    let (tx, mut rx) = mpsc::channel::<SourceBatch>(64);
    for src in &cfg.source {
        spawn_source(src, &tx, &loaded.positions)?;
    }
    drop(tx);

    let stats = Arc::new(LinkStats::default());
    let mut link: Option<Link> = match &cfg.agent.controller {
        Some(url) => Some(link::spawn(
            LinkConfig {
                addr: config::controller_addr(url)?,
                tls_dir: cfg.agent.state_dir.join("tls"),
                enroll_token,
                firewall_backend: backend.name(),
            },
            stats.clone(),
        )),
        None => None,
    };
    let mut remote = RemoteBans::default();

    let mut pending = Pending::default();
    let mut flush = tokio::time::interval(FLUSH_INTERVAL);
    flush.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut prune = tokio::time::interval(Duration::from_secs(60));
    let mut sigterm = signal(SignalKind::terminate())?;
    let ctrl_c = tokio::signal::ctrl_c();
    tokio::pin!(ctrl_c);

    loop {
        tokio::select! {
            msg = rx.recv() => {
                let Some(batch) = msg else {
                    warn!("all sources stopped");
                    break;
                };
                let now = Utc::now();
                let mut entries = Vec::new();
                for line in &batch.lines {
                    for action in engine.process(line, now) {
                        info!(
                            jail = %action.jail,
                            target = %action.key,
                            offense = action.offense,
                            duration = ?action.duration,
                            "ban"
                        );
                        entries.push(BanEntry { net: action.key.net(), timeout: Some(action.duration) });
                        pending.set_offender(action.record());
                        if let Some(l) = &link {
                            let obs = v1::Observation {
                                key: action.key.to_string(),
                                jail: action.jail.clone(),
                                count: action.failures,
                                last_seen_unix_ms: now.timestamp_millis(),
                                locally_banned: true,
                                local_ban_expires_unix_ms: action.until.timestamp_millis(),
                                ..Default::default()
                            };
                            if l.reports.try_send(obs).is_err() {
                                warn!("controller report queue full, dropping report");
                            }
                        }
                    }
                }
                if let Some(position) = batch.position {
                    pending.set_position(&batch.source, position);
                }
                if !entries.is_empty() {
                    // one firewall transaction per batch
                    let b = backend.clone();
                    tokio::task::spawn_blocking(move || {
                        if let Err(e) = b.ban(&entries) {
                            error!(count = entries.len(), error = %e, "ban failed");
                        }
                    });
                }
            }
            ev = next_event(&mut link) => {
                let Some(ev) = ev else {
                    // link task gave up (logged); continue standalone
                    link = None;
                    continue;
                };
                let now = Utc::now();
                let changes = remote.apply(ev, now, |net| engine.is_banned(net, now));
                for net in &changes.lift {
                    for r in engine.lift(net, now) {
                        info!(jail = %r.jail, target = %r.key, "local ban lifted by controller");
                        pending.set_offender(r);
                    }
                }
                apply_remote(&backend, changes);
            }
            _ = flush.tick() => {
                stats.active_bans.store(
                    (engine.active_bans(Utc::now()) + remote.len()) as u64,
                    Ordering::Relaxed,
                );
                if let Err(e) = state.flush_async(std::mem::take(&mut pending)).await {
                    error!(error = %format!("{e:#}"), "saving state failed");
                }
            }
            _ = prune.tick() => {
                remote.prune(Utc::now());
                for (jail, key) in engine.prune(Utc::now()) {
                    pending.forget_offender(&jail, &key);
                }
            }
            _ = &mut ctrl_c => { info!("interrupted, shutting down"); break; }
            _ = sigterm.recv() => { info!("terminated, shutting down"); break; }
        }
    }
    state
        .flush_async(pending)
        .await
        .context("saving state on shutdown")?;
    Ok(())
}

async fn next_event(link: &mut Option<Link>) -> Option<FromController> {
    match link {
        Some(l) => l.events.recv().await,
        None => std::future::pending().await,
    }
}

/// Applies controller-driven firewall changes in the background (unbans
/// first, so a re-ban of the same prefix in one batch wins).
fn apply_remote(backend: &Arc<dyn FirewallBackend>, c: Changes) {
    if c.ban.is_empty() && c.unban.is_empty() {
        return;
    }
    info!(
        ban = c.ban.len(),
        unban = c.unban.len(),
        "applying controller decisions"
    );
    let b = backend.clone();
    tokio::task::spawn_blocking(move || {
        if !c.unban.is_empty() {
            if let Err(e) = b.unban(&c.unban) {
                error!(count = c.unban.len(), error = %e, "unban failed");
            }
        }
        if !c.ban.is_empty() {
            if let Err(e) = b.ban(&c.ban) {
                error!(count = c.ban.len(), error = %e, "ban failed");
            }
        }
    });
}

fn spawn_source(
    src: &SourceConfig,
    tx: &mpsc::Sender<SourceBatch>,
    positions: &HashMap<String, Position>,
) -> anyhow::Result<()> {
    let name: Arc<str> = Arc::from(src.name.as_str());
    match &src.kind {
        SourceKind::File {
            paths,
            start_at_end,
        } => {
            for path in paths {
                let mut tailer = FileTailer::new(name.clone(), path.clone(), *start_at_end);
                if let Some(Position::File {
                    dev, ino, offset, ..
                }) = positions.get(&state::file_position_key(&src.name, path))
                {
                    info!(source = %src.name, path = %path.display(), offset, "resuming file");
                    tailer = tailer.with_position(*dev, *ino, *offset);
                }
                let tx = tx.clone();
                let n = name.clone();
                tokio::spawn(async move {
                    if let Err(e) = tailer.run(tx).await {
                        error!(source = %n, error = %e, "file source failed");
                    }
                });
            }
        }
        SourceKind::Journald {
            matches,
            directory,
            start,
        } => {
            #[cfg(feature = "journald")]
            {
                use crate::config::JournalStart;
                use df2b_sources::journald::Start;
                let start = match *start {
                    JournalStart::Tail => Start::Tail,
                    JournalStart::Head => Start::Head,
                    JournalStart::Since(d) => Start::Since(d),
                };
                let cursor = match positions.get(&state::journald_position_key(&src.name)) {
                    Some(Position::JournalCursor(c)) => {
                        info!(source = %src.name, "resuming journal from saved cursor");
                        Some(c.clone())
                    }
                    _ => None,
                };
                df2b_sources::JournaldSource::new(name, matches.clone())
                    .with_directory(directory.clone())
                    .with_start(start)
                    .with_cursor(cursor)
                    .spawn(tx.clone())
                    .with_context(|| format!("source '{}'", src.name))?;
            }
            #[cfg(not(feature = "journald"))]
            {
                let _ = (matches, directory, start, positions);
                anyhow::bail!(
                    "source '{}': this build has no journald support (enable feature `journald`)",
                    src.name
                );
            }
        }
    }
    Ok(())
}
