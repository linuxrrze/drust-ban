//! dist-f2b agent.
//!
//! Milestone 1 (standalone): sources → engine → firewall backend, with
//! source positions and offenders persisted in redb.
//! TODO: local control socket for `df2bctl --local`, controller connection
//! (heartbeat, observations, decision stream), reconcile loop.

mod config;
mod engine;
mod state;
mod tracker;

use std::collections::HashMap;
use std::io::IsTerminal;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use chrono::Utc;
use clap::Parser;
use df2b_firewall::{BanEntry, DryRun, FirewallBackend, Nftables};
use df2b_sources::{FileTailer, Position, SourceBatch};
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::mpsc;
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

use crate::config::{AgentConfig, FirewallKind, SourceConfig, SourceKind};
use crate::engine::Engine;
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

    if args.check {
        println!(
            "configuration OK: {} source(s), {} jail(s)",
            cfg.source.len(),
            engine.jail_count()
        );
        return Ok(());
    }
    if cfg.agent.controller.is_some() {
        warn!("controller connection not implemented yet, running standalone");
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
            _ = flush.tick() => {
                if let Err(e) = state.flush_async(std::mem::take(&mut pending)).await {
                    error!(error = %format!("{e:#}"), "saving state failed");
                }
            }
            _ = prune.tick() => {
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
