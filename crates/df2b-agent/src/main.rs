//! dist-f2b agent.
//!
//! Milestone 1 (standalone): sources → engine → firewall backend.
//! TODO: redb state, local control socket for `df2bctl --local`,
//! controller connection (heartbeat, observations, decision stream),
//! reconcile loop.

mod config;
mod engine;
mod tracker;

use std::io::IsTerminal;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use chrono::Utc;
use clap::Parser;
use df2b_firewall::{BanEntry, DryRun, FirewallBackend, Nftables};
use df2b_sources::{FileTailer, SourceBatch};
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::mpsc;
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

use crate::config::{AgentConfig, FirewallKind, SourceConfig, SourceKind};
use crate::engine::Engine;

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

    // Bounded in batches (each up to BATCH_MAX lines): a slow engine throttles
    // the sources instead of buffering without limit.
    let (tx, mut rx) = mpsc::channel::<SourceBatch>(64);
    for src in &cfg.source {
        spawn_source(src, &tx)?;
    }
    drop(tx);

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
                    }
                }
                // TODO(redb): persist batch.position (journal cursor / file offset)
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
            _ = prune.tick() => engine.prune(Utc::now()),
            _ = &mut ctrl_c => { info!("interrupted, shutting down"); break; }
            _ = sigterm.recv() => { info!("terminated, shutting down"); break; }
        }
    }
    Ok(())
}

fn spawn_source(src: &SourceConfig, tx: &mpsc::Sender<SourceBatch>) -> anyhow::Result<()> {
    let name: Arc<str> = Arc::from(src.name.as_str());
    match &src.kind {
        SourceKind::File {
            paths,
            start_at_end,
        } => {
            for path in paths {
                let tailer = FileTailer::new(name.clone(), path.clone(), *start_at_end);
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
                // TODO(redb): .with_cursor(saved cursor)
                df2b_sources::JournaldSource::new(name, matches.clone())
                    .with_directory(directory.clone())
                    .with_start(start)
                    .spawn(tx.clone())
                    .with_context(|| format!("source '{}'", src.name))?;
            }
            #[cfg(not(feature = "journald"))]
            {
                let _ = (matches, directory, start);
                anyhow::bail!(
                    "source '{}': this build has no journald support (enable feature `journald`)",
                    src.name
                );
            }
        }
    }
    Ok(())
}
