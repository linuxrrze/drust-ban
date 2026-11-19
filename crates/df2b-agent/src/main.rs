//! dist-f2b agent.
//!
//! Milestone 1 (standalone): sources → engine → firewall backend.
//! TODO: redb state, local control socket for `df2bctl --local`,
//! controller connection (heartbeat, observations, decision stream),
//! reconcile loop.

mod config;
mod engine;
mod tracker;

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use chrono::Utc;
use clap::Parser;
use df2b_firewall::{BanEntry, DryRun, FirewallBackend, Nftables};
use df2b_sources::{FileTailer, LogLine};
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

    let (tx, mut rx) = mpsc::channel::<LogLine>(10_000);
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
                let Some(line) = msg else {
                    warn!("all sources stopped");
                    break;
                };
                for action in engine.process(&line, Utc::now()) {
                    info!(
                        jail = %action.jail,
                        target = %action.key,
                        offense = action.offense,
                        duration = ?action.duration,
                        "ban"
                    );
                    let entry = BanEntry { net: action.key.net(), timeout: Some(action.duration) };
                    let b = backend.clone();
                    // TODO: batch bans (collect for a few ms) instead of one transaction each
                    tokio::task::spawn_blocking(move || {
                        if let Err(e) = b.ban(&[entry]) {
                            error!(error = %e, "ban failed");
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

fn spawn_source(src: &SourceConfig, tx: &mpsc::Sender<LogLine>) -> anyhow::Result<()> {
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
        SourceKind::Journald { matches } => {
            #[cfg(feature = "journald")]
            {
                let source = df2b_sources::JournaldSource::new(name.clone(), matches.clone());
                let tx = tx.clone();
                tokio::spawn(async move {
                    if let Err(e) = source.run(tx).await {
                        error!(source = %name, error = %e, "journald source failed");
                    }
                });
            }
            #[cfg(not(feature = "journald"))]
            {
                let _ = matches;
                anyhow::bail!(
                    "source '{}': this build has no journald support (enable feature `journald`)",
                    src.name
                );
            }
        }
    }
    Ok(())
}
