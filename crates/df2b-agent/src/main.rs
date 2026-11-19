//! dist-f2b agent.
//!
//! sources → engine → firewall backend, with source positions and offenders
//! persisted in redb. With a controller configured: local bans are reported
//! and the controller's decisions are applied (see link.rs). The firewall
//! is reconciled with the known bans periodically (reconcile.rs);
//! `df2bctl --local` talks to the agent over control.rs.

mod central;
mod config;
mod control;
mod engine;
mod health;
mod link;
mod outbox;
mod reconcile;
mod reload;
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
use df2b_sources::{FileSource, Position, SourceBatch};
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
    let mut cfg = AgentConfig::load(&args.config)?;
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
    let mut loaded = state.load()?;
    // jails defined on the controller, as last received: set up before the
    // offender records are restored, so their bans come back too
    let mut central_jails = loaded.central_jails.clone().unwrap_or_default();
    let running_central = {
        let (accepted, rejected) = central::split(&cfg.agent, &central_jails);
        engine.set_central_jails(&accepted, &central_jails.filters, rejected)
    };
    let mut pending = Pending::default();
    // positions of sources and files nobody will resume from
    {
        let central_cfgs: Vec<SourceConfig> = central_jails
            .jails
            .iter()
            .filter_map(|j| j.source_configs().ok())
            .flatten()
            .collect();
        let known: Vec<state::KnownSource> = cfg
            .source
            .iter()
            .chain(&central_cfgs)
            .map(|s| match &s.kind {
                SourceKind::File { paths, .. } => state::KnownSource::Files(&s.name, paths),
                SourceKind::Journald { .. } => state::KnownSource::Journald(&s.name),
            })
            .collect();
        let stale = state::stale_positions(&loaded.positions, &known);
        if !stale.is_empty() {
            info!(
                count = stale.len(),
                "dropping saved positions of sources and files that are gone"
            );
        }
        for key in stale {
            loaded.positions.remove(&key);
            pending.forget_position(key);
        }
    }
    let mut restored = engine.restore(std::mem::take(&mut loaded.offenders), Utc::now());
    // the controller's jail settings as last received
    let mut jail_policies = loaded.jail_policies.clone().unwrap_or_default();
    engine.apply_jail_overrides(&jail_policies.jails);
    // the controller's allowlist as last received: applies before the
    // controller is reachable again
    // the controller's redaction rules as last received: samples sent
    // before the stream delivers them are redacted too
    let mut redaction = loaded.central_redaction.clone().unwrap_or_default();
    if cfg.agent.central_redaction {
        apply_central_redaction(&mut engine, &redaction);
    }
    let mut central = loaded.central_allowlist.clone().unwrap_or_default();
    engine.set_central_allowlist(central.live(Utc::now()));
    for r in engine.lift_allowlisted(Utc::now()) {
        restored.retain(|(key, _)| *key != r.key);
        pending.set_offender(r);
    }
    info!(
        path = %state.path().display(),
        positions = loaded.positions.len(),
        active_bans = restored.len(),
        central_allowlist = central.live(Utc::now()).len(),
        "state loaded"
    );

    let stats = Arc::new(LinkStats::default());
    let inner: Arc<dyn FirewallBackend> = match cfg.agent.firewall {
        FirewallKind::Nftables => Arc::new(Nftables::default()),
        FirewallKind::Ipset => Arc::new(df2b_firewall::Ipset::default()),
        FirewallKind::Exec => Arc::new(df2b_firewall::Exec::new(cfg.agent.firewall_exec.clone())?),
        FirewallKind::DryRun => Arc::new(DryRun),
    };
    // every call's outcome goes into the heartbeats
    let backend: Arc<dyn FirewallBackend> = Arc::new(health::Monitored {
        inner,
        health: stats.firewall.clone(),
    });
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
    // bans made with `df2bctl --local ban`
    let mut manual = loaded.manual_bans.clone();
    manual.retain(|m| m.until.map_or(true, |u| u > Utc::now()));
    if !manual.is_empty() {
        let now = Utc::now();
        let entries: Vec<_> = manual
            .iter()
            .map(|m| BanEntry {
                net: m.target,
                timeout: m
                    .until
                    .map(|u| (u - now).to_std().unwrap_or(Duration::from_secs(1))),
            })
            .collect();
        let b = backend.clone();
        tokio::task::spawn_blocking(move || b.ban(&entries))
            .await?
            .context("re-applying manual bans")?;
        info!(count = manual.len(), "re-applied manual bans");
    }

    // Bounded in batches (each up to BATCH_MAX lines): a slow engine throttles
    // the sources instead of buffering without limit.
    let (tx, mut rx) = mpsc::channel::<SourceBatch>(64);
    let mut local_sources = LocalSources::default();
    let started = local_sources.update(&cfg.source, &tx, &loaded.positions, &stats.sources);
    if let Some((name, e)) = started.failed.first() {
        anyhow::bail!("source '{name}': {e}");
    }
    // kept: central jails start sources later (and an agent without local
    // sources must keep running)
    let src_tx = tx;
    let mut central_sources = CentralSources::default();
    central_sources.update(
        &central_jails,
        &running_central,
        &src_tx,
        &loaded.positions,
        &stats.sources,
        &cfg.agent.central_paths,
    );

    if let Ok(mut v) = stats.allowlist_version.lock() {
        v.clone_from(&central.version);
    }
    if let Ok(mut v) = stats.redaction_version.lock() {
        *v = if cfg.agent.central_redaction {
            redaction.version.clone()
        } else {
            "off".into()
        };
    }
    if let Ok(mut v) = stats.jail_policies_version.lock() {
        v.clone_from(&jail_policies.version);
    }
    if let Ok(mut v) = stats.central_jails_version.lock() {
        v.clone_from(&central_jails.version);
    }
    let mut link: Option<Link> = match &cfg.agent.controller {
        Some(url) => Some(link::spawn(
            LinkConfig {
                addr: config::controller_addr(url)?,
                tls_dir: cfg.agent.state_dir.join("tls"),
                enroll_token,
                firewall_backend: backend.name(),
                state: state.clone(),
            },
            stats.clone(),
        )),
        None => None,
    };
    let mut remote = RemoteBans::default();
    // failures for the controller's correlation rules (DESIGN.md §4.1)
    if link.is_some() {
        engine.collect_observations(cfg.agent.send_samples);
    }
    let mut observe = tokio::time::interval(OBSERVATION_INTERVAL);
    observe.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    let mut flush = tokio::time::interval(FLUSH_INTERVAL);
    flush.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut prune = tokio::time::interval(Duration::from_secs(60));
    let mut reconcile_tick = tokio::time::interval_at(
        tokio::time::Instant::now() + reconcile::INTERVAL,
        reconcile::INTERVAL,
    );
    reconcile_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let reconciling = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let mut control = match cfg.agent.control_socket_path() {
        Some(p) => match control::spawn(&p) {
            Ok(s) => Some(s),
            Err(e) => {
                warn!(error = %format!("{e:#}"), "no control socket (df2bctl --local)");
                None
            }
        },
        None => None,
    };
    let controller_addr = cfg.agent.controller.clone();
    let mut sigterm = signal(SignalKind::terminate())?;
    let mut sighup = signal(SignalKind::hangup())?;
    let with_controller = link.is_some();
    // what a configuration reload works on
    macro_rules! live {
        () => {
            reload::Live {
                path: &args.config,
                cfg: &mut cfg,
                engine: &mut engine,
                central_jails: &central_jails,
                jail_policies: &jail_policies,
                redaction: &redaction,
                local_sources: &mut local_sources,
                central_sources: &mut central_sources,
                src_tx: &src_tx,
                state: &state,
                pending: &mut pending,
                backend: &backend,
                remote: &remote,
                manual: &manual,
                stats: &stats,
                with_controller,
                startup_positions: &loaded.positions,
            }
        };
    }
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
                stats.sources.record(&batch, now);
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
                                sample: if cfg.agent.send_samples {
                                    engine.sample(&action.sample)
                                } else {
                                    String::new()
                                },
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
                if let Some(path) = &batch.gone {
                    info!(source = %batch.source, path = %path.display(), "file gone, dropping its position");
                    pending.forget_position(state::file_position_key(&batch.source, path));
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
                if let FromController::CentralJails(c) = ev {
                    let (accepted, rejected) = central::split(&cfg.agent, &c);
                    let running = engine.set_central_jails(&accepted, &c.filters, rejected);
                    // the policies apply to central jails as well
                    engine.apply_jail_overrides(&jail_policies.jails);
                    // (re)started sources resume from the positions saved up
                    // to now, not those loaded at startup
                    let positions = current_positions(&state, &mut pending, &loaded.positions).await;
                    central_sources.update(
                        &c,
                        &running,
                        &src_tx,
                        &positions,
                        &stats.sources,
                        &cfg.agent.central_paths,
                    );
                    if c.version != central_jails.version {
                        info!(version = %c.version, defined = c.jails.len(), running = running.len(), "central jails applied");
                        let (st, saved) = (state.clone(), c.clone());
                        tokio::task::spawn_blocking(move || {
                            if let Err(e) = st.save_central_jails(&saved) {
                                error!(error = %format!("{e:#}"), "saving the central jails failed");
                            }
                        });
                    }
                    if let Ok(mut v) = stats.central_jails_version.lock() {
                        v.clone_from(&c.version);
                    }
                    central_jails = c;
                    continue;
                }
                if let FromController::Redaction(r) = ev {
                    if !cfg.agent.central_redaction {
                        continue;
                    }
                    apply_central_redaction(&mut engine, &r);
                    if r != redaction {
                        info!(version = %r.version, rules = r.rules.len(), "central redaction rules applied");
                        let (st, saved) = (state.clone(), r.clone());
                        tokio::task::spawn_blocking(move || {
                            if let Err(e) = st.save_central_redaction(&saved) {
                                error!(error = %format!("{e:#}"), "saving the redaction rules failed");
                            }
                        });
                    }
                    if let Ok(mut v) = stats.redaction_version.lock() {
                        v.clone_from(&r.version);
                    }
                    redaction = r;
                    continue;
                }
                if let FromController::JailPolicies(p) = ev {
                    engine.apply_jail_overrides(&p.jails);
                    if p.version != jail_policies.version {
                        info!(version = %p.version, jails = p.jails.len(), "jail policies applied");
                        let (st, saved) = (state.clone(), p.clone());
                        tokio::task::spawn_blocking(move || {
                            if let Err(e) = st.save_jail_policies(&saved) {
                                error!(error = %format!("{e:#}"), "saving the jail policies failed");
                            }
                        });
                    }
                    if let Ok(mut v) = stats.jail_policies_version.lock() {
                        v.clone_from(&p.version);
                    }
                    jail_policies = p;
                    continue;
                }
                if let FromController::Allowlist(list) = ev {
                    apply_central_allowlist(
                        &mut engine, &remote, &backend, &state, &mut pending, &mut central, list,
                    );
                    if let Ok(mut v) = stats.allowlist_version.lock() {
                        v.clone_from(&central.version);
                    }
                    continue;
                }
                let mut changes = remote.apply(ev, now, |net| engine.is_banned(net, now));
                changes.ban.retain(|b| {
                    let refuse = engine.refuses_remote(&b.net) || stats.covers_controller(&b.net);
                    if refuse {
                        warn!(target = %b.net, "refusing a controller ban: allowlisted here or too broad");
                    }
                    !refuse
                });
                for net in &changes.lift {
                    for r in engine.lift(net, now) {
                        info!(jail = %r.jail, target = %r.key, "local ban lifted by controller");
                        pending.set_offender(r);
                    }
                }
                apply_remote(&backend, changes);
            }
            _ = observe.tick() => {
                if let Some(l) = &link {
                    let mut full = 0usize;
                    for (jail, key, o) in engine.take_observations() {
                        let obs = v1::Observation {
                            key: key.to_string(),
                            jail,
                            count: o.failures,
                            first_seen_unix_ms: o.first.timestamp_millis(),
                            last_seen_unix_ms: o.last.timestamp_millis(),
                            sample: o.sample.unwrap_or_default(),
                            ..Default::default()
                        };
                        if l.reports.try_send(obs).is_err() {
                            full += 1;
                        }
                    }
                    if full > 0 {
                        warn!(dropped = full, "controller report queue full, dropping failure counts");
                    }
                }
            }
            _ = flush.tick() => {
                stats.active_bans.store(
                    (engine.active_bans(Utc::now()) + remote.len()) as u64,
                    Ordering::Relaxed,
                );
                if let Ok(mut j) = stats.jails.lock() {
                    *j = engine.jail_status(Utc::now()).into_iter().map(jail_status).collect();
                }
                if let Err(e) = state.flush_async(std::mem::take(&mut pending)).await {
                    error!(error = %format!("{e:#}"), "saving state failed");
                }
            }
            _ = prune.tick() => {
                // the outcome lands in the firewall health (heartbeats)
                let b = backend.clone();
                tokio::spawn(async move {
                    if let Ok(Err(e)) = tokio::task::spawn_blocking(move || b.check()).await {
                        error!(error = %format!("{e:#}"), "firewall check failed");
                    }
                });
                // temporary allowlist entries end here as well (also offline)
                engine.set_central_allowlist(central.live(Utc::now()));
                remote.prune(Utc::now());
                let n = manual.len();
                manual.retain(|m| m.until.map_or(true, |u| u > Utc::now()));
                if manual.len() != n {
                    let (st, m) = (state.clone(), manual.clone());
                    tokio::task::spawn_blocking(move || {
                        if let Err(e) = st.save_manual_bans(&m) {
                            error!(error = %format!("{e:#}"), "saving manual bans failed");
                        }
                    });
                }
                for (jail, key) in engine.prune(Utc::now()) {
                    pending.forget_offender(&jail, &key);
                }
            }
            call = next_call(&mut control) => {
                if matches!(call.req, control::Request::ConfigCheck) {
                    let _ = call.reply.send(reload::check(&args.config, &cfg));
                    continue;
                }
                if matches!(call.req, control::Request::ConfigReload) {
                    info!(peer = %call.peer, "configuration reload requested");
                    let r = reload::reload(live!()).await;
                    if let Err(e) = &r {
                        error!(error = %e, "configuration reload failed, nothing changed");
                    }
                    let _ = call.reply.send(r);
                    continue;
                }
                let cx = control::Ctx {
                    engine: &mut engine,
                    remote: &remote,
                    backend: &backend,
                    pending: &mut pending,
                    state: &state,
                    stats: &stats,
                    manual: &mut manual,
                    controller: controller_addr.as_deref(),
                };
                let r = control::handle(call.req, &call.peer, cx).await;
                let _ = call.reply.send(r);
            }
            _ = reconcile_tick.tick() => {
                if reconciling.swap(true, Ordering::AcqRel) {
                    continue; // the previous round is still running
                }
                let now = Utc::now();
                let mut expected = reconcile::Expected::default();
                for (_, key, _, until) in engine.bans(now) {
                    expected.add(key.net(), Some(until));
                }
                for m in manual.iter().filter(|m| m.until.map_or(true, |u| u > now)) {
                    expected.add(m.target, m.until);
                }
                for (target, until, _) in remote.list(now) {
                    if !engine.refuses_remote(&target) && !stats.covers_controller(&target) {
                        expected.add(target, until);
                    }
                }
                let (b, flag) = (backend.clone(), reconciling.clone());
                tokio::spawn(async move {
                    let r = tokio::task::spawn_blocking(move || reconcile::run(&b, &expected, now)).await;
                    if let Ok(Err(e)) = r {
                        warn!(error = %format!("{e:#}"), "reconciling the firewall failed");
                    }
                    flag.store(false, Ordering::Release);
                });
            }
            _ = &mut ctrl_c => { info!("interrupted, shutting down"); break; }
            _ = sighup.recv() => {
                info!("SIGHUP: reloading the configuration");
                if let Err(e) = reload::reload(live!()).await {
                    error!(error = %e, "configuration reload failed, nothing changed");
                }
            }
            _ = sigterm.recv() => { info!("terminated, shutting down"); break; }
        }
    }
    if let Some(l) = link {
        l.shutdown(Duration::from_secs(5)).await;
    }
    state
        .flush_async(pending)
        .await
        .context("saving state on shutdown")?;
    Ok(())
}

/// Saves pending changes and reads the source positions as saved now
/// (startup positions on failure, logged).
async fn current_positions(
    state: &State,
    pending: &mut Pending,
    fallback: &HashMap<String, Position>,
) -> HashMap<String, Position> {
    if let Err(e) = state.flush_async(std::mem::take(pending)).await {
        error!(error = %format!("{e:#}"), "saving state failed");
    }
    let st = state.clone();
    match tokio::task::spawn_blocking(move || st.positions()).await {
        Ok(Ok(p)) => p,
        Ok(Err(e)) => {
            error!(error = %format!("{e:#}"), "reading saved positions failed");
            fallback.clone()
        }
        Err(e) => {
            error!(error = %e, "reading saved positions failed");
            fallback.clone()
        }
    }
}

/// The next `df2bctl --local` request; never, without a control socket.
async fn next_call(control: &mut Option<control::Socket>) -> control::Call {
    match control {
        Some(s) => match s.calls.recv().await {
            Some(c) => c,
            None => std::future::pending().await,
        },
        None => std::future::pending().await,
    }
}

/// Applies the controller's redaction rules after the local ones; rules
/// this agent cannot compile are left out (logged): the controller redacts
/// again on arrival.
fn apply_central_redaction(engine: &mut Engine, r: &state::CentralRedaction) {
    let (redactor, errors) = df2b_core::Redactor::lenient(&r.rules);
    for e in errors {
        warn!(error = %e, "ignoring a central redaction rule");
    }
    engine.set_central_redaction(&redactor);
}

/// Replaces the controller's allowlist: no new bans there, active local bans
/// overlapping it are lifted (the firewall entry stays if a controller ban
/// still covers that prefix), and the list is saved for restarts.
fn apply_central_allowlist(
    engine: &mut Engine,
    remote: &RemoteBans,
    backend: &Arc<dyn FirewallBackend>,
    state: &State,
    pending: &mut Pending,
    current: &mut state::CentralAllowlist,
    list: state::CentralAllowlist,
) {
    let now = Utc::now();
    engine.set_central_allowlist(list.live(now));
    let mut unban = Vec::new();
    for r in engine.lift_allowlisted(now) {
        info!(jail = %r.jail, target = %r.key, "local ban lifted: allowlisted by the controller");
        let net = r.key.net();
        if !remote.covers(&net) && !unban.contains(&net) {
            unban.push(net);
        }
        pending.set_offender(r);
    }
    apply_remote(
        backend,
        Changes {
            unban,
            ..Default::default()
        },
    );
    if list.version != current.version {
        info!(
            version = %list.version,
            entries = list.networks.len(),
            temporary = list.expires_at.iter().filter(|e| e.is_some()).count(),
            "central allowlist applied"
        );
        let st = state.clone();
        let saved = list.clone();
        tokio::task::spawn_blocking(move || {
            if let Err(e) = st.save_central_allowlist(&saved) {
                error!(error = %format!("{e:#}"), "saving the central allowlist failed");
            }
        });
    }
    *current = list;
}

fn jail_status(j: engine::JailStatus) -> v1::JailStatus {
    let ms = |d: Duration| i64::try_from(d.as_millis()).unwrap_or(i64::MAX);
    v1::JailStatus {
        name: j.name,
        filter: j.filter,
        enabled: j.params.enabled,
        maxretry: j.params.maxretry,
        findtime_ms: ms(j.params.findtime),
        bantime_ms: ms(j.params.bantime),
        bantime_factor: j.params.factor,
        max_bantime_ms: j.params.max_bantime.map_or(0, ms),
        overridden: j.overridden.into_iter().map(str::to_owned).collect(),
        active_bans: j.active_bans as u64,
        origin: j.origin.into(),
        error: j.error,
        tracked: j.tracked as u64,
        evicted: j.evicted,
    }
}

/// How often failure counts are sent to the controller.
const OBSERVATION_INTERVAL: Duration = Duration::from_secs(5);

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

/// Running sources by name: the definition they were started from (to see
/// changes) and their tasks.
struct RunningSources<D>(HashMap<String, (D, Vec<tokio::task::JoinHandle<()>>)>);

impl<D> Default for RunningSources<D> {
    fn default() -> Self {
        Self(HashMap::new())
    }
}

/// What a source update did, by source name.
#[derive(Debug, Default)]
struct SourceChanges {
    started: Vec<String>,
    stopped: Vec<String>,
    /// (name, error)
    failed: Vec<(String, String)>,
}

impl<D: PartialEq> RunningSources<D> {
    /// Stops sources that are gone or changed, starts new ones; unchanged
    /// sources keep running (and their read position). `what`: "local" or
    /// "central", for logs.
    fn sync(
        &mut self,
        wanted: Vec<(D, SourceConfig)>,
        tx: &mpsc::Sender<SourceBatch>,
        positions: &HashMap<String, Position>,
        health: &health::SourceHealth,
        what: &str,
        roots: &[PathBuf],
    ) -> SourceChanges {
        let mut out = SourceChanges::default();
        self.0.retain(|name, (def, tasks)| {
            let keep = wanted.iter().any(|(w, cfg)| cfg.name == *name && w == def);
            if !keep {
                for t in tasks.iter() {
                    t.abort();
                }
                health.stop(name);
                info!(source = %name, "{what} source stopped");
                out.stopped.push(name.clone());
            }
            keep
        });
        for (def, cfg) in wanted {
            if self.0.contains_key(&cfg.name) {
                continue;
            }
            match spawn_owned_source(&cfg, tx, positions, health, roots) {
                Ok(tasks) => {
                    info!(source = %cfg.name, "{what} source started");
                    out.started.push(cfg.name.clone());
                    self.0.insert(cfg.name, (def, tasks));
                }
                Err(e) => {
                    error!(source = %cfg.name, error = %format!("{e:#}"), "{what} source failed");
                    health.errors.set(&cfg.name, format!("{e:#}"));
                    out.failed.push((cfg.name, format!("{e:#}")));
                }
            }
        }
        out
    }
}

/// Sources of the local configuration.
type LocalSources = RunningSources<SourceConfig>;

impl LocalSources {
    fn update(
        &mut self,
        sources: &[SourceConfig],
        tx: &mpsc::Sender<SourceBatch>,
        positions: &HashMap<String, Position>,
        health: &health::SourceHealth,
    ) -> SourceChanges {
        let wanted = sources.iter().map(|s| (s.clone(), s.clone())).collect();
        self.sync(wanted, tx, positions, health, "local", &[])
    }
}

/// Sources of central jails.
type CentralSources = RunningSources<central::CentralSource>;

impl CentralSources {
    fn update(
        &mut self,
        jails: &central::CentralJails,
        running: &[String],
        tx: &mpsc::Sender<SourceBatch>,
        positions: &HashMap<String, Position>,
        health: &health::SourceHealth,
        // files must really be below these (central_paths)
        roots: &[PathBuf],
    ) -> SourceChanges {
        let mut wanted = Vec::new();
        for j in jails.jails.iter().filter(|j| running.contains(&j.name)) {
            if let Ok(cfgs) = j.source_configs() {
                for (def, cfg) in j.sources.iter().zip(cfgs) {
                    if !wanted
                        .iter()
                        .any(|(_, c): &(_, SourceConfig)| c.name == cfg.name)
                    {
                        wanted.push((def.clone(), cfg));
                    }
                }
            }
        }
        self.sync(wanted, tx, positions, health, "central", roots)
    }
}

/// A source with its own channel: aborting the tasks drops the receiver,
/// which also stops journald readers (they notice the closed channel).
fn spawn_owned_source(
    src: &SourceConfig,
    tx: &mpsc::Sender<SourceBatch>,
    positions: &HashMap<String, Position>,
    health: &health::SourceHealth,
    roots: &[PathBuf],
) -> anyhow::Result<Vec<tokio::task::JoinHandle<()>>> {
    let (own_tx, mut own_rx) = mpsc::channel::<SourceBatch>(16);
    let mut tasks = spawn_source(src, &own_tx, positions, health, roots)?;
    let tx = tx.clone();
    tasks.push(tokio::spawn(async move {
        while let Some(b) = own_rx.recv().await {
            if tx.send(b).await.is_err() {
                break;
            }
        }
    }));
    Ok(tasks)
}

fn spawn_source(
    src: &SourceConfig,
    tx: &mpsc::Sender<SourceBatch>,
    positions: &HashMap<String, Position>,
    health: &health::SourceHealth,
    // non-empty: files must really be below these (central sources)
    roots: &[PathBuf],
) -> anyhow::Result<Vec<tokio::task::JoinHandle<()>>> {
    let mut tasks = Vec::new();
    let name: Arc<str> = Arc::from(src.name.as_str());
    health.start(&src.name);
    let errors = health.errors.clone();
    match &src.kind {
        SourceKind::File {
            paths,
            start_at_end,
            timestamps,
        } => {
            for p in paths {
                df2b_sources::file::check_path(p)?;
            }
            let mut files = FileSource::new(name.clone(), paths.clone(), *start_at_end)
                .with_errors(errors.clone())
                .with_timestamps(*timestamps);
            if !roots.is_empty() {
                files = files.with_allowed_roots(roots.to_vec());
            }
            // saved positions of this source: configured paths and glob matches
            for (key, pos) in positions {
                if let Position::File {
                    path,
                    dev,
                    ino,
                    offset,
                } = pos
                {
                    if *key == state::file_position_key(&src.name, path) {
                        files = files.with_position(path.clone(), *dev, *ino, *offset);
                    }
                }
            }
            let (n, tx) = (name.clone(), tx.clone());
            tasks.push(tokio::spawn(async move {
                if let Err(e) = files.run(tx).await {
                    error!(source = %n, error = %e, "file source failed");
                    errors.set(&n, format!("{e:#}"));
                }
            }));
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
                    .with_errors(errors)
                    .spawn(tx.clone())
                    .with_context(|| format!("source '{}'", src.name))?;
            }
            #[cfg(not(feature = "journald"))]
            {
                let _ = (matches, directory, start, positions, errors);
                anyhow::bail!(
                    "source '{}': this build has no journald support (enable feature `journald`)",
                    src.name
                );
            }
        }
    }
    Ok(tasks)
}
