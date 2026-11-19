//! Configuration check and reload: `df2bctl --local config check|reload`,
//! and SIGHUP for reload.
//!
//! A reload reads the configuration file the agent was started with and
//! applies it while running: local jails (filters read again; offense
//! history and counted failures of jails that stay are kept; bans of
//! removed jails end), local sources (changed or removed ones stop, new
//! ones start, unchanged ones keep running), the allowlist (bans
//! overlapping it are lifted), redaction rules, `send_samples`,
//! `offense_memory` and the `central_*` settings (central jails are applied
//! again). If the file or a filter is invalid nothing changes. Settings
//! that need a restart keep their running values and are named in the
//! answer.

use std::path::Path;
use std::sync::Arc;

use chrono::Utc;
use df2b_firewall::FirewallBackend;
use df2b_sources::SourceBatch;
use serde_json::{json, Value};
use tokio::sync::mpsc;
use tracing::info;

use crate::central::CentralJails;
use crate::config::{AgentConfig, AgentSection};
use crate::engine::Engine;
use crate::link::LinkStats;
use crate::remote::{Changes, RemoteBans};
use crate::state::{CentralRedaction, JailPolicies, ManualBan, Pending, State};
use crate::{CentralSources, LocalSources};

/// Settings that only take effect after a restart.
fn restart_needed(old: &AgentSection, new: &AgentSection) -> Vec<&'static str> {
    let mut out = Vec::new();
    if old.controller != new.controller {
        out.push("controller");
    }
    if old.state_dir != new.state_dir {
        out.push("state_dir");
    }
    if old.firewall != new.firewall {
        out.push("firewall");
    }
    if old.firewall_exec != new.firewall_exec {
        out.push("firewall_exec");
    }
    if old.control_socket_path() != new.control_socket_path() {
        out.push("control_socket");
    }
    if old.ipv4_prefix != new.ipv4_prefix {
        out.push("ipv4_prefix");
    }
    if old.ipv6_prefix != new.ipv6_prefix {
        out.push("ipv6_prefix");
    }
    out
}

/// Keeps the running values of settings that need a restart.
fn keep_running(old: &AgentSection, new: &mut AgentSection) {
    new.controller.clone_from(&old.controller);
    new.state_dir.clone_from(&old.state_dir);
    new.firewall = old.firewall;
    new.firewall_exec.clone_from(&old.firewall_exec);
    new.control_socket.clone_from(&old.control_socket);
    new.ipv4_prefix = old.ipv4_prefix;
    new.ipv6_prefix = old.ipv6_prefix;
}

/// Added / removed / changed, by name.
fn by_name<'a, T: PartialEq>(old: &'a [T], new: &'a [T], name: impl Fn(&T) -> &str) -> Value {
    let find = |list: &'a [T], n: &str| list.iter().find(|x| name(x) == n);
    let added: Vec<&str> = new
        .iter()
        .map(&name)
        .filter(|n| find(old, n).is_none())
        .collect();
    let removed: Vec<&str> = old
        .iter()
        .map(&name)
        .filter(|n| find(new, n).is_none())
        .collect();
    let changed: Vec<&str> = new
        .iter()
        .filter(|x| find(old, name(x)).is_some_and(|o| o != *x))
        .map(&name)
        .collect();
    json!({ "added": added, "removed": removed, "changed": changed })
}

pub fn diff(old: &AgentConfig, new: &AgentConfig) -> Value {
    json!({
        "jails": by_name(&old.jail, &new.jail, |j| j.name.as_str()),
        "sources": by_name(&old.source, &new.source, |s| s.name.as_str()),
        "allowlist": old.agent.allowlist != new.agent.allowlist,
        "redact": old.redact != new.redact,
        "restart_needed": restart_needed(&old.agent, &new.agent),
    })
}

fn load(path: &Path) -> Result<(AgentConfig, Engine), String> {
    let new = AgentConfig::load(path).map_err(|e| format!("{e:#}"))?;
    // compiles every filter
    let engine = Engine::from_config(&new).map_err(|e| format!("{e:#}"))?;
    Ok((new, engine))
}

/// Reads and checks the file; changes nothing.
pub fn check(path: &Path, running: &AgentConfig) -> Result<Value, String> {
    let (new, engine) = load(path)?;
    Ok(json!({
        "path": path.display().to_string(),
        "jails": engine.jail_count(),
        "sources": new.source.len(),
        "changes": diff(running, &new),
    }))
}

/// What the reload works on (borrowed from the main loop).
pub struct Live<'a> {
    pub path: &'a Path,
    pub cfg: &'a mut AgentConfig,
    pub engine: &'a mut Engine,
    pub central_jails: &'a CentralJails,
    pub jail_policies: &'a JailPolicies,
    pub redaction: &'a CentralRedaction,
    pub local_sources: &'a mut LocalSources,
    pub central_sources: &'a mut CentralSources,
    pub src_tx: &'a mpsc::Sender<SourceBatch>,
    pub state: &'a State,
    pub pending: &'a mut Pending,
    pub backend: &'a Arc<dyn FirewallBackend>,
    pub remote: &'a RemoteBans,
    pub manual: &'a [ManualBan],
    pub stats: &'a LinkStats,
    pub with_controller: bool,
    /// Used if the saved positions cannot be read.
    pub startup_positions: &'a std::collections::HashMap<String, df2b_sources::Position>,
}

pub async fn reload(l: Live<'_>) -> Result<Value, String> {
    let (mut new, _) = load(l.path)?;
    let changes = diff(l.cfg, &new);
    keep_running(&l.cfg.agent, &mut new.agent);
    let now = Utc::now();
    let ended = l
        .engine
        .reload_local(&new, now)
        .map_err(|e| format!("{e:#}"))?;

    // bans of removed jails and bans the allowlist now covers end, unless
    // something else still bans that prefix
    for (jail, key) in &ended.forgotten {
        l.pending.forget_offender(jail, key);
    }
    let mut unban = ended.ended;
    for r in l.engine.lift_allowlisted(now) {
        info!(jail = %r.jail, target = %r.key, "local ban lifted: allowlisted");
        unban.push(r.key.net());
        l.pending.set_offender(r);
    }
    unban.sort();
    unban.dedup();
    unban.retain(|net| {
        !l.remote.covers(net)
            && !l.engine.is_banned(net, now)
            && !l
                .manual
                .iter()
                .any(|m| m.target == *net && m.until.map_or(true, |u| u > now))
    });
    let lifted = unban.len();
    crate::apply_remote(
        l.backend,
        Changes {
            unban,
            ..Default::default()
        },
    );

    // central jails again: names may clash with local jails differently,
    // and the central_* settings may have changed
    let (accepted, rejected) = crate::central::split(&new.agent, l.central_jails);
    let running = l
        .engine
        .set_central_jails(&accepted, &l.central_jails.filters, rejected);
    l.engine.apply_jail_overrides(&l.jail_policies.jails);
    if new.agent.central_redaction {
        crate::apply_central_redaction(l.engine, l.redaction);
    }
    if let Ok(mut v) = l.stats.redaction_version.lock() {
        *v = if new.agent.central_redaction {
            l.redaction.version.clone()
        } else {
            "off".into()
        };
    }
    if l.with_controller {
        l.engine.collect_observations(new.agent.send_samples);
    }

    // sources resume from the positions saved up to now
    let positions = crate::current_positions(l.state, l.pending, l.startup_positions).await;
    let local = l
        .local_sources
        .update(&new.source, l.src_tx, &positions, &l.stats.sources);
    let central = l.central_sources.update(
        l.central_jails,
        &running,
        l.src_tx,
        &positions,
        &l.stats.sources,
        &new.agent.central_paths,
    );

    *l.cfg = new;
    let failed: Vec<Value> = local
        .failed
        .iter()
        .chain(&central.failed)
        .map(|(n, e)| json!({ "source": n, "error": e }))
        .collect();
    info!(
        jails = l.engine.jail_count(),
        sources_started = local.started.len() + central.started.len(),
        sources_stopped = local.stopped.len() + central.stopped.len(),
        bans_lifted = lifted,
        "configuration reloaded"
    );
    Ok(json!({
        "path": l.path.display().to_string(),
        "jails": l.engine.jail_count(),
        "changes": changes,
        "sources_started": ([local.started, central.started].concat()),
        "sources_stopped": ([local.stopped, central.stopped].concat()),
        "sources_failed": failed,
        "bans_lifted": lifted,
    }))
}
