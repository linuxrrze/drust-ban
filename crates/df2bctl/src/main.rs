//! dist-f2b command line tool.
//!
//! `filter test` (offline), the controller commands over the HTTPS REST
//! API (status, lookup, whoami, audit, agents, sessions, bans, ban, unban,
//! allowlist, jails, correlation, redaction, propagate, filter), and with
//! `--local` the agent on this host over its control socket (status, jails
//! list, bans list, ban, unban, config check|reload).

mod client;
mod commands;
mod filter_test;
mod local;

use std::path::PathBuf;
use std::time::Duration;

use anyhow::bail;
use clap::{Parser, Subcommand, ValueEnum};
use ipnet::IpNet;

#[derive(Debug, Parser)]
#[command(version, about = "Manage dist-f2b agents, bans and policies")]
struct Cli {
    /// Controller REST API, e.g. https://ctl.example.org:7444.
    #[arg(long, global = true, env = "DF2B_CONTROLLER")]
    controller: Option<String>,

    /// API token (df2bapi1.…).
    #[arg(long, global = true, env = "DF2B_API_TOKEN", hide_env_values = true)]
    token: Option<String>,

    /// Pin the controller's internal CA by SHA-256 fingerprint.
    #[arg(long, global = true, env = "DF2B_CA_FINGERPRINT")]
    ca_fingerprint: Option<String>,

    /// Trust these CA certificates (PEM) instead of the public roots.
    #[arg(long, global = true, env = "DF2B_CA_FILE")]
    ca_file: Option<PathBuf>,

    /// Configuration file (default ~/.config/df2b/df2bctl.toml).
    #[arg(long, global = true, env = "DF2B_CTL_CONFIG")]
    config: Option<PathBuf>,

    /// Talk to the agent on this host instead of the controller (status,
    /// jails list, bans list, ban, unban; root or the agent's user).
    #[arg(long, global = true)]
    local: bool,

    /// The agent's control socket (with --local).
    #[arg(long, global = true, env = "DF2B_AGENT_SOCKET", default_value = local::DEFAULT_SOCKET)]
    socket: PathBuf,

    #[arg(long, short, global = true, value_enum, default_value_t = Output::Text)]
    output: Output,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum Output {
    Text,
    Json,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Overall status (controller, agents, ban counts).
    Status,
    /// Everything known about an address or prefix: network (ASN,
    /// country), bans, correlation, sample log lines.
    Lookup {
        #[arg(value_parser = parse_target)]
        target: IpNet,
    },
    /// Show the API token's name and role.
    Whoami,
    /// Show the audit log (admin).
    Audit {
        #[arg(long, default_value_t = 50)]
        limit: usize,
    },
    /// Manage agents.
    #[command(subcommand)]
    Agents(AgentsCmd),
    /// List and end web UI sessions (admin).
    #[command(subcommand)]
    Sessions(SessionsCmd),
    /// List bans.
    #[command(subcommand)]
    Bans(BansCmd),
    /// Ban an address or prefix.
    Ban {
        #[arg(value_parser = parse_target)]
        target: IpNet,
        /// Ban duration, e.g. "24h" (default: permanent).
        #[arg(long = "for", value_parser = humantime::parse_duration)]
        duration: Option<Duration>,
        /// "global", "group:<name>" or "agent:<id>[,<id>...]".
        #[arg(long, default_value = "global")]
        scope: String,
        #[arg(long)]
        jail: Option<String>,
        #[arg(long, default_value = "manual")]
        reason: String,
    },
    /// Remove every active ban overlapping an address or prefix (e.g. the
    /// /64 ban containing an IPv6 address), in the scope it was made.
    Unban {
        #[arg(value_parser = parse_target)]
        target: IpNet,
        #[arg(long)]
        reason: Option<String>,
        /// Then keep it from being banned again for this long, e.g. 24h
        /// (temporary allowlist entry; operators: at most 7d).
        #[arg(long, value_parser = humantime::parse_duration)]
        allow_for: Option<Duration>,
    },
    /// Manage the allowlist.
    #[command(subcommand)]
    Allowlist(AllowlistCmd),
    /// Show jails.
    #[command(subcommand)]
    Jails(JailsCmd),
    /// Correlation rules (DESIGN.md §4.2).
    #[command(subcommand)]
    Correlation(CorrelationCmd),
    /// Rules that rewrite sample log lines on the controller.
    #[command(subcommand)]
    Redaction(RedactionCmd),
    /// Show or set (admin) where agents' local bans apply: global, group or
    /// off.
    Propagate {
        #[arg(value_enum)]
        mode: Option<PropagateArg>,
    },
    /// Work with filters.
    #[command(subcommand)]
    Filter(FilterCmd),
    /// The configuration of the agent on this host (with --local).
    #[command(subcommand)]
    Config(ConfigCmd),
}

#[derive(Debug, Subcommand)]
enum RedactionCmd {
    /// The rules (in order) and the presets.
    List,
    /// Create or replace a rule (admin); lines kept so far are rewritten.
    Set {
        name: String,
        /// Regular expression, e.g. '(for )\S+( from)'.
        #[arg(long)]
        pattern: String,
        /// Replacement; $1, ${name} for groups (default "[redacted]").
        #[arg(long)]
        replace: Option<String>,
        #[arg(long)]
        disabled: bool,
    },
    /// Add a preset (ssh-user, auth-header, email, url-query) under its name.
    Preset {
        name: String,
    },
    Rm {
        name: String,
    },
    /// Show what lines look like after the current rules (and --pattern).
    Test {
        lines: Vec<String>,
        #[arg(long)]
        pattern: Option<String>,
        #[arg(long)]
        replace: Option<String>,
    },
}

#[derive(Debug, Subcommand)]
enum AgentsCmd {
    List,
    Show {
        id: String,
    },
    Revoke {
        id: String,
    },
    /// Move an agent to another group (admin): bans of the old group are
    /// removed from it, those of the new group applied.
    SetGroup {
        id: String,
        group: String,
    },
    /// Create a one-time enrollment token.
    EnrollToken {
        #[arg(long, default_value = "default")]
        group: String,
        #[arg(long, default_value = "1h", value_parser = humantime::parse_duration)]
        valid_for: Duration,
    },
}

#[derive(Debug, Subcommand)]
enum BansCmd {
    List {
        #[arg(long)]
        jail: Option<String>,
        #[arg(long)]
        agent: Option<String>,
        #[arg(long, value_parser = parse_target)]
        target: Option<IpNet>,
    },
}

/// Web UI sessions (admin).
#[derive(Debug, Subcommand)]
enum SessionsCmd {
    /// Live browser sessions, most recently used first.
    List,
    /// End a session by id, all sessions of a user, or all sessions.
    End {
        /// Session id (from `sessions list`).
        #[arg(required_unless_present_any = ["user", "all"], conflicts_with_all = ["user", "all"])]
        id: Option<String>,
        #[arg(long, conflicts_with = "all")]
        user: Option<String>,
        /// Everybody, including your own browser sessions.
        #[arg(long)]
        all: bool,
    },
}

#[derive(Debug, Subcommand)]
enum AllowlistCmd {
    /// Networks the controller never bans.
    List,
    /// Add a network or an autonomous system ("AS64500"; its networks come
    /// from the controller's GeoIP data) (admin); lifts active bans
    /// overlapping it.
    Add {
        #[arg(value_parser = parse_allow_target)]
        target: String,
        #[arg(long)]
        comment: Option<String>,
        /// Keep active bans overlapping the network.
        #[arg(long)]
        keep_bans: bool,
        /// Temporary entry for this long, e.g. 7d (default: permanent).
        #[arg(long = "for", value_parser = humantime::parse_duration)]
        ttl: Option<Duration>,
    },
    /// Remove a network or autonomous system added through the API (admin).
    Rm {
        #[arg(value_parser = parse_allow_target)]
        target: String,
    },
}

#[derive(Debug, Subcommand)]
enum JailsCmd {
    /// Jails reported by the agents, with effective and central settings.
    List,
    /// Set a jail's limits centrally (admin), for all agents or one group.
    /// Replaces earlier settings for that scope; options left out keep each
    /// agent's own configuration.
    Set {
        jail: String,
        #[arg(long)]
        group: Option<String>,
        #[arg(long, conflicts_with = "disable")]
        enable: bool,
        #[arg(long)]
        disable: bool,
        #[arg(long)]
        maxretry: Option<u32>,
        /// e.g. 10m
        #[arg(long)]
        findtime: Option<String>,
        /// e.g. 1h
        #[arg(long)]
        bantime: Option<String>,
        #[arg(long)]
        bantime_factor: Option<f64>,
        /// e.g. 30d
        #[arg(long)]
        max_bantime: Option<String>,
    },
    /// Remove a jail's central settings (all agents, or --group).
    Reset {
        jail: String,
        #[arg(long)]
        group: Option<String>,
    },
    /// Define a jail on the controller for all agents or a group (admin):
    /// created on the agents with its sources and filter.
    Define {
        jail: String,
        #[arg(long)]
        group: Option<String>,
        /// A central filter, or one the agents have in their filter_dir.
        #[arg(long)]
        filter: String,
        /// Log file (repeatable); agents accept paths below central_paths.
        #[arg(long = "file")]
        files: Vec<String>,
        /// Read files from their end (only new lines).
        #[arg(long)]
        start_at_end: bool,
        /// journald match, e.g. _SYSTEMD_UNIT=sshd.service (repeatable).
        #[arg(long = "journald")]
        journald: Vec<String>,
        #[arg(long, default_value_t = 5)]
        maxretry: u32,
        #[arg(long, default_value = "10m")]
        findtime: String,
        #[arg(long, default_value = "1h")]
        bantime: String,
        #[arg(long)]
        bantime_factor: Option<f64>,
        #[arg(long)]
        max_bantime: Option<String>,
        #[arg(long)]
        disabled: bool,
    },
    /// Remove a central jail definition (all agents, or --group).
    Undefine {
        jail: String,
        #[arg(long)]
        group: Option<String>,
    },
}

/// Correlation rules: bans from what several agents observed (admin).
#[derive(Debug, Subcommand)]
enum CorrelationCmd {
    /// Rules, monitor-mode hits and tracked addresses.
    List,
    /// Create or replace a rule. New rules are best tried with --monitor.
    Set {
        name: String,
        #[arg(long, value_enum)]
        kind: RuleKindArg,
        /// Failures in total (threshold rules).
        #[arg(long)]
        min_failures: Option<u32>,
        /// Different agents.
        #[arg(long)]
        min_agents: u32,
        /// e.g. 10m (1m..24h)
        #[arg(long)]
        window: String,
        /// e.g. 1h
        #[arg(long)]
        bantime: String,
        /// Repeat offenders: bantime × factor^(offense-1) (default 1).
        #[arg(long)]
        bantime_factor: Option<f64>,
        /// Upper bound for escalated bans, e.g. 30d.
        #[arg(long)]
        max_bantime: Option<String>,
        /// Only this jail (default: all).
        #[arg(long)]
        jail: Option<String>,
        /// Only this group's agents count, and the ban applies there.
        #[arg(long)]
        group: Option<String>,
        /// Only addresses in this autonomous system (repeatable; "AS64500"
        /// or 64500; needs the controller's GeoIP data).
        #[arg(long = "asn")]
        asns: Vec<String>,
        /// Only record what would be banned.
        #[arg(long)]
        monitor: bool,
        #[arg(long)]
        disabled: bool,
    },
    Rm {
        name: String,
    },
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum RuleKindArg {
    /// at least N failures from at least M agents within the window
    Threshold,
    /// at least M agents banned the address locally within the window
    Quorum,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum PropagateArg {
    Global,
    Group,
    Off,
}

#[derive(Debug, Subcommand)]
enum FilterCmd {
    /// Central filters on the controller.
    List,
    /// Upload a filter file to the controller (admin; replaces one of the
    /// same name). Central jails use it on the agents.
    Push {
        name: String,
        /// Filter definition (TOML).
        file: PathBuf,
    },
    /// Delete a central filter (admin; not while a central jail uses it).
    Rm { name: String },
    /// Run a filter against a log file and report matches (like fail2ban-regex).
    Test {
        /// Filter definition (TOML).
        filter: PathBuf,
        /// Log file to scan.
        log: PathBuf,
        /// Print every matching line.
        #[arg(long)]
        show_matches: bool,
        /// Print every line that passed the prefilter but did not match.
        #[arg(long)]
        show_missed: bool,
    },
}

#[derive(Debug, Subcommand)]
enum ConfigCmd {
    /// Read and check the agent's configuration file and its filters, and
    /// show what a reload would change; nothing is applied.
    Check,
    /// Apply the agent's configuration file without a restart (as SIGHUP).
    Reload,
}

async fn run_local(cmd: Command, socket: &std::path::Path, json: bool) -> anyhow::Result<()> {
    match cmd {
        Command::Status => local::status(socket, json).await,
        Command::Jails(JailsCmd::List) => local::jails(socket, json).await,
        Command::Bans(BansCmd::List {
            jail,
            agent: None,
            target,
        }) => local::bans(socket, target, jail, json).await,
        Command::Bans(BansCmd::List { agent: Some(_), .. }) => {
            bail!("--agent does not apply with --local (this host only)")
        }
        Command::Ban {
            target,
            duration,
            scope,
            jail,
            reason,
        } => {
            if scope != "global" || jail.is_some() {
                bail!("--scope and --jail do not apply with --local (this host only)");
            }
            local::ban(socket, target, duration, reason, json).await
        }
        Command::Unban {
            target,
            reason: _,
            allow_for,
        } => {
            if allow_for.is_some() {
                bail!("--allow-for needs the controller (it is a central allowlist entry)");
            }
            local::unban(socket, target, json).await
        }
        Command::Config(cmd) => local::config(socket, matches!(cmd, ConfigCmd::Reload), json).await,
        _ => bail!(
            "not available with --local; the agent answers: status, jails list, bans list, ban, unban, config check|reload"
        ),
    }
}

/// An address, a prefix or "AS64500".
fn parse_allow_target(s: &str) -> Result<String, String> {
    let t = s.trim();
    if let Some(d) = t.strip_prefix("AS").or_else(|| t.strip_prefix("as")) {
        return match d.parse::<u32>() {
            Ok(n) if n != 0 => Ok(format!("AS{n}")),
            _ => Err(format!("{s}: not an AS number")),
        };
    }
    parse_target(t).map(|n| n.to_string())
}

fn parse_target(s: &str) -> Result<IpNet, String> {
    df2b_core::parse_target(s)
}

#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        eprintln!("error: {e:#}");
        std::process::exit(1);
    }
}

async fn run() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let json = matches!(cli.output, Output::Json);
    if let Command::Filter(FilterCmd::Test {
        filter,
        log,
        show_matches,
        show_missed,
    }) = &cli.command
    {
        return filter_test::run(filter, log, *show_matches, *show_missed, json);
    }
    if cli.local {
        return run_local(cli.command, &cli.socket, json).await;
    }
    let client = || {
        client::Client::new(client::Overrides {
            controller: cli.controller.clone(),
            token: cli.token.clone(),
            ca_fingerprint: cli.ca_fingerprint.clone(),
            ca_file: cli.ca_file.clone(),
            config: cli.config.clone(),
        })
    };
    match cli.command {
        Command::Status => commands::status(&client()?, json).await,
        Command::Lookup { target } => commands::lookup(&client()?, target, json).await,
        Command::Whoami => commands::whoami(&client()?, json).await,
        Command::Audit { limit } => commands::audit(&client()?, limit, json).await,
        Command::Agents(cmd) => {
            let c = client()?;
            match cmd {
                AgentsCmd::List => commands::agents_list(&c, json).await,
                AgentsCmd::Show { id } => commands::agents_show(&c, &id, json).await,
                AgentsCmd::Revoke { id } => commands::agents_revoke(&c, &id, json).await,
                AgentsCmd::SetGroup { id, group } => {
                    commands::agents_set_group(&c, &id, &group, json).await
                }
                AgentsCmd::EnrollToken { group, valid_for } => {
                    commands::enroll_token(&c, &group, valid_for, json).await
                }
            }
        }
        Command::Bans(BansCmd::List {
            jail,
            agent,
            target,
        }) => commands::bans_list(&client()?, target, jail, agent, json).await,
        Command::Ban {
            target,
            duration,
            scope,
            jail,
            reason,
        } => {
            let args = commands::BanArgs {
                target,
                duration,
                scope,
                jail,
                reason,
            };
            commands::ban(&client()?, args, json).await
        }
        Command::Allowlist(cmd) => {
            let c = client()?;
            match cmd {
                AllowlistCmd::List => commands::allowlist_list(&c, json).await,
                AllowlistCmd::Add {
                    target,
                    comment,
                    keep_bans,
                    ttl,
                } => commands::allowlist_add(&c, target, comment, !keep_bans, ttl, json).await,
                AllowlistCmd::Rm { target } => commands::allowlist_rm(&c, target, json).await,
            }
        }
        Command::Jails(cmd) => {
            let c = client()?;
            match cmd {
                JailsCmd::List => commands::jails_list(&c, json).await,
                JailsCmd::Set {
                    jail,
                    group,
                    enable,
                    disable,
                    maxretry,
                    findtime,
                    bantime,
                    bantime_factor,
                    max_bantime,
                } => {
                    let enabled = (enable || disable).then_some(enable);
                    let body = serde_json::json!({
                        "group": group, "enabled": enabled, "maxretry": maxretry,
                        "findtime": findtime, "bantime": bantime,
                        "bantime_factor": bantime_factor, "max_bantime": max_bantime,
                    });
                    commands::jails_set(&c, &jail, body, json).await
                }
                JailsCmd::Reset { jail, group } => {
                    commands::jails_reset(&c, &jail, group, json).await
                }
                JailsCmd::Define {
                    jail,
                    group,
                    filter,
                    files,
                    start_at_end,
                    journald,
                    maxretry,
                    findtime,
                    bantime,
                    bantime_factor,
                    max_bantime,
                    disabled,
                } => {
                    let mut sources = Vec::new();
                    if !files.is_empty() {
                        sources.push(serde_json::json!({ "type": "file", "paths": files, "start_at_end": start_at_end }));
                    }
                    if !journald.is_empty() {
                        sources
                            .push(serde_json::json!({ "type": "journald", "matches": journald }));
                    }
                    if sources.is_empty() {
                        bail!("give at least one --file or --journald");
                    }
                    let body = serde_json::json!({
                        "group": group, "filter": filter, "sources": sources,
                        "enabled": !disabled, "maxretry": maxretry, "findtime": findtime,
                        "bantime": bantime, "bantime_factor": bantime_factor, "max_bantime": max_bantime,
                    });
                    commands::jails_define(&c, &jail, body, json).await
                }
                JailsCmd::Undefine { jail, group } => {
                    commands::jails_undefine(&c, &jail, group, json).await
                }
            }
        }
        Command::Filter(cmd) => {
            let c = client()?;
            match cmd {
                FilterCmd::List => commands::filters_list(&c, json).await,
                FilterCmd::Push { name, file } => {
                    let toml = std::fs::read_to_string(&file)
                        .map_err(|e| anyhow::anyhow!("reading {}: {e}", file.display()))?;
                    commands::filter_push(&c, &name, toml, json).await
                }
                FilterCmd::Rm { name } => commands::filter_rm(&c, &name, json).await,
                FilterCmd::Test { .. } => unreachable!("handled before connecting"),
            }
        }
        Command::Correlation(cmd) => {
            let c = client()?;
            match cmd {
                CorrelationCmd::List => commands::correlation_list(&c, json).await,
                CorrelationCmd::Set {
                    name,
                    kind,
                    min_failures,
                    min_agents,
                    window,
                    bantime,
                    bantime_factor,
                    max_bantime,
                    jail,
                    group,
                    asns,
                    monitor,
                    disabled,
                } => {
                    let asns: Vec<String> = asns
                        .iter()
                        .map(|a| {
                            let a = a.trim();
                            if a.starts_with("AS") || a.starts_with("as") {
                                a.to_owned()
                            } else {
                                format!("AS{a}")
                            }
                        })
                        .collect();
                    let body = serde_json::json!({
                        "bantime_factor": bantime_factor, "max_bantime": max_bantime,
                        "kind": format!("{kind:?}").to_lowercase(),
                        "min_failures": min_failures.unwrap_or(0), "min_agents": min_agents,
                        "window": window, "bantime": bantime, "jail": jail, "group": group,
                        "monitor": monitor, "enabled": !disabled, "asns": asns,
                    });
                    commands::correlation_set(&c, &name, body, json).await
                }
                CorrelationCmd::Rm { name } => commands::correlation_rm(&c, &name, json).await,
            }
        }
        Command::Redaction(cmd) => {
            let c = client()?;
            match cmd {
                RedactionCmd::List => commands::redaction_list(&c, json).await,
                RedactionCmd::Set {
                    name,
                    pattern,
                    replace,
                    disabled,
                } => {
                    let body = serde_json::json!({
                        "pattern": pattern, "replace": replace, "enabled": !disabled,
                    });
                    commands::redaction_set(&c, &name, body, json).await
                }
                RedactionCmd::Preset { name } => commands::redaction_preset(&c, &name, json).await,
                RedactionCmd::Rm { name } => commands::redaction_rm(&c, &name, json).await,
                RedactionCmd::Test {
                    lines,
                    pattern,
                    replace,
                } => commands::redaction_test(&c, lines, pattern, replace, json).await,
            }
        }
        Command::Propagate { mode } => {
            let mode = mode.map(|m| format!("{m:?}").to_lowercase());
            commands::propagate(&client()?, mode, json).await
        }
        Command::Sessions(cmd) => {
            let c = client()?;
            match cmd {
                SessionsCmd::List => commands::sessions_list(&c, json).await,
                SessionsCmd::End { id, user, all } => {
                    commands::sessions_end(&c, id, user, all, json).await
                }
            }
        }
        Command::Unban {
            target,
            reason,
            allow_for,
        } => commands::unban(&client()?, target, reason, allow_for, json).await,
        Command::Config(_) => bail!(
            "config check|reload act on the agent on this host: use --local \
             (to check a file offline: df2b-agent --check --config FILE)"
        ),
    }
}
