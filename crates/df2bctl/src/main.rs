//! dist-f2b command line tool.
//!
//! Implemented: `filter test` (offline) and the controller commands
//! (status, whoami, agents, bans, ban, unban, audit, sessions, allowlist) over
//! the HTTPS
//! REST API.
//! TODO: `--local` (agent control socket), ip, allowlist, jails, config.

// Stub commands carry arguments that are only read once implemented.
#![allow(dead_code)]

mod client;
mod commands;
mod filter_test;

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

    /// Talk to the local agent's control socket instead of the controller.
    #[arg(long, global = true)]
    local: bool,

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
    /// Show observations and decision history for an address.
    Ip {
        #[arg(value_parser = parse_target)]
        target: IpNet,
    },
    /// Manage the allowlist.
    #[command(subcommand)]
    Allowlist(AllowlistCmd),
    /// Show jails.
    #[command(subcommand)]
    Jails(JailsCmd),
    /// Show or set (admin) where agents' local bans apply: global, group or
    /// off.
    Propagate {
        #[arg(value_enum)]
        mode: Option<PropagateArg>,
    },
    /// Work with filters.
    #[command(subcommand)]
    Filter(FilterCmd),
    /// Configuration management.
    #[command(subcommand)]
    Config(ConfigCmd),
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
    /// Add a network (admin); lifts active bans overlapping it.
    Add {
        #[arg(value_parser = parse_target)]
        target: IpNet,
        #[arg(long)]
        comment: Option<String>,
        /// Keep active bans overlapping the network.
        #[arg(long)]
        keep_bans: bool,
        /// Temporary entry for this long, e.g. 7d (default: permanent).
        #[arg(long = "for", value_parser = humantime::parse_duration)]
        ttl: Option<Duration>,
    },
    /// Remove a network added through the API (admin).
    Rm {
        #[arg(value_parser = parse_target)]
        target: IpNet,
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
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum PropagateArg {
    Global,
    Group,
    Off,
}

#[derive(Debug, Subcommand)]
enum FilterCmd {
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
    Check,
    Reload,
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
        bail!("--local (agent control socket) is not implemented yet");
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
        other => bail!("not implemented yet: {other:?}"),
    }
}
