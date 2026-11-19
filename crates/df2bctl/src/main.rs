//! dist-f2b command line tool.
//!
//! Implemented: `filter test` (offline) and the controller commands
//! (status, whoami, agents, bans, ban, unban, audit) over the HTTPS REST API.
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

#[derive(Debug, Subcommand)]
enum AllowlistCmd {
    List,
    Add {
        #[arg(value_parser = parse_target)]
        target: IpNet,
        #[arg(long)]
        comment: Option<String>,
    },
    Rm {
        #[arg(value_parser = parse_target)]
        target: IpNet,
    },
}

#[derive(Debug, Subcommand)]
enum JailsCmd {
    List,
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
        Command::Unban { target, reason } => {
            commands::unban(&client()?, target, reason, json).await
        }
        other => bail!("not implemented yet: {other:?}"),
    }
}
