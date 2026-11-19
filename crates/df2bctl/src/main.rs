//! dist-f2b command line tool.
//!
//! Implemented: `filter test`. Everything else is a stub until the
//! controller REST API (milestone 2) and the agent control socket exist.

// Stub commands carry arguments that are only read once implemented.
#![allow(dead_code)]

mod filter_test;

use std::path::PathBuf;
use std::time::Duration;

use anyhow::bail;
use clap::{Parser, Subcommand, ValueEnum};
use ipnet::IpNet;

#[derive(Debug, Parser)]
#[command(version, about = "Manage dist-f2b agents, bans and policies")]
struct Cli {
    /// Controller base URL.
    #[arg(
        long,
        global = true,
        env = "DF2B_CONTROLLER",
        default_value = "http://127.0.0.1:7080"
    )]
    controller: String,

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
        #[arg(long, default_value = "manual")]
        reason: String,
    },
    /// Remove a ban.
    Unban {
        #[arg(value_parser = parse_target)]
        target: IpNet,
        #[arg(long, default_value = "global")]
        scope: String,
        /// Also allow the target for this long to prevent immediate re-banning.
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

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Filter(FilterCmd::Test {
            filter,
            log,
            show_matches,
            show_missed,
        }) => filter_test::run(
            &filter,
            &log,
            show_matches,
            show_missed,
            matches!(cli.output, Output::Json),
        ),
        other => {
            let via = if cli.local {
                "local agent socket".to_string()
            } else {
                cli.controller
            };
            bail!("not implemented yet ({via}): {other:?}")
        }
    }
}
