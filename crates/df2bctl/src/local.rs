//! `--local`: commands answered by the agent on this host over its control
//! socket (DESIGN.md §8); also works in standalone mode, without a
//! controller.

use std::path::Path;
use std::time::Duration;

use anyhow::{bail, Context};
use ipnet::IpNet;
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

use crate::commands::{fmt_secs, json_out, secs, until};

pub const DEFAULT_SOCKET: &str = "/var/lib/df2b/agent.sock";

/// Sends one request and returns its `data`.
pub async fn call(socket: &Path, req: Value) -> anyhow::Result<Value> {
    let io = async {
        let mut s = UnixStream::connect(socket).await.with_context(|| {
            format!(
                "connecting to the agent at {} (is it running? root or the agent's user only)",
                socket.display()
            )
        })?;
        let mut line = serde_json::to_vec(&req)?;
        line.push(b'\n');
        s.write_all(&line).await?;
        let mut out = String::new();
        s.read_to_string(&mut out).await?;
        anyhow::Ok(out)
    };
    let out = tokio::time::timeout(Duration::from_secs(15), io)
        .await
        .context("the agent did not answer")??;
    let v: Value = serde_json::from_str(&out).context("unreadable answer from the agent")?;
    if v["ok"] != true {
        bail!("{}", v["error"].as_str().unwrap_or("request failed"));
    }
    Ok(v["data"].clone())
}

fn str_or<'a>(v: &'a Value, dash: &'a str) -> &'a str {
    v.as_str().filter(|s| !s.is_empty()).unwrap_or(dash)
}

pub async fn status(socket: &Path, json: bool) -> anyhow::Result<()> {
    let v = call(socket, json!({ "cmd": "status" })).await?;
    if json {
        return json_out(&v);
    }
    println!("agent        {}", str_or(&v["version"], "?"));
    match v["controller"].as_str() {
        None => println!("controller   none (standalone)"),
        Some(c) => println!(
            "controller   {c} ({})",
            if v["connected"] == true {
                "connected"
            } else {
                "not connected"
            }
        ),
    }
    let fw = &v["firewall"];
    match fw["error"].as_str() {
        None => println!("firewall     {} (healthy)", str_or(&fw["backend"], "?")),
        Some(e) => println!("firewall     {} - ERROR: {e}", str_or(&fw["backend"], "?")),
    }
    let b = &v["bans"];
    println!(
        "active bans  {} local, {} manual, {} from the controller",
        b["local"], b["manual"], b["controller"]
    );
    println!("jails        {}", v["jails"]);
    for s in v["sources"].as_array().into_iter().flatten() {
        let mut extra = Vec::new();
        if let Some(lag) = s["lag_ms"].as_u64().filter(|l| *l >= 1000) {
            extra.push(format!("{} behind", fmt_secs((lag / 1000) as i64)));
        }
        if let Some(b) = s["backlog_bytes"].as_u64().filter(|b| *b > 0) {
            extra.push(format!("{b} bytes unread"));
        }
        if let Some(e) = s["error"].as_str().filter(|e| !e.is_empty()) {
            extra.push(format!("ERROR: {e}"));
        }
        println!(
            "source       {:<20} {:>6} lines/s{}",
            str_or(&s["name"], "?"),
            s["lines_per_second"].to_string(),
            if extra.is_empty() {
                String::new()
            } else {
                format!("  {}", extra.join(", "))
            }
        );
    }
    Ok(())
}

pub async fn jails(socket: &Path, json: bool) -> anyhow::Result<()> {
    let v = call(socket, json!({ "cmd": "jails" })).await?;
    if json {
        return json_out(&v);
    }
    let list = v.as_array().cloned().unwrap_or_default();
    if list.is_empty() {
        println!("no jails");
        return Ok(());
    }
    println!(
        "{:<16} {:<12} {:<8} {:<8} {:>5} {:>7} {:>7} {:>6} {:>7} {:>5}  CENTRAL",
        "JAIL", "FILTER", "ORIGIN", "STATE", "FAILS", "WITHIN", "BAN", "FACTOR", "MAX", "BANS"
    );
    for j in &list {
        let state = if !j["error"].as_str().unwrap_or("").is_empty() {
            "error"
        } else if j["enabled"] == true {
            "on"
        } else {
            "off"
        };
        let overridden: Vec<&str> = j["overridden"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .collect();
        println!(
            "{:<16} {:<12} {:<8} {:<8} {:>5} {:>7} {:>7} {:>6} {:>7} {:>5}  {}",
            str_or(&j["name"], "?"),
            str_or(&j["filter"], "-"),
            str_or(&j["origin"], "-"),
            state,
            j["maxretry"].to_string(),
            secs(&j["findtime_secs"]),
            secs(&j["bantime_secs"]),
            j["bantime_factor"].to_string(),
            secs(&j["max_bantime_secs"]),
            j["active_bans"].to_string(),
            if overridden.is_empty() {
                "-".to_owned()
            } else {
                overridden.join(",")
            },
        );
        if let Some(e) = j["error"].as_str().filter(|e| !e.is_empty()) {
            println!("{:<16} ^ {e}", "");
        }
        if let Some(n) = j["evicted"].as_u64().filter(|n| *n > 0) {
            println!(
                "{:<16} ^ {n} addresses forgotten: failure tracker full ({} tracked; raise max_tracked?)",
                "", j["tracked"]
            );
        }
    }
    Ok(())
}

pub async fn bans(
    socket: &Path,
    target: Option<IpNet>,
    jail: Option<String>,
    json: bool,
) -> anyhow::Result<()> {
    let v = call(socket, json!({ "cmd": "bans" })).await?;
    let list: Vec<Value> = v
        .as_array()
        .into_iter()
        .flatten()
        .filter(|b| {
            let t = b["target"].as_str().and_then(|t| t.parse::<IpNet>().ok());
            target.map_or(true, |want| {
                t.is_some_and(|t| want.contains(&t) || t.contains(&want))
            }) && jail.as_ref().map_or(true, |j| {
                b["origin"].as_str() == Some(format!("jail:{j}").as_str())
            })
        })
        .cloned()
        .collect();
    if json {
        return json_out(&Value::Array(list));
    }
    if list.is_empty() {
        println!("no active bans");
        return Ok(());
    }
    println!("{:<24} {:<26} {:<12} REASON", "TARGET", "ORIGIN", "EXPIRES");
    for b in &list {
        let reason = match (b["reason"].as_str(), b["offenses"].as_u64()) {
            (Some(r), _) => format!("{r} ({})", str_or(&b["by"], "?")),
            (None, Some(n)) => format!("offense #{n}"),
            _ => String::new(),
        };
        println!(
            "{:<24} {:<26} {:<12} {}",
            str_or(&b["target"], "?"),
            str_or(&b["origin"], "?"),
            until(&b["expires_at"]),
            reason
        );
    }
    Ok(())
}

pub async fn ban(
    socket: &Path,
    target: IpNet,
    duration: Option<Duration>,
    reason: String,
    json: bool,
) -> anyhow::Result<()> {
    let v = call(
        socket,
        json!({
            "cmd": "ban",
            "target": target.to_string(),
            "duration_secs": duration.map(|d| d.as_secs().max(1)),
            "reason": reason,
        }),
    )
    .await?;
    if json {
        return json_out(&v);
    }
    println!(
        "banned {} on this host ({}); not reported to the controller",
        str_or(&v["target"], "?"),
        until(&v["expires_at"])
    );
    Ok(())
}

pub async fn unban(socket: &Path, target: IpNet, json: bool) -> anyhow::Result<()> {
    let v = call(
        socket,
        json!({ "cmd": "unban", "target": target.to_string() }),
    )
    .await?;
    if json {
        return json_out(&v);
    }
    for n in v["lifted"].as_array().into_iter().flatten() {
        println!("unbanned {} on this host", str_or(n, "?"));
    }
    for n in v["still_banned_by_controller"]
        .as_array()
        .into_iter()
        .flatten()
    {
        println!(
            "{} stays blocked: a controller ban covers it (unban it there)",
            str_or(n, "?")
        );
    }
    Ok(())
}

/// `config check` (nothing applied) or `config reload`.
pub async fn config(socket: &Path, reload: bool, json: bool) -> anyhow::Result<()> {
    let cmd = if reload {
        "config_reload"
    } else {
        "config_check"
    };
    let v = call(socket, json!({ "cmd": cmd })).await?;
    if json {
        return json_out(&v);
    }
    println!(
        "{} {}: {} jail(s)",
        if reload { "reloaded" } else { "valid:" },
        str_or(&v["path"], "?"),
        v["jails"]
    );
    let c = &v["changes"];
    let names = |v: &Value| -> String {
        v.as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .collect::<Vec<_>>()
            .join(", ")
    };
    let mut any = false;
    for what in ["jails", "sources"] {
        for (k, verb) in [
            ("added", "added"),
            ("removed", "removed"),
            ("changed", "changed"),
        ] {
            let n = names(&c[what][k]);
            if !n.is_empty() {
                any = true;
                println!("  {what} {verb}: {n}");
            }
        }
    }
    if c["allowlist"] == true {
        any = true;
        println!("  allowlist changed");
    }
    if c["redact"] == true {
        any = true;
        println!("  redaction rules changed");
    }
    if !any {
        println!(
            "  no jail, source, allowlist or redaction changes (filters are read again on reload)"
        );
    }
    let restart = names(&c["restart_needed"]);
    if !restart.is_empty() {
        println!("  needs a restart (running values kept): {restart}");
    }
    if reload {
        let started = names(&v["sources_started"]);
        let stopped = names(&v["sources_stopped"]);
        if !stopped.is_empty() {
            println!("  sources stopped: {stopped}");
        }
        if !started.is_empty() {
            println!("  sources started: {started}");
        }
        for f in v["sources_failed"].as_array().into_iter().flatten() {
            println!(
                "  source {} FAILED: {}",
                str_or(&f["source"], "?"),
                str_or(&f["error"], "?")
            );
        }
        if let Some(n) = v["bans_lifted"].as_u64().filter(|n| *n > 0) {
            println!("  {n} ban(s) lifted (removed jails, allowlist)");
        }
    }
    Ok(())
}
