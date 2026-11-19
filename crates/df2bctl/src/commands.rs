//! Commands that talk to the controller REST API. `--output json` prints the
//! API response as is; text output is a compact table.

use std::time::Duration;

use chrono::{DateTime, Utc};
use ipnet::IpNet;
use serde_json::{json, Value};

use crate::client::Client;

fn s<'a>(v: &'a Value, path: &[&str]) -> &'a str {
    let mut cur = v;
    for p in path {
        cur = &cur[*p];
    }
    cur.as_str().unwrap_or("-")
}

fn ago(v: &Value) -> String {
    let Some(t) = v.as_str().and_then(|t| t.parse::<DateTime<Utc>>().ok()) else {
        return "-".into();
    };
    let secs = (Utc::now() - t).num_seconds();
    if secs < 0 {
        return format!("in {}", fmt_secs(-secs));
    }
    format!("{} ago", fmt_secs(secs))
}

fn until(v: &Value) -> String {
    match v.as_str().and_then(|t| t.parse::<DateTime<Utc>>().ok()) {
        None => "permanent".into(),
        Some(t) => format!("{} left", fmt_secs((t - Utc::now()).num_seconds().max(0))),
    }
}

fn fmt_secs(s: i64) -> String {
    match s {
        // rounded: a fresh 4 h session shows "4h", not "3h"
        s if s < 120 => format!("{s}s"),
        s if s < 7200 => format!("{}m", (s + 30) / 60),
        s if s < 172_800 => format!("{}h", (s + 1800) / 3600),
        s => format!("{}d", (s + 43_200) / 86400),
    }
}

/// "global", {"type":"group","value":"web"} → "group:web", ...
fn scope(v: &Value) -> String {
    match (v["type"].as_str(), &v["value"]) {
        (Some("global"), _) => "global".into(),
        (Some("group"), g) => format!("group:{}", g.as_str().unwrap_or("?")),
        (Some("agents"), ids) => format!(
            "agent:{}",
            ids.as_array()
                .map(|a| a
                    .iter()
                    .filter_map(Value::as_str)
                    .collect::<Vec<_>>()
                    .join(","))
                .unwrap_or_default()
        ),
        _ => v.to_string(),
    }
}

fn origin(v: &Value) -> String {
    match (v["type"].as_str(), v["value"].as_str()) {
        (Some(t), Some(val)) => format!("{t}:{val}"),
        _ => v.to_string(),
    }
}

fn print_decisions(list: &[Value]) {
    if list.is_empty() {
        println!("no active bans");
        return;
    }
    println!(
        "{:>6}  {:<22} {:<10} {:<14} {:<26} {:<12} REASON",
        "SEQ", "TARGET", "JAIL", "SCOPE", "ORIGIN", "EXPIRES"
    );
    for d in list {
        println!(
            "{:>6}  {:<22} {:<10} {:<14} {:<26} {:<12} {}",
            d["seq"].to_string(),
            s(d, &["target"]),
            d["jail"].as_str().unwrap_or("-"),
            scope(&d["scope"]),
            origin(&d["origin"]),
            until(&d["expires_at"]),
            s(d, &["reason"]),
        );
    }
}

fn json_out(v: &Value) -> anyhow::Result<()> {
    println!("{}", serde_json::to_string_pretty(v)?);
    Ok(())
}

pub async fn whoami(c: &Client, json: bool) -> anyhow::Result<()> {
    let v = c.get("/api/v1/whoami").await?;
    if json {
        return json_out(&v);
    }
    println!("{} ({})", s(&v, &["name"]), s(&v, &["role"]));
    Ok(())
}

pub async fn status(c: &Client, json: bool) -> anyhow::Result<()> {
    let v = c.get("/api/v1/status").await?;
    if json {
        return json_out(&v);
    }
    let a = &v["agents"];
    println!("controller   {}", s(&v, &["version"]));
    println!(
        "agents       {} connected / {} enrolled ({} revoked)",
        a["connected"], a["total"], a["revoked"]
    );
    println!("active bans  {}", v["active_decisions"]);
    println!("decision log seq {}", v["last_seq"]);
    println!("propagate    {}", s(&v, &["propagate"]));
    Ok(())
}

pub async fn agents_list(c: &Client, json: bool) -> anyhow::Result<()> {
    let v = c.get("/api/v1/agents").await?;
    if json {
        return json_out(&v);
    }
    let list = v["agents"].as_array().cloned().unwrap_or_default();
    if list.is_empty() {
        println!("no agents enrolled");
        return Ok(());
    }
    println!(
        "{:<28} {:<10} {:<10} {:<12} {:>5}  {:<10} CERT EXPIRES",
        "AGENT", "GROUP", "STATE", "LAST SEEN", "BANS", "VERSION"
    );
    for a in &list {
        let state = if a["revoked"].as_bool() == Some(true) {
            "revoked"
        } else if a["connected"].as_bool() == Some(true) {
            "online"
        } else {
            "offline"
        };
        println!(
            "{:<28} {:<10} {:<10} {:<12} {:>5}  {:<10} {}",
            s(a, &["id"]),
            s(a, &["group"]),
            state,
            ago(&a["status"]["last_seen"]),
            a["status"]["active_bans"].to_string(),
            a["status"]["agent_version"]
                .as_str()
                .filter(|v| !v.is_empty())
                .unwrap_or("-"),
            ago(&a["cert_not_after"]),
        );
    }
    Ok(())
}

pub async fn agents_show(c: &Client, id: &str, json: bool) -> anyhow::Result<()> {
    let v = c.get(&format!("/api/v1/agents/{id}")).await?;
    if json {
        return json_out(&v);
    }
    let a = &v["agent"];
    let st = &a["status"];
    println!("id            {}", s(a, &["id"]));
    println!("hostname      {}", s(a, &["hostname"]));
    println!("group         {}", s(a, &["group"]));
    println!(
        "enrolled      {} ({})",
        s(a, &["enrolled_at"]),
        ago(&a["enrolled_at"])
    );
    println!(
        "cert expires  {} ({})",
        s(a, &["cert_not_after"]),
        ago(&a["cert_not_after"])
    );
    println!(
        "state         {}{}",
        if a["connected"].as_bool() == Some(true) {
            "online"
        } else {
            "offline"
        },
        if a["revoked"].as_bool() == Some(true) {
            ", REVOKED"
        } else {
            ""
        }
    );
    println!("last seen     {}", ago(&st["last_seen"]));
    println!("version       {}", s(st, &["agent_version"]));
    println!("active bans   {}", st["active_bans"]);
    println!(
        "firewall      {} (healthy: {})",
        s(st, &["firewall_backend"]),
        st["firewall_healthy"]
    );
    println!("clock skew    {} ms", st["clock_skew_ms"]);
    println!("applied seq   {}", st["last_applied_seq"]);
    Ok(())
}

pub async fn agents_revoke(c: &Client, id: &str, json: bool) -> anyhow::Result<()> {
    let v = c
        .post(&format!("/api/v1/agents/{id}/revoke"), json!({}))
        .await?;
    if json {
        return json_out(&v);
    }
    println!("revoked {id}; its connections close within a few seconds");
    Ok(())
}

pub async fn enroll_token(
    c: &Client,
    group: &str,
    valid_for: Duration,
    json: bool,
) -> anyhow::Result<()> {
    let ttl = humantime::format_duration(valid_for).to_string();
    let v = c
        .post(
            "/api/v1/enroll-tokens",
            json!({ "group": group, "ttl": ttl }),
        )
        .await?;
    if json {
        return json_out(&v);
    }
    println!("{}", s(&v, &["token"]));
    eprintln!(
        "one-time token for group '{group}', expires {}; on the agent host:\n  \
         df2b-agent --enroll-token <token>   (or DF2B_ENROLL_TOKEN)",
        s(&v, &["expires_at"])
    );
    Ok(())
}

pub async fn bans_list(
    c: &Client,
    target: Option<IpNet>,
    jail: Option<String>,
    agent: Option<String>,
    json: bool,
) -> anyhow::Result<()> {
    let mut q = Vec::new();
    if let Some(t) = target {
        q.push(("target", t.to_string()));
    }
    if let Some(j) = jail {
        q.push(("jail", j));
    }
    let mut v = c.get_query("/api/v1/decisions", &q).await?;
    if let Some(a) = agent {
        // client-side: bans reported by this agent
        let want = format!("agent:{a}");
        if let Some(list) = v["decisions"].as_array_mut() {
            list.retain(|d| origin(&d["origin"]) == want);
        }
    }
    if json {
        return json_out(&v);
    }
    print_decisions(v["decisions"].as_array().map(Vec::as_slice).unwrap_or(&[]));
    Ok(())
}

pub struct BanArgs {
    pub target: IpNet,
    pub duration: Option<Duration>,
    pub scope: String,
    pub jail: Option<String>,
    pub reason: String,
}

pub async fn ban(c: &Client, a: BanArgs, json: bool) -> anyhow::Result<()> {
    let body = json!({
        "target": a.target.to_string(),
        "duration": a.duration.map(|d| humantime::format_duration(d).to_string()),
        "scope": a.scope,
        "jail": a.jail,
        "reason": a.reason,
    });
    let v = c.post("/api/v1/bans", body).await?;
    if json {
        return json_out(&v);
    }
    match v["decision"].as_object() {
        Some(_) => print_decisions(std::slice::from_ref(&v["decision"])),
        None => println!("{}", s(&v, &["message"])),
    }
    Ok(())
}

pub async fn unban(
    c: &Client,
    target: IpNet,
    reason: Option<String>,
    json: bool,
) -> anyhow::Result<()> {
    let v = c
        .post(
            "/api/v1/unban",
            json!({ "target": target.to_string(), "reason": reason }),
        )
        .await?;
    if json {
        return json_out(&v);
    }
    for d in v["unbans"].as_array().cloned().unwrap_or_default() {
        println!(
            "unbanned {} ({}), revokes decision {}",
            s(&d, &["target"]),
            scope(&d["scope"]),
            s(&d, &["kind", "revokes"])
        );
    }
    Ok(())
}

pub async fn audit(c: &Client, limit: usize, json: bool) -> anyhow::Result<()> {
    let v = c
        .get_query("/api/v1/audit", &[("limit", limit.to_string())])
        .await?;
    if json {
        return json_out(&v);
    }
    for e in v["entries"].as_array().cloned().unwrap_or_default() {
        println!(
            "{:>5}  {}  {:<20} {:<20} {:<22} {}",
            e["seq"].to_string(),
            s(&e, &["time"]).get(..19).unwrap_or("-"),
            s(&e, &["actor"]),
            s(&e, &["action"]),
            e["remote_addr"].as_str().unwrap_or("-"),
            e["details"]
        );
    }
    Ok(())
}

pub async fn sessions_list(c: &Client, json: bool) -> anyhow::Result<()> {
    let v = c.get("/api/v1/sessions").await?;
    if json {
        return json_out(&v);
    }
    let list = v["sessions"].as_array().cloned().unwrap_or_default();
    if list.is_empty() {
        println!("no web UI sessions");
        return Ok(());
    }
    println!(
        "{:<17} {:<20} {:<9} {:<9} {:<10} {:<10} {:<12} {:<22} BROWSER",
        "ID", "USER", "ROLE", "METHOD", "SIGNED IN", "ACTIVE", "EXPIRES", "FROM"
    );
    for x in &list {
        let ua = x["user_agent"].as_str().unwrap_or("-");
        println!(
            "{:<17} {:<20} {:<9} {:<9} {:<10} {:<10} {:<12} {:<22} {}",
            s(x, &["id"]),
            format!(
                "{}{}",
                s(x, &["user"]),
                if x["current"] == true { " *" } else { "" }
            ),
            s(x, &["role"]),
            s(x, &["method"]),
            ago(&x["created_at"]),
            ago(&x["last_used_at"]),
            ago(&x["expires_at"]),
            s(x, &["remote_addr"]),
            ua.chars().take(60).collect::<String>(),
        );
    }
    Ok(())
}

pub async fn sessions_end(
    c: &Client,
    id: Option<String>,
    user: Option<String>,
    all: bool,
    json: bool,
) -> anyhow::Result<()> {
    let v = match (id, user) {
        (Some(id), _) => c.delete(&format!("/api/v1/sessions/{id}"), &[]).await?,
        (None, Some(u)) => c.delete("/api/v1/sessions", &[("user", u)]).await?,
        (None, None) if all => {
            c.delete("/api/v1/sessions", &[("all", "true".into())])
                .await?
        }
        (None, None) => anyhow::bail!("give a session id, --user or --all"),
    };
    if json {
        return json_out(&v);
    }
    println!("ended {} session(s)", v["ended"]);
    eprintln!(
        "note: users can sign in again; to lock someone out, delete the local user \
         (df2b-controller user delete) or disable them at the identity provider"
    );
    Ok(())
}

pub async fn allowlist_list(c: &Client, json: bool) -> anyhow::Result<()> {
    let v = c.get("/api/v1/allowlist").await?;
    if json {
        return json_out(&v);
    }
    let list = v["entries"].as_array().cloned().unwrap_or_default();
    if list.is_empty() {
        println!("the allowlist is empty");
        return Ok(());
    }
    println!(
        "{:<24} {:<14} {:<10} {:>5}  COMMENT",
        "NETWORK", "ADDED BY", "ADDED", "BANS"
    );
    for e in &list {
        let by = if e["source"] == "command line" {
            "--allow"
        } else {
            s(e, &["created_by"])
        };
        println!(
            "{:<24} {:<14} {:<10} {:>5}  {}",
            s(e, &["net"]),
            by,
            ago(&e["created_at"]),
            e["active_bans"].to_string(),
            e["comment"].as_str().unwrap_or(""),
        );
    }
    Ok(())
}

pub async fn allowlist_add(
    c: &Client,
    net: IpNet,
    comment: Option<String>,
    unban: bool,
    json: bool,
) -> anyhow::Result<()> {
    let v = c
        .post(
            "/api/v1/allowlist",
            json!({ "net": net.to_string(), "comment": comment.unwrap_or_default(), "unban": unban }),
        )
        .await?;
    if json {
        return json_out(&v);
    }
    println!(
        "{} allowlisted; {} active ban(s) lifted",
        s(&v, &["net"]),
        v["unbanned"]
    );
    Ok(())
}

pub async fn allowlist_rm(c: &Client, net: IpNet, json: bool) -> anyhow::Result<()> {
    let v = c
        .delete("/api/v1/allowlist", &[("net", net.to_string())])
        .await?;
    if json {
        return json_out(&v);
    }
    println!("{} removed from the allowlist", s(&v, &["removed"]));
    Ok(())
}

pub async fn agents_set_group(c: &Client, id: &str, group: &str, json: bool) -> anyhow::Result<()> {
    let v = c
        .patch(&format!("/api/v1/agents/{id}"), json!({ "group": group }))
        .await?;
    if json {
        return json_out(&v);
    }
    if v["changed"] == true {
        println!(
            "{id}: group {} -> {}; its bans follow within seconds while it is connected",
            s(&v, &["previous_group"]),
            s(&v, &["group"])
        );
    } else {
        println!("{id} is already in group {}", s(&v, &["group"]));
    }
    Ok(())
}
