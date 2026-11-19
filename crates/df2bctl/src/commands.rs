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

pub(crate) fn until(v: &Value) -> String {
    match v.as_str().and_then(|t| t.parse::<DateTime<Utc>>().ok()) {
        None => "permanent".into(),
        Some(t) => format!("{} left", fmt_secs((t - Utc::now()).num_seconds().max(0))),
    }
}

pub(crate) fn fmt_secs(s: i64) -> String {
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

/// "AS64500 · DE" from a GeoIP record ("" without one).
fn geo_short(g: &Value) -> String {
    let mut parts = Vec::new();
    if let Some(a) = g["asn"].as_u64() {
        parts.push(format!("AS{a}"));
    }
    if let Some(c) = g["country"].as_str() {
        parts.push(c.to_owned());
    }
    parts.join(" · ")
}

/// "AS64500 Example Hosting · Germany (DE)"
fn geo_long(g: &Value) -> String {
    let mut parts = Vec::new();
    match (g["asn"].as_u64(), g["as_org"].as_str()) {
        (Some(a), Some(o)) => parts.push(format!("AS{a} {o}")),
        (Some(a), None) => parts.push(format!("AS{a}")),
        (None, Some(o)) => parts.push(o.to_owned()),
        (None, None) => {}
    }
    match (g["country"].as_str(), g["country_name"].as_str()) {
        (Some(c), Some(n)) => parts.push(format!("{n} ({c})")),
        (Some(c), None) => parts.push(c.to_owned()),
        _ => {}
    }
    parts.join(" · ")
}

/// `geo`: target → GeoIP record (a NETWORK column when not empty).
fn print_decisions(list: &[Value], geo: &Value) {
    if list.is_empty() {
        println!("no active bans");
        return;
    }
    let with_geo = geo.as_object().is_some_and(|m| !m.is_empty());
    let net = |d: &Value| {
        if with_geo {
            format!("{:<14} ", geo_short(&geo[s(d, &["target"])]))
        } else {
            String::new()
        }
    };
    println!(
        "{:>6}  {:<22} {}{:<10} {:<14} {:<26} {:<12} REASON",
        "SEQ",
        "TARGET",
        if with_geo {
            format!("{:<14} ", "NETWORK")
        } else {
            String::new()
        },
        "JAIL",
        "SCOPE",
        "ORIGIN",
        "EXPIRES"
    );
    for d in list {
        println!(
            "{:>6}  {:<22} {}{:<10} {:<14} {:<26} {:<12} {}",
            d["seq"].to_string(),
            s(d, &["target"]),
            net(d),
            d["jail"].as_str().unwrap_or("-"),
            scope(&d["scope"]),
            origin(&d["origin"]),
            until(&d["expires_at"]),
            s(d, &["reason"]),
        );
    }
}

pub(crate) fn json_out(v: &Value) -> anyhow::Result<()> {
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
    for g in v["geoip"].as_array().into_iter().flatten() {
        println!(
            "geoip        {} ({}, built {}){}",
            s(g, &["database_type"]),
            s(g, &["path"]),
            g["build"]
                .as_str()
                .map_or("?", |b| b.get(..10).unwrap_or(b)),
            g["error"]
                .as_str()
                .map_or(String::new(), |e| format!(" - reload failed: {e}"))
        );
    }
    Ok(())
}

/// Everything known about an address or prefix (the UI's address page).
pub async fn lookup(c: &Client, target: IpNet, json: bool) -> anyhow::Result<()> {
    let v = c
        .get_query("/api/v1/history", &[("target", target.to_string())])
        .await?;
    if json {
        return json_out(&v);
    }
    println!("{}", s(&v, &["target"]));
    let g = geo_long(&v["geo"]);
    if !g.is_empty() {
        println!("network      {g}");
    }
    if v["allowlisted"].as_bool() == Some(true) {
        println!("allowlisted  yes");
    }
    if let Some(n) = v["correlation_offenses"].as_u64().filter(|n| *n > 0) {
        println!(
            "correlation  {n} ban(s) within {}",
            s(&v, &["offense_memory"])
        );
    }
    let obs = v["observations"].as_array().map_or(0, Vec::len);
    if obs > 0 {
        println!("observed     {obs} recent report(s) from agents");
    }
    for l in v["samples"].as_array().into_iter().flatten().take(5) {
        println!("sample       {}  {}", s(l, &["agent"]), s(l, &["line"]));
    }
    println!();
    print_decisions(
        v["active"].as_array().map(Vec::as_slice).unwrap_or(&[]),
        &Value::Null,
    );
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
    print_decisions(
        v["decisions"].as_array().map(Vec::as_slice).unwrap_or(&[]),
        &v["geo"],
    );
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
        Some(_) => print_decisions(std::slice::from_ref(&v["decision"]), &Value::Null),
        None => println!("{}", s(&v, &["message"])),
    }
    Ok(())
}

pub async fn unban(
    c: &Client,
    target: IpNet,
    reason: Option<String>,
    allow_for: Option<Duration>,
    json: bool,
) -> anyhow::Result<()> {
    let allow_for = allow_for.map(|d| humantime::format_duration(d).to_string());
    let v = c
        .post(
            "/api/v1/unban",
            json!({ "target": target.to_string(), "reason": reason, "allow_for": allow_for }),
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
    if let Some(t) = v["allowed_until"].as_str() {
        println!(
            "{target} will not be banned again until {t} ({})",
            until(&v["allowed_until"])
        );
    } else if v["already_allowlisted"] == true {
        println!("{target} is already allowlisted at least that long");
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
        "{:<24} {:<14} {:<10} {:<12} {:>5}  COMMENT",
        "NETWORK", "ADDED BY", "ADDED", "EXPIRES", "BANS"
    );
    for e in &list {
        let by = if e["source"] == "command line" {
            "--allow"
        } else {
            s(e, &["created_by"])
        };
        let expires = if e["expires_at"].is_string() {
            ago(&e["expires_at"])
        } else {
            "never".into()
        };
        println!(
            "{:<24} {:<14} {:<10} {:<12} {:>5}  {}",
            s(e, &["net"]),
            by,
            ago(&e["created_at"]),
            expires,
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
    ttl: Option<Duration>,
    json: bool,
) -> anyhow::Result<()> {
    let ttl = ttl.map_or_else(
        || "never".to_owned(),
        |d| humantime::format_duration(d).to_string(),
    );
    let v = c
        .post(
            "/api/v1/allowlist",
            json!({ "net": net.to_string(), "comment": comment.unwrap_or_default(), "unban": unban, "ttl": ttl }),
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

pub(crate) fn secs(v: &Value) -> String {
    match v.as_u64() {
        Some(0) | None => "-".into(),
        Some(s) => fmt_secs(s as i64),
    }
}

pub async fn jails_list(c: &Client, json: bool) -> anyhow::Result<()> {
    let v = c.get("/api/v1/policies").await?;
    if json {
        return json_out(&v);
    }
    let jails = v["jails"].as_array().cloned().unwrap_or_default();
    if jails.is_empty() {
        println!("no jails reported yet");
        return Ok(());
    }
    println!(
        "{:<16} {:<28} {:<7} {:>5} {:>7} {:>7} {:>6} {:>7}  CENTRAL",
        "JAIL", "AGENT", "STATE", "FAILS", "WITHIN", "BAN", "FACTOR", "MAX"
    );
    for j in &jails {
        let name = s(j, &["name"]);
        let central: Vec<String> = j["overrides"]
            .as_array()
            .into_iter()
            .flatten()
            .map(|o| {
                let scope = o["group"]
                    .as_str()
                    .map_or("all".to_owned(), |g| format!("group {g}"));
                let mut kv = Vec::new();
                for k in [
                    "enabled",
                    "maxretry",
                    "findtime",
                    "bantime",
                    "bantime_factor",
                    "max_bantime",
                ] {
                    if !o[k].is_null() {
                        kv.push(format!("{k}={}", o[k].to_string().trim_matches('"')));
                    }
                }
                format!("{scope}: {}", kv.join(" "))
            })
            .collect();
        let agents = j["agents"].as_array().cloned().unwrap_or_default();
        if agents.is_empty() {
            println!(
                "{name:<16} {:<28} {:<7} {:>5} {:>7} {:>7} {:>6} {:>7}  {}",
                "(none yet)",
                "",
                "",
                "",
                "",
                "",
                "",
                central.join("; ")
            );
        }
        for (i, a) in agents.iter().enumerate() {
            let jv = &a["jail"];
            if let Some(err) = jv["error"].as_str().filter(|e| !e.is_empty()) {
                println!(
                    "{:<16} {:<28} {:<7} {}",
                    if i == 0 { name } else { "" },
                    s(a, &["agent"]),
                    "ERROR",
                    err
                );
                continue;
            }
            println!(
                "{:<16} {:<28} {:<7} {:>5} {:>7} {:>7} {:>6} {:>7}  {}",
                if i == 0 { name } else { "" },
                s(a, &["agent"]),
                if jv["enabled"] == true { "on" } else { "off" },
                jv["maxretry"].to_string(),
                secs(&jv["findtime_secs"]),
                secs(&jv["bantime_secs"]),
                jv["bantime_factor"].to_string(),
                secs(&jv["max_bantime_secs"]),
                if i == 0 {
                    central.join("; ")
                } else {
                    String::new()
                },
            );
        }
    }
    println!("ban propagation: {}", s(&v, &["propagate"]));
    Ok(())
}

pub async fn jails_set(c: &Client, jail: &str, body: Value, json: bool) -> anyhow::Result<()> {
    let v = c
        .put(&format!("/api/v1/jails/{jail}/policy"), body.clone())
        .await?;
    if json {
        return json_out(&v);
    }
    let scope = body["group"]
        .as_str()
        .map_or("all agents".to_owned(), |g| format!("group {g}"));
    println!("{jail}: central settings for {scope} saved; connected agents apply them at once");
    Ok(())
}

pub async fn jails_reset(
    c: &Client,
    jail: &str,
    group: Option<String>,
    json: bool,
) -> anyhow::Result<()> {
    let q: Vec<(&str, String)> = group.iter().map(|g| ("group", g.clone())).collect();
    let v = c
        .delete(&format!("/api/v1/jails/{jail}/policy"), &q)
        .await?;
    if json {
        return json_out(&v);
    }
    let scope = group.map_or("all agents".to_owned(), |g| format!("group {g}"));
    println!("{jail}: central settings for {scope} removed");
    Ok(())
}

pub async fn propagate(c: &Client, mode: Option<String>, json: bool) -> anyhow::Result<()> {
    let v = match mode {
        Some(m) => {
            c.put("/api/v1/policies/propagate", json!({ "propagate": m }))
                .await?
        }
        None => c.get("/api/v1/policies").await?,
    };
    if json {
        return json_out(&v);
    }
    match v["previous"].as_str() {
        Some(prev) => println!("ban propagation: {prev} -> {}", s(&v, &["propagate"])),
        None => println!("ban propagation: {}", s(&v, &["propagate"])),
    }
    Ok(())
}

pub async fn jails_define(c: &Client, jail: &str, body: Value, json: bool) -> anyhow::Result<()> {
    let v = c
        .put(&format!("/api/v1/jail-definitions/{jail}"), body.clone())
        .await?;
    if json {
        return json_out(&v);
    }
    let scope = body["group"]
        .as_str()
        .map_or("all agents".to_owned(), |g| format!("group {g}"));
    println!("{jail}: defined for {scope}; connected agents start it at once");
    if v["filter_is_central"] == false {
        println!(
            "note: filter {:?} is not central; agents need it in their filter_dir",
            body["filter"].as_str().unwrap_or("")
        );
    }
    Ok(())
}

pub async fn jails_undefine(
    c: &Client,
    jail: &str,
    group: Option<String>,
    json: bool,
) -> anyhow::Result<()> {
    let q: Vec<(&str, String)> = group.iter().map(|g| ("group", g.clone())).collect();
    let v = c
        .delete(&format!("/api/v1/jail-definitions/{jail}"), &q)
        .await?;
    if json {
        return json_out(&v);
    }
    println!("{jail}: definition removed; agents stop the jail");
    Ok(())
}

pub async fn filters_list(c: &Client, json: bool) -> anyhow::Result<()> {
    let v = c.get("/api/v1/filters").await?;
    if json {
        return json_out(&v);
    }
    let list = v["filters"].as_array().cloned().unwrap_or_default();
    if list.is_empty() {
        println!("no central filters");
    }
    for f in &list {
        let used: Vec<&str> = f["used_by"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .collect();
        println!(
            "{:<24} used by {}",
            s(f, &["name"]),
            if used.is_empty() {
                "-".into()
            } else {
                used.join(", ")
            }
        );
    }
    Ok(())
}

pub async fn filter_push(c: &Client, name: &str, toml: String, json: bool) -> anyhow::Result<()> {
    let v = c
        .put(&format!("/api/v1/filters/{name}"), json!({ "toml": toml }))
        .await?;
    if json {
        return json_out(&v);
    }
    println!(
        "filter {name} {}",
        if v["replaced"] == true {
            "replaced"
        } else {
            "uploaded"
        }
    );
    Ok(())
}

pub async fn filter_rm(c: &Client, name: &str, json: bool) -> anyhow::Result<()> {
    let v = c.delete(&format!("/api/v1/filters/{name}"), &[]).await?;
    if json {
        return json_out(&v);
    }
    println!("filter {name} deleted");
    Ok(())
}

pub async fn correlation_list(c: &Client, json: bool) -> anyhow::Result<()> {
    let v = c.get("/api/v1/correlation").await?;
    if json {
        return json_out(&v);
    }
    let rules = v["rules"].as_array().cloned().unwrap_or_default();
    if rules.is_empty() {
        println!("no correlation rules");
    }
    for r in &rules {
        let cond = if r["kind"] == "quorum" {
            format!("banned locally by >= {} agents", r["min_agents"])
        } else {
            format!(
                ">= {} failures from >= {} agents",
                r["min_failures"], r["min_agents"]
            )
        };
        let mode = if r["enabled"] == false {
            "off"
        } else if r["monitor"] == true {
            "monitor"
        } else {
            "active"
        };
        let esc = match r["bantime_factor"].as_f64() {
            Some(f) if f > 1.0 => format!(
                ", x{f} per repeat{}",
                r["max_bantime"]
                    .as_str()
                    .map(|m| format!(" up to {m}"))
                    .unwrap_or_default()
            ),
            _ => String::new(),
        };
        println!(
            "{:<20} {:<8} {cond} within {} -> ban {}{esc}  (jail {}, agents {})",
            s(r, &["name"]),
            mode,
            s(r, &["window"]),
            s(r, &["bantime"]),
            r["jail"].as_str().unwrap_or("all"),
            r["group"]
                .as_str()
                .map_or("all".to_owned(), |g| format!("group {g}")),
        );
    }
    let hits = v["monitor_hits"].as_array().cloned().unwrap_or_default();
    if !hits.is_empty() {
        println!("\nwould have banned (monitor mode):");
        for h in hits.iter().take(20) {
            println!(
                "  {:<24} {:<20} {} agents  {}",
                s(h, &["target"]),
                s(h, &["rule"]),
                h["agents"].as_array().map_or(0, Vec::len),
                ago(&h["at"])
            );
        }
    }
    println!(
        "\naddresses followed: {}; ban propagation: {}",
        v["tracked_addresses"],
        s(&v, &["propagate"])
    );
    Ok(())
}

pub async fn correlation_set(
    c: &Client,
    name: &str,
    body: Value,
    json: bool,
) -> anyhow::Result<()> {
    let v = c
        .put(&format!("/api/v1/correlation/{name}"), body.clone())
        .await?;
    if json {
        return json_out(&v);
    }
    let mode = if body["monitor"] == true {
        " (monitor mode: only records)"
    } else {
        ""
    };
    println!(
        "rule {name} {}{mode}",
        if v["replaced"] == true {
            "replaced"
        } else {
            "created"
        }
    );
    Ok(())
}

pub async fn correlation_rm(c: &Client, name: &str, json: bool) -> anyhow::Result<()> {
    let v = c
        .delete(&format!("/api/v1/correlation/{name}"), &[])
        .await?;
    if json {
        return json_out(&v);
    }
    println!("rule {name} deleted");
    Ok(())
}

pub async fn redaction_list(c: &Client, json: bool) -> anyhow::Result<()> {
    let v = c.get("/api/v1/redaction").await?;
    if json {
        return json_out(&v);
    }
    let rules = v["rules"].as_array().map(Vec::as_slice).unwrap_or(&[]);
    if rules.is_empty() {
        println!("no redaction rules (sample lines are kept as the agents send them)");
    }
    for r in rules {
        println!(
            "{:<16} {:<4} {}  ->  {}",
            s(r, &["name"]),
            if r["enabled"].as_bool() == Some(false) {
                "off"
            } else {
                "on"
            },
            s(r, &["pattern"]),
            s(r, &["replace"])
        );
    }
    let n = |k: &str| v["agents"][k].as_u64().unwrap_or(0);
    if n("connected") > 0 && rules.iter().any(|r| r["enabled"].as_bool() != Some(false)) {
        let mut line = format!(
            "applied by {} of {} connected agent(s) before sending",
            n("current"),
            n("connected")
        );
        if n("off") > 0 {
            line += &format!("; {} refuse them (central_redaction = false)", n("off"));
        }
        println!("{line}");
    }
    println!();
    println!("presets (df2bctl redaction preset <name>):");
    for p in v["presets"].as_array().into_iter().flatten() {
        println!("  {:<14} {}", s(p, &["name"]), s(p, &["description"]));
    }
    Ok(())
}

pub async fn redaction_set(c: &Client, name: &str, body: Value, json: bool) -> anyhow::Result<()> {
    let v = c.put(&format!("/api/v1/redaction/{name}"), body).await?;
    if json {
        return json_out(&v);
    }
    let what = if v["replaced"].as_bool() == Some(true) {
        "replaced"
    } else {
        "created"
    };
    println!(
        "rule {name} {what}; {} kept line(s) redacted",
        v["lines_redacted"].as_u64().unwrap_or(0)
    );
    Ok(())
}

pub async fn redaction_preset(c: &Client, name: &str, json: bool) -> anyhow::Result<()> {
    let v = c.get("/api/v1/redaction").await?;
    let Some(p) = v["presets"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|p| p["name"] == name)
    else {
        anyhow::bail!("no preset {name:?} (see: df2bctl redaction list)");
    };
    let body = json!({ "pattern": p["pattern"], "replace": p["replace"], "enabled": true });
    redaction_set(c, name, body, json).await
}

pub async fn redaction_rm(c: &Client, name: &str, json: bool) -> anyhow::Result<()> {
    let v = c.delete(&format!("/api/v1/redaction/{name}"), &[]).await?;
    if json {
        return json_out(&v);
    }
    println!("rule {name} deleted");
    Ok(())
}

pub async fn redaction_test(
    c: &Client,
    lines: Vec<String>,
    pattern: Option<String>,
    replace: Option<String>,
    json: bool,
) -> anyhow::Result<()> {
    let v = c
        .post(
            "/api/v1/redaction/test",
            json!({ "lines": lines, "pattern": pattern, "replace": replace }),
        )
        .await?;
    if json {
        return json_out(&v);
    }
    for r in v["results"].as_array().into_iter().flatten() {
        let note = if r["stable"].as_bool() == Some(false) {
            "   (changes again when applied twice)"
        } else {
            ""
        };
        println!("{}{note}", s(r, &["line"]));
    }
    Ok(())
}
