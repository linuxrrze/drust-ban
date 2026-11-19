# dist-f2b — Design

A fail2ban replacement written in Rust, with:

- efficient ingestion of **journald** and **plain log files**,
- **distributed** collection of attacker IPs (IPv4 and IPv6),
- **distributed countermeasures** (bans propagated to many hosts),
- a CLI (`df2bctl`) and a **web frontend** for management and overview.

Binaries: `df2b-agent` (runs on every protected host), `df2b-controller`
(central coordinator + web UI), `df2bctl` (CLI).

---

## 1. Architecture

Hub-and-spoke: a central controller, with agents that stay fully functional
when the controller is unreachable.

```
            ┌──────────────── df2b-controller ─────────────────┐
            │  gRPC (mTLS) for agents │ REST + SSE for UI/CLI   │
            │  Correlation engine     │ Decision log (seq#)     │
            │  SQLite / PostgreSQL    │ Embedded web UI         │
            │  Controller-side actions (BGP RTBH, cloud FW, …)  │
            └───────────▲───────────────────────▲──────────────┘
          observations  │  decisions (stream)   │ HTTPS
    ┌───────────────────┼──────────┐       ┌────┴─────┐
    │ df2b-agent (each host)       │       │ browser  │ df2bctl
    │ sources → matcher → tracker  │       └──────────┘
    │        → local decisions     │
    │        → firewall backend    │◄── unix socket ── df2bctl --local
    │ redb state (cursors, bans)   │
    └──────────────────────────────┘
```

Why not peer-to-peer gossip:

- One source of truth for the decision log, the UI and the audit trail.
- Much simpler trust model and enrollment.
- Agents still detect and ban locally without the controller, so the controller
  is a single point of failure for *coordination* only, never for protection.
- High availability can be added later (PostgreSQL + two controllers behind a VIP).

---

## 2. Log ingestion (agent)

### 2.1 journald

- Use `libsystemd` (`sd-journal`) via FFI behind the cargo feature `journald`.
  Never spawn `journalctl`.
- Apply journal matches at the source (`_SYSTEMD_UNIT=sshd.service`,
  `SYSLOG_IDENTIFIER=…`) so filtering happens inside the journal library.
- Integrate `sd_journal_get_fd()` with tokio's `AsyncFd`: no polling thread.
- Persist the journal **cursor**: restarts resume exactly, without gaps or
  re-reading.
- Timestamps come from `__REALTIME_TIMESTAMP`; no date parsing needed.

### 2.2 Files

- Watch with inotify (`notify` crate); track `(dev, inode, offset)` per file.
- Rotation handling:
  - **rename + create**: finish reading the old inode, then switch to the new one;
  - **copytruncate**: `size < offset` means truncated, restart at 0.
- Read in large buffers, split lines with `memchr`, persist offsets periodically.
- Glob paths (`/var/log/nginx/*.access.log`); newly appearing files are picked up.
- Configurable timestamp extraction per source. During catch-up, lines older
  than `findtime` are counted but never trigger a ban.

### 2.3 Matching

fail2ban's main bottleneck is running many regexes on every line. dist-f2b
uses a three-stage matcher:

1. **Literal prefilter** – Aho-Corasick over required literals
   (`"Failed password"`, `"Invalid user"`). The vast majority of lines stop here.
2. **`RegexSet`** – one pass determines which patterns match at all.
3. **Capture** – only the matching regex runs with captures, extracting
   `(?P<host>…)`, which is validated by parsing into `std::net::IpAddr`.
   **No DNS lookups, ever.**

`fancy-regex` is available as an opt-in for filters that need lookaround.

Matching runs on a worker pool fed by bounded channels; a full channel applies
back-pressure to the sources instead of growing memory without limit.

Filter authors should anchor patterns at the end of the line (`$`) and use a
greedy `.*` before the host, so that attacker-controlled text (e.g. user names
containing `from 1.2.3.4`) cannot inject a different IP.

---

## 3. Detection and scoring

- **Key normalization**: IPv4 is tracked as `/32`. IPv6 is aggregated to a
  configurable prefix (default `/64`) because attackers trivially rotate
  addresses inside a /64. Optional escalation to `/56` or `/48` when several
  /64s from the same block misbehave. IPv4-mapped IPv6 addresses are treated
  as IPv4.
- **Tracker**: per (jail, key) a small ring of timestamps forms a sliding
  `findtime` window. Memory is bounded (per-jail key limits, pruning).
- **Escalating ban times** (recidive built in):
  `bantime = base × factor^(n-1)`, capped at `max_bantime`. Offense history is
  kept per key.
- **Allowlist**: CIDR prefix trie. Checked before any ban is created, on both
  agent and controller. A ban whose prefix *overlaps* an allowlisted network is
  rejected (relevant for aggregated IPv6 prefixes).

---

## 4. Distributed collection and countermeasures

### 4.1 Observations, not just bans

Agents send batched aggregates every few seconds:

```
{ key, jail, count, first_seen, last_seen, sample_line? }
```

This lets the controller detect slow, distributed attacks: two failures on each
of 15 hosts never trips a local threshold, but is obvious centrally.

### 4.2 Correlation policies (controller, per jail)

| Policy             | Meaning                                                        |
|--------------------|----------------------------------------------------------------|
| `propagate_local`  | Any agent's local ban becomes a global ban.                    |
| `global_threshold` | > X failures across ≥ Y distinct agents within a window → ban. |
| `quorum`           | ≥ N agents must agree before a global ban (anti-poisoning).    |

### 4.3 Decision log

Every ban and unban is an append-only **decision** with a monotonic sequence
number:

```rust
struct Decision {
    seq: u64,
    id: Uuid,
    kind: DecisionKind,          // Ban | Unban { revokes } | Allow
    target: IpNet,               // v4/v6 prefix
    scope: Scope,                // Global | Group(tag) | Agents(Vec<AgentId>)
    jail: Option<String>,
    created_at: DateTime<Utc>,
    expires_at: Option<DateTime<Utc>>,
    origin: Origin,              // Agent(id) | Correlation(rule) | User(name)
    reason: String,
}
```

- Agents subscribe with `Subscribe(from_seq)`; reconnects resume losslessly and
  applying decisions is idempotent.
- If the gap is too large (log compacted), the controller sends a snapshot of
  active decisions, then continues streaming.
- Expiry uses absolute `expires_at`. Agents report clock skew in heartbeats
  (shown in the UI) and clamp expiries if skew is large.

### 4.4 Transport and identity

- gRPC (`tonic`) bidirectional streams over **mTLS**.
- Enrollment: `df2bctl agents enroll-token --group web` creates a one-time
  token. The agent generates a key pair and sends a CSR + token; the controller
  signs it with its internal CA. Revoking an agent invalidates its certificate.
- Heartbeats carry: version, ingest rate, per-source lag, active ban count,
  clock skew, firewall backend health. These feed the "connected clients" view.

### 4.5 Abuse safeguards

- Per-agent rate limits on observation reports.
- Controller and agents never ban the controller's address, management
  networks or anything on the allowlist.
- Circuit breaker: global cap on new global bans per minute; tripping it
  raises an alert and requires operator confirmation.

---

## 5. Countermeasures / firewall backends (agent)

Primary backend: **nftables**, initially via `nft -f -` batches, later directly
over netlink (`rustables`).

```
table inet df2b {
  set ban_v4 { type ipv4_addr; flags interval, timeout; }
  set ban_v6 { type ipv6_addr; flags interval, timeout; }
  chain input {
    type filter hook input priority -10; policy accept;
    ip  saddr @ban_v4 drop
    ip6 saddr @ban_v6 drop
  }
}
```

- **Kernel-side timeouts**: set elements expire in the kernel even if the daemon
  crashes.
- **Batched updates**: one transaction per batch, not one process per ban;
  100k+ entries are fine.
- **Reconcile loop**: periodically diff desired state (active decisions) against
  the actual set contents and repair drift. On agent start the table is
  recreated and re-populated from persisted state.
- Further backends behind the `FirewallBackend` trait: iptables + ipset (legacy),
  `exec` hook (custom scripts), `dry-run` (log only; for rollout).

**Controller-side actions** (network-wide): BGP RTBH / FlowSpec via GoBGP's API,
cloud firewall APIs, webhooks (chat, SIEM).

---

## 6. Storage

- **Agent**: `redb` (embedded, pure Rust): journal cursors, file offsets, active
  decisions, last applied `seq`, queue of unsent observations.
- **Controller**: `sqlx` with SQLite by default, PostgreSQL for HA/large setups.
  Tables: `agents`, `decisions`, `observations_rollup` (per minute, pruned after
  N days), `offense_history`, `users`, `api_tokens`, `audit_log`.

---

## 7. Configuration (TOML)

Agent (`/etc/df2b/agent.toml`), see `config/agent.example.toml`:

```toml
[agent]
controller = "https://df2b.example.org:7443"
group = "web"
ipv6_prefix = 64
firewall = "nftables"          # or "dry-run"
allowlist = ["127.0.0.0/8", "::1/128"]

[[source]]
name = "sshd"
type = "journald"
matches = ["_SYSTEMD_UNIT=sshd.service"]

[[source]]
name = "nginx"
type = "file"
paths = ["/var/log/nginx/access.log"]

[[jail]]
name = "sshd"
sources = ["sshd"]
filter = "sshd"                # <filter_dir>/sshd.toml
maxretry = 5
findtime = "10m"
bantime = "1h"
bantime_factor = 2.0
max_bantime = "30d"
```

Filters live in separate files (`filters/*.toml`): a list of prefilter literals,
`failregex` patterns using the `<HOST>` placeholder (like fail2ban) and optional
`ignoreregex`. `df2bctl import fail2ban /etc/fail2ban` converts existing
filters where the regex syntax allows it.

---

## 8. CLI: `df2bctl`

Talks to the controller over REST (API token), or to the local agent over a
Unix socket with `--local` (also works in standalone mode). `--output json` on
every command.

```
df2bctl status
df2bctl agents list | show <id> | revoke <id> | enroll-token --group web
df2bctl bans list [--jail sshd] [--agent X] [--target 2001:db8::/48]
df2bctl ban 203.0.113.7 --for 24h --scope global --reason "manual"
df2bctl unban 203.0.113.7 [--scope …] [--allow-for 1h]
df2bctl ip 203.0.113.7            # observations per host, decision history
df2bctl allowlist add|rm|list
df2bctl jails list
df2bctl filter test filters/sshd.toml /var/log/auth.log   # like fail2ban-regex
df2bctl config check | reload
```

---

## 9. Web frontend

- Backend: `axum` REST API, OpenAPI spec generated with `utoipa`, Server-Sent
  Events for live updates.
- Frontend: SvelteKit SPA (static build), TypeScript client generated from the
  OpenAPI spec, embedded into the controller binary with `rust-embed`
  (single-binary deployment).
- Auth: local users (argon2) and optional OIDC. Roles: `viewer`, `operator`
  (ban/unban), `admin` (agents, policies, users).

Pages:

- **Dashboard** – active bans (v4/v6), bans per hour, top jails, top attacking
  prefixes/ASNs (optional MaxMind GeoLite), agents online/offline.
- **Agents** – status, last heartbeat, version, group, ingest lines/s, source
  lag, active bans, clock skew, backend health. Actions: revoke, change group.
- **Bans** – searchable/filterable table (prefix, jail, origin, scope, created,
  expires, hits). Unban single or bulk, with scope picker and "allow for X"
  to prevent immediate re-banning.
- **IP detail** – timeline of observations across hosts, decision history,
  sample log lines.
- **Policies / jails**, **Allowlist**, **Audit log**.

**Unban semantics**: an unban is an `Unban` decision revoking a ban's id. It
propagates through the decision log; agents remove the set element and reset
their tracker counters for that key.

---

## 10. Repository layout

```
crates/
  df2b-core/        IpKey/prefix normalization, Decision model, allowlist, ban-time escalation
  df2b-proto/       protobuf definitions + tonic codegen (vendored protoc)
  df2b-sources/     file tailer, journald (feature `journald`)
  df2b-matcher/     filter definitions, literal prefilter, RegexSet matching
  df2b-firewall/    FirewallBackend trait, nftables, dry-run
  df2b-agent/       agent binary (config, tracker, engine)
  df2b-controller/  controller binary (axum + tonic + sqlx + embedded UI)
  df2bctl/          CLI binary (clap)
web/                SvelteKit frontend
config/             example configuration
filters/            bundled filters
packaging/          systemd units, later deb/rpm
```

The agent runs as a dedicated user, not root: `AmbientCapabilities=CAP_NET_ADMIN`,
`SupplementaryGroups=systemd-journal adm`, `ProtectSystem=strict` and further
systemd hardening.

---

## 11. Milestones

1. **Standalone agent** – file + journald sources, matcher, tracker, nftables
   backend, local CLI, `filter test`. Goal: fail2ban parity.
2. **Controller** – enrollment, observation reporting, decision log, global bans,
   CLI against the controller.
3. **Web UI** – dashboard, agents, bans/unban, IP detail, audit log.
4. **Advanced** – correlation policies and quorum, BGP/cloud actions, HA with
   PostgreSQL, central config distribution to agent groups.

### Scaffold status (milestone 1)

| Area                         | State                                            |
|------------------------------|--------------------------------------------------|
| `IpKey`, decisions, ban time | implemented + tests                              |
| Matcher (prefilter/RegexSet) | implemented + tests                              |
| File tailer                  | polling implementation; inotify, globs, persisted offsets TODO |
| journald                     | stub behind feature `journald`                   |
| Tracker / engine             | implemented + tests                              |
| nftables backend             | via `nft -f -`; netlink + reconcile loop TODO    |
| Agent state (redb)           | TODO                                             |
| `df2bctl filter test`        | implemented; other commands are stubs            |
| Controller                   | health endpoint only                             |
| gRPC protocol                | `.proto` drafted, codegen wired                  |
| Web UI                       | placeholder                                      |

---

## 12. Open decisions

These defaults are assumed until decided otherwise:

1. **Scale** – SQLite on the controller; observations aggregated per 5 s per agent.
   Revisit if > ~200 agents or very high event rates.
2. **Firewall backends** – nftables first; iptables/ipset and edge (BGP) later.
3. **Frontend stack** – SvelteKit SPA embedded in the controller (alternatives:
   Leptos for an all-Rust stack, or server-rendered htmx).
4. **Trust model** – `propagate_local` by default; `quorum` available for
   environments where agents are less trusted.
