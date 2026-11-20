# dist-f2b — Design

A fail2ban replacement written in Rust, with:

- efficient ingestion of **journald** and **plain log files**,
- **distributed** collection of attacker IPs (IPv4 and IPv6),
- **distributed countermeasures** (bans propagated to many hosts),
- a CLI (`df2bctl`) and a **web frontend** for management and overview,
- **encrypted and mutually authenticated communication between all nodes**
  (see §4.4).

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

- Use `libsystemd`'s `sd-journal` API, **loaded at runtime** (`dlopen` of
  `libsystemd.so.0`). Building needs no systemd headers, the feature
  `journald` is on by default, and the same binary runs on hosts without
  systemd (a journald source then fails at startup with a clear error).
  Never spawn `journalctl`.
- Apply journal matches at the source so filtering happens inside libsystemd.
  `journalctl` semantics: same field = OR, different fields = AND, a `"+"`
  term starts a new OR group.
- **One dedicated OS thread per journald source.** An `sd_journal` handle is
  not thread-safe and must stay on the thread that opened it, so the thread
  reads entries as fast as the journal yields them and blocks in
  `sd_journal_wait` once caught up (with a short timeout to notice shutdown).
  This is simpler and faster than an `AsyncFd` integration, which would still
  have to call back into the handle from one fixed thread.
- Per entry only `MESSAGE` and `__REALTIME_TIMESTAMP` are read (no date
  parsing), with a data threshold so oversized messages are not fully
  decompressed. The **cursor** is fetched once per batch, not per entry, and
  travels with the batch so it can be persisted; restarts then resume
  exactly. Without a cursor, `start` selects `tail` (default), `head` or a
  look-back duration.
- Configuration errors (missing libsystemd, invalid match, unreadable
  `directory`) surface when the agent starts, not later on the thread.

### 2.2 Files

- **Event times**: each line's time comes from a timestamp at its start
  when it has one (ISO 8601 / RFC 3339, also with a space and without a
  zone = local time; classic syslog `Nov 19 19:20:01`, local time, the
  year closest to now; the access-log stamp `[19/Nov/2026:19:20:01 +0000]`
  in the first 128 bytes), capped at now; otherwise the time it is read.
  So reading old file content (first start, replaced file) never counts
  failures outside `findtime`, and lag is reported for file sources too.
  Per source `timestamps = false` turns it off.
- Woken by inotify: one instance per process (the default limit is 128 per
  user), read by one thread; each tailer watches its path's directory entry
  (filtered by name: creation, rename, writes) and the inode it has open
  (also after a rename, via `/proc/self/fd`). Events are only a hint: the
  tailer still checks every 2 s, and every 250 ms if inotify is not
  available. Track `(dev, inode, offset)` per file. The tailer keeps the
  file it reads open.
- Rotation handling:
  - **rename + create**: finish reading the old inode (through the open file),
    then switch to the new one, flushing an incomplete last line. While the new
    file is still empty the old one stays open for up to 30 s (the writer may
    not have reopened its log yet);
  - **copytruncate**: `size < offset` means truncated, restart at 0;
  - **rotated while stopped**: if the saved inode is no longer at the path, the
    file with that device and inode is looked up in the same directory
    (`auth.log.1`, `auth.log-20261119`, …) and read from the saved offset
    first; positions keep naming the configured path.
- Read in large buffers, split lines with `memchr`, persist offsets periodically.
- Glob paths (`/var/log/nginx/*.access.log`; `*`, `?`, `[…]`): expanded at
  start and every 10 s; matches present at start follow `start_at_end`, files
  appearing later are read from the start. Each match has its own tailer and
  position; it ends once the file is gone and read to its end. At most 1024
  files per source. A pattern must not match rotated names (`*.log`, not
  `*.log*`), or rotated files are read twice. Central jails may use globs too
  (still below `central_paths`; the controller checks the pattern).
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

Sources send **batches** of up to 1024 lines, each tagged with the source
position (journal cursor or file offset) after its last line. Batching
amortizes channel synchronization, and the agent applies all bans that result
from one batch in a single firewall transaction. The channel is bounded (in
batches), so a slow engine applies back-pressure to the sources instead of
growing memory without limit.

Measured on one core (release build, 2M syslog lines, 5% sshd failures):
the matcher alone handles ~3.1M lines/s; the whole agent pipeline
(file source → batches → engine → dry-run bans) ~3M lines/s. The engine
currently runs on one task; sharding jails across a worker pool is the next
step if a single host ever exceeds that.

Filter authors should anchor patterns at the end of the line (`$`) and use a
greedy `.*` before the host, so that attacker-controlled text (e.g. user names
containing `from 1.2.3.4`) cannot inject a different IP.

---

## 3. Detection and scoring

- **Key normalization**: IPv4 is tracked as `/32`. IPv6 is aggregated to a
  configurable prefix (default `/64`) because attackers trivially rotate
  addresses inside a /64. Optional widening (`ipv6_widen_after`, off by
  default): once a jail has banned that many prefixes inside one block
  (`ipv6_widen_prefix`, /48 by default, /56 possible) at the same time, it
  bans the block - with the jail's ban time, escalated for repeat blocks -
  and stops banning further prefixes inside it while that lasts. A block
  overlapping the allowlist is never banned; the wider ban reaches the
  controller like any local ban (which accepts nothing wider than /48 from
  an agent). IPv4-mapped IPv6 addresses are treated as IPv4.
- **Tracker**: per (jail, key) a small ring of timestamps forms a sliding
  `findtime` window. Memory is bounded per jail (`max_tracked` keys,
  default 100 000): when full, expired entries are pruned (at most once a
  second) and then the key tracked longest is evicted, so a flood of new
  addresses is still counted. Evictions are logged (at powers of two),
  reported per jail in heartbeats (`tracked`, `evicted`), shown on the
  Policies page and in `df2bctl --local jails list`.
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

Implemented as runtime ban propagation (`global`/`group`/`off`) plus
correlation rules of kind `threshold` and `quorum`; see §9 "Observations
and correlation".

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
- **Log compaction** (daily, first a minute after start): decisions older
  than `--log-retention` (default 90d, at least 31d so the 30-day offense
  counts rebuilt from the log stay right; `never` keeps everything) are
  deleted, except bans still active (permanent ones included). The highest
  deleted sequence number is stored: agents resuming from before it get a
  snapshot, and numbers are never reused after a restart. Older address
  history is gone with it.
- Expiry uses absolute `expires_at`. Agents report clock skew in heartbeats
  (shown in the UI) and clamp expiries if skew is large.

### 4.4 Transport, encryption and identity

**Requirement: every link between nodes is encrypted and authenticated.**
Observations contain attacker and user IPs and sample log lines, and
decisions control firewalls; neither may cross the network in plaintext or be
accepted from an unauthenticated peer.

| Link                                  | Protection                                                      |
|---------------------------------------|-----------------------------------------------------------------|
| agent ↔ controller (gRPC)             | TLS 1.3, **mutual** auth: agent client cert + controller server cert, both from the internal CA |
| `df2bctl` / browser → controller      | TLS 1.3 (HTTPS); users authenticate with a session (local password or OIDC), CLI with API tokens; optional client certs |
| controller ↔ controller (HA)          | TLS 1.3 with mutual auth; PostgreSQL connections with `sslmode=verify-full` |
| controller → external actions         | TLS with system trust store (cloud APIs, webhooks); BGP sessions with TCP-AO/MD5 where the peer supports it |
| `df2bctl --local` → agent             | Unix socket only (no network), access by file permissions / `SO_PEERCRED` |

Rules:

- **rustls only, TLS 1.3 only**, no cipher-suite configuration surface. No
  plaintext listener except an explicit `--insecure-dev` flag that refuses to
  bind to non-loopback addresses.
- **Internal CA** on the controller (ECDSA P-256 or Ed25519). Agent
  certificates are short-lived (default 30 days) and renewed automatically
  over the existing mTLS channel; the CN/SAN is the agent id. An operator may
  supply an external CA instead.
- **Enrollment without trust-on-first-use**:
  `df2bctl agents enroll-token --group web` creates a one-time, short-lived
  token that embeds the **SHA-256 fingerprint of the controller CA**
  (`df2b1.<secret>.<ca-fingerprint>`). The agent pins that fingerprint during
  the first TLS handshake, so a man in the middle cannot impersonate the
  controller. The agent generates its key pair locally (the private key never
  leaves the host), sends a CSR + token, and receives its signed certificate.
- **Revocation**: revoking an agent puts its certificate serial on a deny
  list that the controller checks on every handshake and stream; open streams
  are closed immediately. Short lifetimes bound the damage of a missed
  revocation.
- **Identity from the certificate only**: the controller derives the agent id
  from the verified client certificate, never from message fields.
- **Keys at rest**: agent key `0600`, owned by the agent user, in
  `state_dir`; controller CA key separately protected (file `0600`, or
  PKCS#11/TPM later).
- Heartbeats carry: version, ingest rate, per-source lag, active ban count,
  clock skew, firewall backend health, **certificate expiry**. These feed the
  "connected clients" view, which flags certificates close to expiry.

#### Implementation (agent ↔ controller, crate `df2b-tls`)

- rustls 0.23 with the *ring* provider, TLS 1.3 only, ALPN `h2`. The TLS
  layer is done with tokio-rustls in front of tonic (tonic's own TLS options
  cannot express TLS-1.3-only, optional client auth or CA pinning).
- The controller creates its CA (`ca.pem`, `ca.key` 0600) on first start and
  issues a fresh server certificate at every start (key only in memory). The
  server certificate always carries the name `df2b-controller`, which agents
  verify regardless of the address they connect to; `--name` adds more.
  Agent certificates carry EKU *clientAuth* only, so they cannot impersonate
  the controller; the controller ignores CSR subjects and sets CN = agent id.
- Client certificates are optional at the TLS layer (Enroll comes first);
  every other RPC requires one and maps it to an enrolled agent whose record
  lists the certificate serial.
- **Tokens**: `df2bctl agents enroll-token --group web` (REST, admin) or,
  on the controller host, `df2b-controller enroll-token --group web [--ttl 1h]`.
  Only the SHA-256 of the
  secret is stored (`enroll-tokens/<hash>.json`); redeeming renames the file,
  so a token works once even under concurrent use. The CSR is checked before
  the token is consumed. The agent takes the token from `--enroll-token` or
  `DF2B_ENROLL_TOKEN` (systemd: `EnvironmentFile`) and stores
  `<state_dir>/tls/{ca.pem, agent.pem (cert + key, 0600), identity.json}`.
- **Renewal** after 2/3 of the lifetime, over the authenticated channel with
  a new key. The controller then accepts the new serial and the one used for
  the renewal call (a lost response cannot lock the agent out); the one
  before is rejected. An agent that stays offline past expiry must be
  re-enrolled with a new token (it says so and re-enrolls automatically when
  given one).
- **Revocation**: `df2b-controller revoke <agent-id>` (a file in
  `revoked/`); checked on every RPC and every 5 s on open decision streams.
- **Decision stream**: `Subscribe(from_seq)` sends a snapshot of active
  decisions (first connect, or more than 10 000 behind) or the backlog, then
  live decisions. Appends are committed before publication, and subscribing
  takes "current seq + live receiver" atomically, so nothing is lost or
  duplicated between backlog and live stream. A lagging subscriber is cut off
  and resumes by seq.
- **Policy** `propagate_local` (`--propagate global|group|off`): an agent's
  local ban becomes a decision unless an active ban for the same target and
  scope lasts at least as long. Rejected: prefixes broader than /24 (v4) or
  /48 (v6) from a single agent, and anything overlapping the controller
  allowlist (`--allow`).
- The agent applies remote bans to the same firewall sets as local ones;
  a remote ban that disappears is only removed if no local ban or other
  decision still covers the prefix; an unban decision also lifts local bans
  (offense history is kept for escalation).
- **Revocation** also via `df2bctl agents revoke <id>` (REST, admin).
- Reports queued while disconnected (max 10 000) are kept in `agent.redb`
  across restarts (§6).
- **Health in heartbeats**: per source the lines per second since the last
  heartbeat, the largest lag (age of the newest processed journal entry)
  and file backlog (bytes written but not read) in that interval, and the
  error that stopped it (a file of it, or a central source that failed to
  start). Firewall: the last ban/unban/setup failure (until one succeeds)
  and a check every minute (nftables: the input chain with its drop rules
  still exists); `firewall_error` says what failed. The UI shows sources
  on the agent page (lag ≥ 10 s and backlog ≥ 1 MiB highlighted) and
  lists agents with a stopped source on the dashboard.

#### Implementation (REST API)

- HTTPS only, TLS 1.3, HTTP/1.1 and HTTP/2 (`--https-listen`, default
  `[::]:7444`); there is no plaintext listener. The certificate is either
  issued by the internal CA (name `df2b-controller` plus `--name`s) or an
  operator-provided chain (`--https-cert`/`--https-key`, e.g. from a public
  CA; loaded again when the files change, see below).
- **API tokens** `df2bapi1.<secret>` as bearer tokens, created on the
  controller host with `df2b-controller api-token create --name <n> --role
  viewer|operator|admin [--ttl 90d]`, listed and revoked (effective
  immediately) with `api-token list|revoke`. Only the SHA-256 of the secret is
  stored (`api-tokens/<hash>.json`), so lookup needs no secret comparison.
  Creation prints a ready `df2bctl.toml` including the CA fingerprint.
- **Roles**: `viewer` reads; `operator` also bans/unbans; `admin` also
  revokes agents, creates enrollment tokens and reads the audit log.
- **Audit log** (redb table `audit`): every change made through the API, plus
  agent enrollments, with actor (token name or `agent:<id>`), client address
  and details.
- `df2bctl` trusts the controller by pinned CA fingerprint (checked against
  the name `df2b-controller`, so any address works), by a CA file, or by
  Mozilla's roots. Settings: flags, `DF2B_*` environment, or
  `~/.config/df2b/df2bctl.toml` (warns if readable by others).
- **Request rate limit** (all of `/api/` except `/api/v1/health`): a token
  bucket per client (IPv6: per /64), `--api-rate` 20/s sustained and
  `--api-burst` 200 at once by default; over it 429 with `Retry-After`.
  Requests with invalid tokens count too. 0 turns it off (behind a reverse
  proxy every client has the proxy's address). Idle buckets are dropped;
  beyond 50 000 clients the rest share one bucket. Failed logins keep
  their own stricter limit.
- **Certificate reload**: an operator certificate (`--https-cert`,
  `--https-key`) is checked once a minute (content hashes) and loaded again
  when it changed, e.g. after a renewal; new connections use it. A pair
  that does not fit (key not matching, caught half written) is logged and
  the current certificate kept until the next check.
- **OpenAPI**: `crates/df2b-controller/openapi.json` (OpenAPI 3.1,
  hand-written, no code generation), embedded into the binary and served
  without authentication at `GET /api/v1/openapi.json` (it only describes
  the API). Every operation names its minimum role in `x-required-role`
  (`none`, `authenticated`, `viewer`, `operator`, `admin`). A test
  (`openapi_tests.rs`) parses the router in `api.rs` and fails when a
  route or method is missing from the document or documented but not
  served, when a role differs from the handler's `require(Role::…)`, or
  when the document is malformed (dangling `$ref`, missing responses or
  path parameters). Response shapes are maintained by hand.

### 4.5 Abuse safeguards

What a compromised agent, a malicious controller or an outside attacker
can do is bounded (security review 2026-11-19, regression tests for each):

- **Agent reports** (controller): 20 000 observations per agent and
  minute; valid jail names (<= 64 characters); bans must carry an expiry,
  capped at 90 days; at most 20 000 active bans per agent; reserved ranges
  (loopback, unspecified, link-local, multicast, broadcast) are never
  banned by anyone; the controller allowlist (including ASN entries) wins.
  Correlation keeps at most 64 entries per agent and address and lets one
  agent bring in at most an eighth of its address table. The clock skew
  is clamped to +-1 day, heartbeat strings are bounded, at most 4 decision
  streams per agent, streams close when the certificate expires.
- **Controller decisions** (agent): bans overlapping the agent's own or the
  central allowlist, wider than /8 resp. /16, or covering the controller's
  address are refused; decisions name their origin agent (its host name)
  and carry the reason only for the agent that made them, the others see
  just "agent", "correlation" or "user" (a compromised agent cannot map
  the other groups' hosts from the bans it receives); central jails and
  policies with findtime > 7 days
  or ban times > 10 years are dropped; central file paths must really be
  below `central_paths` (no glob or symlink tricks, regular files only);
  filters are bounded (100 patterns each, 4 KiB per pattern, 2 MiB per
  compiled regex); messages up to 64 MiB.
- **Listeners**: at most 10 000 connections each, idle connections close
  after 2 minutes, HTTP request headers within 30 s; enrollment checks the
  token before any signing work.
- **REST API**: per-client request rate; login failures counted atomically
  per client and user name (tables full: the least-attacked entries go);
  API tokens cannot create tokens or manage users; at most 10 pending OIDC
  logins per client and 100 per network; 10 event streams per caller;
  filter tests off the async workers, two at a time; user text cleaned of
  control characters before it reaches decisions, the audit log or logs.
- **systemd units**: both services run sandboxed (ProtectSystem=strict,
  no new privileges, only the capabilities they need) with a system call
  filter: `@system-service` without `@privileged` and `@resources`, other
  calls fail with EPERM. CI installs the packages on a runner and runs
  enrollment and bans through nftables and ipset under these units
  (`packaging/test/systemd-e2e.sh`).
- **Local**: the agent's state is private (0600, unit UMask 0077), the
  control socket is 0600 with SO_PEERCRED; log lines over 16 KiB are cut
  and their rest skipped, live lines cannot claim old time stamps; sshd
  lines in syslog files are only taken from the sshd program (journald is
  preferred: it knows the sending unit).
- **Circuit breaker** (controller): more than `--breaker-max` (1000)
  automatic bans - agent propagation and correlation rules, not bans made
  by people - within `--breaker-window` (10 min) trip it; further
  automatic bans are then held back (not recorded, so not distributed;
  agents keep enforcing their local bans) until an admin resets it
  (`POST /api/v1/breaker/reset`, the overview page). The tripped state,
  the number of held bans and the latest of them are stored and shown, so
  a restart does not silently resume; trip and reset are audited.

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
- **Overlapping prefixes**: the sets are interval sets, which refuse an
  element overlapping another (e.g. a local /32 inside a controller /24)
  and would fail the whole batch. Batches are normalized (equal prefixes
  merged, longest timeout wins; prefixes inside a wider one dropped); if a
  batch still fails, the sets are listed and it is resolved against them
  (entries an element already covers skipped, narrower elements replaced
  by the wider new one) in one transaction. The reconcile loop counts a
  prefix inside a claimed wider element as present, and re-adds a narrower
  ban once the wider one is gone.
- **Reconcile loop** (every 5 min): the agent lists both sets
  (`nft -j list set`) and compares them with the bans it knows (jail bans,
  manual bans, controller bans; longest expiry per prefix): missing
  prefixes are added again with their remaining time (unless they end
  within 10 s), prefixes nobody claims are removed – the `df2b` table
  belongs to the agent. If the sets cannot be listed and the chain check
  fails too, the table is set up again and everything re-added. Only
  presence is compared, not remaining timeouts. On agent start the table
  is recreated and re-populated from persisted state.
- Further backends behind the `FirewallBackend` trait (`firewall = …`):
  - `ipset`: `hash:net` sets `df2b4`/`df2b6` with timeouts and one DROP
    rule each at the top of INPUT (iptables/ip6tables `-m set`); batches
    via `ipset restore`; no overlap conflicts. ipset timeouts end at
    2147483 s (~24.8 days): longer bans go in without one and the reconcile
    loop removes them when they expire. `list` reads `ipset save`, `check`
    the sets and both rules.
  - `exec` (`firewall_exec = ["/path/prog", args…]`): the program gets
    `setup|ban|unban|check|list` as last argument, `PREFIX TIMEOUT` /
    `PREFIX` lines on stdin; `list` prints prefixes or exits 2 ("cannot
    list"). No shell, cleared environment, 60 s timeout.
  - `dry-run` (log only; for rollout).

**Controller-side actions** (network-wide; `--actions FILE`, module
`actions.rs`, example `config/actions.example.toml`):
- `[[webhook]]`: HTTPS POST of each event as JSON (chat, SIEM, ticketing),
  optionally signed (`X-Df2b-Signature: sha256=<hex>`, HMAC-SHA256 over
  `"<X-Df2b-Timestamp>.<body>"`), two retries, no redirects, TLS 1.3 with
  system roots or `ca_file`; `http://` only with `allow_http`.
- `[[exec]]`: a program per event (absolute path, no shell, cleared
  environment, timeout, not retried): event JSON on stdin, `DF2B_EVENT`,
  `DF2B_TARGET`, `DF2B_SCOPE`, `DF2B_EXPIRES_AT`, `DF2B_STILL_BANNED`.
  Plus a `sync` event with all active bans at start, every `sync_interval`
  and after missed events — the hook for BGP RTBH / FlowSpec and cloud
  firewalls, which keep state elsewhere. `contrib/rtbh-gobgp.sh` announces
  bans with the BLACKHOLE community via the gobgp CLI and reconciles on
  sync.
- Events `ban`, `unban`, `expire` (the controller schedules expiries
  itself); `still_banned` tells whether another active ban covers the same
  target (withdraw only when false). Filters: events, scopes, origins.
- Each action has a bounded queue and its own worker; overflow is counted
  and logged, never blocks. Counters (delivered, failed, dropped, last
  error) in `GET /api/v1/status` → `actions`.
- Not built in: GoBGP's gRPC API and cloud vendors' APIs (via exec).

---

## 6. Storage

- **Agent**: `redb` (embedded, pure Rust) at `<state_dir>/agent.redb`:
  - **source positions** – journal cursor per journald source, `(dev, inode,
    offset)` per file. Every log line is read and processed once, also across
    restarts. A file replaced while the agent was down (same path, new inode)
    is read from the start; the remainder of the rotated-away file is not
    drained yet. Positions nobody will resume from are dropped: a glob
    match once it is gone and read to its end, and at startup those of
    sources no longer configured (locally or centrally) and of files that
    are gone, unless configured by their literal path (a rotation while
    the agent was down is resumed through it).
  - **offender records** – offense count and ban expiry per (jail, key). On
    startup, still-active bans are re-applied to the firewall with their
    remaining time (the nftables table is recreated empty), and escalation
    continues. Records are forgotten `offense_memory` (default 30 days) after
    their ban expired.
  - agent identity and certificate in `<state_dir>/tls/` (§4.4).
  - **unsent reports** – observations the controller has not accepted yet
    (unreachable, or the send failed) are written once per second and
    deleted once sent; while connected the queue is normally empty and
    nothing is written. At most 10 000 are kept (failure counts dropped
    before ban reports); on shutdown the rest is saved as well, so bans
    from an offline period reach the controller after a restart. Remote
    decisions are not stored: after a restart the agent subscribes from 0
    and gets a snapshot.

  Writes are buffered and committed in **one transaction per second** (one
  fsync), not per batch – at high volume that would mean thousands of fsyncs
  per second – plus a final commit on shutdown. After a crash at most about
  one second of log lines is processed again; bans from that window are
  already kept from double-counting by the offender records that were saved.
- **Controller** (now): `redb` at `<state_dir>/controller.redb` with enrolled
  agents, the decision and audit logs, allowlist, policies, central jails,
  correlation rules and the observations of the last hours; runtime status (heartbeats, connections) is in
  memory only. Planned: `sqlx` with SQLite by default, PostgreSQL for HA/large setups.
  Tables: `agents`, `decisions`, `observations_rollup` (per minute, pruned after
  N days), `offense_history`, `users`, `api_tokens`, `audit_log`.

---

## 7. Configuration (TOML)

Agent (`/etc/df2b/agent.toml`), see `config/agent.example.toml`:

```toml
[agent]
controller = "https://df2b.example.org:7443"   # group comes from the enrollment token
ipv6_prefix = 64
firewall = "nftables"          # or "dry-run"
allowlist = ["127.0.0.0/8", "::1/128"]

[[source]]
name = "sshd"
type = "journald"
matches = ["_SYSTEMD_UNIT=sshd.service", "_SYSTEMD_UNIT=ssh.service"]
start = "10m"                  # "tail" (default), "head", or a look-back

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

Talks to the controller over HTTPS (API token, see §4.4), or to the local
agent over a Unix socket with `--local` (also works in standalone mode).
`--output json` on every command.

Implemented: `status`, `whoami`, `agents …`, `bans list`, `ban`, `unban`,
`audit`, `filter test`. An unban revokes every active ban overlapping the
target (e.g. the /64 containing an IPv6 address) in the scope it was made.
Added later (see §9): `unban --allow-for`, `lookup` (the address page),
`allowlist`, `jails`, `filters`, `correlation`, `propagate`, `config`
(with `--local`).

`--local` (socket `--socket`, default `/var/lib/df2b/agent.sock`; agent
setting `control_socket`, "" = off) answers `status` (controller link,
firewall health, ban counts, sources), `jails list`, `bans list` (local,
manual and controller bans on this host), `ban` and `unban`. The socket
is mode 0600 and the peer must be root or the agent's user
(`SO_PEERCRED`); one JSON request per connection, answered with one JSON
line. A local `ban` is a **manual ban of this host only**: kept in
`agent.redb`, re-applied after restarts, not reported to the controller
(at most /8 resp. /16, never on the allowlist; `--scope`, `--jail` are
refused). A local `unban` lifts this host's jail and manual bans; an
address a controller ban still covers stays blocked and is named in the
answer (unban it on the controller).

`config check` / `config reload` (with `--local`; `reload` also on SIGHUP,
`systemctl reload df2b-agent`) act on the agent's configuration file.
`check` reads it and compiles every filter, and shows what a reload would
change (jails and sources added/removed/changed, allowlist, redaction
rules, settings that need a restart); nothing is applied. `reload`
applies it while running: local jails are rebuilt with their filters
read again, keeping the offense history and counted failures of jails
that stay; bans of removed jails end (unless something else still bans
the prefix); local sources that changed or went away stop, new ones
start, unchanged ones keep running, and restarted ones resume from the
positions saved up to now; the allowlist (lifting bans overlapping it),
redaction rules, `send_samples`, `offense_memory` and the `central_*`
settings apply, and central jails are applied again. An invalid file or
filter changes nothing. `controller`, `state_dir`, `firewall`,
`control_socket` and the IPv4/IPv6 prefixes need a restart: they keep
their running values and the answer names them. Without `--local`, df2bctl
points there (offline: `df2b-agent --check`).

```
df2bctl status
df2bctl agents list | show <id> | revoke <id> | enroll-token --group web
df2bctl bans list [--jail sshd] [--agent X] [--target 2001:db8::/48]
df2bctl ban 203.0.113.7 --for 24h --scope global --reason "manual"
df2bctl unban 203.0.113.7 [--reason …] [--allow-for 1h]
df2bctl audit [--limit 50]
df2bctl whoami
df2bctl lookup 203.0.113.7        # network (ASN/country), bans, observations, samples
df2bctl allowlist add|rm|list
df2bctl jails list
df2bctl filter test filters/sshd.toml /var/log/auth.log   # like fail2ban-regex
df2bctl config check | reload
```

---

## 9. Web frontend

- Backend: `axum` REST API on the HTTPS port, Server-Sent Events for live
  updates; hand-written OpenAPI 3.1 description (§4.4).
- Frontend: Svelte 5 + TypeScript, built with Vite into static files and
  embedded into the controller binary with `rust-embed` (single-binary
  deployment). Plain Vite rather than SvelteKit: SvelteKit's static output
  needs an inline bootstrap script, which a strict CSP forbids. Hash routing
  (`#/bans`), so the controller only serves real files.
- Auth: local users (argon2) and optional OIDC. Roles: `viewer`, `operator`
  (ban/unban), `admin` (agents, policies, users). The same roles already apply
  to API tokens (§4.4).

### Implementation

- **Users**: `df2b-controller user add|passwd|set-role|list|delete` on the
  controller host; `<state_dir>/users/<name>.json` (0600, directory 0700)
  with an argon2id hash (RustCrypto defaults: 19 MiB, t=2). Users and API
  tokens share one name space, so the audit log is unambiguous. Passwords
  have at least 12 characters.
- **Sessions**: `POST /api/v1/session` sets `__Host-df2b_session` (Secure,
  HttpOnly, SameSite=Strict, Path=/). Only the SHA-256 of the session secret
  is kept, in memory (a controller restart logs everybody out). Sessions end
  after 4 h idle, 24 h in total, on logout (`DELETE /api/v1/session`), and
  on the next request after the user is deleted or the password changed (the
  user file is read on every request; role changes apply the same way).
- **CSRF**: every request with a session cookie other than GET/HEAD must
  send the session's token in `X-CSRF-Token` (returned by login and
  `whoami`, kept in memory by the UI). A bearer token takes precedence over a
  cookie and needs no CSRF token.
- **Login limits**: 10 failures per 15 min per client (IPv6: per /64), 30
  per user name (this lets an attacker lock a user out for 15 min, a
  deliberate trade-off against password spraying); at most 4 password checks
  run at once. Unknown names cost the same as wrong passwords (dummy hash).
  Successful logins are audited, failures logged.
- **Headers** on every response: CSP `default-src 'none'; script-src 'self';
  style-src 'self'; connect-src 'self'; frame-ancestors 'none'; …` (the UI
  sets no inline styles or scripts; charts use SVG attributes), HSTS,
  `nosniff`, `no-referrer`, `X-Frame-Options: DENY`, COOP/CORP same-origin;
  API responses `Cache-Control: no-store`, hashed assets cached immutably.
- **Live updates**: `GET /api/v1/events` (SSE): `hello`, `decision` for
  every new decision, `resync` when the client lagged, `logout` when the
  token/session became invalid (re-checked every 30 s). Streams end after 1 h
  and the browser reconnects; pages reload their data after each (re)connect.
- **Dashboard data**: `GET /api/v1/stats` (new bans per hour for 48 h from an
  in-memory histogram rebuilt from the log at start, active bans by family,
  top jails, /16 and /32 networks, origins); `GET /api/v1/history?target=`
  (all decisions overlapping an address or prefix, newest first; scans the
  log).
- **Pages**: overview (tiles, bans per hour, top lists, latest bans, agents
  needing attention: offline, firewall error, certificate expiring within 3
  days), bans (search, filter by jail and family, sort, ban dialog, single
  and bulk unban), agents (state, details, revoke, enrollment token dialog),
  address lookup (active bans, decision timeline, ban/unban), audit log
  (admin, paged). Operator/admin actions are hidden for lower roles; the API
  enforces them regardless. The admin pages (users, API tokens, sessions,
  audit log) sit in an "Admin" menu (disclosure pattern: Escape, outside
  click and leaving it with Tab close it; shown inline on phones).
- **OIDC** (`--oidc-config`, see `config/oidc.example.toml`; crate
  `openidconnect` 4 on the controller's rustls/reqwest stack, no redirects
  followed): authorization code flow with PKCE (S256), `state` and `nonce`.
  `GET /api/v1/oidc/login` stores the pending login in memory (10 min, each
  state usable once) and binds it to the browser with `__Host-df2b_oidc`
  (SameSite=Lax, since the callback is a cross-site navigation); the callback
  refuses a state without the matching binding cookie, so a login link
  cannot be planted in someone else's browser. The ID token is verified
  (provider JWKS, issuer, audience, expiry, nonce, `at_hash`); on failure
  the metadata and keys are fetched once more (key rotation), otherwise they
  are cached for an hour. User name from `username_claim` (default
  `preferred_username`; `email` only if verified), groups from
  `groups_claim` (dotted paths such as `realm_access.roles`), both completed
  from userinfo when missing (same `sub` required). The highest role whose
  group list matches wins, else `default_role`, else access is refused. The
  name must be valid and must not belong to a local user or API token. It
  is bound to the account (issuer + `sub`) that used it first
  (`<state_dir>/oidc-names/`): `preferred_username` can often be changed by
  the user at the provider, and without the binding a renamed account would
  appear under another user's name in sessions and the audit log. A name
  bound to another account is refused (`conflict`); after a rename or
  deletion at the provider the admin frees it with `df2b-controller
  oidc-name release <name>` (`oidc-name list` shows the bindings). Local
  users and API tokens cannot take a bound name either. The result is an ordinary session (role fixed for `session_lifetime`, default
  8 h; idle limit 4 h), audited with method, issuer, subject and role.
  Logout returns the provider's `end_session_endpoint` (RP-initiated logout)
  for the UI to open. `disable_password_login` leaves only SSO in the UI.
- **Back-channel logout** (OIDC Back-Channel Logout 1.0): the provider
  POSTs `logout_token` to `/api/v1/oidc/backchannel-logout` when a user logs
  out there or is disabled. The token's signature is checked with the
  provider's JWKS (asymmetric algorithms only; keys fetched again once on
  failure, at most once a minute, so junk tokens cannot make the controller
  hammer the provider); then `iss`, `aud`, `iat` (at most 10 min old, 1 min
  clock leeway), `exp` if present, the back-channel `events` claim, no
  `nonce` (so an ID token is never accepted), `sub` or `sid`, `typ` if
  present, and `jti` (each accepted once). Sessions store the subject and
  the ID token's `sid`: a token with `sid` ends that provider session's
  browser sessions, one with only `sub` all of the subject's. Local sessions
  are never affected. Answer 200 (also when nothing matched) or 400
  `invalid_request`; audited as actor `oidc-provider` (a reserved name). Open
  SSE streams notice within 30 s and the UI returns to the login page.
  Failures send the browser to `/#/login-error/<code>` (expired, cancelled,
  denied, conflict, unavailable, failed); details go to the log only.
- Dependencies pinned to exact versions at least two weeks old; `npm` runs
  with `ignore-scripts`. The built UI is ~90 KB of JavaScript (31 KB gzip).
- **Session management** (admin): `GET /api/v1/sessions` lists live
  browser sessions (user, role, method, sign-in and last use, end of
  session, client address, browser; the caller's own is marked) with a
  random public id that is unrelated to the cookie secret; no secrets or
  CSRF tokens are listed. `DELETE /api/v1/sessions/<id>` ends one,
  `DELETE /api/v1/sessions?user=<name>` all of a user,
  `DELETE /api/v1/sessions?all=true` everybody's (incident response,
  includes the caller). All audited. Also `df2bctl sessions list|end
  [<id>|--user <name>|--all]` and the "Sessions" page. Ending a session does
  not lock anybody out: delete the local user or disable them at the
  provider. User agents are stored without control characters, at most 200
  characters.
- **User management** (admin; local users only, OIDC users live at the
  provider): `GET/POST /api/v1/users`, `PATCH|DELETE /api/v1/users/<name>`
  (role, delete), `POST /api/v1/users/<name>/password` (reset) and the
  "Users" page with a password generator (20 random characters, rejection
  sampling). Passwords set by an admin are **temporary** by default: until
  the user picks their own, the session can only call `whoami`, change the
  password or log out (403 otherwise), and the UI shows only the change
  form. A reset or deletion ends the user's sessions; role changes apply at
  the next request. Admins cannot lower their own role, delete themselves
  or reset their own password through the API (another admin or the host
  CLI can), so nobody locks themselves out by accident. Password rules: 12
  to 1024 characters, not the user name. All audited, never with passwords.
- **Own password** (`POST /api/v1/session/password`, account page): needs
  the current password (wrong guesses count towards the login limits and
  return 403, not 401, so the session stays); the session is replaced with
  a new cookie and CSRF token and all other sessions of the user end.
- **API tokens in the UI** (admin): `GET /api/v1/api-tokens` (name, role,
  created by and when, expiry, last use since the controller started; the
  caller's own token marked), `POST /api/v1/api-tokens` (name, role, ttl up
  to 5 years or "never") and `DELETE /api/v1/api-tokens/<name>`; the
  "API tokens" page shows a new token once, with a ready `df2bctl.toml`
  (with the CA fingerprint when the internal CA serves HTTPS). **Tokens
  cannot create tokens** (browser session or host CLI only), so a leaked
  admin token cannot plant replacements that outlive its revocation; tokens
  can list and revoke (also themselves). Tokens record their creator
  (`created_by`, absent for host-created ones). Audited without secrets.
- **Front-channel logout** (OIDC Front-Channel Logout 1.0, for providers
  without back-channel logout): the provider's logout page loads
  `/api/v1/oidc/frontchannel-logout?iss=&sid=` in an iframe. The request is
  unauthenticated, so it needs the exact issuer and ends only sessions with
  that `sid` (the provider must send it: "session required"); the session
  cookie (SameSite=Strict) is not sent in the frame and not needed. This
  one response carries `frame-ancestors <issuer origin>` instead of
  `'none'` and no `X-Frame-Options` (the middleware leaves handlers' own
  CSP alone), plus `Cache-Control: no-cache, no-store`. Only effective
  logouts are audited, so junk requests cannot fill the audit log. The
  provider's logout page must be served from the issuer's origin.
- **Allowlist editing**: `--allow` entries stay fixed ("command line");
  admins add and remove more through `GET|POST|DELETE /api/v1/allowlist`,
  the "Allowlist" page (read-only for other roles; also "Allowlist…" on the
  address page) or `df2bctl allowlist list|add|rm`. Entries are stored in
  redb (table `allowlist`), apply at once to manual bans and agent reports,
  and survive restarts. Adding lifts the active bans overlapping the
  network by default (`unban: false` / `--keep-bans` to keep them). Refused:
  prefixes broader than /8 or /16 (a /0 would switch banning off),
  duplicates and networks already covered by an entry (409). Comments are
  stored without control characters (max 200). Audited.
- **Allowlist distribution**: the decision stream carries
  `AllowlistUpdate { version, networks }` with the complete central list
  (fixed + API entries), after the snapshot/backlog and on every change;
  `version` is a content hash (stable across restarts). Agents keep it apart
  from their configured allowlist and check both before banning, lift local
  bans overlapping it (also a /64 containing an allowlisted address; offense
  history is kept; the firewall entry stays while a controller ban covers
  that exact prefix, e.g. after `--keep-bans`), store it in `agent.redb`
  (applies after a restart while the controller is unreachable) and report
  the applied version in heartbeats. A malformed update is ignored as a
  whole, never applied partially. The UI shows per agent whether its list
  is current and how many connected agents use the current one. Older
  agents ignore the new event (protobuf) and show as "unknown".
- **Changing an agent's group** (admin: `PATCH /api/v1/agents/<id>`
  `{group}`, "Change…" in the agent details, `df2bctl agents set-group`):
  the record is updated and marked `resync` (persisted, so it also works
  while the agent is offline or across a controller restart). Open streams
  of the agent are closed with `Aborted` within 5 s (the revocation check);
  the agent resubscribes at once (logged at info level, no backoff) and the
  `resync` flag turns that subscription into a full snapshot for the new
  group, which removes the old group's bans and applies the new group's
  (global and agent-scoped bans are unaffected). The flag is cleared under
  the state lock when the snapshot is built. The agent learns its group
  from the heartbeat response and updates `identity.json`. Revoked agents
  cannot be moved; audited as `agent.group` (only real changes).
- **"Allow for X" after unban**: `POST /api/v1/unban {..., allow_for}`
  (unban dialog "Then don't ban it again for", `df2bctl unban --allow-for`)
  first adds a *temporary allowlist entry* for the target, then unbans, so
  agents stop banning before the unbans reach them. This uses the central
  allowlist (with its distribution to agents) rather than `Allow`
  decisions in the log, which the agents never needed. Operators may set
  up to 7 days, admins 30; targets at most /24 (IPv4) or /48 (IPv6) —
  broader exemptions belong on the allowlist proper. Without `allow_for`
  an unban with nothing to unban stays a 404; with it, the entry is still
  created. Temporary entries can also be created on the allowlist (`ttl`,
  "Keep for …", `allowlist add --for`). Merging: a permanent entry replaces
  a temporary one for the same network, a longer temporary entry replaces a
  shorter one (`already_allowlisted` otherwise), a temporary entry inside a
  permanent one is not stored. Expired entries stop applying at once, are
  removed by the controller's housekeeping (every minute; agents then get
  the shorter list) and dropped by agents on their own (every minute, also
  while disconnected): `AllowlistUpdate.expires_unix_ms` carries one
  expiry per network. The version hash includes expiries, so extensions
  reach agents too. Offense history is kept, so a returning attacker is
  escalated as before.
- **Policies** (page "Policies"; `GET /api/v1/policies`):
  - *Ban propagation* (`global` / `group` / `off`) is changeable at runtime
    (`PUT /api/v1/policies/propagate`, `df2bctl propagate <mode>`) and stored
    in redb (table `settings`). `--propagate`, when given, wins at startup
    (and is stored); without it the stored value applies (default global).
  - *Jail settings*: jails stay defined in each agent's configuration (log
    sources and filter files are host-specific); admins override their
    parameters — enabled, maxretry, findtime, bantime, bantime_factor,
    max_bantime — for all agents or one group (`PUT|DELETE
    /api/v1/jails/<name>/policy`, `df2bctl jails set|reset`). A PUT replaces
    that scope's settings; unset fields fall through (group → all agents →
    agent configuration), field by field. Bounds: maxretry 1–1000, findtime
    ≤ 7 days, bans 1 minute–10 years, factor 1–10, max ≥ bantime. Stored in
    redb (`jail_policies`) and written before they are published. The
    decision stream sends each agent its group's merged settings
    (`JailPolicies`, content-hash version) after the allowlist and on every
    change that affects it; a group change re-sends them (new stream).
  - Agents apply them on top of their configured values (`base`), so
    removing a policy restores the configuration; counted failures and
    offense history are kept; a disabled jail counts and bans nothing while
    its active bans run out. Implausible entries are dropped. Settings are
    stored in `agent.redb` and apply after a restart while the controller is
    unreachable. Heartbeats report each jail's effective values, which
    fields are overridden and its active bans; the Policies page and
    `df2bctl jails list` show this inventory (values as ranges across
    agents). Policies for jails no agent has reported yet are possible
    (e.g. before rolling out a new jail). Changes are audited.
- **Central jail definitions** (Policies page sections "Jail definitions"
  and "Filters"; `PUT|DELETE /api/v1/jail-definitions/<name>[?group=]`,
  `PUT|DELETE /api/v1/filters/<name>`, `POST /api/v1/filters/test`;
  `df2bctl jails define|undefine`, `df2bctl filter list|push|rm`). A
  definition has a filter, log sources (files, or journald matches with a
  start) and limits, for all agents or one group (a group definition
  replaces the all-agents one of the same name). Filters use the agents'
  TOML format and are compiled when saved; a definition may also name a
  filter the agents have in their `filter_dir`. Validation: absolute paths
  without `..`, `FIELD=value` matches, at most 8 sources, 16 paths, 32
  matches, 100 failregex, 64 KiB per filter; a filter in use cannot be
  deleted. Stored in redb (`jail_defs`, `filters`); the decision stream
  sends each agent its group's definitions with the central filters they
  use (`CentralJails`, content-hash version) after the jail policies and on
  every change that affects the group. Audited.
- **On the agent** (the controller decides *what*, the agent *whether*):
  `central_jails` (default on), `central_paths` (default `/var/log`;
  component-wise prefix, so `/var/logx` is outside), `central_journald`
  (default on). Rejected definitions, filters that do not compile or are
  missing, and names of local jails (local jails win) are reported per jail
  in heartbeats (`origin`, `error`) and shown in the inventory and
  `df2bctl jails list`. Each central source (`central:<jail>:<n>`) runs with
  its own channel: unchanged sources keep running and their read position
  across updates, changed or removed ones are stopped (aborting the tasks
  closes the channel, which also stops journald readers). A redefined jail
  keeps its counters and offense history; jail policies apply to central
  jails as well. Definitions are stored in `agent.redb` and set up before
  offender records are restored, so their bans come back after a restart,
  also while the controller is unreachable. The source channel stays open,
  so an agent with only central jails keeps running. Lines read are only
  matched to extract addresses; nothing is sent back. Source names starting
  with `central:` are reserved in the agent configuration.
- **Observations and correlation** (§4.1, §4.2; Policies page "Correlation
  rules", `GET|PUT|DELETE /api/v1/correlation[/<name>]`, `df2bctl
  correlation list|set|rm`):
  - Agents with a controller count every failure that passes their
    allowlists (also below their own threshold; not for addresses they
    already ban) per jail and key and send the counts every 5 s (at most
    50 000 keys per interval). When the report queue is full, failure
    counts are dropped before ban reports.
  - **Sample log lines**: with each count the agent sends the latest
    matching line for that jail and key, and with a local ban the line
    that triggered it (`send_samples = false` in agent.toml: counts only,
    no log content leaves the host). Lines are cleaned (control characters
    and escape sequences become spaces) and cut to 512 bytes by the agent
    and again by the controller, which keeps the latest 10 per jail and
    key (at most 100 000 in all, about 50 MB), prunes and persists them
    with the observations and shows them on the address page (newest 50,
    `samples` in `GET /api/v1/history`). They are only as private as the
    logs: sshd lines name the attempted user, web logs URLs.
  - **Redaction** (`df2b_core::redact`): rules of a regular expression
    and a replacement (`$1`, `${name}`; `$$` = `$`; default
    `[redacted]`), applied in order. The `regex` crate matches in linear
    time and the compiled size is limited (1 MiB), so a pattern cannot
    stall anything; patterns up to 500 characters, at most 50 rules,
    none that matches the empty string. Two sources of rules:
    - **Agent**: `[[redact]] pattern/replace` in agent.toml, applied
      before a line leaves the host (checked at start; unknown keys are
      errors).
    - **Controller**: admins manage rules on the Policies page ("Sample
      line redaction", presets `ssh-user`, `auth-header`, `email`,
      `url-query`, live preview) or with `df2bctl redaction
      list|set|preset|rm|test`; `GET /api/v1/redaction`, `PUT|DELETE
      /api/v1/redaction/<name>` (admin, audited), `POST
      /api/v1/redaction/test` (preview, not stored). Stored in redb
      `settings` key `redaction`. They apply to every line on arrival
      (before it is kept or written), and a change rewrites the lines kept
      so far in memory and in the database at once (`lines_redacted` in
      the reply), so the original text is gone everywhere; at start they
      apply to the restored lines as well. Because kept lines are
      redacted again on every change, a rule should not match its own
      replacement: the preview flags rules whose result changes when
      applied twice. A stored rule that no longer compiles is skipped
      with a warning. (redb is copy-on-write: replaced pages are freed,
      not wiped, so old bytes can stay in the file until the space is
      reused; text that must never be stored belongs in agent.toml.)
    - **Distribution**: the enabled controller rules also go to every
      agent (`DecisionEvent.redaction`, after the central jails on
      subscribe and on every change; version = content hash of name,
      pattern, replacement in order, so adding a disabled rule sends
      nothing). Agents apply them after their own `[[redact]]` rules, so
      what they hide never leaves the host either; they keep the last
      rules in agent.redb (`central_redaction`) so lines sent after a
      restart, before the stream delivers the rules, are redacted too, and
      report the version in heartbeats (`redaction_version`). A rule an
      agent cannot compile is skipped there with a warning (the controller
      still applies it). `central_redaction = false` in agent.toml refuses
      them (reported as `off`). The Policies card shows how many connected
      agents apply the current rules, the agent page each agent's state.
      The controller keeps redacting on arrival: for agents that refuse
      the rules, older agents, and lines sent before a change arrived.
  - The controller rate-limits each agent (20 000 observations per minute).
    At the first observation over the rate it stops processing the report
    and answers `consumed` (how many from the start it handled) and
    `retry_after_ms` (until the next minute); the agent keeps the rest
    queued (and persisted) and pauses reports until then (at most 5 min).
    Ban reports in the deferred part make no decision yet. It ignores malformed, too broad
    and allowlisted keys, and places each observation by the agent's
    `last_seen` corrected by the clock skew from its heartbeats (clamped
    to now; older than 24 h dropped), so reports queued while an agent was
    offline do not look like a fresh burst. Observations are kept in
    memory for the longest rule window (at least an hour), for at most
    200 000 addresses.
  - **Across restarts**: accepted observations are buffered and written to
    redb `observations` every 5 s in one transaction (and at shutdown),
    together with the firing pauses and monitor hits (settings key
    `correlation`) when they changed. At start they are replayed (those
    within the longest window), so a restart loses at most the last 5 s,
    does not fire a rule again for an address it already fired for, and
    keeps the monitor list. Rows are pruned with the in-memory ones (every
    minute, older than the longest window).
  - Rules (stored in redb `correlation_rules`): `threshold` — at least N
    failures from at least M different agents within a window (local ban
    reports are votes, not failures); `quorum` — at least M (≥ 2) agents
    banned the address locally within the window. A rule applies to one
    jail or all, and to all agents (ban global) or one group (only its
    agents count; ban in that group). It fires once per address until its
    ban ends, skips addresses already banned there, and bans for its
    `bantime` with origin `correlation:<rule>` and a reason naming the
    agents. *Monitor* mode only records what it would have banned (last
    200, shown on the Policies page); new rules start in monitor mode in
    the UI. Anti-poisoning setup: propagation "Only locally" plus a quorum
    rule — one compromised agent then cannot ban anything elsewhere.
  - The address page shows the recent observations per host.
  - **Escalation**: rules have `bantime_factor` (default 1) and an optional
    `max_bantime` (always at most 10 years); the n-th correlation ban of an
    address gets `bantime × factor^(n-1)` (the agents' formula). Offenses
    are the address's earlier correlation bans from *any* rule within 30
    days (exact target), also ended ones; bans a person lifted (unban by a
    user, e.g. a false positive or an allowlist entry) are forgiven. The
    count is kept from the decision log (rebuilt at start, updated on every
    append), so it survives controller restarts; the reason says "offense n" and the address page shows the count.
    When several rules fire for the same address in one report, only the
    longest ban is recorded.
- **ASN/GeoIP** (`--geoip <file.mmdb>`, repeatable or comma-separated in
  `DF2B_GEOIP`; module `geo.rs`, crate `maxminddb`): MaxMind DB files —
  GeoLite2/GeoIP2 ASN, Country or City, DB-IP Lite, or ipinfo Lite (ASN
  and country in one file, its own field names; both layouts are read).
  Lookups merge the files in order (the first file with an AS, resp. a
  country, wins; ASN and organization, code and name go together; a
  prefix is looked up by its first address) and only read those fields
  (`decode_path`), so ranking thousands of bans stays cheap. Files are
  read into memory; housekeeping (every minute) reloads one whose mtime
  changed (e.g. `geoipupdate`), a broken update keeps the previous data
  and shows "reload failed". No file is downloaded or shipped (licenses):
  the operator provides them. Used for display, and for decisions only
  where an operator asks for it explicitly (ASN allowlist entries, rules
  limited to some AS; below).
  - API: `geo` in `GET /api/v1/history`; `geo` (target → record, unknown
    left out) in `GET /api/v1/decisions`; `geoip`, `top_asns`,
    `top_countries` in `GET /api/v1/stats` (active bans); the loaded
    files in `GET /api/v1/status`.
  - UI: address page line ("AS64500 Example Hosting · Germany (DE)", link
    to that network's bans); Bans "Network" column and search (`as:64500`,
    `country:de`, AS or country name), preset by `#/bans/<term>`; Overview
    "Top autonomous systems" and "Top countries" (linking to the filtered
    list) and the files with their build date in the footer.
  - CLI: `df2bctl lookup <addr>` (network, bans, correlation, samples),
    NETWORK column in `bans list`, files in `status`.
  - Tests build small MaxMind DB files (a minimal writer in
    `geo::testdb`) and read them with the real reader.
- **ASN allowlist entries** (`AS64500` wherever a network is accepted:
  API `POST/DELETE /api/v1/allowlist`, `df2bctl allowlist add|rm`, the
  Allowlist page; admin; permanent only): stored in their own table and
  expanded into the AS's networks from all loaded databases (walking them:
  at start, on adding, after a database reload). The networks count for
  the controller's checks and go to agents as ordinary entries; adding one
  lifts overlapping bans (unless `unban: false`). Without ASN data an entry
  matches nothing (shown as "none known"). The controller keeps every
  allowlist source in one prefix trie, rebuilt on changes and when the
  next temporary entry expires. Data errors can only mean fewer bans.
- **Rules limited to autonomous systems**: correlation rules take `asns`
  (API, `df2bctl correlation set --asn`, rule dialog); such a rule only
  applies to addresses whose AS (GeoIP) is listed — unknown AS: it does not
  apply. The AS is looked up only when some rule is limited.

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
their tracker counters for that key (offense history stays). "Allow for X"
adds a temporary entry to the central allowlist first (see the allowlist
implementation notes in §9).

---

## 10. Repository layout

```
crates/
  df2b-core/        IpKey/prefix normalization, Decision model, allowlist, ban-time escalation
  df2b-proto/       protobuf definitions + tonic codegen (vendored protoc)
  df2b-sources/     file tailer, journald (feature `journald`, libsystemd via dlopen)
  df2b-matcher/     filter definitions, literal prefilter, RegexSet matching
  df2b-firewall/    FirewallBackend trait, nftables, dry-run
  df2b-agent/       agent binary (config, tracker, engine)
  df2b-controller/  controller binary (axum + tonic + sqlx + embedded UI)
  df2bctl/          CLI binary (clap)
web/                Svelte + Vite frontend (built into web/dist, embedded)
config/             example configuration
filters/            bundled filters
packaging/          systemd units, Debian (deb/, cargo-deb) and RPM packages (rpm/, cargo-generate-rpm)
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
| File tailer                  | inotify wake-ups (2 s fallback poll), resumes from saved offset (also across rotation), drains rotated files, glob paths |
| journald                     | implemented (dlopen, dedicated thread, batches, resumes from saved cursor) |
| Tracker / engine             | implemented + tests; one firewall transaction per batch |
| nftables backend             | via `nft -f -`, set listing (`nft -j`), chain check, reconcile loop every 5 min; netlink TODO |
| Agent state (redb)           | source positions, offender records, manual bans, unsent reports, central settings; flushed every 1 s; bans re-applied on start |
| `df2bctl`                    | `filter test`, controller commands, `--local` (agent socket) incl. config check/reload |
| Controller                   | CA, enrollment, AgentService over mTLS, decision log (redb), `propagate_local` |
| REST API                     | HTTPS (TLS 1.3), API tokens and browser sessions (password, OIDC) with roles, agents, enrollment tokens, bans, unban, audit log, stats, IP history, SSE |
| gRPC protocol                | Enroll, Renew, Heartbeat, Report, Subscribe implemented |
| Agent ↔ controller link      | enrollment with CA pinning, renewal, reconnect with backoff, remote bans, central allowlist, jail settings and central jail definitions applied |
| Encrypted transport (§4.4)   | agent ↔ controller (mTLS) and CLI/browser → controller (HTTPS) and `df2bctl --local` → agent (Unix socket) done; HA, external actions TODO |
| Web UI                       | Svelte, embedded: login, overview, bans, agents, address lookup, audit log; live updates; login with local users or OIDC |

---

## 12. Open decisions

These defaults are assumed until decided otherwise:

1. **Scale** – SQLite on the controller; observations aggregated per 5 s per agent.
   Revisit if > ~200 agents or very high event rates.
2. **Firewall backends** – nftables first; iptables/ipset and edge (BGP) later.
3. **Frontend stack** – decided: Svelte 5 + Vite SPA embedded in the controller
   (§9; not SvelteKit, because of the CSP).
4. **Trust model** – `propagate_local` by default; `quorum` available for
   environments where agents are less trusted.
