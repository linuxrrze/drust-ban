# dist-f2b

A distributed fail2ban replacement written in Rust. See [DESIGN.md](DESIGN.md).

## Build

```sh
cargo build --workspace
cargo test --workspace
# without journald support (libsystemd is loaded at runtime, so this is
# only needed to drop the dependency entirely):
cargo build -p df2b-agent --no-default-features

# journald test against a running journald (needs systemd-cat):
cargo test -p df2b-sources --features journald -- --ignored live_journal
```

`protoc` is vendored (`protoc-bin-vendored`); set `PROTOC` to use a system one.

## Try it

```sh
# Test a filter against a log file (like fail2ban-regex)
cargo run -p df2bctl -- filter test filters/sshd.toml /var/log/auth.log

# Validate an agent configuration
cargo run -p df2b-agent -- --config config/agent.example.toml --check

# Run the agent without touching the firewall (example uses firewall = "dry-run").
# Needs read access to the journal (root, or groups systemd-journal / adm).
cargo run -p df2b-agent -- --config config/agent.example.toml

```

### Controller and agents

```sh
# Controller: creates its CA in --state-dir on first start, agents connect on :7443
cargo run -p df2b-controller -- --state-dir /tmp/df2b-ctl

# One-time enrollment token (prints df2b1.<secret>.<ca-fingerprint>)
cargo run -p df2b-controller -- --state-dir /tmp/df2b-ctl enroll-token --group web

# Agent: set `controller = "https://127.0.0.1:7443"` in its config, then start
# it once with the token; afterwards the certificate in <state_dir>/tls is used.
cargo run -p df2b-agent -- --config agent.toml --enroll-token df2b1.…

# Overview (read-only, loopback)
curl http://127.0.0.1:7080/api/v1/agents
curl http://127.0.0.1:7080/api/v1/decisions

# Revoke an agent
cargo run -p df2b-controller -- --state-dir /tmp/df2b-ctl revoke <agent-id>
```

With systemd, put `DF2B_ENROLL_TOKEN=df2b1.…` into `/etc/df2b/agent.env` for
the first start (the unit reads it); the token is useless afterwards.
