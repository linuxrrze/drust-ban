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

# Revoke an agent
cargo run -p df2b-controller -- --state-dir /tmp/df2b-ctl revoke <agent-id>
```

### df2bctl (REST API over HTTPS, port 7444)

```sh
# On the controller host: create an API token (roles: viewer, operator, admin).
# It prints the token and a ready df2bctl.toml with the CA fingerprint.
cargo run -p df2b-controller -- --state-dir /tmp/df2b-ctl \
    api-token create --name alice --role admin --url https://127.0.0.1:7444
#   → put the printed snippet into ~/.config/df2b/df2bctl.toml (chmod 600)

cargo run -p df2bctl -- status
cargo run -p df2bctl -- agents list
cargo run -p df2bctl -- agents enroll-token --group web
cargo run -p df2bctl -- ban 203.0.113.7 --for 24h --reason scanner
cargo run -p df2bctl -- bans list
cargo run -p df2bctl -- unban 203.0.113.7
cargo run -p df2bctl -- audit

# Plain HTTPS works too (internal CA: verify the name df2b-controller)
curl --cacert /tmp/df2b-ctl/ca.pem --resolve df2b-controller:7444:127.0.0.1 \
    -H "Authorization: Bearer df2bapi1.…" https://df2b-controller:7444/api/v1/status
```

With systemd, put `DF2B_ENROLL_TOKEN=df2b1.…` into `/etc/df2b/agent.env` for
the first start (the unit reads it); the token is useless afterwards.
