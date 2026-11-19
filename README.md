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

# Controller (health endpoint only so far)
cargo run -p df2b-controller
curl http://127.0.0.1:7080/api/v1/health
```
