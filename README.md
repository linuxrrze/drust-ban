# dist-f2b

A distributed fail2ban replacement written in Rust. See [DESIGN.md](DESIGN.md).

## Build

```sh
cargo build --workspace
cargo test --workspace
# journald support (stub for now):
cargo build -p df2b-agent --features journald
```

`protoc` is vendored (`protoc-bin-vendored`); set `PROTOC` to use a system one.

## Try it

```sh
# Test a filter against a log file (like fail2ban-regex)
cargo run -p df2bctl -- filter test filters/sshd.toml /var/log/auth.log

# Validate an agent configuration
cargo run -p df2b-agent -- --config config/agent.example.toml --check

# Run the agent without touching the firewall (example uses firewall = "dry-run").
# The example has a journald source: until journald is implemented, build with
# --features journald (the stub logs an error, file sources keep working)
# or remove that source.
cargo run -p df2b-agent --features journald -- --config config/agent.example.toml

# Controller (health endpoint only so far)
cargo run -p df2b-controller
curl http://127.0.0.1:7080/api/v1/health
```
