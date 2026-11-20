# dist-f2b

A distributed fail2ban replacement written in Rust. See [DESIGN.md](DESIGN.md).

## Build

```sh
# web UI first (Node.js 20+); it is embedded into the controller binary.
# Without it the controller serves a short notice instead of the UI.
npm --prefix web ci && npm --prefix web run build

cargo build --workspace
cargo test --workspace
npm --prefix web run check      # type-check the UI
# without journald support (libsystemd is loaded at runtime, so this is
# only needed to drop the dependency entirely):
cargo build -p df2b-agent --no-default-features

# journald test against a running journald (needs systemd-cat):
cargo test -p df2b-sources --features journald -- --ignored live_journal
```

`protoc` is vendored (`protoc-bin-vendored`); set `PROTOC` to use a system one.

## Debian packages

CI (`.github/workflows/packages.yml`) builds `.deb` packages for amd64 and arm64
(Debian 12+, Ubuntu 24.04+): download them from the workflow run's artifacts
or, for `v*` tags, from the GitHub release. Locally: build the web UI, then
`cargo install cargo-deb --locked && packaging/deb/build.sh` (→ `target/debian/`).

| Package           | Contents                                                                                 |
|-------------------|------------------------------------------------------------------------------------------|
| `df2b-agent`      | `/usr/bin/df2b-agent`, `df2b-agent.service` (user `df2b`), `/etc/df2b/agent.toml`, `/etc/df2b/filters/` |
| `df2b-controller` | `/usr/bin/df2b-controller` (web UI embedded), `df2b-controller.service`                   |
| `df2bctl`         | `/usr/bin/df2bctl`                                                                       |

```sh
sudo apt install ./df2b-agent_*.deb ./df2bctl_*.deb   # pulls in nftables
```

The services are enabled and started on installation. The agent starts with
`firewall = "dry-run"`: edit `/etc/df2b/agent.toml` (and the filters in
`/etc/df2b/filters/`, both kept on upgrades), set `firewall = "nftables"`,
then `sudo systemctl reload df2b-agent` (or `df2bctl --local config reload`).
For a controller, put `DF2B_ENROLL_TOKEN=…` into `/etc/df2b/agent.env` and
restart the agent.

The controller keeps its state in `/var/lib/df2b-controller`; its options
go into `/etc/df2b/controller.env` as environment variables
(`DF2B_OIDC_CONFIG=/etc/df2b/oidc.toml`, `DF2B_GEOIP=a.mmdb,b.mmdb`, see
`df2b-controller --help`). It runs with `DynamicUser=yes`, so run its
management commands (`user`, `api-token`, `enroll-token`, `revoke`) as that
user:

```sh
sudo systemd-run --pty --quiet -p DynamicUser=yes -p User=df2b-controller \
    -p StateDirectory=df2b-controller \
    /usr/bin/df2b-controller user add ada --role admin
```

`apt remove` and `apt purge` keep the state in `/var/lib/df2b` and
`/var/lib/private/df2b-controller` (agent keys, controller CA, users and
tokens: a reinstalled controller keeps its agents). Delete it by hand to
start over.

## RPM packages

The same workflow builds `.rpm` packages for x86_64 and aarch64 on
AlmaLinux 9 (glibc 2.34: RHEL 9 and its rebuilds, Fedora): workflow
artifacts, or the GitHub release for `v*` tags. Locally: build the web UI,
then `cargo install cargo-generate-rpm --locked && packaging/rpm/build.sh`
(→ `target/generate-rpm/`; no `rpmbuild` needed).

The packages and files are those of the Debian packages (units in
`/usr/lib/systemd/system`, the `df2b` user from `/usr/lib/sysusers.d`);
`/etc/df2b/agent.toml` and the filters are `%config(noreplace)`.

```sh
sudo dnf install ./df2b-agent-*.rpm ./df2bctl-*.rpm   # pulls in nftables
```

As with the Debian packages, installation enables and starts the services
(not the Fedora/RHEL convention of starting nothing), and upgrades restart
running services. Configure the agent as above.

`dnf remove` stops and disables the services but keeps the state in
`/var/lib/df2b` and `/var/lib/private/df2b-controller` (delete them by
hand) and saves modified configuration files as `*.rpmsave`.

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
cargo run -p df2bctl -- agents set-group <agent-id> db   # admin
cargo run -p df2bctl -- ban 203.0.113.7 --for 24h --reason scanner
cargo run -p df2bctl -- bans list
cargo run -p df2bctl -- unban 203.0.113.7
cargo run -p df2bctl -- audit
cargo run -p df2bctl -- allowlist add 192.0.2.0/24 --comment office   # admin
cargo run -p df2bctl -- allowlist list
cargo run -p df2bctl -- jails list                # jails on the agents, central settings
cargo run -p df2bctl -- jails set sshd --maxretry 3 --bantime 2h [--group web]   # admin
cargo run -p df2bctl -- propagate group           # admin: local bans apply to the host's group
cargo run -p df2bctl -- correlation set distributed --kind threshold --min-failures 20 --min-agents 4 --window 1h --bantime 12h --monitor
cargo run -p df2bctl -- filter push app-auth app-auth.toml                     # admin
cargo run -p df2bctl -- jails define app --filter app-auth --file /var/log/app/auth.log --group web
cargo run -p df2bctl -- sessions list            # web UI sessions (admin)
cargo run -p df2bctl -- redaction preset ssh-user   # admin: hide user names in sample lines (agents apply it too)
cargo run -p df2bctl -- sessions end --user olga # or <id>, or --all

# Plain HTTPS works too (internal CA: verify the name df2b-controller)
curl --cacert /tmp/df2b-ctl/ca.pem --resolve df2b-controller:7444:127.0.0.1 \
    -H "Authorization: Bearer df2bapi1.…" https://df2b-controller:7444/api/v1/status
```

The API is described in OpenAPI 3.1 at `/api/v1/openapi.json` (no token
needed; also in the repository as `crates/df2b-controller/openapi.json`):

```sh
curl --cacert /tmp/df2b-ctl/ca.pem --resolve df2b-controller:7444:127.0.0.1 \
    https://df2b-controller:7444/api/v1/openapi.json
```

### Web UI (same port, 7444)

```sh
# On the controller host, as the controller's user (the files are 0600):
cargo run -p df2b-controller -- --state-dir /tmp/df2b-ctl user add ada --role admin
#   asks for the password (min. 12 characters); or pipe it on stdin
# also: user list, user passwd ada, user set-role ada viewer, user delete ada
```

Further users can be added by an admin on the "Users" page (with a temporary
password the user must change at the first sign-in). Then open
`https://<controller>:7444/`. With the internal CA the browser warns
until you trust `<state-dir>/ca.pem` and use the name `df2b-controller` (or a
`--name`); for a public name use `--https-cert/--https-key`.

Single sign-on with an OpenID Connect provider (Keycloak, Authentik, Entra
ID, Google, ...): register `https://<controller>:7444/api/v1/oidc/callback`
as redirect URI, map the provider's groups to roles in a copy of
[`config/oidc.example.toml`](config/oidc.example.toml) and start the
controller with `--oidc-config /etc/df2b/oidc.toml`. The login page then
offers "Sign in with …". Also register
`https://<controller>:7444/api/v1/oidc/backchannel-logout` as back-channel
logout URL, so logging out or disabling a user at the provider ends their
controller sessions at once (providers without it: front-channel logout
URL `…/api/v1/oidc/frontchannel-logout`, with "session required").

ASN and country of banned addresses (Overview, Bans, address page,
`df2bctl lookup`): start the controller with `--geoip` and MaxMind DB
files, e.g. `--geoip /var/lib/GeoIP/GeoLite2-ASN.mmdb --geoip
/var/lib/GeoIP/GeoLite2-Country.mmdb` (kept current by `geoipupdate`;
reloaded when they change). DB-IP Lite and ipinfo Lite `.mmdb` files work
too. No database is included.

UI development with hot reload against a running controller:
`DF2B_CONTROLLER=https://127.0.0.1:7444 npm --prefix web run dev`.

With systemd, put `DF2B_ENROLL_TOKEN=df2b1.…` into `/etc/df2b/agent.env` for
the first start (the unit reads it); the token is useless afterwards.

## License

MIT, see [LICENSE](LICENSE).

The binaries also contain third-party code: Rust crates, and the Svelte
runtime in the controller's web UI. All of it is under permissive licenses
(MIT, Apache-2.0, BSD, ISC, Unicode-3.0, CDLA-Permissive-2.0 for the Mozilla
root certificates in `webpki-roots`, ...). Their license texts are installed
with every package as `THIRD-PARTY-LICENSES`, in `/usr/share/doc/<package>/`
(deb) or `/usr/share/licenses/<package>/` (rpm). The package builds generate
that file with `node packaging/third-party-licenses.mjs`. The build fails
when a dependency's license is not on the script's allow list, so a copyleft
or unknown license cannot slip in with a new dependency. GeoIP databases are
not included (their licenses are separate), and `libsystemd` (LGPL-2.1+) is
loaded at run time, not linked in.
