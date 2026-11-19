#!/bin/sh
# Builds the Debian packages df2b-agent, df2b-controller and df2bctl into
# target/debian/ (needs cargo-deb: cargo install cargo-deb --locked).
#
# The web UI must be built first (it is embedded into the controller):
#   npm --prefix web ci && npm --prefix web run build
#
# DEB_VERSION overrides the package version (default: Cargo version, "-1").
set -eu

cd "$(dirname "$0")/../.."

if [ ! -f web/dist/index.html ]; then
    echo "web/dist is missing: run 'npm --prefix web ci && npm --prefix web run build' first" >&2
    exit 1
fi

# /etc/df2b/agent.toml: the example configuration with the filters in
# /etc/df2b/filters (the example's "../filters" fits the source tree only).
mkdir -p packaging/deb/generated
sed 's|^filter_dir = "../filters"|filter_dir = "filters"|' \
    config/agent.example.toml > packaging/deb/generated/agent.toml
if ! grep -q '^filter_dir = "filters"' packaging/deb/generated/agent.toml; then
    echo "config/agent.example.toml: filter_dir line not found, update $0" >&2
    exit 1
fi

cargo build --release --locked -p df2b-agent -p df2b-controller -p df2bctl

for pkg in df2b-agent df2b-controller df2bctl; do
    cargo deb --no-build --locked -p "$pkg" -o target/debian/ \
        ${DEB_VERSION:+--deb-version "$DEB_VERSION"}
done

ls -l target/debian/*.deb
