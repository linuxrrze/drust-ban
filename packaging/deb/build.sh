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

# debian/copyright (DEP-5): the license text as an indented field
sed 's/^$/./; s/^/ /' LICENSE > packaging/deb/generated/LICENSE.dep5

# license texts of the third-party code in the binaries; fails on a
# dependency whose license is not on the allowed list
node packaging/third-party-licenses.mjs > packaging/deb/generated/THIRD-PARTY-LICENSES.tmp
mv packaging/deb/generated/THIRD-PARTY-LICENSES.tmp packaging/deb/generated/THIRD-PARTY-LICENSES

cargo build --release --locked -p df2b-agent -p df2b-controller -p df2bctl

# manual pages from the command line definitions (one per subcommand),
# compressed reproducibly
rm -rf packaging/deb/generated/man
for bin in df2b-agent df2b-controller df2bctl; do
    "target/release/$bin" --generate-man "packaging/deb/generated/man/$bin"
done
gzip -9n packaging/deb/generated/man/*/*.1

version=${DEB_VERSION:-$(sed -n 's/^version = "\(.*\)"$/\1/p' Cargo.toml | head -n1)-1}
for pkg in df2b-agent df2b-controller df2bctl; do
    # /usr/share/doc/<package>/changelog.Debian.gz, from git
    packaging/deb/changelog.sh "$pkg" "$version" > "packaging/deb/generated/$pkg.changelog"
    cargo deb --no-build --locked -p "$pkg" -o target/debian/ \
        ${DEB_VERSION:+--deb-version "$DEB_VERSION"}
done

ls -l target/debian/*.deb
