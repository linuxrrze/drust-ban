#!/bin/sh
# Builds the RPM packages df2b-agent, df2b-controller and df2bctl into
# target/generate-rpm/ (needs cargo-generate-rpm, no rpmbuild:
# cargo install cargo-generate-rpm --locked).
#
# The web UI must be built first (it is embedded into the controller):
#   npm --prefix web ci && npm --prefix web run build
#
# RPM_VERSION overrides the package version (default: Cargo version),
# RPM_RELEASE the release (default: 1). The asset and scriptlet paths in the
# [package.metadata.generate-rpm] sections are relative to the workspace root.
set -eu

cd "$(dirname "$0")/../.."

if [ ! -f web/dist/index.html ]; then
    echo "web/dist is missing: run 'npm --prefix web ci && npm --prefix web run build' first" >&2
    exit 1
fi

# cargo-generate-rpm takes a scriptlet path that does not exist for the
# script text itself: make sure they are all there.
for script in post preun postun; do
    for pkg in df2b-agent df2b-controller; do
        if [ ! -f "packaging/rpm/$pkg/$script" ]; then
            echo "packaging/rpm/$pkg/$script is missing" >&2
            exit 1
        fi
    done
done

# /etc/df2b/agent.toml: the example configuration with the filters in
# /etc/df2b/filters (the example's "../filters" fits the source tree only).
mkdir -p target/rpm/bin
sed 's|^filter_dir = "../filters"|filter_dir = "filters"|' \
    config/agent.example.toml > target/rpm/agent.toml
if ! grep -q '^filter_dir = "filters"' target/rpm/agent.toml; then
    echo "config/agent.example.toml: filter_dir line not found, update $0" >&2
    exit 1
fi

# license texts of the third-party code in the binaries; fails on a
# dependency whose license is not on the allowed list
node packaging/third-party-licenses.mjs > target/rpm/THIRD-PARTY-LICENSES.tmp
mv target/rpm/THIRD-PARTY-LICENSES.tmp target/rpm/THIRD-PARTY-LICENSES

cargo build --release --locked -p df2b-agent -p df2b-controller -p df2bctl

# cargo-generate-rpm does not strip (cargo-deb does): package stripped copies
for bin in df2b-agent df2b-controller df2bctl; do
    cp "target/release/$bin" "target/rpm/bin/$bin"
    strip "target/rpm/bin/$bin"
done

set --
if [ -n "${RPM_VERSION:-}" ]; then
    set -- "$@" --set-metadata "version = \"$RPM_VERSION\""
fi
if [ -n "${RPM_RELEASE:-}" ]; then
    set -- "$@" --set-metadata "release = \"$RPM_RELEASE\""
fi

mkdir -p target/generate-rpm
rm -f target/generate-rpm/df2b-agent-*.rpm target/generate-rpm/df2b-controller-*.rpm \
    target/generate-rpm/df2bctl-*.rpm
for pkg in df2b-agent df2b-controller df2bctl; do
    cargo generate-rpm -p "crates/$pkg" -o target/generate-rpm/ "$@"
done

ls -l target/generate-rpm/*.rpm
