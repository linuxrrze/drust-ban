# syntax=docker/dockerfile:1
#
# One image with df2b-agent, df2b-controller and df2bctl.
#
#   docker build -f Containerfile -t df2b .      (or: podman build -t df2b .)
#
# The controller is the default command and runs as the unprivileged user
# df2b-controller. The agent needs the host's network and NET_ADMIN to
# reach the host's nftables ruleset: see packaging/container/compose.yaml
# and the "Containers" section of README.md.
#
# Base images: override with --build-arg to pin exact versions or digests.
# The build and runtime stages must share a Debian release (glibc).
ARG NODE_IMAGE=node:24-trixie-slim
ARG RUST_IMAGE=rust:1-trixie
ARG RUNTIME_IMAGE=debian:trixie-slim

# --- web UI (embedded into the controller) ---
FROM ${NODE_IMAGE} AS web
WORKDIR /src/web
COPY web/package.json web/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY web/ ./
RUN npm run build

# --- binaries, manual pages, license notices ---
FROM ${RUST_IMAGE} AS build
WORKDIR /src
COPY . .
COPY --from=web /src/web/dist web/dist
# the license generator also reads the web UI's runtime packages
COPY --from=web /src/web/node_modules web/node_modules
COPY --from=web /usr/local/bin/node /usr/local/bin/node
# The license generator fails on a dependency whose license is not on the
# allowed list. The agent's configuration gets its filters from
# /etc/df2b/filters, like the packages.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    set -eu; \
    cargo build --release --locked -p df2b-agent -p df2b-controller -p df2bctl; \
    mkdir -p /out/bin /out/man /out/doc; \
    for bin in df2b-agent df2b-controller df2bctl; do \
        cp "target/release/$bin" /out/bin/; \
        "target/release/$bin" --generate-man /out/man; \
    done; \
    gzip -9n /out/man/*.1; \
    node packaging/third-party-licenses.mjs > /out/doc/THIRD-PARTY-LICENSES; \
    cp LICENSE /out/doc/; \
    sed 's|^filter_dir = "../filters"|filter_dir = "filters"|' \
        config/agent.example.toml > /out/agent.toml; \
    grep -q '^filter_dir = "filters"' /out/agent.toml

# --- runtime ---
FROM ${RUNTIME_IMAGE}
# nftables: the agent's default firewall backend (nft); libsystemd0: the
# journald source (loaded at runtime); ca-certificates: OIDC, webhooks
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates libsystemd0 nftables \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --user-group --no-create-home \
        --home-dir /var/lib/df2b-controller --shell /usr/sbin/nologin df2b-controller \
    && install -d -m 0700 -o df2b-controller -g df2b-controller /var/lib/df2b-controller \
    && install -d -m 0700 /var/lib/df2b
COPY --from=build /out/bin/ /usr/bin/
COPY --from=build /out/man/ /usr/share/man/man1/
COPY --from=build /out/doc/ /usr/share/doc/df2b/
COPY --from=build /out/agent.toml /etc/df2b/agent.toml
COPY filters/ /etc/df2b/filters/

ARG VERSION=dev
LABEL org.opencontainers.image.title="dist-f2b" \
      org.opencontainers.image.description="Distributed fail2ban: agent, controller and df2bctl" \
      org.opencontainers.image.source="https://github.com/linuxrrze/drust-ban" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.version="${VERSION}"

# agents (gRPC, mutual TLS) and REST API / web UI (HTTPS)
EXPOSE 7443 7444
VOLUME ["/var/lib/df2b-controller"]
USER df2b-controller
CMD ["df2b-controller"]
