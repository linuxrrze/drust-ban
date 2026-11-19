#!/bin/sh
# Example exec action for df2b-controller: announces banned prefixes to a
# local GoBGP daemon with the BLACKHOLE community (RFC 7999), so upstream
# routers drop the traffic (remotely triggered black hole).
#
# actions.toml:
#   [[exec]]
#   name = "rtbh"
#   command = ["/usr/local/bin/rtbh-gobgp.sh",
#              "/var/lib/df2b-controller/rtbh.announced", "192.0.2.1"]
#   scopes = ["global"]          # only network-wide bans
#   sync_interval = "1h"
#
# Needs gobgp (the CLI) and jq. Events (DF2B_EVENT): ban, unban, expire,
# sync (stdin: {"bans": [...]}, the complete list: routes not in it are
# withdrawn). Never pass these values through a shell unquoted.
set -eu

# Arguments (the controller clears the environment):
#   rtbh-gobgp.sh STATE_FILE [NEXTHOP [COMMUNITY [GOBGP [MIN_V4 [MIN_V6]]]]]
# STATE_FILE lists the prefixes this script announced (in a directory the
# controller may write, e.g. /var/lib/df2b-controller/rtbh.announced).
STATE=${1:?usage: rtbh-gobgp.sh STATE_FILE [NEXTHOP [COMMUNITY [GOBGP]]]}
NEXTHOP=${2:-192.0.2.1}      # discard next hop known upstream
COMMUNITY=${3:-65535:666}    # BLACKHOLE
GOBGP=${4:-gobgp}
# Only blackhole prefixes at least this long (default: single hosts): a
# wider ban - a mistake or a compromised agent - must not drop whole
# networks upstream.
MIN_V4=${5:-32}
MIN_V6=${6:-128}

family() {
    case "$1" in
        *:*) echo ipv6 ;;
        *) echo ipv4 ;;
    esac
}

# true if the prefix is narrow enough to blackhole
narrow() {
    len=${1##*/}
    case "$1" in
        *:*) [ "$len" -ge "$MIN_V6" ] ;;
        *) [ "$len" -ge "$MIN_V4" ] ;;
    esac
}

announce() {
    if ! narrow "$1"; then
        echo "not blackholing $1: wider than /$MIN_V4 resp. /$MIN_V6" >&2
        return 0
    fi
    "$GOBGP" global rib -a "$(family "$1")" add "$1" nexthop "$NEXTHOP" community "$COMMUNITY"
    grep -qxF "$1" "$STATE" 2>/dev/null || printf '%s\n' "$1" >> "$STATE"
}

withdraw() {
    "$GOBGP" global rib -a "$(family "$1")" del "$1" || true
    if [ -f "$STATE" ]; then
        grep -vxF "$1" "$STATE" > "$STATE.tmp" || true
        mv "$STATE.tmp" "$STATE"
    fi
}

case "${DF2B_EVENT:-}" in
    ban)
        announce "$DF2B_TARGET"
        ;;
    unban | expire)
        # another ban may still cover the same prefix
        if [ "${DF2B_STILL_BANNED:-0}" = 0 ]; then
            withdraw "$DF2B_TARGET"
        fi
        ;;
    sync)
        # set differences with sort/comm: one pass, also for many bans
        tmp=$(mktemp -d)
        trap 'rm -rf "$tmp"' EXIT
        jq -r '.bans[].target' | sort -u > "$tmp/wanted"
        sort -u "$STATE" 2>/dev/null > "$tmp/have" || : > "$tmp/have"
        comm -23 "$tmp/wanted" "$tmp/have" | while read -r p; do announce "$p"; done
        comm -13 "$tmp/wanted" "$tmp/have" | while read -r p; do withdraw "$p"; done
        ;;
    *)
        echo "unknown event ${DF2B_EVENT:-}" >&2
        exit 1
        ;;
esac
