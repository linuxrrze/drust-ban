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
#   rtbh-gobgp.sh STATE_FILE [NEXTHOP [COMMUNITY [GOBGP]]]
# STATE_FILE lists the prefixes this script announced (in a directory the
# controller may write, e.g. /var/lib/df2b-controller/rtbh.announced).
STATE=${1:?usage: rtbh-gobgp.sh STATE_FILE [NEXTHOP [COMMUNITY [GOBGP]]]}
NEXTHOP=${2:-192.0.2.1}      # discard next hop known upstream
COMMUNITY=${3:-65535:666}    # BLACKHOLE
GOBGP=${4:-gobgp}

family() {
    case "$1" in
        *:*) echo ipv6 ;;
        *) echo ipv4 ;;
    esac
}

announce() {
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
        wanted=$(jq -r '.bans[].target')
        have=$(cat "$STATE" 2>/dev/null || true)
        for p in $wanted; do
            printf '%s\n' "$have" | grep -qxF "$p" || announce "$p"
        done
        for p in $have; do
            printf '%s\n' "$wanted" | grep -qxF "$p" || withdraw "$p"
        done
        ;;
    *)
        echo "unknown event ${DF2B_EVENT:-}" >&2
        exit 1
        ;;
esac
