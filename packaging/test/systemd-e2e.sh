#!/bin/bash
# End-to-end test of the Debian packages under their real systemd units
# (sandboxing, SystemCallFilter, DynamicUser) with the real nftables and
# ipset/iptables backends. Needs a disposable host with systemd as PID 1,
# root, and the three .deb files: CI runs it on a GitHub runner.
#
#   sudo packaging/test/systemd-e2e.sh target/debian
#
# It installs the packages, enrolls the agent, feeds failed logins through
# the journal (as a unit, like sshd) and a log file, and checks that the
# bans reach the firewall and the controller. Then it does the same with
# firewall = "ipset". Any unit that dies or logs a seccomp/permission
# problem fails the test.
set -euo pipefail

debs=$(realpath "${1:?usage: $0 <directory with the .deb files>}")
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

step() { echo "::group::$*"; }
end() { echo "::endgroup::"; }
fail() {
    echo "::error::$*"
    for u in df2b-controller df2b-agent; do
        echo "--- $u"
        systemctl status --no-pager "$u" || true
        journalctl -b -u "$u" --no-pager | tail -n 80 || true
    done
    exit 1
}

# waits up to $1 seconds for the command to succeed
wait_for() {
    local t=$1
    shift
    for _ in $(seq "$t"); do
        if "$@" > /dev/null 2>&1; then
            return 0
        fi
        sleep 1
    done
    return 1
}

active() {
    for u in "$@"; do
        systemctl is-active --quiet "$u" || fail "$u is not running"
    done
}

# a management command as the controller's (dynamic) user, as README.md
# documents it
as_controller() {
    systemd-run --pipe --wait --quiet -p DynamicUser=yes -p User=df2b-controller \
        -p StateDirectory=df2b-controller /usr/bin/df2b-controller "$@"
}

# a failed sshd login, sent to the journal by a unit called
# df2b-test-sshd.service (journald records the sending unit)
journal_failure() {
    systemd-run --wait --quiet --unit="df2b-test-sshd-$RANDOM" \
        -p SyslogIdentifier=sshd \
        /bin/echo "Failed password for root from $1 port 22 ssh2" > /dev/null
}

file_failure() {
    echo "$(date '+%b %e %H:%M:%S') host sshd[123]: Failed password for root from $1 port 22 ssh2" \
        >> /var/log/df2b-test.log
}

step "install"
apt-get update -q
DEBIAN_FRONTEND=noninteractive apt-get install -y -q nftables ipset iptables \
    "$debs"/df2b-agent_*.deb "$debs"/df2b-controller_*.deb "$debs"/df2bctl_*.deb
active df2b-controller df2b-agent
systemctl show -p SystemCallFilter --value df2b-agent | grep -q . \
    || fail "df2b-agent.service has no SystemCallFilter"
systemd-analyze security --no-pager df2b-agent df2b-controller || true
end

step "enroll the agent"
token=$(as_controller enroll-token --group web | head -n1)
[[ $token == df2b1.* ]] || fail "no enrollment token: $token"
# (the df2bctl configuration comes on stderr; neither goes to the log)
umask 077
as_controller api-token create --name ci --role admin --url https://127.0.0.1:7444 2>&1 \
    | sed -n '/^controller = /,$p' > "$work/df2bctl.toml"
umask 022
grep -q '^token = ' "$work/df2bctl.toml" || fail "no df2bctl configuration from api-token create"
export DF2B_CTL_CONFIG="$work/df2bctl.toml"

install -m 0640 -g adm /dev/null /var/log/df2b-test.log
agent_config() {
    cat > /etc/df2b/agent.toml <<EOF
[agent]
controller = "https://127.0.0.1:7443"
filter_dir = "filters"
firewall = "$1"
ipv6_widen_after = 2

[[source]]
name = "journal"
type = "journald"
matches = ["SYSLOG_IDENTIFIER=sshd"]

[[source]]
name = "file"
type = "file"
paths = ["/var/log/df2b-test.log"]

[[jail]]
name = "sshd"
sources = ["journal"]
filter = "sshd"
maxretry = 2
findtime = "10m"
bantime = "1h"

[[jail]]
name = "sshd-file"
sources = ["file"]
filter = "sshd-syslog"
maxretry = 2
findtime = "10m"
bantime = "1h"
EOF
}
agent_config nftables
echo "DF2B_ENROLL_TOKEN=$token" > /etc/df2b/agent.env
systemctl restart df2b-agent
wait_for 30 df2bctl --local status || fail "agent control socket not answering"
wait_for 30 sh -c 'df2bctl --local status | grep -q "(connected)"' \
    || { df2bctl --local status || true; fail "agent not connected to the controller"; }
df2bctl --local status
df2bctl agents list
end

step "bans with nftables"
for _ in 1 2; do
    journal_failure 192.0.2.10
    file_failure 198.51.100.20
    file_failure 2001:db8:77:1::1
    file_failure 2001:db8:77:2::1
done
in_set() { nft list set inet df2b "$1" | grep -q -- "$2"; }
wait_for 30 in_set ban_v4 192.0.2.10 || fail "journal ban not in nftables"
wait_for 30 in_set ban_v4 198.51.100.20 || fail "file ban not in nftables"
wait_for 30 in_set ban_v6 2001:db8:77::/48 || fail "widened /48 not in nftables"
nft list table inet df2b
wait_for 30 sh -c 'df2bctl bans list | grep -q 192.0.2.10' || fail "ban not on the controller"
df2bctl bans list
# reconciliation lists the set through nft -j (every 5 minutes after the
# start): a deleted element comes back
nft delete element inet df2b ban_v4 '{ 198.51.100.20 }'
wait_for 330 in_set ban_v4 198.51.100.20 || fail "reconciliation did not restore a deleted element"
# a ban from the controller reaches the firewall, an unban lifts it
df2bctl ban 203.0.113.30 --reason ci > /dev/null
wait_for 30 in_set ban_v4 203.0.113.30 || fail "controller ban not in nftables"
df2bctl unban 203.0.113.30 > /dev/null
wait_for 30 sh -c '! nft list set inet df2b ban_v4 | grep -q 203.0.113.30' \
    || fail "controller unban not applied"
systemctl reload df2b-agent
sleep 2
active df2b-controller df2b-agent
end

step "bans with ipset"
agent_config ipset
mkdir -p /etc/systemd/system/df2b-agent.service.d
cat > /etc/systemd/system/df2b-agent.service.d/ipset.conf <<'EOF'
[Service]
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW
ReadWritePaths=-/run/xtables.lock
EOF
systemctl daemon-reload
systemctl restart df2b-agent
wait_for 30 df2bctl --local status || fail "agent not answering after the switch to ipset"
for _ in 1 2; do
    file_failure 198.51.100.40
done
wait_for 30 sh -c 'ipset list df2b4 | grep -q 198.51.100.40' || fail "ban not in ipset"
# active bans are re-applied to the new backend
wait_for 30 sh -c 'ipset list df2b4 | grep -q 192.0.2.10' || fail "active ban not re-applied"
iptables -S | grep -q df2b4 || fail "no iptables rule for the set"
ipset list df2b4
active df2b-controller df2b-agent
end

step "no sandbox violations"
if journalctl -b --no-pager -u df2b-agent -u df2b-controller \
    | grep -Ei 'operation not permitted|permission denied|seccomp|bad system call'; then
    fail "the services ran into their sandbox"
fi
if journalctl -b -k --no-pager | grep -E 'audit.*(type=1326|SECCOMP).*df2b'; then
    fail "seccomp denials in the kernel log"
fi
end
step "purge keeps the state"
DEBIAN_FRONTEND=noninteractive apt-get purge -y -q df2b-agent df2b-controller df2bctl
for u in df2b-controller df2b-agent; do
    ! systemctl is-active --quiet "$u" || fail "$u still running after the purge"
done
test -d /var/lib/df2b || fail "purge removed /var/lib/df2b"
test -d /var/lib/private/df2b-controller || fail "purge removed the controller state"
ls -la /var/lib/df2b /var/lib/private/df2b-controller
end
echo "systemd end-to-end test passed"
