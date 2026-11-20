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
# bans reach the firewall and the controller. A ban must also stop
# forwarded traffic to a DNATed port, the way Docker publishes container
# ports (client and server in network namespaces). Then it does the same
# with firewall = "ipset". Any unit that dies or logs a seccomp/permission
# problem fails the test.
set -euo pipefail

debs=$(realpath "${1:?usage: $0 <directory with the .deb files>}")
work=$(mktemp -d)
trap 'rm -rf "$work"; [[ -z $httpd ]] || kill "$httpd" 2> /dev/null || true' EXIT

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

# A "published container port": a client namespace (10.99.1.2) reaches
# port 8080 on the host (10.99.1.1), which is DNATed to a web server in a
# second namespace (10.99.2.2:80), so the packets are forwarded and never
# pass the host's input hook.
httpd=
forward_setup() {
    ip netns add df2bc
    ip netns add df2bs
    ip link add c1 type veth peer name c0 netns df2bc
    ip link add s1 type veth peer name s0 netns df2bs
    ip addr add 10.99.1.1/24 dev c1
    ip addr add 10.99.2.1/24 dev s1
    ip link set c1 up
    ip link set s1 up
    ip -n df2bc addr add 10.99.1.2/24 dev c0
    ip -n df2bs addr add 10.99.2.2/24 dev s0
    for ns in df2bc df2bs; do
        ip -n "$ns" link set lo up
    done
    ip -n df2bc link set c0 up
    ip -n df2bs link set s0 up
    ip -n df2bc route add default via 10.99.1.1
    ip -n df2bs route add default via 10.99.2.1
    sysctl -qw net.ipv4.ip_forward=1
    nft -f - <<'NFT'
table ip df2btest {
    chain prerouting {
        type nat hook prerouting priority -100; policy accept;
        iifname "c1" tcp dport 8080 dnat to 10.99.2.2:80
    }
}
NFT
    # Docker on the runner sets the FORWARD policy to DROP
    iptables -I FORWARD 1 -i c1 -o s1 -j ACCEPT
    iptables -I FORWARD 1 -i s1 -o c1 -j ACCEPT
    ip netns exec df2bs python3 -m http.server 80 --bind 10.99.2.2 > /dev/null 2>&1 &
    httpd=$!
}
reach() {
    ip netns exec df2bc curl -s -o /dev/null --max-time 3 http://10.99.1.1:8080/
}
unreachable() { ! reach; }
# $1: backend, $2…: command that succeeds once 10.99.1.2 is in its set
forwarded_ban() {
    local backend=$1
    shift
    wait_for 15 reach || fail "forwarded port not reachable before the ban ($backend)"
    df2bctl ban 10.99.1.2 --reason ci > /dev/null
    wait_for 30 "$@" || fail "forwarded-port ban not in the firewall ($backend)"
    wait_for 10 unreachable || fail "a ban did not stop forwarded (DNAT) traffic ($backend)"
    df2bctl unban 10.99.1.2 > /dev/null
    wait_for 30 reach || fail "forwarded port not reachable after the unban ($backend)"
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
forward_setup
forwarded_ban nftables in_set ban_v4 10.99.1.2
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
iptables -t raw -S PREROUTING | grep -q df2b4 || fail "no iptables rule for the set"
forwarded_ban ipset ipset test df2b4 10.99.1.2
ipset list df2b4
active df2b-controller df2b-agent
end

step "action secrets as systemd credentials"
# root-only files, handed to the controller's dynamic user with
# LoadCredential= (README.md); the action program finds its secret through
# $CREDENTIALS_DIRECTORY and leaves the secret's checksum as proof
head -c 32 /dev/urandom | base64 > /etc/df2b/hook-token
chmod 600 /etc/df2b/hook-token
install -m 0600 /dev/stdin /etc/df2b/actions.toml <<'TOML'
[[exec]]
name = "ci"
command = ["/usr/local/bin/df2b-test-action"]
origins = ["user"]
events = ["ban"]
timeout = "10s"
TOML
install -m 0755 /dev/stdin /usr/local/bin/df2b-test-action <<'SH'
#!/bin/sh
# atomically: the test may read while another run of the action writes
d=/var/lib/df2b-controller
sha256sum < "$CREDENTIALS_DIRECTORY/hook-token" > "$d/action-saw.$$"
mv "$d/action-saw.$$" "$d/action-saw"
SH
mkdir -p /etc/systemd/system/df2b-controller.service.d
cat > /etc/systemd/system/df2b-controller.service.d/credentials.conf <<'INI'
[Service]
LoadCredential=actions.toml:/etc/df2b/actions.toml
LoadCredential=hook-token:/etc/df2b/hook-token
Environment=DF2B_ACTIONS=%d/actions.toml
INI
systemctl daemon-reload
systemctl restart df2b-controller
wait_for 30 df2bctl agents list || fail "controller not answering with the credentials drop-in"
df2bctl ban 203.0.113.50 --reason ci > /dev/null
saw=/var/lib/private/df2b-controller/action-saw
wait_for 30 test -s "$saw" || fail "the action did not run or could not read its credential"
[[ $(cat "$saw") == "$(sha256sum < /etc/df2b/hook-token)" ]] \
    || fail "the action read something else than the credential: '$(cat "$saw")'"
df2bctl unban 203.0.113.50 > /dev/null
if journalctl -b --no-pager -u df2b-controller | grep -q 'readable by everyone'; then
    fail "the controller warned about a readable actions file"
fi
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
