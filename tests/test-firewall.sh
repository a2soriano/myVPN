#!/usr/bin/env bash
# Exercise rule selection, idempotence and failure rollback with fake commands.
# This never invokes the host's iptables/ip6tables binaries or requires root.
set -euo pipefail
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
test_dir=$(mktemp -d)
trap 'rm -rf -- "$test_dir"' EXIT
export MYVPN_MOCK_RULES="$test_dir/rules"
printf 'unrelated pre-existing rule\n' > "$MYVPN_MOCK_RULES"

cat > "$test_dir/mock.sh" <<'MOCK'
mock_firewall() {
    local binary=$1
    shift
    [[ $1 == -w && $2 == 5 && $3 == -t ]] || return 90
    local table=$4 operation=$5 chain=$6
    shift 6
    if [[ $operation == -I ]]; then
        [[ $1 == 1 ]] || return 91
        shift
    fi
    local row="$binary $table $chain $*"
    case $operation in
        -C) grep -F -x -q -- "$row" "$MYVPN_MOCK_RULES" ;;
        -I)
            if [[ $binary == ip6tables && ${MYVPN_MOCK_FAIL_IPV6:-0} == 1 ]]; then return 17; fi
            printf '%s\n' "$row" >> "$MYVPN_MOCK_RULES"
            ;;
        -D)
            grep -F -x -v -- "$row" "$MYVPN_MOCK_RULES" > "$MYVPN_MOCK_RULES.new" || true
            mv -- "$MYVPN_MOCK_RULES.new" "$MYVPN_MOCK_RULES"
            ;;
        *) return 92 ;;
    esac
}
iptables() { mock_firewall iptables "$@"; }
ip6tables() { mock_firewall ip6tables "$@"; }
MOCK

cat > "$test_dir/normal.sh" <<'NORMAL'
. "$1"
. "$2"
action=up tunnel=wg0 uplink=eth0 port=443
run_hooks
[[ $(wc -l < "$MYVPN_MOCK_RULES") == 7 ]]
grep -F -q -- '--dport 443' "$MYVPN_MOCK_RULES"
grep -F -q -- 'ip6tables filter FORWARD -i wg0' "$MYVPN_MOCK_RULES"
grep -F -q -- '-s 10.66.66.2/32 -d 10.66.66.1/32 -p icmp --icmp-type echo-request' "$MYVPN_MOCK_RULES"
run_hooks
[[ $(wc -l < "$MYVPN_MOCK_RULES") == 7 ]]
action=down
run_hooks
[[ $(cat "$MYVPN_MOCK_RULES") == 'unrelated pre-existing rule' ]]
run_hooks
[[ $(cat "$MYVPN_MOCK_RULES") == 'unrelated pre-existing rule' ]]
NORMAL
bash "$test_dir/normal.sh" "$script_dir/../server/myvpn-firewall.sh" "$test_dir/mock.sh"

cat > "$test_dir/failing.sh" <<'FAILING'
. "$1"
. "$2"
action=up tunnel=wg0 uplink=eth0 port=51820
MYVPN_MOCK_FAIL_IPV6=1
run_hooks
FAILING
set +e
bash "$test_dir/failing.sh" "$script_dir/../server/myvpn-firewall.sh" "$test_dir/mock.sh"
result=$?
set -e
[[ $result == 17 ]] || { echo 'Firewall failure exit code was not preserved.' >&2; exit 1; }
[[ $(cat "$MYVPN_MOCK_RULES") == 'unrelated pre-existing rule' ]] || { echo 'Partial rules were not rolled back.' >&2; exit 1; }

# A failed repair must preserve rules that predated this invocation, including
# existing owned rules; rollback is limited to successful inserts just made.
printf 'iptables filter INPUT -p udp --dport 51820 -m comment --comment myvpn-wg0 -j ACCEPT\n' >> "$MYVPN_MOCK_RULES"
printf 'iptables nat POSTROUTING -s 10.66.66.0/24 -o eth0 -m comment --comment myvpn-wg0 -j MASQUERADE\n' >> "$MYVPN_MOCK_RULES"
cp -- "$MYVPN_MOCK_RULES" "$test_dir/original-rules"
set +e
bash "$test_dir/failing.sh" "$script_dir/../server/myvpn-firewall.sh" "$test_dir/mock.sh"
result=$?
set -e
[[ $result == 17 ]] || { echo 'Repair failure exit code was not preserved.' >&2; exit 1; }
cmp -s "$MYVPN_MOCK_RULES" "$test_dir/original-rules" || { echo 'Rollback removed rules from an earlier invocation.' >&2; exit 1; }
printf 'Passed 5 mocked firewall scenarios: port/ping/IPv6 rules, repeatable up, repeatable down/preservation, new-rule rollback, existing-rule preservation.\n'
