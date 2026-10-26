#!/usr/bin/env bash
# Managed wg-quick hooks. Adds/removes only rules bearing this project's tag.
set -Eeuo pipefail

# Insertion at the front is deliberate: explicit, narrowly scoped rules must
# precede a host's default DROP. The installer refuses UFW/firewalld management.
rule() {
    local identifier=$1 binary=$2 table=$3
    shift 3
    local chain=$1
    shift
    if [[ ${MYVPN_ROLLBACK_ONLY_NEW:-0} == 1 && " ${MYVPN_INSERTED_RULES[*]} " != *" $identifier "* ]]; then
        return 0
    fi
    if [[ $action == up ]]; then
        if ! "$binary" -w 5 -t "$table" -C "$chain" "$@" 2>/dev/null; then
            "$binary" -w 5 -t "$table" -I "$chain" 1 "$@"
            MYVPN_INSERTED_RULES+=("$identifier")
        fi
    elif "$binary" -w 5 -t "$table" -C "$chain" "$@" 2>/dev/null; then
        "$binary" -w 5 -t "$table" -D "$chain" "$@"
    fi
}

apply_rules() {
    rule listener iptables filter INPUT -p udp --dport "$port" -m comment --comment myvpn-wg0 -j ACCEPT
    rule tunnel-ping iptables filter INPUT -i "$tunnel" -s 10.66.66.2/32 -d 10.66.66.1/32 -p icmp --icmp-type echo-request -m comment --comment myvpn-wg0 -j ACCEPT
    rule forward-out iptables filter FORWARD -i "$tunnel" -o "$uplink" -s 10.66.66.0/24 -m conntrack --ctstate NEW,ESTABLISHED,RELATED -m comment --comment myvpn-wg0 -j ACCEPT
    rule forward-in iptables filter FORWARD -i "$uplink" -o "$tunnel" -d 10.66.66.0/24 -m conntrack --ctstate ESTABLISHED,RELATED -m comment --comment myvpn-wg0 -j ACCEPT
    rule masquerade iptables nat POSTROUTING -s 10.66.66.0/24 -o "$uplink" -m comment --comment myvpn-wg0 -j MASQUERADE
    # IPv6 internet is deliberately unsupported. Do not depend on the host's
    # global forwarding default: it might already be enabled for another service.
    rule ipv6-block ip6tables filter FORWARD -i "$tunnel" -m comment --comment myvpn-wg0-v6block -j REJECT
}

rollback() {
    local result=$?
    trap - ERR
    action=down
    MYVPN_ROLLBACK_ONLY_NEW=1
    set +e
    apply_rules
    exit "$result"
}

run_hooks() {
    MYVPN_INSERTED_RULES=()
    MYVPN_ROLLBACK_ONLY_NEW=0
    if [[ $action == up ]]; then
        # wg-quick does not necessarily run PostDown when PostUp fails. Remove
        # this helper's partial rules before returning the original failure.
        trap rollback ERR
    fi
    apply_rules
    trap - ERR
}

main() {
    if [[ $# != 4 || $1 != @(up|down) ]]; then
        echo 'Usage: myvpn-firewall.sh up|down wg0 UPLINK_INTERFACE UDP_PORT' >&2
        return 2
    fi
    action=$1
    tunnel=$2
    uplink=$3
    port=$4
    if [[ $tunnel != wg0 || ! $uplink =~ ^[a-zA-Z0-9_.:-]{1,15}$ || $uplink == wg0 ]]; then
        echo 'Invalid tunnel or uplink interface.' >&2
        return 2
    fi
    if [[ ! $port =~ ^[0-9]{1,5}$ ]] || (( 10#$port < 1 || 10#$port > 65535 )); then
        echo 'Invalid UDP port.' >&2
        return 2
    fi
    if (( EUID != 0 )); then
        echo 'Run this hook as root through wg-quick.' >&2
        return 1
    fi
    run_hooks
}

# Tests source these functions and supply fake iptables commands; no privileged
# command or host network change occurs merely from loading the file.
if [[ ${BASH_SOURCE[0]} == "$0" ]]; then main "$@"; fi
