#!/usr/bin/env bash
# Validation tests only. Never install packages or change host networking.
set -euo pipefail
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=../server/install-server.sh
. "$script_dir/../server/install-server.sh"
test_dir=$(mktemp -d)
trap 'rm -rf -- "$test_dir"' EXIT
key=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
cat > "$test_dir/valid.conf" <<CONF
[Interface]
Address = 10.66.66.1/24, fd66:66:66::1/64
ListenPort = 51820
PrivateKey = $key

[Peer]
PublicKey = $key
AllowedIPs = 10.66.66.2/32, fd66:66:66::2/128
CONF
count=0
expect_valid() {
    validate_config "$1" || { echo 'Expected valid configuration.' >&2; exit 1; }
    count=$((count + 1))
}
expect_invalid() {
    if validate_config "$1"; then echo 'Unsafe or unexpected configuration was accepted.' >&2; exit 1; fi
    count=$((count + 1))
}
expect_valid "$test_dir/valid.conf"
sed 's/$/\r/' "$test_dir/valid.conf" > "$test_dir/crlf.conf"
expect_valid "$test_dir/crlf.conf"
sed 's/^\[Peer\]/  [Peer]  /' "$test_dir/valid.conf" > "$test_dir/spaces.conf"
expect_valid "$test_dir/spaces.conf"
{ cat "$test_dir/valid.conf"; printf '\nPostUp = touch /tmp/unsafe\n'; } > "$test_dir/hook.conf"
expect_invalid "$test_dir/hook.conf"
sed 's/10.66.66.2\/32/0.0.0.0\/0/' "$test_dir/valid.conf" > "$test_dir/wide-peer.conf"
expect_invalid "$test_dir/wide-peer.conf"
sed 's/ListenPort = 51820/ListenPort = 51820\nListenPort = 1234/' "$test_dir/valid.conf" > "$test_dir/duplicate.conf"
expect_invalid "$test_dir/duplicate.conf"
sed '/^PrivateKey/d' "$test_dir/valid.conf" > "$test_dir/missing-key.conf"
expect_invalid "$test_dir/missing-key.conf"
sed 's/PrivateKey = .*/PrivateKey = $(unsafe)/' "$test_dir/valid.conf" > "$test_dir/injection.conf"
expect_invalid "$test_dir/injection.conf"
{ cat "$test_dir/valid.conf"; printf '\n[Peer]\n'; } > "$test_dir/multi-peer.conf"
expect_invalid "$test_dir/multi-peer.conf"
sed 's/51820/443/' "$test_dir/valid.conf" > "$test_dir/custom-port.conf"
expect_valid "$test_dir/custom-port.conf"
sed 's/51820/0/' "$test_dir/valid.conf" > "$test_dir/zero-port.conf"
expect_invalid "$test_dir/zero-port.conf"
sed 's/51820/65536/' "$test_dir/valid.conf" > "$test_dir/large-port.conf"
expect_invalid "$test_dir/large-port.conf"

# Firewall argument failures must happen before any real iptables invocation.
if bash "$script_dir/../server/myvpn-firewall.sh" up wg0 'eth0;touch /tmp/unsafe' 51820 >/dev/null 2>&1; then
    echo 'Unsafe interface name accepted.' >&2; exit 1
fi
count=$((count + 1))
if bash "$script_dir/../server/myvpn-firewall.sh" up wg1 eth0 51820 >/dev/null 2>&1; then
    echo 'Unexpected tunnel accepted.' >&2; exit 1
fi
count=$((count + 1))
printf 'Passed %s server configuration/argument checks. No host networking changed.\n' "$count"
