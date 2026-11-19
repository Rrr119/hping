#!/usr/bin/env bash
#
# hping3 TCP option / timestamp firewall probe test suite.
#
# All network tests run inside an unprivileged user+network namespace, so
# no real root, nftables, tcpdump or scapy is required. A second network
# namespace hosts a small Python AF_PACKET middlebox (tests/fwbox) that
# emulates three firewall behaviours while hping3 probes it.
#
# Topology (single outer userns, one child netns):
#
#   [ outer netns ]  veth-hp <================> veth-fw [ child netns ]
#   hping3 10.20.0.1        10.20.0.2 (real) / 10.20.0.3 (middlebox VIP)
#
# The middlebox answers from the unconfigured VIP 10.20.0.3, so the child
# kernel never owns that address and cannot race the emulator with its own
# TCP RST. A static neighbour entry avoids ARP for the VIP.

set -u

ROOT=$(cd "$(dirname "$0")/.." && pwd)
HPING="$ROOT/hping3"
FWBOX="$ROOT/tests"
LOGDIR="$ROOT/.tmp"

HP_IP=10.20.0.1
FW_IP=10.20.0.2
VIP_IP=10.20.0.3
NET_PREFIX=10.20.0

PASS=0
FAIL=0

ok()   { echo "PASS: $1"; PASS=$((PASS + 1)); }
bad()  { echo "FAIL: $1"; FAIL=$((FAIL + 1)); }

# assert_contains <file> <grep -E pattern> <message>
assert_contains() {
	local file=$1 pattern=$2 message=$3
	if grep -Eq -- "$pattern" "$file"; then ok "$message"; else bad "$message"; fi
}

assert_absent() {
	local file=$1 pattern=$2 message=$3
	if grep -Eq -- "$pattern" "$file"; then bad "$message"; else ok "$message"; fi
}

# Build the two-namespace veth topology and echo the child PID.
# On return: veth-hp exists in the outer ns, veth-fw inside $CHILD ns.
topology_create() {
	ip link set lo up
	ip link add veth-hp type veth peer name veth-fw
	unshare -Urn sleep 120 &
	CHILD=$!
	sleep 1
	ip link set veth-fw netns "$CHILD"
	ip link set veth-hp up
	ip addr add "${HP_IP}/24" dev veth-hp

	nsenter -t "$CHILD" -n ip link set lo up
	nsenter -t "$CHILD" -n ip link set veth-fw up
	nsenter -t "$CHILD" -n ip addr add "${FW_IP}/24" dev veth-fw

	# Static neighbour for the unconfigured middlebox VIP.
	local fw_mac
	fw_mac=$(nsenter -t "$CHILD" -n ip -br link show veth-fw \
		| awk '{print $3}')
	ip neigh replace "$VIP_IP" lladdr "$fw_mac" dev veth-hp nud permanent
}

topology_destroy() {
	kill "$CHILD" 2>/dev/null || true
}

# run_firewall <mode> <logfile>: start the middlebox in the child netns.
run_firewall() {
	local mode=$1 logfile=$2
	nsenter -t "$CHILD" -n env PYTHONPATH="$FWBOX" \
		python3 -m fwbox.firewall veth-fw "$mode" --count 1 \
		--src-ip "$VIP_IP" >"$logfile" 2>&1 &
	FW=$!
	sleep 1
}

build_unit_test() {
	echo "== building C unit tests =="
	cc -O2 -Wall -Werror -I"$ROOT" \
		"$ROOT/tests/unit/test_tcp_options.c" \
		"$ROOT/tcp_options.c" \
		-o "$LOGDIR/test_tcp_options"
}

test_unit() {
	echo "== unit: tcp_options builder =="
	if "$LOGDIR/test_tcp_options" >"$LOGDIR/unit.log" 2>&1; then
		ok "tcp_options unit tests"
	else
		bad "tcp_options unit tests (see .tmp/unit.log)"
		cat "$LOGDIR/unit.log"
	fi
}

test_compat_existing_flags() {
	echo "== compat: help and non-TCP mode rejection =="
	"$HPING" --help >"$LOGDIR/help.log" 2>&1
	assert_contains "$LOGDIR/help.log" 'tcp-option' \
		"help documents --tcp-option"
	assert_contains "$LOGDIR/help.log" 'tsecr-check' \
		"help documents --tsecr-check"
	if "$HPING" --icmp --tcp-option 030307 127.0.0.1 --count 1 \
			>"$LOGDIR/mode.log" 2>&1; then
		bad "TCP option rejected in non-TCP mode"
	else
		ok "TCP option rejected in ICMP mode"
	fi
	assert_contains "$LOGDIR/mode.log" 'only works in TCP mode' \
		"mode conflict error is descriptive"
	# legacy --tcp-timestamp still works on its own (parse + build path)
	if "$HPING" --tcp-timestamp --help >"$LOGDIR/ts.log" 2>&1; then
		ok "legacy --tcp-timestamp still parses"
	else
		bad "legacy --tcp-timestamp still parses"
	fi
}

# Whole integration scenario runs in one outer userns invocation and is
# passed the test function name to execute.
ns_wrapper() {
	unshare -Urn bash -c '
		set -e
		cd "'"$ROOT"'"
		ROOT="'"$ROOT"'" HPING="'"$HPING"'" FWBOX="'"$FWBOX"'" \
		LOGDIR="'"$LOGDIR"'" HP_IP="'"$HP_IP"'" FW_IP="'"$FW_IP"'" \
		VIP_IP="'"$VIP_IP"'" PASS='"$PASS"' FAIL='"$FAIL"' \
		bash "'"$ROOT"'/tests/scenario.sh" '"$1"'
	'
}

test_wire_format() {
	echo "== wire: custom option + timestamp layout =="
	ns_wrapper wire
	assert_contains "$LOGDIR/wire.log" 'kind=3 len=3 value=07' \
		"window scale option present on the wire"
	assert_contains "$LOGDIR/wire.log" 'kind=8 len=10' \
		"timestamp option present alongside custom option"
	assert_contains "$LOGDIR/wire.log" 'optlen=16' \
		"option block NOP/EOL padded to 16 bytes"
}

test_fw1_passthrough() {
	echo "== firewall 1: RFC1323 compliant host (echo preserved) =="
	ns_wrapper passthrough
	assert_contains "$LOGDIR/probe-passthrough.log" \
		'TCP timestamp echo: tsecr=[0-9]+ OK' \
		"compliant firewall echoes our TSval (OK)"
	assert_absent "$LOGDIR/probe-passthrough.log" 'MISMATCH|STRIPPED' \
		"no false alarm against a compliant firewall"
}

test_fw2_rewrite() {
	echo "== firewall 2: timestamp normalizer (TSecr rewritten) =="
	ns_wrapper rewrite
	assert_contains "$LOGDIR/probe-rewrite.log" \
		'TCP timestamp echo: tsecr=3735928559 MISMATCH' \
		"rewriting firewall detected via bogus TSecr (MISMATCH)"
	assert_absent "$LOGDIR/probe-rewrite.log" ' OK ' \
		"rewritten echo is never accepted as valid"
}

test_fw3_strip() {
	echo "== firewall 3: option-stripping firewall =="
	ns_wrapper strip
	assert_contains "$LOGDIR/probe-strip.log" \
		'TCP timestamp echo: option STRIPPED' \
		"option-stripping firewall detected (STRIPPED)"
	assert_absent "$LOGDIR/probe-strip.log" ' OK ' \
		"stripped reply is never accepted as valid"
}

mkdir -p "$LOGDIR"
[ -x "$HPING" ] || { echo "build hping3 first (make)"; exit 2; }

build_unit_test
test_unit
test_compat_existing_flags
test_wire_format
test_fw1_passthrough
test_fw2_rewrite
test_fw3_strip

echo
echo "================ summary ================"
echo "passed: $PASS, failed: $FAIL"
[ "$FAIL" -eq 0 ]
