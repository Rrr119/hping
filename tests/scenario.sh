#!/usr/bin/env bash
#
# Executed *inside* the outer user+network namespace by run_tests.sh.
# Builds the two-namespace veth topology, starts the requested middlebox
# scenario and leaves transcripts under $LOGDIR.

set -u

SCENARIO=$1

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

	fw_mac=$(nsenter -t "$CHILD" -n ip -br link show veth-fw \
		| awk '{print $3}')
	ip neigh replace "$VIP_IP" lladdr "$fw_mac" dev veth-hp nud permanent
}

topology_destroy() {
	kill "$CHILD" 2>/dev/null || true
}

trap topology_destroy EXIT
topology_create

case "$SCENARIO" in
wire)
	# Capture hping's outgoing frame on the child side of the veth.
	nsenter -t "$CHILD" -n env PYTHONPATH="$FWBOX" \
		python3 -m fwbox.sniff veth-fw --count 1 --seconds 10 \
		>"$LOGDIR/wire.log" 2>&1 &
	SNIFF=$!
	sleep 1
	"$HPING" --interface veth-hp --numeric --count 1 --syn \
		--destport 80 --keep --tcp-option 030307 --tcp-timestamp \
		"$VIP_IP" >"$LOGDIR/hping-wire.log" 2>&1 || true
	wait "$SNIFF" || true
	;;
passthrough|rewrite|strip)
	nsenter -t "$CHILD" -n env PYTHONPATH="$FWBOX" \
		python3 -m fwbox.firewall veth-fw "$SCENARIO" --count 1 \
		--src-ip "$VIP_IP" >"$LOGDIR/fw-$SCENARIO.log" 2>&1 &
	FW=$!
	sleep 1
	"$HPING" --interface veth-hp --numeric --count 1 --syn \
		--destport 80 --keep --tsecr-check "$VIP_IP" \
		>"$LOGDIR/probe-$SCENARIO.log" 2>&1 || true
	wait "$FW" || true
	;;
*)
	echo "unknown scenario: $SCENARIO" >&2
	exit 2
	;;
esac
