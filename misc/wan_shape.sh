#!/bin/sh
# Bandwidth-limit loopback for the emulated WAN measurements.
# The paper adds no latency and reports no packet drop, so this shapes
# rate only. Run as root.
#
#   sudo misc/wan_shape.sh 100mbit    # WAN 100 Mbps
#   sudo misc/wan_shape.sh 10mbit     # WAN 10 Mbps
#   sudo misc/wan_shape.sh off        # back to LAN
set -e
DEV=lo
tc qdisc del dev $DEV root 2>/dev/null || true
[ "$1" = "off" ] && { echo "shaping removed"; tc qdisc show dev $DEV; exit 0; }
[ -z "$1" ] && { echo "usage: $0 <rate|off>"; exit 1; }
# large burst/limit so the token bucket does not drop packets at these rates
tc qdisc add dev $DEV root tbf rate "$1" burst 256kb limit 32mb
tc qdisc show dev $DEV
