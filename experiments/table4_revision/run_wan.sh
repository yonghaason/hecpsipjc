#!/usr/bin/env bash
# Run only with permission to alter loopback qdisc. Does not supply any pre-existing result.
set -euo pipefail
cd "$(dirname "$0")/../.."
if [ "$(id -u)" -ne 0 ]; then
  echo 'Run this script as root; tc requires CAP_NET_ADMIN.' >&2
  exit 1
fi
if ! tc qdisc show dev lo | rg -q '^qdisc noqueue '; then
  echo 'Refusing to replace an existing custom loopback qdisc.' >&2
  exit 1
fi
mkdir -p experiments/table4_revision/wan_raw
trap 'bash misc/wan_shape.sh off' EXIT
for rate in 100mbit 10mbit; do
  bash misc/wan_shape.sh "$rate"
  for n in 65536 1048576; do
    for trial in 1 2 3; do
      out/build/linux/frontend/frontend -u RsPsiInnerproduct_perf_test -n "$n" -rns -tcp -nt 1 > "experiments/table4_revision/wan_raw/${rate}_ours_${n}_${trial}.log" 2>&1
      out/build/linux/frontend/frontend -u KLS26_innerprod_84_test -n "$n" -nt 1 > "experiments/table4_revision/wan_raw/${rate}_kls26_${n}_${trial}.log" 2>&1
      tc -s qdisc show dev lo > "experiments/table4_revision/wan_raw/${rate}_${n}_${trial}_qdisc.txt"
    done
  done
done
