#!/usr/bin/env bash
# Table 2: modular inner product, n=2^20, one thread, three serial trials.
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."

for tool in tc ping python3 git sha256sum; do
    command -v "$tool" >/dev/null || { echo "Missing tool: $tool" >&2; exit 1; }
done
binary=out/build/linux/frontend/frontend
[[ -x "$binary" ]] || { echo "Missing binary: $binary" >&2; exit 1; }

result_dir=$(mktemp -d "$PWD/experiments/table2_run_$(date -u +%Y%m%dT%H%M%SZ)_XXXXXX")
tc qdisc show dev lo > "$result_dir/initial_qdisc.txt"
tc -j qdisc show dev lo > "$result_dir/initial_qdisc.json"
# Restore supported existing netem settings instead of discarding them.
# Complex trees and unhandled options are left unchanged.
python3 - "$result_dir" <<'PY'
import json, sys
from decimal import Decimal
from pathlib import Path
dest = Path(sys.argv[1])
tree = json.loads((dest / 'initial_qdisc.json').read_text(), parse_float=Decimal)
def reject():
    raise SystemExit('Existing loopback qdisc is not a supported simple netem/noqueue; leaving it unchanged.')
if len(tree) != 1 or not tree[0].get('root'):
    reject()
q = tree[0]
if q['kind'] == 'noqueue':
    args = ['qdisc', 'del', 'dev', 'lo', 'root']
elif q['kind'] == 'netem':
    o = q.get('options', {})
    if set(o) - {'limit', 'delay', 'rate', 'ecn', 'gap'} or o.get('ecn') or o.get('gap'):
        reject()
    args = ['qdisc', 'replace', 'dev', 'lo', 'root', 'handle', q['handle'], 'netem', 'limit', str(o['limit'])]
    d = o.get('delay')
    if d:
        if set(d) - {'delay', 'jitter', 'correlation'} or d.get('jitter') or d.get('correlation'):
            reject()
        args += ['delay', f"{Decimal(str(d['delay'])) * 1000000:f}us"]
    r = o.get('rate')
    if r:
        if set(r) - {'rate', 'packetoverhead', 'cellsize', 'celloverhead'} or any(r.get(k) for k in ('packetoverhead', 'cellsize', 'celloverhead')):
            reject()
        args += ['rate', f"{r['rate'] * 8}bit"]
else:
    reject()
(dest / 'restore_tc_args.txt').write_text('\n'.join(args) + '\n')
PY
mapfile -t restore_args < "$result_dir/restore_tc_args.txt"
printf 'Results: %s\n' "$result_dir"
tc_prefix=()
shaped=0
cleanup() {
    if (( shaped )); then
        if ! "${tc_prefix[@]}" tc "${restore_args[@]}"; then
            echo "Cleanup failed. Original settings and restore arguments are in $result_dir" >&2
            return 1
        fi
        tc qdisc show dev lo > "$result_dir/restored_qdisc.txt"
        shaped=0
    fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# Try the operation directly: this also supports file capabilities on tc.
if tc qdisc replace dev lo root netem limit 100000 delay 0.1ms rate 10gbit \
    2> "$result_dir/direct_tc.log"; then
    shaped=1
else
    cat "$result_dir/direct_tc.log" >&2
    if ! command -v sudo >/dev/null; then
        echo 'tc needs CAP_NET_ADMIN; sudo is unavailable.' >&2
        exit 1
    fi
    echo 'Direct tc failed; trying sudo for network configuration only.' >&2
    sudo -v
    tc_prefix=(sudo)
    "${tc_prefix[@]}" tc qdisc replace dev lo root netem limit 100000 delay 0.1ms rate 10gbit
    shaped=1
fi

cat > "$result_dir/settings.txt" <<'SETTINGS'
Table 2 modular inner product. n=1048576; threads=1; trials=3.
LAN: 10 Gbps, target RTT 0.2 ms.
WAN100: 100 Mbps, target RTT 80 ms.
WAN10: 10 Mbps, target RTT 80 ms.
TCP loopback; netem delay is RTT/2 per traversal.
Rate limits aggregate loopback egress, not independent full-duplex directions.
[4] and paper files are unchanged. Ours runs without -rns.
SETTINGS
git rev-parse HEAD > "$result_dir/commit.txt"
git diff > "$result_dir/source.patch"
sha256sum "$binary" > "$result_dir/binary.sha256"

for setting in LAN WAN100 WAN10; do
    case "$setting" in
        LAN) rate=10gbit; delay=0.1ms ;;
        WAN100) rate=100mbit; delay=40ms ;;
        WAN10) rate=10mbit; delay=40ms ;;
    esac
    "${tc_prefix[@]}" tc qdisc replace dev lo root netem limit 100000 delay "$delay" rate "$rate"
    ping -n -c 5 127.0.0.1 | tee "$result_dir/${setting}_ping.log"
    for trial in 1 2 3; do
        for protocol in ref7 ours; do
            if [[ "$protocol" == ref7 ]]; then
                args=(-u KLS26_innerprod_32_test -n 1048576 -nt 1)
            else
                args=(-u RsPsiInnerproduct_perf_test -n 1048576 -nt 1 -tcp)
            fi
            stem="$result_dir/${setting}_${protocol}_${trial}"
            printf 'RUN %s %s trial %s\n' "$setting" "$protocol" "$trial"
            printf '%q ' "$binary" "${args[@]}" > "$stem.command"
            printf '\n' >> "$stem.command"
            if ! "$binary" "${args[@]}" > "$stem.log" 2>&1; then
                tail -n 30 "$stem.log" >&2
                exit 1
            fi
            tc -s qdisc show dev lo > "$stem.qdisc.log"
            python3 - "$stem.log" "$stem.qdisc.log" <<'PY'
import re, sys
from pathlib import Path
log = Path(sys.argv[1]).read_text()
if 'All Passed (1)' not in log:
    raise SystemExit(f'Test did not report success: {sys.argv[1]}')
if any(int(n) for n in re.findall(r'dropped (\d+)', Path(sys.argv[2]).read_text())):
    raise SystemExit('Packet drops detected. Reject this run; see qdisc log.')
PY
            printf 'PASS %s %s trial %s\n' "$setting" "$protocol" "$trial"
        done
    done
done
cleanup

python3 - "$result_dir" <<'PY'
import csv, re, statistics, sys
from pathlib import Path
dest = Path(sys.argv[1])
rows = []
for network in ('LAN', 'WAN100', 'WAN10'):
    for protocol in ('ref7', 'ours'):
        for trial in range(1, 4):
            log = (dest / f'{network}_{protocol}_{trial}.log').read_text()
            log = re.sub(r'\x1b\[[0-9;]*m', '', log)
            online_bytes = online_seconds = ''
            if protocol == 'ours':
                match = re.search(r'^total,(\d+),(\d+),(\d+),[^,]+,([0-9.]+)', log, re.M)
                byte_count, seconds = int(match[3]), float(match[4])
            else:
                match = re.search(r'VOLEPSI_INNERPRODUCT_PERF .*', log)
                data = dict(re.findall(r'(\w+)=([\d.]+)', match[0]))
                byte_count, seconds = int(data['totalBytes']), float(data['totalSeconds'])
                online_bytes, online_seconds = int(data['onlineBytes']), float(data['onlineSeconds'])
            rows.append(dict(network=network, protocol=protocol, trial=trial,
                             totalBytes=byte_count, totalSeconds=seconds,
                             onlineBytes=online_bytes, onlineSeconds=online_seconds))
with (dest / 'measurements.csv').open('w') as f:
    writer = csv.DictWriter(f, fieldnames=rows[0])
    writer.writeheader()
    writer.writerows(rows)
summary = ['network,protocol,medianTotalSeconds,medianTotalMB_decimal']
for network in ('LAN', 'WAN100', 'WAN10'):
    for protocol in ('ref7', 'ours'):
        subset = [r for r in rows if r['network'] == network and r['protocol'] == protocol]
        seconds = statistics.median(r['totalSeconds'] for r in subset)
        mb = statistics.median(r['totalBytes'] for r in subset) / 1e6
        summary.append(f'{network},{protocol},{seconds:.6f},{mb:.6f}')
text = '\n'.join(summary) + '\n'
(dest / 'summary.csv').write_text(text)
print(text)
print('Saved:', dest)
PY
