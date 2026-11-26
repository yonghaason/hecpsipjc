# Table 2: network-only remeasurement

Each configuration was measured once. Protocol source and the original binary are unchanged. Ours uses 16-bit payloads and a 32-bit plaintext modulus.

| n | Protocol | Total MB | LAN seconds | WAN100 seconds | WAN10 seconds |
|---|---|---:|---:|---:|---:|
| 2^16 | KLS26 | 21.374 | 1.735 | 6.738 | 21.461 |
| 2^16 | Ours | 14.150 | 0.750 | 4.567 | 14.118 |
| 2^20 | KLS26 | 330.100 | 28.112 | 60.468 | 302.270 |
| 2^20 | Ours | 218.010 | 12.426 | 32.710 | 188.588 |

Rates limit aggregate loopback egress. MB = 10^6 bytes; totals include setup. Baseline online costs are in measurements.csv.
External CHT+23 values are unchanged in table2.tex and are not remeasured.
KLS26 communication is the current unchanged implementation's measured byte count; its difference from the old paper table is not attributed to RTT.

Observed ping average RTT:
- LAN: 0.240 ms
- WAN100: 80.094 ms
- WAN10: 80.246 ms

All 12 measurements completed; qdisc drops were zero. Original noqueue restored.
Binary SHA256: aa2078a01f2ff7b2b7c6e4acad845be47b3c474204dd78fa848702e1950d44b6
