# Table 3 remeasurement

One run, n=2^20; unchanged binary; payload16 bits, plaintext modulus32 bits. LAN10Gbps, target RTT0.2ms. Decimal MB.

| Stage | Runtime (s) | Comm. (MB) |
|---|---:|---:|
| AF-CPSI | 10.884480 | 172.955698 |
| B2A-OT | 0.347262 | 22.769104 |
| HE Computation | 0.261041 | 22.285270 |
| Total | 11.517638 | 218.010072 |

Share addition: 0.019353s; total minus three main stages: 0.024855s.
Separate VOLE calibration is diagnostic and is not added to protocol totals.
