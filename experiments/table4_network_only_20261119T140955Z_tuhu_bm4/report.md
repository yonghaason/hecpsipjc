# Table 4: exact integer inner product remeasurement

Unchanged corrected implementation; 32-bit unsigned payloads. Each configuration measured once, without separate boundary sweeps. Total includes setup; MB = 10^6 bytes.

| n | Protocol | Total MB | LAN seconds | WAN100 seconds | WAN10 seconds |
|---|---|---:|---:|---:|---:|
| 2^16 | [8] KLS26 | 44.711 | 2.498 | 9.760 | 41.078 |
| 2^16 | Ours | 22.090 | 1.156 | 5.671 | 20.665 |
| 2^20 | [8] KLS26 | 708.059 | 40.039 | 103.678 | 618.093 |
| 2^20 | Ours | 340.694 | 15.869 | 43.972 | 291.313 |

KLS26 denotes our adaptation of [8] to exact integer inner products, using 32-bit OT choices and 84-bit arithmetic; each run computes and verifies the integer result. Ours uses two 43-bit CRT primes. Both arithmetic spaces cover the full result range for n<=2^20. These are single-run totals including setup, with decimal MB.

Ours parameters: p0=8796092858369, p1=8796092792833; N=8192; coefficient-modulus bits {60,50,30}; SEAL tc128 enabled.
The common caption (L=84) was omitted because KLS26 uses an 84-bit ring, while the Ours CRT product has 86 bits. Both recover the exact same bounded integer.

Observed average RTT:
- LAN: 0.250 ms
- WAN100: 80.064 ms
- WAN10: 80.216 ms

Rates limit aggregate loopback egress. All 12 runs completed; packet drops zero. Original noqueue restored.
Binary SHA256: aa2078a01f2ff7b2b7c6e4acad845be47b3c474204dd78fa848702e1950d44b6

Ratios KLS26 / Ours:
- n=65536: communication 2.024001; runtime ratios LAN/WAN100/WAN10 = 2.160999/1.720897/1.987782
- n=1048576: communication 2.078284; runtime ratios LAN/WAN100/WAN10 = 2.523135/2.357798/2.121750
