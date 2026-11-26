# Better Private Join and Compute

Artifact for the ASIA CCS 2027 submission *Better Private Join and Compute*.

It contains our PJC protocol, the prior circuit-PSI-based PJC we compare
against, and the harnesses that produce every number in the paper. The code is
a fork of [VOLE-PSI](https://github.com/Visa-Research/volepsi); the two PJC
protocols share its OPRF, OKVS, GMW and circuit-PSI layers.

## What is here

| Path | What it is |
| --- | --- |
| `volePSI/RsCpsi.{h,cpp}` | Circuit-PSI. Our AF-CPSI lives here as `ValueShareType::prime`: payload shares over `Z_p`, the redundant encoding of Sec. 5, and the RNS (multi-residue) mode of Sec. 6.4. |
| `volePSI/PSI_Innerproduct.{h,cpp}` | Our PJC (Sec. 6): B2A-OT to arithmetic shares, then one plaintext-ciphertext BGV multiplication. `psiIpHe*Rns` are the RNS variants with CRT reconstruction. |
| `volePSI/Cpso.{h,cpp}` | The prior protocol's PJC (`PsoSender/PsoReceiver::*InnerProd`), used as the baseline. `*InnerProdWide` is the corrected exact-integer baseline for 32-bit inputs (see the Table 4 revision below). |
| `tests/RsPsiInnerproduct_*.cpp` | Correctness tests and the measurement harness for our PJC. |
| `tests/Pso_Tests.cpp` | Measurement harness for the baseline. |
| `misc/wan_shape.sh` | Loopback bandwidth shaping for the WAN rows. |

## Build

Needs a C++20 compiler, CMake >= 3.18, and network access on the first build
(dependencies are fetched automatically). Everything lands under `out/`.

```
python3 build.py -DVOLE_PSI_ENABLE_BOOST=ON -DVOLE_PSI_ENABLE_SEAL=ON
```

`VOLE_PSI_ENABLE_SEAL=ON` is required: the homomorphic step uses Microsoft
SEAL. `VOLE_PSI_ENABLE_BOOST=ON` is required for the TCP transport used by the
WAN measurements. The first build takes roughly 20 minutes; later ones are
incremental. The binary is `out/build/linux/frontend/frontend`.

## Check that it works

```
out/build/linux/frontend/frontend -u
```

58 tests, all should pass. The ones that matter here:

- `Cpsi_Rs_full_prime_test` — AF-CPSI produces additive shares over `Z_p`.
- `RsPsiInnerproduct_seal_test` — our PJC returns the correct inner product.
- `RsPsiInnerproduct_seal_rns_test` — the RNS path returns the correct *integer*
  inner product for full 32-bit payloads, including 0 and 2^32-1.

## Reproduce the paper

Numbers are printed as a CSV line per protocol stage plus a `total` row;
communication is in bytes, so divide by 1e6 for the MB in the paper. `-tcp`
runs the parties over loopback TCP, which is what the reported numbers use.

**Table 2 and its breakdown (modular inner product, Sec. 7.2).** Ours:

```
out/build/linux/frontend/frontend -u 49 -n 65536   -tcp
out/build/linux/frontend/frontend -u 49 -n 1048576 -tcp
```

Baseline:

```
out/build/linux/frontend/frontend -u 52 -nn 16
out/build/linux/frontend/frontend -u 52 -nn 20
```

**Table 4 revision (integer inner product, Sec. 7.3).** The integer baseline
now computes and checks the exact integer result in Z/(2^84), using 32 choice
bits and 84-bit arithmetic messages. Ours uses two 43-bit CRT primes with
N=8192 and the SEAL tc128 check enabled. These changes replace the original
XOR cost harness and its performance factors. See
[the Korean TeX report](experiments/table4_revision/table4_revision_ko.tex) and
[raw measurements](experiments/table4_revision/measurements.csv).
Use test names to avoid depending on numeric test indices:

```
out/build/linux/frontend/frontend -u RsPsiInnerproduct_perf_test -n 65536   -rns -tcp
out/build/linux/frontend/frontend -u RsPsiInnerproduct_perf_test -n 1048576 -rns -tcp
out/build/linux/frontend/frontend -u KLS26_innerprod_84_test -nn 16
out/build/linux/frontend/frontend -u KLS26_innerprod_84_test -nn 20
```

**WAN rows.** Shape loopback first (needs root), then re-run any command above:

```
sudo misc/wan_shape.sh 100mbit
sudo misc/wan_shape.sh 10mbit
sudo misc/wan_shape.sh off
```

The script limits rate only and adds no latency, matching Sec. 7.1. Confirm no
packets were dropped afterwards with `tc -s qdisc show dev lo`.

At `n = 2^20` over 10 Mbps the baseline moves about 1.5 GB and takes roughly
20 minutes; everything else finishes in under 5.

## Notes

Communication is deterministic: the byte counts reproduce exactly. Runtimes
depend on the machine; ours were taken on a 32-core AMD Ryzen Threadripper
9970X with 64 GB of RAM, single-threaded.

The baseline's setup phase moves slightly more data here than in its own
repository (221 KB against 191 KB at `n = 2^16`) because this tree uses our
OT generator for both protocols. The online phase, which is what the paper
compares, is unaffected.

## Corrected integer experiment artifacts

Run `python3 experiments/table4_revision/run.py` for boundary checks and three
serial LAN runs per configuration. The report and CSV use total cost including
setup; baseline online cost is listed separately. At n=2^20 the measured totals
are 340.694 MB / 13.342 s for Ours and 708.059 MB / 36.904 s for the corrected
baseline (time medians). Both pass identical-set, all-maximum 32-bit payloads.
WAN was not remeasured because root access for tc was unavailable; old WAN
figures must not be treated as corrected results. `run_wan.sh` supplies the
commands for an environment with root access. SEAL tc128 parameter validation
does not establish the separate circuit-privacy assumption.
