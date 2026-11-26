# Experimental-results LaTeX revision

`original_supplied.tex` is a byte-for-byte copy of the attachment.
`experimental_results_tracked.tex` is the requested version: old prose and
changed cell values remain visible with strikeout, and new text is red.
Each changed numeric cell stacks old above new to keep tables narrow.
Original citation keys and section/table labels are retained. CHI+23 rows
are unchanged. The original paper source and experiment code are untouched.

Add the two packages in `revision_packages.tex` to the existing preamble
(avoid duplicate package options), then paste/input the tracked section.
The tracked file defines its three revision macros before the section.
The existing paper already needs booktabs, multirow, cleveref and math
packages, plus its citation and Z macros. A clean companion without revision
markup is provided as `experimental_results_clean.tex`.

Data comes from the latest table2_network_only, table3_network_only and
table4_network_only experiment directories dated 2026-11-19. Ratios use raw,
unrounded CSV values. New table values use three decimal places.

Scientific corrections include payload16 versus modulus32 in the modular
setting, the preserved KLS26 input/domain difference, actual 84-bit integer
arithmetic, 43-bit CRT primes/N8192/q110, and the independently measured
Table 3 total. Unsupported equal-payload, exact doubling, quadratic-growth
and runtime-convergence explanations were replaced with observed ratios.
