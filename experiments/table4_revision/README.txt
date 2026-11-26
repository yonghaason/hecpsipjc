Main report: table4_revision_ko.tex (UTF-8 Korean; compile with XeLaTeX + kotex).
Drop-in English table: table4_corrected.tex (booktabs).
Results: measurements.csv, summary.csv, summary.json. All 22 protocol runs passed.
Regression: raw/regression_suite.log, all 58 existing tests passed.
Reproduce: run.py from this directory inside the patched repository.
Apply source.patch at git base recorded in parameters.json, then install dependencies and build.
WAN: NOT measured. run_wan.sh needs root; no prior WAN speedups retained.
No TeX engine was available here; TeX sources were generated and syntax-checked, not compiled to PDF.
Security scope: SEAL tc128 parameter check passes; circuit privacy is a separate unresolved assumption.
