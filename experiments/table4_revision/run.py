#!/usr/bin/env python3
"""Serial measured LAN runs, exact-integer checks, with all raw output retained."""
import csv,json,platform,re,subprocess,time
from pathlib import Path
root=Path(__file__).resolve().parents[2]
out=Path(__file__).resolve().parent
raw=out/'raw';raw.mkdir(exist_ok=True)
bin=root/'out/build/linux/frontend/frontend'
rows=[]

def run(protocol,n,label,extra=(),trial=0):
 test='RsPsiInnerproduct_perf_test' if protocol=='Ours' else 'KLS26_innerprod_84_test'
 cmd=[str(bin),'-u',test,'-n',str(n),'-nt','1']
 if protocol=='Ours':cmd+=['-rns','-tcp']
 cmd+=list(extra)
 name=f'{label}_{protocol.lower()}_{n}_{trial}'
 print('RUN',name,flush=True)
 start=time.time()
 p=subprocess.run(cmd,cwd=root,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=600)
 log=re.sub(r'\x1b\[[0-9;]*m','',p.stdout)
 (raw/(name+'.log')).write_text(log)
 (raw/(name+'.command.json')).write_text(json.dumps(cmd,indent=2))
 if p.returncode or 'All Passed (1)' not in log:raise RuntimeError(f'{name} failed: {log[-1500:]}')
 if protocol=='Ours':
  m=re.search(r'^total,(\d+),(\d+),(\d+),[^,]+,([0-9.]+)',log,re.M)
  b=int(m[3]);t=float(m[4]);online_b=b;online_t=t
 else:
  m=re.search(r'VOLEPSI_INNERPRODUCT84_PERF .*',log)
  d=dict(re.findall(r'(\w+)=([\d.]+)',m[0]))
  b=int(d['totalBytes']);t=float(d['totalSeconds']);online_b=int(d['onlineBytes']);online_t=float(d['onlineSeconds'])
 rows.append(dict(label=label,protocol=protocol,n=n,trial=trial,totalBytes=b,totalSeconds=t,onlineBytes=online_b,onlineSeconds=online_t,elapsedSeconds=time.time()-start,log=str((raw/(name+'.log')).relative_to(out))))
 with (out/'measurements.csv').open('w') as f:
  w=csv.DictWriter(f,fieldnames=rows[0]);w.writeheader();w.writerows(rows)
 print('PASS',name,'bytes',b,'seconds',t,flush=True)

# Boundary and edge correctness at protocol level, not just the HE postprocessing.
for n in (65536,1048576):
 for protocol in ('Ours','KLS26'):
  run(protocol,n,'worst',['-identical','-maxPayload','-rnsdebug'] if protocol=='Ours' else ['-identical','-maxPayload'])
for extra,label in ((['-intersection','0'],'empty'),(['-identical','-zeroPayload'],'zero'),(['-identical'],'identical')):
 for protocol in ('Ours','KLS26'):run(protocol,1024,label,extra)
# Repeat the original half-overlap setting; same payload bounds, deterministic formulas.
for trial in range(1,4):
 for n in (65536,1048576):
  for protocol in ('Ours','KLS26'):run(protocol,n,'lan',trial=trial)
print('DONE',flush=True)
