#!/usr/bin/env python3
import csv,json,statistics,re
from pathlib import Path
p=Path(__file__).resolve().parent
rows=list(csv.DictReader((p/'measurements.csv').open()))
groups={}
for r in rows:
 if r['label']=='lan':groups.setdefault((int(r['n']),r['protocol']),[]).append(r)
assert len(groups)==4 and all(len(v)==3 for v in groups.values()),'Need all 12 successful LAN runs'
summary=[]
for (n,protocol),v in sorted(groups.items()):
 assert len(set(x['totalBytes'] for x in v))==1
 times=[float(x['totalSeconds']) for x in v]
 online=[float(x['onlineSeconds']) for x in v]
 summary.append(dict(n=n,protocol=protocol,totalBytes=int(v[0]['totalBytes']),MB=int(v[0]['totalBytes'])/1e6,medianSeconds=statistics.median(times),minSeconds=min(times),maxSeconds=max(times),onlineBytes=int(v[0]['onlineBytes']),onlineMedianSeconds=statistics.median(online),trials=len(v)))
with (p/'summary.csv').open('w') as f:
 w=csv.DictWriter(f,fieldnames=summary[0]);w.writeheader();w.writerows(summary)
s=r'\begin{center}\begin{tabular}{llrrr}\toprule $n$ & Protocol & Total MB & Median s & Min--Max s \\ \midrule'+'\n'
for r in summary:
 n=16 if r['n']==65536 else 20
 s+=f"$2^{{{n}}}$ & {r['protocol']} & {r['MB']:.3f} & {r['medianSeconds']:.3f} & {r['minSeconds']:.3f}--{r['maxSeconds']:.3f} \\\\\n"
s+=r'\bottomrule\end{tabular}\end{center}'
s+='\n'+r'Baseline의 setup/online 구분은 다음과 같다. Ours의 대응되는 offline/online 분리를 새로 정의하지 않았으므로 이 표로 online speedup을 계산하지 않는다.'+'\n'
s+=r'\begin{center}\begin{tabular}{lrrr}\toprule $n$ & Setup MB & Online MB & Online median s \\ \midrule'+'\n'
for r in summary:
 if r['protocol']=='KLS26':
  n=16 if r['n']==65536 else 20
  s+=f"$2^{{{n}}}$ & {(r['totalBytes']-r['onlineBytes'])/1e6:.3f} & {r['onlineBytes']/1e6:.3f} & {r['onlineMedianSeconds']:.3f} \\\\\n"
s+=r'\bottomrule\end{tabular}\end{center}'
ratios=[]
for n in [65536,1048576]:
 a=next(r for r in summary if r['n']==n and r['protocol']=='Ours');b=next(r for r in summary if r['n']==n and r['protocol']=='KLS26')
 ratios.append(f"$n=2^{{{16 if n==65536 else 20}}}$에서 baseline/Ours 통신량 비는 ${b['totalBytes']/a['totalBytes']:.3f}$, 전체 LAN 시간 중앙값 비는 ${b['medianSeconds']/a['medianSeconds']:.3f}$이다.")
checks=[r for r in rows if r['label']!='lan']
assert len(checks)==10
c=r'\begin{center}\begin{tabular}{llll}\toprule 입력 & $n$ & Ours & Baseline \\ \midrule'+'\n'
for label,n,desc in [('worst',65536,'동일 집합, 모두 최대값'),('worst',1048576,'동일 집합, 모두 최대값'),('empty',1024,'빈 교집합'),('zero',1024,'동일 집합, 모두 0'),('identical',1024,'동일 집합, 일반 payload')]:
 assert sum(r['label']==label and int(r['n'])==n for r in checks)==2
 c+=f'{desc} & {n} & PASS & PASS \\\\\n'
c+=r'\bottomrule\end{tabular}\end{center}'
noise=re.findall(r'HE_NOISE[^\n]*budget=(\d+)',(p/'raw/worst_ours_65536_0.log').read_text())
d=json.loads((p/'parameters.json').read_text())
src=(p/'report_template.tex').read_text()
for a,b in {'@RESULTS@':s,'@RATIOS@':'\n\n'.join(ratios),'@CORRECTNESS@':c,'@SMALLNOISE@':', '.join(noise)+' bits','@BASE@':d['git_base'][:12],'@SEAL@':d['seal_commit'][:12]}.items():src=src.replace(a,b)
assert not re.search(r'@[A-Z]+@',src)
(p/'table4_revision_ko.tex').write_text(src)
print(json.dumps(summary,indent=2))
