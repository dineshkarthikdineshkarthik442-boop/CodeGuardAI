import argparse
import json
import sys
from pathlib import Path
from ci_gate import scan_uploaded_archive

def main():
 p=argparse.ArgumentParser(description='CodeGuard AI V12 CI/CD Security Gate')
 p.add_argument('archive');p.add_argument('--threshold',type=int,default=80);p.add_argument('--max-high',type=int,default=0);p.add_argument('--max-critical',type=int,default=0);p.add_argument('--json',action='store_true');a=p.parse_args()
 try:
  path=Path(a.archive)
  if path.stat().st_size>50*1024*1024: raise ValueError('ZIP exceeds 50 MB.')
  r=scan_uploaded_archive(path.read_bytes(),path.name,policy={'threshold':a.threshold,'max_high':a.max_high,'max_critical':a.max_critical})
 except Exception as exc:
  print('Gate error: '+str(getattr(exc,'detail',exc)),file=sys.stderr);return 2
 print(json.dumps(r,indent=2) if a.json else f"CodeGuard V12: {r['status']} · score {r['security_score']}/100")
 return 0 if r['passed'] else 1
if __name__=='__main__':sys.exit(main())
