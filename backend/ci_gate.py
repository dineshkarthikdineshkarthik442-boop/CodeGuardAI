from __future__ import annotations
import io, os, zipfile
from pathlib import Path
from fastapi import HTTPException
IGNORED_DIRS={'.git','.github','.idea','.gradle','node_modules','venv','.venv','__pycache__','build','dist','target','.next','.dart_tool'}
SOURCE_EXTENSIONS={'.py','.js','.jsx','.ts','.tsx','.java','.kt','.kts','.go','.php','.rb','.rs','.c','.cpp','.h','.hpp'}
PENALTY={'CRITICAL':30,'HIGH':15,'MEDIUM':8,'LOW':2}
def _safe(n):
 p=Path(n); return not p.is_absolute() and '..' not in p.parts
def scan_uploaded_archive(data:bytes, filename:str, retain_sources=False, policy=None):
 try: zf=zipfile.ZipFile(io.BytesIO(data))
 except zipfile.BadZipFile as e: raise HTTPException(400,'Uploaded file is not a valid ZIP archive.') from e
 try: from security_scanner import scan_python_source
 except Exception: scan_python_source=None
 findings=[]; files=lines=0; syntax_errors=[]; sources={}
 if len(zf.infolist())>10000 or sum(i.file_size for i in zf.infolist())>100*1024*1024:
  raise HTTPException(413,'Expanded archive exceeds safety limits (100 MB / 10000 entries).')
 for info in zf.infolist():
  if info.is_dir() or not _safe(info.filename): continue
  p=Path(info.filename)
  if any(x in IGNORED_DIRS for x in p.parts) or p.suffix.lower() not in SOURCE_EXTENSIONS: continue
  if info.file_size>750000 or files>=500: continue
  try: text=zf.read(info).decode('utf-8','replace')
  except Exception: continue
  files+=1; lines+=len(text.splitlines())
  if retain_sources and p.suffix.lower()=='.py' and len(text.encode('utf-8'))<=60000:
   if info.filename in sources: raise HTTPException(400,'Duplicate source file path in ZIP.')
   sources[info.filename]=text
  if p.suffix.lower()=='.py' and scan_python_source:
   try:
    analysis=scan_python_source(text)
    if analysis.get('syntax_error'): syntax_errors.append({'file':info.filename,'message':analysis['syntax_error']})
    for f in analysis.get('issues',[]):
     x=dict(f); x['file']=info.filename; x['source']='FAST'; findings.append(x)
    continue
   except Exception: pass
  for n,line in enumerate(text.splitlines(),1):
   low=line.lower()
   if any(t in low for t in ('api_key=','apikey=','secret_key=','password=','access_token=','private_key=')):
    findings.append({'rule_id':'CG-SECRET-GENERIC','severity':'HIGH','category':'Hardcoded Secret','line':n,'file':info.filename,'message':'Possible hardcoded secret detected.','recommendation':'Move secrets to environment variables or a secret manager.','source':'FAST'})
   if 'eval(' in low or 'exec(' in low:
    findings.append({'rule_id':'CG-CODE-GENERIC','severity':'CRITICAL','category':'Code Injection','line':n,'file':info.filename,'message':'Dynamic code execution pattern detected.','recommendation':'Avoid evaluating untrusted input as executable code.','source':'FAST'})
 unique={(f.get('file'),f.get('line'),f.get('rule_id'),f.get('message')):f for f in findings}; findings=list(unique.values())
 counts={s:sum(f.get('severity')==s for f in findings) for s in PENALTY}; score=max(0,100-sum(counts[s]*PENALTY[s] for s in counts))
 policy=policy or {}
 threshold=int(policy.get('threshold',os.getenv('CODEGUARD_GATE_THRESHOLD','80'))); max_high=int(policy.get('max_high',os.getenv('CODEGUARD_GATE_MAX_HIGH','0'))); max_critical=int(policy.get('max_critical',os.getenv('CODEGUARD_GATE_MAX_CRITICAL','0')))
 if not 0<=threshold<=100 or min(max_high,max_critical)<0: raise HTTPException(400,'Invalid gate policy.')
 if files==0: raise HTTPException(400,'No supported source files found in the archive.')
 passed=not syntax_errors and score>=threshold and counts['HIGH']<=max_high and counts['CRITICAL']<=max_critical
 return {**({'_sources':sources} if retain_sources else {}),'success':True,'version':'V11.1','syntax_errors':syntax_errors,'limits':{'max_files':500,'max_file_bytes':750000},'coverage':'Python AST rules; other supported languages receive basic pattern checks','filename':filename,'files_scanned':files,'lines_scanned':lines,'security_score':score,'threshold':threshold,'max_high_allowed':max_high,'max_critical_allowed':max_critical,'passed':passed,'status':'PASS' if passed else 'FAIL','severity_counts':counts,'findings':findings,'message':'Security gate passed. Build may continue.' if passed else 'Security gate failed. Review the findings before continuing the build.'}
