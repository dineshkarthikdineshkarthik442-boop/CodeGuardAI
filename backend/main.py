from ci_gate import scan_uploaded_archive
from cloud_store import init_db, register, login, user_from_token, save_scan, list_scans, get_scan, revoke_token
import os
import shutil
import tempfile
from pathlib import Path

from fastapi import FastAPI, File, UploadFile, HTTPException, Header, Form
from fastapi.middleware.cors import CORSMiddleware

from security_scanner import scan_python_source
from github_scanner import scan_repository, download_repository
from pr_reviewer import review_pull_request

try:
    from ai_reviewer import review_code_with_ai
except Exception:
    review_code_with_ai = None
try:
    from ai_fixer import generate_secure_fix
except Exception:
    generate_secure_fix = None
try:
    from ai_test_generator import generate_security_tests
except Exception:
    generate_security_tests = None

app = FastAPI(title="CodeGuard AI V14.2", version="14.2.0", docs_url="/docs" if os.getenv("CODEGUARD_ENABLE_DOCS","1")=="1" else None, redoc_url=None)
init_db()
from request_security import RequestSecurity
app.add_middleware(RequestSecurity)
app.add_middleware(CORSMiddleware, allow_origins=[x.strip() for x in os.getenv("CODEGUARD_ALLOWED_ORIGINS","http://localhost:5173,http://127.0.0.1:5173").split(",") if x.strip()], allow_credentials=True, allow_methods=["GET","POST","OPTIONS"], allow_headers=["Authorization","Content-Type"])


def analyze_source(source, name):
    result = scan_python_source(source)
    if not result.get("success"):
        return {"success": False, "error": result.get("syntax_error", "Syntax error")}
    return {"success": True, "file": name, "lines": len(source.splitlines()), "score": result.get("score", 100), "issues": result.get("issues", [])}


@app.get("/")
def root(): return {"name": "CodeGuard AI", "version": "V14.2", "status": "online"}

@app.get("/health")
def health(): return {"status": "ok", "version": "V14.2"}

@app.post("/api/analyze")
async def analyze(file: UploadFile = File(...)):
    if not file.filename or Path(file.filename).suffix.lower() != ".py": return {"success": False, "error": "Python files only."}
    try:
        source = (await file.read()).decode("utf-8", errors="replace")
        return analyze_source(source, Path(file.filename).name)
    except Exception as exc: return {"success": False, "error": str(exc)}

@app.post("/api/v4/github-scan")
def github_scan(payload: dict):
    try: return scan_repository((payload or {}).get("url", "").strip())
    except Exception as exc: return {"success": False, "error": str(exc)}

@app.post("/api/v7/pr-review")
def v7_pr_review(payload: dict):
    url = (payload or {}).get("url", "").strip()
    if not url: return {"success": False, "error": "GitHub Pull Request URL is required."}
    try: return review_pull_request(url)
    except Exception as exc: return {"success": False, "error": str(exc)}

@app.post("/api/v7/ai-explain")
def v7_ai_explain(payload: dict):
    if review_code_with_ai is None: return {"success": False, "error": "AI reviewer is unavailable."}
    payload = payload or {}; finding = payload.get("finding") or {}; code = payload.get("code", "")
    if not finding or not code: return {"success": False, "error": "Finding and code context are required."}
    try: return {"success": True, "ai_review": review_code_with_ai(code, [finding])}
    except Exception as exc: return {"success": False, "error": str(exc)}

@app.post("/api/v7/ai-summary")
def v7_ai_summary(payload: dict):
    if review_code_with_ai is None: return {"success": False, "error": "AI reviewer is unavailable."}
    payload = payload or {}; diff = payload.get("diff", ""); findings = payload.get("findings") or []
    if not diff: return {"success": False, "error": "Pull Request diff is required."}
    try:
        clipped = diff[:50000]
        return {"success": True, "ai_review": review_code_with_ai(clipped, findings)}
    except Exception as exc: return {"success": False, "error": str(exc)}

@app.post("/api/v5/ai-fix")
def v5_ai_fix(payload: dict):
    if generate_secure_fix is None: return {"success": False, "error": "AI fixer is unavailable."}
    payload = payload or {}; repo_url = (payload.get("repo_url") or "").strip(); finding = payload.get("finding") or {}
    if not repo_url or not finding: return {"success": False, "error": "Repository URL and finding are required."}
    relative_file = str(finding.get("file") or "").replace("\\", "/").lstrip("/")
    temp_dir = None
    try:
        temp_dir, repo_root, owner, repo = download_repository(repo_url)
        target = (repo_root / relative_file).resolve()
        if repo_root.resolve() not in target.parents or not target.is_file(): return {"success": False, "error": "Finding file was not found inside the repository."}
        source = target.read_text(encoding="utf-8", errors="replace")
        return {"success": True, "repository": {"owner": owner, "name": repo, "url": f"https://github.com/{owner}/{repo}"}, "file": relative_file, "finding": finding, "original_code": source, "fix": generate_secure_fix(source, finding)}
    except Exception as exc: return {"success": False, "error": str(exc)}
    finally:
        if temp_dir: shutil.rmtree(temp_dir, ignore_errors=True)

@app.post("/api/v6/generate-tests")
def v6_generate_tests(payload: dict):
    if generate_security_tests is None: return {"success": False, "error": "AI test generator is unavailable."}
    payload = payload or {}; finding = payload.get("finding") or {}; original = payload.get("original_code") or ""; fixed = payload.get("fixed_code") or ""
    if not finding or not original or not fixed: return {"success": False, "error": "Finding, original code, and fixed code are required."}
    try: return {"success": True, "finding": finding, "tests": generate_security_tests(original, fixed, finding)}
    except Exception as exc: return {"success": False, "error": str(exc)}




@app.post("/api/v8/security-gate")
async def v8_security_gate(file: UploadFile = File(...)):
    if not file.filename or not file.filename.lower().endswith(".zip"):
        raise HTTPException(status_code=400, detail="V8 security gate expects a .zip source archive.")
    data = await file.read()
    if len(data) > 50 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="Archive is larger than the 50 MB V8 limit.")
    return scan_uploaded_archive(data, file.filename)


@app.post("/api/v9/auth/register")
def v9_register(payload: dict):
    if os.getenv("CODEGUARD_ALLOW_SIGNUP","1")!="1": raise HTTPException(403,"New account registration is disabled.")
    payload=payload or {}; email=str(payload.get("email","")).strip(); password=str(payload.get("password","")); name=str(payload.get("name","Developer"))
    if "@" not in email: return {"success":False,"error":"Enter a valid email address."}
    result,error=register(email,password,name)
    from browser_auth import auth_response
    return auth_response(result,error)

@app.post("/api/v9/auth/login")
def v9_login(payload: dict):
    payload=payload or {}; result,error=login(str(payload.get("email","")),str(payload.get("password","")))
    from browser_auth import auth_response
    return auth_response(result,error)

@app.get("/api/v9/me")
async def v9_me(authorization: str = Header(default="")):
    user=user_from_token(authorization.replace("Bearer ","",1))
    if not user: raise HTTPException(status_code=401, detail="Authentication required.")
    return {"success":True,"user":user}

@app.get("/api/v9/scans")
async def v9_scans(authorization: str = Header(default="")):
    user=user_from_token(authorization.replace("Bearer ","",1))
    if not user: raise HTTPException(status_code=401, detail="Authentication required.")
    return {"success":True,"scans":list_scans(user["id"])}

@app.get("/api/v9/scans/{scan_id}")
async def v9_scan(scan_id:int, authorization: str = Header(default="")):
    user=user_from_token(authorization.replace("Bearer ","",1));
    if not user: raise HTTPException(status_code=401, detail="Authentication required.")
    scan=get_scan(user["id"],scan_id)
    if not scan: raise HTTPException(status_code=404, detail="Scan not found.")
    scan["result"].pop("_sources",None)
    return {"success":True,"scan":scan}

@app.post("/api/v9/scans")
async def v9_save_scan(payload: dict, authorization: str = Header(default="")):
    user=user_from_token(authorization.replace("Bearer ","",1))
    if not user: raise HTTPException(status_code=401, detail="Authentication required.")
    payload=payload or {}; result=payload.get("result") or {}
    sid=save_scan(user["id"],str(payload.get("scan_type","Repository")),str(payload.get("target","Local scan")),result)
    return {"success":True,"scan_id":sid}


@app.post("/api/v9/scan/github")
def v9_scan_github(payload: dict, authorization: str = Header(default="")):
    user=user_from_token(authorization.replace("Bearer ","",1))
    if not user: raise HTTPException(status_code=401, detail="Authentication required.")
    url=str((payload or {}).get("url", "")).strip()
    if not url: return {"success":False,"error":"GitHub repository URL is required."}
    try:
        result=scan_repository(url)
        if not result.get("success"): return result
        score=result.get("security_score", result.get("score", 0))
        status="PASS" if int(score or 0) >= 80 else "REVIEW"
        result["status"]=status
        result["scan_id"]=save_scan(user["id"], "GitHub Repository", url, result)
        return result
    except Exception as exc: return {"success":False,"error":str(exc)}

@app.post("/api/v9/scan/zip")
async def v9_scan_zip(file: UploadFile = File(...), authorization: str = Header(default="")):
    user=user_from_token(authorization.replace("Bearer ","",1))
    if not user: raise HTTPException(status_code=401, detail="Authentication required.")
    if not file.filename or not file.filename.lower().endswith(".zip"):
        raise HTTPException(status_code=400, detail="Please upload a .zip project archive.")
    data=await file.read()
    if len(data)>50*1024*1024: raise HTTPException(status_code=413, detail="Archive is larger than the 50 MB limit.")
    try:
        result=scan_uploaded_archive(data,file.filename,retain_sources=True)
        result["scan_id"]=save_scan(user["id"], "Project ZIP", file.filename, result)
        result.pop("_sources",None)
        return result
    except Exception as exc: return {"success":False,"error":str(exc)}


@app.get("/api/v11/scans/{scan_id}/source/{finding_index}")
def v11_source(scan_id:int, finding_index:int, authorization: str = Header(default="")):
    user=user_from_token(authorization.replace("Bearer ","",1))
    if not user: raise HTTPException(401,"Authentication required.")
    scan=get_scan(user["id"],scan_id)
    if not scan: raise HTTPException(404,"Saved scan not found.")
    findings=scan["result"].get("findings",[])
    if not 0<=finding_index<len(findings): raise HTTPException(400,"Invalid finding index.")
    filename=findings[finding_index].get("file")
    source=scan["result"].get("_sources",{}).get(filename)
    if source is None: return {"success":True,"available":False,"message":"Source unavailable. Rescan your ZIP in V11.1. Python files must be at most 60 KB. GitHub and older scans can use manual source."}
    return {"success":True,"available":True,"file":filename,"code":source}

@app.post("/api/v11/fix")
def v11_fix(payload: dict, authorization: str = Header(default="")):
    from fix_validation import validate_fix
    user=user_from_token(authorization.replace("Bearer ","",1))
    if not user: raise HTTPException(401, "Authentication required.")
    scan=get_scan(user["id"],int(payload.get("scan_id") or 0))
    if not scan: raise HTTPException(404,"Saved scan not found.")
    findings=scan["result"].get("findings",[])
    index=payload.get("finding_index")
    if not isinstance(index,int) or isinstance(index,bool) or not 0<=index<len(findings): raise HTTPException(400,"Invalid finding index.")
    finding=findings[index]
    filename=str(finding.get("file") or "source.py")
    if not filename.lower().endswith(".py"): raise HTTPException(400,"V11 fixes support Python files only.")
    source=scan["result"].get("_sources",{}).get(filename)
    if source is None: source=payload.get("code")
    if not isinstance(source,str) or not source.strip() or len(source.encode())>60000: raise HTTPException(400,"Paste a Python source file of up to 60 KB.")
    analysis=scan_python_source(source)
    if not analysis.get("success"): raise HTTPException(400,"Source has Python syntax errors.")
    if not any(f.get("rule_id")==finding.get("rule_id") and f.get("line")==finding.get("line") for f in analysis["issues"]): raise HTTPException(400,"Source does not match the selected finding and line. Paste the scanned file.")
    if payload.get("consent") is not True: raise HTTPException(400,"Confirm sending this source file and finding to Groq.")
    if generate_secure_fix is None: raise HTTPException(503,"AI fixer unavailable.")
    fix=generate_secure_fix(source,finding)
    if not fix.get("available"): return {"success":False,"error":fix.get("summary","AI unavailable.")}
    fixed=fix.get("fixed_code")
    if not isinstance(fixed,str) or len(fixed.encode())>200000: raise HTTPException(502,"AI returned invalid or oversized source.")
    return {"success":True,"file":filename,"original_code":source,"fix":fix,"validation":validate_fix(source,fixed,finding,filename)}

@app.post("/api/v12/pr-review")
def v12_pr(payload: dict, authorization: str = Header(default="")):
    user=user_from_token(authorization.replace("Bearer ","",1))
    if not user: raise HTTPException(401,"Authentication required.")
    url=str(payload.get("url") or "").strip()
    try:
        result=review_pull_request(url)
        if not result.get("success"): return result
        errors=[{"file":f["file"],"message":f["error"]} for f in result.get("files",[]) if f.get("error")]
        result["syntax_errors"]=errors
        result["coverage"]="Python files in the PR head only. Introduced means the finding falls on an added diff line; this is not a base-versus-head vulnerability comparison."
        result["status"]="REVIEW" if errors or result.get("introduced_findings") or not result.get("python_files_changed") else "PASS"
        result["scan_id"]=save_scan(user["id"],"Pull Request",url,result)
        return result
    except Exception as exc: return {"success":False,"error":str(exc)}

@app.post("/api/v12/gate")
async def v12_gate(file: UploadFile = File(...), threshold:int=Form(80), max_high:int=Form(0), max_critical:int=Form(0), authorization:str=Header(default="")):
    user=user_from_token(authorization.replace("Bearer ","",1))
    if not user: raise HTTPException(401,"Authentication required.")
    if not file.filename or not file.filename.lower().endswith(".zip"): raise HTTPException(400,"Upload a ZIP archive.")
    data=await file.read(50*1024*1024+1)
    if len(data)>50*1024*1024: raise HTTPException(413,"ZIP exceeds 50 MB.")
    result=scan_uploaded_archive(data,file.filename,retain_sources=True,policy={"threshold":threshold,"max_high":max_high,"max_critical":max_critical})
    result["scan_id"]=save_scan(user["id"],"CI/CD Gate",file.filename,result)
    result.pop("_sources",None)
    return result

@app.post("/api/v13/logout")
def v13_logout(authorization:str=Header(default="")):
    revoke_token(authorization.replace("Bearer ","",1))
    from fastapi.responses import JSONResponse
    response=JSONResponse({"success":True})
    response.delete_cookie("cg_session",path="/")
    return response

from google_login import router as google_router
app.include_router(google_router)

from fastapi.staticfiles import StaticFiles
static_dir=Path(__file__).with_name("web")
if static_dir.is_dir(): app.mount("/app",StaticFiles(directory=static_dir,html=True),name="frontend")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host=os.getenv("CODEGUARD_HOST","127.0.0.1"), port=int(os.getenv("PORT","8000")), reload=False)
