import shutil
import tempfile
from pathlib import Path

from fastapi import FastAPI, File, UploadFile
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

app = FastAPI(title="CodeGuard AI V7", version="7.0.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])


def analyze_source(source, name):
    result = scan_python_source(source)
    if not result.get("success"):
        return {"success": False, "error": result.get("syntax_error", "Syntax error")}
    return {"success": True, "file": name, "lines": len(source.splitlines()), "score": result.get("score", 100), "issues": result.get("issues", [])}


@app.get("/")
def root(): return {"name": "CodeGuard AI", "version": "V7.0", "status": "online"}

@app.get("/health")
def health(): return {"status": "ok", "version": "V7.0"}

@app.post("/api/analyze")
async def analyze(file: UploadFile = File(...)):
    if not file.filename or Path(file.filename).suffix.lower() != ".py": return {"success": False, "error": "Python files only."}
    try:
        source = (await file.read()).decode("utf-8", errors="replace")
        return analyze_source(source, Path(file.filename).name)
    except Exception as exc: return {"success": False, "error": str(exc)}

@app.post("/api/v4/github-scan")
async def github_scan(payload: dict):
    try: return scan_repository((payload or {}).get("url", "").strip())
    except Exception as exc: return {"success": False, "error": str(exc)}

@app.post("/api/v7/pr-review")
async def v7_pr_review(payload: dict):
    url = (payload or {}).get("url", "").strip()
    if not url: return {"success": False, "error": "GitHub Pull Request URL is required."}
    try: return review_pull_request(url)
    except Exception as exc: return {"success": False, "error": str(exc)}

@app.post("/api/v7/ai-explain")
async def v7_ai_explain(payload: dict):
    if review_code_with_ai is None: return {"success": False, "error": "AI reviewer is unavailable."}
    payload = payload or {}; finding = payload.get("finding") or {}; code = payload.get("code", "")
    if not finding or not code: return {"success": False, "error": "Finding and code context are required."}
    try: return {"success": True, "ai_review": review_code_with_ai(code, [finding])}
    except Exception as exc: return {"success": False, "error": str(exc)}

@app.post("/api/v7/ai-summary")
async def v7_ai_summary(payload: dict):
    if review_code_with_ai is None: return {"success": False, "error": "AI reviewer is unavailable."}
    payload = payload or {}; diff = payload.get("diff", ""); findings = payload.get("findings") or []
    if not diff: return {"success": False, "error": "Pull Request diff is required."}
    try:
        clipped = diff[:50000]
        return {"success": True, "ai_review": review_code_with_ai(clipped, findings)}
    except Exception as exc: return {"success": False, "error": str(exc)}

@app.post("/api/v5/ai-fix")
async def v5_ai_fix(payload: dict):
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
async def v6_generate_tests(payload: dict):
    if generate_security_tests is None: return {"success": False, "error": "AI test generator is unavailable."}
    payload = payload or {}; finding = payload.get("finding") or {}; original = payload.get("original_code") or ""; fixed = payload.get("fixed_code") or ""
    if not finding or not original or not fixed: return {"success": False, "error": "Finding, original code, and fixed code are required."}
    try: return {"success": True, "finding": finding, "tests": generate_security_tests(original, fixed, finding)}
    except Exception as exc: return {"success": False, "error": str(exc)}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=False)
