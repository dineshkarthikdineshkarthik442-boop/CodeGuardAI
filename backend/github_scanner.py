import ast
import io
import os
import re
import shutil
import tempfile
import zipfile
from pathlib import Path
from urllib.parse import urlparse

import requests

from security_scanner import scan_python_source

IGNORED_DIRS = {
    ".git", ".github", "node_modules", "venv", ".venv", "env", ".env",
    "__pycache__", ".pytest_cache", ".mypy_cache", ".idea", ".vscode",
    "dist", "build", "coverage", "site-packages", "target"
}
MAX_FILES = 500
MAX_FILE_BYTES = 750_000


def parse_github_url(url: str):
    value = (url or "").strip()
    if not value:
        raise ValueError("GitHub repository URL is required.")
    if not value.startswith(("https://", "http://")):
        value = "https://" + value
    parsed = urlparse(value)
    if parsed.netloc.lower() not in {"github.com", "www.github.com"}:
        raise ValueError("Only github.com repository URLs are supported.")
    parts = [p for p in parsed.path.split("/") if p]
    if len(parts) < 2:
        raise ValueError("Use a repository URL like https://github.com/owner/repository")
    owner, repo = parts[0], parts[1]
    repo = re.sub(r"\.git$", "", repo)
    if not owner or not repo:
        raise ValueError("Could not determine the GitHub owner and repository name.")
    return owner, repo


def _download_with_requests(owner: str, repo: str, temp_dir: Path):
    """Download a public repository without requiring a GitHub token."""
    archive_url = f"https://api.github.com/repos/{owner}/{repo}/zipball"
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "CodeGuard-AI/6.1",
    }
    response = requests.get(
        archive_url,
        headers=headers,
        timeout=(10, 45),
        allow_redirects=True,
        stream=True,
    )
    if response.status_code == 404:
        raise ValueError("Repository not found or it is private. Public repositories are supported in V4.")
    if response.status_code == 403:
        raise RuntimeError("GitHub API rate limit or access restriction. CodeGuard will try Git fallback next.")
    response.raise_for_status()
    archive_path = temp_dir / "repository.zip"
    size=0
    with response, archive_path.open('wb') as output:
        for chunk in response.iter_content(65536):
            size+=len(chunk)
            if size>50*1024*1024: raise ValueError("Repository download exceeds 50 MB.")
            output.write(chunk)
    with archive_path.open('rb') as downloaded:
        if downloaded.read(2)!=b'PK': raise ValueError("GitHub returned an unexpected archive response.")
    return archive_path


def _download_with_git(url: str, temp_dir: Path):
    """Fallback for environments where the GitHub API is blocked/rate-limited."""
    import subprocess

    clone_dir = temp_dir / "repo"
    command = [
        "git", "clone", "--depth", "1", "--filter=blob:none", url, str(clone_dir)
    ]
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=90,
            check=False,
        )
    except FileNotFoundError:
        raise RuntimeError(
            "GitHub fetch failed because the Git executable is not installed. "
            "Install Git for Windows and restart CodeGuard AI."
        )
    except subprocess.TimeoutExpired:
        raise RuntimeError("GitHub fetch timed out after 90 seconds. Try a smaller public repository.")

    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout or "Unknown git error").strip()
        detail = detail[-500:]
        raise RuntimeError(f"GitHub fetch failed: {detail}")
    return clone_dir


def download_repository(url: str):
    owner, repo = parse_github_url(url)
    temp_dir = Path(tempfile.mkdtemp(prefix="codeguard_repo_"))

    try:
        try:
            archive_path = _download_with_requests(owner, repo, temp_dir)
            extract_dir = temp_dir / "repo"
            extract_dir.mkdir()
            with zipfile.ZipFile(archive_path) as archive:
                if len(archive.infolist())>10000 or sum(i.file_size for i in archive.infolist())>100*1024*1024: raise RuntimeError("Repository archive exceeds safety limits.")
                for item in archive.infolist():
                    target=(extract_dir/item.filename).resolve()
                    if extract_dir.resolve() not in target.parents: raise ValueError("Unsafe repository archive path.")
                archive.extractall(extract_dir)
            roots = [p for p in extract_dir.iterdir() if p.is_dir()]
            repo_root = roots[0] if roots else extract_dir
            return temp_dir, repo_root, owner, repo
        except (requests.RequestException, RuntimeError, zipfile.BadZipFile) as api_error:
            # Git clone avoids GitHub API rate limits and works when api.github.com
            # is blocked by a network/proxy, while still supporting public repos.
            try:
                if os.getenv("CODEGUARD_ENABLE_GIT_FALLBACK","0")!="1": raise RuntimeError("Git fallback disabled. Try the GitHub download again later or upload a ZIP.")
                repo_root = _download_with_git(f"https://github.com/{owner}/{repo}.git", temp_dir)
                return temp_dir, repo_root, owner, repo
            except Exception as git_error:
                shutil.rmtree(temp_dir, ignore_errors=True)
                raise RuntimeError(
                    "Unable to fetch this public GitHub repository. "
                    f"API attempt: {api_error}. Git fallback: {git_error}"
                ) from git_error
    except Exception:
        shutil.rmtree(temp_dir, ignore_errors=True)
        raise


def _python_counts(source: str):
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return 0, 0, 0
    functions = sum(isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) for node in ast.walk(tree))
    classes = sum(isinstance(node, ast.ClassDef) for node in ast.walk(tree))
    imports = sum(isinstance(node, (ast.Import, ast.ImportFrom)) for node in ast.walk(tree))
    return functions, classes, imports


def scan_repository(url: str):
    temp_dir, repo_root, owner, repo = download_repository(url)
    try:
        findings = []
        files_scanned = 0
        lines_analyzed = 0
        functions = classes = imports = 0
        syntax_errors = []

        for path in repo_root.rglob("*.py"):
            if files_scanned >= MAX_FILES:
                break
            if any(part in IGNORED_DIRS for part in path.parts):
                continue
            try:
                size = path.stat().st_size
            except OSError:
                continue
            if size > MAX_FILE_BYTES:
                continue
            try:
                source = path.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                try:
                    source = path.read_text(encoding="latin-1")
                except OSError:
                    continue
            except OSError:
                continue

            files_scanned += 1
            lines_analyzed += len(source.splitlines())
            f_count, c_count, i_count = _python_counts(source)
            functions += f_count
            classes += c_count
            imports += i_count

            result = scan_python_source(source)
            if result.get("syntax_error"):
                syntax_errors.append({"file": str(path.relative_to(repo_root)).replace("\\", "/"), "message": result["syntax_error"]})
                continue
            for finding in result.get("issues", []):
                item = dict(finding)
                item["file"] = str(path.relative_to(repo_root)).replace("\\", "/")
                findings.append(item)

        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        findings.sort(key=lambda x: (severity_order.get(x.get("severity", "LOW"), 9), x.get("file", ""), x.get("line", 0)))
        counts = {key: sum(1 for f in findings if f.get("severity") == key) for key in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]}
        categories = {}
        for finding in findings:
            category = finding.get("category", "Other")
            categories[category] = categories.get(category, 0) + 1

        score = 100
        penalties = {"CRITICAL": 30, "HIGH": 15, "MEDIUM": 8, "LOW": 2}
        for finding in findings:
            score -= penalties.get(finding.get("severity"), 0)
        score = max(0, score)

        return {
            "success": True,
            "repository": {
                "owner": owner,
                "name": repo,
                "url": f"https://github.com/{owner}/{repo}",
            },
            "scanner": "CodeGuard AI V4 Repository Scanner",
            "score": score,
            "files_scanned": files_scanned,
            "lines_analyzed": lines_analyzed,
            "functions": functions,
            "classes": classes,
            "imports": imports,
            "findings": findings,
            "severity_counts": counts,
            "categories": categories,
            "syntax_errors": syntax_errors,
            "limits": {"max_files": MAX_FILES, "max_file_bytes": MAX_FILE_BYTES},
        }
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)
