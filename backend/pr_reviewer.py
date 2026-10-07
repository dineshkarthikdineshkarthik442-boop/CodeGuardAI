import re
from pathlib import Path
from urllib.parse import urlparse

import requests

from security_scanner import scan_python_source

GITHUB_API = "https://api.github.com"
HEADERS = {
    "Accept": "application/vnd.github+json",
    "User-Agent": "CodeGuard-AI/7.0",
}
MAX_FILES = 100
MAX_FILE_BYTES = 750_000


def parse_pr_url(url: str):
    value = (url or "").strip()
    if not value.startswith(("https://", "http://")):
        value = "https://" + value
    parsed = urlparse(value)
    if parsed.netloc.lower() not in {"github.com", "www.github.com"}:
        raise ValueError("Only github.com Pull Request URLs are supported.")
    parts = [p for p in parsed.path.split("/") if p]
    if len(parts) < 4 or parts[2].lower() != "pull" or not parts[3].isdigit():
        raise ValueError("Use a Pull Request URL like https://github.com/owner/repository/pull/123")
    return parts[0], parts[1], int(parts[3])


def _get(url, params=None):
    response = requests.get(url, headers=HEADERS, params=params, timeout=(10, 30))
    if response.status_code == 404:
        raise ValueError("Pull Request or repository was not found. Public repositories are supported.")
    if response.status_code == 403:
        raise RuntimeError("GitHub API rate limit or access restriction. Try again later.")
    response.raise_for_status()
    return response


def _added_lines_from_patch(patch: str):
    """Return new-file line numbers represented by + lines in a unified diff."""
    added = set()
    if not patch:
        return added
    new_line = None
    for raw in patch.splitlines():
        if raw.startswith("@@"):
            match = re.search(r"\+(\d+)(?:,(\d+))?", raw)
            if match:
                new_line = int(match.group(1))
            continue
        if new_line is None:
            continue
        if raw.startswith("+++"):
            continue
        if raw.startswith("+"):
            added.add(new_line)
            new_line += 1
        elif raw.startswith("-"):
            continue
        else:
            new_line += 1
    return added


def _raw_file(owner, repo, sha, path):
    url = f"{GITHUB_API}/repos/{owner}/{repo}/contents/{path}"
    response = _get(url, {"ref": sha})
    data = response.json()
    if isinstance(data, list):
        raise ValueError(f"{path} is not a file.")
    import base64
    content = data.get("content", "")
    encoding = data.get("encoding")
    if encoding != "base64":
        raise ValueError(f"GitHub returned unsupported content encoding for {path}.")
    source = base64.b64decode(content).decode("utf-8", errors="replace")
    if len(source.encode("utf-8")) > MAX_FILE_BYTES:
        raise ValueError(f"{path} is too large for PR analysis.")
    return source


def _severity_counts(findings):
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for item in findings:
        sev = str(item.get("severity", "LOW")).upper()
        counts[sev] = counts.get(sev, 0) + 1
    return counts


def _finding_key(item):
    return (item.get("rule_id"), item.get("line"), item.get("message"))


def review_pull_request(pr_url: str):
    owner, repo, number = parse_pr_url(pr_url)
    base_url = f"{GITHUB_API}/repos/{owner}/{repo}/pulls/{number}"
    pr = _get(base_url).json()
    if pr.get("state") != "open":
        state = pr.get("state", "unknown")
    files = _get(f"{base_url}/files", {"per_page": MAX_FILES}).json()
    if not isinstance(files, list):
        raise RuntimeError("GitHub returned an invalid Pull Request file list.")
    if len(files) >= MAX_FILES:
        files = files[:MAX_FILES]

    findings = []
    file_summaries = []
    changed_python = 0
    added_lines_total = 0
    removed_lines_total = 0
    combined_diff = []

    for item in files:
        path = item.get("filename", "")
        status = item.get("status", "modified")
        additions = int(item.get("additions", 0) or 0)
        deletions = int(item.get("deletions", 0) or 0)
        added_lines_total += additions
        removed_lines_total += deletions
        patch = item.get("patch", "") or ""
        if patch:
            combined_diff.append(f"diff --git a/{path} b/{path}\n{patch}")
        is_python = path.lower().endswith(".py")
        summary = {
            "file": path,
            "status": status,
            "additions": additions,
            "deletions": deletions,
            "changed": True,
            "language": "Python" if is_python else "Other",
        }
        file_summaries.append(summary)
        if not is_python or status == "removed":
            continue
        changed_python += 1
        try:
            source = _raw_file(owner, repo, pr.get("head", {}).get("sha"), path)
            scan = scan_python_source(source)
        except Exception as exc:
            summary["error"] = str(exc)
            continue
        if not scan.get("success"):
            summary["error"] = scan.get("syntax_error", "Syntax error")
            continue
        added_lines = _added_lines_from_patch(patch)
        summary["added_security_lines"] = len(added_lines)
        summary["findings"] = len(scan.get("issues", []))
        for finding in scan.get("issues", []):
            line = int(finding.get("line", 0) or 0)
            classification = "INTRODUCED" if line in added_lines else "EXISTING"
            enriched = dict(finding)
            lines = source.splitlines()
            start = max(0, line - 4)
            end = min(len(lines), line + 3)
            enriched.update({
                "file": path,
                "code_context": "\n".join(f"{i+1}: {lines[i]}" for i in range(start, end)),
                "pr_status": classification,
                "source": "changed-file-head",
            })
            findings.append(enriched)

    counts = _severity_counts(findings)
    introduced = [f for f in findings if f.get("pr_status") == "INTRODUCED"]
    existing = [f for f in findings if f.get("pr_status") == "EXISTING"]
    score = max(0, 100 - sum({"CRITICAL": 30, "HIGH": 15, "MEDIUM": 8, "LOW": 2}.get(str(f.get("severity", "LOW")).upper(), 2) for f in findings))

    return {
        "success": True,
        "pull_request": {
            "number": number,
            "title": pr.get("title", ""),
            "state": state,
            "draft": bool(pr.get("draft")),
            "author": (pr.get("user") or {}).get("login", "unknown"),
            "base": (pr.get("base") or {}).get("ref", ""),
            "head": (pr.get("head") or {}).get("ref", ""),
            "base_sha": (pr.get("base") or {}).get("sha", ""),
            "head_sha": (pr.get("head") or {}).get("sha", ""),
            "url": pr.get("html_url", pr_url),
        },
        "repository": {"owner": owner, "name": repo, "url": f"https://github.com/{owner}/{repo}"},
        "files": file_summaries,
        "files_changed": len(files),
        "python_files_changed": changed_python,
        "additions": added_lines_total,
        "deletions": removed_lines_total,
        "added_lines_analyzed": added_lines_total,
        "score": score,
        "severity_counts": counts,
        "introduced_findings": introduced,
        "existing_findings": existing,
        "findings": findings,
        "diff": "\n\n".join(combined_diff)[:50000],
        "summary": {
            "introduced": len(introduced),
            "existing": len(existing),
            "total": len(findings),
        },
    }
