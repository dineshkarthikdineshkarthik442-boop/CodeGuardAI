import ast
import re

SEVERITY_PENALTY = {"CRITICAL": 30, "HIGH": 15, "MEDIUM": 8, "LOW": 2}


def _source_lines(source):
    return source.splitlines()


def scan_python_source(source: str):
    lines = _source_lines(source)
    issues = []

    try:
        tree = ast.parse(source)
    except SyntaxError as exc:
        return {"success": False, "issues": [], "syntax_error": str(exc)}

    def add(severity, category, line, message, recommendation, rule_id):
        issues.append({
            "severity": severity,
            "category": category,
            "line": int(line or 1),
            "message": message,
            "recommendation": recommendation,
            "rule_id": rule_id,
        })

    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            name = node.func.id
            if name == "eval":
                add("CRITICAL", "Code Injection", node.lineno, "eval() executes dynamically supplied Python code.", "Avoid eval(). Use a safe parser or an allow-listed operation map.", "CG-CODE-001")
            elif name == "exec":
                add("CRITICAL", "Code Injection", node.lineno, "exec() can execute attacker-controlled Python code.", "Remove exec() or replace it with explicit, validated operations.", "CG-CODE-002")
            elif name == "input":
                add("LOW", "Input Handling", node.lineno, "Raw input() is used without visible validation.", "Validate, constrain, and sanitize untrusted input before use.", "CG-INPUT-001")
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            full = f"{getattr(node.func.value, 'id', '')}.{node.func.attr}"
            if full in {"os.system", "os.popen"}:
                add("CRITICAL", "Command Injection", node.lineno, f"{full} can execute operating-system commands.", "Use subprocess with shell=False and a fixed argument list.", "CG-CMD-001")
            if node.func.attr in {"run", "Popen", "call", "check_call", "check_output"}:
                for kw in node.keywords:
                    if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                        add("CRITICAL", "Command Injection", node.lineno, "subprocess is configured with shell=True.", "Use shell=False and pass arguments as a list.", "CG-CMD-001")
            if node.func.attr in {"loads", "load"}:
                module = getattr(node.func.value, "id", "")
                if module in {"pickle", "cPickle", "marshal"}:
                    add("CRITICAL", "Insecure Deserialization", node.lineno, f"{module}.{node.func.attr} can deserialize untrusted data into executable objects.", "Do not deserialize untrusted data with pickle/marshal. Use a safe data format such as JSON.", "CG-DESER-001")
            if node.func.attr in {"md5", "sha1", "DES", "des"}:
                add("MEDIUM", "Weak Cryptography", node.lineno, f"Weak or legacy cryptographic primitive {node.func.attr} detected.", "Use modern primitives such as SHA-256 for hashing or AES-GCM/ChaCha20-Poly1305 for encryption.", "CG-CRYPTO-001")
            if node.func.attr in {"get", "post", "put", "delete", "request", "head"} and getattr(node.func.value, "id", "") in {"requests", "httpx"}:
                add("MEDIUM", "SSRF", node.lineno, "Server-side HTTP request target may be attacker controlled.", "Allow-list destinations and validate URLs before making server-side requests.", "CG-SSRF-002")
        if isinstance(node, ast.Attribute) and node.attr in {"innerHTML", "outerHTML"}:
            add("HIGH", "Cross-Site Scripting", node.lineno, f"Dynamic assignment to {node.attr} can create an XSS sink.", "Prefer safe DOM APIs and encode untrusted content before rendering.", "CG-XSS-001")

    source_lower = source.lower()
    for lineno, line in enumerate(lines, 1):
        stripped = line.strip()
        secret_match = re.search(r"\b(password|passwd|secret|api_key|apikey|token|private_key)\b\s*=\s*([\"']).+?\2", stripped, re.I)
        if secret_match:
            name = secret_match.group(1)
            add("HIGH", "Hardcoded Secret", lineno, f"Possible hardcoded secret in variable '{name}'.", "Move secrets to environment variables or a secret manager and rotate exposed credentials.", "CG-SECRET-001")
        if re.search(r"\b(?:query|sql|statement)\b\s*=.*(?:\+|%\(|\.format\(|f[\"'])", stripped, re.I) and re.search(r"select\s+|insert\s+|update\s+|delete\s+", stripped, re.I):
            add("HIGH", "SQL Injection", lineno, "SQL query appears to be dynamically constructed from a value.", "Use parameterized queries/prepared statements instead of string concatenation or interpolation.", "CG-SQL-003")
        if re.search(r"open\s*\(\s*[\"'][^\"']*[\"']\s*\+", stripped):
            add("HIGH", "Path Traversal", lineno, "A file path is dynamically constructed from a value.", "Normalize and validate paths, then enforce an approved base directory before opening files.", "CG-PATH-001")
        if re.search(r"(telnetlib|ftplib)\b", stripped):
            add("MEDIUM", "Insecure Protocol", lineno, "Legacy plaintext network protocol detected.", "Prefer encrypted protocols such as SSH or TLS-protected HTTP/FTP alternatives.", "CG-PROTO-001")
        if re.search(r"\brandom\.(random|randint|choice|randrange|choices|shuffle)\s*\(", stripped):
            add("MEDIUM", "Weak Randomness", lineno, "The standard random module is not suitable for security-sensitive randomness.", "Use secrets.SystemRandom or the secrets module for security-sensitive values.", "CG-RANDOM-001")

    # AST-aware SQL concatenation / interpolation detection.
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr in {"execute", "executemany", "executescript"}:
            if node.args:
                query_node = node.args[0]
                if isinstance(query_node, (ast.BinOp, ast.JoinedStr, ast.Call)):
                    add("HIGH", "SQL Injection", node.lineno, "Database execution receives a dynamically constructed SQL expression.", "Use parameterized SQL placeholders and bind user values separately.", "CG-SQL-003")
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr in {"safe_load", "load"}:
            module = getattr(node.func.value, "id", "")
            if module == "yaml":
                for kw in node.keywords:
                    if kw.arg == "Loader":
                        add("HIGH", "Insecure Deserialization", node.lineno, "YAML loading uses an explicit loader and may permit unsafe object construction.", "Use yaml.safe_load() for untrusted YAML and avoid unsafe loaders.", "CG-DESER-002")

    # Dedupe by rule + line + category.
    unique = {}
    for issue in issues:
        key = (issue["rule_id"], issue["line"], issue["category"])
        unique[key] = issue
    issues = list(unique.values())
    issues.sort(key=lambda x: (x["line"], x["severity"], x["rule_id"]))
    score = 100 - sum(SEVERITY_PENALTY.get(x["severity"], 0) for x in issues)
    return {"success": True, "issues": issues, "score": max(0, score), "syntax_error": None}
