# CodeGuard AI V8 — CI/CD Security Gate

V8 adds a build-time security gate. Upload a repository ZIP, run the FAST security analysis, and receive a machine-readable PASS/FAIL result.

## API
`POST /api/v8/security-gate` with multipart field `file`.

## Policy
- `CODEGUARD_GATE_THRESHOLD` default `80`
- `CODEGUARD_GATE_MAX_HIGH` default `0`
- `CODEGUARD_GATE_MAX_CRITICAL` default `0`

## CLI
```powershell
cd backend
python ci_gate_cli.py ..\repository.zip
python ci_gate_cli.py ..\repository.zip --json
```
Exit code `0` = pass, `1` = fail, `2` = input error.

## Run
```powershell
cd C:\Users\WELCOME\CodeGuardAI\backend
.\.venv\Scripts\Activate.ps1
$env:GROQ_MODEL="openai/gpt-oss-120b"
python main.py
```
Then start the existing frontend with `npm run dev`.

V8 is read-only and does not push or merge changes.
