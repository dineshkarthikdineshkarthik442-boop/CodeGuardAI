# CodeGuard AI V9 — Cloud Security Dashboard

V9 adds a lightweight cloud-style workspace on top of the existing V8 security engine.

## New
- Email/password account creation and login
- SQLite persistence (local by default)
- Session tokens
- Personal scan history
- Dashboard metrics
- Persistent report metadata
- Scan detail API
- Keeps V4/V5/V6/V7/V8 endpoints intact

## API
- POST `/api/v9/auth/register`
- POST `/api/v9/auth/login`
- GET `/api/v9/me`
- GET `/api/v9/scans`
- GET `/api/v9/scans/{id}`
- POST `/api/v9/scans`

Run backend:
```powershell
cd C:\Users\WELCOME\CodeGuardAI\backend
.\.venv\Scripts\Activate.ps1
$env:GROQ_MODEL="openai/gpt-oss-120b"
python main.py
```

Run frontend:
```powershell
cd C:\Users\WELCOME\CodeGuardAI\frontend
npm run dev
```

The database is `backend/codeguard.db`. This V9 package is intended as a local/cloud-ready foundation; production deployment should add HTTPS, secure cookies/JWT rotation, password hashing such as Argon2/bcrypt, rate limiting, and a managed database.
