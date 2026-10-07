# CodeGuard AI V13 — Hardened local release and deployment package

## Upgrade on Windows
1. Close both old server windows.
2. Extract V13 into a NEW folder.
3. Back up your old backend/codeguard.db. Copy it into V13/backend.
4. Copy your working config.bat beside START_ALL.bat. Never upload this file or your database to GitHub.
5. Run START_ALL.bat and open http://localhost:5173.
6. Sign in again: V13 deliberately invalidates old sessions once. Existing accounts and scans remain. Legacy password hashes upgrade on successful sign-in; old passwords continue to work. New accounts require 10–256-character passwords.

All previous pages remain: ZIP/GitHub scanning, reports, automatic Python source loading, AI fix previews, PR reviews, and CI/CD gates.

## Security changes
- Salted PBKDF2-SHA256 password hashes with 600000 iterations; legacy SHA256 hashes migrate on sign-in.
- Session tokens are hashed in the database, expire after 24 hours, and are revoked on logout.
- All /api routes except sign-in and registration require a valid session, including old v4–v8 routes. CLI gates remain local and do not need a token.
- Login/registration rate limit: 20 requests per client IP per minute, in process memory. Multiple workers/instances require a shared gateway/rate limiter.
- Request-body limits apply even without Content-Length: 1 MB normally, 55 MB for ZIP multipart endpoints; ZIP scanner limits remain stricter.
- CORS defaults to localhost development origins; configure explicit frontend origins when hosting separately.
- Configurable signup and API docs, database location and host/port; sensitive database/config files excluded by .gitignore and .dockerignore.
- Repository archive extraction validates member paths and expanded size.
- Frontend error fallback replaces an empty page if rendering crashes.

## Docker: frontend and backend together
Docker files are provided but Docker image execution was not tested in this environment.

    docker compose up --build -d

Open http://localhost:8000/app/ (the trailing slash matters). Compose binds the service to loopback, and data persists in the named codeguard-data volume. AI is optional; set GROQ_API_KEY in your shell environment before starting Compose if using AI previews. config.bat is only for Windows batch startup and is not copied into the container.

The first signup creates your account. You can then set CODEGUARD_ALLOW_SIGNUP=0 and recreate the service to disable additional registrations. Existing account sign-in continues.

## Configuration
| Variable | Purpose |
| --- | --- |
| GROQ_API_KEY | Backend AI provider key |
| GROQ_MODEL | Optional model override supported by your Groq account |
| CODEGUARD_DB_PATH | Absolute database path; use persistent storage on a host |
| CODEGUARD_ALLOWED_ORIGINS | Comma-separated frontend origins, no wildcard |
| CODEGUARD_ALLOW_SIGNUP | 1 enables registration; 0 disables it |
| CODEGUARD_ENABLE_DOCS | 1 enables /docs; Docker defaults to 0 |
| CODEGUARD_HOST | Defaults to 127.0.0.1; Docker uses 0.0.0.0 |
| PORT | Backend port, default 8000 |

For a separately hosted frontend set VITE_API_URL at build time. The combined production build uses the same origin and /app/ path. A raw frontend production preview without a backend on its origin needs VITE_API_URL configured.

## Before public hosting
This is a hardened development release, not an audited multi-tenant service. Deploy behind HTTPS, persist and back up the database, restrict registration, enforce edge request/concurrency limits, and keep credentials out of source control. Browser tokens remain in localStorage. The GitHub downloader retains a Git fallback, which needs resource constraints on the hosting machine. Only the included scanner rules are used; scores are not security guarantees. Code is parsed but never executed. AI suggestions need project tests and human review.

No website was deployed and no hosting account was changed. Use your selected host's Docker deployment support with a persistent data mount and runtime secrets. Free hosts with ephemeral filesystems can lose SQLite history; confirm storage before uploading important work.

## Validation
14 backend tests passed, including old-account migration, expiry/logout, authentication of legacy APIs, request-size rejection, CORS and signup/rate policy.
8 frontend render checks and Vite production build passed.
Provider and PR network calls were mocked in tests. Docker, live hosted deployment, Windows batch execution, and a browser end-to-end run were not tested here.

    cd backend
    python -m pip install -r requirements.txt pytest httpx
    python -m pytest tests -q

    cd frontend
    npm ci
    npm test
    npm run build

## Release scope
V13 completes the proposed first-release roadmap as a local package with deployment scaffolding. Public launch still requires deployment and live acceptance checks. README_V12.md describes PR and gate workflows; README_V11_1.md describes automatic source loading.
