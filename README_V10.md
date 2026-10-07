# CodeGuard AI V10 — Detailed Security Reports

Built from your V9 Fixed archive. Existing v4-v9 API routes and database schema are preserved.

## Start on Windows

Extract to a NEW folder, for example C:\Users\WELCOME\CodeGuardAI_V10.
Install Python 3.12+ and Node.js LTS if missing. Double-click START_ALL.bat.
When Vite reports ready, open http://localhost:5173. Both server windows must remain open.

To retain existing accounts/history: stop the old backend and copy its backend/codeguard.db into the new backend folder before starting V10. Keep a backup. No database is included in this ZIP.

Manual backend: cd backend; python -m venv .venv; .venv\Scripts\python.exe -m pip install -r requirements.txt; .venv\Scripts\python.exe main.py
Manual frontend in another terminal: cd frontend; npm install; npm run dev

## Workflow

Sign in or create account → New Scan → GitHub Repository or Upload Project ZIP → Run Security Scan.
Below the score, inspect file paths, line numbers, rule identifiers, severity, explanations, and recommended actions.
Filter by severity or search a file/rule/message. Download JSON for machine processing, or HTML for sharing.
Open the HTML in a browser and use Print → Save as PDF for PDF output. Exports include all findings regardless of current filters and safely escape report content.
Scan History → View report reopens an authenticated saved result. Other accounts cannot retrieve that report.

## Fixes and limits

- Python ZIP scans now use the real AST scanner instead of silently falling back after an invalid function call.
- Parser failures appear in reports and fail ZIP security gates.
- Empty/unsupported ZIPs are rejected rather than receiving a passing score.
- Archive expansion is limited to 100 MB / 10000 entries; source scans are capped at 500 files and 750 KB per file.
- Added missing frontend package, entry point, and HTML setup files.
- Startup block now follows route registration; version endpoints report V10.
- New scans return their saved report ID.

GitHub scans currently inspect Python. ZIP scans inspect Python with AST rules; other listed source languages receive only basic pattern checks. Scores are rule penalties, not measured security assurance. Findings can be false positives. No uploaded code is executed. AI-generated fixes are a later UI milestone; existing backend AI routes remain available.

This package remains a LOCAL development release. Existing legacy API routes are retained and some are unauthenticated; do not expose this server publicly before authentication hardening. V9 password/session storage is retained for compatibility.

## Validation

From backend: python -m pip install pytest httpx; python -m pytest tests -q
From frontend: npm run build
GitHub endpoint tests use a local fixture; live GitHub access requires network connectivity.

## Proposed remaining roadmap

V11: AI fix preview and validation. V12: integrated PR review and CI/CD interface. V13: deployment hardening, performance, and release checks. Completion depends on verified behavior, not version numbers.

## V10.1 blank-page correction
Explicit React imports fix the default classic JSX runtime. Removed undefined result reference from History. Added npm test to render login, dashboard, both history states, new scan, and detailed report.
Stop both old servers, extract this package, and start START_ALL.bat from the new folder. Refresh with Ctrl+F5.
