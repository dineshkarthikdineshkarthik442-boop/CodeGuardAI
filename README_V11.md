# CodeGuard AI V11 — AI Fix Preview

Extract to a new folder and stop old CodeGuard server windows before starting.
Copy your old backend/codeguard.db into this backend folder while the servers are stopped to retain accounts/history.

## Enable AI

Create config.bat beside START_ALL.bat using config.example.bat as a template. Set your existing GROQ_API_KEY locally. Never share this file or commit it to Git. The key is used by the backend only.
Run START_ALL.bat and open http://localhost:5173.
Without a key, scanning and reports still work; AI previews show an availability error.

## Generate a fix

Run a scan or open a report from Scan History. On a Python finding click Generate Fix.
Paste the COMPLETE corresponding source file (60 KB maximum). Source must still contain the selected rule at its scanned line. Changed files should be rescanned first.
Read and check the consent box: the pasted source and finding will be sent to Groq. Remove secrets/private information before sending; source is not saved in the scan database.
Click Generate AI preview. Review original and replacement code, the unified diff, syntax validity, rule counts, and remaining findings. Download the patch or replacement file for manual review/application.

Validation parses and scans code; it does not execute source, run project tests, guarantee security, or verify preserved behavior. A cleared rule means only the rule pattern was no longer detected. Non-Python fixes are not supported in this release. No repository files are automatically changed.

## Verification

Backend: python -m pytest tests -q (install pytest and httpx for tests).
Frontend: npm test; npm run build.
Live Groq generation requires a valid API key, provider availability, and connectivity. Provider calls were mocked in automated tests; no real source was sent during development.
