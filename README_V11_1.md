# V11.1 — Automatic ZIP source

Stop old server windows, extract this version to a new folder, copy backend/codeguard.db and config.bat from your previous version if needed, then run START_ALL.bat.

Upload and scan your ZIP again. On a Python finding click Generate Fix. CodeGuard automatically reads the exact matching nested file from the ZIP; no manual extraction or paste is needed. Review the loaded source, check consent to send the file to Groq, then click Generate AI preview. Preview and patch downloads use the original scanned source.

Python files up to 60 KB are retained in your local scan database for automatic fixes. Access requires the owning account. Full source is excluded from ordinary report responses and exports. Treat the database and backups as private project files. Larger files, GitHub scans, and old scans use the manual source fallback. No source is executed or written to your project. Live AI still needs GROQ_API_KEY in config.bat.

Checks: 8 backend tests, 6 frontend render checks, production build passed. Live Groq calls and Windows execution were not tested.
