# V14.1 Google login and rounded button

Copy the contents of this CodeGuardAI_V14 folder over your existing CodeGuardAI_V14 Git repository, replacing matching files. Keep config.bat and your database. Do not delete your Git repository.

In the original folder run:

```
git add frontend/src/App.jsx frontend/src/App.css frontend/src/GoogleLogin.jsx frontend/package.json frontend/package-lock.json frontend/tests/render.mjs frontend/tests/auth.mjs backend/main.py backend/request_security.py UPDATE_V14_1.md
git commit -m "Fix Google session handling and rounded login button"
git push origin main
```

Render auto deploys if enabled; otherwise use Manual Deploy > Deploy latest commit.
Keep GOOGLE_CLIENT_ID and GROQ_API_KEY unchanged. CODEGUARD_ALLOWED_ORIGINS must be https://codeguardai-hcas.onrender.com, CODEGUARD_COOKIE_SECURE=1 and CODEGUARD_PRODUCTION=1.

Open https://codeguardai-hcas.onrender.com/app/ and press Ctrl+F5. If the email already has a password account, enter its CodeGuard password before Google sign-in to link securely. Copy any error below the Google button if sign-in still fails.

Session restoration no longer calls logout; the login form waits for restoration; history errors do not end the session; localStorage is no longer required; the saved cookie is verified before dashboard entry. Google errors are visible with a retry action. The official Google button has responsive width, centered placement and pill-shaped ends. Referrer-Policy now follows Google's recommended cross-origin setting.

Validation: 17 backend tests, 8 render checks, production build and mocked React interaction tests for login, refresh, logout, account-link conflict, missing cookie and history failures. Real Google account login and browser visual verification remain untested here. This ZIP has not been pushed or deployed to your service.

Render Free still loses SQLite accounts and history on restart/redeploy/sleep. This patch does not add persistent storage.
