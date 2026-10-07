# CodeGuard V14 — Publish and configure Google sign-in

This is a deployable package, not an already deployed website. No hosting account or Google OAuth application was created. No application can be guaranteed impossible to breach. Keep the old V13 folder and database backup until acceptance checks pass.

## 1. Put source on GitHub
Extract the ZIP. The inner CodeGuardAI_V14 folder should contain Dockerfile, frontend, backend, and render.yaml at its root.
Create a PRIVATE GitHub repository, then push this folder using GitHub Desktop or Git:

    git init
    git add .
    git commit -m "CodeGuard V14 Google sign-in and browser security"
    git branch -M main
    git remote add origin YOUR_GITHUB_REPOSITORY_URL
    git push -u origin main

Replace the repository URL placeholder. .gitignore excludes config.bat, .env, databases, dependencies, and build output. Review the staged files before committing. Do not upload only this ZIP: Render needs the extracted source files. Never commit API keys or private scan databases.

## 2. Create the Render web service
Sign in at https://dashboard.render.com. New → Web Service → connect your GitHub repository.
Use Docker runtime, repository root directory (leave blank), Dockerfile ./Dockerfile, health check /health. Leave Docker Command blank to use the Dockerfile's CMD. Render supplies PORT; do not hardcode a different port.

For a free demo choose Free. SQLite files and all new users/history/source snapshots can disappear on a restart or deploy. Render free services cannot attach a persistent disk, so this is not durable production hosting.
For durable SQLite choose a PAID web service and add a persistent disk mounted at /data. Set CODEGUARD_DB_PATH=/data/codeguard.db. Confirm pricing and storage before choosing a paid plan. The non-root container user must be able to write the mounted directory; inspect logs if permissions prevent startup. No purchase was made by this package.

Set these runtime environment variables (not in GitHub):

| Name | Value |
| --- | --- |
| GROQ_API_KEY | Your working Groq key; secret |
| CODEGUARD_HOST | 0.0.0.0 |
| CODEGUARD_COOKIE_SECURE | 1 |
| CODEGUARD_PRODUCTION | 1 |
| CODEGUARD_ENABLE_DOCS | 0 |
| CODEGUARD_ALLOWED_ORIGINS | Exact HTTPS origin returned by Render, without /app or trailing slash |
| CODEGUARD_ALLOW_SIGNUP | 1 initially; set 0 after creating allowed accounts if this is your private tool |
| GOOGLE_CLIENT_ID | Set after step 3; this is a public OAuth client ID |

Deploy. First verify /health. Open your Render URL with /app/ appended. If the deployment URL wasn't known when creating the service, update CODEGUARD_ALLOWED_ORIGINS to the exact returned origin and redeploy before trying login.
The frontend and backend share the same host. No separate frontend service, VITE_API_URL, custom domain, or CORS wildcard is needed.

## 3. Create Google Identity Services credentials
Open https://console.cloud.google.com. Create/select a project, then open Google Auth Platform (or APIs & Services → Credentials, depending on the console layout).
Configure Branding/Audience/consent information with your application name and contact email. For testing add your own Google account as a test user where required. Publish the consent configuration only after completing Google's requirements for your intended audience.
Create an OAuth client with application type Web application.
In Authorized JavaScript origins add the EXACT Render HTTPS origin (no /app path).
For local tests optionally add http://localhost:5173 and http://127.0.0.1:5173.
Copy the CLIENT ID ending in .apps.googleusercontent.com. Set GOOGLE_CLIENT_ID in Render and redeploy.

This app uses the GIS JavaScript popup button with server ID-token verification, not an authorization-code redirect flow. A client secret and custom redirect URI are not used by this implementation. Never paste a client secret in the frontend.

## 4. Sign in
Open the live /app/ login page. Click the official Sign in with Google button and choose your account.
The server verifies Google's token signature, client audience, issuer, expiry, verified email, and the browser's one-time nonce. Identities are stored by Google's subject ID.
If that email already has a CodeGuard password account, enter its existing password in the login form and try Google again to confirm linking. CodeGuard does not automatically link accounts solely by email.
After linking, you can use Google without the CodeGuard password. Disabling registration prevents creation of new Google accounts but allows existing linked accounts to sign in.

## 5. Acceptance checks
Password and Google login; logout and 24-hour session expiry; ZIP scan; saved report; AI fix preview; PR review; gate policy; rejection of cross-origin browser POSTs; persistent reports after an intentional redeploy if using durable storage.
Live Google credentials, hosted deployment, Docker execution, and browser interaction have not been validated here. Automated Google tests mock the token verifier. Source and identity databases are private data: maintain backups and restrict host access.

## What changed in V14
Browser sessions use HttpOnly cookies, Secure on the production configuration, SameSite=Lax; the frontend no longer keeps the real session token in localStorage. Explicit trusted-Origin checks protect browser writes. Production responses include CSP, HSTS and other headers. Google challenges expire after 10 minutes and cannot be reused. GitHub downloads are capped at 50 MB; uncontrolled Git clone fallback is disabled unless explicitly enabled. Prior password hashing, request limits and account isolation remain.

Current rate limiting is per-process/IP, not a distributed abuse-control service. Use a trusted gateway with shared rate/concurrency controls for a multi-user public launch. Existing legacy AI APIs remain authenticated but do not all require per-request consent. Do not open unrestricted registration on a host with your shared AI key unless you intend that usage.

## Official references
https://developers.google.com/identity/gsi/web/guides/verify-google-id-token
https://developers.google.com/identity/gsi/web/reference/js-reference
https://render.com/docs/docker
https://render.com/docs/disks
https://render.com/docs/free
