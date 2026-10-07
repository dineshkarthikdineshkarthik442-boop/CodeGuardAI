# V14.2: dashboard immediately after Google login

Copy this CodeGuardAI_V14 folder's contents over your existing Git repository folder. Replace matching files; retain your config.bat and database.

Run in your existing repository:
```
git add frontend backend UPDATE_V14_2.md
git commit -m "Fix immediate Google session check after login"
git push origin main
```
Wait for Render to deploy the latest commit. If necessary, use Manual Deploy > Deploy latest commit.
Open https://codeguardai-hcas.onrender.com/app/ and press Ctrl+F5 once to load the new frontend. Future sign-ins should open the dashboard without a manual refresh.

The patch disables fetch caching for API calls, makes the post-login session check use a unique URL, retries transient verification failures up to three times (150ms then 400ms waits), and marks middleware authentication errors no-store. It retains the rounded Google button and verifies the session before displaying protected content. It does not weaken cookie or token validation. Errors now report confirmation failure without assuming cookies are blocked.

Tested: 18 backend tests, 8 frontend render checks, authentication interaction tests (including a first post-login 401 followed by success without refresh), and the production build. Actual Google sign-in on your Render account remains to be tested after deployment. This package is not yet deployed.

No Google Client ID or Render environment changes required. Render Free SQLite persistence limitations still apply.
