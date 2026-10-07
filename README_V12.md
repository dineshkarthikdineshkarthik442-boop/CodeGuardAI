# CodeGuard AI V12 — Pull Request Review and CI/CD Gates

## Upgrade
Stop both old server windows. Extract into a new folder. Copy your working config.bat and backend/codeguard.db into the corresponding locations while the old backend is stopped. Keep a database backup. Run START_ALL.bat and open http://localhost:5173.

## Pull Request Review
Choose PR Review in the sidebar. Enter a public GitHub URL such as https://github.com/owner/repo/pull/123 and click Review Pull Request. The report is saved to your account's history. Inspect changed files, severity, locations, and recommendations; download JSON or HTML.

Only Python files in the PR head are scanned. INTRODUCED means a finding occurs on an added diff line, not a validated comparison against the base commit. Missing patches can cause findings to be classified as existing. Errors or PRs without Python coverage receive REVIEW. CodeGuard does not post comments, merge, or modify GitHub repositories. Existing V11 fix previews and automatic ZIP source remain available; PR fixes require manual source.

## CI/CD Gate
Choose CI/CD Gate. Upload a source ZIP, set minimum score (0–100), allowed high findings and allowed critical findings, then run. A pass requires meeting all limits and no Python syntax errors. Results and policy are saved to history; automatic source loading is available for supported Python files.

Run the included CLI in automation:

    python backend/ci_gate_cli.py project.zip --threshold 80 --max-high 0 --max-critical 0 --json

Exit 0: pass; exit 1: gate failed; exit 2: invalid input/tool failure. The CLI runs local static analysis without an AI key or a running server. A passing rule scan does not guarantee security.

## GitHub Actions example
The example below assumes the CodeGuard backend files are included in your repository at tools/codeguard/backend. Adjust that path for your layout. It packages tracked project files, excluding dependency folders, using git archive.

```yaml
name: CodeGuard Security Gate
on: [push, pull_request]
permissions:
  contents: read
jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.12'
      - run: python -m pip install fastapi
      - run: git archive --format=zip HEAD -o project.zip
      - run: python tools/codeguard/backend/ci_gate_cli.py project.zip --threshold 80 --max-high 0 --max-critical 0 --json
```

This sample is provided for manual setup, not installed into your repository. No uploaded project code is executed. ZIP limits remain 50 MB compressed / 100 MB expanded / 10000 entries / 500 scanned files / 750 KB each. Automatic fix source retention applies to Python files up to 60 KB.

V12 is still a local development release. Public deployment hardening is the proposed V13 milestone.
