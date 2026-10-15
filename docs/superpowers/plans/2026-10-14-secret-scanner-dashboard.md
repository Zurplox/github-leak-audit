# GitHub Public Secret Scanner Dashboard Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a loopback-only browser dashboard that runs the existing scanner and clearly shows each detected API/provider, exact file path, line, and immutable GitHub source link.

**Architecture:** Extend `ScanQueue` with safe read-only summaries, add a `ScanManager` for one cooperative background run, and expose it through a standard-library `ThreadingHTTPServer`. Serve dependency-free static assets that poll the JSON API; keep the CLI and scanner engine unchanged. Add a Windows launcher that starts the server from the repository root.

**Tech Stack:** Python 3.11+, `http.server`, `threading`, `json`, `urllib`, SQLite, HTML/CSS/JavaScript, `unittest`; no runtime third-party dependencies.

**Spec:** `docs/superpowers/specs/2026-10-14-secret-scanner-dashboard-design.md`

## Global Constraints

- Bind the dashboard to `127.0.0.1` only.
- Never send complete credentials, source text, request bodies, headers, or raw GitHub responses to the browser.
- Reuse `GitHubClient`, discovery adapters, `ScanQueue`, `scan_queue_item`, and report writers.
- Keep `GITHUB_TOKEN` and `SCANNER_FINGERPRINT_KEY` in the process environment; never collect them in the UI.
- Support search, broad, hybrid, and targeted repository modes.
- Keep pause and stop cooperative; do not kill threads or interrupt socket calls.
- Preserve the existing CLI and standard-library-only runtime.
- Escape untrusted values as JSON/text, not HTML.

## Review Focus

- A second start while a scan is active must return `409 CONFLICT` and never create a second worker; test manager/API state.
- Invalid JSON, unknown fields, invalid modes, malformed repositories, and oversized pagination must return structured `422` errors; test the HTTP boundary.
- Queue and finding endpoints must paginate deterministically and never include `Candidate.value`; test a synthetic complete secret across every response.
- Pause/stop during an in-flight item must finish that item, then prevent further work; test cooperative events without timing sleeps where possible.
- Hostile repository metadata must render as text in the browser assets; test the response and static HTML for safe DOM-writing patterns.

---

### Task 1: Safe dashboard data access

**Files:**
- Modify: `scanner/storage.py`
- Test: `tests/test_storage.py`
- Create: `scanner/dashboard_data.py`
- Test: `tests/test_dashboard_data.py`

**Interfaces:**
- `ScanQueue.queue_counts() -> dict[str, int]` returns only counts for `pending`, `in_progress`, `done`, and `failed`.
- `ScanQueue.list_findings_page(page: int, page_size: int, provider: str | None = None) -> tuple[list[FindingRecord], int]` returns safe records and total count.
- `dashboard_data.findings_payload(findings, page, page_size, total) -> dict` returns JSON-ready safe dictionaries.
- `dashboard_data.summary_payload(findings) -> dict` returns provider, confidence, status, and UTC-date counts.

- [ ] Write failing tests for queue counts, deterministic pagination, exact provider filtering, and summary buckets.
- [ ] Run `python -m unittest tests.test_storage tests.test_dashboard_data -v` and confirm failure.
- [ ] Implement parameterized SQLite reads and pure safe transformation functions; reject invalid page/page-size values.
- [ ] Run the focused tests and verify they pass.

### Task 2: Scan manager and HTTP API

**Files:**
- Create: `scanner/scan_manager.py`
- Create: `scanner/dashboard.py`
- Test: `tests/test_scan_manager.py`
- Test: `tests/test_dashboard.py`

**Interfaces:**
- `ScanManager(config: Config).start(mode: str, repository: str | None, once: bool) -> dict`.
- `ScanManager.pause() -> dict`, `ScanManager.stop() -> dict`, and `ScanManager.status() -> dict`.
- `DashboardServer(host: str, port: int, manager: ScanManager, config: Config)` serves `/`, `/static/*`, `/api/status`, `/api/findings`, `/api/summary`, `/api/scans`, `/api/scans/pause`, `/api/scans/stop`, and `/api/disclosures/{finding_id}`.
- Errors use `{ "error": { "code": str, "message": str, "details": object } }` with `409`, `404`, `422`, and `503` as specified.

- [ ] Write failing tests for manager state transitions, start conflict, repo validation, once behavior, safe status counters, API pagination/filtering, disclosure lookup, and safe error responses.
- [ ] Run `python -m unittest tests.test_scan_manager tests.test_dashboard -v` and confirm failure.
- [ ] Implement one daemon worker with lock/events, reuse CLI scan ordering, sanitize errors, and keep all HTTP responses safe.
- [ ] Run the focused tests and verify they pass.

### Task 3: Dashboard UI and launcher

**Files:**
- Create: `scanner/dashboard_assets/index.html`
- Create: `scanner/dashboard_assets/app.js`
- Create: `scanner/dashboard_assets/styles.css`
- Create: `github-public-secret-scanner/run-dashboard.cmd`
- Test: `tests/test_dashboard_assets.py`

**Interfaces:**
- Static root renders a labelled control panel and prominent findings table.
- Each finding row displays provider/API type, repository, file path, line, commit, masked preview, confidence/status, and an `Open source` link using the API permalink.
- JavaScript polls safe endpoints and writes untrusted values with `textContent`/DOM properties, never `innerHTML` for repository data.

- [ ] Write failing asset tests for required labels, API paths, source-link column, masked-only wording, and launcher safeguards.
- [ ] Run `python -m unittest tests.test_dashboard_assets -v` and confirm failure.
- [ ] Implement semantic responsive HTML, accessible controls, loading/empty/error states, safe DOM rendering, and the launcher’s Python/environment checks.
- [ ] Run the asset tests and inspect the served root response.

### Task 4: Integrated verification and browser run

**Files:**
- Modify: `README.md`
- Modify: `github-public-secret-scanner/verification-log.md`
- Test: `tests/test_end_to_end.py`

- [ ] Add an end-to-end dashboard test that starts from a fake public repository, verifies file/line/permalink fields, and searches all JSON/draft/dashboard responses for the complete synthetic value.
- [ ] Run `PYTHONDONTWRITEBYTECODE=1 python -m unittest discover -v`.
- [ ] Run `python -m compileall scanner tests` and `python -m scanner --help`.
- [ ] Start the local server on an available loopback port, check `/`, `/api/status`, `/api/findings`, and `/api/summary`, then open it for interactive browser testing.
- [ ] Record the actual commands and outcomes in `github-public-secret-scanner/verification-log.md`.

## Checkpoint

- [ ] The dashboard shows real scanner findings with exact file and source links.
- [ ] No complete synthetic credential appears in any persisted or browser-visible artifact.
- [ ] Existing 51-test baseline remains passing plus dashboard tests.
- [ ] The local dashboard is reachable and usable through the launcher/server flow.
