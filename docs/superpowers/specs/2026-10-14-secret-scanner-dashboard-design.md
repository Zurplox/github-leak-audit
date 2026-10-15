# GitHub Public Secret Scanner — Local Dashboard Design

## Goal

Add a local browser dashboard that lets an operator run and observe the existing
GitHub public-code scanner in real time. The dashboard is a presentation and
control layer over the current scanner modules; it must not weaken the scanner's
safe-storage guarantees or add a second scanning implementation.

## User outcome

An operator can double-click a Windows launcher, open a browser dashboard on
`127.0.0.1`, choose a bounded scan mode, start/pause/stop a run, and see the
actual scan results in a clear findings table. Each result identifies the
detected API/provider, repository, exact file path, line number, commit, masked
preview, and a clickable exact GitHub source link, alongside queue progress,
provider summaries, and links to private disclosure drafts. The dashboard never
displays complete credentials and never asks for tokens in the browser.

## Scope

### In scope

- A standard-library Python HTTP server bound to loopback only.
- A background scan manager that reuses `GitHubClient`, discovery adapters,
  `ScanQueue`, repository scanning, and report writers.
- Safe JSON API endpoints for status, findings, summaries, scan lifecycle, and
  disclosure drafts.
- A dependency-free responsive HTML/CSS/JavaScript dashboard.
- Empty, loading, paused, rate-limited, failed, and completed states.
- A Windows `run-dashboard.cmd` launcher that starts the local server and opens
  the dashboard.
- Unit/integration tests for API validation, lifecycle behavior, safe response
  fields, and the launcher/server smoke path.

### Explicitly out of scope

- A standalone bundled `.exe` or Python packaging/distribution system.
- Browser-side GitHub credentials, localStorage tokens, or credential forms.
- Full-key reveal, credential validation, provider API calls, or owner contact.
- Remote binding, authentication, public hosting, WebSockets, or a frontend
  dependency/toolchain.
- Replacing the existing CLI.

## Safety and runtime boundaries

- The server binds to `127.0.0.1` by default and rejects non-loopback bind
  addresses unless a future explicit feature changes the contract.
- `GITHUB_TOKEN` and `SCANNER_FINGERPRINT_KEY` are read by the Python process
  from its environment. The browser receives only status and safe finding data.
- The API never serializes `Candidate.value`; only fields from `FindingRecord`
  may cross the boundary.
- Repository-controlled strings are JSON encoded by the server and escaped by
  the browser renderer. The UI inserts untrusted values as text, not HTML.
- Pause and stop are cooperative: an in-flight HTTP request is allowed to
  finish, then no new queue item or continuous polling pass is started.
- A server restart relies on `ScanQueue`'s existing recovery behavior to requeue
  interrupted work. No raw source response or checkout is introduced.

## Architecture

```text
Browser
  │ loopback HTTP / JSON
  ▼
DashboardServer (standard library)
  ├─ static dashboard assets
  ├─ request validation and safe response shaping
  └─ ScanManager (one background worker)
       ├─ Config + RuntimeSecrets
       ├─ GitHubClient
       ├─ SearchDiscovery / BroadDiscovery
       ├─ ScanQueue
       ├─ scan_queue_item
       └─ reports.write_jsonl / write_disclosure_draft
```

There is at most one active scan manager per dashboard process. A second start
request returns a structured conflict response instead of starting concurrent
scans against the same SQLite database.

## API contract

All JSON errors use one shape:

```json
{
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "mode must be search, broad, hybrid, or repo",
    "details": {}
  }
}
```

### `GET /api/status`

Returns the current manager state and safe queue counters:

```json
{
  "status": "idle|running|paused|rate_limited|completed|failed|stopped",
  "mode": "search|broad|hybrid|repo|null",
  "repository": "OWNER/REPO|null",
  "startedAt": "ISO-8601|null",
  "updatedAt": "ISO-8601|null",
  "lastError": "safe message|null",
  "counters": {
    "queued": 0,
    "inProgress": 0,
    "done": 0,
    "failed": 0,
    "findings": 0,
    "requests": 0
  },
  "continuous": false,
  "pollIntervalSeconds": 300
}
```

`lastError` is a local, sanitized exception message and never contains an HTTP
response body, request header, source text, or candidate value.

### `GET /api/findings?page=1&pageSize=50&provider=...`

Returns paginated safe `FindingRecord` dictionaries. `pageSize` is bounded to
1–100. The optional provider filter is exact and case-insensitive. The response
contains `data`, `page`, `pageSize`, and `totalItems`.

### `GET /api/summary`

Returns counts derived from safe stored findings: total findings, provider
distribution, confidence buckets, status distribution, and findings grouped by
UTC discovery date. No source text is returned.

### `POST /api/scans`

Starts one scan. The body is JSON and accepts:

```json
{
  "mode": "search|broad|hybrid|repo",
  "repository": "OWNER/REPO",
  "once": true
}
```

`repository` is required only for `repo`. Unknown fields are rejected. If a run
is active, the endpoint returns `409 CONFLICT`; invalid input returns `422
VALIDATION_ERROR`; missing environment configuration returns `503
CONFIGURATION_ERROR`.

### `POST /api/scans/pause`

Requests cooperative pause. It is idempotent for an already paused or idle
manager and returns the current status.

### `POST /api/scans/stop`

Requests cooperative stop. It is idempotent for an already stopped, completed,
failed, or idle manager and returns the current status.

### `GET /api/disclosures/{finding_id}`

Validates a 64-character lowercase hexadecimal finding ID, loads the existing
safe finding, renders the existing private Markdown draft, and returns the draft
content plus its local path. A missing finding is `404 NOT_FOUND`. The draft is
safe because it contains only masked evidence and an exact GitHub source link.

## Scan manager behavior

The manager owns a single daemon worker thread and a small state object protected
by a lock. It uses `threading.Event` for pause and stop requests; it does not
kill threads or interrupt socket operations. The worker follows the same order as
the CLI:

1. Discover queue items for the selected mode.
2. Enqueue them with existing deduplication.
3. Claim bounded batches using configured concurrency as the batch size.
4. Scan items, persist safe findings, append JSONL, and write drafts.
5. Mark queue items done, pending on rate limits, or failed on terminal errors.
6. For continuous broad/hybrid runs, wait for the configured poll interval
   unless `once` or stop was requested.

The dashboard's configured concurrency remains the scanner's existing bounded
batch limit; this first version does not introduce a second thread pool.

## UI design

The page is a compact operations dashboard rather than a marketing page:

- Header: product name, loopback-only badge, current scan state, last update.
- Control panel: mode select, repository input shown only for repo mode, run-once
  checkbox, start/pause/stop buttons, and an inline validation/error region.
- Metric row: safe findings, queued items, completed items, failed items, and
  request count.
- Main content: a prominent findings table where every scanned result shows the
  provider/API type, confidence, repository, exact file path, line number,
  commit SHA, masked preview, status, and a clickable **Open source** link to
  the immutable GitHub commit/file/line permalink. The table supports paging and
  provider filtering so the source of each result can be found quickly.
- Secondary content: provider distribution, confidence distribution, and daily
  finding counts rendered with semantic bars rather than a chart dependency.
- Draft panel: a safe Markdown preview/path for a selected finding and a link to
  the exact GitHub source.

The UI uses semantic headings, labelled form controls, visible focus styles,
keyboard-accessible buttons, status text that is not color-only, responsive table
fallbacks for narrow screens, and explicit empty/loading/error states. It polls
`/api/status`, `/api/findings`, and `/api/summary` at a modest interval while a
run is active and stops polling when idle.

## Launcher

`github-public-secret-scanner/run-dashboard.cmd` will:

1. Resolve the repository root from the script location.
2. Check that Python 3.11+ is available.
3. Create `config.toml` from `config.example.toml` if it does not exist.
4. Check that `SCANNER_FINGERPRINT_KEY` exists without echoing its value.
5. Start `python -m scanner.dashboard --config config.toml --open` from the
   repository root.

It will not create or persist secrets. `GITHUB_TOKEN` remains optional for the
   existing public API client, while the fingerprint key remains required.

## Verification plan

- Unit tests for queue summary and safe pagination/summary transforms.
- API tests using an in-process fake client/manager for status, validation,
  conflict, not-found, and safe-field behavior.
- Lifecycle tests for start, cooperative pause, stop, restart recovery, and
  continuous `once` behavior.
- A regression test that places a complete synthetic candidate in scanner output
  and asserts it is absent from every dashboard JSON response and draft payload.
- Static asset smoke test that serves the dashboard and checks the root page,
  script, and stylesheet are reachable.
- Existing suite, `python -m compileall scanner tests`, and
  `python -m scanner --help` remain passing.
- Manual browser check on loopback at 320px, 768px, 1024px, and 1440px widths,
  including keyboard navigation and the empty/loading/error states.

## Acceptance criteria

1. Double-clicking the launcher opens a local dashboard without npm or external
   frontend dependencies.
2. An operator can start search, broad, hybrid, and targeted repository scans
   from the dashboard using the existing scanner engine.
3. Every detected result is visible in a paginated findings table with its
   provider/API type, repository, exact file path, line number, commit, masked
   preview, and clickable immutable GitHub source link.
4. Start conflicts, invalid input, missing configuration, rate limits, failures,
   pause, stop, completion, and empty data show clear states.
5. Findings, counters, summaries, and drafts are read from real local state and
   contain only safe fields; no complete candidate reaches the browser.
6. The dashboard is loopback-only, keyboard usable, responsive, and does not
   expose secrets through browser storage or source HTML.
7. The existing CLI remains available and all automated checks pass.
