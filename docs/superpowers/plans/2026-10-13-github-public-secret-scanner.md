# GitHub Public Secret Scanner Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a local Python CLI that discovers public GitHub code through search and broad activity, detects likely exposed API credentials, identifies providers, and writes only safe masked disclosure reports.

**Architecture:** A standard-library Python package separates GitHub transport, discovery, detection, safe finding persistence, and reporting. GitHub responses are processed in memory; SQLite stores queue/checkpoint metadata and safe findings; JSONL and Markdown drafts contain no complete candidate values.

**Tech Stack:** Python 3.11+, `urllib`, `argparse`, `sqlite3`, `tomllib`, `unittest`; no runtime third-party dependencies.

**Spec:** `docs/superpowers/specs/2026-10-13-github-public-secret-scanner-design.md`

## Global Constraints

- Use Python 3.11+ and the standard library where practical.
- `GITHUB_TOKEN` is read only from the environment.
- `SCANNER_FINGERPRINT_KEY` is required for stable keyed finding fingerprints.
- Complete credentials are never included in findings, logs, exceptions, reports, databases, filenames, or disclosure drafts.
- The scanner never validates discovered credentials or calls arbitrary provider endpoints.
- The scanner never executes repository code, workflows, hooks, or build scripts.
- Broad crawling is best-effort, bounded, resumable, and rate-limit aware.
- Default output directories are local and gitignored; no raw repository checkout or GitHub response is stored.
- The MVP generates private disclosure drafts for human review and does not send messages or create public issues.

## Review Focus

- A candidate containing a newline, Unicode, or delimiter cannot break JSONL or Markdown output; test multiline and control-character handling in `tests/test_reports.py`.
- A placeholder or masked example must not become a finding; test representative placeholders in `tests/test_detection.py`.
- A rate-limit response must pause/retry without losing queue state; test `Retry-After` and remaining-limit handling in `tests/test_github_client.py`.
- A malformed or hostile GitHub response must not crash the process or trigger arbitrary fetches; test schema validation and URL handling in `tests/test_github_client.py`.
- An interrupted broad crawl must resume without duplicate work or unsafe state; test checkpoint and queue transitions in `tests/test_storage.py`.

---

### Task 1: Project foundation, configuration, and safe local state

**Files:**
- Create: `pyproject.toml`
- Create: `.gitignore`
- Create: `scanner/__init__.py`
- Create: `scanner/__main__.py`
- Create: `scanner/config.py`
- Create: `scanner/models.py`
- Create: `scanner/storage.py`
- Create: `config.example.toml`
- Test: `tests/test_config.py`
- Test: `tests/test_storage.py`

**Interfaces:**
- `Config.load(path: Path) -> Config`
- `Config.from_environment() -> RuntimeSecrets`
- `ScanQueue.enqueue(item: QueueItem) -> bool`
- `ScanQueue.claim(limit: int) -> list[QueueItem]`
- `ScanQueue.complete(item_id: str, status: str) -> None`
- `ScanQueue.checkpoint(name: str, value: str) -> None`
- `ScanQueue.get_checkpoint(name: str) -> str | None`
- `FindingRecord` contains only safe, serializable fields defined by the spec.

- [ ] **Step 1: Write failing tests** for TOML defaults, invalid values, missing fingerprint key, queue deduplication, claim/complete transitions, and checkpoint persistence.
- [ ] **Step 2: Run `python -m unittest tests.test_config tests.test_storage -v`** and confirm the new interfaces fail before implementation.
- [ ] **Step 3: Implement typed configuration and SQLite state** with conservative defaults, WAL mode, parameterized SQL, and a schema version.
- [ ] **Step 4: Implement `FindingRecord` and queue models** without any raw-secret field.
- [ ] **Step 5: Run the focused tests** and verify PASS.

### Task 2: Detection, provider identification, masking, and fingerprints

**Files:**
- Create: `scanner/redaction.py`
- Create: `scanner/rules.py`
- Create: `scanner/detector.py`
- Test: `tests/test_redaction.py`
- Test: `tests/test_detection.py`

**Interfaces:**
- `mask_secret(value: str, prefix: int = 4, suffix: int = 4) -> str`
- `fingerprint_secret(value: str, key: bytes) -> str`
- `is_placeholder(value: str) -> bool`
- `detect_candidates(text: str, path: str, threshold: int) -> list[Candidate]`
- `Candidate.to_safe_finding(context: FindingContext, key: bytes) -> FindingRecord`

- [ ] **Step 1: Write failing tests** for provider patterns, generic assignments, entropy scoring, placeholder rejection, masked previews, keyed fingerprints, and exact line numbers.
- [ ] **Step 2: Run `python -m unittest tests.test_redaction tests.test_detection -v`** and confirm failure.
- [ ] **Step 3: Implement redaction and fingerprinting** so only a masked preview and HMAC-SHA256 digest leave the detection layer.
- [ ] **Step 4: Implement provider rules** for representative cloud, payment, messaging, source-control, AI, and communications formats, plus generic API key/token/password assignments.
- [ ] **Step 5: Implement placeholder filtering and confidence scoring**; discard low-confidence matches below the configured threshold.
- [ ] **Step 6: Run focused tests** and add a regression assertion that the complete fixture secret is absent from every safe finding representation.

### Task 3: GitHub transport and discovery adapters

**Files:**
- Create: `scanner/github_client.py`
- Create: `scanner/discovery.py`
- Test: `tests/test_github_client.py`
- Test: `tests/test_discovery.py`

**Interfaces:**
- `GitHubClient.request(method: str, path: str, params: Mapping[str, str] | None = None) -> object`
- `GitHubClient.search_code(query: str, page: int = 1) -> SearchPage`
- `GitHubClient.list_public_events(cursor: str | None = None) -> EventPage`
- `GitHubClient.repository(owner: str, name: str) -> Repository`
- `GitHubClient.tree(owner: str, name: str, ref: str) -> list[TreeEntry]`
- `GitHubClient.content(owner: str, name: str, path: str, ref: str) -> str`
- `GitHubClient.commits(owner: str, name: str, since: str | None = None) -> list[CommitSummary]`
- `SearchDiscovery.discover() -> Iterable[QueueItem]`
- `BroadDiscovery.discover() -> Iterable[QueueItem]`

- [ ] **Step 1: Write mocked-transport tests** for auth headers, timeout, pagination, malformed payloads, retryable failures, `Retry-After`, and exhausted rate limits.
- [ ] **Step 2: Run `python -m unittest tests.test_github_client tests.test_discovery -v`** and confirm failure.
- [ ] **Step 3: Implement an injectable `urllib` transport** with bounded response size, JSON schema checks, no body logging, capped exponential backoff, and rate-limit pause behavior.
- [ ] **Step 4: Implement search discovery** with configurable query templates and normalized repository/path/ref records.
- [ ] **Step 5: Implement broad discovery** from recent public activity plus bounded historical repository/commit discovery, using checkpoints and queue deduplication.
- [ ] **Step 6: Run focused tests** and verify hostile response fields cannot cause arbitrary URL fetches.

### Task 4: Repository scanning and safe report generation

**Files:**
- Create: `scanner/repository_scan.py`
- Create: `scanner/reports.py`
- Create: `scanner/templates/disclosure.md`
- Test: `tests/test_repository_scan.py`
- Test: `tests/test_reports.py`

**Interfaces:**
- `select_candidate_files(tree: list[TreeEntry], config: Config) -> list[TreeEntry]`
- `scan_queue_item(client: GitHubClient, item: QueueItem, detector: Detector) -> list[FindingRecord]`
- `write_jsonl(findings: Iterable[FindingRecord], path: Path) -> int`
- `render_disclosure(finding: FindingRecord, template: str) -> str`
- `write_disclosure_draft(finding: FindingRecord, directory: Path) -> Path`

- [ ] **Step 1: Write tests** for text-file/path selection, size limits, binary skipping, content fetches, exact line/permalink construction, JSONL escaping, and disclosure rendering.
- [ ] **Step 2: Run `python -m unittest tests.test_repository_scan tests.test_reports -v`** and confirm failure.
- [ ] **Step 3: Implement in-memory candidate scanning** with no checkout and no raw-response persistence.
- [ ] **Step 4: Convert detector candidates to safe `FindingRecord` values** and persist only safe fields to SQLite/JSONL.
- [ ] **Step 5: Render private disclosure drafts** with provider, confidence, masked preview, repository, exact commit/file/line link, “validity not tested,” and rotation/remediation guidance.
- [ ] **Step 6: Run focused tests** and scan all generated artifacts for the fixture secret, failing if it appears.

### Task 5: CLI orchestration, example configuration, and user documentation

**Files:**
- Create: `scanner/cli.py`
- Create: `README.md`
- Modify: `scanner/__main__.py`
- Modify: `config.example.toml`
- Test: `tests/test_cli.py`

**Interfaces:**
- `main(argv: Sequence[str] | None = None) -> int`
- Commands: `scan search`, `scan broad`, `scan hybrid`, `scan repo OWNER/REPO`, `report list`, and `report draft FINDING_ID`.

- [ ] **Step 1: Write CLI smoke tests** using a fake GitHub client for all modes, resume behavior, report listing, and draft generation.
- [ ] **Step 2: Run `python -m unittest tests.test_cli -v`** and confirm failure.
- [ ] **Step 3: Implement CLI orchestration** that loads config, checks required environment variables, initializes state, runs discovery, scans bounded queue work, and writes safe reports.
- [ ] **Step 4: Add `config.example.toml`, `.gitignore`, and README instructions** covering Python version, environment variables, local-only outputs, rate limits, responsible disclosure, and the fact that validity is never tested.
- [ ] **Step 5: Run the complete suite with `python -m unittest discover -v`** and verify all tests pass.

### Task 6: End-to-end verification and artifact audit

**Files:**
- Create: `tests/fixtures/fake_public_repo.env`
- Create: `tests/test_end_to_end.py`

- [ ] **Step 1: Create a fixture** containing a clearly fake provider-shaped value, placeholders, masked examples, and unrelated high-entropy text.
- [ ] **Step 2: Write an end-to-end test** that runs the scanner against a mocked GitHub API and checks provider identification, masked output, permalink, queue resume, and disclosure draft fields.
- [ ] **Step 3: Run `python -m unittest discover -v`**.
- [ ] **Step 4: Run a repository-wide artifact audit** that searches generated output, logs, SQLite-exported fields, and reports for the fixture’s complete value; expected result is zero matches.
- [ ] **Step 5: Run `python -m compileall scanner tests`** and a CLI help smoke test with `python -m scanner --help`.
- [ ] **Step 6: Record actual commands and results in the final handoff.**

## Plan self-review

- **Spec coverage:** discovery modes, bounded backfill, rate limits, safe detection, keyed fingerprints, SQLite state, JSONL reports, disclosure drafts, CLI configuration, and safe-storage verification each map to a task above.
- **Step scan:** each task has a failing-test phase, a focused implementation boundary, and a directly runnable verification command.
- **Type consistency:** later tasks consume `QueueItem`, `FindingRecord`, `Config`, and `GitHubClient` interfaces introduced earlier.
- **Review focus:** multiline values, placeholders, rate limits, hostile responses, and interruption/resume behavior each have an owning test.
- **Proportion:** the plan keeps implementation choices at interface and test level; algorithm bodies remain for the implementer.
