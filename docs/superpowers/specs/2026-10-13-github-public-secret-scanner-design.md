# GitHub Public Secret Scanner — Design Specification

## Goal

Build a local, resumable scanner that discovers public GitHub repositories through
search and broad public activity, detects likely exposed API credentials, identifies
the likely provider, and creates private disclosure-ready reports.

The scanner is for responsible notification. It must never persist, print, or send
complete third-party credentials.

## Scope

### In scope

- Search-based public repository discovery.
- Broad best-effort discovery from recent public GitHub activity.
- Bounded historical backfill.
- Scanning repository trees, candidate files, diffs, and selected commit history.
- Provider-specific and generic secret detection.
- Placeholder and masked-value filtering.
- Provider confidence scoring.
- Exact repository, commit, file, line, and permalink evidence.
- Masked previews and keyed fingerprints for deduplication.
- Resumable local queue and scan state.
- JSONL reports and private disclosure-message drafts.
- GitHub rate-limit handling, retry/backoff, and bounded concurrency.

### Explicitly out of scope

- Storing or displaying complete credentials.
- Testing credentials against providers or using them to access services.
- Automatic public issue comments, emails, or direct messages.
- Claiming that a detected credential is active or valid.
- Guaranteed exhaustive crawling of all public GitHub history.
- Scanning private repositories without an explicit future authorization flow.

## User-visible modes

The local CLI supports three modes:

- `search`: execute configurable GitHub code/repository search queries.
- `broad`: discover repositories from recent public activity and bounded backfill.
- `hybrid`: run search discovery and broad discovery through the same queue.

Broad mode is best-effort. It checkpoints discovery cursors and scan progress so a
long-running local process can resume after interruption.

## Proposed architecture

```text
GitHub REST API
  ├─ code/repository search
  ├─ recent public events
  ├─ repository metadata and trees
  ├─ blob/content fetches
  └─ commit metadata/diffs
          ↓
Discovery adapters → SQLite queue/checkpoints → bounded worker pool
                                      ↓
                              candidate extraction
                                      ↓
                    provider rules + generic secret rules
                                      ↓
                    filters/scoring/masking/fingerprinting
                                      ↓
                      JSONL findings + disclosure drafts
```

The GitHub client is the only network boundary. Scanner rules operate on response
content in memory. Source files, API responses, and complete candidate values are
never written to disk.

## Components

### Configuration and CLI

Use Python 3.11+ and the standard library where practical. Read a TOML config file
with `tomllib`; read credentials only from environment variables:

- `GITHUB_TOKEN`: optional for public endpoints, strongly recommended for useful
  rate limits.
- `SCANNER_FINGERPRINT_KEY`: required for stable keyed finding fingerprints.

CLI commands:

- `scan search`
- `scan broad`
- `scan hybrid`
- `scan repo OWNER/REPO`
- `report list`
- `report draft FINDING_ID`

The first MVP may expose the commands through `python -m scanner` rather than a
packaged console entry point.

### GitHub client

Use HTTPS REST requests with:

- explicit timeouts;
- bounded response sizes;
- `Accept` and API version headers;
- token authentication from the environment;
- retry/backoff for transient failures and rate limits;
- no response-body logging;
- response parsing that keeps secrets in memory only.

The client must honor `Retry-After` and rate-limit headers. It must not attempt
credential validation or call arbitrary provider endpoints.

### Discovery adapters

Search discovery builds queries from configured file names, assignment names,
provider prefixes, languages, and date filters. Results are normalized to a
repository, ref/commit, path, and URL before entering the queue.

Broad discovery consumes recent public activity, extracts repository identities,
and optionally performs a bounded historical backfill. Repository identities are
deduplicated before scanning.

### Repository scanner

For each queued repository, fetch metadata and a recursive tree when available.
Only candidate text files are fetched. Candidate selection uses path and extension
allowlists with size limits; binaries, vendored directories, generated artifacts,
and large files are skipped by default.

For history scanning, fetch only selected commit metadata/diffs and process patches
in memory. The scanner records the exact commit SHA and source URL for evidence.

### Detection engine

Detection has two layers:

1. Provider rules for recognizable formats, including common cloud, payment,
   messaging, source-control, AI, and communications providers.
2. Generic rules for assignments such as `API_KEY`, `TOKEN`, `SECRET`, database
   URLs, bearer tokens, and private-key blocks.

Each candidate receives a score based on provider match, variable-name context,
entropy, file context, and placeholder checks. Findings below the configured
threshold are discarded or marked low confidence.

The engine must recognize and discard examples such as placeholders, environment
variable references, obvious test strings, masked values, and documentation-only
snippets where confidence is low.

### Safe finding model

Persist only:

- stable finding ID;
- provider and confidence;
- repository owner/name;
- branch/ref and commit SHA;
- file path, line number, and commit permalink;
- masked preview showing only a short prefix and suffix;
- keyed HMAC fingerprint;
- rule IDs and evidence categories;
- discovery time and status.

The complete candidate is never included in a finding, log, exception, report,
database, filename, or disclosure draft. The process discards it after masking and
fingerprinting.

### State and reports

SQLite stores queue state, discovery checkpoints, scan status, and safe finding
metadata. JSONL is used for append-only report export. Disclosure drafts contain
the provider, masked evidence, exact permalink, impact wording, and rotation steps.

Default output directories are local and gitignored. No raw GitHub response or
repository checkout is stored.

## Configuration surface

The initial config supports:

- mode: `search`, `broad`, or `hybrid`;
- search query templates and result limits;
- supported languages and file/path filters;
- recent-activity window;
- historical backfill window and maximum repositories;
- worker count and request timeout;
- maximum file size and maximum commits per repository;
- report directory and disclosure template;
- confidence threshold;
- owner/repository denylist and exclusion patterns.

Defaults are conservative and bounded. A user must explicitly raise limits for
larger crawls.

## Error handling and abuse resistance

- Never retry indefinitely; use capped exponential backoff.
- Stop or pause when the GitHub rate limit is exhausted.
- Treat repository names, paths, commit messages, and fetched text as untrusted.
- Escape all report output; do not render raw content as HTML.
- Do not follow arbitrary URLs discovered in repository content.
- Do not execute repository code, workflows, hooks, or build scripts.
- Do not log request headers or response bodies.
- Keep reports private and redact before any notification workflow.

## Disclosure workflow

The MVP generates a private draft for human review. It recommends contacting the
repository owner through an appropriate private channel and includes the exact
commit permalink so the owner can inspect the full value directly on GitHub.

It does not automatically create public issues or send messages. It labels results
as “publicly exposed; validity not tested” and recommends immediate revocation,
replacement, and history cleanup.

## Verification plan

- Unit tests for masking, placeholder detection, HMAC fingerprints, provider rules,
  generic rules, line mapping, and disclosure rendering.
- HTTP-client tests using mocked responses for pagination, retries, rate limits, and
  malformed API responses.
- Integration tests with local fixtures that contain fake, clearly nonfunctional
  credentials and verify that only safe finding fields are persisted.
- A regression test that searches every generated artifact and log for the fixture
  secret and fails if the full value appears.
- CLI smoke tests for search, broad, hybrid, resume, and report generation.

## Acceptance criteria

1. A local user can configure a GitHub token through the environment and run a
   bounded search scan.
2. The user can select search, broad, or hybrid mode in configuration.
3. Broad mode discovers repositories from recent public activity and performs the
   configured bounded backfill.
4. A recognized fake provider key produces a provider label, masked preview, exact
   file/line, commit SHA, and GitHub permalink.
5. Placeholders and masked examples are excluded or marked low confidence.
6. SQLite, JSONL, logs, and disclosure drafts contain no complete candidate value.
7. Rate limits and transient failures pause/retry without losing queue state.
8. The scanner never executes repository code or validates discovered credentials.
9. Tests prove the safe-storage invariant.
