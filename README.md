# GitHub Public Secret Scanner

Local, resumable scanning of **public GitHub code** for likely exposed API
credentials. The scanner supports search-based discovery, broad recent-activity
discovery, bounded repository backfill, and a hybrid mode.

## Safety model

The scanner identifies likely providers and writes exact GitHub source links, file
paths, line numbers, masked previews, and keyed fingerprints. It never writes or
prints complete third-party credentials, tests whether a credential works, follows
URLs found in source, executes repository code, or automatically contacts owners.

Use the exact source link in the private disclosure draft so the repository owner
can inspect the value directly on GitHub and rotate it.

## Requirements

- Python 3.11 or newer
- A GitHub token is recommended for rate limits. Set it locally as `GITHUB_TOKEN`.
- Set a local fingerprint key as `SCANNER_FINGERPRINT_KEY`.

Do not put either value in `config.toml`, source code, reports, or shell history.

## Quick start

```powershell
$env:GITHUB_TOKEN = "<your-local-token>"
$env:SCANNER_FINGERPRINT_KEY = "<local-deduplication-key>"
Copy-Item config.example.toml config.toml
python -m scanner --config config.toml scan search
```

Modes:

```text
scan search       GitHub code-search queries
scan broad        recent public events plus bounded repository backfill
scan hybrid       both discovery paths
scan repo A/B     one public repository
report list       safe JSON findings
report draft ID   write a private disclosure draft
```

Reports are written under the configured output directory. The state database is
resumable and stores only safe finding metadata. Defaults are deliberately bounded;
increase limits in the TOML configuration only when you understand GitHub rate
limits and local resource use. Set `broad.continuous = true` to keep polling local
public activity; use `scan broad --once` for a single pass.

## Disclosure workflow

Review each generated Markdown draft privately. It includes provider confidence,
masked evidence, the exact commit/file/line permalink, and rotation guidance. It
states that credential validity was not tested. Do not paste credentials into a
public issue or redistribute them.

## Tests

```powershell
$env:PYTHONDONTWRITEBYTECODE = "1"
python -m unittest discover -v
python -m compileall scanner tests
python -m scanner --help
```
