"""Command-line orchestration for local safe scans."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
import time

from .config import Config, ConfigError
from .discovery import BroadDiscovery, SearchDiscovery
from .github_client import AuthenticationError, GitHubClient, GitHubClientError, RateLimitError
from .models import QueueItem
from .reports import write_disclosure_draft, write_jsonl
from .repository_scan import scan_queue_item
from .storage import ScanQueue


def main(argv=None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    try:
        config = Config.load(Path(args.config))
        if args.command == "report":
            return _report_command(config, args)
        secrets = Config.from_environment()
        client = GitHubClient(secrets.github_token, max_file_bytes=config.scan.max_file_size,
                              max_tree_entries=config.scan.max_tree_entries)
        return _scan_command(config, secrets.fingerprint_key, client, args)
    except (ConfigError, GitHubClientError, ValueError, OSError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Scan public GitHub code for exposed credentials safely.")
    parser.add_argument("--config", default="config.toml", help="TOML configuration path")
    commands = parser.add_subparsers(dest="command", required=True)

    scan = commands.add_parser("scan", help="discover and scan public repositories")
    scan.add_argument("mode", choices=("search", "broad", "hybrid", "repo"))
    scan.add_argument("repository", nargs="?", help="OWNER/REPO for repo mode")
    scan.add_argument("--once", action="store_true", help="run one pass even when broad mode is continuous")

    report = commands.add_parser("report", help="list findings or create a safe private draft")
    report.add_argument("action", choices=("list", "draft"))
    report.add_argument("finding_id", nargs="?")
    return parser


def _scan_command(config, fingerprint_key, client, args) -> int:
    queue = ScanQueue(config.reports.state_database)
    try:
        findings_path = config.reports.output_directory / "findings.jsonl"
        drafts_directory = config.reports.output_directory / "drafts"
        while True:
            if args.mode == "repo":
                if not args.repository or args.repository.count("/") != 1:
                    raise ValueError("repo mode requires OWNER/REPO")
                owner, name = args.repository.split("/", 1)
                repository = client.repository(owner, name)
                items = [QueueItem(repository.full_name, repository.default_branch, "")]
            else:
                items = []
                if args.mode in {"search", "hybrid"}:
                    items.extend(SearchDiscovery(client, config.search).discover())
                if args.mode in {"broad", "hybrid"}:
                    items.extend(BroadDiscovery(client, config.broad).discover())

            for item in items:
                queue.enqueue(item)
            total = 0
            while True:
                batch = queue.claim(config.broad.max_concurrent_scans)
                if not batch:
                    break
                for item in batch:
                    try:
                        findings = scan_queue_item(client, item, config, fingerprint_key)
                        new_findings = [finding for finding in findings if queue.save_finding(finding)]
                        write_jsonl(new_findings, findings_path)
                        for finding in new_findings:
                            write_disclosure_draft(finding, drafts_directory)
                        total += len(new_findings)
                        queue.complete(item.identity, "done")
                    except (RateLimitError, AuthenticationError):
                        queue.complete(item.identity, "pending")
                        raise
                    except GitHubClientError:
                        queue.complete(item.identity, "failed")
                        raise
                    except (OSError, ValueError):
                        queue.complete(item.identity, "failed")
                        raise
            print(json.dumps({"findings_created": total, "reports": str(findings_path)}, sort_keys=True))
            if not (args.mode in {"broad", "hybrid"} and config.broad.continuous and not args.once):
                break
            time.sleep(config.broad.poll_interval_seconds)
        return 0
    finally:
        queue.close()


def _report_command(config, args) -> int:
    queue = ScanQueue(config.reports.state_database)
    try:
        if args.action == "list":
            for finding in queue.list_findings():
                print(json.dumps(finding.as_dict(), ensure_ascii=False, sort_keys=True))
            return 0
        if not args.finding_id:
            raise ValueError("draft action requires FINDING_ID")
        finding = queue.get_finding(args.finding_id)
        if finding is None:
            raise ValueError("finding not found")
        path = write_disclosure_draft(finding, config.reports.output_directory / "drafts")
        print(str(path))
        return 0
    finally:
        queue.close()
