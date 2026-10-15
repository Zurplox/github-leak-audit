"""Loopback-only standard-library HTTP API for the scanner dashboard."""

from __future__ import annotations

import argparse
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ipaddress
import json
from pathlib import Path
import re
import sqlite3
from urllib.parse import parse_qs, unquote, urlsplit
import webbrowser

from .config import Config, ConfigError
from .dashboard_data import findings_payload, summary_payload
from .reports import render_disclosure, write_disclosure_draft
from .scan_manager import ScanConfigurationError, ScanConflict, ScanManager, ScanValidationError
from .storage import ScanQueue


class DashboardServer(ThreadingHTTPServer):
    allow_reuse_address = True

    def __init__(self, host: str, port: int, manager, config: Config, *, static_root: Path | None = None):
        if not _is_loopback(host):
            raise ValueError("dashboard server must bind to a loopback address")
        self.manager = manager
        self.config = config
        self.static_root = (static_root or Path(__file__).parent / "dashboard_assets").resolve()
        super().__init__((host, port), DashboardRequestHandler)


class DashboardRequestHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server: DashboardServer

    def do_GET(self):
        parsed = urlsplit(self.path)
        if parsed.path == "/api/status":
            return self._send_json(HTTPStatus.OK, self.server.manager.status())
        if parsed.path == "/api/findings":
            return self._get_findings(parse_qs(parsed.query, keep_blank_values=True))
        if parsed.path == "/api/summary":
            return self._get_summary()
        if parsed.path.startswith("/api/disclosures/"):
            return self._get_disclosure(unquote(parsed.path.rsplit("/", 1)[-1]))
        if parsed.path == "/":
            return self._serve_static("index.html", "text/html; charset=utf-8")
        if parsed.path.startswith("/static/"):
            return self._serve_static(unquote(parsed.path[len("/static/"):]))
        return self._error(HTTPStatus.NOT_FOUND, "NOT_FOUND", "resource not found")

    def do_POST(self):
        path = urlsplit(self.path).path
        if path == "/api/scans":
            return self._post_start()
        if path == "/api/scans/pause":
            return self._post_control("pause")
        if path == "/api/scans/stop":
            return self._post_control("stop")
        return self._error(HTTPStatus.NOT_FOUND, "NOT_FOUND", "resource not found")

    def log_message(self, format, *args):
        return

    def _get_findings(self, query):
        try:
            page = _query_int(query, "page", 1, 1_000_000)
            page_size = _query_int(query, "pageSize", 50, 100)
            provider = _query_single(query, "provider")
            _query_known(query, {"page", "pageSize", "provider"})
            queue = ScanQueue(self.server.config.reports.state_database, read_only=True)
            try:
                findings, total = queue.list_findings_page(page, page_size, provider)
            finally:
                queue.close()
            return self._send_json(HTTPStatus.OK, findings_payload(findings, page, page_size, total))
        except ValueError as error:
            return self._error(HTTPStatus.UNPROCESSABLE_ENTITY, "VALIDATION_ERROR", str(error))
        except (OSError, sqlite3.Error):
            return self._error(HTTPStatus.INTERNAL_SERVER_ERROR, "SERVER_ERROR", "dashboard storage unavailable")

    def _get_summary(self):
        queue = None
        try:
            queue = ScanQueue(self.server.config.reports.state_database, read_only=True)
            return self._send_json(HTTPStatus.OK, summary_payload(queue.list_findings()))
        except (OSError, sqlite3.Error):
            return self._error(HTTPStatus.INTERNAL_SERVER_ERROR, "SERVER_ERROR", "dashboard storage unavailable")
        finally:
            if queue is not None:
                queue.close()

    def _get_disclosure(self, finding_id):
        if not re.fullmatch(r"[0-9a-f]{64}", finding_id):
            return self._error(HTTPStatus.UNPROCESSABLE_ENTITY, "VALIDATION_ERROR", "finding_id must be 64 lowercase hexadecimal characters")
        queue = None
        try:
            queue = ScanQueue(self.server.config.reports.state_database, read_only=True)
            finding = queue.get_finding(finding_id)
        except (OSError, sqlite3.Error):
            return self._error(HTTPStatus.INTERNAL_SERVER_ERROR, "SERVER_ERROR", "dashboard storage unavailable")
        finally:
            if queue is not None:
                queue.close()
        if finding is None:
            return self._error(HTTPStatus.NOT_FOUND, "NOT_FOUND", "finding not found")
        try:
            path = write_disclosure_draft(finding, self.server.config.reports.output_directory / "drafts")
            content = render_disclosure(finding)
        except (OSError, ValueError):
            return self._error(HTTPStatus.INTERNAL_SERVER_ERROR, "SERVER_ERROR", "disclosure draft unavailable")
        return self._send_json(HTTPStatus.OK, {"findingId": finding_id, "path": str(path), "content": content})

    def _post_start(self):
        try:
            body = self._read_json()
            _require_object(body)
            allowed = {"mode", "repository", "once"}
            unknown = set(body) - allowed
            if unknown:
                raise ValueError("unknown scan fields: " + ", ".join(sorted(unknown)))
            mode = body.get("mode")
            repository = body.get("repository")
            once = body.get("once", False)
            if mode not in {"search", "broad", "hybrid", "repo"}:
                raise ValueError("mode must be search, broad, hybrid, or repo")
            if not isinstance(once, bool):
                raise ValueError("once must be a boolean")
            if mode == "repo":
                if not isinstance(repository, str) or not re.fullmatch(r"^[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9_.-]{1,100}$", repository):
                    raise ValueError("repo mode requires OWNER/REPO")
            elif repository is not None:
                raise ValueError("repository is only valid for repo mode")
            result = self.server.manager.start(mode, repository, once)
            return self._send_json(HTTPStatus.ACCEPTED, result)
        except (ValueError, ScanValidationError, json.JSONDecodeError, UnicodeDecodeError) as error:
            return self._error(HTTPStatus.UNPROCESSABLE_ENTITY, "VALIDATION_ERROR", str(error))
        except ScanConflict as error:
            return self._error(HTTPStatus.CONFLICT, "CONFLICT", str(error))
        except ScanConfigurationError as error:
            return self._error(HTTPStatus.SERVICE_UNAVAILABLE, "CONFIGURATION_ERROR", str(error))
        except Exception as error:
            return self._error(HTTPStatus.INTERNAL_SERVER_ERROR, "SERVER_ERROR", _safe_message(error))

    def _post_control(self, action):
        try:
            self._discard_body()
            result = getattr(self.server.manager, action)()
            return self._send_json(HTTPStatus.OK, result)
        except (OSError, ValueError) as error:
            return self._error(HTTPStatus.INTERNAL_SERVER_ERROR, "SERVER_ERROR", _safe_message(error))

    def _discard_body(self):
        raw_length = self.headers.get("Content-Length")
        if raw_length is None:
            return
        try:
            length = int(raw_length)
        except ValueError:
            raise ValueError("invalid Content-Length") from None
        if length < 0 or length > 64 * 1024:
            raise ValueError("request body is too large")
        self.rfile.read(length)

    def _read_json(self):
        raw_length = self.headers.get("Content-Length")
        if raw_length is None:
            raise ValueError("JSON request body is required")
        try:
            length = int(raw_length)
        except ValueError:
            raise ValueError("invalid Content-Length") from None
        if length < 0 or length > 64 * 1024:
            raise ValueError("request body is too large")
        raw = self.rfile.read(length)
        return json.loads(raw.decode("utf-8"))

    def _serve_static(self, relative, content_type=None):
        if not relative or "\\" in relative:
            return self._error(HTTPStatus.NOT_FOUND, "NOT_FOUND", "resource not found")
        root = self.server.static_root
        target = (root / relative).resolve()
        try:
            target.relative_to(root)
        except ValueError:
            return self._error(HTTPStatus.NOT_FOUND, "NOT_FOUND", "resource not found")
        if not target.is_file():
            return self._error(HTTPStatus.NOT_FOUND, "NOT_FOUND", "resource not found")
        try:
            body = target.read_bytes()
        except OSError:
            return self._error(HTTPStatus.NOT_FOUND, "NOT_FOUND", "resource not found")
        content_type = content_type or {
            ".js": "text/javascript; charset=utf-8", ".css": "text/css; charset=utf-8",
            ".json": "application/json; charset=utf-8",
        }.get(target.suffix.lower(), "application/octet-stream")
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def _send_json(self, status, payload):
        body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def _error(self, status, code, message, details=None):
        return self._send_json(status, {"error": {"code": code, "message": message, "details": details or {}}})


def _is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _query_known(query, allowed):
    unknown = set(query) - allowed
    if unknown:
        raise ValueError("unknown query parameter: " + ", ".join(sorted(unknown)))


def _query_single(query, name):
    values = query.get(name)
    if values is None:
        return None
    if len(values) != 1 or not values[0] or len(values[0]) > 200:
        raise ValueError(name + " must be a single non-empty value")
    return values[0]


def _query_int(query, name, default, maximum):
    value = _query_single(query, name)
    if value is None:
        return default
    if not value.isdecimal():
        raise ValueError(name + " must be an integer")
    result = int(value)
    if result < 1 or result > maximum:
        raise ValueError(name + " is out of range")
    return result


def _require_object(value):
    if not isinstance(value, dict):
        raise ValueError("request body must be a JSON object")


def _safe_message(error):
    return "".join(character if ord(character) >= 32 else " " for character in str(error))[:300] or type(error).__name__


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Run the local scanner dashboard.")
    parser.add_argument("--config", default="config.toml")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--open", action="store_true")
    args = parser.parse_args(argv)
    try:
        config = Config.load(Path(args.config))
        manager = ScanManager(config)
        server = DashboardServer(args.host, args.port, manager, config)
    except (ConfigError, OSError, ValueError) as error:
        parser.error(str(error))
        return 2
    if args.open:
        webbrowser.open(f"http://{args.host}:{server.server_port}/")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        manager.close()
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
