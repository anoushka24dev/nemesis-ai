"""Zero-dependency web server for the demo UI.

Uses only the Python standard library, so the demo cannot fail because a
package was missing at showtime.

Routes
------
GET  /            -> the UI (static/index.html)
GET  /api/inbox   -> the seeded mailbox, before any attack
GET  /api/run     -> run the full attack and return inbox + trace + metrics
GET  /healthz     -> readiness probe
"""

from __future__ import annotations

import argparse
import json
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs

from gmail_demo.engine import build_state, run_episode
from gmail_demo.models import is_email_demo_mode
from gmail_demo.inbox import FakeInbox

STATIC_DIR = Path(__file__).parent / "static"
INDEX_FILE = STATIC_DIR / "index.html"


def _is_true(values: list[str] | None) -> bool:
    """Truthy check for a query parameter such as ?hardened=1."""
    if not values:
        return False
    return values[0].strip().lower() in {"1", "true", "yes", "on"}


def _json_response(handler: BaseHTTPRequestHandler, payload: dict, status: int = 200) -> None:
    body = json.dumps(payload, indent=2, default=str).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Content-Length", str(len(body)))
    handler.send_header("Cache-Control", "no-store")
    handler.end_headers()
    handler.wfile.write(body)


class DemoHandler(BaseHTTPRequestHandler):
    server_version = "GmailDemoHTTP/1.0"

    def log_message(self, fmt: str, *args) -> None:  # quieter console
        return

    # -- GET ------------------------------------------------------------

    def do_GET(self) -> None:  # noqa: N802 (stdlib naming)
        path, query = self._split_path()

        if path in ("/", "/index.html"):
            return self._serve_index()
        if path == "/api/inbox":
            return _json_response(
                self,
                {"inbox": FakeInbox().to_dict(), "episode": None, "hardened": False},
            )
        # Priority: explicit ?demo_mode= query param, else EMAIL_DEMO_MODE env.
        if "demo_mode" in query:
            demo_mode = _is_true(query.get("demo_mode"))
        else:
            demo_mode = is_email_demo_mode()
        if path == "/api/run":
            return _json_response(
                self,
                build_state(
                    hardened=_is_true(query.get("hardened")),
                    demo_mode=demo_mode,
                ),
            )
        if path == "/healthz":
            return _json_response(self, {"ok": True})
        return _json_response(self, {"error": "not found", "path": path}, status=404)

    def do_POST(self) -> None:  # noqa: N802
        path, query = self._split_path()
        if path in ("/api/run", "/api/state"):
            if "demo_mode" in query:
                demo_mode = _is_true(query.get("demo_mode"))
            else:
                demo_mode = is_email_demo_mode()
            return _json_response(
                self,
                build_state(
                    hardened=_is_true(query.get("hardened")),
                    demo_mode=demo_mode,
                ),
            )
        return _json_response(self, {"error": "not found", "path": path}, status=404)

    def _split_path(self) -> tuple[str, dict[str, list[str]]]:
        """Split the request line into path and parsed query parameters."""
        if "?" not in self.path:
            return self.path, {}
        path, _, raw = self.path.partition("?")
        return path, parse_qs(raw)

    # -- helpers --------------------------------------------------------

    def _serve_index(self) -> None:
        if not INDEX_FILE.exists():
            return _json_response(
                self, {"error": "index.html missing", "expected": str(INDEX_FILE)}, status=500
            )
        body = INDEX_FILE.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)


def serve(host: str = "127.0.0.1", port: int = 8765, open_browser: bool = True) -> None:
    httpd = ThreadingHTTPServer((host, port), DemoHandler)
    url = f"http://{host}:{port}/"
    print(f"Gmail agent demo running at {url}")
    print("Endpoints: /  /api/inbox  /api/run  /healthz")
    print("Press Ctrl+C to stop.")
    if open_browser:
        try:
            webbrowser.open(url)
        except Exception:
            pass
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping demo server.")
    finally:
        httpd.server_close()


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the Gmail agent demo UI.")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--no-browser", action="store_true")
    parser.add_argument(
        "--cli",
        action="store_true",
        help="Run one episode in the terminal and print the trace instead of serving the UI.",
    )
    args = parser.parse_args()

    if args.cli:
        demo_mode = is_email_demo_mode()
        result = run_episode(demo_mode=demo_mode)
        print(json.dumps(result.to_dict(), indent=2, default=str))
        return

    serve(args.host, args.port, open_browser=not args.no_browser)


if __name__ == "__main__":
    main()
