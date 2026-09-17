"""
Stitch MCP frontend server for Nemesis Mode 2 / Config C1 demo.

Serves:
  - Static frontend (index.html, app.js, styles.css)
  - /api/run_c1            POST — runs run_demo_episode("C1") and returns the result dict
  - /api/episodes_csv      GET  — raw episodes.csv
  - /api/episodes_jsonl    GET  — raw episodes.json (JSONL)
  - /api/config_summary    GET  — raw config_summary.json
  - /api/doc               POST — renders a markdown doc to HTML
  - /api/adr_index         GET  — list of ADR entries
  - /api/adr               POST — renders a single ADR to HTML

No external API calls. Everything comes from local stub artifacts.
"""

from __future__ import annotations

import html
import json
import markdown
import os
import re
import sys
from pathlib import Path
from http.server import HTTPServer, SimpleHTTPRequestHandler
from urllib.parse import parse_qs, urlparse

PROJECT_ROOT = Path(__file__).resolve().parent.parent
FRONTEND_DIR = PROJECT_ROOT / "frontend"
RESULTS_DIR = PROJECT_ROOT / "results" / "mode2_c1"
DOCS_DIR = PROJECT_ROOT / "docs"

# Where the stubs drop artifacts. Mirrors mode2_c1_stubs.RESULTS_DIR default.
DEFAULT_RESULTS = PROJECT_ROOT / "results" / "mode2_c1"

# ---- ADR metadata (title + raw path) ----

ADR_INDEX = [
    {"id": "ADR-001", "title": "Controller is Non-LLM Python"},
    {"id": "ADR-002", "title": "Attacker Uses Hill-Climbing Adaptation"},
    {"id": "ADR-003", "title": "Three-Defense Architecture (CaMeL + Progent + Verifier)"},
    {"id": "ADR-004", "title": "Memory System Uses Five Memory Types"},
    {"id": "ADR-005", "title": "Defense Adapter Uses Majority Voting"},
    {"id": "ADR-006", "title": "Diagnoser Uses Two-Stage Classification"},
    {"id": "ADR-007", "title": "Stop Conditions Use Cryptographic Checksums"},
    {"id": "ADR-008", "title": "Episodes Persist as JSON Files"},
    {"id": "ADR-009", "title": "Metrics Modules Run in Parallel"},
    {"id": "ADR-010", "title": "Experimental Modes Are Separated"},
    {"id": "ADR-011", "title": "Target Agent Uses AgentDojo Framework"},
    {"id": "ADR-012", "title": "Cross-Agent Bridge for Multi-Agent Mode"},
    {"id": "ADR-013", "title": "LLM Clients via Anthropic SDK"},
    {"id": "ADR-014", "title": "CLI via argparse"},
    {"id": "ADR-015", "title": "All API Calls Logged for Cost Tracking"},
    {"id": "ADR-016", "title": "YAML Configuration with pydantic Validation"},
]


def read_file_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except FileNotFoundError:
        return f"/* File not found: {path} */"


def load_run_stubs():
    """Import run_demo_episode from the stubs module (local, no API)."""
    import sys
    project_root = str(PROJECT_ROOT)
    if project_root not in sys.path:
        sys.path.insert(0, project_root)
    from adaptive_agent_eval.pipelines.mode2_c1_stubs import run_demo_episode
    return run_demo_episode


# ---- markdown -> HTML (with a couple of lightweight extensions) ----

_MARKDOWN_EXTRA = [
    "tables",
    "fenced_code",
    "codehilite",
    "toc",
]


def render_markdown(text: str, css_class: str = "markdown-body") -> str:
    """Convert markdown text to an HTML fragment with a wrapper class."""
    try:
        md = markdown.Markdown(extensions=_MARKDOWN_EXTRA)
        body = md.convert(text)
    except Exception:
        body = f"<pre class='error'>{html.escape(text)}</pre>"
    return f'<div class="{css_class}">{body}</div>'


# ---- HTTP handler ----


class DemoHandler(SimpleHTTPRequestHandler):
    """Serves the frontend and API endpoints backed by local stub artifacts."""

    def __init__(self, *args, **kwargs):
        # serve static files from frontend/
        super().__init__(*args, directory=str(FRONTEND_DIR), **kwargs)

    # ---- static file serving (index.html etc.) ----

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/":
            self._serve_file(FRONTEND_DIR / "index.html", "text/html")
            return
        if parsed.path == "/app.js":
            self._serve_file(FRONTEND_DIR / "app.js", "application/javascript")
            return
        if parsed.path == "/styles.css":
            self._serve_file(FRONTEND_DIR / "styles.css", "text/css")
            return
        if parsed.path == "/api/episodes_csv":
            self._serve_csv()
            return
        if parsed.path == "/api/episodes_jsonl":
            self._serve_jsonl()
            return
        if parsed.path == "/api/config_summary":
            self._serve_config_summary()
            return
        if parsed.path == "/api/adr_index":
            self._serve_adr_index()
            return
        # static assets (favicon etc.) — fall through to parent
        super().do_GET()

    def do_POST(self):
        parsed = urlparse(self.path)
        ctype = self.headers.get("Content-Type", "")
        if parsed.path == "/api/run_c1":
            self._api_run_c1()
            return
        if parsed.path == "/api/doc":
            content_len = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_len) if content_len else b"{}"
            try:
                payload = json.loads(body)
            except json.JSONDecodeError:
                payload = {}
            self._api_doc(payload.get("name", ""))
            return
        if parsed.path == "/api/adr":
            content_len = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_len) if content_len else b"{}"
            try:
                payload = json.loads(body)
            except json.JSONDecodeError:
                payload = {}
            self._api_adr(payload.get("id", ""))
            return
        self.send_error(404, "Unknown POST endpoint")

    # ---- responses ----

    def _serve_file(self, path: Path, mime: str):
        if not path.exists():
            self.send_error(404, f"Not found: {path.name}")
            return
        data = path.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", mime)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        self.wfile.write(data)

    def _send_json(self, obj, status=200):
        data = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        self.wfile.write(data)

    def _send_html(self, html_text: str, status=200):
        data = html_text.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        self.wfile.write(data)

    def _send_error(self, message: str, status=400):
        self._send_json({"error": message}, status=status)

    # ---- endpoints ----

    def _api_run_c1(self):
        try:
            runner = load_run_stubs()
        except Exception as exc:
            self._send_error(f"Failed to load stub runner: {exc}")
            return
        try:
            result = runner(config_id="C1", max_rounds=2, n_episodes=2, seed=42,
                            results_dir=DEFAULT_RESULTS)
        except Exception as exc:
            self._send_error(f"run_demo_episode failed: {exc}")
            return
        self._send_json(result)

    def _serve_csv(self):
        csv_path = RESULTS_DIR / "episodes.csv"
        if not csv_path.exists():
            self._send_error("episodes.csv not found — run the demo first.", 404)
            return
        data = csv_path.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", "text/csv; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        self.wfile.write(data)

    def _serve_jsonl(self):
        jsonl_path = RESULTS_DIR / "episodes.json"
        if not jsonl_path.exists():
            self._send_error("episodes.json not found — run the demo first.", 404)
            return
        data = jsonl_path.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", "application/jsonl; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        self.wfile.write(data)

    def _serve_config_summary(self):
        summary_path = RESULTS_DIR / "config_summary.json"
        if not summary_path.exists():
            self._send_error("config_summary.json not found — run the demo first.", 404)
            return
        obj = json.loads(summary_path.read_text(encoding="utf-8"))
        self._send_json(obj)

    def _serve_adr_index(self):
        self._send_json(ADR_INDEX)

    def _api_doc(self, name: str):
        mapping = {
            "results_template": DOCS_DIR / "RESULTS_TEMPLATE.md",
            "experiment_plan": DOCS_DIR / "EXPERIMENT_PLAN.md",
        }
        path = mapping.get(name)
        if not path:
            self._send_error(f"Unknown doc '{name}'. Choose: {list(mapping.keys())}")
            return
        text = read_file_text(path)
        if not path.exists():
            self._send_error(f"Doc file not found: {path}")
            return
        html_fragment = render_markdown(text)
        self._send_json({"html": html_fragment})

    def _api_adr(self, adr_id: str):
        adr_path = DOCS_DIR / "ARCHITECTURE_DECISIONS.md"
        text = read_file_text(adr_path)
        if not adr_path.exists():
            self._send_error("ADR document not found.")
            return
        # Extract the ADR section from the markdown source.
        entry = next((a for a in ADR_INDEX if a["id"] == adr_id), None)
        if not entry:
            self._send_error(f"Unknown ADR '{adr_id}'.")
            return
        section = _extract_adr_section(text, adr_id)
        if not section:
            self._send_error(f"ADR section '{adr_id}' not found in source.")
            return
        html_fragment = render_markdown(section)
        self._send_json({"html": html_fragment, "title": entry["title"]})


def _extract_adr_section(text: str, adr_id: str) -> str:
    """Grab the markdown chunk for a given ADR id from ARCHITECTURE_DECISIONS.md."""
    # Match the heading line like "### ADR-001: Controller is Non-LLM Python"
    pattern = re.compile(rf"^###\s+{re.escape(adr_id)}:.*$", re.MULTILINE)
    m = pattern.search(text)
    if not m:
        return ""
    start = m.start()
    # Find the next "### " after start.
    rest = text[m.end():]
    next_m = re.search(r"^###\s+", rest, re.MULTILINE)
    end = m.end() + (next_m.start() if next_m else len(rest))
    return text[start:end].strip()


# ---- CLI ----


def main(port: int = 8000):
    os.chdir(FRONTEND_DIR)
    server = HTTPServer(("127.0.0.1", port), DemoHandler)
    print(f"Nemesis Stitch MCP Demo — http://127.0.0.1:{port}")
    print("  /            index.html")
    print("  /app.js      frontend logic")
    print("  /styles.css  theme")
    print("  /api/run_c1           POST — run 2 episodes, return result dict")
    print("  /api/episodes_csv     GET  — episodes.csv")
    print("  /api/episodes_jsonl   GET  — episodes.json (JSONL)")
    print("  /api/config_summary   GET  — config_summary.json")
    print("  /api/doc              POST — render RESULTS_TEMPLATE.md / EXPERIMENT_PLAN.md")
    print("  /api/adr_index        GET  — ADR list")
    print("  /api/adr              POST — render a single ADR")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down.")
        server.server_close()


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8000
    main(port)
