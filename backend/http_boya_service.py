"""Local JSON HTTP service that wraps the BYOA target module.

Exposes:
* ``POST /execute`` - execute a documented BYOA request.
* ``GET /execute`` - informational response (HTTP 405) explaining the endpoint
  requires POST; no target action is executed.
* ``GET /health`` - lightweight health check.

The service imports and uses the ``boya_target_module`` entry point
``run_turn`` to genuinely execute Python target code, and returns the response
in the format expected by ``ExternalHttpTargetAdapter`` (``tool_calls``,
``output``, ``evidence``).

This respects ADR-022 by using the supported ``http_api`` mechanism: the agent
is exposed behind a JSON HTTP endpoint, not as an inline ``user_byoa`` kind
target within the harness ``start()`` method.
"""

import json
import logging
import threading
from typing import Any
from http.server import HTTPServer, BaseHTTPRequestHandler

from backend.boya_target_module import run_turn, _failure_response

logger = logging.getLogger(__name__)

# --- Endpoint configuration ---

BIND_ADDRESS = "127.0.0.1"
BIND_PORT = 11643  # non-conflicting port; Ollama uses 11434
ENDPOINT_URL = f"http://{BIND_ADDRESS}:{BIND_PORT}/execute"


def _info_response() -> dict[str, Any]:
    """Informational response describing the endpoint contract."""
    return {
        "service": "Nemesis HTTP BYOA Target",
        "endpoint": "/execute",
        "supported_method": "POST",
        "message": "Send a JSON POST request to execute a target action.",
        "health_endpoint": "/health",
    }


# --- HTTP request handler ---


class _BoyaExecuteHandler(BaseHTTPRequestHandler):
    """Handle ``POST /execute``, ``GET /execute``, and ``GET /health``."""

    def _send_json(self, code: int, body: dict[str, Any]) -> None:
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        if code == 405:
            self.send_header("Allow", "POST")
        self.end_headers()
        self.wfile.write(json.dumps(body, ensure_ascii=False).encode("utf-8"))

    def _method_not_allowed(self) -> None:
        """Reject a method without executing or navigating to a target action."""
        self._send_json(
            405,
            {
                **_info_response(),
                "error": "Method Not Allowed",
                "detail": "This endpoint requires POST to execute actions.",
            },
        )

    def do_GET(self) -> None:
        if self.path == "/execute":
            self._method_not_allowed()
            return
        if self.path == "/health":
            # Health is a readiness check, not a target turn: never execute an
            # action from GET. The target module is imported at startup, so a
            # callable run_turn is the execution dependency we can truthfully
            # report as available here.
            ready = callable(run_turn)
            self._send_json(
                200,
                {
                    "status": "ok" if ready else "degraded",
                    "service": "Nemesis HTTP BYOA Target",
                    "endpoint": "/execute",
                    "supported_method": "POST",
                    "port": BIND_PORT,
                    "execution_ready": ready,
                    "detail": "target module loaded" if ready else "target module unavailable",
                },
            )
            return
        self.send_error(404, "Not found")

    def do_HEAD(self) -> None:  # noqa: N802 - required by BaseHTTPRequestHandler
        self._method_not_allowed()

    def do_OPTIONS(self) -> None:  # noqa: N802 - required by BaseHTTPRequestHandler
        self._method_not_allowed()

    def do_PUT(self) -> None:  # noqa: N802 - required by BaseHTTPRequestHandler
        self._method_not_allowed()

    def do_PATCH(self) -> None:  # noqa: N802 - required by BaseHTTPRequestHandler
        self._method_not_allowed()

    def do_DELETE(self) -> None:  # noqa: N802 - required by BaseHTTPRequestHandler
        self._method_not_allowed()

    def do_POST(self) -> None:  # noqa: N802 - required by BaseHTTPRequestHandler
        if self.path != "/execute":
            self.send_error(404, "Not found")
            return

        content_length = int(self.headers.get("Content-Length", 0))
        raw_body = self.rfile.read(content_length)

        try:
            request_dict = json.loads(raw_body.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            logger.warning("Malformed JSON body: %s", exc)
            self._send_json(400, {"error": "Invalid JSON", "detail": str(exc)})
            return
        if not isinstance(request_dict, dict):
            self._send_json(400, {"error": "Invalid request", "detail": "JSON body must be an object"})
            return
        if not isinstance(request_dict.get("input", ""), str):
            self._send_json(400, {"error": "Invalid request", "detail": "'input' must be a string"})
            return

        correlation_id = request_dict.get("correlation_id")
        correlation_label = correlation_id if isinstance(correlation_id, str) else "-"
        print(
            f"BYOA POST /execute correlation_id={correlation_label}",
            flush=True,
        )

        # --- Invoke the BYOA target ---
        try:
            response_dict = run_turn(request_dict)
        except Exception as exc:  # noqa: BLE001 - surface as diagnostic
            logger.exception("BYOA target execution failed")
            response_dict = _failure_response(reason=str(exc))

        # --- Format response for ExternalHttpTargetAdapter ---
        # The adapter expects: tool_calls (list of {tool_name, arguments, raw_text}),
        # output (string), evidence (dict).

        tool_names: list[dict[str, Any]] = []
        for tc in response_dict.get("tool_calls", []):
            if isinstance(tc, dict) and "tool_name" in tc:
                tool_names.append(
                    {
                        "tool_name": tc["tool_name"],
                        "arguments": tc.get("arguments", {}),
                        "raw_text": tc.get("raw_text", ""),
                    }
                )

        out_text = str(response_dict.get("output", ""))

        evidence = response_dict.get("evidence", {})
        if isinstance(evidence, dict):
            evidence["target_mode"] = "remote"
        else:
            evidence = {"target_mode": "remote"}

        response_payload = {
            "tool_calls": tool_names,
            "output": out_text,
            "evidence": evidence,
            # Also include observations at top level for convenience.
            "observations": response_dict.get("observations", {}),
            "ground_truth": response_dict.get("ground_truth", {}),
        }
        # Echo the caller's correlation/session identifiers when supplied so
        # campaign requests can be matched to target responses. These are
        # identifiers, not target execution results.
        for key in ("correlation_id", "session_id"):
            value = request_dict.get(key)
            if isinstance(value, str) and value:
                response_payload[key] = value

        # --- Send response ---
        print(
            f"BYOA 200 /execute correlation_id={correlation_label} "
            f"tool_calls={len(tool_names)}",
            flush=True,
        )
        self._send_json(200, response_payload)

    # Silence default stderr logging from BaseHTTPRequestHandler
    def log_message(self, format: str, *args):  # noqa: A002
        pass


# --- Server bootstrap ---


def _start_server(host: str = BIND_ADDRESS, port: int = BIND_PORT) -> HTTPServer:
    """Start the BYOA HTTP service and return the server instance."""
    server = HTTPServer((host, port), _BoyaExecuteHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    logger.info("BYOA HTTP service listening on %s", server.server_address)
    print(f"BYOA HTTP service listening on {host}:{port}")
    return server



# --- Module entry point for standalone execution ---

if __name__ == "__main__":
    server = _start_server()
    try:
        import time as _time

        while True:
            _time.sleep(60)
    except KeyboardInterrupt:
        logger.info("Shutting down BYOA HTTP service")
        server.shutdown()
