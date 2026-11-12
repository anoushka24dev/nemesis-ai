"""Ollama provider tests (Part 3 / Part 12.2).

The real provider code sends requests to a controlled local HTTP server; the
tests assert the client contract, the error taxonomy, provenance counters and
the absence of any silent fake fallback. Exercising a *real* Ollama model is
reported separately and is never required for these tests to pass.
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from adaptive_agent_eval.llm.provider import (
    OllamaConfig,
    OllamaProviderError,
    make_provider_config,
    create_provider,
    ollama_health_check,
)

# ---------------------------------------------------------------------------
# Controlled local HTTP server (a stand-in Ollama endpoint)
# ---------------------------------------------------------------------------


class _StubOllama:
    """Scriptable local endpoint speaking the ``/api/chat`` + ``/api/tags`` API."""

    def __init__(self, mode: str = "ok", model: str = "llama3.1:8b"):
        self.mode = mode
        self.model = model
        self.requests: list[dict] = []
        server = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):  # silence
                pass

            def do_GET(self):
                if self.path.startswith("/api/tags"):
                    if server.mode == "down":
                        self.send_error(500)
                        return
                    body = json.dumps(
                        {"models": [{"name": server.model}]}
                    ).encode()
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                    return
                self.send_error(404)

            def do_POST(self):
                length = int(self.headers.get("Content-Length", 0))
                raw = self.rfile.read(length) if length else b"{}"
                try:
                    payload = json.loads(raw.decode("utf-8"))
                except ValueError:
                    payload = {}
                server.requests.append(
                    {
                        "path": self.path,
                        "payload": payload,
                        "content_type": self.headers.get("Content-Type"),
                    }
                )
                if server.mode == "http_error":
                    self.send_error(503, "busy")
                    return
                if server.mode == "garbage":
                    body = b"this is not json"
                    self.send_response(200)
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                    return
                if server.mode == "empty":
                    body = json.dumps({"message": {"content": ""}}).encode()
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                    return
                if server.mode == "non_string":
                    body = json.dumps({"message": {"content": 12345}}).encode()
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                    return
                body = json.dumps(
                    {"message": {"role": "assistant", "content": '{"candidate_ladder": []}'}}
                ).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self._server.server_address[1]
        self.endpoint = f"http://127.0.0.1:{self.port}"
        self._thread = threading.Thread(
            target=self._server.serve_forever, daemon=True
        )
        self._thread.start()

    def close(self):
        self._server.shutdown()
        self._server.server_close()


def _cfg(endpoint: str, **overrides) -> OllamaConfig:
    cfg = OllamaConfig()
    cfg.api_base_override = endpoint
    cfg.retries = overrides.pop("retries", 1)
    cfg.timeout_seconds = overrides.pop("timeout_seconds", 5.0)
    for k, v in overrides.items():
        setattr(cfg, k, v)
    return cfg


# ---------------------------------------------------------------------------
# 12.2 request contract
# ---------------------------------------------------------------------------


def test_provider_is_wired_into_the_existing_abstraction():
    cfg = make_provider_config("ollama")
    assert cfg.provider == "ollama"
    assert cfg.endpoint == "http://127.0.0.1:11434"  # documented default
    assert cfg.model_for_role("attacker") == "llama3.1:8b"  # documented default
    provider = create_provider(cfg)
    assert type(provider).__name__ == "OllamaProvider"
    # No credential is invented or read from the environment.
    assert "credential" in cfg.api_key()


def test_real_request_shape_hits_chat_endpoint_with_model_and_system():
    stub = _StubOllama()
    try:
        cfg = _cfg(stub.endpoint)
        client = create_provider(cfg).messages()
        resp = client.create(
            model="llama3.1:8b",
            max_tokens=256,
            system="SYSTEM PROMPT HERE",
            messages=[{"role": "user", "content": "user content"}],
            temperature=0.2,
        )
    finally:
        stub.close()
    assert resp.content[0].text == '{"candidate_ladder": []}'
    assert len(stub.requests) == 1
    req = stub.requests[0]
    assert req["path"] == "/api/chat"
    payload = req["payload"]
    assert payload["model"] == "llama3.1:8b"
    assert payload["stream"] is False
    assert payload["options"]["num_predict"] == 256
    assert payload["options"]["temperature"] == 0.2
    roles = [(m["role"], m["content"]) for m in payload["messages"]]
    assert ("system", "SYSTEM PROMPT HERE") in roles
    assert ("user", "user content") in roles


def test_provenance_and_request_counters_are_accurate():
    stub = _StubOllama()
    try:
        cfg = _cfg(stub.endpoint, max_model_calls=5)
        client = create_provider(cfg).messages()
        client.create(
            model="llama3.1:8b", max_tokens=32, system="s",
            messages=[{"role": "user", "content": "u"}],
        )
        tel = cfg.telemetry()
        assert tel["provider"] == "ollama"
        assert tel["endpoint"] == stub.endpoint
        assert tel["successful_requests"] == 1
        assert tel["failed_requests"] == 0
        assert tel["model_calls_consumed"] == 1
        assert tel["last_error_category"] is None
        assert tel["total_elapsed_seconds"] >= 0.0
    finally:
        stub.close()


def test_model_request_budget_is_enforced_before_any_request():
    stub = _StubOllama()
    try:
        cfg = _cfg(stub.endpoint, max_model_calls=1, model_calls_consumed=1)
        client = create_provider(cfg).messages()
        with pytest.raises(RuntimeError) as exc:
            client.create(
                model="llama3.1:8b", max_tokens=32, system="s",
                messages=[{"role": "user", "content": "u"}],
            )
        assert "budget exhausted" in str(exc.value)
        assert stub.requests == []  # nothing went out
    finally:
        stub.close()


# ---------------------------------------------------------------------------
# failure handling — typed errors, counters, NO silent fallback
# ---------------------------------------------------------------------------


def test_connection_refused_is_an_explicit_provider_failure():
    cfg = _cfg("http://127.0.0.1:59997", timeout_seconds=1.0, retries=1)
    client = create_provider(cfg).messages()
    with pytest.raises(OllamaProviderError) as exc:
        client.create(
            model="llama3.1:8b", max_tokens=32, system="s",
            messages=[{"role": "user", "content": "u"}],
        )
    assert exc.value.category in ("unavailable", "timeout")
    assert cfg.failed_requests == 1
    assert cfg.successful_requests == 0
    assert cfg.last_error_category == exc.value.category
    # A failed request is never converted into a fake answer.
    with pytest.raises(OllamaProviderError):
        client.create(
            model="llama3.1:8b", max_tokens=32, system="s",
            messages=[{"role": "user", "content": "u"}],
        )


def test_http_error_is_typed_and_counted():
    stub = _StubOllama(mode="http_error")
    try:
        cfg = _cfg(stub.endpoint, retries=1)
        client = create_provider(cfg).messages()
        with pytest.raises(OllamaProviderError) as exc:
            client.create(
                model="llama3.1:8b", max_tokens=32, system="s",
                messages=[{"role": "user", "content": "u"}],
            )
        assert exc.value.category in ("http_error", "server_error")
        assert cfg.failed_requests == 1
        assert cfg.successful_requests == 0
    finally:
        stub.close()


@pytest.mark.parametrize("mode", ["garbage", "empty", "non_string"])
def test_malformed_responses_are_rejected_not_repaired(mode):
    stub = _StubOllama(mode=mode)
    try:
        cfg = _cfg(stub.endpoint, retries=1)
        client = create_provider(cfg).messages()
        with pytest.raises(OllamaProviderError) as exc:
            client.create(
                model="llama3.1:8b", max_tokens=32, system="s",
                messages=[{"role": "user", "content": "u"}],
            )
        assert exc.value.category in ("invalid_response", "http_error")
        assert cfg.successful_requests == 0
    finally:
        stub.close()


def test_timeout_is_reported_as_timeout_category(monkeypatch):
    # An endpoint that never answers: use a raw socket server that accepts and
    # stalls, so the client's wall-clock timeout is what fires.
    import socket

    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]

    def _stall():
        try:
            conn, _ = srv.accept()
            import time

            time.sleep(3)
            conn.close()
        except OSError:
            pass

    t = threading.Thread(target=_stall, daemon=True)
    t.start()
    try:
        cfg = _cfg(f"http://127.0.0.1:{port}", timeout_seconds=0.5, retries=1)
        client = create_provider(cfg).messages()
        with pytest.raises(OllamaProviderError) as exc:
            client.create(
                model="llama3.1:8b", max_tokens=32, system="s",
                messages=[{"role": "user", "content": "u"}],
            )
        assert exc.value.category in ("timeout", "unavailable")
        assert cfg.last_error_category == exc.value.category
    finally:
        srv.close()


def test_failed_request_never_invokes_another_provider(monkeypatch):
    """A broken Ollama endpoint must not be silently replaced (Part 3.4)."""
    from adaptive_agent_eval.llm import provider as provider_mod

    calls: list[str] = []
    original = provider_mod.create_provider

    def spy(cfg, *args, **kwargs):
        calls.append(getattr(cfg, "provider", "?"))
        return original(cfg, *args, **kwargs)

    monkeypatch.setattr(provider_mod, "create_provider", spy)
    cfg = _cfg("http://127.0.0.1:59997", timeout_seconds=1.0, retries=1)
    client = create_provider(cfg).messages()
    with pytest.raises(OllamaProviderError):
        client.create(
            model="llama3.1:8b", max_tokens=32, system="s",
            messages=[{"role": "user", "content": "u"}],
        )
    # Only the ollama provider was ever constructed for this call.
    assert all(c in ("ollama", "None") for c in calls), calls
    assert cfg.last_error_category is not None


# ---------------------------------------------------------------------------
# health / readiness (Part 3.2)
# ---------------------------------------------------------------------------


def test_health_check_reports_ready_endpoint_with_model():
    stub = _StubOllama(model="llama3.1:8b")
    try:
        health = ollama_health_check(stub.endpoint, timeout=3.0)
    finally:
        stub.close()
    assert health["reachable"] is True
    assert health["model_available"] is True
    assert health["error_category"] is None


def test_health_check_reports_missing_model_separately_from_down():
    stub = _StubOllama(model="totally-other-model")
    try:
        health = ollama_health_check(stub.endpoint, timeout=3.0)
    finally:
        stub.close()
    assert health["reachable"] is True
    assert health["model_available"] is False
    assert health["error_category"] == "model_not_found"
    assert "totally-other-model" in health["error"] or "installed models" in health["error"]


def test_health_check_reports_unreachable_endpoint():
    health = ollama_health_check("http://127.0.0.1:59996", timeout=1.0)
    assert health["reachable"] is False
    assert health["model_available"] is False
    assert health["error_category"] == "unavailable"
    assert health["error"]
