"""Safety assertions for the Stage B backend.

These are read-only property checks: they assert what MUST be true, never what
the backend happens to do in one run. They are meant to be kept as permanent
guards even as the implementation evolves.
"""
from __future__ import annotations

import json
import tempfile
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from starlette.routing import Mount

from backend.stage_b import (
    _MOUNT_PREFIX,
    _PINNED_EXTENSION_ID_ENV,
    ALLOWED_EXTENSION_ORIGINS,
    APP_ORIGIN,
    StageBBackend,
    _feed_name_from_token,
    _header_token,
    _local_request,
    _nonce_matches,
    _now_iso,
    _origin_allowed,
    _origin_matches,
    _request_origin,
    _serve,
    create_app,
)
from gmail_auth import GMAIL_READONLY_SCOPE, requested_scopes
from gmail_demo.models import Email

_NONCE = "test-pairing-nonce"


def _mock_request(
    *,
    origin: str | None = None,
    authorization: str | None = None,
    json_body: dict | None = None,
) -> MagicMock:
    req = MagicMock()
    req.headers = {
        "origin": origin or "",
        "authorization": authorization or "",
    }
    req.client = MagicMock()
    host, port = "127.0.0.1", 8123
    req.client.host = host
    req.client.port = port
    req.json = MagicMock(return_value=json_body or {})
    return req


def _payload(response: object) -> dict:
    try:
        return json.loads(response.body.decode("utf-8"))
    except Exception:
        return {"_raw": str(response)}


@pytest.fixture
def backend(tmp_path: Path) -> StageBBackend:
    return StageBBackend(
        credentials_path=tmp_path / "creds.json",
        token_path=tmp_path / "token.json",
        pairing_nonce=_NONCE,
    )


def test_app_origin_is_loopback() -> None:
    assert APP_ORIGIN == "http://127.0.0.1:8123"


def test_allowed_origins_include_extension_scheme() -> None:
    assert "chrome-extension://" in ALLOWED_EXTENSION_ORIGINS


def test_backend_starts_unpaired(backend: StageBBackend) -> None:
    assert backend._state == "unpaired"
    assert backend._paired_origin is None


def test_present_nonce_pairs_from_allowed_origin(backend: StageBBackend) -> None:
    origin = "chrome-extension://abcdefghijklmnop"
    resp = backend.present_nonce(_mock_request(origin=origin), _NONCE)
    assert resp.status_code == 200
    payload = _payload(resp)
    assert payload["state"] == "paired"
    assert payload["origin_validated"] == origin
    assert backend._state == "paired"
    assert backend._paired_origin == origin


def test_present_wrong_nonce_is_rejected(backend: StageBBackend) -> None:
    resp = backend.present_nonce(_mock_request(origin="chrome-extension://id"), "wrong")
    assert resp.status_code == 403
    assert backend._state == "unpaired"


def test_present_missing_nonce_is_rejected(backend: StageBBackend) -> None:
    resp = backend.present_nonce(_mock_request(origin="chrome-extension://id"), "")
    assert resp.status_code == 400
    assert backend._state == "unpaired"


def test_present_request_without_origin_is_rejected(backend: StageBBackend) -> None:
    resp = backend.present_nonce(_mock_request(origin=None), _NONCE)
    assert resp.status_code == 400
    assert backend._state == "unpaired"


def test_present_non_extension_origin_is_rejected(backend: StageBBackend) -> None:
    resp = backend.present_nonce(
        _mock_request(origin="http://localhost:9876"), _NONCE
    )
    assert resp.status_code == 403
    assert backend._state == "unpaired"


def test_ping_rejects_unpaired(backend: StageBBackend) -> None:
    resp = backend.ping(_mock_request(origin="chrome-extension://id"))
    assert resp.status_code == 403


def test_ping_rejects_missing_bearer_after_pairing(backend: StageBBackend) -> None:
    origin = "chrome-extension://id"
    backend.present_nonce(_mock_request(origin=origin), _NONCE)
    resp = backend.ping(_mock_request(origin=origin, authorization=None))
    assert resp.status_code == 401


def test_ping_rejects_wrong_bearer_after_pairing(backend: StageBBackend) -> None:
    origin = "chrome-extension://id"
    backend.present_nonce(_mock_request(origin=origin), _NONCE)
    resp = backend.ping(
        _mock_request(origin=origin, authorization="Bearer wrong")
    )
    assert resp.status_code == 401


def test_ping_rejects_origin_change_after_pairing(backend: StageBBackend) -> None:
    origin_a = "chrome-extension://abcdefghijklmnop"
    origin_b = "chrome-extension://qrstuvwxyz012345"
    backend.present_nonce(_mock_request(origin=origin_a), _NONCE)
    resp = backend.ping(
        _mock_request(
            origin=origin_b, authorization="Bearer %s" % _NONCE
        )
    )
    assert resp.status_code == 403


def test_ping_accepts_valid_paired_request(backend: StageBBackend) -> None:
    origin = "chrome-extension://abcdefghijklmnop"
    backend.present_nonce(_mock_request(origin=origin), _NONCE)
    resp = backend.ping(
        _mock_request(
            origin=origin, authorization="Bearer %s" % _NONCE
        )
    )
    assert resp.status_code == 200
    payload = _payload(resp)
    assert payload["state"] == "paired"
    assert payload["origin_validated"] == origin


def test_fetch_rejects_unpaired(backend: StageBBackend) -> None:
    resp = backend.fetch_demo_emails(
        _mock_request(origin="chrome-extension://id", json_body={"max_results": 5}),
        5,
    )
    assert resp.status_code == 403


def test_fetch_rejects_missing_bearer_after_pairing(backend: StageBBackend) -> None:
    origin = "chrome-extension://id"
    backend.present_nonce(
        _mock_request(origin=origin, json_body={"max_results": 5}), _NONCE
    )
    resp = backend.fetch_demo_emails(
        _mock_request(
            origin=origin, authorization=None, json_body={"max_results": 5}
        ),
        5,
    )
    assert resp.status_code == 401


def test_fetch_rejects_wrong_bearer_after_pairing(backend: StageBBackend) -> None:
    origin = "chrome-extension://id"
    backend.present_nonce(
        _mock_request(origin=origin, json_body={"max_results": 5}), _NONCE
    )
    resp = backend.fetch_demo_emails(
        _mock_request(
            origin=origin,
            authorization="Bearer wrong",
            json_body={"max_results": 5},
        ),
        5,
    )
    assert resp.status_code == 401


def test_fetch_rejects_origin_change_after_pairing(backend: StageBBackend) -> None:
    origin_a = "chrome-extension://abcdefghijklmnop"
    origin_b = "chrome-extension://qrstuvwxyz012345"
    backend.present_nonce(
        _mock_request(origin=origin_a, json_body={"max_results": 5}), _NONCE
    )
    resp = backend.fetch_demo_emails(
        _mock_request(
            origin=origin_b,
            authorization="Bearer %s" % _NONCE,
            json_body={"max_results": 5},
        ),
        5,
    )
    assert resp.status_code == 403


def test_analyze_rejects_unpaired(backend: StageBBackend) -> None:
    resp = backend.analyze_demo_emails(
        _mock_request(origin="chrome-extension://id", json_body={"max_results": 5}),
        5,
    )
    assert resp.status_code == 403


def test_reset_requires_allowed_origin(backend: StageBBackend) -> None:
    backend.present_nonce(_mock_request(origin="chrome-extension://id"), _NONCE)
    resp = backend.reset(_mock_request(origin="chrome-extension://id"))
    payload = _payload(resp)
    assert payload["state"] == "unpaired"
    assert payload["pairing_nonce_exposed"] is False
    assert backend._state == "unpaired"


def test_reset_requires_allowed_origin_header(backend: StageBBackend) -> None:
    backend.present_nonce(_mock_request(origin="chrome-extension://id"), _NONCE)
    with pytest.raises(HTTPException):
        backend.reset(_mock_request(origin="http://localhost:9876"))


def test_reset_accepts_null_origin_when_request_is_none(backend: StageBBackend) -> None:
    backend.present_nonce(_mock_request(origin="chrome-extension://id"), _NONCE)
    resp = backend.reset(request=None)
    payload = _payload(resp)
    assert payload["state"] == "unpaired"
    assert payload["pairing_nonce_exposed"] is False


def test_no_leak_of_pairing_nonce_in_any_response(backend: StageBBackend) -> None:
    origin = "chrome-extension://id"
    calls = [
        backend.present_nonce(_mock_request(origin=origin), _NONCE),
        backend.present_nonce(_mock_request(origin=origin), "wrong"),
        backend.ping(
            _mock_request(
                origin=origin, authorization="Bearer %s" % _NONCE
            )
        ),
        backend.fetch_demo_emails(
            _mock_request(
                origin=origin,
                authorization="Bearer %s" % _NONCE,
                json_body={"max_results": 1},
            ),
            1,
        ),
        backend.analyze_demo_emails(
            _mock_request(
                origin=origin,
                authorization="Bearer %s" % _NONCE,
                json_body={"max_results": 1},
            ),
            1,
        ),
    ]
    for response in calls:
        payload = _payload(response)
        assert _NONCE not in json.dumps(payload), payload
        assert "pairing_nonce" not in payload, payload


def test_reset_clears_pairing_without_exposing_nonce(backend: StageBBackend) -> None:
    origin = "chrome-extension://id"
    backend.present_nonce(_mock_request(origin=origin), _NONCE)
    resp = backend.reset()
    payload = _payload(resp)
    assert payload["state"] == "unpaired"
    assert _NONCE not in json.dumps(payload)
    assert "pairing_nonce" not in payload


def test_origin_matches_extension_scheme() -> None:
    assert _origin_matches(
        "chrome-extension://abcdefghijklmnop", ALLOWED_EXTENSION_ORIGINS
    ) is True
    assert _origin_matches(
        "CHROME-EXTENSION://ABCDEFGHIJKLMNOP", ALLOWED_EXTENSION_ORIGINS
    ) is True
    assert _origin_matches(
        "http://localhost:8080", ALLOWED_EXTENSION_ORIGINS
    ) is False
    assert _origin_matches(
        "https://example.com", ALLOWED_EXTENSION_ORIGINS
    ) is False


def test_local_request_loopback_8123_is_local() -> None:
    assert _local_request(_mock_request()) is True


def test_local_request_other_port_is_not_local() -> None:
    req = _mock_request()
    req.client.port = 12345
    assert _local_request(req) is False


def test_local_request_other_host_is_not_local() -> None:
    req = _mock_request()
    req.client.host = "192.168.1.1"
    assert _local_request(req) is False


def test_header_token_strips_bearer() -> None:
    assert _header_token("Bearer nonce-123") == "nonce-123"
    assert _header_token("Bearer  nonce-123  ") == "nonce-123"
    assert _header_token(None) is None
    assert _header_token("") is None


def test_request_origin_from_headers() -> None:
    req = _mock_request(origin="chrome-extension://foo")
    assert _request_origin(req) == "chrome-extension://foo"
    assert _request_origin(_mock_request(origin=None)) is None


def test_now_iso_format() -> None:
    ts = _now_iso()
    assert ts.endswith("Z") or "+" in ts
    assert len(ts) >= 20


def test_requested_scopes_is_readonly() -> None:
    scopes = requested_scopes()
    assert scopes == [GMAIL_READONLY_SCOPE]
    assert frozenset(scopes) == frozenset({GMAIL_READONLY_SCOPE})


def _wire_fastapi_app(*, pairing_nonce: str = _NONCE):
    tmp = Path(tempfile.mkdtemp())
    app = create_app(
        credentials_path=tmp / "creds.json",
        token_path=tmp / "token.json",
        pairing_nonce=pairing_nonce,
    )
    return app


def test_fastapi_app_mounts_stage_b_routes() -> None:
    app = _wire_fastapi_app()
    mount = next(
        r for r in app.routes if isinstance(r, Mount) and r.path == _MOUNT_PREFIX
    )
    mounted = mount.app
    routes = {route.path for route in mounted.routes if hasattr(route, "path")}
    assert "/pair" in routes
    assert "/ping" in routes
    assert "/feed" in routes
    assert "/reset" in routes
    attachment_paths = {
        route.path
        for route in mounted.routes
        if hasattr(route, "path") and "/attachments/" in route.path
    }
    assert "/attachments/{filename}" in attachment_paths


def test_attachment_metadata_is_nonce_and_filename_bound() -> None:
    app = _wire_fastapi_app(pairing_nonce="install-a")
    client_a = TestClient(app, follow_redirects=False)
    client_a.post(
        f"/{_MOUNT_PREFIX.lstrip('/')}/pair",
        json={
            "presented_nonce": "install-a",
            "extension_origin": "chrome-extension://chlorophyll-modern-bread",
        },
    )
    first = client_a.post(
        f"/{_MOUNT_PREFIX.lstrip('/')}/attachments/shared.bin",
        headers={
            "origin": "chrome-extension://chlorophyll-modern-bread",
            "authorization": "Bearer install-a",
        },
    )
    assert first.status_code == 200
    first_body = first.json()

    app_b = _wire_fastapi_app(pairing_nonce="install-b")
    client_b = TestClient(app_b, follow_redirects=False)
    client_b.post(
        f"/{_MOUNT_PREFIX.lstrip('/')}/pair",
        json={
            "presented_nonce": "install-b",
            "extension_origin": "chrome-extension://chlorophyll-modern-bread",
        },
    )
    second = client_b.post(
        f"/{_MOUNT_PREFIX.lstrip('/')}/attachments/shared.bin",
        headers={
            "origin": "chrome-extension://chlorophyll-modern-bread",
            "authorization": "Bearer install-b",
        },
    )
    assert second.status_code == 200
    second_body = second.json()

    assert first_body["attachment_id"] != second_body["attachment_id"]
    assert first_body["sha256"] != second_body["sha256"]
    assert first_body["size_bytes"] == second_body["size_bytes"]

    third_app = _wire_fastapi_app(pairing_nonce="install-a")
    third_client = TestClient(third_app, follow_redirects=False)
    third_client.post(
        f"/{_MOUNT_PREFIX.lstrip('/')}/pair",
        json={
            "presented_nonce": "install-a",
            "extension_origin": "chrome-extension://chlorophyll-modern-bread",
        },
    )
    third = third_client.post(
        f"/{_MOUNT_PREFIX.lstrip('/')}/attachments/other.bin",
        headers={
            "origin": "chrome-extension://chlorophyll-modern-bread",
            "authorization": "Bearer install-a",
        },
    )
    assert third.status_code == 200
    third_body = third.json()
    assert first_body["attachment_id"] != third_body["attachment_id"]
    assert first_body["sha256"] != third_body["sha256"]
    assert first_body["size_bytes"] == third_body["size_bytes"]


def test_attachment_metadata_is_stable_for_same_inputs() -> None:
    app = _wire_fastapi_app(pairing_nonce="install-x")
    client = TestClient(app, follow_redirects=False)
    client.post(
        f"/{_MOUNT_PREFIX.lstrip('/')}/pair",
        json={
            "presented_nonce": "install-x",
            "extension_origin": "chrome-extension://chlorophyll-modern-bread",
        },
    )
    call_a = client.post(
        f"/{_MOUNT_PREFIX.lstrip('/')}/attachments/stable.bin",
        headers={
            "origin": "chrome-extension://chlorophyll-modern-bread",
            "authorization": "Bearer install-x",
        },
    )
    assert call_a.status_code == 200
    body_a = call_a.json()

    call_b = client.post(
        f"/{_MOUNT_PREFIX.lstrip('/')}/attachments/stable.bin",
        headers={
            "origin": "chrome-extension://chlorophyll-modern-bread",
            "authorization": "Bearer install-x",
        },
    )
    assert call_b.status_code == 200
    body_b = call_b.json()

    assert body_a["attachment_id"] == body_b["attachment_id"]
    assert body_a["sha256"] == body_b["sha256"]
    assert body_a["size_bytes"] == body_b["size_bytes"]
    assert isinstance(body_a["attachment_id"], str) and body_a[
        "attachment_id"
    ].startswith("att_")
    assert isinstance(body_a["sha256"], str) and len(body_a["sha256"]) == 64
    assert isinstance(body_a["size_bytes"], int) and body_a["size_bytes"] > 0


def test_sanitize_attachment_keeps_id_and_rejects_non_dicts() -> None:
    backend = StageBBackend(
        credentials_path=Path("dummy-creds.json"),
        token_path=Path("dummy-token.json"),
        pairing_nonce=_NONCE,
    )
    raw = {
        "id": "att-1",
        "size": 100,
        "mimeType": "image/png",
        "filename": "x.png",
    }
    safe = backend._sanitize_attachment(raw)
    assert isinstance(safe, dict)
    assert safe["id"] == "att-1"
    assert safe["size"] == 100
    assert safe["mimeType"] == "image/png"
    assert safe["filename"] == "x.png"
    assert backend._sanitize_attachment("not-a-dict") is None
    assert backend._sanitize_attachment([]) is None
    assert backend._sanitize_attachment({}) is None
    assert backend._sanitize_attachment({"name": "x"}) is None


def test_sanitize_attachment_renames_attachmentId_to_id() -> None:
    backend = StageBBackend(
        credentials_path=Path("dummy-creds.json"),
        token_path=Path("dummy-token.json"),
        pairing_nonce=_NONCE,
    )
    raw = {"attachmentId": "att-2", "size": 200}
    safe = backend._sanitize_attachment(raw)
    assert isinstance(safe, dict)
    assert safe["id"] == "att-2"
    assert "attachmentId" not in safe


def test_offer_pairing_rejects_missing_nonce_and_origin() -> None:
    app = _wire_fastapi_app()
    client = TestClient(app, follow_redirects=False)

    no_nonce = client.post(
        f"/{_MOUNT_PREFIX.lstrip('/')}/pair",
        json={
            "extension_origin": "chrome-extension://chlorophyll-modern-bread",
            "presented_nonce": _NONCE,
        },
    )
    assert no_nonce.status_code == 200, no_nonce.json()

    no_origin = client.post(
        f"/{_MOUNT_PREFIX.lstrip('/')}/pair",
        json={"presented_nonce": _NONCE},
        headers={"origin": "chrome-extension://chlorophyll-modern-bread"},
    )
    assert no_origin.status_code == 400
    assert "extension_origin" in no_origin.json()["error"].lower()

    wrong_extension_origin = client.post(
        f"/{_MOUNT_PREFIX.lstrip('/')}/pair",
        json={
            "presented_nonce": _NONCE,
            "extension_origin": "http://localhost:9876",
        },
        headers={"origin": "chrome-extension://chlorophyll-modern-bread"},
    )
    assert wrong_extension_origin.status_code == 403
    assert wrong_extension_origin.json()["error"] == "Extension origin not allowed"

    wrong_pairing_nonce = client.post(
        f"/{_MOUNT_PREFIX.lstrip('/')}/pair",
        json={
            "presented_nonce": "wrong-pairing-nonce",
            "extension_origin": "chrome-extension://chlorophyll-modern-bread",
        },
        headers={"origin": "chrome-extension://chlorophyll-modern-bread"},
    )
    assert wrong_pairing_nonce.status_code == 403
    assert wrong_pairing_nonce.json()["error"] == "Pairing nonce rejected"
    assert wrong_pairing_nonce.json()["hint"].startswith(
        "PAIRING NONCE EXPOSED: STOP"
    )
    assert app.extra["_stage_b"].nonces_exposed >= 1

    correct = client.post(
        f"/{_MOUNT_PREFIX.lstrip('/')}/pair",
        json={
            "presented_nonce": _NONCE,
            "extension_origin": "chrome-extension://chlorophyll-modern-bread",
        },
        headers={"origin": "chrome-extension://chlorophyll-modern-bread"},
    )
    assert correct.status_code == 200
    assert correct.json()["state"] == "paired"
    assert (
        correct.json()["origin_validated"]
        == "chrome-extension://chlorophyll-modern-bread"
    )


def test_offer_pairing_rejects_missing_extension_origin_field() -> None:
    app = _wire_fastapi_app()
    client = TestClient(app, follow_redirects=False)

    no_origin_key = client.post(
        f"/{_MOUNT_PREFIX.lstrip('/')}/pair",
        json={"presented_nonce": _NONCE},
        headers={"origin": "chrome-extension://chlorophyll-modern-bread"},
    )
    assert no_origin_key.status_code == 400
    assert "extension_origin" in no_origin_key.json()["error"].lower()

    explicit_none = client.post(
        f"/{_MOUNT_PREFIX.lstrip('/')}/pair",
        json={"presented_nonce": _NONCE, "extension_origin": None},
        headers={"origin": "chrome-extension://chlorophyll-modern-bread"},
    )
    assert explicit_none.status_code == 400
    assert "extension_origin" in explicit_none.json()["error"].lower()


def test_offer_pairing_rejects_blank_pairing_nonce() -> None:
    app = _wire_fastapi_app()
    client = TestClient(app, follow_redirects=False)

    for bad in ("", "   "):
        resp = client.post(
            f"/{_MOUNT_PREFIX.lstrip('/')}/pair",
            json={
                "presented_nonce": bad,
                "extension_origin": "chrome-extension://chlorophyll-modern-bread",
            },
        )
        assert resp.status_code == 400
        assert "nonce" in resp.json()["error"].lower()


def test_offer_pairing_rejects_blank_extension_origin() -> None:
    app = _wire_fastapi_app()
    client = TestClient(app, follow_redirects=False)

    for bad in ("", "   "):
        resp = client.post(
            f"/{_MOUNT_PREFIX.lstrip('/')}/pair",
            json={
                "presented_nonce": _NONCE,
                "extension_origin": bad,
            },
        )
        assert resp.status_code == 400
        assert "extension_origin" in resp.json()["error"].lower()


def test_pairing_page_response_never_exposes_pairing_nonce() -> None:
    app = _wire_fastapi_app()
    client = TestClient(app, follow_redirects=False)

    for bad in ("", "wrong", "   "):
        resp = client.post(
            f"/{_MOUNT_PREFIX.lstrip('/')}/pair",
            json={
                "presented_nonce": bad,
                "extension_origin": "chrome-extension://chlorophyll-modern-bread",
            },
        )
        body = resp.json()
        assert _NONCE not in json.dumps(body)
        assert "pairing_nonce" not in body

    good = client.post(
        f"/{_MOUNT_PREFIX.lstrip('/')}/pair",
        json={
            "presented_nonce": _NONCE,
            "extension_origin": "chrome-extension://chlorophyll-modern-bread",
        },
    )
    good_body = good.json()
    assert _NONCE not in json.dumps(good_body)
    assert "pairing_nonce" not in good_body
    assert good_body["state"] == "paired"


def test_reset_clears_pairing_state() -> None:
    app = _wire_fastapi_app()
    client = TestClient(app, follow_redirects=False)

    client.post(
        f"/{_MOUNT_PREFIX.lstrip('/')}/pair",
        json={
            "presented_nonce": _NONCE,
            "extension_origin": "chrome-extension://chlorophyll-modern-bread",
        },
    )
    first_reset = client.post(
        f"/{_MOUNT_PREFIX.lstrip('/')}/reset",
        headers={"origin": "chrome-extension://chlorophyll-modern-bread"},
    )
    assert first_reset.status_code == 200
    assert first_reset.json()["state"] == "unpaired"
    assert first_reset.json()["paired"] is False
    assert first_reset.json()["pairing_nonce_exposed"] is False
    assert (
        first_reset.json()["reset_at"].endswith("Z")
        or "+" in first_reset.json()["reset_at"]
    )

    after_reset_state = client.post(
        f"/{_MOUNT_PREFIX.lstrip('/')}/ping",
        headers={"origin": "chrome-extension://chlorophyll-modern-bread"},
    )
    assert after_reset_state.status_code == 403


def test_pairing_state_is_idempotent_after_reset() -> None:
    app = _wire_fastapi_app()
    client = TestClient(app, follow_redirects=False)

    client.post(
        f"/{_MOUNT_PREFIX.lstrip('/')}/pair",
        json={
            "presented_nonce": _NONCE,
            "extension_origin": "chrome-extension://chlorophyll-modern-bread",
        },
    )

    first_reset = client.post(
        f"/{_MOUNT_PREFIX.lstrip('/')}/reset",
        headers={"origin": "chrome-extension://chlorophyll-modern-bread"},
    )
    assert first_reset.status_code == 200
    assert first_reset.json()["state"] == "unpaired"

    second_reset = client.post(
        f"/{_MOUNT_PREFIX.lstrip('/')}/reset",
        headers={"origin": "chrome-extension://chlorophyll-modern-bread"},
    )
    assert second_reset.status_code == 200
    assert second_reset.json()["state"] == "unpaired"

    re_offer = client.post(
        f"/{_MOUNT_PREFIX.lstrip('/')}/pair",
        json={
            "presented_nonce": _NONCE,
            "extension_origin": "chrome-extension://chlorophyll-modern-bread",
        },
    )
    assert re_offer.status_code == 200
    assert re_offer.json()["state"] == "paired"


def test_ping_requires_bearer_token_after_pairing() -> None:
    app = _wire_fastapi_app()
    client = TestClient(app, follow_redirects=False)

    client.post(
        f"/{_MOUNT_PREFIX.lstrip('/')}/pair",
        json={
            "presented_nonce": _NONCE,
            "extension_origin": "chrome-extension://chlorophyll-modern-bread",
        },
    )

    no_bearer = client.post(
        f"/{_MOUNT_PREFIX.lstrip('/')}/ping",
        headers={"origin": "chrome-extension://chlorophyll-modern-bread"},
    )
    assert no_bearer.status_code == 401
    assert no_bearer.json()["error"] == "Missing bearer token"

    wrong_bearer = client.post(
        f"/{_MOUNT_PREFIX.lstrip('/')}/ping",
        headers={
            "origin": "chrome-extension://chlorophyll-modern-bread",
            "authorization": "Bearer wrong-token",
        },
    )
    assert wrong_bearer.status_code == 401
    assert wrong_bearer.json()["error"] == "Bearer token rejected"

    good_bearer = client.post(
        f"/{_MOUNT_PREFIX.lstrip('/')}/ping",
        headers={
            "origin": "chrome-extension://chlorophyll-modern-bread",
            "authorization": "Bearer %s" % _NONCE,
        },
    )
    assert good_bearer.status_code == 200
    body = good_bearer.json()
    assert body["state"] == "paired"
    assert body["status"] == "ok"
    assert (
        _feed_name_from_token(_NONCE) == body["feed_name_prefix"]
    )


def test_ping_require_bearer_after_pairing_matches_stage_b_backend_api() -> None:
    app = _wire_fastapi_app()
    client = TestClient(app, follow_redirects=False)

    client.post(
        f"/{_MOUNT_PREFIX.lstrip('/')}/pair",
        json={
            "presented_nonce": _NONCE,
            "extension_origin": "chrome-extension://chlorophyll-modern-bread",
        },
    )

    handler = app.extra["_stage_b"]
    origin = "chrome-extension://chlorophyll-modern-bread"
    raw_req = _mock_request(origin=origin, authorization=None)
    resp = handler.ping(raw_req)
    assert resp.status_code == 401
    assert json.loads(resp.body.decode("utf-8")) == {"error": "Missing bearer token"}

    raw_req2 = _mock_request(origin=origin, authorization="Bearer wrong")
    resp2 = handler.ping(raw_req2)
    assert resp2.status_code == 401
    assert json.loads(resp2.body.decode("utf-8")) == {"error": "Bearer token rejected"}

    raw_req3 = _mock_request(
        origin=origin, authorization="Bearer %s" % _NONCE
    )
    resp3 = handler.ping(raw_req3)
    assert resp3.status_code == 200
    assert (
        json.loads(resp3.body.decode("utf-8"))["feed_name_prefix"]
        == _feed_name_from_token(_NONCE)
    )


def test_empty_nonzero_nonces_rejected_at_pairing_page() -> None:
    app = _wire_fastapi_app()
    client = TestClient(app, follow_redirects=False)

    for bad in ("", "   ", None):
        resp = client.post(
            f"/{_MOUNT_PREFIX.lstrip('/')}/pair",
            json={
                "extension_origin": "chrome-extension://chlorophyll-modern-bread",
                "presented_nonce": bad,
            },
        )
        assert resp.status_code in (400, 403), (bad, resp.json())
        body = resp.json()
        assert "nonce" in body["error"].lower() or body["error"].lower().startswith(
            "pairing nonce"
        )


def test_paired_after_reset_only_reappears_after_re_offer() -> None:
    app = _wire_fastapi_app()
    client = TestClient(app, follow_redirects=False)

    client.post(
        f"/{_MOUNT_PREFIX.lstrip('/')}/pair",
        json={
            "extension_origin": "chrome-extension://chlorophyll-modern-bread",
            "presented_nonce": _NONCE,
        },
    )
    first_ping = client.post(
        f"/{_MOUNT_PREFIX.lstrip('/')}/ping",
        headers={
            "origin": "chrome-extension://chlorophyll-modern-bread",
            "authorization": "Bearer %s" % _NONCE,
        },
    )
    assert first_ping.status_code == 200

    client.post(
        f"/{_MOUNT_PREFIX.lstrip('/')}/reset",
        headers={"origin": "chrome-extension://chlorophyll-modern-bread"},
    )

    after_reset = client.post(
        f"/{_MOUNT_PREFIX.lstrip('/')}/ping",
        headers={
            "origin": "chrome-extension://chlorophyll-modern-bread",
            "authorization": "Bearer %s" % _NONCE,
        },
    )
    assert after_reset.status_code == 403
    assert after_reset.json()["error"] == "Not paired with an extension"

    client.post(
        f"/{_MOUNT_PREFIX.lstrip('/')}/pair",
        json={
            "extension_origin": "chrome-extension://chlorophyll-modern-bread",
            "presented_nonce": _NONCE,
        },
    )
    again = client.post(
        f"/{_MOUNT_PREFIX.lstrip('/')}/ping",
        headers={
            "origin": "chrome-extension://chlorophyll-modern-bread",
            "authorization": "Bearer %s" % _NONCE,
        },
    )
    assert again.status_code == 200
    assert again.json()["state"] == "paired"


def test_reset_accepts_valid_extension_origin() -> None:
    app = _wire_fastapi_app()
    client = TestClient(app, follow_redirects=False)

    client.post(
        f"/{_MOUNT_PREFIX.lstrip('/')}/pair",
        json={
            "extension_origin": "chrome-extension://chlorophyll-modern-bread",
            "presented_nonce": _NONCE,
        },
    )

    reset_no_origin = client.post(f"/{_MOUNT_PREFIX.lstrip('/')}/reset")
    assert reset_no_origin.status_code == 200

    reset_bad_origin = client.post(
        f"/{_MOUNT_PREFIX.lstrip('/')}/reset",
        headers={"origin": "chrome-extension://not-installed"},
    )
    assert reset_bad_origin.status_code == 403

    reset_ok_with_origin = client.post(
        f"/{_MOUNT_PREFIX.lstrip('/')}/reset",
        headers={"origin": "chrome-extension://chlorophyll-modern-bread"},
    )
    assert reset_ok_with_origin.status_code == 200
    assert reset_ok_with_origin.json()["state"] == "unpaired"


def test_regex_origin_rejects_http_localhost_with_port() -> None:
    assert (
        _origin_matches(
            "http://localhost:9999", ALLOWED_EXTENSION_ORIGINS
        )
        is False
    )


def test_origin_missing_or_empty_is_rejected_anywhere_it_is_checked() -> None:
    """The backend treats a missing or empty origin the same as a disallowed origin
    everywhere it checks origin (pairing, ping, reset), so the first failing request
    still returns a status code under the extension retry ceiling."""
    app = _wire_fastapi_app()
    client = TestClient(app, follow_redirects=False)

    empty = client.post(
        f"/{_MOUNT_PREFIX.lstrip('/')}/pair", json={"presented_nonce": _NONCE}
    )
    assert empty.status_code in (400, 403), empty.json()

    handler = app.extra["_stage_b"]
    for _path in (
        f"/{_MOUNT_PREFIX.lstrip('/')}/feed",
        f"/{_MOUNT_PREFIX.lstrip('/')}/attachments/binary.bin",
    ):
        bad_origin = _mock_request(origin="")
        with pytest.raises(HTTPException):
            handler._require_paired(bad_origin)


def test_ping_backend_returns_feed_name_prefix() -> None:
    app = _wire_fastapi_app()
    client = TestClient(app, follow_redirects=False)

    client.post(
        f"/{_MOUNT_PREFIX.lstrip('/')}/pair",
        json={
            "presented_nonce": _NONCE,
            "extension_origin": "chrome-extension://chlorophyll-modern-bread",
        },
    )

    resp = client.post(
        f"/{_MOUNT_PREFIX.lstrip('/')}/ping",
        headers={
            "origin": "chrome-extension://chlorophyll-modern-bread",
            "authorization": "Bearer %s" % _NONCE,
        },
    )
    assert resp.status_code == 200
    assert _feed_name_from_token(_NONCE) == resp.json()["feed_name_prefix"]


def test_attachment_endpoint_rejects_unpaired() -> None:
    app = _wire_fastapi_app()
    client = TestClient(app, follow_redirects=False)

    resp = client.post(
        f"/{_MOUNT_PREFIX.lstrip('/')}/attachments/weird.bin",
        json={"max_results": 1},
    )
    assert resp.status_code in (400, 401, 403), resp.json()


def test_attachment_endpoint_rejects_non_bin_extensions() -> None:
    app = _wire_fastapi_app()
    client = TestClient(app, follow_redirects=False)

    client.post(
        f"/{_MOUNT_PREFIX.lstrip('/')}/pair",
        json={
            "presented_nonce": _NONCE,
            "extension_origin": "chrome-extension://chlorophyll-modern-bread",
        },
    )

    txt = client.post(
        f"/{_MOUNT_PREFIX.lstrip('/')}/attachments/evil.txt",
        json={"max_results": 1},
        headers={
            "origin": "chrome-extension://chlorophyll-modern-bread",
            "authorization": "Bearer %s" % _NONCE,
        },
    )
    assert txt.status_code == 400
    assert (
        txt.json()["error"]
        == "Only .bin attachments are served by this backend"
    )


def test_attachment_endpoint_rejects_path_traversal() -> None:
    app = _wire_fastapi_app()
    client = TestClient(app, follow_redirects=False)

    client.post(
        f"/{_MOUNT_PREFIX.lstrip('/')}/pair",
        json={
            "presented_nonce": _NONCE,
            "extension_origin": "chrome-extension://chlorophyll-modern-bread",
        },
    )

    traversal = client.post(
        f"/{_MOUNT_PREFIX.lstrip('/')}/attachments/..%2Ftoken.json.bin",
        json={"max_results": 1},
        headers={
            "origin": "chrome-extension://chlorophyll-modern-bread",
            "authorization": "Bearer %s" % _NONCE,
        },
    )
    assert traversal.status_code == 400
    assert "Invalid attachment filename" in traversal.json()["error"]


def test_attachment_endpoint_rejects_absolute_paths() -> None:
    app = _wire_fastapi_app()
    client = TestClient(app, follow_redirects=False)

    client.post(
        f"/{_MOUNT_PREFIX.lstrip('/')}/pair",
        json={
            "presented_nonce": _NONCE,
            "extension_origin": "chrome-extension://chlorophyll-modern-bread",
        },
    )

    absolute = client.post(
        f"/{_MOUNT_PREFIX.lstrip('/')}/attachments//etc/passwd.bin",
        json={"max_results": 1},
        headers={
            "origin": "chrome-extension://chlorophyll-modern-bread",
            "authorization": "Bearer %s" % _NONCE,
        },
    )
    assert absolute.status_code == 400
    assert "Invalid attachment filename" in absolute.json()["error"]


def test_attachment_endpoint_returns_readonly_metadata() -> None:
    app = _wire_fastapi_app()
    client = TestClient(app, follow_redirects=False)

    client.post(
        f"/{_MOUNT_PREFIX.lstrip('/')}/pair",
        json={
            "presented_nonce": _NONCE,
            "extension_origin": "chrome-extension://chlorophyll-modern-bread",
        },
    )

    resp = client.post(
        f"/{_MOUNT_PREFIX.lstrip('/')}/attachments/sample-attachment.bin",
        json={"max_results": 1},
        headers={
            "origin": "chrome-extension://chlorophyll-modern-bread",
            "authorization": "Bearer %s" % _NONCE,
        },
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ok"
    assert body["filename"] == "sample-attachment.bin"
    assert body["mime"] == "application/octet-stream"
    assert body["read_only"] is True
    assert isinstance(body["sha256"], str) and len(body["sha256"]) == 64
    assert isinstance(body["size_bytes"], int) and body["size_bytes"] > 0
    assert isinstance(body["attachment_id"], str) and body[
        "attachment_id"
    ].startswith("att_")
    assert "fetched_at" in body


def test_attachment_metadata_is_paired_nonce_bound() -> None:
    first_nonce = "first-install-nonce"
    second_nonce = "second-install-nonce"

    first_app = _wire_fastapi_app(pairing_nonce=first_nonce)
    first_client = TestClient(first_app, follow_redirects=False)
    first_client.post(
        f"/{_MOUNT_PREFIX.lstrip('/')}/pair",
        json={
            "presented_nonce": first_nonce,
            "extension_origin": "chrome-extension://chlorophyll-modern-bread",
        },
    )
    first = first_client.post(
        f"/{_MOUNT_PREFIX.lstrip('/')}/attachments/shared-name.bin",
        json={"max_results": 1},
        headers={
            "origin": "chrome-extension://chlorophyll-modern-bread",
            "authorization": "Bearer %s" % first_nonce,
        },
    )
    assert first.status_code == 200
    body = first.json()
    attachment_id = body["attachment_id"]
    sha = body["sha256"]
    size = body["size_bytes"]

    second_app = _wire_fastapi_app(pairing_nonce=second_nonce)
    second_client = TestClient(second_app, follow_redirects=False)
    second_client.post(
        f"/{_MOUNT_PREFIX.lstrip('/')}/pair",
        json={
            "presented_nonce": second_nonce,
            "extension_origin": "chrome-extension://chlorophyll-modern-bread",
        },
    )
    second = second_client.post(
        f"/{_MOUNT_PREFIX.lstrip('/')}/attachments/shared-name.bin",
        json={"max_results": 1},
        headers={
            "origin": "chrome-extension://chlorophyll-modern-bread",
            "authorization": "Bearer %s" % second_nonce,
        },
    )
    assert second.status_code == 200
    second_body = second.json()
    assert second_body["attachment_id"] != attachment_id
    assert second_body["sha256"] != sha
    assert second_body["size_bytes"] == size


def test_attachment_metadata_is_filename_bound() -> None:
    app = _wire_fastapi_app()
    client = TestClient(app, follow_redirects=False)

    client.post(
        f"/{_MOUNT_PREFIX.lstrip('/')}/pair",
        json={
            "presented_nonce": _NONCE,
            "extension_origin": "chrome-extension://chlorophyll-modern-bread",
        },
    )

    first = client.post(
        f"/{_MOUNT_PREFIX.lstrip('/')}/attachments/one.bin",
        json={"max_results": 1},
        headers={
            "origin": "chrome-extension://chlorophyll-modern-bread",
            "authorization": "Bearer %s" % _NONCE,
        },
    )
    assert first.status_code == 200
    a = first.json()

    second = client.post(
        f"/{_MOUNT_PREFIX.lstrip('/')}/attachments/two.bin",
        json={"max_results": 1},
        headers={
            "origin": "chrome-extension://chlorophyll-modern-bread",
            "authorization": "Bearer %s" % _NONCE,
        },
    )
    assert second.status_code == 200
    b = second.json()

    assert a["attachment_id"] != b["attachment_id"]
    assert a["sha256"] != b["sha256"]
    assert a["size_bytes"] == b["size_bytes"]


def test_attachment_hashes_are_stable_across_calls() -> None:
    app = _wire_fastapi_app()
    client = TestClient(app, follow_redirects=False)

    client.post(
        f"/{_MOUNT_PREFIX.lstrip('/')}/pair",
        json={
            "presented_nonce": _NONCE,
            "extension_origin": "chrome-extension://chlorophyll-modern-bread",
        },
    )

    calls = []
    for _ in range(3):
        resp = client.post(
            f"/{_MOUNT_PREFIX.lstrip('/')}/attachments/stable.bin",
            json={"max_results": 1},
            headers={
                "origin": "chrome-extension://chlorophyll-modern-bread",
                "authorization": "Bearer %s" % _NONCE,
            },
        )
        assert resp.status_code == 200
        calls.append(resp.json())

    assert (
        calls[0]["sha256"]
        == calls[1]["sha256"]
        == calls[2]["sha256"]
    )
    assert (
        calls[0]["attachment_id"]
        == calls[1]["attachment_id"]
        == calls[2]["attachment_id"]
    )
    assert (
        calls[0]["size_bytes"]
        == calls[1]["size_bytes"]
        == calls[2]["size_bytes"]
    )


def test_attachment_endpoint_rejects_after_reset() -> None:
    app = _wire_fastapi_app()
    client = TestClient(app, follow_redirects=False)

    client.post(
        f"/{_MOUNT_PREFIX.lstrip('/')}/pair",
        json={
            "presented_nonce": _NONCE,
            "extension_origin": "chrome-extension://chlorophyll-modern-bread",
        },
    )
    client.post(
        f"/{_MOUNT_PREFIX.lstrip('/')}/reset",
        headers={"origin": "chrome-extension://chlorophyll-modern-bread"},
    )

    resp = client.post(
        f"/{_MOUNT_PREFIX.lstrip('/')}/attachments/anything.bin",
        json={"max_results": 1},
        headers={
            "origin": "chrome-extension://chlorophyll-modern-bread",
            "authorization": "Bearer %s" % _NONCE,
        },
    )
    assert resp.status_code == 403
    assert resp.json()["error"] == "Not paired with an extension"


# ---------------------------------------------------------------------------
# Focused security review additions (Stage C gate).
# Each test pins a specific property identified during the review. Existing
# security tests above are unchanged.
# ---------------------------------------------------------------------------


def test_nonce_comparison_rejects_non_ascii_and_diff_length_without_crashing() -> None:
    """The constant-time nonce comparison must fail closed, never raise, for
    non-ASCII or mismatched-length input (a timing/error oracle would leak)."""
    assert _nonce_matches(_NONCE, _NONCE) is True
    assert _nonce_matches("wrong", _NONCE) is False
    assert _nonce_matches("", _NONCE) is False
    assert _nonce_matches("\u00e9", _NONCE) is False  # non-ASCII must not raise
    assert _nonce_matches(_NONCE + "x", _NONCE) is False

    backend = StageBBackend(
        credentials_path=Path("dummy-creds.json"),
        token_path=Path("dummy-token.json"),
        pairing_nonce=_NONCE,
    )
    # A non-ASCII presented nonce is rejected, not crashed on.
    resp = backend.offer_pairing(
        _mock_request(origin="chrome-extension://id"),
        presented_nonce="\u00e9",
        extension_origin="chrome-extension://id",
    )
    assert resp.status_code == 403
    assert backend.state == "unpaired"


def test_pinned_extension_id_rejects_other_extension_ids(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When an extension ID is pinned, identity becomes an exact origin match;
    any other extension under the chrome-extension:// scheme is refused."""
    monkeypatch.setenv(_PINNED_EXTENSION_ID_ENV, "legitimateextensionid")
    assert _origin_allowed("chrome-extension://legitimateextensionid") is True
    assert _origin_allowed("chrome-extension://evil-extension-id") is False
    assert _origin_allowed("https://evil.example") is False

    backend = StageBBackend(
        credentials_path=Path("dummy-creds.json"),
        token_path=Path("dummy-token.json"),
        pairing_nonce=_NONCE,
    )
    rejected = backend.offer_pairing(
        _mock_request(origin="chrome-extension://evil"),
        presented_nonce=_NONCE,
        extension_origin="chrome-extension://evil",
    )
    assert rejected.status_code == 403
    assert backend.state == "unpaired"

    accepted = backend.offer_pairing(
        _mock_request(origin="chrome-extension://legitimateextensionid"),
        presented_nonce=_NONCE,
        extension_origin="chrome-extension://legitimateextensionid",
    )
    assert accepted.status_code == 200
    assert backend.state == "paired"


def test_no_pin_keeps_any_extension_origin_allowed() -> None:
    """Without a pinned ID the scheme prefix is accepted (default dev behavior)."""
    assert _origin_allowed("chrome-extension://anything") is True
    assert _origin_allowed("http://localhost") is False


def test_attachment_route_returns_metadata_only_not_content() -> None:
    """The attachment endpoint must serve metadata only; no content/bytes field
    may ever be returned (simulation-only, no file is read)."""
    app = _wire_fastapi_app()
    client = TestClient(app, follow_redirects=False)
    client.post(
        f"/{_MOUNT_PREFIX.lstrip('/')}/pair",
        json={
            "presented_nonce": _NONCE,
            "extension_origin": "chrome-extension://chlorophyll-modern-bread",
        },
    )
    resp = client.post(
        f"/{_MOUNT_PREFIX.lstrip('/')}/attachments/sample.bin",
        headers={
            "origin": "chrome-extension://chlorophyll-modern-bread",
            "authorization": "Bearer %s" % _NONCE,
        },
    )
    assert resp.status_code == 200
    body = resp.json()
    for forbidden in ("content", "data", "bytes", "body", "file", "blob"):
        assert forbidden not in body, body
    assert set(body) >= {
        "status",
        "filename",
        "mime",
        "size_bytes",
        "sha256",
        "attachment_id",
        "read_only",
        "fetched_at",
    }


def test_serve_refuses_non_loopback_host(capsys: pytest.CaptureFixture[str]) -> None:
    """The serve command must refuse to bind anything but loopback in this stage."""
    rc = _serve(host="0.0.0.0")
    assert rc != 0
    captured = capsys.readouterr()
    assert "non-loopback" in captured.err.lower()


def test_offer_pairing_binds_body_origin_not_header() -> None:
    """Pairing identity comes from the body extension_origin; a spoofed Origin
    header alone cannot choose the bound origin."""
    app = _wire_fastapi_app()
    client = TestClient(app, follow_redirects=False)
    resp = client.post(
        f"/{_MOUNT_PREFIX.lstrip('/')}/pair",
        json={
            "presented_nonce": _NONCE,
            "extension_origin": "chrome-extension://chlorophyll-modern-bread",
        },
        headers={"origin": "chrome-extension://some-other-header-origin"},
    )
    assert resp.status_code == 200
    assert resp.json()["origin_validated"] == "chrome-extension://chlorophyll-modern-bread"
    handler = app.extra["_stage_b"]
    assert handler.paired_origin == "chrome-extension://chlorophyll-modern-bread"


def test_feed_serializes_real_email_model_fields(monkeypatch: pytest.MonkeyPatch) -> None:
    """Regression: /feed must serialize the actual ``Email`` model fields.

    A live test once surfaced ``'Email' object has no attribute 'snippet'``
    because the serializer referenced fields the model does not define. This
    drives the real serialization path with real ``Email`` objects (no network)
    so the field mapping cannot silently break again.
    """
    import backend.stage_b as sb

    real_emails = [
        Email(
            id="msg-1",
            sender="alice@example.com",
            subject="Hello",
            body="Body line one.\r\nBody line two.",
            labels=["NEMESIS_DEMO"],
            received_at="Thu, 15 Oct 2026 13:41:21 +0530",
        ),
        Email(id="msg-2", sender="bob@example.com", subject="Second", body="x"),
    ]

    class _Creds:
        pass

    monkeypatch.setattr(sb, "get_credentials", lambda **kw: _Creds())
    monkeypatch.setattr(sb, "build_gmail_service", lambda creds: object())
    monkeypatch.setattr(
        sb, "fetch_nemesis_demo_emails", lambda service, max_results: real_emails
    )

    app = _wire_fastapi_app()
    client = TestClient(app, follow_redirects=False)
    origin = "chrome-extension://chlorophyll-modern-bread"
    client.post(
        f"/{_MOUNT_PREFIX.lstrip('/')}/pair",
        json={"presented_nonce": _NONCE, "extension_origin": origin},
    )
    resp = client.post(
        f"/{_MOUNT_PREFIX.lstrip('/')}/feed",
        json={"max_results": 5},
        headers={"origin": origin, "authorization": "Bearer %s" % _NONCE},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["status"] == "ok"
    assert body["email_count"] == 2
    first = body["emails"][0]
    assert first["id"] == "msg-1"
    assert first["sender"] == "alice@example.com"
    assert first["subject"] == "Hello"
    assert first["body_text"] == "Body line one.\r\nBody line two."
    assert first["raw_body_chars"] == len("Body line one.\r\nBody line two.")
    assert first["labels"] == ["NEMESIS_DEMO"]
    assert first["received_at"] == "Thu, 15 Oct 2026 13:41:21 +0530"
    assert isinstance(first["snippet"], str) and first["snippet"]
    # The nonce never appears in the serialized feed.
    assert _NONCE not in json.dumps(body)


def test_pairing_never_leaks_nonce_even_on_wrong_length_attempt() -> None:
    """A wrong-length nonce attempt must not reveal the real nonce in the response."""
    app = _wire_fastapi_app()
    client = TestClient(app, follow_redirects=False)
    resp = client.post(
        f"/{_MOUNT_PREFIX.lstrip('/')}/pair",
        json={
            "presented_nonce": _NONCE + "-suffix",
            "extension_origin": "chrome-extension://chlorophyll-modern-bread",
        },
    )
    assert resp.status_code == 403
    body = resp.json()
    assert _NONCE not in json.dumps(body)
    assert "pairing_nonce" not in body


# ---------------------------------------------------------------------------
# /analyze: success wrapper and honest model-failure mapping
# ---------------------------------------------------------------------------


def _paired(backend: StageBBackend) -> str:
    origin = "chrome-extension://abcdefghijklmnop"
    backend.present_nonce(_mock_request(origin=origin), _NONCE)
    return origin


def test_analyze_success_returns_per_email_verdicts(backend, monkeypatch) -> None:
    import backend.stage_b as stage_b_mod
    from gmail_auth import DEMO_LABEL

    origin = _paired(backend)
    monkeypatch.setattr(stage_b_mod, "get_credentials", lambda **kw: object())
    monkeypatch.setattr(stage_b_mod, "build_gmail_service", lambda creds: object())
    monkeypatch.setattr(
        stage_b_mod,
        "fetch_nemesis_demo_emails",
        lambda svc, max_results: [
            Email(
                id="e1",
                sender="a@example.com",
                subject="hello",
                body="all good",
                labels=[DEMO_LABEL],
            )
        ],
    )
    monkeypatch.setattr(
        stage_b_mod,
        "_analyze_emails",
        lambda emails: {
            "status": "ok",
            "provider": "gemini",
            "risk_score": 0.4,
            "risk_level": "medium",
            "defense": [
                {"email_id": "e1", "decision": "review", "risk_level": "medium",
                 "risk_score": 0.4, "threat_types": ["prompt_injection"],
                 "indicators": [], "reasons": []}
            ],
            "action_authorization": {
                "performed_actions": [],
                "gmail_writes": "not_permitted",
            },
            "read_only": True,
        },
    )
    resp = backend.analyze_demo_emails(
        _mock_request(
            origin=origin,
            authorization="Bearer %s" % _NONCE,
            json_body={"max_results": 1},
        ),
        1,
    )
    assert resp.status_code == 200
    payload = _payload(resp)
    assert payload["status"] == "ok"
    analysis = payload["analysis"]
    assert analysis["defense"][0]["decision"] == "review"
    assert analysis["action_authorization"]["performed_actions"] == []
    assert analysis["read_only"] is True
    # The pairing nonce must never appear in any analysis response body.
    assert _NONCE not in json.dumps(payload)


def test_analyze_maps_model_failure_to_structured_502(backend, monkeypatch) -> None:
    """A failed model call surfaces as an honest structured error, never as a
    fabricated successful analysis."""
    import backend.stage_b as stage_b_mod
    from gmail_auth import DEMO_LABEL, GeminiAnalysisError

    origin = _paired(backend)
    monkeypatch.setattr(stage_b_mod, "get_credentials", lambda **kw: object())
    monkeypatch.setattr(stage_b_mod, "build_gmail_service", lambda creds: object())
    monkeypatch.setattr(
        stage_b_mod,
        "fetch_nemesis_demo_emails",
        lambda svc, max_results: [
            Email(
                id="e1",
                sender="a@example.com",
                subject="hello",
                body="all good",
                labels=[DEMO_LABEL],
            )
        ],
    )

    def _boom(emails):
        raise GeminiAnalysisError(
            "model call failed after 3 attempt(s) (HTTP 503): upstream unavailable"
        )

    monkeypatch.setattr(stage_b_mod, "_analyze_emails", _boom)
    resp = backend.analyze_demo_emails(
        _mock_request(
            origin=origin,
            authorization="Bearer %s" % _NONCE,
            json_body={"max_results": 1},
        ),
        1,
    )
    assert resp.status_code == 502
    body = _payload(resp)
    assert "HTTP 503" in body["error"]
    assert "analysis" not in body  # no fabricated assessment
    assert _NONCE not in json.dumps(body)


def test_serve_startup_path_binds_loopback_prints_nonce_and_pairs(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Live startup path: ``_serve`` (no real socket) — nonce printed once to
    the terminal only, loopback enforced, fresh app starts unpaired, and the
    printed nonce pairs against THAT instance's app."""
    import uvicorn

    captured: dict[str, object] = {}

    def _fake_run(app, host=None, port=None, **kwargs):
        captured["app"] = app
        captured["host"] = host
        captured["port"] = port

    monkeypatch.setattr(uvicorn, "run", _fake_run)

    rc = _serve(host="127.0.0.1", port=8123)
    assert rc == 0
    out = capsys.readouterr().out

    # Exactly one 64-hex nonce line, printed after the pairing banner.
    lines = out.splitlines()
    nonces = [
        ln
        for ln in lines
        if len(ln) == 64 and all(c in "0123456789abcdef" for c in ln)
    ]
    assert len(nonces) == 1, "nonce must be printed exactly once"
    nonce = nonces[0]
    assert any("Pairing nonce" in ln for ln in lines)
    # Non-loopback binding is refused before uvicorn would run.
    assert captured["host"] == "127.0.0.1"
    assert captured["port"] == 8123

    app = captured["app"]
    client = TestClient(app)

    # Fresh instance: health reports unpaired; nonce is not in any payload.
    health = client.get("/health")
    assert health.status_code == 200
    assert health.json()["state"] == "unpaired"
    assert nonce not in health.text

    # Unpaired requests are rejected.
    origin = "chrome-extension://startuptest123456"
    unpaired = client.post(
        "/api/v1/stage_b/feed",
        json={"max_results": 1},
        headers={"Origin": origin},
    )
    assert unpaired.status_code == 403

    # The terminal-printed nonce pairs THIS instance.
    paired = client.post(
        "/api/v1/stage_b/pair",
        json={"presented_nonce": nonce, "extension_origin": origin},
        headers={"Origin": origin},
    )
    assert paired.status_code == 200
    assert paired.json()["state"] == "paired"
    assert nonce not in paired.text
