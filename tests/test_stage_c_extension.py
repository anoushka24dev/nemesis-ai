# -*- coding: utf-8 -*-
"""Static security and packaging checks for the Stage C Chrome extension.

These are property checks over the extension's on-disk sources. They assert
what MUST be true of a read-only, simulation-only, locally-bundled MV3
extension. They do not require a browser or network.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

EXT = Path(__file__).resolve().parents[1] / "extension"


def _read(name: str) -> str:
    return (EXT / name).read_text(encoding="utf-8")


def _manifest() -> dict:
    return json.loads(_read("manifest.json"))


def test_manifest_is_mv3_and_loads_local_worker() -> None:
    m = _manifest()
    assert m["manifest_version"] == 3
    # Service worker + side panel + content script must all be local paths.
    assert m["background"]["service_worker"] == "background.js"
    assert m["side_panel"]["default_path"] == "sidepanel.html"
    for cs in m["content_scripts"]:
        for js in cs["js"]:
            assert not js.startswith(("http://", "https://", "//")), js
        for match in cs["matches"]:
            assert match.startswith("https://mail.google.com"), match


def test_all_referenced_assets_exist_locally() -> None:
    m = _manifest()
    referenced = [
        m["background"]["service_worker"],
        m["side_panel"]["default_path"],
        *[js for cs in m["content_scripts"] for js in cs["js"]],
        *m["icons"].values(),
    ]
    for ref in referenced:
        path = EXT / ref
        assert path.exists(), f"missing bundled asset: {ref}"
        # No remote references.
        assert not ref.startswith(("http://", "https://", "//")), ref


def test_host_permissions_are_scoped_to_loopback_and_gmail() -> None:
    m = _manifest()
    allowed = {
        "http://127.0.0.1:8123/*",
        "http://localhost:8123/*",
        "https://mail.google.com/*",
    }
    assert set(m["host_permissions"]) == allowed
    # No wildcard-all permission.
    for perm in m["host_permissions"]:
        assert perm != "<all_urls>"
        assert not perm.endswith("://*/")


def test_permissions_do_not_include_gmail_or_web_mail_scopes() -> None:
    m = _manifest()
    perms = set(m["permissions"])
    # The extension never touches the Gmail API, so it must not request the
    # gmail.* or mail permissions that would enable it.
    for forbidden in ("gmailModify", "mail", "tabs", "webRequest", "scripting"):
        assert forbidden not in perms, forbidden


def test_html_references_only_local_scripts_and_styles() -> None:
    html = _read("sidepanel.html")
    # No remote script or stylesheet URLs.
    for tag in re.findall(r"<script[^>]*src=\"([^\"]+)\"", html):
        assert not tag.startswith(("http://", "https://", "//")), tag
    for tag in re.findall(r"<link[^>]*href=\"([^\"]+)\"", html):
        assert not tag.startswith(("http://", "https://", "//")), tag
    # CSP: MV3 default CSP forbids remote code; assert no inline handlers that
    # would require relaxed CSP.
    assert "onclick=" not in html
    assert "onerror=" not in html


def test_no_remote_code_patterns_in_js() -> None:
    for name in ("background.js", "content.js", "sidepanel.js"):
        src = _read(name)
        # No remote fetch/import of executable code.
        assert "importScripts(" not in src, name
        assert not re.search(r"import\s+[^'\"]*from\s+['\"]https?://", src), name
        # No eval-like dynamic code execution.
        assert "eval(" not in src, name
        assert "new Function(" not in src, name


def test_content_script_is_read_only_no_writes_or_mutation() -> None:
    src = _read("content.js")
    # Must not perform any Gmail write/modify/send operation or form submit.
    for forbidden in (
        "document.querySelector('[role=\"button\"]').click",
        ".click()",
        ".submit()",
        "XMLHttpRequest",
        "fetch(",
    ):
        assert forbidden not in src, forbidden
    # It reads the DOM only; assert read helpers exist.
    assert "readSubject" in src
    assert "readBody" in src


def test_sidepanel_never_logs_or_exposes_nonce() -> None:
    src = _read("sidepanel.js")
    # The nonce must not be written to the console.
    assert "console.log" not in src
    assert "console.debug" not in src
    assert "console.info" not in src
    # The nonce input is a password field (not echoed in the DOM).
    html = _read("sidepanel.html")
    nonce_input = re.search(r"<input[^>]*id=\"nonce\"[^>]*>", html)
    assert nonce_input is not None
    assert 'type="password"' in nonce_input.group(0)


def test_sidepanel_only_calls_loopback_backend() -> None:
    src = _read("sidepanel.js")
    # Every fetch target must be the loopback API base.
    assert 'const API_BASE = "http://127.0.0.1:8123/api/v1/stage_b";' in src
    # No other http(s) host is fetched.
    for url in re.findall(r"fetch\(([^)]*)\)", src):
        assert "API_BASE" in url, url


def test_simulated_actions_are_labelled_and_not_executed() -> None:
    content = _read("content.js")
    panel = _read("sidepanel.js")
    # The content script returns simulation text only.
    assert "SIMULATION ONLY" in content
    # The side panel renders the list but never targets a Gmail write endpoint.
    # Match actual quoted request paths (backendPost("...") / fetch("...")), not
    # prose in comments, so a comment mentioning "send" does not false-positive.
    request_paths = re.findall(r"backendPost\(\s*[\"'`]([^\"'`]*)", panel)
    request_paths += re.findall(r"fetch\(\s*[\"']([^\"']*)", panel)
    assert request_paths, "expected at least one backend request"
    for path in request_paths:
        for forbidden in ("send", "modify", "trash", "drafts", "batchModify"):
            assert forbidden not in path, path
    # And the only host ever fetched is the loopback backend.
    for path in request_paths:
        assert path.startswith("/") or "API_BASE" in panel, path


def test_icons_are_valid_pngs() -> None:
    for size in (16, 48, 128):
        data = (EXT / "icons" / f"icon{size}.png").read_bytes()
        assert data[:8] == b"\x89PNG\r\n\x1a\n", size
        assert len(data) > 8, size


def test_panel_is_the_single_action_dashboard() -> None:
    """The approved panel exposes one primary action and no manual analysis or
    compose controls; every backend call still targets the loopback API."""
    html = _read("sidepanel.html")
    js = _read("sidepanel.js")

    assert html.count('id="demo-run-btn"') == 1
    assert "Start Nemesis Demo" in html
    for stale in (
        'id="analyze-provider"', 'id="c-to"', 'id="c-subject"', 'id="c-body"',
        'id="prepare-new-btn"', 'id="submit-btn"', 'id="agent-send-btn"',
    ):
        assert stale not in html, stale

    # No new remote host: the extension still only talks to the loopback API.
    assert 'const API_BASE = "http://127.0.0.1:8123/api/v1/stage_b";' in js
    assert 'backendPost("/nemesis/demo/run"' in js


def test_demo_action_is_honest_about_what_it_starts() -> None:
    html = _read("sidepanel.html")
    js = _read("sidepanel.js")
    text = html.lower()
    assert "architecture" in text
    assert "regression gate" in text
    assert "email" in text
    # The panel separates simulation from live execution.
    assert 'setPill(' in js
    assert 'mode === "LIVE"' in js
    assert "simulation" in text
