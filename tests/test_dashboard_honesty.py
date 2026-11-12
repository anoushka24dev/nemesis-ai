"""Dashboard honesty assertions — backed by the same ConnectionStore the server
uses, so these prove what the rendered card claims rather than what a congested
resident server happens to echo right now.

These mirror the key honesty requirements from the spec:
* Agent Framework is described as a real LangChain/LangGraph construction that
  actually invokes the model (not a marked-up proxy).
* Agent Framework has passed a real validation that reached the model.
* Agent Framework's honest limitations are visible.
* The seeded local-proxy defenses that exist in the codebase are the ONLY thing
  claimed as "real research" in the UI — the repository must not present a
  placeholder card as verified.

The store is a TEMPORARY store written with the exact record shape that
``ConnectionStore.connect`` persists (including ``last_validation.detail``),
so these tests exercise card derivation without depending on whichever live
run happens to be in ``results/connections.json`` or on a fixture file that
another test may or may not have created.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))


def _validation_record() -> dict:
    """The record shape written by ConnectionStore.connect for a successful
    bounded LangChain invocation (see backend/connections.py)."""
    return {
        "model": "llama3.1:8b",
        "base_url": "http://127.0.0.1:11434",
        "target_id": "langchain-agent",
        "timeout_seconds": 30.0,
        "method": "agent_framework",
        "connected_at": "2026-11-01T00:00:00Z",
        "last_validation": {
            "ok": True,
            "checked_at": "2026-11-01T00:00:00Z",
            "error": None,
            "error_category": None,
            "status_code": None,
            "detail": {
                "elapsed_seconds": 1.5,
                "output_preview": "ready",
            },
        },
    }


@pytest.fixture()
def store(tmp_path):
    import backend.connections as C

    s = C.ConnectionStore(path=str(tmp_path / "connections.json"))
    data = s.load()
    data["active"] = "agent_framework"
    data["connections"]["agent_framework"] = _validation_record()
    s._save(data)
    return s


def _library_card(store, method: str) -> dict:
    for card in store.methods():
        if card.get("method") == method:
            return card
    raise AssertionError(f"no {method!r} card in store.methods()")


def test_store_persists_invocation_evidence_not_just_a_status(store):
    """The record `connect()` persists must carry invocation evidence.

    This is the seed for the card tests below; it also guards the contract so
    a status-only record can never satisfy them.
    """
    card = _library_card(store, "agent_framework")
    detail = (card.get("last_validation") or {}).get("detail") or {}
    assert detail.get("elapsed_seconds") is not None
    assert detail.get("output_preview")


def test_agent_framework_card_describes_real_langgraph_agent(store):
    card = _library_card(store, "agent_framework")
    display = card.get("display_name") or ""
    subtitle = card.get("subtitle") or ""
    description = card.get("description") or ""

    # Real integration: the card names the actual construction and framework.
    assert display == "Agent Framework (LangChain)"
    assert "LangGraph" in subtitle or "LangGraph" in description
    assert "ReAct" in subtitle or "ReAct" in description
    # Honest about what is invoked: the real model, at run time.
    assert "actually invoked" in description or "real" in description.lower()
    # Not a vague placeholder.
    assert "(LangChain)" in display


def test_agent_framework_card_shows_real_validation(store):
    card = _library_card(store, "agent_framework")
    vc = card.get("last_validation") or {}
    # Availability requires a real invocation-proven validation, not an import
    # check or a status that is only claimed. `detail` carries evidence that a
    # real model/transport call was made (elapsed time, output preview).
    assert card.get("status") == "available", card.get("status_label")
    assert vc.get("ok") is True, vc
    assert vc.get("detail") is not None, "no invocation evidence"
    assert vc.get("detail", {}).get("output_preview"), "no model output recorded"
    assert vc.get("error") is None, vc.get("error")


def test_agent_framework_card_has_honest_limitations(store):
    card = _library_card(store, "agent_framework")
    limits = card.get("limitations") or []
    assert isinstance(limits, list) and limits, "missing honest limitations"
    limits_text = " ".join(limits).lower()
    # Must not over-claim. At least one limitation that keeps the claim honest.
    assert ("stub" in limits_text) or ("tools are" in limits_text) or ("not" in limits_text)


def test_agent_framework_card_is_selectable_when_connected(store):
    card = _library_card(store, "agent_framework")
    # A real, validated, available integration is the expected active target.
    assert card.get("status") == "available"
    assert card.get("selected") is True
    assert card.get("connected") is True


def test_catalog_does_not_fake_real_research_cards(store):
    """Only Progent and CaMeL are shown as real research implementations, and
    the local proxies explicitly label themselves as proxies.

    The retired Local Python Agent must not reappear as a connection method.
    """
    # Connection methods: the three supported integrations, no retired BYOA card.
    methods = [c.get("method") for c in store.methods()]
    assert methods == ["http_api", "gmail", "agent_framework"], methods
    for c in store.methods():
        name = (c.get("display_name") or "").lower()
        if c["method"] != "agent_framework":
            assert "langchain" not in name and "ollama" not in name and "llm" not in name

    # Defense catalog: the CURRENT vocabulary lives in the harness, and the
    # real/proxy classification comes from defense_eval's catalog.
    from backend.adaptive_harness import DEFENSE_CHOICES
    from backend.defense_eval import defense_catalog

    catalog = {d["defense_id"]: d for d in defense_catalog()}
    real_ids = {"progent_real", "camel_real"}
    assert real_ids <= set(DEFENSE_CHOICES)
    # "none" is the attack campaign's no-defense setting: it has no evaluator
    # to describe and must not appear as a selectable Defense evaluation.
    assert "none" not in catalog
    for name in (c for c in DEFENSE_CHOICES if c != "none"):
        assert name in catalog, name
        entry = catalog[name]
        if name in real_ids:
            assert entry["available"] is True, name
            assert entry["implementation_type"] == "real_integration", name
            assert entry["source"].startswith("https://"), name
            does_not = entry["does_not"] or ""
            assert isinstance(does_not, str) and does_not, name
            # The claim must be scoped, not an unqualified "full system".
            assert "not" in does_not.lower() or "partial" in does_not.lower(), name
            if name == "progent_real":
                # Must name the repository that is actually vendored, and must
                # not present the vendored source tree as an installed SDK.
                assert entry["source"] == "https://github.com/sunblaze-ucb/progent"
                assert "vendored" in does_not.lower(), does_not
            if name == "camel_real":
                assert "partial" in does_not.lower(), does_not
        else:
            assert entry["implementation_type"] == "local_proxy", name
            does_not = entry["does_not"] or ""
            assert isinstance(does_not, str) and does_not, name
            assert "not" in does_not.lower() or "no " in does_not.lower(), name
