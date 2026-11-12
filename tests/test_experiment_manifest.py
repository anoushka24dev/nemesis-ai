"""Phase 2 — the approved experiment configuration manifest.

Covers the validated 26-configuration / 1,300-episode plan: structure,
per-mode counts, unique + stable IDs, seed policy, documented factor
interpretations, secret exclusion, tamper rejection, the CLI validation
command, and the read-only API endpoint. No experiment is ever executed.
"""

from __future__ import annotations

import copy
import json
import os
import subprocess
import sys
from collections import Counter
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from adaptive_agent_eval.contracts import ExperimentConfig
from adaptive_agent_eval.experiment_matrix import (
    ATTACKER_TYPE,
    EPISODES_PER_CONFIG,
    SCHEMA_VERSION,
    TOTAL_CONFIGS,
    TOTAL_EPISODES,
    build_manifest,
    experiment_config_from_entry,
    manifest_summary,
    manifest_to_json,
    validate_manifest,
)
from adaptive_agent_eval.models import (
    DefenseType,
    EpisodeMode,
    IntegrationStatus,
)

_REPO_ROOT = Path(__file__).resolve().parent.parent

_NONCE = "test-pairing-nonce"
_ORIGIN = "chrome-extension://chlorophyll-modern-bread"


# ------------------------------------------------------------------ plan ----


def test_manifest_is_valid():
    assert validate_manifest(build_manifest()) == []


def test_manifest_counts_and_totals():
    manifest = build_manifest()
    configs = manifest["configurations"]
    assert len(configs) == TOTAL_CONFIGS == 26

    counts = Counter(c["mode"] for c in configs)
    assert counts == {
        "single-agent": 12,
        "cross-agent": 6,
        "defense-composition": 8,
    }
    assert sum(c["episodes"] for c in configs) == TOTAL_EPISODES == 1300
    assert all(c["episodes"] == EPISODES_PER_CONFIG == 50 for c in configs)
    assert all(c["max_rounds"] == 5 for c in configs)

    plan = manifest["plan"]
    assert plan["total_configs"] == 26
    assert plan["total_episodes"] == 1300
    assert plan["episodes_per_config"] == 50
    assert "future extension" in plan["note"]  # five-mode plan is NOT active


def test_manifest_ids_unique_and_ordered():
    configs = build_manifest()["configurations"]
    ids = [c["config_id"] for c in configs]
    assert len(set(ids)) == 26
    assert ids[0] == "M1-01" and ids[11] == "M1-12"
    assert ids[12] == "M2-01" and ids[17] == "M2-06"
    assert ids[18] == "M3-01" and ids[25] == "M3-08"


def test_manifest_is_stable_across_builds():
    first = manifest_to_json(build_manifest())
    second = manifest_to_json(build_manifest())
    assert first == second
    # JSON round-trip stays valid and byte-stable.
    reparsed = json.loads(first)
    assert manifest_to_json(reparsed) == first
    assert validate_manifest(reparsed) == []


def test_manifest_seeds_follow_documented_policy():
    configs = build_manifest()["configurations"]
    seeds = [c["seed"] for c in configs]
    assert len(set(seeds)) == 26  # no collisions
    for index, seed in enumerate(seeds, start=1):
        assert seed == index * 1000
    policy = build_manifest()["seed_policy"]
    assert policy["config_seed_formula"] == "config_seed = config_index * 1000"
    assert policy["episode_seed_formula"] == "episode_seed = config_seed + episode_index"
    assert policy["base_seed"] == 42
    assert policy["config_index_scope"] == "global-1-based-position-in-manifest"
    assert "collide" in policy["note"]  # the ambiguity is disclosed


def test_m2_m3_target_tier_interpretation_is_explicit():
    manifest = build_manifest()
    m23 = [
        c
        for c in manifest["configurations"]
        if c["mode"] in ("cross-agent", "defense-composition")
    ]
    assert len(m23) == 14  # 6 Mode 2 + 8 Mode 3
    assert all(c["target_tier"] == "cheap" for c in m23)

    interpretation = next(
        i
        for i in manifest["factor_interpretations"]
        if i["id"] == "target-tier-m2-m3"
    )
    assert interpretation["value"] == "cheap"
    assert "section 2.2 and 3.2 tables have no target-tier" in interpretation["source_silence"]
    assert "Explicit user decision" in interpretation["decision"]
    assert "26-configuration grid" in interpretation["decision"]
    assert "Not inferred" in interpretation["rationale"]

    # Mode 1 keeps the plan's explicit varying target tiers.
    m1 = [c for c in manifest["configurations"] if c["mode"] == "single-agent"]
    assert {c["target_tier"] for c in m1} == {"cheap", "frontier"}


def test_provider_binding_documented_and_secret_free():
    manifest = build_manifest()
    binding = manifest["provider_binding"]
    assert binding["provider"] == "gemini"
    assert binding["cheap_model"] == "gemini-2.5-flash"
    assert binding["frontier_model"] == "gemini-2.5-pro"
    assert "ADR-016" in binding["decision"]
    blob = manifest_to_json(manifest)
    for needle in ("AIza", "sk-", "ghp_", "Bearer ", "api_key", "token", "secret"):
        assert needle not in blob


def test_unsupported_dependencies_declared():
    manifest = build_manifest()
    deps = {d["name"]: d for d in manifest["unsupported_dependencies"]}
    assert deps["agentdojo"]["status"] == "not_installed"
    assert "never reported as real AgentDojo" in deps["agentdojo"]["impact"]
    assert deps["static-baseline-attacker"]["status"] == "planned_phase_4"


def test_every_entry_contracts_into_valid_experiment_config():
    for entry in build_manifest()["configurations"]:
        config = experiment_config_from_entry(entry)
        assert isinstance(config, ExperimentConfig)
        config.validate()  # raises on any problem
        assert config.mode == EpisodeMode(entry["mode"])
        assert config.defenses == tuple(DefenseType(d) for d in entry["defenses"])
        assert config.episodes == 50
        assert config.seed == entry["seed"]
        assert config.attacker_type == ATTACKER_TYPE
        assert config.provider == "gemini"
        assert config.label == entry["config_id"]


def test_summary_never_claims_execution():
    summary = manifest_summary(build_manifest())
    assert summary["kind"] == "configuration_validation_only"
    assert summary["execution"] == "not_started"
    assert summary["episodes_executed"] == 0
    assert summary["valid"] is True
    assert summary["errors"] == []
    assert summary["configurations"] == 26
    assert summary["planned_episodes"] == 1300


# -------------------------------------------------------------- tampering --


def test_validator_rejects_invalid_mode():
    manifest = build_manifest()
    manifest["configurations"][0]["mode"] = "free-for-all"
    errors = validate_manifest(manifest)
    assert any("invalid mode 'free-for-all'" in e for e in errors)


def test_validator_rejects_duplicate_id():
    manifest = build_manifest()
    manifest["configurations"][13]["config_id"] = manifest["configurations"][0]["config_id"]
    errors = validate_manifest(manifest)
    assert any("duplicate config_id" in e for e in errors)


def test_validator_rejects_extra_configuration():
    manifest = build_manifest()
    extra = copy.deepcopy(manifest["configurations"][0])
    extra["config_id"] = "M9-01"
    manifest["configurations"].append(extra)
    errors = validate_manifest(manifest)
    assert any("not in the approved grid" in e for e in errors)
    assert any("expected 26, got 27" in e for e in errors)


def test_validator_reports_missing_configuration():
    manifest = build_manifest()
    removed = manifest["configurations"].pop(5)  # M1-06
    assert removed["config_id"] == "M1-06"
    errors = validate_manifest(manifest)
    assert any("missing intended configuration" in e and "M1-06" in e for e in errors)
    assert any("single-agent': expected 12 configurations, got 11" in e for e in errors)
    assert any("expected 1300" in e for e in errors)


def test_validator_rejects_missing_entry_field():
    manifest = build_manifest()
    del manifest["configurations"][0]["target_tier"]
    errors = validate_manifest(manifest)
    assert any("missing field 'target_tier'" in e for e in errors)


def test_validator_rejects_missing_top_level_field():
    manifest = build_manifest()
    del manifest["seed_policy"]
    errors = validate_manifest(manifest)
    assert errors == ["missing top-level field: seed_policy"]


def test_validator_rejects_wrong_schema_version():
    manifest = build_manifest()
    manifest["schema_version"] = "0.9"
    errors = validate_manifest(manifest)
    assert any("schema_version" in e for e in errors)


def test_validator_rejects_wrong_episode_counts():
    manifest = build_manifest()
    manifest["configurations"][0]["episodes"] = 0
    errors = validate_manifest(manifest)
    assert any("episodes must equal the approved 50" in e for e in errors)
    assert any("total planned episodes" in e for e in errors)


def test_validator_rejects_unsupported_combination():
    manifest = build_manifest()
    manifest["configurations"][3]["agent_setup"] = "multi-agent"  # a Mode 1 row
    errors = validate_manifest(manifest)
    assert any("unsupported combination" in e for e in errors)


def test_validator_rejects_wrong_defense_count_per_mode():
    manifest = build_manifest()
    manifest["configurations"][18]["defenses"] = ["camel"]  # M3-01 needs 2-3
    errors = validate_manifest(manifest)
    assert any("2 or 3 stacked defenses" in e for e in errors)


def test_validator_rejects_secret_key_and_secret_value():
    manifest = build_manifest()
    manifest["configurations"][0]["api_key"] = "not-a-real-key"
    errors = validate_manifest(manifest)
    assert any("secret-like key" in e for e in errors)

    manifest = build_manifest()
    manifest["provider_binding"]["cheap_model"] = "AIza" + "x" * 40
    errors = validate_manifest(manifest)
    assert any("secret-looking value" in e for e in errors)


def test_validator_requires_documented_interpretations():
    manifest = build_manifest()
    manifest["factor_interpretations"] = [
        i
        for i in manifest["factor_interpretations"]
        if i["id"] != "target-tier-m2-m3"
    ]
    errors = validate_manifest(manifest)
    assert any("target-tier-m2-m3" in e for e in errors)


def test_validator_rejects_plan_tampering():
    manifest = build_manifest()
    manifest["plan"]["total_episodes"] = 1900  # the five-mode plan
    errors = validate_manifest(manifest)
    assert any("plan.total_episodes" in e for e in errors)


def test_validator_rejects_seed_policy_violation():
    manifest = build_manifest()
    manifest["configurations"][7]["seed"] = 1000  # collides with M1-01's seed
    errors = validate_manifest(manifest)
    assert any("collides" in e or "violates the manifest seed policy" in e for e in errors)


def test_validator_rejects_non_object_manifest():
    assert validate_manifest(None) == ["manifest must be an object, got NoneType"]
    assert "must be an object" in validate_manifest([])[0]


# -------------------------------------------------------------------- CLI ---


def _run_cli(*args: str) -> subprocess.CompletedProcess:
    env = dict(os.environ)
    env["PYTHONUTF8"] = "1"
    env["PYTHONIOENCODING"] = "utf-8"
    return subprocess.run(
        [sys.executable, "-m", "adaptive_agent_eval.cli", *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,  # asserted explicitly on `returncode` below
        env=env,
        cwd=str(_REPO_ROOT),
        timeout=120,
    )


def test_cli_validate_manifest_reports_plan_without_executing(tmp_path):
    out_file = tmp_path / "manifest.json"
    proc = _run_cli("--validate-manifest", "--manifest-out", str(out_file))
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "Result: VALID" in proc.stdout
    assert "26" in proc.stdout and "1300" in proc.stdout
    assert "single-agent: 12" in proc.stdout
    assert "cross-agent: 6" in proc.stdout
    assert "defense-composition: 8" in proc.stdout
    # Validation-only language, no execution claim.
    assert "no experiment was executed" in proc.stdout
    assert "runs nothing" in proc.stdout

    written = json.loads(out_file.read_text(encoding="utf-8"))
    assert len(written["configurations"]) == 26
    assert validate_manifest(written) == []


def test_cli_default_behavior_unchanged():
    proc = _run_cli()
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "Adaptive Agent Defense Evaluation Framework" in proc.stdout
    assert "Mode: single-agent" in proc.stdout
    assert "Result: VALID" not in proc.stdout  # manifest branch not triggered


# -------------------------------------------------------------------- API ---


@pytest.fixture
def app_client(tmp_path):
    from backend.stage_b import _MOUNT_PREFIX, create_app

    app = create_app(
        credentials_path=tmp_path / "c.json",
        token_path=tmp_path / "t.json",
        pairing_nonce=_NONCE,
        feedback_store=tmp_path / "fb.json",
        quality_store=tmp_path / "q.json",
        adaptive_store=str(tmp_path / "adaptive.json"),
    )
    client = TestClient(app, follow_redirects=False)
    base = f"/{_MOUNT_PREFIX.lstrip('/')}"
    return client, base


def test_api_experiment_manifest_endpoint(app_client):
    client, base = app_client
    response = client.get(f"{base}/experiment-manifest")
    assert response.status_code == 200
    body = response.json()
    summary = body["summary"]
    manifest = body["manifest"]

    assert summary["kind"] == "configuration_validation_only"
    assert summary["execution"] == "not_started"
    assert summary["episodes_executed"] == 0
    assert summary["valid"] is True
    assert summary["errors"] == []
    assert summary["configurations"] == 26
    assert summary["planned_episodes"] == 1300
    assert summary["mode_counts"] == {
        "single-agent": 12,
        "cross-agent": 6,
        "defense-composition": 8,
    }
    assert len(manifest["configurations"]) == 26
    assert manifest["schema_version"] == SCHEMA_VERSION
    assert validate_manifest(manifest) == []

    # No secrets in the response.
    text = response.text
    for needle in ("AIza", "ghp_", "sk-", "api_key", "authorization"):
        assert needle not in text


def test_api_health_integrations_are_honest(app_client):
    client, _ = app_client
    response = client.get("/health")
    assert response.status_code == 200
    body = response.json()

    # Existing health contract preserved (additive change only).
    for key in ("status", "bind", "origin", "state", "timestamp"):
        assert key in body
    assert body["status"] == "ok"

    integrations = body["integrations"]
    assert len(integrations) >= 8
    valid_statuses = {s.value for s in IntegrationStatus}
    by_name = {}
    for report in integrations:
        assert set(report) == {"name", "status", "detail"}
        assert report["status"] in valid_statuses
        by_name[report["name"]] = report

    # Defenses are labeled proxies, AgentDojo is honestly absent, and a
    # provider key presence never claims a live connection.
    assert by_name["defense:camel"]["status"] == "proxy_implementation"
    assert by_name["agentdojo"]["status"] == "not_installed"
    assert by_name["llm-provider"]["status"] != "connected"
    assert by_name["extension-pairing"]["status"] == "not_configured"
    assert by_name["gmail-readonly"]["status"] in (
        "available",
        "not_configured",
    )

    text = response.text
    assert "AIza" not in text  # no credential material in health output


def test_api_health_reports_connected_after_real_pairing(app_client):
    client, base = app_client
    pair = client.post(
        f"{base}/pair",
        json={"presented_nonce": _NONCE, "extension_origin": _ORIGIN},
        headers={"origin": _ORIGIN},
    )
    assert pair.status_code == 200, pair.text

    body = client.get("/health").json()
    pairing = next(
        r for r in body["integrations"] if r["name"] == "extension-pairing"
    )
    # CONNECTED is only claimed after an actual completed pairing.
    assert pairing["status"] == "connected"
    assert body["state"] in ("paired", "active") or isinstance(body["state"], str)


# ------------------------------------------------- integration probes -------


def test_collect_integrations_with_explicit_env(tmp_path):
    from backend.integrations import collect_integrations

    def by_name(reports):
        return {r.name: r for r in reports}

    empty = by_name(
        collect_integrations(
            token_path=tmp_path / "missing.json",
            results_dir=tmp_path / "results",
            env={},
        )
    )
    assert empty["llm-provider"].status == IntegrationStatus.NOT_CONFIGURED
    assert "LLM_PROVIDER not set" in empty["llm-provider"].detail
    assert empty["gmail-readonly"].status == IntegrationStatus.NOT_CONFIGURED
    assert empty["artifact-storage"].status == IntegrationStatus.NOT_CONFIGURED
    assert empty["extension-pairing"].status == IntegrationStatus.NOT_CONFIGURED

    gemini = by_name(
        collect_integrations(
            token_path=tmp_path / "tok.json",
            results_dir=tmp_path,
            env={"LLM_PROVIDER": "gemini"},
        )
    )
    assert gemini["llm-provider"].status == IntegrationStatus.NOT_CONFIGURED
    assert "no GEMINI_API_KEY" in gemini["llm-provider"].detail

    with_key = by_name(
        collect_integrations(
            token_path=tmp_path / "tok.json",
            results_dir=tmp_path,
            env={"LLM_PROVIDER": "gemini", "GEMINI_API_KEY": "present-not-printed"},
        )
    )
    assert with_key["llm-provider"].status == IntegrationStatus.AVAILABLE
    assert "not verified live" in with_key["llm-provider"].detail
    # Presence is reported, never the value.
    assert "present-not-printed" not in with_key["llm-provider"].detail

    unknown = by_name(
        collect_integrations(env={"LLM_PROVIDER": "cohere"})
    )
    assert unknown["llm-provider"].status == IntegrationStatus.FAILED

    # The token file flips gmail to AVAILABLE (still not a live check).
    (tmp_path / "tok.json").write_text("{}", encoding="utf-8")
    gmail = by_name(collect_integrations(token_path=tmp_path / "tok.json", env={}))
    assert gmail["gmail-readonly"].status == IntegrationStatus.AVAILABLE
    assert "not verified live" in gmail["gmail-readonly"].detail

    # Pairing CONNECTED requires an actual paired origin.
    paired = by_name(collect_integrations(paired_origin=_ORIGIN, env={}))
    assert paired["extension-pairing"].status == IntegrationStatus.CONNECTED


def test_probe_details_never_contain_secret_values(tmp_path):
    from backend.integrations import collect_integrations

    fake_key = "AIza" + "Z" * 35
    reports = collect_integrations(
        token_path=tmp_path / "t.json",
        results_dir=tmp_path,
        env={"LLM_PROVIDER": "gemini", "GEMINI_API_KEY": fake_key},
    )
    blob = json.dumps([r.to_dict() for r in reports])
    assert fake_key not in blob
    assert "AIza" not in blob
