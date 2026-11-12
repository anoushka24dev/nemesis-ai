"""Approved experiment configuration manifest — the validated plan.

Plan source: ``docs/EXPERIMENT_PLAN.md`` §1.2 (Mode 1), §2.2 (Mode 2) and
§3.2 (Mode 3): 12 + 6 + 8 = **26 configurations × 50 episodes = 1,300
episodes**. This is the presentation's three-mode plan adopted as the active
matrix; the five-mode / 38-configuration / 1,900-episode description found in
other repository documents is recorded as a *future extension*, not this
manifest.

This module only **builds and validates the plan**. It never executes an
experiment; a successful validation means "the configuration grid is
well-formed", nothing more.

Documented factor interpretations (recorded, never silent)
----------------------------------------------------------
1. ``target-tier-m2-m3`` — EXPERIMENT_PLAN.md's Mode 2 and Mode 3 tables have
   no target-tier column. Explicit user decision (Phase 2, 2026-10-24): all
   Mode 2 and Mode 3 configurations use ``target_tier = "cheap"`` to preserve
   the approved 26-configuration grid. The manifest carries the explicit
   value plus this rationale.
2. ``seed-index-scope`` — §8.1 gives ``config_seed = config_index × 1000`` but
   never states the index scope. This manifest uses the **global 1-based
   position** (1..26) because per-mode indices would collide (M1-01, M2-01 and
   M3-01 would all seed 1000).
3. ``target-environment`` — §1.2/§3.2 do not name a target environment for
   Modes 1/3; entries record the repository's local single-agent target. The
   real AgentDojo benchmark is **not installed** (declared under
   ``unsupported_dependencies``) and no result may be labeled as real
   AgentDojo.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from typing import Any

from adaptive_agent_eval.models import (
    AttackerTier,
    DefenseType,
    EpisodeMode,
    TargetTier,
)

SCHEMA_VERSION = "1.0"
PLAN_SOURCE = "docs/EXPERIMENT_PLAN.md sections 1.2, 2.2, 3.2"

EPISODES_PER_CONFIG = 50
MAX_ROUNDS = 5
BASE_SEED = 42

MODE_COUNTS: dict[str, int] = {
    EpisodeMode.SINGLE_AGENT.value: 12,
    EpisodeMode.CROSS_AGENT.value: 6,
    EpisodeMode.DEFENSE_COMPOSITION.value: 8,
}
TOTAL_CONFIGS = 26
TOTAL_EPISODES = 1_300

#: Per-entry fields that must be present; the validator reports each missing
#: one rather than filling a default.
REQUIRED_ENTRY_FIELDS = (
    "config_id",
    "mode",
    "defenses",
    "attacker_tier",
    "target_tier",
    "agent_setup",
    "attacker_type",
    "episodes",
    "max_rounds",
    "seed",
    "target_environment",
    "required_integrations",
)

REQUIRED_TOP_LEVEL = (
    "schema_version",
    "plan_source",
    "seed_policy",
    "provider_binding",
    "factor_interpretations",
    "unsupported_dependencies",
    "configurations",
)

SEED_POLICY: dict[str, Any] = {
    "base_seed": BASE_SEED,
    "config_seed_formula": "config_seed = config_index * 1000",
    "episode_seed_formula": "episode_seed = config_seed + episode_index",
    "config_index_scope": "global-1-based-position-in-manifest",
    "source": "docs/EXPERIMENT_PLAN.md section 8.1",
    "note": (
        "Section 8.1 does not state the config_index scope; this manifest uses "
        "the global 1-based position (1..26) because per-mode indices would "
        "collide across modes (M1-01/M2-01/M3-01 would all seed 1000)."
    ),
}

PROVIDER_BINDING: dict[str, Any] = {
    "provider": "gemini",
    "cheap_model": "gemini-2.5-flash",
    "frontier_model": "gemini-2.5-pro",
    "endpoint_kind": "openai-compatible",
    "decision": "ADR-016 (user-approved Phase 2 decision, 2026-10-24)",
    "verification": (
        "Gemini models list via the OpenAI-compatible endpoint confirmed both "
        "model IDs available on 2026-10-24; model names only — credentials "
        "never enter this manifest."
    ),
}

FACTOR_INTERPRETATIONS: list[dict[str, str]] = [
    {
        "id": "target-tier-m2-m3",
        "applies_to": "all Mode 2 and Mode 3 configurations",
        "field": "target_tier",
        "value": "cheap",
        "source_silence": (
            "EXPERIMENT_PLAN.md section 2.2 and 3.2 tables have no target-tier "
            "column; only section 1.2 (Mode 1) varies target tiers."
        ),
        "decision": (
            "Explicit user decision (Phase 2, 2026-10-24): assign "
            "target_tier=cheap to all Mode 2 and Mode 3 configurations to "
            "preserve the approved 26-configuration grid."
        ),
        "rationale": (
            "Not inferred from attacker tier or repository defaults — recorded "
            "as an explicit project-level interpretation; tests assert the "
            "value and this rationale are present."
        ),
    },
    {
        "id": "seed-index-scope",
        "applies_to": "all configurations (seed field)",
        "field": "seed",
        "value": "config_index * 1000 with global 1-based index",
        "source_silence": "EXPERIMENT_PLAN.md section 8.1 omits the index scope.",
        "decision": (
            "Global 1-based index across the manifest (implementation "
            "interpretation, flagged for review in the Phase 2 report)."
        ),
        "rationale": "Per-mode indices would collide (all would seed 1000).",
    },
    {
        "id": "target-environment-m1-m3",
        "applies_to": "all Mode 1 and Mode 3 configurations",
        "field": "target_environment",
        "value": "local-target-agent",
        "source_silence": (
            "EXPERIMENT_PLAN.md section 1.2/3.2 do not name a target "
            "environment for Modes 1/3."
        ),
        "decision": (
            "Record the repository's local single-agent target "
            "(adaptive_agent_eval.target), explicitly not real AgentDojo."
        ),
        "rationale": (
            "agentdojo is not installed; results from this environment must "
            "be labeled local/proxy, never as the real 97-task benchmark."
        ),
    },
]

UNSUPPORTED_DEPENDENCIES: list[dict[str, str]] = [
    {
        "name": "agentdojo",
        "status": "not_installed",
        "impact": (
            "The real AgentDojo benchmark is unavailable. Single-agent targets "
            "use the local target implementation; results must be labeled as "
            "local/proxy and never reported as real AgentDojo results."
        ),
    },
    {
        "name": "static-baseline-attacker",
        "status": "planned_phase_4",
        "impact": (
            "The adaptive-vs-static comparison baseline is not implemented yet; "
            "it is not a factor of the 26-configuration grid."
        ),
    },
]

ATTACKER_TYPE = "adaptive-hill-climbing"

#: Values that look like credentials must never appear anywhere in the
#: manifest (in addition to the key-name scan).
_SECRET_VALUE_RE = re.compile(
    r"(AIza[0-9A-Za-z_\-]{20,}|sk-[0-9A-Za-z_\-]{16,}|ghp_[0-9A-Za-z]{20,}"
    r"|Bearer\s+[0-9A-Za-z])",
    re.IGNORECASE,
)

_SECRET_KEY_NAMES = frozenset(
    {
        "api_key",
        "apikey",
        "api_secret",
        "token",
        "access_token",
        "refresh_token",
        "secret",
        "password",
        "passwd",
        "authorization",
        "credential",
        "credentials",
        "private_key",
        "client_secret",
        "bearer",
    }
)


def _required_integrations(mode: str, defenses: list[str]) -> list[str]:
    integrations = [f"llm-provider:{PROVIDER_BINDING['provider']}"]
    integrations.extend(f"defense:{d} (local-implementation)" for d in defenses)
    if mode == EpisodeMode.CROSS_AGENT.value:
        integrations.append("target:email-calendar-pipeline (local)")
    else:
        integrations.append("target:local-target-agent (local)")
    return integrations


def _target_environment(mode: str) -> str:
    return (
        "email-calendar-pipeline"
        if mode == EpisodeMode.CROSS_AGENT.value
        else "local-target-agent"
    )


def build_manifest() -> dict[str, Any]:
    """Deterministically build the approved 26-configuration manifest.

    Same inputs -> byte-identical output: no randomness, no timestamps, no
    UUIDs (stability is asserted by tests).
    """
    entries: list[dict[str, Any]] = []
    global_index = 0

    # Mode 1 (EXPERIMENT_PLAN.md §1.2): defense × attacker tier × target tier.
    per_mode = 0
    for defense in ("camel", "progent", "verifier"):
        for attacker in ("cheap", "frontier"):
            for target in ("cheap", "frontier"):
                global_index += 1
                per_mode += 1
                entries.append(
                    _entry(
                        config_id=f"M1-{per_mode:02d}",
                        mode=EpisodeMode.SINGLE_AGENT.value,
                        defenses=[defense],
                        attacker_tier=attacker,
                        target_tier=target,
                        agent_setup="single-agent",
                        global_index=global_index,
                    )
                )

    # Mode 2 (§2.2): defense × agent setup; attacker tier cheap (plan),
    # target tier cheap (documented interpretation target-tier-m2-m3).
    per_mode = 0
    for defense in ("camel", "progent", "verifier"):
        for setup in ("single-agent", "multi-agent"):
            global_index += 1
            per_mode += 1
            entries.append(
                _entry(
                    config_id=f"M2-{per_mode:02d}",
                    mode=EpisodeMode.CROSS_AGENT.value,
                    defenses=[defense],
                    attacker_tier="cheap",
                    target_tier="cheap",
                    agent_setup=setup,
                    global_index=global_index,
                )
            )

    # Mode 3 (§3.2): stacked defense × attacker tier; target tier cheap
    # (documented interpretation target-tier-m2-m3).
    stacks = [
        ["camel", "progent"],
        ["camel", "verifier"],
        ["progent", "verifier"],
        ["camel", "progent", "verifier"],
    ]
    per_mode = 0
    for stack in stacks:
        for attacker in ("cheap", "frontier"):
            global_index += 1
            per_mode += 1
            entries.append(
                _entry(
                    config_id=f"M3-{per_mode:02d}",
                    mode=EpisodeMode.DEFENSE_COMPOSITION.value,
                    defenses=stack,
                    attacker_tier=attacker,
                    target_tier="cheap",
                    agent_setup="single-agent",
                    global_index=global_index,
                )
            )

    return {
        "schema_version": SCHEMA_VERSION,
        "plan_source": PLAN_SOURCE,
        "plan": {
            "modes": 3,
            "total_configs": TOTAL_CONFIGS,
            "episodes_per_config": EPISODES_PER_CONFIG,
            "max_rounds": MAX_ROUNDS,
            "total_episodes": TOTAL_EPISODES,
            "note": (
                "Presentation three-mode plan (active). The five-mode "
                "38-configuration 1,900-episode description elsewhere in the "
                "repository is a future extension, not this manifest."
            ),
        },
        "seed_policy": dict(SEED_POLICY),
        "provider_binding": dict(PROVIDER_BINDING),
        "factor_interpretations": [dict(i) for i in FACTOR_INTERPRETATIONS],
        "unsupported_dependencies": [dict(d) for d in UNSUPPORTED_DEPENDENCIES],
        "configurations": entries,
    }


def _entry(
    *,
    config_id: str,
    mode: str,
    defenses: list[str],
    attacker_tier: str,
    target_tier: str,
    agent_setup: str,
    global_index: int,
) -> dict[str, Any]:
    return {
        "config_id": config_id,
        "mode": mode,
        "defenses": list(defenses),
        "attacker_tier": attacker_tier,
        "target_tier": target_tier,
        "agent_setup": agent_setup,
        "attacker_type": ATTACKER_TYPE,
        "episodes": EPISODES_PER_CONFIG,
        "max_rounds": MAX_ROUNDS,
        "seed": global_index * 1000,
        "target_environment": _target_environment(mode),
        "required_integrations": _required_integrations(mode, defenses),
    }


# ---------------------------------------------------------------------------
# Independent expected grid (hand-transcribed from EXPERIMENT_PLAN.md tables;
# deliberately NOT derived from build_manifest's loops, so a builder bug is
# caught rather than mirrored).
# ---------------------------------------------------------------------------

def _expected_grid() -> list[tuple]:
    rows: list[tuple] = []
    for n, (defense, attacker, target) in enumerate((
        ("camel", "cheap", "cheap"),
        ("camel", "cheap", "frontier"),
        ("camel", "frontier", "cheap"),
        ("camel", "frontier", "frontier"),
        ("progent", "cheap", "cheap"),
        ("progent", "cheap", "frontier"),
        ("progent", "frontier", "cheap"),
        ("progent", "frontier", "frontier"),
        ("verifier", "cheap", "cheap"),
        ("verifier", "cheap", "frontier"),
        ("verifier", "frontier", "cheap"),
        ("verifier", "frontier", "frontier"),
    ), start=1):
        rows.append(
            (f"M1-{n:02d}", "single-agent", (defense,), attacker, target, "single-agent")
        )
    for n, (defense, setup) in enumerate((
        ("camel", "single-agent"),
        ("camel", "multi-agent"),
        ("progent", "single-agent"),
        ("progent", "multi-agent"),
        ("verifier", "single-agent"),
        ("verifier", "multi-agent"),
    ), start=1):
        rows.append(
            (f"M2-{n:02d}", "cross-agent", (defense,), "cheap", "cheap", setup)
        )
    n = 0
    for stack in (
        ("camel", "progent"),
        ("camel", "verifier"),
        ("progent", "verifier"),
        ("camel", "progent", "verifier"),
    ):
        for attacker in ("cheap", "frontier"):
            n += 1
            rows.append(
                (f"M3-{n:02d}", "defense-composition", stack, attacker, "cheap", "single-agent")
            )
    return rows


def _walk_secrets(node: Any, path: str, errors: list[str]) -> None:
    if isinstance(node, dict):
        for key, value in node.items():
            key_l = str(key).lower()
            if key_l in _SECRET_KEY_NAMES:
                errors.append(f"secret-like key at {path}: {key!r}")
            _walk_secrets(value, f"{path}.{key}", errors)
    elif isinstance(node, (list, tuple)):
        for i, value in enumerate(node):
            _walk_secrets(value, f"{path}[{i}]", errors)
    elif isinstance(node, str) and _SECRET_VALUE_RE.search(node):
        errors.append(f"secret-looking value at {path}")


def validate_manifest(manifest: Any) -> list[str]:
    """Validate the planned experiment matrix; returns every problem found.

    Checks: required fields, unique IDs, valid factor values, positive episode
    counts, unsupported combinations, exact grid membership (all intended
    configurations represented and no extras), per-mode counts (12/6/8), the
    26/1,300 totals, seed policy consistency, the required documented
    interpretations, and absence of secrets. The validator never fills in
    missing information — it reports it.
    """
    errors: list[str] = []

    if not isinstance(manifest, dict):
        return [f"manifest must be an object, got {type(manifest).__name__}"]

    for key in REQUIRED_TOP_LEVEL:
        if key not in manifest:
            errors.append(f"missing top-level field: {key}")
    if errors:
        return errors  # nothing further can be checked meaningfully

    if manifest["schema_version"] != SCHEMA_VERSION:
        errors.append(
            f"schema_version: expected {SCHEMA_VERSION!r}, "
            f"got {manifest['schema_version']!r}"
        )

    # -- documented interpretations must be present (including the explicit
    #    M2/M3 target-tier decision) -------------------------------------
    interpretations = manifest["factor_interpretations"]
    if not isinstance(interpretations, list):
        errors.append("factor_interpretations: must be a list")
        interpretations = []
    interp_ids = {
        i.get("id") for i in interpretations if isinstance(i, dict)
    } if interpretations else set()
    for required_id in ("target-tier-m2-m3", "seed-index-scope", "target-environment-m1-m3"):
        if required_id not in interp_ids:
            errors.append(
                f"factor_interpretations: missing required interpretation {required_id!r}"
            )

    # -- provider binding ---------------------------------------------------
    binding = manifest["provider_binding"]
    if not isinstance(binding, dict):
        errors.append("provider_binding: must be an object")
        binding = {}
    for key in ("provider", "cheap_model", "frontier_model"):
        if not binding.get(key):
            errors.append(f"provider_binding: missing {key!r}")

    # -- seed policy --------------------------------------------------------
    policy = manifest["seed_policy"]
    if not isinstance(policy, dict):
        errors.append("seed_policy: must be an object")
        policy = {}
    for key in ("base_seed", "config_seed_formula", "episode_seed_formula"):
        if key not in policy:
            errors.append(f"seed_policy: missing {key!r}")

    # -- configurations -----------------------------------------------------
    configs = manifest["configurations"]
    if not isinstance(configs, list):
        return errors + ["configurations: must be a list"]
    if not configs:
        return errors + ["configurations: empty — no plan represented"]

    seen_ids: set[str] = set()
    mode_counts: dict[str, int] = {}
    total_episodes = 0
    seeds: set[int] = set()

    for pos, entry in enumerate(configs):
        where = f"configurations[{pos}]"
        if not isinstance(entry, dict):
            errors.append(f"{where}: must be an object")
            continue

        for key in REQUIRED_ENTRY_FIELDS:
            if key not in entry:
                errors.append(f"{where}: missing field {key!r}")
        if any(
            e.startswith(f"{where}: missing field") for e in errors
        ):
            continue  # cannot check factors on an incomplete entry

        cid = entry["config_id"]
        if not isinstance(cid, str) or not cid:
            errors.append(f"{where}: config_id must be a non-empty string")
            continue
        where = cid
        if cid in seen_ids:
            errors.append(f"duplicate config_id: {cid}")
        seen_ids.add(cid)

        # Factor validity (strict; no coercion).
        try:
            mode = EpisodeMode(entry["mode"])
        except (ValueError, TypeError):
            errors.append(f"{where}: invalid mode {entry['mode']!r}")
            continue
        mode_counts[mode.value] = mode_counts.get(mode.value, 0) + 1

        defenses_raw = entry["defenses"]
        defenses: list[DefenseType] = []
        if not isinstance(defenses_raw, (list, tuple)) or not defenses_raw:
            errors.append(f"{where}: defenses must be a non-empty list")
        else:
            ok = True
            for d in defenses_raw:
                try:
                    defenses.append(DefenseType(d))
                except (ValueError, TypeError):
                    errors.append(f"{where}: invalid defense {d!r}")
                    ok = False
            if ok and len(set(defenses)) != len(defenses):
                errors.append(f"{where}: duplicate defenses {defenses_raw!r}")
            if ok:
                if mode in (EpisodeMode.SINGLE_AGENT, EpisodeMode.CROSS_AGENT) and len(defenses) != 1:
                    errors.append(
                        f"{where}: {mode.value} requires exactly one defense "
                        f"(unsupported combination: {defenses_raw!r})"
                    )
                if mode == EpisodeMode.DEFENSE_COMPOSITION and len(defenses) not in (2, 3):
                    errors.append(
                        f"{where}: defense-composition requires 2 or 3 stacked "
                        f"defenses (unsupported combination: {defenses_raw!r})"
                    )

        try:
            AttackerTier(entry["attacker_tier"])
        except (ValueError, TypeError):
            errors.append(f"{where}: invalid attacker_tier {entry['attacker_tier']!r}")
        try:
            TargetTier(entry["target_tier"])
        except (ValueError, TypeError):
            errors.append(f"{where}: invalid target_tier {entry['target_tier']!r}")

        if entry["agent_setup"] not in ("single-agent", "multi-agent"):
            errors.append(f"{where}: invalid agent_setup {entry['agent_setup']!r}")
        elif mode != EpisodeMode.CROSS_AGENT and entry["agent_setup"] != "single-agent":
            errors.append(
                f"{where}: unsupported combination — agent_setup "
                f"{entry['agent_setup']!r} with mode {mode.value!r}"
            )
        elif mode == EpisodeMode.CROSS_AGENT and entry["agent_setup"] not in (
            "single-agent",
            "multi-agent",
        ):  # pragma: no cover - unreachable via tuple check
            errors.append(f"{where}: invalid agent_setup for cross-agent mode")

        if entry["attacker_type"] != ATTACKER_TYPE:
            errors.append(
                f"{where}: unsupported attacker_type {entry['attacker_type']!r}"
            )

        episodes = entry["episodes"]
        if isinstance(episodes, bool) or not isinstance(episodes, int):
            errors.append(f"{where}: episodes must be an integer, got {episodes!r}")
        elif episodes != EPISODES_PER_CONFIG:
            errors.append(
                f"{where}: episodes must equal the approved "
                f"{EPISODES_PER_CONFIG}, got {episodes}"
            )
        elif episodes < 1:
            errors.append(f"{where}: episodes must be positive")
        else:
            total_episodes += episodes

        rounds = entry["max_rounds"]
        if isinstance(rounds, bool) or not isinstance(rounds, int) or rounds < 1:
            errors.append(f"{where}: max_rounds must be a positive integer")

        seed = entry["seed"]
        if isinstance(seed, bool) or not isinstance(seed, int) or seed < 0:
            errors.append(f"{where}: seed must be a non-negative integer")
        else:
            if seed in seeds:
                errors.append(f"{where}: seed {seed} collides with another config")
            seeds.add(seed)
            expected_seed = (pos + 1) * 1000
            if seed != expected_seed:
                errors.append(
                    f"{where}: seed {seed} violates the manifest seed policy "
                    f"config_index * 1000 = {expected_seed} (global 1-based)"
                )

        if entry["target_environment"] not in (
            "local-target-agent",
            "email-calendar-pipeline",
        ):
            errors.append(
                f"{where}: invalid target_environment "
                f"{entry['target_environment']!r}"
            )
        integrations = entry["required_integrations"]
        if not isinstance(integrations, list) or not integrations:
            errors.append(f"{where}: required_integrations must be a non-empty list")
        elif not all(isinstance(i, str) and i for i in integrations):
            errors.append(f"{where}: required_integrations entries must be strings")

    # -- exact grid membership (all intended configurations, nothing extra) --
    expected = _expected_grid()
    actual = [
        (
            e.get("config_id"),
            e.get("mode"),
            tuple(e.get("defenses", ())),
            e.get("attacker_tier"),
            e.get("target_tier"),
            e.get("agent_setup"),
        )
        for e in configs
        if isinstance(e, dict)
        and all(k in e for k in REQUIRED_ENTRY_FIELDS)
    ]
    if len(actual) == len(configs):
        missing = [row for row in expected if row not in actual]
        extra = [row for row in actual if row not in expected]
        for row in missing:
            errors.append(f"missing intended configuration: {row}")
        for row in extra:
            errors.append(f"configuration not in the approved grid: {row}")

    # -- per-mode counts and totals ----------------------------------------
    for mode_value, count in MODE_COUNTS.items():
        got = mode_counts.get(mode_value, 0)
        if got != count:
            errors.append(
                f"mode {mode_value!r}: expected {count} configurations, got {got}"
            )
    if len(configs) != TOTAL_CONFIGS:
        errors.append(
            f"total configurations: expected {TOTAL_CONFIGS}, got {len(configs)}"
        )
    if total_episodes != TOTAL_EPISODES:
        errors.append(
            f"total planned episodes: expected {TOTAL_EPISODES}, got {total_episodes}"
        )
    plan = manifest["plan"]
    if not isinstance(plan, dict):
        errors.append("plan: must be an object")
    else:
        if plan.get("total_configs") != TOTAL_CONFIGS:
            errors.append("plan.total_configs does not match the approved 26")
        if plan.get("total_episodes") != TOTAL_EPISODES:
            errors.append("plan.total_episodes does not match the approved 1300")
        if plan.get("episodes_per_config") != EPISODES_PER_CONFIG:
            errors.append("plan.episodes_per_config does not match 50")

    # -- unsupported dependencies must be declared -------------------------
    unsupported = manifest["unsupported_dependencies"]
    if not isinstance(unsupported, list) or not unsupported:
        errors.append("unsupported_dependencies: must declare known gaps")
    else:
        names = {d.get("name") for d in unsupported if isinstance(d, dict)}
        if "agentdojo" not in names:
            errors.append(
                "unsupported_dependencies: agentdojo gap must be declared"
            )

    # -- secrets ------------------------------------------------------------
    _walk_secrets(manifest, "manifest", errors)

    return errors


def manifest_summary(manifest: dict[str, Any]) -> dict[str, Any]:
    """Compact, honest summary for CLI/API output (validation-only: no
    experiment has been executed)."""
    configs = manifest.get("configurations") or []
    mode_counts: dict[str, int] = {}
    total_episodes = 0
    for entry in configs:
        if not isinstance(entry, dict):
            continue
        mode = entry.get("mode", "unknown")
        mode_counts[mode] = mode_counts.get(mode, 0) + 1
        episodes = entry.get("episodes")
        if isinstance(episodes, int) and not isinstance(episodes, bool):
            total_episodes += episodes
    errors = validate_manifest(manifest)
    return {
        "kind": "configuration_validation_only",
        "execution": "not_started",
        "episodes_executed": 0,
        "schema_version": manifest.get("schema_version"),
        "plan_source": manifest.get("plan_source"),
        "configurations": len(configs),
        "mode_counts": mode_counts,
        "planned_episodes": total_episodes,
        "valid": not errors,
        "errors": errors,
    }


def manifest_to_json(manifest: dict[str, Any]) -> str:
    """Deterministic JSON serialization (stable given a stable manifest)."""
    return json.dumps(manifest, indent=2, ensure_ascii=False) + "\n"


def experiment_config_from_entry(entry: Mapping[str, Any]) -> Any:
    """Convert one manifest entry into a validated ``ExperimentConfig``.

    Only fields the configuration contract understands are carried over
    (``config_id``, ``target_environment`` and ``required_integrations`` are
    plan-level metadata); provider/model binding comes from the manifest's
    ADR-016 decision. Unknown or missing contract fields are rejected by
    ``ExperimentConfig.from_dict`` — nothing is silently substituted.
    """
    from adaptive_agent_eval.contracts import ExperimentConfig

    if not isinstance(entry, Mapping):
        raise TypeError(f"manifest entry must be an object, got {type(entry).__name__}")
    carry = (
        "mode",
        "defenses",
        "episodes",
        "seed",
        "max_rounds",
        "attacker_tier",
        "target_tier",
        "agent_setup",
        "attacker_type",
    )
    data: dict[str, Any] = {key: entry[key] for key in carry if key in entry}
    data.update(
        {
            "provider": PROVIDER_BINDING["provider"],
            "cheap_model": PROVIDER_BINDING["cheap_model"],
            "frontier_model": PROVIDER_BINDING["frontier_model"],
            "label": str(entry.get("config_id", "")),
        }
    )
    return ExperimentConfig.from_dict(data)
