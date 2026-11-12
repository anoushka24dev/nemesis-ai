"""Artifact manifest and integrity verification.

Writes ``manifest.json`` next to experiment artifacts (SHA-256 per covered
file plus a canonical hash of the episode-record payload) and verifies it
later, so modified, missing, or truncated artifacts are detectable.

What verification CAN detect
----------------------------
* Any byte-level change to a covered file after the manifest was written.
* A covered file that was deleted or truncated.
* Changed episode records inside ``episodes.json`` (payload hash).

What it CANNOT detect (documented limits)
-----------------------------------------
* Anyone who can edit a covered file can also rewrite ``manifest.json`` with
  matching hashes: the manifest is integrity bookkeeping, NOT a signature.
  There is no key pair here (same limitation as ADR-007 for stop-condition
  checksums) — integrity, not authenticity.
* Files not covered by the manifest.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

MANIFEST_NAME = "manifest.json"
ALGORITHM = "sha256"

#: Artifact files covered by the manifest when present in the results dir.
ARTIFACT_FILES = ("episodes.csv", "episodes.json", "config_summary.json")


def file_sha256(path: Path | str) -> str:
    """Streaming SHA-256 of a file's bytes."""
    digest = hashlib.sha256()
    with Path(path).open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _load_episode_records(episodes_path: Path) -> list[dict] | None:
    """Load episode records from either on-disk shape:

    * a JSON array (``mode2_c1.MetricsLogger``), or
    * JSON Lines, one object per line (``mode2_c1_stubs.MetricsLogger``).

    Returns ``None`` when the file is absent or unparseable.
    """
    if not episodes_path.exists():
        return None
    try:
        text = episodes_path.read_text(encoding="utf-8")
    except OSError:
        return None
    if not text.strip():
        return None
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        data = None
    if isinstance(data, list):
        return data
    # Fall back to JSON Lines (one JSON object per line).
    records: list[dict] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            parsed = json.loads(line)
        except json.JSONDecodeError:
            return None
        if not isinstance(parsed, dict):
            return None
        records.append(parsed)
    return records


def episodes_payload_sha256(results_dir: Path | str) -> str | None:
    """Canonical hash over the episode-record list in ``episodes.json``.

    Uses the same algorithm as ``mode2_c1_stubs.run_demo_episode``'s
    aggregation checksum (sorted-key JSON per record, concatenated). Returns
    ``None`` when no readable episode list exists.
    """
    records = _load_episode_records(Path(results_dir) / "episodes.json")
    if records is None:
        return None
    blob = "".join(
        json.dumps(r, sort_keys=True, ensure_ascii=False) for r in records
    )
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def write_manifest(
    results_dir: Path | str, extra: dict[str, Any] | None = None
) -> dict[str, Any]:
    """Write ``manifest.json`` covering the artifact files in ``results_dir``.

    Returns the manifest payload that was written.
    """
    results_dir = Path(results_dir)
    files: dict[str, dict[str, Any]] = {}
    for name in ARTIFACT_FILES:
        path = results_dir / name
        if path.exists():
            files[name] = {
                "sha256": file_sha256(path),
                "size_bytes": path.stat().st_size,
            }
    manifest: dict[str, Any] = {
        "algorithm": ALGORITHM,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "files": files,
        "episodes_payload_sha256": episodes_payload_sha256(results_dir),
    }
    if extra:
        manifest["extra"] = dict(extra)
    (results_dir / MANIFEST_NAME).write_text(
        json.dumps(manifest, indent=2), encoding="utf-8"
    )
    return manifest


def verify_artifacts(results_dir: Path | str) -> dict[str, Any]:
    """Verify artifacts in ``results_dir`` against ``manifest.json``.

    Returns::

        {
          "ok": bool,                # True only when everything matches
          "algorithm": str | None,
          "generated_at": str | None,
          "files": {name: {"status": "ok"|"modified"|"missing", ...}},
          "episodes_payload": {"status": "ok"|"modified"|"missing"
                               |"not_recorded", "expected":..., "actual":...},
          "error": str,              # only when the manifest itself is absent
                                      # or unreadable
        }
    """
    results_dir = Path(results_dir)
    manifest_path = results_dir / MANIFEST_NAME
    if not manifest_path.exists():
        return {
            "ok": False,
            "algorithm": None,
            "generated_at": None,
            "files": {},
            "episodes_payload": {"status": "not_recorded"},
            "error": f"{MANIFEST_NAME} not found — artifacts are unverified",
        }
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        return {
            "ok": False,
            "algorithm": None,
            "generated_at": None,
            "files": {},
            "episodes_payload": {"status": "not_recorded"},
            "error": f"manifest unreadable: {exc}",
        }

    ok = True
    files_report: dict[str, dict[str, Any]] = {}
    for name, meta in (manifest.get("files") or {}).items():
        expected = (meta or {}).get("sha256")
        path = results_dir / name
        if not path.exists():
            files_report[name] = {"status": "missing", "expected": expected}
            ok = False
            continue
        actual = file_sha256(path)
        if actual == expected:
            files_report[name] = {"status": "ok", "sha256": actual}
        else:
            files_report[name] = {
                "status": "modified",
                "expected": expected,
                "actual": actual,
            }
            ok = False

    expected_payload = manifest.get("episodes_payload_sha256")
    actual_payload = episodes_payload_sha256(results_dir)
    if expected_payload is None:
        payload_report = {"status": "not_recorded"}
    elif actual_payload is None:
        payload_report = {
            "status": "missing",
            "expected": expected_payload,
            "actual": None,
        }
        ok = False
    elif actual_payload == expected_payload:
        payload_report = {
            "status": "ok",
            "expected": expected_payload,
            "actual": actual_payload,
        }
    else:
        payload_report = {
            "status": "modified",
            "expected": expected_payload,
            "actual": actual_payload,
        }
        ok = False

    return {
        "ok": ok,
        "algorithm": manifest.get("algorithm"),
        "generated_at": manifest.get("generated_at"),
        "files": files_report,
        "episodes_payload": payload_report,
    }
