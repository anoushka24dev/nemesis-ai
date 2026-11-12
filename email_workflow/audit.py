"""Append-only audit log for outbound workflow actions.

Every submission (allowed, denied, errored, simulated) is recorded. Bodies are
NEVER stored: only a SHA-256 fingerprint and a character count. String fields
pass through ``threats.redact_digits`` so identity numbers cannot leak into
the audit trail. The log is append-only JSONL; there is no update or delete
path.
"""
from __future__ import annotations

import hashlib
import json
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from threats import redact_digits

__all__ = ["AuditLog", "body_fingerprint"]

MAX_FIELD_CHARS = 300


def body_fingerprint(body: str) -> str:
    """SHA-256 of the exact body bytes: correlates without storing content."""
    return hashlib.sha256(str(body or "").encode("utf-8")).hexdigest()


class AuditLog:
    """In-memory always; JSONL file when ``path`` is given (append-only)."""

    def __init__(
        self,
        path: str | Path | None = None,
        *,
        clock: Callable[[], str] | None = None,
    ) -> None:
        self.path = Path(path) if path else None
        self.records: list[dict[str, Any]] = []
        self._clock = clock

    def _now(self) -> str:
        if self._clock is not None:
            return self._clock()
        return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    @staticmethod
    def _clean(value: Any) -> Any:
        if isinstance(value, str):
            return redact_digits(value)[:MAX_FIELD_CHARS]
        if isinstance(value, bool) or value is None or isinstance(value, (int, float)):
            return value
        if isinstance(value, (list, tuple)):
            return [AuditLog._clean(v) for v in value]
        if isinstance(value, dict):
            return {str(k): AuditLog._clean(v) for k, v in value.items()}
        return redact_digits(str(value))[:MAX_FIELD_CHARS]

    def record(self, event: str, **fields: Any) -> dict[str, Any]:
        """Append one audit entry. ``body=`` is rejected outright: pass
        ``body_fingerprint(body)`` instead (minimize stored message content).
        ``action`` is reserved for the audit event name; workflow intent must
        be passed as ``workflow_action=``."""
        if "body" in fields:
            raise ValueError(
                "message bodies are never stored in the audit log; "
                "pass body_fingerprint(body) instead"
            )
        if "action" in fields:
            raise ValueError(
                "field name 'action' is reserved for the audit event; "
                "pass workflow_action= instead"
            )
        entry: dict[str, Any] = {"at": self._now(), "action": str(event)}
        for key, value in fields.items():
            entry[key] = self._clean(value)
        self.records.append(entry)
        if self.path is not None:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
        return entry

    def tail(self, n: int = 10) -> list[dict[str, Any]]:
        return self.records[-n:]

    def actions(self) -> list[str]:
        return [str(r.get("action")) for r in self.records]
