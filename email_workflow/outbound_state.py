"""Durable state for the protected Gmail outbound workflow.

This module intentionally uses only the Python standard library (SQLite). It
stores three things that must survive a backend restart:

* the global outbound kill switch (fail-safe: ON unless an explicit, durable
  release was recorded),
* one row per outbound idempotency key, including ambiguous delivery outcomes,
* the sliding-window outbound rate-limit events.

No message body, token, or credential is stored here. Message identity is kept
as a SHA-256 fingerprint plus the minimum Gmail response identifiers needed for
delivery evidence and reconciliation.
"""
from __future__ import annotations

import os
import sqlite3
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from email_workflow.policy import RateLimitExceeded

__all__ = [
    "DEFAULT_STATE_PATH",
    "STATE_PATH_ENV",
    "OutboundStateError",
    "OutboundStateStore",
    "default_state_path",
]

STATE_PATH_ENV = "NEMESIS_OUTBOUND_STATE_PATH"
DEFAULT_STATE_PATH = (
    Path(__file__).resolve().parent.parent / "results" / "nemesis_outbound_state.sqlite3"
)

# Attempt states. Terminal states are never automatically retried.
ATTEMPT_IN_FLIGHT = "in_flight"
ATTEMPT_CONFIRMED = "confirmed"
ATTEMPT_SIMULATED = "simulated"
ATTEMPT_FAILED = "failed"
ATTEMPT_UNCERTAIN = "uncertain"

_TERMINAL = frozenset({ATTEMPT_CONFIRMED, ATTEMPT_SIMULATED, ATTEMPT_FAILED, ATTEMPT_UNCERTAIN})
_DO_NOT_RETRY = frozenset({ATTEMPT_CONFIRMED, ATTEMPT_SIMULATED, ATTEMPT_UNCERTAIN, ATTEMPT_IN_FLIGHT})


class OutboundStateError(RuntimeError):
    """Persistent workflow state could not be read or written safely."""


def default_state_path() -> Path:
    raw = os.environ.get(STATE_PATH_ENV, "").strip()
    return Path(raw) if raw else DEFAULT_STATE_PATH


class OutboundStateStore:
    """Small, transactional SQLite store shared by workflow instances."""

    def __init__(self, path: str | Path | None = None) -> None:
        self.path = Path(path) if path is not None else default_state_path()
        self._lock = threading.RLock()
        self._healthy = True
        self._init_error: str | None = None
        self._initialize()

    # -- connection / schema ------------------------------------------------

    def _connect(self) -> sqlite3.Connection:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(self.path), timeout=10.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA busy_timeout = 10000")
        conn.execute("PRAGMA journal_mode = WAL")
        conn.execute("PRAGMA synchronous = FULL")
        return conn

    def _initialize(self) -> None:
        try:
            with self._connect() as conn:
                conn.executescript(
                    """
                    CREATE TABLE IF NOT EXISTS kill_switch (
                        id INTEGER PRIMARY KEY CHECK (id = 1),
                        engaged INTEGER NOT NULL CHECK (engaged IN (0, 1)),
                        updated_at TEXT NOT NULL,
                        actor TEXT,
                        reason TEXT
                    );
                    CREATE TABLE IF NOT EXISTS kill_switch_audit (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        at TEXT NOT NULL,
                        event TEXT NOT NULL,
                        actor TEXT,
                        reason TEXT,
                        previous_state INTEGER,
                        new_state INTEGER NOT NULL,
                        detail TEXT
                    );
                    CREATE TABLE IF NOT EXISTS outbound_attempt (
                        idempotency_key TEXT PRIMARY KEY,
                        action TEXT NOT NULL,
                        state TEXT NOT NULL,
                        created_at TEXT NOT NULL,
                        updated_at TEXT NOT NULL,
                        message_fingerprint TEXT,
                        recipient_fingerprint TEXT,
                        transport TEXT,
                        record_id TEXT,
                        message_id TEXT,
                        thread_id TEXT,
                        error TEXT,
                        note TEXT,
                        attempts INTEGER NOT NULL DEFAULT 1
                    );
                    CREATE TABLE IF NOT EXISTS rate_event (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        at REAL NOT NULL,
                        action TEXT NOT NULL,
                        idempotency_key TEXT
                    );
                    """
                )
                row = conn.execute(
                    "SELECT engaged FROM kill_switch WHERE id = 1"
                ).fetchone()
                if row is None:
                    now = _utc_now()
                    conn.execute(
                        "INSERT INTO kill_switch(id, engaged, updated_at, actor, reason) "
                        "VALUES (1, 1, ?, 'system', 'safe default on first initialization')",
                        (now,),
                    )
                    conn.execute(
                        "INSERT INTO kill_switch_audit"
                        "(at, event, actor, reason, previous_state, new_state, detail) "
                        "VALUES (?, 'initial_safe_default', 'system', "
                        "'first initialization defaults ON', NULL, 1, NULL)",
                        (now,),
                    )
        except (sqlite3.Error, OSError) as exc:
            # Fail closed: an unreadable/corrupt store must never look released.
            self._healthy = False
            self._init_error = f"{type(exc).__name__}: {exc}"

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        with self._lock:
            conn: sqlite3.Connection | None = None
            try:
                conn = self._connect()
                conn.execute("BEGIN IMMEDIATE")
                yield conn
                conn.commit()
            except Exception:
                if conn is not None:
                    try:
                        conn.rollback()
                    except sqlite3.Error:
                        pass
                raise
            finally:
                if conn is not None:
                    conn.close()

    # -- kill switch --------------------------------------------------------

    def kill_switch_record(self) -> dict[str, Any]:
        """Return the durable stop state, defaulting to ON on every failure."""
        if not self._healthy:
            return {
                "engaged": True,
                "durable": False,
                "defaulted": True,
                "error": self._init_error or "state store unhealthy",
            }
        try:
            with self._connect() as conn:
                row = conn.execute(
                    "SELECT engaged, updated_at, actor, reason FROM kill_switch WHERE id = 1"
                ).fetchone()
            if row is None:
                return {
                    "engaged": True,
                    "durable": False,
                    "defaulted": True,
                    "error": "kill-switch row missing; fail closed",
                }
            return {
                "engaged": bool(row["engaged"]),
                "durable": True,
                "defaulted": False,
                "updated_at": row["updated_at"],
                "actor": row["actor"],
                "reason": row["reason"],
            }
        except (sqlite3.Error, OSError) as exc:
            return {
                "engaged": True,
                "durable": False,
                "defaulted": True,
                "error": f"{type(exc).__name__}: {exc}",
            }

    def kill_switch_engaged(self) -> bool:
        return bool(self.kill_switch_record()["engaged"])

    def set_kill_switch(
        self,
        engaged: bool,
        *,
        actor: str | None = None,
        reason: str | None = None,
        require_confirm: bool = False,
    ) -> dict[str, Any]:
        """Persist a stop/release transition and its audit event.

        A release requires ``require_confirm=True`` from an explicit caller.
        Any write failure raises; the caller must keep the in-memory stop ON.
        """
        if not engaged and not require_confirm:
            raise OutboundStateError(
                "releasing the outbound stop requires explicit confirmation"
            )
        if not self._healthy:
            raise OutboundStateError(
                f"outbound state store is unhealthy: {self._init_error or 'unknown error'}"
            )
        now = _utc_now()
        try:
            with self._transaction() as conn:
                row = conn.execute(
                    "SELECT engaged FROM kill_switch WHERE id = 1"
                ).fetchone()
                previous = bool(row["engaged"]) if row is not None else True
                if row is None:
                    conn.execute(
                        "INSERT INTO kill_switch(id, engaged, updated_at, actor, reason) "
                        "VALUES (1, ?, ?, ?, ?)",
                        (1 if engaged else 0, now, actor, reason),
                    )
                else:
                    conn.execute(
                        "UPDATE kill_switch SET engaged = ?, updated_at = ?, actor = ?, reason = ? "
                        "WHERE id = 1",
                        (1 if engaged else 0, now, actor, reason),
                    )
                conn.execute(
                    "INSERT INTO kill_switch_audit"
                    "(at, event, actor, reason, previous_state, new_state, detail) "
                    "VALUES (?, ?, ?, ?, ?, ?, NULL)",
                    (
                        now,
                        "released" if not engaged else "engaged",
                        actor,
                        reason,
                        int(previous),
                        int(bool(engaged)),
                    ),
                )
            return {
                "engaged": bool(engaged),
                "durable": True,
                "previous_state": previous,
                "updated_at": now,
                "actor": actor,
                "reason": reason,
            }
        except (sqlite3.Error, OSError) as exc:
            raise OutboundStateError(
                f"could not persist outbound kill switch: {type(exc).__name__}: {exc}"
            ) from exc

    def kill_switch_audit(self, limit: int = 25) -> list[dict[str, Any]]:
        try:
            with self._connect() as conn:
                rows = conn.execute(
                    "SELECT * FROM kill_switch_audit ORDER BY id DESC LIMIT ?",
                    (max(1, int(limit)),),
                ).fetchall()
            return [dict(r) for r in rows]
        except (sqlite3.Error, OSError):
            return []

    # -- outbound idempotency ledger ---------------------------------------

    def begin_attempt(
        self,
        key: str,
        *,
        action: str,
        message_fingerprint: str = "",
        recipient_fingerprint: str = "",
    ) -> dict[str, Any]:
        """Claim an idempotency key or return its existing terminal state.

        ``claimed=True`` means this caller may proceed to the transport. A
        concurrent claimant sees ``claimed=False`` and must not call out. A
        previously failed attempt may be retried; accepted/uncertain/simulated
        attempts may not.
        """
        now = _utc_now()
        try:
            with self._transaction() as conn:
                row = conn.execute(
                    "SELECT * FROM outbound_attempt WHERE idempotency_key = ?", (key,)
                ).fetchone()
                if row is None:
                    conn.execute(
                        "INSERT INTO outbound_attempt"
                        "(idempotency_key, action, state, created_at, updated_at, "
                        "message_fingerprint, recipient_fingerprint, attempts) "
                        "VALUES (?, ?, ?, ?, ?, ?, ?, 1)",
                        (
                            key,
                            action,
                            ATTEMPT_IN_FLIGHT,
                            now,
                            now,
                            message_fingerprint,
                            recipient_fingerprint,
                        ),
                    )
                    return {"claimed": True, "state": ATTEMPT_IN_FLIGHT, "attempt": None}
                state = str(row["state"])
                if state in _DO_NOT_RETRY:
                    return {"claimed": False, "state": state, "attempt": dict(row)}
                if state in (ATTEMPT_FAILED,):
                    conn.execute(
                        "UPDATE outbound_attempt SET state = ?, updated_at = ?, "
                        "attempts = attempts + 1, error = NULL, note = NULL, "
                        "transport = NULL, record_id = NULL, message_id = NULL, "
                        "thread_id = NULL WHERE idempotency_key = ?",
                        (ATTEMPT_IN_FLIGHT, now, key),
                    )
                    return {"claimed": True, "state": ATTEMPT_IN_FLIGHT, "attempt": dict(row)}
                # Unknown states are treated as non-retryable (fail closed).
                return {"claimed": False, "state": state, "attempt": dict(row)}
        except (sqlite3.Error, OSError) as exc:
            raise OutboundStateError(
                f"could not claim outbound attempt: {type(exc).__name__}: {exc}"
            ) from exc

    def finish_attempt(
        self,
        key: str,
        *,
        state: str,
        transport: str | None = None,
        record_id: str | None = None,
        message_id: str | None = None,
        thread_id: str | None = None,
        error: str | None = None,
        note: str | None = None,
    ) -> None:
        if state not in _TERMINAL:
            raise OutboundStateError(f"invalid terminal attempt state: {state!r}")
        try:
            with self._transaction() as conn:
                conn.execute(
                    "UPDATE outbound_attempt SET state = ?, updated_at = ?, "
                    "transport = ?, record_id = ?, message_id = ?, thread_id = ?, "
                    "error = ?, note = ? WHERE idempotency_key = ?",
                    (
                        state,
                        _utc_now(),
                        transport,
                        record_id,
                        message_id,
                        thread_id,
                        _safe_text(error),
                        _safe_text(note),
                        key,
                    ),
                )
        except (sqlite3.Error, OSError) as exc:
            raise OutboundStateError(
                f"could not finish outbound attempt: {type(exc).__name__}: {exc}"
            ) from exc

    def get_attempt(self, key: str) -> dict[str, Any] | None:
        try:
            with self._connect() as conn:
                row = conn.execute(
                    "SELECT * FROM outbound_attempt WHERE idempotency_key = ?", (key,)
                ).fetchone()
            return dict(row) if row is not None else None
        except (sqlite3.Error, OSError):
            return None

    def uncertain_attempts(self, limit: int = 50) -> list[dict[str, Any]]:
        try:
            with self._connect() as conn:
                rows = conn.execute(
                    "SELECT * FROM outbound_attempt WHERE state = ? "
                    "ORDER BY updated_at DESC LIMIT ?",
                    (ATTEMPT_UNCERTAIN, max(1, int(limit))),
                ).fetchall()
            return [dict(r) for r in rows]
        except (sqlite3.Error, OSError):
            return []

    def reconcile_attempt(
        self,
        key: str,
        *,
        outcome: str,
        actor: str | None = None,
        note: str | None = None,
    ) -> dict[str, Any]:
        """Resolve an ``uncertain`` attempt explicitly; never auto-retries."""
        if outcome not in (ATTEMPT_CONFIRMED, ATTEMPT_FAILED):
            raise OutboundStateError(
                "reconciliation outcome must be 'confirmed' or 'failed'"
            )
        try:
            with self._transaction() as conn:
                row = conn.execute(
                    "SELECT state FROM outbound_attempt WHERE idempotency_key = ?", (key,)
                ).fetchone()
                if row is None:
                    raise OutboundStateError("unknown outbound attempt")
                if str(row["state"]) != ATTEMPT_UNCERTAIN:
                    raise OutboundStateError(
                        f"only uncertain attempts can be reconciled (state={row['state']})"
                    )
                conn.execute(
                    "UPDATE outbound_attempt SET state = ?, updated_at = ?, note = ? "
                    "WHERE idempotency_key = ?",
                    (outcome, _utc_now(), _safe_text(note), key),
                )
                conn.execute(
                    "INSERT INTO kill_switch_audit"
                    "(at, event, actor, reason, previous_state, new_state, detail) "
                    "VALUES (?, 'attempt_reconciled', ?, ?, NULL, NULL, ?)",
                    (_utc_now(), actor, note, f"{key}:{outcome}"),
                )
            return {"key": key, "state": outcome}
        except OutboundStateError:
            raise
        except (sqlite3.Error, OSError) as exc:
            raise OutboundStateError(
                f"could not reconcile outbound attempt: {type(exc).__name__}: {exc}"
            ) from exc

    # -- persistent rate limiter -------------------------------------------

    def record_rate_event(
        self,
        limit: int,
        *,
        action: str,
        idempotency_key: str | None = None,
        clock: float | None = None,
    ) -> int:
        """Atomically consume one rate slot, or raise ``RateLimitExceeded``."""
        if limit < 1:
            raise OutboundStateError("rate limit must be >= 1")
        now = time.time() if clock is None else float(clock)
        cutoff = now - 3600.0
        try:
            with self._transaction() as conn:
                conn.execute("DELETE FROM rate_event WHERE at <= ?", (cutoff,))
                count = int(
                    conn.execute("SELECT COUNT(*) FROM rate_event").fetchone()[0]
                )
                if count >= limit:
                    raise RateLimitExceeded(
                        f"rate limit reached: {limit} outbound actions per hour"
                    )
                conn.execute(
                    "INSERT INTO rate_event(at, action, idempotency_key) VALUES (?, ?, ?)",
                    (now, action, idempotency_key),
                )
                return max(0, limit - (count + 1))
        except RateLimitExceeded:
            raise
        except (sqlite3.Error, OSError) as exc:
            raise OutboundStateError(
                f"could not record outbound rate event: {type(exc).__name__}: {exc}"
            ) from exc

    def rate_remaining(self, limit: int, *, clock: float | None = None) -> int:
        now = time.time() if clock is None else float(clock)
        try:
            with self._connect() as conn:
                count = int(
                    conn.execute(
                        "SELECT COUNT(*) FROM rate_event WHERE at > ?", (now - 3600.0,)
                    ).fetchone()[0]
                )
            return max(0, limit - count)
        except (sqlite3.Error, OSError):
            return 0  # fail closed: report no capacity


def _utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _safe_text(value: str | None) -> str | None:
    if value is None:
        return None
    return str(value)[:500]
