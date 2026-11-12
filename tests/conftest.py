"""Per-test isolation for the durable outbound workflow state."""
from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _isolated_outbound_state(tmp_path, monkeypatch):
    monkeypatch.setenv(
        "NEMESIS_OUTBOUND_STATE_PATH",
        str(tmp_path / "outbound_state.sqlite3"),
    )
    yield
