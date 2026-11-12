# -*- coding: utf-8 -*-
"""
Stage B read-only backend package.

This package is intentionally separate from ``gmail_demo`` and the existing
adaptive-agent-eval test domain. It is the backend layer for the RealGmail
reading pilot extension during development.
"""
from __future__ import annotations

from backend.stage_b import (
    APP_ORIGIN,
    ALLOWED_EXTENSION_ORIGINS,
    StageBBackend,
    create_app,
    create_app_with_defaults,
)

__all__ = [
    "APP_ORIGIN",
    "ALLOWED_EXTENSION_ORIGINS",
    "StageBBackend",
    "create_app",
    "create_app_with_defaults",
]
