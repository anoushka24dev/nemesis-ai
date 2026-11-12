#!/usr/bin/env python
"""Standalone launcher for the BYOA HTTP backend server.

Ensures PYTHONPATH includes the project root so ``import backend`` resolves.
"""
import os
import sys

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

if __name__ == "__main__":
    from backend.http_boya_service import _start_server

    server = _start_server()
    try:
        import time as _time

        while True:
            _time.sleep(60)
    except KeyboardInterrupt:
        server.shutdown()
