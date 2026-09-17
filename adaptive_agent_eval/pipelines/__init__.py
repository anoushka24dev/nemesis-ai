"""Pipelines package — self-contained runnable stub pipelines.

Each pipeline wires together stub versions of the framework components
for a specific experimental configuration (see docs/EXPERIMENT_PLAN.md).
"""

from adaptive_agent_eval.pipelines.mode2_c1 import run_mode2_c1

__all__ = ["run_mode2_c1"]
