"""Target agent module and adapter interfaces."""

from adaptive_agent_eval.target.adapter import (
    BaseTargetAdapter,
    DeterministicFakeTargetAdapter,
    EmailDemoTargetAdapter,
    ExternalHttpTargetAdapter,
    TargetCapability,
    TargetConfigurationError,
    TargetDeclaration,
    TargetExecutionResult,
    TargetRegistry,
    TargetSession,
    get_target_registry,
)

__all__ = [
    "BaseTargetAdapter",
    "DeterministicFakeTargetAdapter",
    "EmailDemoTargetAdapter",
    "ExternalHttpTargetAdapter",
    "TargetCapability",
    "TargetConfigurationError",
    "TargetDeclaration",
    "TargetExecutionResult",
    "TargetRegistry",
    "TargetSession",
    "get_target_registry",
]
