"""Adaptive AI Agent Defense Evaluation Framework."""

from adaptive_agent_eval.target.email import (
    EmailAttackGoal,
    EmailDemoRunner,
    EmailTargetAgent,
    PROTECTED_INBOX_ADDRESS,
    SANDBOX_ADDRESS,
    crafted_email_forward,
    crafted_email_reply,
    crafted_email_send,
    demo_trace_text,
    is_trusted_destination,
    run_email_demo,
)

__all__ = [
    "EmailAttackGoal",
    "EmailDemoRunner",
    "EmailTargetAgent",
    "PROTECTED_INBOX_ADDRESS",
    "SANDBOX_ADDRESS",
    "crafted_email_forward",
    "crafted_email_reply",
    "crafted_email_send",
    "demo_trace_text",
    "is_trusted_destination",
    "run_email_demo",
]

__version__ = "0.1.0"
