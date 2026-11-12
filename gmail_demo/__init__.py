"""Simulated Gmail agent demo.

A self-contained, dependency-free demo of a Gmail-style agent, a separate
defense checker, and a persistent 5-variant attacker.

Nothing here talks to a real mailbox, a real network, or an LLM at runtime.
All behavior comes from explicit rules applied to email content.
"""

from gmail_demo.agent import GmailAgent
from gmail_demo.attacker import Attacker
from gmail_demo.defense import DefenseChecker
from gmail_demo.engine import build_state, run_episode
from gmail_demo.inbox import FakeInbox
from gmail_demo.models import build_demo_defense_checker

__all__ = [
    "Attacker",
    "build_demo_defense_checker",
    "build_state",
    "DefenseChecker",
    "FakeInbox",
    "GmailAgent",
    "run_episode",
]
