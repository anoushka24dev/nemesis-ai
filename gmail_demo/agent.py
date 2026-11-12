"""The target agent: a Gmail-style assistant with a real capability set.

The agent can list, read, search, reply, forward, send, delete, move, and
flag. It does NOT decide on its own whether a sensitive action is safe.
Instead it proposes an action and hands it to the defense checker.

Important detail for the demo: the agent normalizes/normalizes obfuscated
text (for example ``intel[at]exfil[dot]io``) before it reads a recipient.
The defense checker does not, and that mismatch is a real, explainable
failure mode the demo is built to surface.
"""

from __future__ import annotations

import re

from gmail_demo.models import (
    BENIGN_ACTIONS,
    SENSITIVE_ACTIONS,
    Email,
    ProposedAction,
    is_external,
)

# Action verbs, ordered by how sensitive they are. A naive assistant that
# follows the strongest instruction it can find is exactly what makes this
# demo interesting.
_ACTION_PRIORITY: tuple[tuple[str, str], ...] = (
    ("forward", r"\bforwards?\b|\bforwarding\b|\bre-?send\b"),
    ("delete", r"\bdeletes?\b|\bdelete\b|\bremove\b|\bpurge\b"),
    ("send", r"\bsends?\b|\bsending\b|\bsend\b|\be-?mail it\b"),
    ("reply", r"\brepl(y|ies|ying)\b|\brespond\b"),
    ("search", r"\bsearch\b|\bfind\b|\blook ?up\b"),
    ("read", r"\bread\b|\bopen\b|\bsummar(y|ize|ise)\b"),
)

# Phrases that mark content as trying to manipulate the agent.
MANIPULATION_MARKERS: tuple[str, ...] = (
    "ignore previous instructions",
    "ignore all previous",
    "ignore prior",
    "disregard",
    "system override",
    "you are now",
    "new instructions",
    "forget your rules",
    "forget the policy",
    "do not tell",
    "without asking",
    "bypass",
)

_ADDRESS_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")

# Obfuscation the agent is happy to undo before reading the content.
_OBFUSCATION = {
    "[at]": "@",
    "(at)": "@",
    "{at}": "@",
    "[dot]": ".",
    "(dot)": ".",
    "{dot}": ".",
    "\u200b": "",
    "\u200c": "",
    "\u200d": "",
}


def normalize_text(text: str) -> str:
    """Undo common email-text obfuscation.

    The agent does this before reading an instruction. The defense checker
    deliberately does not, which is the normalization gap the demo shows.
    """
    out = text
    for token, real in _OBFUSCATION.items():
        out = out.replace(token, real)
    return out


class GmailAgent:
    """The mailbox assistant under test."""

    name = "gmail_agent"

    def propose(self, email: Email) -> ProposedAction:
        """Read one email and propose what to do with it."""
        # The agent reads the *normalized* text.
        text = normalize_text(email.body)
        lowered = text.lower()

        action = self._detect_action(lowered)
        recipients = self._detect_recipients(text)
        recipient = recipients[0] if recipients else ""

        requested = action not in ("read", "none")
        sensitive = action in SENSITIVE_ACTIONS

        manipulated = action in {"reply", "forward"} and any(
            marker in lowered for marker in MANIPULATION_MARKERS
        )

        return ProposedAction(
            action=action,
            email_id=email.id,
            to=recipient,
            requested=requested,
            sensitive=sensitive,
            manipulated=manipulated,
            reason=self._explain(action, recipient, sensitive, manipulated),
        )

    # -- internals ------------------------------------------------------

    @staticmethod
    def _detect_action(lowered_text: str) -> str:
        for action, pattern in _ACTION_PRIORITY:
            if re.search(pattern, lowered_text):
                return action
        return "read"

    @staticmethod
    def _detect_recipients(text: str) -> list[str]:
        return _ADDRESS_RE.findall(text)

    @staticmethod
    def _explain(action: str, recipient: str, sensitive: bool, manipulated: bool) -> str:
        if action in BENIGN_ACTIONS or action == "none":
            return f"Read-only handling ({action}); no privileged action requested."

        parts = [f"Email requests a '{action}'"]
        if recipient:
            kind = "external" if is_external(recipient) else "internal"
            parts.append(f"to {recipient} ({kind} recipient)")
        if sensitive:
            parts.append("this is a sensitive action and needs defense approval")
        if manipulated:
            parts.append("body contains manipulation markers")
        return "; ".join(parts) + "."
