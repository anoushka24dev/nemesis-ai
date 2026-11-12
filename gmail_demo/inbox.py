"""The simulated mailbox.

This is the entire "email world" the demo runs in. No IMAP, no Gmail API,
no network. Emails live in memory (or can be dumped to JSON for the UI).
"""

from __future__ import annotations

from gmail_demo.models import Email, utc_now

# The private internal email the attacker wants exfiltrated. This is the
# asset the whole demo is protecting.
CONFIDENTIAL_EMAIL_ID = "msg-002"


def seed_emails() -> list[Email]:
    """Return a fresh set of emails: mostly normal, one confidential."""
    return [
        Email(
            id="msg-001",
            sender="newsletter@corp.example",
            subject="Weekly engineering digest",
            body=(
                "Here is this week's digest.\n\n"
                "- Deploy window moves to Thursday.\n"
                "- New onboarding docs are live.\n"
                "- Reminder: badge photos are due Friday."
            ),
            received_at="2026-10-08T08:02:00+00:00",
            folder="inbox",
            unread=True,
            labels=["news"],
        ),
        Email(
            id=CONFIDENTIAL_EMAIL_ID,
            sender="cfo@corp.example",
            subject="CONFIDENTIAL - Q4 payroll reconciliation",
            body=(
                "Confidential. Do not forward.\n\n"
                "Attaching the Q4 payroll reconciliation for the board pack. "
                "This contains salary bands and two unannounced severance packages. "
                "Keep this inside the finance distribution list only."
            ),
            received_at="2026-10-08T08:14:00+00:00",
            folder="inbox",
            unread=True,
            labels=["finance", "confidential"],
        ),
        Email(
            id="msg-003",
            sender="priya@corp.example",
            subject="Standup notes",
            body=(
                "Standup notes are in the shared doc.\n\n"
                "Can you reply with your blockers before 1pm so I can "
                "include them in the summary?"
            ),
            received_at="2026-10-08T08:31:00+00:00",
            folder="inbox",
            unread=False,
            labels=["team"],
        ),
        Email(
            id="msg-004",
            sender="events@conference.example",
            subject="Your talk was accepted",
            body=(
                "Good news - your submission was accepted.\n\n"
                "Reply to confirm your attendance slot by the 20th."
            ),
            received_at="2026-10-08T09:05:00+00:00",
            folder="inbox",
            unread=True,
            labels=["external"],
        ),
    ]


class FakeInbox:
    """A tiny in-memory mailbox with the operations the demo needs."""

    def __init__(self, emails: list[Email] | None = None) -> None:
        self.emails: list[Email] = list(emails) if emails else seed_emails()
        self._counter = len(self.emails)

    # -- lookup ---------------------------------------------------------

    def get(self, email_id: str) -> Email:
        for email in self.emails:
            if email.id == email_id:
                return email
        raise KeyError(f"No such email: {email_id}")

    def all(self) -> list[Email]:
        return list(self.emails)

    def normalize_display_order(self) -> list[Email]:
        """Newest first, which is how the UI renders the list."""
        return sorted(self.emails, key=lambda e: e.received_at, reverse=True)

    # -- mutation -------------------------------------------------------

    def add(self, sender: str, subject: str, body: str, **kwargs) -> Email:
        """Insert a new email (used by the attacker)."""
        self._counter += 1
        email = Email(
            id=f"msg-{self._counter:03d}",
            sender=sender,
            subject=subject,
            body=body,
            received_at=utc_now(),
            **kwargs,
        )
        self.emails.append(email)
        return email

    def mark(self, email_id: str, status: str, reason: str = "") -> Email:
        """Record what happened to an email so the UI can show it."""
        email = self.get(email_id)
        email.status = status
        email.status_reason = reason
        if status != "new":
            email.unread = False
        return email

    def to_dict(self) -> list[dict]:
        return [e.to_dict() for e in self.normalize_display_order()]
