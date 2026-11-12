"""Gmail agent: composition is local-model-backed and sending is explicit.

These are unit tests for the contract, not proof of a real send. Real model and
real Gmail behavior are exercised separately in the live run.
"""

from __future__ import annotations

import pytest

from backend import gmail_agent


def test_parse_json_object_accepts_fenced_output():
    data = gmail_agent._parse_json_object('```json\n{"subject": "Hi", "body": "Hello"}\n```')
    assert data["subject"] == "Hi"


def test_parse_json_object_rejects_non_json():
    with pytest.raises(gmail_agent.GmailAgentError):
        gmail_agent._parse_json_object("no json here")


def test_generate_compose_without_recipient_is_rejected():
    with pytest.raises(gmail_agent.GmailAgentError):
        gmail_agent.generate(action="compose", recipient="", instruction="say hi")


def test_generate_compose_uses_model_and_returns_unsent_draft(monkeypatch, tmp_path):
    monkeypatch.setattr(gmail_agent, "HISTORY_PATH", tmp_path / "history.json")

    def fake_model(prompt):
        assert "write a compose email" in prompt.lower()
        return (
            {"subject": "Quarterly update", "body": "Here is the update."},
            {"provider": "ollama", "model": "llama3.1:8b", "url": "http://127.0.0.1:11434"},
        )

    monkeypatch.setattr(gmail_agent, "_generate_with_ollama", fake_model)
    draft = gmail_agent.generate(
        action="compose", recipient="owner@example.com", instruction="summarize"
    )
    assert draft["to"] == "owner@example.com"
    assert draft["subject"] == "Quarterly update"
    assert draft["body"] == "Here is the update."
    assert draft["model"] == "llama3.1:8b"
    assert draft["sent"] is False
    assert gmail_agent.history()[0]["type"] == "draft"


def test_generate_reply_derives_recipient_from_source_sender(monkeypatch, tmp_path):
    monkeypatch.setattr(gmail_agent, "HISTORY_PATH", tmp_path / "history.json")
    monkeypatch.setattr(
        gmail_agent,
        "message_context",
        lambda mid: {
            "id": mid,
            "thread_id": "thread-1",
            "from": "Sender Name <sender@example.com>",
            "to": "owner@example.com",
            "subject": "Original",
            "date": "",
            "message_id_header": "<abc@example.com>",
            "references": ["<abc@example.com>"],
            "body": "Original body",
            "label_ids": ["NEMESIS_DEMO"],
        },
    )
    monkeypatch.setattr(
        gmail_agent,
        "_generate_with_ollama",
        lambda prompt: (
            {"subject": "Original", "body": "Thanks for the note."},
            {"provider": "ollama", "model": "llama3.1:8b", "url": "http://127.0.0.1:11434"},
        ),
    )
    draft = gmail_agent.generate(action="reply", message_id="m1")
    assert draft["to"] == "sender@example.com"
    assert draft["subject"].startswith("Re:")
    assert draft["thread_id"] == "thread-1"
    assert draft["in_reply_to"] == "<abc@example.com>"
    assert draft["context_used"] is True


def test_send_without_recipient_raises():
    with pytest.raises(gmail_agent.GmailAgentError):
        gmail_agent.send({"to": "", "subject": "x", "body": "y"})


def test_send_reports_policy_failure_without_claiming_success(monkeypatch, tmp_path):
    monkeypatch.setattr(gmail_agent, "HISTORY_PATH", tmp_path / "history.json")

    class FailingService:
        def prepare_message(self, message, *, confirmed=False):
            from email_workflow.policy import PolicyDenied

            raise PolicyDenied("kill switch engaged: all outbound actions refused")

    monkeypatch.setattr(gmail_agent, "_build_service", lambda: FailingService())
    result = gmail_agent.send(
        {"to": "owner@example.com", "subject": "Test", "body": "Body", "action": "compose"}
    )
    assert result["sent"] is False
    assert result["message_id"] is None
    assert "kill switch" in result["reason"]
    assert gmail_agent.history()[0]["status"] == "denied"


def test_recent_duplicate_blocks_identical_resend(monkeypatch, tmp_path):
    monkeypatch.setattr(gmail_agent, "HISTORY_PATH", tmp_path / "history.json")
    digest = gmail_agent._draft_hash("owner@example.com", "Subject", "Body")
    gmail_agent._append_history(
        {
            "at": gmail_agent._now_iso(),
            "type": "send",
            "status": "sent",
            "digest": digest,
            "message_id": "abc123",
            "thread_id": "t1",
            "to": "owner@example.com",
            "subject": "Subject",
        }
    )
    dup = gmail_agent._recent_duplicate(digest)
    assert dup is not None
    assert dup["message_id"] == "abc123"
