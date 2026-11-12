"""One autonomous demo run: architecture sources -> strategy -> email action.

The side panel has exactly one primary action, ``Start Nemesis Demo``. This
module is the backend orchestrator behind it. A run is a real, ordered sequence
of stages; every stage records what actually happened (or the real error that
stopped it) and nothing here fabricates a score, an improvement, or a send.

What the run reuses (no parallel implementation)
-----------------------------------------------
* Architecture / strategy / evaluation Markdown documents that exist in the
  repository are discovered and read, and the rules shown in the panel are
  quoted from those files.
* The strategy hill climb is ``backend.adaptive_harness.AdaptiveHarness``: the
  real controller episode loop, defense adapter, diagnoser, memory, metrics,
  and the regression gate. Baseline vs candidate scores are measured.
* The email step goes through ``backend.nemesis_workflow.NemesisWorkflow`` ->
  ``email_workflow.service``: outgoing defense scan, policy allowlist, rate
  limit, kill switch, idempotency, and (only when owner-armed) the live Gmail
  transport. Simulation is reported as simulation.
* Audit entries come from the same workflow audit log the rest of the backend
  uses.

Runs are single-flight: a second ``start`` while one is active is refused, so a
double click cannot execute the workflow twice.
"""

from __future__ import annotations

import copy
import hashlib
import re
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import backend.feedback as _feedback
import threats
from backend.adaptive_harness import (
    CAMPAIGN_DEFENSE as DEFENSE_TYPE_NONE,
    _default_ladder,
    evaluate_strategy,
)
from backend.nemesis_workflow import NemesisWorkflow, _sandbox_senders
from gmail_demo.attacker import VARIANTS
from gmail_demo.models import Email as DemoEmail
from email_workflow.policy import OperatingMode

ROOT = Path(__file__).resolve().parent.parent

STAGES: tuple[tuple[str, str], ...] = (
    ("architecture", "Load architecture and strategy sources"),
    ("scenario", "Initialize demo scenario and sandbox identities"),
    ("attack_email", "Generate the attack / demo email"),
    ("evaluation", "Evaluate the target and the defense"),
    ("hillclimb", "Run the Hill Climber candidate evaluation"),
    ("decision", "Strategy decision and regression checks"),
    ("email", "Authorized sandbox email execution"),
    ("audit", "Record the final outcome and audit trail"),
)

# Documents are discovered, never assumed: only paths that exist are read.
_ARCHITECTURE_DOCS: tuple[str, ...] = (
    "architecture.md",
    "ARCHITECTURE.md",
    "docs/architecture.md",
    "docs/ARCHITECTURE_DECISIONS.md",
    "docs/ARCHITECTURE_PROMPT.md",
    "docs/decisions/phase1_architecture.md",
    "docs/AUTONOMOUS_EMAIL.md",
    "docs/THREAT_CLASSIFICATION.md",
    "docs/METRICS_DEFINITIONS.md",
    "docs/stage_b_contract.md",
)

_RULE_HINT = re.compile(
    r"(architecture|strategy|strategies|regression|gate|utility|episode|"
    r"allowlist|kill switch|simulation|metric|scope|least privilege|"
    r"defen[cs]e|attacker|baseline|candidate)",
    re.IGNORECASE,
)
_HEADING = re.compile(r"^(#{1,3})\s+(.+?)\s*$", re.MULTILINE)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _initial_stages() -> list[dict[str, Any]]:
    return [
        {
            "id": stage_id,
            "label": label,
            "state": "pending",
            "detail": "",
            "started_at": None,
            "finished_at": None,
        }
        for stage_id, label in STAGES
    ]


def _stage(run: dict[str, Any], stage_id: str) -> dict[str, Any]:
    for stage in run["stages"]:
        if stage["id"] == stage_id:
            return stage
    raise KeyError(stage_id)


def _stage_start(run: dict[str, Any], stage_id: str, detail: str = "") -> None:
    stage = _stage(run, stage_id)
    stage["state"] = "running"
    stage["started_at"] = _now_iso()
    if detail:
        stage["detail"] = detail


def _stage_done(run: dict[str, Any], stage_id: str, detail: str = "") -> None:
    stage = _stage(run, stage_id)
    stage["state"] = "done"
    stage["finished_at"] = _now_iso()
    if detail:
        stage["detail"] = detail


def _stage_fail(run: dict[str, Any], stage_id: str, detail: str) -> None:
    stage = _stage(run, stage_id)
    stage["state"] = "failed"
    stage["finished_at"] = _now_iso()
    stage["detail"] = detail


def _stage_skip(run: dict[str, Any], stage_id: str, reason: str) -> None:
    stage = _stage(run, stage_id)
    if stage["state"] in ("done", "failed"):
        return
    stage["state"] = "skipped"
    stage["finished_at"] = _now_iso()
    stage["detail"] = reason


class DemoRunner:
    """Owns the single demo run for one Stage B backend instance."""

    def __init__(self, backend: Any, *, root: Path | None = None) -> None:
        self._backend = backend
        self._root = Path(root) if root else ROOT
        self._lock = threading.RLock()
        self._start_lock = threading.Lock()
        self._stop_event = threading.Event()
        self._run: dict[str, Any] | None = None
        self._thread: threading.Thread | None = None

    # -- public API ---------------------------------------------------------

    def start(self, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """Start a run. Refuses while another run is still active."""
        params = params or {}
        if not self._start_lock.acquire(blocking=False):
            raise RuntimeError("a Nemesis demo run is already starting")
        try:
            with self._lock:
                if self._run and self._run["state"] == "running":
                    raise RuntimeError("a Nemesis demo run is already running")
                run = self._new_run(params)
                self._run = run
                self._stop_event.clear()
            worker = threading.Thread(
                target=self._execute, args=(run["run_id"],), daemon=True
            )
            self._thread = worker
            worker.start()
            return self.status()
        finally:
            self._start_lock.release()

    def status(self) -> dict[str, Any]:
        with self._lock:
            if self._run is None:
                return {
                    "run": None,
                    "stages": [
                        {"id": stage_id, "label": label, "state": "pending",
                         "detail": "", "started_at": None, "finished_at": None}
                        for stage_id, label in STAGES
                    ],
                    "running": False,
                }
            snapshot = copy.deepcopy(self._run)
            return {
                "run": snapshot,
                "stages": snapshot["stages"],
                "running": snapshot.get("state") == "running",
            }

    def stop(self) -> dict[str, Any]:
        with self._lock:
            active = bool(self._run and self._run["state"] == "running")
        if active:
            self._stop_event.set()
            try:
                self._backend.adaptive_harness.stop()
            except Exception:  # defensive: stopping must never raise
                pass
        return {"stop_signalled": self._stop_event.is_set(), "running": active}

    # -- run construction ---------------------------------------------------

    def _new_run(self, params: dict[str, Any]) -> dict[str, Any]:
        policy = self._backend._workflow.policy
        transport_name = getattr(self._backend._workflow.transport, "name", "mock")
        live = bool(
            getattr(self._backend._workflow.transport, "executes_live_actions", False)
        )
        configured_mode = policy.mode.value
        return {
            "run_id": f"demo-{uuid.uuid4().hex[:10]}",
            "state": "running",
            "started_at": _now_iso(),
            "finished_at": None,
            "mode": "LIVE" if live else "SIMULATION",
            "configured_mode": configured_mode,
            "transport": transport_name,
            "live_transport_selected": live,
            "live_eligible": bool(live and not policy.kill_switch),
            "mode_detail": (
                f"configured mode={configured_mode}; selected transport={transport_name}; "
                + (
                    "the selected transport can execute real Gmail actions (subject to "
                    "the remaining policy gates)"
                    if live
                    else "no live transport is selected; this run cannot deliver"
                )
            ),
            "params": {
                "episodes": int(params.get("episodes") or 6),
                "max_rounds": int(params.get("max_rounds") or 3),
                "iterations": int(params.get("iterations") or 3),
                "seed": params.get("seed"),
            },
            "stages": _initial_stages(),
            "architecture": None,
            "scenario": None,
            "attack_email": None,
            "evaluation": None,
            "hillclimb": None,
            "decision": None,
            "email": None,
            "audit": None,
            "error": None,
        }

    def _execute(self, run_id: str) -> None:
        with self._lock:
            run = self._run
        if not run or run.get("run_id") != run_id:
            return
        try:
            self._run_stages(run)
        except Exception as exc:  # defensive: a failed run is reported, not hidden
            with self._lock:
                current = None
                for stage in run["stages"]:
                    if stage["state"] == "running":
                        current = stage["id"]
                        _stage_fail(run, stage["id"], f"{type(exc).__name__}: {exc}")
                run["error"] = f"{type(exc).__name__}: {exc}"
                run["state"] = "failed"
                run["finished_at"] = _now_iso()
                for stage_id, _label in STAGES:
                    if _stage(run, stage_id)["state"] == "pending":
                        _stage_skip(
                            run,
                            stage_id,
                            f"not reached: {current or 'earlier stage'} failed",
                        )

    # -- stages -------------------------------------------------------------

    def _run_stages(self, run: dict[str, Any]) -> None:
        params = run["params"]

        # 1. Architecture and strategy sources.
        _stage_start(run, "architecture")
        architecture = self._read_architecture()
        with self._lock:
            run["architecture"] = architecture
        if not architecture["documents"]:
            _stage_fail(
                run,
                "architecture",
                "no architecture or strategy Markdown documents were found",
            )
            run["state"] = "failed"
            run["error"] = "architecture sources missing"
            run["finished_at"] = _now_iso()
            self._skip_remaining(run, "architecture failed")
            return
        _stage_done(
            run,
            "architecture",
            f"{len(architecture['documents'])} document(s) read, "
            f"{len(architecture['rules'])} quoted rule(s)",
        )
        if self._check_stop(run, "scenario"):
            return

        # 2. Demo scenario and sandbox identities.
        _stage_start(run, "scenario")
        scenario = self._build_scenario(run["run_id"])
        with self._lock:
            run["scenario"] = scenario
        _stage_done(
            run,
            "scenario",
            f"{scenario['name']} | attacker={scenario['attacker_sender']} | "
            f"sandbox recipient={scenario['sandbox_recipient'] or 'none configured'}",
        )
        if self._check_stop(run, "attack_email"):
            return

        # 3. Attack / demo email generation (deterministic, offline).
        _stage_start(run, "attack_email")
        variant = VARIANTS[scenario["variant_index"]]
        email = DemoEmail(
            id=f"{run['run_id']}-attack",
            sender=variant.sender,
            subject=variant.subject,
            body=variant.body,
            labels=["NEMESIS_DEMO"],
        )
        payload = {
            "variant": variant.key,
            "variant_number": variant.number,
            "variant_name": variant.name,
            "sender": variant.sender,
            "subject": variant.subject,
            "body_sha256": _sha256(variant.body),
            "body_preview": threats.redact_digits(variant.body)[:180],
        }
        with self._lock:
            run["attack_email"] = payload
        _stage_done(run, "attack_email", f"{variant.name} from {variant.sender}")
        if self._check_stop(run, "evaluation"):
            return

        # 4. Target and defense evaluation of that email (real ruleset).
        _stage_start(run, "evaluation")
        ruleset = _feedback.active_ruleset(self._backend._feedback_path())
        verdict = threats.assess_email(email, ruleset)
        baseline_eval = evaluate_strategy(
            _default_ladder(int(params["max_rounds"])),
            episodes=int(params["episodes"]),
            max_rounds=int(params["max_rounds"]),
            seed=int(params["seed"] if params["seed"] is not None else 11),
            strategy_id=f"{run['run_id']}-baseline",
            stop_event=self._stop_event,
            # Run Experiment is attack-only; the harness baseline it is
            # compared against is measured the same way.
            defense=DEFENSE_TYPE_NONE,
        )
        with self._lock:
            run["evaluation"] = {
                "verdict": verdict,
                "rule_version": ruleset.version,
                "ruleset_source": str(self._backend._feedback_path() or "")
                or "shipped defaults",
                "baseline": baseline_eval.to_dict(),
            }
        _stage_done(
            run,
            "evaluation",
            f"decision={verdict['decision']} score={verdict['risk_score']} "
            f"| baseline ASR={baseline_eval.asr} utility={baseline_eval.utility_score}",
        )
        if self._check_stop(run, "hillclimb"):
            return

        # 5. Hill Climber: real harness run (candidate ladders vs baseline).
        _stage_start(run, "hillclimb")
        harness = self._backend.adaptive_harness
        started = harness.start(
            episodes=int(params["episodes"]),
            max_rounds=int(params["max_rounds"]),
            iterations=int(params["iterations"]),
            seed=int(params["seed"]) if params["seed"] is not None else None,
            background=False,
        )
        harness_run_id = started["run"]["run_id"]
        state = harness.status()
        record = None
        for entry in state.get("runs", []):
            if entry.get("run_id") == harness_run_id:
                record = entry
                break
        if record is None:
            raise RuntimeError(
                f"hill-climb run {harness_run_id} produced no stored record"
            )
        active = state.get("strategy_engine", {}).get("active", {})
        candidate_eval = None
        for stored in state.get("candidates", []):
            if stored.get("candidate_id") == record.get("candidate_id"):
                candidate_eval = stored.get("evaluation")
                break
        final_candidate_asr = (
            candidate_eval.get("asr") if candidate_eval else record.get("best_asr")
        )
        hillclimb = {
            "run_id": harness_run_id,
            "status": record.get("status"),
            "iterations": record.get("iterations"),
            "iteration": record.get("iteration"),
            "episodes": record.get("episodes"),
            "baseline_asr": record.get("baseline_asr"),
            "best_asr": record.get("best_asr"),
            "candidate_asr": final_candidate_asr,
            "improved": record.get("improved"),
            "converged": record.get("converged"),
            "history": record.get("history", []),
            "gate": record.get("gate", {}),
            "candidate_id": record.get("candidate_id"),
            "utility_floor": state.get("strategy_engine", {}).get("utility_floor"),
            "min_episodes_for_promotion": state.get("strategy_engine", {}).get(
                "min_episodes_for_promotion"
            ),
            "active_strategy_id": active.get("strategy_id"),
            "active_ladder": active.get("ladder", []),
            "active_evaluation": active.get("evaluation") or {},
            "candidate_evaluation": candidate_eval or {},
            "candidate_ladder": [
                h.get("candidate_ladder")
                for h in record.get("history", [])[-1:]
            ],
            "baseline_ladder": _default_ladder(int(params["max_rounds"])),
        }
        with self._lock:
            run["hillclimb"] = hillclimb
        _stage_done(
            run,
            "hillclimb",
            f"run {harness_run_id}: baseline ASR={record.get('baseline_asr')} "
            f"-> candidate {final_candidate_asr} (best observed "
            f"{record.get('best_asr')}) over "
            f"{len(record.get('history', []))} candidate evaluation(s)",
        )
        if self._check_stop(run, "decision"):
            return

        # 6. Strategy decision + regression gate outcome.
        _stage_start(run, "decision")
        gate = record.get("gate") or {}
        passed = bool(gate.get("passed"))
        decision = {
            "outcome": "retained" if passed else "rejected",
            "gate": gate,
            "reasons": gate.get("reasons", []),
            "candidate_id": record.get("candidate_id"),
            "strategy_id": (
                record.get("candidate_id") if passed else active.get("strategy_id")
            ),
            "baseline_asr": record.get("baseline_asr"),
            "candidate_asr": final_candidate_asr,
            "best_asr": record.get("best_asr"),
            "changed": bool(record.get("improved")),
        }
        with self._lock:
            run["decision"] = decision
        _stage_done(
            run,
            "decision",
            (
                f"candidate {decision['candidate_id']} retained; gate passed"
                if passed
                else f"candidate {decision['candidate_id']} rejected: "
                + "; ".join(decision["reasons"] or ["gate did not pass"])
            ),
        )
        if self._check_stop(run, "email"):
            return

        # 7. Authorized sandbox email action (policy-gated transport path).
        _stage_start(run, "email")
        email_result = self._execute_email(run, verdict, decision)
        with self._lock:
            run["email"] = email_result
        if email_result["status"] == "failed":
            _stage_fail(run, "email", email_result["detail"])
            run["state"] = "failed"
            run["error"] = email_result["detail"]
            run["finished_at"] = _now_iso()
            self._skip_remaining(run, "email step failed")
            return
        _stage_done(
            run,
            "email",
            f"{email_result['label']}: {email_result['detail']}",
        )

        # 8. Final outcome + audit.
        _stage_start(run, "audit")
        activity = self._safe_activity()
        audit = {
            "event_id": run["run_id"],
            "workflow_entries": activity.get("workflow", [])[-6:],
            "feedback_entries": activity.get("feedback_audit", [])[-3:],
            "quality_entries": activity.get("quality_audit", [])[-3:],
        }
        with self._lock:
            run["audit"] = audit
            run["state"] = "completed"
            run["finished_at"] = _now_iso()
        _stage_done(
            run,
            "audit",
            f"audit run id {run['run_id']} | "
            f"{len(audit['workflow_entries'])} workflow entr(y/ies) recorded",
        )

    # -- stage helpers ------------------------------------------------------

    def _check_stop(self, run: dict[str, Any], next_stage_id: str) -> bool:
        """Mark the run stopped before the next stage when a stop was asked."""
        if not self._stop_event.is_set():
            return False
        with self._lock:
            run["state"] = "stopped"
            run["finished_at"] = _now_iso()
        _stage_skip(run, next_stage_id, "run stopped by operator")
        self._skip_remaining(run, "run stopped by operator")
        return True

    def _skip_remaining(self, run: dict[str, Any], reason: str) -> None:
        for stage_id, _label in STAGES:
            if _stage(run, stage_id)["state"] == "pending":
                _stage_skip(run, stage_id, reason)

    def _safe_activity(self) -> dict[str, Any]:
        try:
            workflow = NemesisWorkflow(
                workflow_service=self._backend._workflow,
                kill_switch=self._backend._workflow.policy.kill_switch,
                policy=self._backend._workflow.policy,
            )
            return workflow.activity(limit=10)
        except Exception as exc:  # defensive: audit failure must be visible
            return {"workflow": [], "feedback_audit": [], "quality_audit": [],
                    "error": f"activity unavailable: {exc}"}

    # -- architecture -------------------------------------------------------

    def _read_architecture(self) -> dict[str, Any]:
        documents: list[dict[str, Any]] = []
        rules: list[dict[str, str]] = []
        seen_rules: set[str] = set()
        seen_paths: set[Path] = set()
        for rel in _ARCHITECTURE_DOCS:
            path = (self._root / rel).resolve()
            if path in seen_paths or not path.is_file():
                continue
            seen_paths.add(path)
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            headings = [h[1].strip() for h in _HEADING.findall(text)][:8]
            rel_name = path.relative_to(self._root).as_posix()
            documents.append(
                {
                    "path": rel_name,
                    "bytes": len(text.encode("utf-8")),
                    "sha256": _sha256(text),
                    "headings": headings,
                    "sections": len(headings),
                }
            )
            # Every discovered document is read; the quoted rules are
            # capped per document so one long file cannot crowd out the rest.
            quoted = 0
            for raw in text.splitlines():
                if quoted >= 4 or len(rules) >= 16:
                    break
                line = raw.strip()
                if len(line) < 24 or len(line) > 200:
                    continue
                if line.startswith(("#", "|", ">", "<", "```", "![")):
                    continue
                if "](" in line:
                    continue
                line = line.lstrip("-*0123456789. ").strip()
                if len(line) < 24 or not _RULE_HINT.search(line):
                    continue
                key = line.lower()
                if key in seen_rules:
                    continue
                seen_rules.add(key)
                rules.append({"text": line, "source": rel_name})
                quoted += 1
        return {
            "documents": documents,
            "rules": rules,
            "scanned": [rel for rel in _ARCHITECTURE_DOCS
                        if (self._root / rel).is_file()],
        }

    # -- scenario -----------------------------------------------------------

    def _build_scenario(self, run_id: str) -> dict[str, Any]:
        policy = self._backend._workflow.policy
        senders = _sandbox_senders()
        allowed = sorted(policy.allowed_recipients)
        variant_index = 1  # instruction_override: the classic exfil attempt
        variant = VARIANTS[variant_index]
        return {
            "id": f"scenario-{run_id}",
            "name": f"Payroll exfiltration attempt ({variant.name})",
            "variant_index": variant_index,
            "variant": variant.key,
            "attacker_sender": variant.sender,
            "sender_identity": senders["sender_a"]["address"],
            "recipient_identity": senders["sender_b"]["address"],
            "sandbox_recipient": allowed[0] if allowed else "",
            "allowed_recipients": allowed,
            "allowed_domains": sorted(policy.allowed_domains),
            "policy_mode": policy.mode.value,
            "kill_switch": bool(policy.kill_switch),
            "rate_limit_per_hour": policy.rate_limit_per_hour,
        }

    # -- email action -------------------------------------------------------

    def _execute_email(
        self, run: dict[str, Any], verdict: dict[str, Any], decision: dict[str, Any]
    ) -> dict[str, Any]:
        policy = self._backend._workflow.policy
        scenario = run["scenario"] or {}
        recipient = scenario.get("sandbox_recipient") or ""
        strategy = decision.get("strategy_id") or "baseline"
        base = {
            "mode": run["mode"],
            "transport": getattr(self._backend._workflow.transport, "name", "?"),
            "recipient": recipient,
            "purpose": "send",
        }
        if policy.kill_switch and policy.mode is not OperatingMode.SIMULATION:
            return {
                **base,
                "status": "blocked",
                "label": "BLOCKED",
                "detail": "outbound kill switch is engaged; no submission was attempted",
                "simulated": False,
                "executed": False,
            }
        if not recipient:
            return {
                **base,
                "status": "blocked",
                "label": "BLOCKED",
                "detail": (
                    "no allowlisted sandbox recipient is configured "
                    "(NEMESIS_ALLOWED_RECIPIENTS is empty); the send was not submitted"
                ),
                "simulated": False,
                "executed": False,
            }
        workflow = NemesisWorkflow(
            workflow_service=self._backend._workflow,
            kill_switch=policy.kill_switch,
            policy=policy,
        )
        subject = f"Nemesis demo {run['run_id']}: defended {verdict['decision']} verdict"
        if len(subject) > 120:
            subject = subject[:117] + "..."
        body = (
            "Nemesis autonomous demo completed.\n\n"
            f"Scenario: {scenario.get('name')}\n"
            f"Inbound verdict: {verdict['decision']} "
            f"(risk {verdict['risk_level']}, score {verdict['risk_score']})\n"
            f"Strategy retained: {strategy}\n"
            f"Baseline ASR: {decision.get('baseline_asr')} -> "
            f"candidate ASR: {decision.get('candidate_asr')}\n"
            "This message was generated by the Nemesis autonomous workflow.\n"
        )
        try:
            prepared = workflow.prepare_new(
                to=[recipient],
                subject=subject,
                body=body,
                settings=None,
                confirm=False,
            )
        except Exception as exc:
            return {
                **base,
                "status": "blocked",
                "label": "BLOCKED",
                "detail": f"prepare refused: {type(exc).__name__}: {exc}",
                "simulated": False,
                "executed": False,
            }
        message = (prepared.get("report") or {}).get("message") or {}
        if not message:
            return {
                **base,
                "status": "failed",
                "label": "FAILED",
                "detail": f"prepare returned status {prepared.get('status')!r} "
                "without a composed message",
                "simulated": False,
                "executed": False,
            }
        try:
            submitted = workflow.submit(
                message=message,
                purpose="send",
                confirm=False,
                prepared_id=str(message.get("message_id") or ""),
            )
        except Exception as exc:
            return {
                **base,
                "status": "failed",
                "label": "FAILED",
                "detail": f"submit raised {type(exc).__name__}: {exc}",
                "simulated": False,
                "executed": False,
            }
        report = submitted.get("report") or {}
        status = str(report.get("status") or "")
        executed = bool(report.get("executed"))
        simulated = bool(report.get("simulated"))
        transport_called = bool(report.get("transport_called"))
        reason = report.get("reason") or ""
        transport = report.get("transport") or {}
        if status == "sent" or executed:
            if reported_delivery_confirmed(transport):
                label, state = "DELIVERED", "delivered"
                detail = "Gmail accepted the send and the transport reported delivery."
            else:
                label, state = "ACCEPTED", "accepted"
                detail = (
                    "Gmail accepted the send request "
                    f"(message id {transport.get('message_id') or transport.get('record_id') or 'n/a'}"
                    f", thread id {transport.get('thread_id') or 'n/a'}); "
                    "delivery to the recipient is not confirmed by this API."
                )
        elif status == "simulated_send":
            label, state = "SIMULATED", "simulated"
            detail = reason or "simulation mode: nothing left the process"
        elif status == "uncertain":
            label, state = "UNCERTAIN", "uncertain"
            detail = reason or (
                "Gmail may have accepted the message; automatic retry is disabled"
            )
        elif status == "denied":
            label, state = "BLOCKED", "blocked"
            detail = reason or "policy denied the submission"
        else:
            label, state = "FAILED", "failed"
            detail = reason or f"workflow status {status!r}"
        return {
            **base,
            "status": state,
            "label": label,
            "detail": detail,
            "simulated": simulated,
            "executed": executed,
            "transport_called": transport_called,
            "transport": transport,
            "audit_id": report.get("audit_id"),
            "defense": report.get("defense"),
            "workflow_status": status,
            "subject": message.get("subject"),
            "to": message.get("to"),
            "body_sha256": _sha256(str(message.get("body") or "")),
        }


def reported_delivery_confirmed(transport: dict[str, Any] | None) -> bool:
    """Delivery is only 'confirmed' when the transport explicitly says so."""
    if not isinstance(transport, dict):
        return False
    for key in ("delivered", "delivery_confirmed"):
        if transport.get(key) is True:
            return True
    return False


# ---------------------------------------------------------------------------
# Route hand-holders used by backend.stage_b
# ---------------------------------------------------------------------------


def demo_runner(backend: Any) -> DemoRunner:
    runner = getattr(backend, "_demo_runner", None)
    if runner is None:
        runner = DemoRunner(backend)
        backend._demo_runner = runner
    return runner


async def nemesis_demo_run(request: Any, backend: Any) -> Any:
    from fastapi.responses import JSONResponse

    auth_error = backend._require_auth(request)
    if auth_error:
        return auth_error
    body: dict[str, Any] = {}
    try:
        parsed = await request.json()
        if isinstance(parsed, dict):
            body = parsed
    except Exception:
        body = {}
    try:
        snapshot = demo_runner(backend).start(body)
        return JSONResponse(status_code=200, content={"status": "ok", "demo": snapshot})
    except RuntimeError as exc:
        return JSONResponse(status_code=409, content={"error": str(exc)})
    except Exception as exc:
        return JSONResponse(
            status_code=500, content={"error": f"demo run failed to start: {exc}"}
        )


async def nemesis_demo_status(request: Any, backend: Any) -> Any:
    from fastapi.responses import JSONResponse

    auth_error = backend._require_auth(request)
    if auth_error:
        return auth_error
    try:
        return JSONResponse(
            status_code=200,
            content={"status": "ok", "demo": demo_runner(backend).status()},
        )
    except Exception as exc:
        return JSONResponse(
            status_code=500, content={"error": f"demo status failed: {exc}"}
        )


async def nemesis_demo_stop(request: Any, backend: Any) -> Any:
    from fastapi.responses import JSONResponse

    auth_error = backend._require_auth(request)
    if auth_error:
        return auth_error
    try:
        return JSONResponse(
            status_code=200,
            content={"status": "ok", "stop": demo_runner(backend).stop()},
        )
    except Exception as exc:
        return JSONResponse(
            status_code=500, content={"error": f"demo stop failed: {exc}"}
        )
