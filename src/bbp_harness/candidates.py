from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from typing import Any

from .db import Database
from .ids import new_id
from .util import canonical_json, utcnow


STATES = (
    "HYPOTHESIS",
    "CANDIDATE",
    "REPRODUCED",
    "NEGATIVE_CONTROL_PASS",
    "COUNTERFACTUAL_PASS",
    "SKEPTIC_PASS",
    "PRIOR_ART_CLEAR",
    "STRONG",
    "REPORT_READY",
    "BLOCKED",
    "KILLED",
)

LINEAR_STATES = STATES[:9]

KILL_CODES = {
    "KILL_NO_ATTACKER_CONTROL",
    "KILL_UNREACHABLE",
    "KILL_DOCUMENTED_BEHAVIOR",
    "KILL_EQUAL_AUTHORITY",
    "KILL_NO_PROTECTED_EFFECT",
    "KILL_NO_CAPABILITY_DELTA",
    "KILL_KNOWN",
    "KILL_DUPLICATE",
    "KILL_OUT_OF_SCOPE",
    "KILL_NON_PRODUCTION_TARGET",
    "KILL_THREAT_MODEL",
    "KILL_ENVIRONMENT_MISMATCH",
    "KILL_NO_PRODUCTION_REACHABILITY",
    "KILL_SCHEMA_INVALID",
    "KILL_SAFETY_BOUNDARY",
}


@dataclass(slots=True)
class GateDecision:
    allowed: bool
    next_state: str | None
    blockers: list[str]


class CandidateStateMachine:
    def __init__(self, database: Database, reproduction_threshold: int = 3):
        self.database = database
        self.reproduction_threshold = reproduction_threshold

    def create(
        self,
        campaign_id: str,
        title: str,
        hypothesis_id: str | None = None,
        candidate_class: str = "unknown",
        root_cause_family: str = "",
        dossier: dict[str, Any] | None = None,
        candidate_id: str | None = None,
    ) -> str:
        identity = candidate_id or new_id("C")
        now = utcnow()
        with self.database.transaction(immediate=True) as connection:
            connection.execute(
                """
                INSERT INTO candidates(
                    id, campaign_id, hypothesis_id, title, class, root_cause_family,
                    state, dossier_json, created_at, updated_at
                ) VALUES(?,?,?,?,?,?,'HYPOTHESIS',?,?,?)
                """,
                (
                    identity,
                    campaign_id,
                    hypothesis_id,
                    title,
                    candidate_class,
                    root_cause_family,
                    canonical_json(dossier or {}),
                    now,
                    now,
                ),
            )
            self.database.event(
                campaign_id,
                "candidate",
                identity,
                "CANDIDATE_CREATED",
                {"state": "HYPOTHESIS", "title": title},
                connection,
            )
        return identity

    def get(self, candidate_id: str, connection: sqlite3.Connection | None = None) -> sqlite3.Row:
        if connection is not None:
            row = connection.execute("SELECT * FROM candidates WHERE id=?", (candidate_id,)).fetchone()
        else:
            row = self.database.one("SELECT * FROM candidates WHERE id=?", (candidate_id,))
        if row is None:
            raise KeyError(f"unknown candidate: {candidate_id}")
        return row

    def update(self, candidate_id: str, **fields: Any) -> None:
        allowed = {
            "title",
            "class",
            "root_cause_family",
            "verdict",
            "attacker_control",
            "reachability",
            "protected_boundary",
            "capability_delta",
            "reproduction_attempts",
            "reproduction_successes",
            "negative_control",
            "counterfactual",
            "skeptic",
            "prior_art",
            "evidence_gate",
            "impact_gate",
            "manual_status",
            "severity_status",
            "severity_locked",
            "triager_proof",
            "dossier_json",
        }
        unknown = set(fields) - allowed
        if unknown:
            raise ValueError(f"unsupported candidate fields: {sorted(unknown)}")
        if not fields:
            return
        if "dossier_json" in fields and not isinstance(fields["dossier_json"], str):
            fields["dossier_json"] = canonical_json(fields["dossier_json"])
        fields["updated_at"] = utcnow()
        assignments = ", ".join(f"{name}=?" for name in fields)
        values = list(fields.values()) + [candidate_id]
        with self.database.transaction(immediate=True) as connection:
            row = self.get(candidate_id, connection)
            connection.execute(f"UPDATE candidates SET {assignments} WHERE id=?", values)
            self.database.event(
                row["campaign_id"],
                "candidate",
                candidate_id,
                "CANDIDATE_EVIDENCE_UPDATED",
                fields,
                connection,
            )

    def decision(self, row: sqlite3.Row) -> GateDecision:
        state = str(row["state"])
        if state in {"KILLED", "BLOCKED", "REPORT_READY"}:
            return GateDecision(False, None, [f"terminal state: {state}"])
        if state == "HYPOTHESIS":
            checks = {
                "attacker control": row["attacker_control"] == "PROVEN",
                "release reachability": row["reachability"] == "PROVEN",
                "protected boundary": row["protected_boundary"] == "PROVEN",
                "capability delta": row["capability_delta"] == "PROVEN",
            }
            return self._from_checks("CANDIDATE", checks)
        if state == "CANDIDATE":
            checks = {
                f"reproduction successes >= {self.reproduction_threshold}": int(row["reproduction_successes"])
                >= self.reproduction_threshold,
                "all reproduction attempts succeeded": int(row["reproduction_attempts"]) > 0
                and int(row["reproduction_successes"]) == int(row["reproduction_attempts"]),
            }
            return self._from_checks("REPRODUCED", checks)
        if state == "REPRODUCED":
            return self._from_checks("NEGATIVE_CONTROL_PASS", {"negative control": row["negative_control"] == "PASS"})
        if state == "NEGATIVE_CONTROL_PASS":
            return self._from_checks("COUNTERFACTUAL_PASS", {"counterfactual": row["counterfactual"] == "PASS"})
        if state == "COUNTERFACTUAL_PASS":
            return self._from_checks("SKEPTIC_PASS", {"skeptic review": row["skeptic"] == "PASS"})
        if state == "SKEPTIC_PASS":
            return self._from_checks("PRIOR_ART_CLEAR", {"prior art": row["prior_art"] == "CLEAR"})
        if state == "PRIOR_ART_CLEAR":
            checks = {
                "evidence gate": row["evidence_gate"] == "PASS",
                "program impact gate": row["impact_gate"] == "PASS",
                "manual reproduction": row["manual_status"] == "MANUALLY_CONFIRMED",
                "severity locked": bool(row["severity_locked"]),
            }
            return self._from_checks("STRONG", checks)
        if state == "STRONG":
            return self._from_checks("REPORT_READY", {"triager proof": row["triager_proof"] == "PASS"})
        return GateDecision(False, None, [f"unrecognized state: {state}"])

    @staticmethod
    def _from_checks(next_state: str, checks: dict[str, bool]) -> GateDecision:
        blockers = [name for name, passed in checks.items() if not passed]
        return GateDecision(not blockers, next_state if not blockers else None, blockers)

    def advance(self, candidate_id: str, actor: str = "state-machine") -> dict[str, Any]:
        transitions: list[dict[str, str]] = []
        with self.database.transaction(immediate=True) as connection:
            while True:
                row = self.get(candidate_id, connection)
                decision = self.decision(row)
                if not decision.allowed or not decision.next_state:
                    return {
                        "candidate_id": candidate_id,
                        "state": row["state"],
                        "advanced": transitions,
                        "blockers": decision.blockers,
                    }
                from_state = str(row["state"])
                to_state = decision.next_state
                now = utcnow()
                report_ready = 1 if to_state == "REPORT_READY" else int(row["report_ready"])
                verdict = "STRONG" if to_state in {"STRONG", "REPORT_READY"} else row["verdict"]
                connection.execute(
                    "UPDATE candidates SET state=?, report_ready=?, verdict=?, updated_at=? WHERE id=?",
                    (to_state, report_ready, verdict, now, candidate_id),
                )
                connection.execute(
                    """
                    INSERT INTO candidate_transitions(candidate_id, from_state, to_state, reason, evidence_json, actor, created_at)
                    VALUES(?,?,?,?,?,?,?)
                    """,
                    (candidate_id, from_state, to_state, "deterministic gates passed", "[]", actor, now),
                )
                self.database.event(
                    row["campaign_id"],
                    "candidate",
                    candidate_id,
                    "CANDIDATE_TRANSITION",
                    {"from": from_state, "to": to_state},
                    connection,
                )
                transitions.append({"from": from_state, "to": to_state})
                if to_state == "REPORT_READY":
                    return {
                        "candidate_id": candidate_id,
                        "state": to_state,
                        "advanced": transitions,
                        "blockers": [],
                    }

    def kill(
        self,
        candidate_id: str,
        kill_code: str,
        reason: str,
        evidence: list[str] | None = None,
        actor: str = "skeptic",
    ) -> None:
        if kill_code not in KILL_CODES:
            raise ValueError(f"unknown kill code: {kill_code}")
        with self.database.transaction(immediate=True) as connection:
            row = self.get(candidate_id, connection)
            if row["state"] == "REPORT_READY":
                raise ValueError("report-ready candidate cannot be killed without an explicit adjudication workflow")
            now = utcnow()
            connection.execute(
                "UPDATE candidates SET state='KILLED', verdict='KILL', kill_code=?, kill_reason=?, updated_at=? WHERE id=?",
                (kill_code, reason, now, candidate_id),
            )
            connection.execute(
                """
                INSERT INTO candidate_transitions(candidate_id, from_state, to_state, reason, evidence_json, actor, created_at)
                VALUES(?,?,'KILLED',?,?,?,?)
                """,
                (candidate_id, row["state"], reason, canonical_json(evidence or []), actor, now),
            )
            self.database.event(
                row["campaign_id"],
                "candidate",
                candidate_id,
                "CANDIDATE_KILLED",
                {"kill_code": kill_code, "reason": reason, "evidence": evidence or []},
                connection,
            )

    def block(self, candidate_id: str, reason: str, actor: str = "state-machine") -> None:
        with self.database.transaction(immediate=True) as connection:
            row = self.get(candidate_id, connection)
            now = utcnow()
            connection.execute(
                "UPDATE candidates SET state='BLOCKED', kill_reason=?, updated_at=? WHERE id=?",
                (reason, now, candidate_id),
            )
            connection.execute(
                """
                INSERT INTO candidate_transitions(candidate_id, from_state, to_state, reason, evidence_json, actor, created_at)
                VALUES(?,?,'BLOCKED',?,'[]',?,?)
                """,
                (candidate_id, row["state"], reason, actor, now),
            )

    def explain(self, candidate_id: str) -> dict[str, Any]:
        row = self.get(candidate_id)
        decision = self.decision(row)
        transitions = [dict(item) for item in self.database.all(
            "SELECT from_state, to_state, reason, evidence_json, actor, created_at "
            "FROM candidate_transitions WHERE candidate_id=? ORDER BY id",
            (candidate_id,),
        )]
        record = dict(row)
        try:
            record["dossier"] = json.loads(record.pop("dossier_json"))
        except json.JSONDecodeError:
            record["dossier"] = {}
        return {
            "candidate": record,
            "next_state": decision.next_state,
            "current_blockers": decision.blockers,
            "transitions": transitions,
        }
