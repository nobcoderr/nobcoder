from __future__ import annotations

import json
import unittest

from bbp_harness.orchestrator import Orchestrator
from bbp_harness.workers import ScriptedWorkerRunner

from .helpers import HarnessFixture


MAPPER = {
    "status": "PASS",
    "summary": "fixture mapped",
    "architecture": ["HTTP handler -> object store"],
    "entrypoints": ["app.py:handle"],
    "trust_boundaries": ["user -> tenant object"],
    "protected_sinks": ["store.write"],
    "attack_surfaces": [
        {
            "key": "http-object",
            "kind": "api",
            "name": "object update",
            "location": "app.py:10",
            "trust_boundary": "tenant",
            "protected_sink": "store.write",
            "evidence": ["app.py:10"],
        }
    ],
    "release_reachability": ["fixture release"],
    "knowledge_query_terms": ["authorization", "tenant"],
    "unknowns": [],
}


HYPOTHESIS = {
    "status": "PASS",
    "summary": "one hypothesis",
    "lane": "authority",
    "covered_surfaces": ["http-object"],
    "hypotheses": [
        {
            "local_id": "H-local-1",
            "title": "object scope omitted",
            "class": "authorization",
            "statement": "actor action is checked without target object scope",
            "falsifier": "prove downstream tenant filter",
            "research_path": "http-object",
            "root_cause_family": "missing-object-scope",
            "attacker_condition": "ordinary tenant user",
            "server_condition": "fixture release",
            "protected_boundary": "cross tenant write",
            "capability_delta_hypothesis": "write another tenant object",
            "evidence": ["app.py:10", "policy.py:5"],
            "missing_proof": ["runtime readback"],
            "priority": 90,
        }
    ],
    "negative_evidence": [],
    "new_knowledge_queries": [],
    "stop_reason": "",
}


EMPTY_HYPOTHESES = {
    "status": "PASS",
    "summary": "no target-native lead",
    "lane": "other",
    "covered_surfaces": [],
    "hypotheses": [],
    "negative_evidence": ["no relevant consumer"],
    "new_knowledge_queries": [],
    "stop_reason": "lane exhausted for this wave",
}


REPRODUCER = {
    "status": "PASS",
    "candidate_id": "PLACEHOLDER",
    "attacker_control": "PROVEN",
    "reachability": "PROVEN",
    "protected_boundary": "PROVEN",
    "capability_delta": "PROVEN",
    "attempts": 3,
    "successes": 3,
    "baseline": "own object write",
    "positive": "foreign object write",
    "negative_control": "PASS",
    "counterfactual": "PASS",
    "authoritative_readback": "foreign owner observed canary",
    "evidence": ["fixture:test"],
    "cleanup": "canary removed",
    "blockers": [],
}


SKEPTIC = {
    "status": "PASS",
    "candidate_id": "PLACEHOLDER",
    "verdict": "PASS",
    "strongest_objections": ["possible downstream filter"],
    "checks": {
        "documented_behavior": "not documented",
        "equal_authority": "no",
        "reachable": "yes",
        "attacker_control": "yes",
        "protected_effect": "yes",
        "threat_model": "cross tenant protected",
        "scope": "in scope",
        "mitigation": "none observed",
    },
    "kill_code": "",
    "kill_reason": "",
    "evidence": ["fixture:test"],
    "unresolved": [],
}


PRIOR = {
    "status": "PASS",
    "candidate_id": "PLACEHOLDER",
    "decision": "CLEAR",
    "sources": [],
    "root_cause_overlap": "none found",
    "searched_terms": ["missing object scope"],
    "limitations": [],
}


JUDGE = {
    "status": "PASS",
    "candidate_id": "PLACEHOLDER",
    "verdict": "STRONG",
    "evidence_gate": "PASS",
    "impact_gate": "PASS",
    "manual_status": "NOT_TESTED",
    "severity_status": "LOCKED",
    "severity_locked": True,
    "triager_proof": "BLOCKED",
    "report_ready": False,
    "gates": ["source", "runtime", "controls"],
    "blockers": ["human manual reproduction"],
    "reasoning": "technical evidence passes; human gate remains",
}


class DynamicScriptedRunner(ScriptedWorkerRunner):
    def run(self, **kwargs):
        job = kwargs["job"]
        role = job["role"]
        if role in {"reproducer", "skeptic", "prior_art", "evidence_judge"}:
            input_data = json.loads(job["input_json"])
            queue = self.outputs[role]
            queue[0] = dict(queue[0], candidate_id=input_data["candidate_id"])
        return super().run(**kwargs)


class OrchestratorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = HarnessFixture()
        self.target = self.fixture.root / "repository"
        self.target.mkdir()
        (self.target / "app.py").write_text("def handle(actor, obj):\n    return store.write(obj)\n", encoding="utf-8")
        runner = DynamicScriptedRunner(
            {
                "mapper": [MAPPER],
                "researcher": [HYPOTHESIS, EMPTY_HYPOTHESES, EMPTY_HYPOTHESES],
                "reproducer": [REPRODUCER],
                "skeptic": [SKEPTIC],
                "prior_art": [PRIOR],
                "evidence_judge": [JUDGE],
            }
        )
        self.orchestrator = Orchestrator(
            self.fixture.database,
            self.fixture.paths,
            self.fixture.config,
            runner=runner,
        )
        self.orchestrator.initialize_target(self.target)
        scope_path = self.target / ".bbpresearch" / "scope.yaml"
        scope = json.loads(scope_path.read_text())
        scope["authorization"].update({"confirmed": True, "source": "owned fixture", "program": "fixture"})
        scope_path.write_text(json.dumps(scope), encoding="utf-8")

    def tearDown(self) -> None:
        self.fixture.close()

    def test_end_to_end_workers_stop_at_human_gate(self) -> None:
        started = self.orchestrator.start_campaign(self.target, "audit fixture")
        result = self.orchestrator.run(started["campaign_id"], max_waves=5)
        status = result["status"]
        self.assertEqual(status["counts"]["attack_surfaces"], 1)
        self.assertEqual(status["counts"]["hypotheses"], 1)
        self.assertEqual(status["counts"]["candidates"], 1)
        self.assertEqual(status["candidates"][0]["state"], "PRIOR_ART_CLEAR")
        explained = self.orchestrator.candidates.explain(status["candidates"][0]["id"])
        self.assertIn("manual reproduction", explained["current_blockers"])

    def test_start_reuses_persistent_marker(self) -> None:
        started = self.orchestrator.start_campaign(self.target, "audit fixture")
        self.assertEqual(self.orchestrator.current_campaign(self.target), started["campaign_id"])

    def test_abort_closes_campaign_and_cancels_queued_jobs(self) -> None:
        started = self.orchestrator.start_campaign(self.target, "audit fixture")
        result = self.orchestrator.abort_campaign(started["campaign_id"], "test complete")
        status = self.orchestrator.status(started["campaign_id"])
        self.assertEqual(result["status"], "ABORTED")
        self.assertEqual(result["jobs_cancelled"], 1)
        self.assertEqual(status["campaign"]["status"], "ABORTED")
        self.assertEqual(status["jobs"].get("CANCELLED"), 1)


if __name__ == "__main__":
    unittest.main()
