from __future__ import annotations

import unittest

from bbp_harness.candidates import CandidateStateMachine

from .helpers import HarnessFixture


class CandidateStateMachineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = HarnessFixture()
        self.campaign_id = self.fixture.seed_campaign()
        self.machine = CandidateStateMachine(self.fixture.database)

    def tearDown(self) -> None:
        self.fixture.close()

    def test_candidate_cannot_skip_hypothesis_gates(self) -> None:
        candidate = self.machine.create(self.campaign_id, "missing auth scope")
        result = self.machine.advance(candidate)
        self.assertEqual(result["state"], "HYPOTHESIS")
        self.assertIn("attacker control", result["blockers"])
        self.assertIn("capability delta", result["blockers"])

    def test_full_evidence_advances_monotonically(self) -> None:
        candidate = self.machine.create(self.campaign_id, "cross object write")
        self.machine.update(
            candidate,
            attacker_control="PROVEN",
            reachability="PROVEN",
            protected_boundary="PROVEN",
            capability_delta="PROVEN",
            reproduction_attempts=3,
            reproduction_successes=3,
            negative_control="PASS",
            counterfactual="PASS",
            skeptic="PASS",
            prior_art="CLEAR",
            evidence_gate="PASS",
            impact_gate="PASS",
            manual_status="MANUALLY_CONFIRMED",
            severity_status="LOCKED",
            severity_locked=1,
            triager_proof="PASS",
        )
        result = self.machine.advance(candidate)
        self.assertEqual(result["state"], "REPORT_READY")
        self.assertEqual(len(result["advanced"]), 8)
        row = self.machine.get(candidate)
        self.assertEqual(row["verdict"], "STRONG")
        self.assertEqual(row["report_ready"], 1)

    def test_kill_records_specific_reason(self) -> None:
        candidate = self.machine.create(self.campaign_id, "same authority behavior")
        self.machine.kill(candidate, "KILL_EQUAL_AUTHORITY", "supported path has the same power")
        explained = self.machine.explain(candidate)
        self.assertEqual(explained["candidate"]["state"], "KILLED")
        self.assertEqual(explained["candidate"]["kill_code"], "KILL_EQUAL_AUTHORITY")
        self.assertEqual(explained["transitions"][-1]["to_state"], "KILLED")


if __name__ == "__main__":
    unittest.main()
