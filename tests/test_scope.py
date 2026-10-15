from __future__ import annotations

import json
import unittest

from bbp_harness.orchestrator import Orchestrator
from bbp_harness.scope import ScopeError, load_scope

from .helpers import HarnessFixture


class ScopeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = HarnessFixture()
        self.target = self.fixture.root / "repo"
        self.target.mkdir()
        self.orchestrator = Orchestrator(
            self.fixture.database, self.fixture.paths, self.fixture.config
        )

    def tearDown(self) -> None:
        self.fixture.close()

    def test_initialized_scope_uses_standing_authorization(self) -> None:
        self.orchestrator.initialize_target(self.target)
        card = load_scope(self.target)
        self.assertTrue(card.authorization_confirmed)
        self.assertEqual(
            card.raw["authorization"]["source"],
            "user_supplied_official_bug_bounty_scope",
        )
        self.assertEqual(
            card.raw["authorization"]["confirmation_mode"],
            "standing_authorization",
        )

    def test_unconfirmed_scope_without_evidence_is_blocked(self) -> None:
        self.orchestrator.initialize_target(self.target)
        scope_path = self.target / ".bbpresearch" / "scope.yaml"
        raw = json.loads(scope_path.read_text())
        raw["authorization"].update(
            {
                "confirmed": False,
                "source": "REPLACE_WITH_PROGRAM_POLICY_OR_OWNERSHIP_EVIDENCE",
            }
        )
        raw["authorization"].pop("confirmation_mode", None)
        scope_path.write_text(json.dumps(raw), encoding="utf-8")
        with self.assertRaises(ScopeError) as raised:
            load_scope(self.target)
        self.assertTrue(any("authorization is not confirmed" in reason for reason in raised.exception.reasons))

    def test_standing_authorization_overrides_legacy_false_flag(self) -> None:
        self.orchestrator.initialize_target(self.target)
        scope_path = self.target / ".bbpresearch" / "scope.yaml"
        raw = json.loads(scope_path.read_text())
        raw["authorization"]["confirmed"] = False
        scope_path.write_text(json.dumps(raw), encoding="utf-8")
        card = load_scope(self.target)
        self.assertTrue(card.authorization_confirmed)

    def test_campaign_start_does_not_require_reconfirmation(self) -> None:
        self.orchestrator.initialize_target(self.target)
        scope_path = self.target / ".bbpresearch" / "scope.yaml"
        raw = json.loads(scope_path.read_text())
        raw["authorization"]["confirmed"] = False
        scope_path.write_text(json.dumps(raw), encoding="utf-8")

        started = self.orchestrator.start_campaign(
            self.target,
            "authorized standing-scope fixture",
        )

        self.assertEqual(started["scope"], "PASS")

    def test_standing_authorization_requires_canonical_source(self) -> None:
        self.orchestrator.initialize_target(self.target)
        scope_path = self.target / ".bbpresearch" / "scope.yaml"
        raw = json.loads(scope_path.read_text())
        raw["authorization"].update({"confirmed": False, "source": "unverified target"})
        scope_path.write_text(json.dumps(raw), encoding="utf-8")
        with self.assertRaises(ScopeError) as raised:
            load_scope(self.target)
        self.assertTrue(any("standing authorization requires" in reason for reason in raised.exception.reasons))

    def test_confirmed_scope_passes(self) -> None:
        initialized = self.orchestrator.initialize_target(self.target)
        scope_path = self.target / ".bbpresearch" / "scope.yaml"
        raw = json.loads(scope_path.read_text())
        raw["authorization"].update(
            {"confirmed": True, "source": "https://example.test/policy", "program": "fixture"}
        )
        scope_path.write_text(json.dumps(raw), encoding="utf-8")
        card = load_scope(self.target)
        self.assertTrue(card.authorization_confirmed)
        self.assertEqual(card.program, "fixture")
        self.assertIn("source_review", card.allowed_methods)
        self.assertEqual(initialized["scope"], str(scope_path))

    def test_destructive_scope_is_rejected(self) -> None:
        self.orchestrator.initialize_target(self.target)
        scope_path = self.target / ".bbpresearch" / "scope.yaml"
        raw = json.loads(scope_path.read_text())
        raw["authorization"].update({"confirmed": True, "source": "owned fixture"})
        raw["allowed_actions"]["destructive"] = True
        scope_path.write_text(json.dumps(raw), encoding="utf-8")
        with self.assertRaises(ScopeError) as raised:
            load_scope(self.target)
        self.assertTrue(any("destructive" in reason for reason in raised.exception.reasons))

    def test_out_of_scope_asset_is_rejected_under_standing_authorization(self) -> None:
        self.orchestrator.initialize_target(self.target)
        scope_path = self.target / ".bbpresearch" / "scope.yaml"
        raw = json.loads(scope_path.read_text())
        raw["asset"]["in_scope"] = False
        scope_path.write_text(json.dumps(raw), encoding="utf-8")
        with self.assertRaises(ScopeError) as raised:
            load_scope(self.target)
        self.assertIn("asset.in_scope must be true", raised.exception.reasons)


if __name__ == "__main__":
    unittest.main()
