from __future__ import annotations

import json
import unittest

from bbp_harness.evals import EvaluationSuite

from .helpers import HarnessFixture


class EvaluationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = HarnessFixture()
        self.evals = EvaluationSuite(self.fixture.database, "test")
        self.manifest = self.fixture.root / "suite.json"
        self.manifest.write_text(
            json.dumps(
                {
                    "suite": "mini",
                    "cases": [
                        {"id": "real", "target_path": "real", "expected_class": "REAL_VULN"},
                        {"id": "patched", "target_path": "patched", "expected_class": "PATCHED"},
                        {"id": "trap", "target_path": "trap", "expected_class": "TRAP"},
                        {"id": "docs", "target_path": "docs", "expected_class": "DOCUMENTED"},
                    ],
                }
            ),
            encoding="utf-8",
        )

    def tearDown(self) -> None:
        self.fixture.close()

    def test_scores_real_and_false_positive_cases(self) -> None:
        self.evals.import_manifest(self.manifest)
        run_id = self.evals.start("mini")
        self.evals.record(
            run_id,
            "real",
            observed_class="REPORT_READY",
            found=True,
            reproduced=True,
            correctly_triaged=True,
            false_positive=False,
        )
        self.evals.record(
            run_id,
            "patched",
            observed_class="KILLED",
            found=False,
            reproduced=False,
            correctly_triaged=True,
            false_positive=False,
        )
        self.evals.record(
            run_id,
            "trap",
            observed_class="STRONG",
            found=True,
            reproduced=False,
            correctly_triaged=False,
            false_positive=True,
        )
        self.evals.record(
            run_id,
            "docs",
            observed_class="KILLED",
            found=False,
            reproduced=False,
            correctly_triaged=True,
            false_positive=False,
        )
        score = self.evals.score(run_id)
        self.assertEqual(score["metrics"]["real_vuln_found"], 1)
        self.assertEqual(score["metrics"]["patched_false_positives"], 0)
        self.assertEqual(score["metrics"]["trap_incorrect_strong"], 1)
        self.assertEqual(score["metrics"]["documented_incorrect_strong"], 0)
        self.assertEqual(score["status"], "COMPLETE")


if __name__ == "__main__":
    unittest.main()
