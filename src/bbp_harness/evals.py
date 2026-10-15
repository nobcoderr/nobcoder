from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .db import Database
from .ids import new_id
from .util import canonical_json, utcnow


EXPECTED_CLASSES = {"REAL_VULN", "PATCHED", "TRAP", "DOCUMENTED"}


class EvaluationSuite:
    def __init__(self, database: Database, harness_version: str):
        self.database = database
        self.harness_version = harness_version

    def import_manifest(self, path: Path) -> dict[str, Any]:
        raw = json.loads(path.read_text(encoding="utf-8"))
        suite = str(raw["suite"])
        cases = raw.get("cases", [])
        imported = 0
        with self.database.transaction(immediate=True) as connection:
            for case in cases:
                expected = str(case["expected_class"])
                if expected not in EXPECTED_CLASSES:
                    raise ValueError(f"invalid expected_class for {case.get('id')}: {expected}")
                connection.execute(
                    """
                    INSERT INTO eval_cases(
                        id, suite, target_path, target_revision, expected_class,
                        expected_candidate_key, public_metadata_json,
                        secret_ground_truth_json, created_at
                    ) VALUES(?,?,?,?,?,?,?,?,?)
                    ON CONFLICT(id) DO UPDATE SET
                        suite=excluded.suite,
                        target_path=excluded.target_path,
                        target_revision=excluded.target_revision,
                        expected_class=excluded.expected_class,
                        expected_candidate_key=excluded.expected_candidate_key,
                        public_metadata_json=excluded.public_metadata_json,
                        secret_ground_truth_json=excluded.secret_ground_truth_json
                    """,
                    (
                        case["id"],
                        suite,
                        case["target_path"],
                        case.get("target_revision", ""),
                        expected,
                        case.get("expected_candidate_key", ""),
                        canonical_json(case.get("public_metadata", {})),
                        canonical_json(case.get("ground_truth", {})),
                        utcnow(),
                    ),
                )
                imported += 1
        return {"suite": suite, "cases_imported": imported}

    def start(self, suite: str) -> str:
        count = self.database.one("SELECT count(*) FROM eval_cases WHERE suite=?", (suite,))[0]
        if not count:
            raise ValueError(f"evaluation suite has no cases: {suite}")
        run_id = new_id("EV")
        with self.database.connect() as connection:
            connection.execute(
                "INSERT INTO eval_runs(id, suite, harness_version, status, started_at) VALUES(?,?,?,'RUNNING',?)",
                (run_id, suite, self.harness_version, utcnow()),
            )
        return run_id

    def record(
        self,
        run_id: str,
        case_id: str,
        *,
        observed_class: str,
        found: bool,
        reproduced: bool,
        correctly_triaged: bool,
        false_positive: bool,
        elapsed_seconds: float = 0,
        token_cost: int = 0,
        details: dict[str, Any] | None = None,
    ) -> None:
        with self.database.connect() as connection:
            connection.execute(
                """
                INSERT INTO eval_results(
                    eval_run_id, case_id, observed_class, found, reproduced,
                    correctly_triaged, false_positive, elapsed_seconds,
                    token_cost, details_json
                ) VALUES(?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(eval_run_id, case_id) DO UPDATE SET
                    observed_class=excluded.observed_class,
                    found=excluded.found,
                    reproduced=excluded.reproduced,
                    correctly_triaged=excluded.correctly_triaged,
                    false_positive=excluded.false_positive,
                    elapsed_seconds=excluded.elapsed_seconds,
                    token_cost=excluded.token_cost,
                    details_json=excluded.details_json
                """,
                (
                    run_id,
                    case_id,
                    observed_class,
                    int(found),
                    int(reproduced),
                    int(correctly_triaged),
                    int(false_positive),
                    elapsed_seconds,
                    token_cost,
                    canonical_json(details or {}),
                ),
            )

    def score(self, run_id: str, finalize: bool = True) -> dict[str, Any]:
        run = self.database.one("SELECT * FROM eval_runs WHERE id=?", (run_id,))
        if run is None:
            raise KeyError(run_id)
        rows = self.database.all(
            """
            SELECT c.expected_class, r.*
            FROM eval_results r JOIN eval_cases c ON c.id=r.case_id
            WHERE r.eval_run_id=?
            """,
            (run_id,),
        )
        totals = {name: 0 for name in EXPECTED_CLASSES}
        metrics = {
            "real_vuln_found": 0,
            "real_vuln_reproduced": 0,
            "real_vuln_correctly_triaged": 0,
            "patched_false_positives": 0,
            "trap_incorrect_strong": 0,
            "documented_incorrect_strong": 0,
            "elapsed_seconds": 0.0,
            "token_cost": 0,
        }
        for row in rows:
            expected = row["expected_class"]
            totals[expected] += 1
            metrics["elapsed_seconds"] += float(row["elapsed_seconds"])
            metrics["token_cost"] += int(row["token_cost"])
            if expected == "REAL_VULN":
                metrics["real_vuln_found"] += int(row["found"])
                metrics["real_vuln_reproduced"] += int(row["reproduced"])
                metrics["real_vuln_correctly_triaged"] += int(row["correctly_triaged"])
            elif expected == "PATCHED":
                metrics["patched_false_positives"] += int(row["false_positive"])
            elif expected == "TRAP" and row["observed_class"] in {"STRONG", "REPORT_READY"}:
                metrics["trap_incorrect_strong"] += 1
            elif expected == "DOCUMENTED" and row["observed_class"] in {"STRONG", "REPORT_READY"}:
                metrics["documented_incorrect_strong"] += 1
        result = {
            "run_id": run_id,
            "suite": run["suite"],
            "cases_recorded": len(rows),
            "totals": totals,
            "metrics": metrics,
        }
        if finalize:
            expected_count = int(self.database.one("SELECT count(*) FROM eval_cases WHERE suite=?", (run["suite"],))[0])
            status = "COMPLETE" if len(rows) == expected_count else "PARTIAL"
            with self.database.connect() as connection:
                connection.execute(
                    "UPDATE eval_runs SET status=?, completed_at=?, metrics_json=? WHERE id=?",
                    (status, utcnow(), canonical_json(result), run_id),
                )
            result["status"] = status
        return result
