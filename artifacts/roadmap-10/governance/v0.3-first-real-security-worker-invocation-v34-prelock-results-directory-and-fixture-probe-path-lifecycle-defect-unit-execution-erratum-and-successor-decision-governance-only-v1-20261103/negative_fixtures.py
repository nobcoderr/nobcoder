#!/usr/bin/env python3
"""Pure negative fixtures for the successor storage lifecycle contract."""

from copy import deepcopy

from governance_common import ROOT, canonical_lifecycle_case, lifecycle_fixture_verdict, write_once


def main() -> int:
    good = canonical_lifecycle_case()
    cases: list[tuple[str, dict, bool]] = [("N001_EXACT_LIFECYCLE", good, True)]

    def altered(identity: str, key: str, value, expected: bool = False) -> None:
        candidate = deepcopy(good)
        candidate[key] = value
        cases.append((identity, candidate, expected))

    altered("N002_PRELOCK_ROOT_ABSENT", "prelock_exists", False)
    altered("N003_FIXTURE_PROBE_ROOT_ABSENT", "probe_root_exists", False)
    altered("N004_PROBE_PARENT_SYMLINK", "probe_root_symlink", True)
    altered("N005_PROBE_ESCAPES_WORKSPACE", "probe_path", "/outside/.predecessor-symlink-probe")
    altered("N006_PROBE_TARGETS_PREDECESSOR", "probe_path", "/workspace/v34/.predecessor-symlink-probe")
    altered("N007_NEGATIVE_FIXTURE_MUTATES_PREDECESSOR", "predecessor_mutated", True)
    altered("N008_FIRST_FAILURE_EVIDENCE_NOT_WRITABLE", "first_unit_failure_evidence_writable", False)
    altered("N009_PREEXISTING_ROOT_REUSE", "preexisting_reuse", True)
    altered("N010_WRONG_LIFECYCLE_ORDER", "order", ["WORKSPACE_BOUNDARY_PASS", "UNIT_FIXTURES", "PRELOCK_ROOT_PROVISIONED"])

    rows = []
    for identity, candidate, expected in cases:
        actual = lifecycle_fixture_verdict(candidate)
        rows.append({
            "id": identity,
            "expected_accept": expected,
            "actual_accept": actual,
            "filesystem_mutations": 0,
            "predecessor_mutations": 0,
            "status": "PASS" if actual is expected else "FAIL",
        })
    result = {
        "record_type": "NEGATIVE_GOVERNANCE_FIXTURES",
        "fixtures": rows,
        "passed": sum(row["status"] == "PASS" for row in rows),
        "total": len(rows),
        "filesystem_mutations": 0,
        "predecessor_mutations": 0,
        "status": "PASS" if all(row["status"] == "PASS" for row in rows) else "FAIL_CLOSED",
    }
    write_once(ROOT / "NEGATIVE_GOVERNANCE_FIXTURES.json", result)
    print(f"NEGATIVE_GOVERNANCE_FIXTURES={result['passed']}/{result['total']} {result['status']}")
    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
