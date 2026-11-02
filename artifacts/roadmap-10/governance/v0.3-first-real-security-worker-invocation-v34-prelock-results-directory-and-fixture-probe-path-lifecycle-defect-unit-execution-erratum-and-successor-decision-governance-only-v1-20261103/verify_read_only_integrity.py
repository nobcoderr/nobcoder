#!/usr/bin/env python3
"""Verify V34/V33 immutability and the governance authority ceiling."""

from governance_common import ROOT, V34, V35, load, verify_v33_frozen, verify_v34_frozen, write_once


def main() -> int:
    required = [
        "PRIMARY_GOVERNANCE_VALIDATION.json",
        "NEGATIVE_GOVERNANCE_FIXTURES.json",
        "INDEPENDENT_GOVERNANCE_VALIDATION.json",
    ]
    terminal = load(V34 / "results/prelock/PRELOCK_TERMINAL_ENGINEERING_RESULT.json")
    checks = {
        "R001_V34_BYTE_EXACT": verify_v34_frozen()["status"] == "PASS",
        "R002_V33_BYTE_EXACT": verify_v33_frozen()["status"] == "PASS",
        "R003_VALIDATIONS_PASS": all(load(ROOT / name)["status"] == "PASS" for name in required),
        "R004_V34_STATIC_LOCK_ABSENT": not (V34 / "STATIC_EXECUTION_LOCK.json").exists(),
        "R005_V34_ATTEMPT_ABSENT": not any(V34.rglob("ATTEMPT_MARKER.json")),
        "R006_V34_RUNTIME_ABSENT": not any(V34.rglob("runtime-result-0001.json")),
        "R007_V35_ABSENT": not V35.exists(),
        "R008_NO_BYTECODE": not any(V34.rglob("*.pyc")) and not any(path.name == "__pycache__" for path in V34.rglob("*")),
        "R009_COUNTERS_ZERO": terminal["attempt_count"] == terminal["worker_invocation_count"] == terminal["codex_as_worker_invocation_count"] == 0,
        "R010_NEGATIVES_MUTATION_FREE": load(ROOT / "NEGATIVE_GOVERNANCE_FIXTURES.json")["filesystem_mutations"] == load(ROOT / "NEGATIVE_GOVERNANCE_FIXTURES.json")["predecessor_mutations"] == 0,
    }
    result = {
        "record_type": "READ_ONLY_INTEGRITY_VERIFICATION",
        "checks": [{"id": key, "status": "PASS" if value else "FAIL"} for key, value in checks.items()],
        "passed": sum(checks.values()),
        "total": len(checks),
        "status": "PASS" if all(checks.values()) else "FAIL_CLOSED",
    }
    write_once(ROOT / "READ_ONLY_INTEGRITY_VERIFICATION.json", result)
    print(f"READ_ONLY_INTEGRITY={result['passed']}/{result['total']} {result['status']}")
    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
