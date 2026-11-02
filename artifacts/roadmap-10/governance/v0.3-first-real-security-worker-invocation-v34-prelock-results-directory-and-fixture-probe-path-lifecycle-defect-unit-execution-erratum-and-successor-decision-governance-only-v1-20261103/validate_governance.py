#!/usr/bin/env python3
"""Primary governance validation for the V34 lifecycle adjudication."""

from governance_common import ROOT, V35, failure_path_evidence, load, verify_v33_frozen, verify_v34_frozen, write_once


def main() -> int:
    adjudication = load(ROOT / "V34_PRELOCK_RESULTS_AND_FIXTURE_PROBE_LIFECYCLE_ADJUDICATION.json")
    contract = load(ROOT / "SUCCESSOR_V35_PRELOCK_RESULTS_AND_FIXTURE_PROBE_LIFECYCLE_CONTRACT.json")
    matrix = load(ROOT / "V34_FAILURE_AND_V35_REGRESSION_MATRIX.json")
    preserved = load(ROOT / "V34_PRESERVED_ENGINEERING_FACTS.json")
    separation = load(ROOT / "V34_RUNTIME_AND_PROOF_GATE_SEPARATION_ADJUDICATION.json")
    decision = load(ROOT / "V34_TERMINAL_AND_V35_SUCCESSOR_DECISION.json")
    checks = {
        "G001_V34_FROZEN": verify_v34_frozen()["status"] == "PASS",
        "G002_V33_FROZEN": verify_v33_frozen()["status"] == "PASS",
        "G003_FAILURE_RECONSTRUCTED": failure_path_evidence()["status"] == "PASS",
        "G004_PRELOCK_DEFECT_YES": adjudication["PRELOCK_RESULTS_DIRECTORY_LIFECYCLE_DEFECT"] == "YES",
        "G005_PROBE_PRECONDITION_DEFECT_YES": adjudication["FIXTURE_PROBE_PARENT_DIRECTORY_PRECONDITION_DEFECT"] == "YES",
        "G006_NO_AD_HOC_WORKAROUND": adjudication["ad_hoc_directory_workaround_authorized"] is False,
        "G007_RESPONSIBLE_CONTROLLER": contract["responsible_component"] == "V35_PRELOCK_STORAGE_LIFECYCLE_CONTROLLER_V1",
        "G008_PRELOCK_BEFORE_WRITER": contract["prelock_evidence_root"]["availability_deadline"] == "BEFORE_FIRST_EVIDENCE_WRITER_AND_BEFORE_UNIT_FIXTURES",
        "G009_PRELOCK_EXACT_MODE": contract["prelock_evidence_root"]["mode_during_prelock"] == "0700",
        "G010_SCRATCH_SEPARATE": contract["fixture_scratch_probe_root"]["separate_from_authoritative_evidence_root"] is True,
        "G011_EXCLUSIVE_NO_REUSE": contract["prelock_evidence_root"]["preexisting_state"] == "PROHIBITED_FOR_FRESH_V35" and "EXIST_OK_TRUE" in contract["prohibited_repairs"],
        "G012_BOUNDARY": contract["boundary_requirements"]["canonical_realpath_containment"] == "EXACT_V35_WORKSPACE_ONLY",
        "G013_PREDECESSOR_DENY_WRITE": contract["boundary_requirements"]["predecessor_roots"] == "EXPLICIT_READ_ONLY_DENY_WRITE_ROOTS",
        "G014_TYPED_FAILURE": contract["failure_policy"] == "FAIL_CLOSED_BEFORE_UNIT_VALIDATION_OR_STATIC_LOCK_OR_ATTEMPT",
        "G015_REGRESSIONS": matrix["count"] == len(set(matrix["required_regressions"])) == 9,
        "G016_PRESERVED_NOT_PROMOTED": preserved["classification"] == "FROZEN_ENGINEERING_FACTS_ONLY_NOT_FULL_UNIT_OR_STATIC_VALIDATION_PASS",
        "G017_RUNTIME_NOT_ESTABLISHED": separation["SECURITY_WORKER_RUNTIME"] == separation["TEMPORAL_OBSERVER_RUNTIME"] == "NOT_ESTABLISHED",
        "G018_PROOF_GATES_NOT_PROVEN": separation["PROCESS_LINEAGE"] == separation["PRODUCER_AUTHORIZATION"] == separation["CONFINEMENT"] == "NOT_PROVEN",
        "G019_V34_TERMINAL": decision["v34_disposition"] == "TERMINAL_IMMUTABLE_NO_RETRY",
        "G020_V35_CONDITIONAL": decision["v35_disposition"] == "CONDITIONALLY_AUTHORIZED_NOT_CREATED_NOT_EXECUTED",
        "G021_V35_ABSENT": not V35.exists(),
    }
    result = {
        "record_type": "PRIMARY_GOVERNANCE_VALIDATION",
        "checks": [{"id": key, "status": "PASS" if value else "FAIL"} for key, value in checks.items()],
        "passed": sum(checks.values()),
        "total": len(checks),
        "status": "PASS" if all(checks.values()) else "FAIL_CLOSED",
    }
    write_once(ROOT / "PRIMARY_GOVERNANCE_VALIDATION.json", result)
    print(f"PRIMARY_GOVERNANCE_VALIDATION={result['passed']}/{result['total']} {result['status']}")
    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
