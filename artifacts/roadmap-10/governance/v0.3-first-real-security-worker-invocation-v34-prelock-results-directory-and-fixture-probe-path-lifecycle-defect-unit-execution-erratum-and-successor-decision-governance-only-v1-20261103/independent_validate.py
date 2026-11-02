#!/usr/bin/env python3
"""Independent reconstruction of the V34 unit harness lifecycle failure."""

import hashlib
import json
import stat
from pathlib import Path

from governance_common import ROOT, V33, V34, V35, write_once


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def verify_tree(root: Path, manifest: dict, expected_count: int, expected_root: str) -> bool:
    rows = manifest["members"]
    serialized = "".join(f"{row['sha256']}  {row['path']}\n" for row in rows)
    computed = hashlib.sha256(serialized.encode("utf-8")).hexdigest()
    exact = all(
        (root / row["path"]).is_file()
        and not (root / row["path"]).is_symlink()
        and digest(root / row["path"]) == row["sha256"]
        and (root / row["path"]).stat().st_size == row["bytes"]
        and stat.S_IMODE((root / row["path"]).stat().st_mode) == 0o444
        for row in rows
    )
    return len(rows) == manifest["member_count"] == expected_count and exact and computed == manifest["canonical_evidence_root_sha256"] == expected_root


def main() -> int:
    pre = V34 / "results/prelock"
    terminal_path = pre / "PRELOCK_TERMINAL_ENGINEERING_RESULT.json"
    manifest_path = pre / "PRELOCK_FAILURE_EVIDENCE_MANIFEST.json"
    freeze_path = pre / "PRELOCK_FAILURE_EVIDENCE_FREEZE_VERIFICATION.json"
    unit_path = pre / "unit-fixtures-run-0001.json"
    terminal, manifest, unit = map(read, (terminal_path, manifest_path, unit_path))

    source_path = V34 / "tests/run_unit_fixtures.py"
    source_lines = source_path.read_text(encoding="utf-8").splitlines()
    line253, line254, line255 = (source_lines[index - 1].strip() for index in (253, 254, 255))
    relevant_before = [line for line in source_lines[:255] if "results/prelock" in line or "symlink_probe" in line]

    v33_pre = V33 / "results/prelock"
    v33_manifest = read(v33_pre / "PRELOCK_FAILURE_EVIDENCE_MANIFEST.json")
    decision = read(ROOT / "V34_TERMINAL_AND_V35_SUCCESSOR_DECISION.json")
    adjudication = read(ROOT / "V34_PRELOCK_RESULTS_AND_FIXTURE_PROBE_LIFECYCLE_ADJUDICATION.json")
    contract = read(ROOT / "SUCCESSOR_V35_PRELOCK_RESULTS_AND_FIXTURE_PROBE_LIFECYCLE_CONTRACT.json")
    primary = read(ROOT / "PRIMARY_GOVERNANCE_VALIDATION.json")
    negatives = read(ROOT / "NEGATIVE_GOVERNANCE_FIXTURES.json")

    checks = {
        "I001_TERMINAL_SHA": digest(terminal_path) == "8c34d02a97d837c0466ff311e4d1ab197253ba7e04330db7e4ed7666a45759b3",
        "I002_MANIFEST_SHA": digest(manifest_path) == "604dcf1b0675392ed8ce724a9de424fd0f7a640c8f9da9e5250fa0c0bebaab3a",
        "I003_FREEZE_SHA": digest(freeze_path) == "4f7f55ba9528b357ab8cec1082bdac6ed177f37c0d70866be788ada8960d9b45",
        "I004_UNIT_SHA": digest(unit_path) == "933ad055156fdae69331b28d7c239e5f2b2e385411abcede65155dacd04bc981",
        "I005_V34_TREE": verify_tree(V34, manifest, 249, "fb38ae77756d335cdd8b14ea833920b4255478f63a5d6a97544b1464eb6a9811"),
        "I006_V33_TREE": verify_tree(V33, v33_manifest, 339, "7697ad9d1f20e8e47d6544031c229b9037dec1fd8c7ab7574d1f3091e729227d"),
        "I007_V33_DIGESTS": digest(v33_pre / "PRELOCK_TERMINAL_ENGINEERING_RESULT.json") == "6fc29626608e6a286e21b7b442ccc5d3c299513fa378439f23c2898630e7ad62" and digest(v33_pre / "PRELOCK_FAILURE_EVIDENCE_MANIFEST.json") == "67e9a687aae31566859e01d58a1713e91ccb6bb2876154f3dd9032ba4640c01c" and digest(v33_pre / "PRELOCK_FAILURE_EVIDENCE_FREEZE_VERIFICATION.json") == "111604877cb22a242b4c8252a7472555dd673f9b1512d34f4cd9c1a84bfb260b",
        "I008_TERMINAL_STATE": terminal["status"] == "FAIL_CLOSED_DURING_UNIT_VALIDATION_PRELOCK_TERMINAL_NO_RETRY_FROZEN_FAILURE_EVIDENCE",
        "I009_UNIT_EXCEPTION": unit["exception"]["type"] == "FileNotFoundError" and unit["exception"]["errno"] == 2 and unit["exception"]["line"] == 255,
        "I010_PROBE_ASSIGNMENT": line253 == 'symlink_probe = ROOT / "results/prelock/.v34-predecessor-symlink-probe"',
        "I011_AUTHORIZATION_NOT_CREATION": line254.startswith("authorize_write(symlink_probe"),
        "I012_SYMLINK_OPERATION": line255 == "os.symlink(v14_root, symlink_probe)",
        "I013_NO_PARENT_PROVISIONING": not any("mkdir" in line for line in relevant_before),
        "I014_NO_LATER_GATES": terminal["primary"] == terminal["independent"] == terminal["fresh_preflight"] == terminal["dependency_closure"] == "NOT_STARTED",
        "I015_NO_EXECUTION": terminal["static_lock"] == "NOT_ISSUED" and terminal["attempt_count"] == terminal["worker_invocation_count"] == terminal["codex_as_worker_invocation_count"] == 0,
        "I016_BOTH_DEFECTS": adjudication["PRELOCK_RESULTS_DIRECTORY_LIFECYCLE_DEFECT"] == adjudication["FIXTURE_PROBE_PARENT_DIRECTORY_PRECONDITION_DEFECT"] == "YES",
        "I017_CONTRACT_SEPARATES_ROOTS": contract["prelock_evidence_root"]["canonical_path"] != contract["fixture_scratch_probe_root"]["canonical_path"] and contract["fixture_scratch_probe_root"]["separate_from_authoritative_evidence_root"] is True,
        "I018_CONTRACT_BOUNDARY": contract["boundary_requirements"]["relative_traversal"] == contract["boundary_requirements"]["symlink_parent_or_component"] == "REJECT_BEFORE_MUTATION",
        "I019_PRIMARY_PASS": primary["status"] == "PASS",
        "I020_NEGATIVES_PASS": negatives["status"] == "PASS" and negatives["filesystem_mutations"] == negatives["predecessor_mutations"] == 0,
        "I021_V34_TERMINAL": decision["v34_disposition"] == "TERMINAL_IMMUTABLE_NO_RETRY",
        "I022_V35_CONDITIONAL": decision["v35_disposition"] == "CONDITIONALLY_AUTHORIZED_NOT_CREATED_NOT_EXECUTED",
        "I023_V35_ABSENT": not V35.exists(),
    }
    result = {
        "record_type": "INDEPENDENT_GOVERNANCE_VALIDATION",
        "checks": [{"id": key, "status": "PASS" if value else "FAIL"} for key, value in checks.items()],
        "passed": sum(checks.values()),
        "total": len(checks),
        "status": "PASS" if all(checks.values()) else "FAIL_CLOSED",
    }
    write_once(ROOT / "INDEPENDENT_GOVERNANCE_VALIDATION.json", result)
    print(f"INDEPENDENT_GOVERNANCE_VALIDATION={result['passed']}/{result['total']} {result['status']}")
    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
