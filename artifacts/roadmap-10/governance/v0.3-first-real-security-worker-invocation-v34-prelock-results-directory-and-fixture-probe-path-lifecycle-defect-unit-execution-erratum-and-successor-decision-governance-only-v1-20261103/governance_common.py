#!/usr/bin/env python3
"""Read-only helpers for the V34 prelock/probe lifecycle governance milestone."""

from __future__ import annotations

import hashlib
import json
import os
import stat
from pathlib import Path, PurePosixPath
from typing import Any


ROOT = Path(__file__).resolve().parent
V34 = Path("/home/nobcoder/v0.3-first-real-security-worker-invocation-v34-20261103")
V35 = Path("/home/nobcoder/v0.3-first-real-security-worker-invocation-v35-20261103")
V33 = Path("/home/nobcoder/v0.3-first-real-security-worker-invocation-v33-20261103")

IDENTITY = (
    "V0_3_FIRST_REAL_SECURITY_WORKER_INVOCATION_V34_PRELOCK_RESULTS_DIRECTORY_"
    "AND_FIXTURE_PROBE_PATH_LIFECYCLE_DEFECT_UNIT_EXECUTION_ERRATUM_AND_"
    "SUCCESSOR_DECISION_GOVERNANCE_ONLY"
)
V34_IDENTITY = "V0_3_FIRST_REAL_SECURITY_WORKER_INVOCATION_V34"
V35_IDENTITY = "V0_3_FIRST_REAL_SECURITY_WORKER_INVOCATION_V35"
V34_STATUS = "FAIL_CLOSED_DURING_UNIT_VALIDATION_PRELOCK_TERMINAL_NO_RETRY_FROZEN_FAILURE_EVIDENCE"

V34_ROOT_SHA = "fb38ae77756d335cdd8b14ea833920b4255478f63a5d6a97544b1464eb6a9811"
V34_TERMINAL_SHA = "8c34d02a97d837c0466ff311e4d1ab197253ba7e04330db7e4ed7666a45759b3"
V34_MANIFEST_SHA = "604dcf1b0675392ed8ce724a9de424fd0f7a640c8f9da9e5250fa0c0bebaab3a"
V34_FREEZE_SHA = "4f7f55ba9528b357ab8cec1082bdac6ed177f37c0d70866be788ada8960d9b45"
V34_UNIT_SHA = "933ad055156fdae69331b28d7c239e5f2b2e385411abcede65155dacd04bc981"

V33_ROOT_SHA = "7697ad9d1f20e8e47d6544031c229b9037dec1fd8c7ab7574d1f3091e729227d"
V33_TERMINAL_SHA = "6fc29626608e6a286e21b7b442ccc5d3c299513fa378439f23c2898630e7ad62"
V33_MANIFEST_SHA = "67e9a687aae31566859e01d58a1713e91ccb6bb2876154f3dd9032ba4640c01c"
V33_FREEZE_SHA = "111604877cb22a242b4c8252a7472555dd673f9b1512d34f4cd9c1a84bfb260b"


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def write_once(path: Path, value: Any) -> None:
    if path.exists() or path.is_symlink():
        raise FileExistsError(f"append-only output exists: {path}")
    with path.open("x", encoding="utf-8", newline="\n") as handle:
        json.dump(value, handle, indent=2, sort_keys=True)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())


def v34_paths() -> dict[str, Path]:
    pre = V34 / "results/prelock"
    return {
        "terminal": pre / "PRELOCK_TERMINAL_ENGINEERING_RESULT.json",
        "manifest": pre / "PRELOCK_FAILURE_EVIDENCE_MANIFEST.json",
        "freeze": pre / "PRELOCK_FAILURE_EVIDENCE_FREEZE_VERIFICATION.json",
        "unit": pre / "unit-fixtures-run-0001.json",
        "source": V34 / "tests/run_unit_fixtures.py",
        "closure": V34 / "contracts/AUTHORITATIVE_ARTIFACT_CREATION_CLOSURE.json",
        "symbols": V34 / "contracts/LOCKED_ENTRYPOINT_SYMBOL_BINDING_MANIFEST.json",
        "helper_matrix": V34 / "contracts/V34_TYPED_VALIDATOR_HELPER_RETURN_REGRESSION_MATRIX.json",
        "helper_source": V34 / "src/validator_helper_contract_v34.py",
    }


def _verify_manifest(root: Path, manifest: dict[str, Any], expected_count: int, expected_root: str) -> tuple[bool, str]:
    members = manifest.get("members", [])
    exact: list[bool] = []
    for row in members:
        member = root / row.get("path", "")
        exact.append(
            member.is_file()
            and not member.is_symlink()
            and sha256(member) == row.get("sha256")
            and member.stat().st_size == row.get("bytes")
            and stat.S_IMODE(member.stat().st_mode) == 0o444
        )
    rows = "".join(f"{row['sha256']}  {row['path']}\n" for row in members)
    computed = hashlib.sha256(rows.encode("utf-8")).hexdigest()
    return (
        len(members) == manifest.get("member_count") == expected_count
        and all(exact)
        and computed == manifest.get("canonical_evidence_root_sha256") == expected_root,
        computed,
    )


def failure_path_evidence() -> dict[str, Any]:
    p = v34_paths()
    unit = load(p["unit"])
    lines = p["source"].read_text(encoding="utf-8").splitlines()
    numbered = {index + 1: value.strip() for index, value in enumerate(lines)}
    exception = unit.get("exception", {})
    before_failure = "\n".join(lines[:255])
    checks = {
        "exception_type": exception.get("type") == "FileNotFoundError",
        "exception_errno": exception.get("errno") == 2,
        "exception_line": exception.get("line") == 255,
        "probe_assignment": numbered.get(253) == 'symlink_probe = ROOT / "results/prelock/.v34-predecessor-symlink-probe"',
        "guard_authorization_only": numbered.get(254, "").startswith("authorize_write(symlink_probe"),
        "symlink_creation": numbered.get(255) == "os.symlink(v14_root, symlink_probe)",
        "no_preceding_parent_provisioning": "mkdir" not in "\n".join(
            line for line in lines[:255] if "results/prelock" in line or "symlink_probe" in line
        ),
        "unit_result_identifies_parent_absence": "RESULTS_PRELOCK_PARENT_ABSENT_BEFORE_NEGATIVE_SYMLINK_FIXTURE" in unit.get("failure_ids", []),
        "unit_validation_incomplete": unit.get("validation_completed") is False,
        "source_contains_failure_operation": "os.symlink(v14_root, symlink_probe)" in before_failure,
    }
    return {
        "record_type": "V34_FIXTURE_PROBE_PARENT_LIFECYCLE_EVIDENCE",
        "source": str(p["source"]),
        "source_sha256": sha256(p["source"]),
        "unit_result_sha256": sha256(p["unit"]),
        "probe_path": str(V34 / "results/prelock/.v34-predecessor-symlink-probe"),
        "failure_stage": "BEFORE_UNIT_VALIDATION_COMPLETION_AND_BEFORE_FIRST_UNIT_RESULT_WRITE",
        "checks": checks,
        "status": "PASS" if all(checks.values()) else "FAIL_CLOSED",
    }


def verify_v34_frozen() -> dict[str, Any]:
    p = v34_paths()
    terminal = load(p["terminal"])
    manifest = load(p["manifest"])
    unit = load(p["unit"])
    closure = load(p["closure"])
    symbols = load(p["symbols"])
    helper_matrix = load(p["helper_matrix"])
    manifest_exact, computed_root = _verify_manifest(V34, manifest, 249, V34_ROOT_SHA)
    checks = {
        "terminal_digest": sha256(p["terminal"]) == V34_TERMINAL_SHA,
        "manifest_digest": sha256(p["manifest"]) == V34_MANIFEST_SHA,
        "freeze_digest": sha256(p["freeze"]) == V34_FREEZE_SHA,
        "unit_digest": sha256(p["unit"]) == V34_UNIT_SHA,
        "manifest_members_and_root": manifest_exact,
        "workspace_read_only": stat.S_IMODE(V34.stat().st_mode) == 0o555,
        "terminal_state": terminal.get("status") == V34_STATUS,
        "unit_execution_error": unit.get("status") == "FAIL_CLOSED_EXECUTION_ERROR" and unit.get("failed_gate") == "UNIT_HARNESS_NEGATIVE_FIXTURE_PARENT_DIRECTORY_LIFECYCLE",
        "exception_exact": unit.get("exception", {}).get("type") == "FileNotFoundError" and unit.get("exception", {}).get("errno") == 2 and unit.get("exception", {}).get("line") == 255,
        "later_gates_not_started": terminal.get("primary") == terminal.get("independent") == terminal.get("fresh_preflight") == terminal.get("dependency_closure") == "NOT_STARTED",
        "static_lock_not_issued": terminal.get("static_lock") == "NOT_ISSUED" and not (V34 / "STATIC_EXECUTION_LOCK.json").exists(),
        "counters_zero": terminal.get("attempt_count") == terminal.get("worker_invocation_count") == terminal.get("codex_as_worker_invocation_count") == 0,
        "attempt_absent": terminal.get("attempt_marker") == "ABSENT" and not any(V34.rglob("ATTEMPT_MARKER.json")),
        "runtime_absent": terminal.get("runtime_evidence") == "ABSENT" and not any(V34.rglob("runtime-result-0001.json")),
        "no_bytecode": not any(V34.rglob("*.pyc")) and not any(path.name == "__pycache__" for path in V34.rglob("*")),
        "artifact_closure_199": closure.get("member_count") == 199 and closure.get("status") == "PASS_CREATION_PHASE_CLOSED_IMMUTABILITY_APPLIED",
        "symbol_graph_97": symbols.get("symbol_count") == len(symbols.get("symbols", [])) == 97 and symbols.get("status") == "PASS",
        "helper_regressions_8": helper_matrix.get("case_count") == len(helper_matrix.get("cases", [])) == 8,
        "typed_helper_source_present": p["helper_source"].is_file(),
        "failure_path_reconstructed": failure_path_evidence()["status"] == "PASS",
    }
    return {
        "record_type": "V34_FROZEN_FAILURE_EVIDENCE_VERDICT",
        "checks": checks,
        "member_count": manifest.get("member_count"),
        "canonical_evidence_root_sha256": computed_root,
        "status": "PASS" if all(checks.values()) else "FAIL_CLOSED",
    }


def verify_v33_frozen() -> dict[str, Any]:
    pre = V33 / "results/prelock"
    terminal_path = pre / "PRELOCK_TERMINAL_ENGINEERING_RESULT.json"
    manifest_path = pre / "PRELOCK_FAILURE_EVIDENCE_MANIFEST.json"
    freeze_path = pre / "PRELOCK_FAILURE_EVIDENCE_FREEZE_VERIFICATION.json"
    terminal = load(terminal_path)
    manifest = load(manifest_path)
    manifest_exact, computed_root = _verify_manifest(V33, manifest, 339, V33_ROOT_SHA)
    checks = {
        "terminal_digest": sha256(terminal_path) == V33_TERMINAL_SHA,
        "manifest_digest": sha256(manifest_path) == V33_MANIFEST_SHA,
        "freeze_digest": sha256(freeze_path) == V33_FREEZE_SHA,
        "manifest_members_and_root": manifest_exact,
        "workspace_read_only": stat.S_IMODE(V33.stat().st_mode) == 0o555,
        "terminal_immutable": terminal.get("status") == "FAIL_CLOSED_DURING_PRIMARY_STATIC_VALIDATION_PRELOCK_TERMINAL_NO_RETRY_FROZEN_FAILURE_EVIDENCE",
        "no_attempt": not any(V33.rglob("ATTEMPT_MARKER.json")),
        "no_runtime": not any(V33.rglob("runtime-result-0001.json")),
    }
    return {
        "record_type": "V33_FROZEN_EVIDENCE_VERDICT",
        "checks": checks,
        "member_count": manifest.get("member_count"),
        "canonical_evidence_root_sha256": computed_root,
        "status": "PASS" if all(checks.values()) else "FAIL_CLOSED",
    }


def _contained(path: str, workspace: str) -> bool:
    candidate = PurePosixPath(path)
    root = PurePosixPath(workspace)
    if ".." in candidate.parts:
        return False
    try:
        candidate.relative_to(root)
    except ValueError:
        return False
    return True


def lifecycle_fixture_verdict(case: dict[str, Any]) -> bool:
    """Pure governance oracle: it performs no filesystem mutation."""
    workspace = case.get("workspace", "/workspace/v35")
    prelock = case.get("prelock_root", f"{workspace}/results/prelock")
    scratch = case.get("probe_root", f"{workspace}/scratch/prelock-fixtures/run-0001")
    probe = case.get("probe_path", f"{scratch}/.predecessor-symlink-probe")
    predecessor = case.get("predecessor_root", "/workspace/v34")
    exact = {
        "workspace_boundary_verified": case.get("workspace_boundary_verified") is True,
        "prelock_exact": prelock == f"{workspace}/results/prelock" and _contained(prelock, workspace),
        "scratch_exact": scratch == f"{workspace}/scratch/prelock-fixtures/run-0001" and _contained(scratch, workspace),
        "probe_contained": _contained(probe, scratch) and not _contained(probe, predecessor),
        "prelock_exists": case.get("prelock_exists") is True,
        "prelock_real_directory": case.get("prelock_real_directory") is True and case.get("prelock_symlink") is False,
        "prelock_owner_mode": case.get("prelock_owner") == "EXPECTED_UID_GID" and case.get("prelock_mode") == "0700",
        "prelock_initially_empty": case.get("prelock_initially_empty") is True,
        "probe_root_exists": case.get("probe_root_exists") is True,
        "probe_root_real_directory": case.get("probe_root_real_directory") is True and case.get("probe_root_symlink") is False,
        "probe_root_owner_mode": case.get("probe_root_owner") == "EXPECTED_UID_GID" and case.get("probe_root_mode") == "0700",
        "probe_root_initially_empty": case.get("probe_root_initially_empty") is True,
        "exclusive_creation": case.get("exclusive_creation") is True and case.get("preexisting_reuse") is False,
        "lifecycle_order": case.get("order") == ["WORKSPACE_BOUNDARY_PASS", "PRELOCK_ROOT_PROVISIONED", "PROBE_ROOT_PROVISIONED", "FIRST_EVIDENCE_WRITER", "UNIT_FIXTURES"],
        "negative_symlink_executed": case.get("negative_symlink_fixture_executed") is True,
        "predecessor_unchanged": case.get("predecessor_mutated") is False,
        "first_failure_writable": case.get("first_unit_failure_evidence_writable") is True,
    }
    return all(exact.values())


def canonical_lifecycle_case() -> dict[str, Any]:
    return {
        "workspace": "/workspace/v35",
        "prelock_root": "/workspace/v35/results/prelock",
        "probe_root": "/workspace/v35/scratch/prelock-fixtures/run-0001",
        "probe_path": "/workspace/v35/scratch/prelock-fixtures/run-0001/.predecessor-symlink-probe",
        "predecessor_root": "/workspace/v34",
        "workspace_boundary_verified": True,
        "prelock_exists": True,
        "prelock_real_directory": True,
        "prelock_symlink": False,
        "prelock_owner": "EXPECTED_UID_GID",
        "prelock_mode": "0700",
        "prelock_initially_empty": True,
        "probe_root_exists": True,
        "probe_root_real_directory": True,
        "probe_root_symlink": False,
        "probe_root_owner": "EXPECTED_UID_GID",
        "probe_root_mode": "0700",
        "probe_root_initially_empty": True,
        "exclusive_creation": True,
        "preexisting_reuse": False,
        "order": ["WORKSPACE_BOUNDARY_PASS", "PRELOCK_ROOT_PROVISIONED", "PROBE_ROOT_PROVISIONED", "FIRST_EVIDENCE_WRITER", "UNIT_FIXTURES"],
        "negative_symlink_fixture_executed": True,
        "predecessor_mutated": False,
        "first_unit_failure_evidence_writable": True,
    }
