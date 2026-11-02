"""Fail-before-write lifecycle for V35 prelock evidence and fixture scratch roots."""

from __future__ import annotations

import hashlib
import json
import os
import stat
from pathlib import Path
from typing import Any, Mapping

from workspace_boundary_v35 import (
    PREDECESSOR_DENY_WRITE_ROOTS,
    WORKSPACE,
    authorize_write,
    guarded_mkdir_exact_leaf,
    guarded_open_text,
)


EXECUTION_IDENTITY = "V0_3_FIRST_REAL_SECURITY_WORKER_INVOCATION_V35"
GENERATION_IDENTITY = "V35_CURRENT_GOVERNANCE_BOUND_TYPED_PREFLIGHT_BINDING_GENERATION_0001"
CONTROLLER_IDENTITY = "V35_PRELOCK_STORAGE_LIFECYCLE_CONTROLLER_V1"
PRELOCK_PROVISIONER_IDENTITY = "V35_PRELOCK_EVIDENCE_ROOT_PROVISIONER_V1"
FIXTURE_PROVISIONER_IDENTITY = "V35_FIXTURE_SCRATCH_ROOT_PROVISIONER_V1"
GOVERNANCE_LOCK_SHA256 = "d2263268f61b9ddde99a0b60f4b43a26df1586e0c577ba2ca98c07b64c21f811"

CONTRACT = WORKSPACE / "contracts/SUCCESSOR_V35_PRELOCK_RESULTS_AND_FIXTURE_PROBE_LIFECYCLE_CONTRACT.json"
GOVERNANCE_LOCK = Path(
    "/home/nobcoder/codex-security-harness-eval/governance/"
    "v0.3-first-real-security-worker-invocation-v34-prelock-results-directory-and-fixture-"
    "probe-path-lifecycle-defect-unit-execution-erratum-and-successor-decision-"
    "governance-only-v1-20261103/GOVERNANCE_LOCK.json"
)
V34 = Path("/home/nobcoder/v0.3-first-real-security-worker-invocation-v34-20261103")
V34_MANIFEST = V34 / "results/prelock/PRELOCK_FAILURE_EVIDENCE_MANIFEST.json"

RESULTS_ROOT = WORKSPACE / "results"
PRELOCK_ROOT = RESULTS_ROOT / "prelock"
SCRATCH_ROOT = WORKSPACE / "scratch"
FIXTURE_SCRATCH_PARENT = SCRATCH_ROOT / "prelock-fixtures"
FIXTURE_PROBE_ROOT = FIXTURE_SCRATCH_PARENT / "run-0001"
PROVISIONING_EVIDENCE = PRELOCK_ROOT / "prelock-storage-lifecycle-run-0001.json"
PROBE_LEAF_NAME = ".predecessor-symlink-probe"

CREATION_ORDER = [
    "FRESH_WORKSPACE_IDENTITY_BOUND",
    "WORKSPACE_BOUNDARY_AND_PREDECESSOR_DENY_ROOTS_VERIFIED",
    "PRELOCK_EVIDENCE_ROOT_ATOMIC_EXCLUSIVE_PROVISIONING",
    "FIXTURE_SCRATCH_ROOT_ATOMIC_EXCLUSIVE_PROVISIONING",
    "PROVISIONING_EVIDENCE_APPEND_ONLY_WRITE",
    "FIRST_UNIT_OR_VALIDATION_EVIDENCE_WRITER",
    "UNIT_FIXTURE_EXECUTION",
]
ALLOWED_COMPONENTS = frozenset({
    "UNIT", "PRIMARY_VALIDATOR", "INDEPENDENT_VALIDATOR", "FRESH_PREFLIGHT",
    "DEPENDENCY_CLOSURE", "STATIC_LOCK_PREPARATION", "STATIC_LOCK_VERIFICATION",
    "LOCKED_RUNTIME", "POST_VALIDATOR",
})


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _load(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"JSON object required: {path}")
    return value


def _real_empty_0700_owned(path: Path) -> bool:
    try:
        info = path.lstat()
    except FileNotFoundError:
        return False
    return (
        stat.S_ISDIR(info.st_mode)
        and not path.is_symlink()
        and stat.S_IMODE(info.st_mode) == 0o700
        and info.st_uid == os.getuid()
        and info.st_gid == os.getgid()
        and not any(path.iterdir())
    )


def lifecycle_fixture_verdict(candidate: Mapping[str, Any]) -> dict[str, Any]:
    checks = {
        "workspace_boundary_pass": candidate.get("workspace_boundary_status") == "PASS",
        "prelock_path_exact": candidate.get("prelock_root") == str(PRELOCK_ROOT),
        "probe_root_exact": candidate.get("fixture_probe_root") == str(FIXTURE_PROBE_ROOT),
        "prelock_real": candidate.get("prelock_real_directory") is True and candidate.get("prelock_symlink") is False,
        "probe_real": candidate.get("probe_real_directory") is True and candidate.get("probe_symlink") is False,
        "prelock_empty": candidate.get("prelock_initially_empty") is True,
        "probe_empty": candidate.get("probe_initially_empty") is True,
        "modes": candidate.get("prelock_mode") == candidate.get("probe_mode") == "0700",
        "owners": candidate.get("prelock_uid") == candidate.get("probe_uid") == os.getuid()
        and candidate.get("prelock_gid") == candidate.get("probe_gid") == os.getgid(),
        "exclusive": candidate.get("exclusive_creation") is True and candidate.get("preexisting_reuse") is False,
        "order": candidate.get("creation_order") == CREATION_ORDER,
        "contained": candidate.get("current_workspace_containment") is True,
        "predecessor_denied": candidate.get("predecessor_deny_write") is True,
        "predecessor_unchanged": candidate.get("predecessor_snapshot_before") == candidate.get("predecessor_snapshot_after"),
        "first_writer": candidate.get("provisioning_evidence_is_first_prelock_writer") is True,
        "first_failure_writable": candidate.get("first_unit_failure_evidence_writable") is True,
    }
    return {
        "record_type": "V35_PRELOCK_STORAGE_LIFECYCLE_FIXTURE_VERDICT",
        "checks": checks,
        "status": "PASS" if all(checks.values()) else "FAIL_CLOSED_BEFORE_FILESYSTEM_MUTATION_OR_UNIT_VALIDATION",
    }


def _contract_precheck() -> dict[str, Any]:
    if not CONTRACT.is_file() or CONTRACT.is_symlink() or not GOVERNANCE_LOCK.is_file() or GOVERNANCE_LOCK.is_symlink():
        return {"status": "FAIL_CLOSED_BEFORE_FILESYSTEM_MUTATION", "reason": "CONTRACT_OR_GOVERNANCE_LOCK_UNAVAILABLE"}
    contract = _load(CONTRACT)
    lock = _load(GOVERNANCE_LOCK)
    checks = {
        "contract_identity": contract.get("contract_identity") == "V35_PRELOCK_RESULTS_AND_FIXTURE_PROBE_LIFECYCLE_CONTRACT_V1",
        "successor_identity": contract.get("successor_identity") == EXECUTION_IDENTITY,
        "controller": contract.get("responsible_component") == CONTROLLER_IDENTITY,
        "prelock_provisioner": contract.get("provisioners", {}).get("prelock_evidence_root") == PRELOCK_PROVISIONER_IDENTITY,
        "fixture_provisioner": contract.get("provisioners", {}).get("fixture_probe_root") == FIXTURE_PROVISIONER_IDENTITY,
        "governance_lock_digest": _sha256(GOVERNANCE_LOCK) == GOVERNANCE_LOCK_SHA256,
        "governance_lock_state": lock.get("status") == "PASS_LOCKED_GOVERNANCE_ONLY" and lock.get("v35_disposition") == "CONDITIONALLY_AUTHORIZED_NOT_CREATED_NOT_EXECUTED",
        "no_recursive_or_idempotent_create": "AD_HOC_MKDIR_P" in contract.get("prohibited_repairs", []) and "EXIST_OK_TRUE" in contract.get("prohibited_repairs", []),
    }
    return {
        "record_type": "V35_PRELOCK_STORAGE_LIFECYCLE_CONTRACT_PRECHECK",
        "contract_sha256": _sha256(CONTRACT),
        "governance_lock_sha256": _sha256(GOVERNANCE_LOCK),
        "checks": checks,
        "status": "PASS" if all(checks.values()) else "FAIL_CLOSED_BEFORE_FILESYSTEM_MUTATION",
    }


def _workspace_boundary_precheck() -> dict[str, Any]:
    candidates = (RESULTS_ROOT, PRELOCK_ROOT, SCRATCH_ROOT, FIXTURE_SCRATCH_PARENT, FIXTURE_PROBE_ROOT, PROVISIONING_EVIDENCE)
    verdicts = []
    for index, destination in enumerate(candidates):
        verdicts.append(authorize_write(
            destination,
            operation_identity=f"V35_PRELOCK_STORAGE_BOUNDARY_PREFLIGHT_{index}",
            write_generation_identity=GENERATION_IDENTITY,
            expected_destination=destination,
        ))
    denied_roots_present = V34 in PREDECESSOR_DENY_WRITE_ROOTS
    return {
        "record_type": "V35_PRELOCK_STORAGE_WORKSPACE_BOUNDARY_PRECHECK",
        "authorized_destinations": verdicts,
        "v34_explicit_deny_write_root": denied_roots_present,
        "status": "PASS" if len(verdicts) == len(candidates) and denied_roots_present else "FAIL_CLOSED_BEFORE_FILESYSTEM_MUTATION",
    }


def provision_prelock_storage() -> dict[str, Any]:
    contract = _contract_precheck()
    boundary = _workspace_boundary_precheck()
    if contract.get("status") != "PASS" or boundary.get("status") != "PASS":
        return {
            "record_type": "V35_PRELOCK_STORAGE_PROVISIONING_RESULT",
            "contract": contract,
            "workspace_boundary": boundary,
            "status": "FAIL_CLOSED_BEFORE_FILESYSTEM_MUTATION",
        }
    targets = (RESULTS_ROOT, PRELOCK_ROOT, SCRATCH_ROOT, FIXTURE_SCRATCH_PARENT, FIXTURE_PROBE_ROOT)
    if any(path.exists() or path.is_symlink() for path in targets) or PROVISIONING_EVIDENCE.exists() or PROVISIONING_EVIDENCE.is_symlink():
        return {
            "record_type": "V35_PRELOCK_STORAGE_PROVISIONING_RESULT",
            "status": "FAIL_CLOSED_BEFORE_FILESYSTEM_MUTATION",
            "reason": "PREEXISTING_RESULTS_PRELOCK_SCRATCH_OR_EVIDENCE_PROHIBITED",
        }
    if not V34_MANIFEST.is_file() or V34_MANIFEST.is_symlink():
        return {"record_type": "V35_PRELOCK_STORAGE_PROVISIONING_RESULT", "status": "FAIL_CLOSED_BEFORE_FILESYSTEM_MUTATION", "reason": "V34_FROZEN_MANIFEST_UNAVAILABLE"}
    predecessor_before = _sha256(V34_MANIFEST)
    if predecessor_before != "604dcf1b0675392ed8ce724a9de424fd0f7a640c8f9da9e5250fa0c0bebaab3a":
        return {"record_type": "V35_PRELOCK_STORAGE_PROVISIONING_RESULT", "status": "FAIL_CLOSED_BEFORE_FILESYSTEM_MUTATION", "reason": "V34_FROZEN_MANIFEST_DRIFT"}

    guarded_mkdir_exact_leaf(RESULTS_ROOT, operation_identity=PRELOCK_PROVISIONER_IDENTITY, generation=GENERATION_IDENTITY, mode=0o700)
    guarded_mkdir_exact_leaf(PRELOCK_ROOT, operation_identity=PRELOCK_PROVISIONER_IDENTITY, generation=GENERATION_IDENTITY, mode=0o700)
    prelock_initially_empty = _real_empty_0700_owned(PRELOCK_ROOT)
    guarded_mkdir_exact_leaf(SCRATCH_ROOT, operation_identity=FIXTURE_PROVISIONER_IDENTITY, generation=GENERATION_IDENTITY, mode=0o700)
    guarded_mkdir_exact_leaf(FIXTURE_SCRATCH_PARENT, operation_identity=FIXTURE_PROVISIONER_IDENTITY, generation=GENERATION_IDENTITY, mode=0o700)
    guarded_mkdir_exact_leaf(FIXTURE_PROBE_ROOT, operation_identity=FIXTURE_PROVISIONER_IDENTITY, generation=GENERATION_IDENTITY, mode=0o700)
    probe_initially_empty = _real_empty_0700_owned(FIXTURE_PROBE_ROOT)
    if not prelock_initially_empty or not probe_initially_empty:
        raise RuntimeError("V35_PROVISIONED_ROOT_POSTCONDITION_FAILED_NO_CLEANUP_AUTHORIZED")
    predecessor_after = _sha256(V34_MANIFEST)
    if predecessor_after != predecessor_before:
        raise RuntimeError("V35_PREDECESSOR_MUTATED_DURING_PROVISIONING")

    info_prelock = PRELOCK_ROOT.lstat()
    info_probe = FIXTURE_PROBE_ROOT.lstat()
    payload = {
        "record_type": "V35_PRELOCK_STORAGE_LIFECYCLE_PROVISIONING_EVIDENCE",
        "workspace_identity": EXECUTION_IDENTITY,
        "binding_generation_identity": GENERATION_IDENTITY,
        "controller_identity": CONTROLLER_IDENTITY,
        "provisioner_identities": [PRELOCK_PROVISIONER_IDENTITY, FIXTURE_PROVISIONER_IDENTITY],
        "canonical_paths": {
            "prelock_evidence_root": str(PRELOCK_ROOT.resolve(strict=True)),
            "fixture_probe_root": str(FIXTURE_PROBE_ROOT.resolve(strict=True)),
        },
        "uid": info_prelock.st_uid,
        "gid": info_prelock.st_gid,
        "modes": {"prelock_evidence_root": "0700", "fixture_probe_root": "0700"},
        "initial_emptiness": {"prelock_evidence_root": prelock_initially_empty, "fixture_probe_root": probe_initially_empty},
        "real_directories_not_symlinks": True,
        "exclusive_creation": True,
        "preexisting_state_reused": False,
        "creation_order": CREATION_ORDER,
        "current_workspace_containment": True,
        "predecessor_deny_write_roots_count": len(PREDECESSOR_DENY_WRITE_ROOTS),
        "predecessor_snapshot_digest": predecessor_before,
        "predecessor_snapshot_after_digest": predecessor_after,
        "contract_sha256": contract["contract_sha256"],
        "governance_lock_sha256": GOVERNANCE_LOCK_SHA256,
        "provisioning_evidence_is_first_prelock_writer": True,
        "attempt_count": 0,
        "worker_invocation_count": 0,
        "codex_as_worker_invocation_count": 0,
        "status": "PASS",
    }
    with guarded_open_text(PROVISIONING_EVIDENCE, operation_identity="V35_PRELOCK_STORAGE_PROVISIONING_EVIDENCE", generation=GENERATION_IDENTITY) as handle:
        json.dump(payload, handle, indent=2, sort_keys=True)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    return payload


def prelock_storage_lifecycle_precheck(component: str, *, require_probe_empty: bool = True) -> dict[str, Any]:
    if component not in ALLOWED_COMPONENTS or not PROVISIONING_EVIDENCE.is_file() or PROVISIONING_EVIDENCE.is_symlink():
        return {"record_type": "V35_PRELOCK_STORAGE_LIFECYCLE_PRECHECK", "component": component, "status": "FAIL_CLOSED_BEFORE_VALIDATION_STATIC_LOCK_OR_ATTEMPT", "reason": "COMPONENT_OR_EVIDENCE_INVALID"}
    evidence = _load(PROVISIONING_EVIDENCE)
    try:
        prelock_info = PRELOCK_ROOT.lstat()
        probe_info = FIXTURE_PROBE_ROOT.lstat()
    except FileNotFoundError:
        return {"record_type": "V35_PRELOCK_STORAGE_LIFECYCLE_PRECHECK", "component": component, "status": "FAIL_CLOSED_BEFORE_VALIDATION_STATIC_LOCK_OR_ATTEMPT", "reason": "ROOT_MISSING"}
    checks = {
        "status": evidence.get("status") == "PASS",
        "identity": evidence.get("workspace_identity") == EXECUTION_IDENTITY,
        "generation": evidence.get("binding_generation_identity") == GENERATION_IDENTITY,
        "controller": evidence.get("controller_identity") == CONTROLLER_IDENTITY,
        "governance": evidence.get("governance_lock_sha256") == GOVERNANCE_LOCK_SHA256,
        "contract": evidence.get("contract_sha256") == _sha256(CONTRACT),
        "prelock_path": evidence.get("canonical_paths", {}).get("prelock_evidence_root") == str(PRELOCK_ROOT.resolve(strict=True)),
        "probe_path": evidence.get("canonical_paths", {}).get("fixture_probe_root") == str(FIXTURE_PROBE_ROOT.resolve(strict=True)),
        "prelock_real": stat.S_ISDIR(prelock_info.st_mode) and not PRELOCK_ROOT.is_symlink(),
        "probe_real": stat.S_ISDIR(probe_info.st_mode) and not FIXTURE_PROBE_ROOT.is_symlink(),
        "modes": stat.S_IMODE(prelock_info.st_mode) == stat.S_IMODE(probe_info.st_mode) == 0o700,
        "owners": prelock_info.st_uid == probe_info.st_uid == os.getuid() and prelock_info.st_gid == probe_info.st_gid == os.getgid(),
        "initial_empty_attested": evidence.get("initial_emptiness") == {"prelock_evidence_root": True, "fixture_probe_root": True},
        "probe_empty_if_required": (not require_probe_empty) or not any(FIXTURE_PROBE_ROOT.iterdir()),
        "predecessor_snapshot": evidence.get("predecessor_snapshot_digest") == evidence.get("predecessor_snapshot_after_digest") == _sha256(V34_MANIFEST),
        "first_writer": evidence.get("provisioning_evidence_is_first_prelock_writer") is True,
        "counters_zero": evidence.get("attempt_count") == evidence.get("worker_invocation_count") == evidence.get("codex_as_worker_invocation_count") == 0,
    }
    return {
        "record_type": "V35_PRELOCK_STORAGE_LIFECYCLE_PRECHECK",
        "component": component,
        "evidence_sha256": _sha256(PROVISIONING_EVIDENCE),
        "checks": checks,
        "status": "PASS" if all(checks.values()) else "FAIL_CLOSED_BEFORE_VALIDATION_STATIC_LOCK_OR_ATTEMPT",
    }
