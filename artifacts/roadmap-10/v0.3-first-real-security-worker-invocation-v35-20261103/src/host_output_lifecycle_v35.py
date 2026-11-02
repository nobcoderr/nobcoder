"""Exclusive, evidence-bound lifecycle for the V35 host output bind source."""

from __future__ import annotations

import hashlib
import json
import os
import stat
from pathlib import Path
from typing import Any, Mapping

from workspace_boundary_v35 import guarded_json_once, guarded_mkdir_exact_leaf


WORKSPACE = Path("/home/nobcoder/v0.3-first-real-security-worker-invocation-v35-20261103")
EXECUTION_IDENTITY = "V0_3_FIRST_REAL_SECURITY_WORKER_INVOCATION_V35"
GENERATION_IDENTITY = "V35_CURRENT_GOVERNANCE_BOUND_TYPED_PREFLIGHT_BINDING_GENERATION_0001"
PROVISIONER_IDENTITY = "V35_HOST_OUTPUT_BIND_SOURCE_PROVISIONER_V1"
CONTRACT = WORKSPACE / "contracts/HOST_OUTPUT_BIND_SOURCE_LIFECYCLE_CONTRACT.json"
HOST_OUTPUT = WORKSPACE / "static-run-v35"
EVIDENCE = WORKSPACE / "results/prelock/host-output-bind-source-lifecycle-run-0001.json"
AUTHORIZED_STAGE = "AFTER_WORKSPACE_BOUNDARY_BEFORE_BIND_FEASIBILITY"
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


def lifecycle_fixture_verdict(candidate: Mapping[str, Any]) -> dict[str, Any]:
    checks = {
        "execution_identity": candidate.get("execution_identity") == EXECUTION_IDENTITY,
        "generation_identity": candidate.get("binding_generation_identity") == GENERATION_IDENTITY,
        "provisioner_identity": candidate.get("creator_component") == PROVISIONER_IDENTITY,
        "creation_stage": candidate.get("creation_stage") == AUTHORIZED_STAGE,
        "canonical_path": candidate.get("canonical_path") == str(HOST_OUTPUT),
        "exclusive_creation": candidate.get("creation_semantics") == "ATOMIC_EXCLUSIVE_DIRECTORY_CREATION_NO_EXIST_OK",
        "owner": candidate.get("owner_uid") == os.getuid() and candidate.get("owner_gid") == os.getgid(),
        "mode": candidate.get("mode") == "0700",
        "initial_state": candidate.get("required_initial_state") == "EMPTY_DIRECTORY",
        "preexisting_prohibited": candidate.get("preexisting_state_permitted") is False,
        "before_feasibility": candidate.get("created_before_feasibility_validation") is True,
        "append_only_evidence": candidate.get("append_only_evidence") is True,
        "evidence_path": candidate.get("evidence_path") == "results/prelock/host-output-bind-source-lifecycle-run-0001.json",
    }
    return {"record_type": "V35_HOST_OUTPUT_BIND_SOURCE_LIFECYCLE_FIXTURE_VERDICT", "checks": checks, "status": "PASS" if all(checks.values()) else "FAIL_CLOSED_BEFORE_BIND_FEASIBILITY"}


def provisioning_fixture_verdict(
    *,
    path_exists_before: bool,
    is_symlink: bool = False,
    is_directory: bool = False,
    is_empty: bool = True,
    mode: int = 0o700,
    owner_uid: int | None = None,
    owner_gid: int | None = None,
    workspace_boundary_status: str = "PASS",
    lifecycle_stage: str = AUTHORIZED_STAGE,
) -> dict[str, Any]:
    """Pure oracle: only an absent path may proceed to exclusive creation."""
    owner_uid = os.getuid() if owner_uid is None else owner_uid
    owner_gid = os.getgid() if owner_gid is None else owner_gid
    checks = {
        "workspace_boundary_pass": workspace_boundary_status == "PASS",
        "lifecycle_stage_exact": lifecycle_stage == AUTHORIZED_STAGE,
        "path_absent_before": path_exists_before is False,
        "not_symlink": is_symlink is False,
        "no_reused_directory": is_directory is False,
        "no_reused_content": is_empty is True,
        "requested_mode_exact": mode == 0o700,
        "requested_owner_exact": owner_uid == os.getuid() and owner_gid == os.getgid(),
    }
    return {"record_type": "V35_HOST_OUTPUT_BIND_SOURCE_PROVISIONING_FIXTURE_VERDICT", "checks": checks, "status": "PASS_TO_EXCLUSIVE_CREATE" if all(checks.values()) else "FAIL_CLOSED_BEFORE_FILESYSTEM_MUTATION"}


def _contract_precheck() -> dict[str, Any]:
    if not CONTRACT.is_file() or CONTRACT.is_symlink():
        return {"status": "FAIL_CLOSED_BEFORE_BIND_FEASIBILITY", "reason": "CONTRACT_MISSING_OR_UNSAFE"}
    contract = _load(CONTRACT)
    verdict = lifecycle_fixture_verdict(contract)
    return {
        "record_type": "V35_HOST_OUTPUT_BIND_SOURCE_LIFECYCLE_CONTRACT_PRECHECK",
        "contract_sha256": _sha256(CONTRACT),
        "fixture_verdict": verdict,
        "status": "PASS" if verdict["status"] == "PASS" else "FAIL_CLOSED_BEFORE_BIND_FEASIBILITY",
    }


def provision_host_output_bind_source(*, workspace_boundary_status: str, lifecycle_stage: str) -> dict[str, Any]:
    """Create the exact output root once; fail before mutation on any ambiguity."""
    contract = _contract_precheck()
    if contract.get("status") != "PASS":
        return contract
    if workspace_boundary_status != "PASS" or lifecycle_stage != AUTHORIZED_STAGE:
        return {"record_type": "V35_HOST_OUTPUT_BIND_SOURCE_PROVISIONING", "status": "FAIL_CLOSED_BEFORE_BIND_FEASIBILITY", "reason": "LIFECYCLE_ORDER_OR_WORKSPACE_BOUNDARY_INVALID"}
    if HOST_OUTPUT.exists() or HOST_OUTPUT.is_symlink() or EVIDENCE.exists() or EVIDENCE.is_symlink():
        return {"record_type": "V35_HOST_OUTPUT_BIND_SOURCE_PROVISIONING", "status": "FAIL_CLOSED_BEFORE_BIND_FEASIBILITY", "reason": "PREEXISTING_SOURCE_OR_EVIDENCE_PROHIBITED"}
    guarded_mkdir_exact_leaf(HOST_OUTPUT, operation_identity=PROVISIONER_IDENTITY, generation=GENERATION_IDENTITY, mode=0o700)
    info = HOST_OUTPUT.lstat()
    created_checks = {
        "real_directory": stat.S_ISDIR(info.st_mode) and not HOST_OUTPUT.is_symlink(),
        "empty": not any(HOST_OUTPUT.iterdir()),
        "mode": stat.S_IMODE(info.st_mode) == 0o700,
        "owner": info.st_uid == os.getuid() and info.st_gid == os.getgid(),
    }
    if not all(created_checks.values()):
        raise RuntimeError("V35_PROVISIONED_BIND_SOURCE_POSTCONDITION_FAILED_NO_CLEANUP_AUTHORIZED")
    payload = {
        "record_type": "V35_HOST_OUTPUT_BIND_SOURCE_PROVISIONING_EVIDENCE",
        "execution_identity": EXECUTION_IDENTITY,
        "binding_generation_identity": GENERATION_IDENTITY,
        "creator_component": PROVISIONER_IDENTITY,
        "creation_stage": lifecycle_stage,
        "canonical_path": str(HOST_OUTPUT.resolve(strict=True)),
        "creation_semantics": "ATOMIC_EXCLUSIVE_DIRECTORY_CREATION_NO_EXIST_OK",
        "owner_uid": info.st_uid,
        "owner_gid": info.st_gid,
        "mode": f"{stat.S_IMODE(info.st_mode):04o}",
        "initial_state": "EMPTY_DIRECTORY",
        "preexisting_state": False,
        "workspace_boundary_status": workspace_boundary_status,
        "created_before_feasibility_validation": True,
        "contract_sha256": contract["contract_sha256"],
        "status": "PASS",
    }
    guarded_json_once(EVIDENCE, payload, operation_identity="V35_HOST_OUTPUT_BIND_SOURCE_PROVISIONING_EVIDENCE", generation=GENERATION_IDENTITY)
    return payload


def host_output_bind_source_precheck(component: str, *, require_current_empty: bool = False) -> dict[str, Any]:
    if component not in ALLOWED_COMPONENTS:
        return {"status": "FAIL_CLOSED_BEFORE_STATIC_LOCK_AND_ATTEMPT", "reason": "UNAUTHORIZED_COMPONENT"}
    contract = _contract_precheck()
    if contract.get("status") != "PASS" or not EVIDENCE.is_file() or EVIDENCE.is_symlink():
        return {"status": "FAIL_CLOSED_BEFORE_STATIC_LOCK_AND_ATTEMPT", "reason": "CONTRACT_OR_EVIDENCE_INVALID"}
    evidence = _load(EVIDENCE)
    try:
        info = HOST_OUTPUT.lstat()
    except FileNotFoundError:
        return {"status": "FAIL_CLOSED_BEFORE_STATIC_LOCK_AND_ATTEMPT", "reason": "BIND_SOURCE_MISSING"}
    checks = {
        "evidence_status": evidence.get("status") == "PASS",
        "execution_identity": evidence.get("execution_identity") == EXECUTION_IDENTITY,
        "generation_identity": evidence.get("binding_generation_identity") == GENERATION_IDENTITY,
        "provisioner_identity": evidence.get("creator_component") == PROVISIONER_IDENTITY,
        "lifecycle_order": evidence.get("creation_stage") == AUTHORIZED_STAGE and evidence.get("created_before_feasibility_validation") is True,
        "canonical_path": evidence.get("canonical_path") == str(HOST_OUTPUT.resolve(strict=True)),
        "real_directory": stat.S_ISDIR(info.st_mode) and not HOST_OUTPUT.is_symlink(),
        "owner": info.st_uid == evidence.get("owner_uid") == os.getuid() and info.st_gid == evidence.get("owner_gid") == os.getgid(),
        "mode": stat.S_IMODE(info.st_mode) == 0o700 and evidence.get("mode") == "0700",
        "initial_empty_attested": evidence.get("initial_state") == "EMPTY_DIRECTORY" and evidence.get("preexisting_state") is False,
        "current_empty_if_required": (not require_current_empty) or not any(HOST_OUTPUT.iterdir()),
        "contract_digest": evidence.get("contract_sha256") == contract.get("contract_sha256"),
    }
    return {"record_type": "V35_HOST_OUTPUT_BIND_SOURCE_LIFECYCLE_PRECHECK", "component": component, "checks": checks, "evidence_sha256": _sha256(EVIDENCE), "status": "PASS" if all(checks.values()) else "FAIL_CLOSED_BEFORE_STATIC_LOCK_AND_ATTEMPT"}
