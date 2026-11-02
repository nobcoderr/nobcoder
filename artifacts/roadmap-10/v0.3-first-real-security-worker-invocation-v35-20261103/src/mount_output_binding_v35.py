"""Governance-bound V35 mount/output identity resolution."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Mapping


WORKSPACE = Path("/home/nobcoder/v0.3-first-real-security-worker-invocation-v35-20261103")
EXECUTION_IDENTITY = "V0_3_FIRST_REAL_SECURITY_WORKER_INVOCATION_V35"
WORKSPACE_IDENTITY = "V0_3_FIRST_REAL_SECURITY_WORKER_INVOCATION_V35_WORKSPACE"
LOGICAL_OUTPUT_IDENTITY = "V35_RUNTIME_OUTPUT_ROOT"
GENERATION_IDENTITY = "V35_GOVERNANCE_BOUND_MOUNT_OUTPUT_BINDING_GENERATION_0001"
GOVERNANCE_IDENTITY = "V0_3_FIRST_REAL_SECURITY_WORKER_INVOCATION_V34_PRELOCK_RESULTS_DIRECTORY_AND_FIXTURE_PROBE_PATH_LIFECYCLE_DEFECT_UNIT_EXECUTION_ERRATUM_AND_SUCCESSOR_DECISION_GOVERNANCE_ONLY"
GOVERNANCE_LOCK_SHA256 = "d2263268f61b9ddde99a0b60f4b43a26df1586e0c577ba2ca98c07b64c21f811"
HOST_OUTPUT = WORKSPACE / "static-run-v35"
NAMESPACE_OUTPUT = Path("/run/nobcoder-first-worker-v35/output")
MOUNT_MODE = "READ_WRITE_EXACT_DECLARED_OUTPUT_BIND_ONLY"
CONTRACT = WORKSPACE / "contracts/SUCCESSOR_V35_GOVERNANCE_BOUND_MOUNT_OUTPUT_IDENTITY_CONTRACT.json"
BINDING = WORKSPACE / "contracts/MOUNT_OUTPUT_IDENTITY_BINDING.json"
MOUNT_POLICY = WORKSPACE / "contracts/MOUNT_PROVENANCE_WRITE_CONTRACT.json"
ALLOWED_COMPONENTS = frozenset({
    "RUNNER", "PRIMARY_VALIDATOR", "INDEPENDENT_VALIDATOR", "FRESH_PREFLIGHT",
    "DEPENDENCY_CLOSURE", "STATIC_LOCK_PREPARATION", "STATIC_LOCK_VERIFICATION",
    "LOCKED_RUNTIME", "POST_VALIDATOR", "UNIT",
})
REQUIRED_CONSUMERS = frozenset({
    "runner", "primary_validator", "independent_validator", "fresh_preflight",
    "dependency_closure", "static_lock", "runtime_namespace", "post_validator",
})


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _load(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"JSON object required: {path}")
    return value


def mount_output_binding_fixture_verdict(
    binding: Mapping[str, Any],
    contract: Mapping[str, Any],
    policy: Mapping[str, Any],
    *,
    component: str,
) -> dict[str, Any]:
    host = str(HOST_OUTPUT)
    namespace = str(NAMESPACE_OUTPUT)
    authorized = policy.get("authorized_host_output_bind", {})
    checks = {
        "component_authorized": component in ALLOWED_COMPONENTS,
        "contract_identity_exact": contract.get("contract_identity") == "V35_GOVERNANCE_BOUND_MOUNT_OUTPUT_IDENTITY_CONTRACT_V1",
        "contract_governance_exact": contract.get("governance_identity") == GOVERNANCE_IDENTITY,
        "selection_rule_exact": contract.get("selection_rule") == "EXACT_GOVERNANCE_SUCCESSOR_DECISION_NO_VERSION_INFERENCE",
        "execution_identity_exact": binding.get("execution_identity") == EXECUTION_IDENTITY,
        "workspace_identity_exact": binding.get("workspace_identity") == WORKSPACE_IDENTITY,
        "logical_output_exact": binding.get("logical_runtime_output_identity") == LOGICAL_OUTPUT_IDENTITY,
        "workspace_root_exact": binding.get("canonical_workspace_root") == str(WORKSPACE),
        "host_output_exact": binding.get("host_output_path") == host,
        "namespace_output_exact": binding.get("namespace_output_path") == namespace,
        "mount_source_exact": binding.get("mount_source_path") == host == authorized.get("host_source"),
        "mount_destination_exact": binding.get("mount_destination_path") == namespace == authorized.get("sandbox_mount_point"),
        "mount_mode_exact": binding.get("mount_mode") == MOUNT_MODE and authorized.get("write_authority") == "EXACT_DECLARED_OUTPUT_BIND_ONLY",
        "governance_identity_exact": binding.get("governance_identity") == GOVERNANCE_IDENTITY,
        "governance_digest_exact": binding.get("governance_lock_sha256") == GOVERNANCE_LOCK_SHA256,
        "generation_exact": binding.get("binding_generation_identity") == GENERATION_IDENTITY == policy.get("binding_generation_identity"),
        "consumers_complete": set(binding.get("consumers", [])) == REQUIRED_CONSUMERS == set(contract.get("required_consumers", [])),
        "policy_execution_exact": policy.get("execution_identity") == EXECUTION_IDENTITY,
        "policy_logical_output_exact": policy.get("logical_runtime_output_identity") == LOGICAL_OUTPUT_IDENTITY,
        "policy_binding_source_exact": policy.get("mount_output_binding_source") == "contracts/MOUNT_OUTPUT_IDENTITY_BINDING.json",
    }
    return {
        "record_type": "V35_MOUNT_OUTPUT_IDENTITY_BINDING_VERDICT",
        "component": component,
        "binding_generation_identity": binding.get("binding_generation_identity"),
        "checks": checks,
        "status": "PASS" if all(checks.values()) else "FAIL_CLOSED_BEFORE_STATIC_LOCK_AND_ATTEMPT",
    }


def mount_output_binding_precheck(component: str) -> dict[str, Any]:
    required = (CONTRACT, BINDING, MOUNT_POLICY)
    if component not in ALLOWED_COMPONENTS or not all(path.is_file() and not path.is_symlink() for path in required):
        return {"record_type": "V35_MOUNT_OUTPUT_IDENTITY_PRECHECK", "component": component, "status": "FAIL_CLOSED_BEFORE_STATIC_LOCK_AND_ATTEMPT", "reason": "COMPONENT_OR_REQUIRED_ARTIFACT_INVALID"}
    result = mount_output_binding_fixture_verdict(_load(BINDING), _load(CONTRACT), _load(MOUNT_POLICY), component=component)
    result.update({"record_type": "V35_MOUNT_OUTPUT_IDENTITY_PRECHECK", "binding_sha256": _digest(BINDING), "contract_sha256": _digest(CONTRACT), "mount_policy_sha256": _digest(MOUNT_POLICY)})
    return result


def stale_mount_literal_precheck() -> dict[str, Any]:
    paths = [
        WORKSPACE / "contracts/MOUNT_OUTPUT_IDENTITY_BINDING.json",
        WORKSPACE / "contracts/MOUNT_PROVENANCE_WRITE_CONTRACT.json",
        WORKSPACE / "contracts/SUCCESSOR_V35_GOVERNANCE_BOUND_MOUNT_OUTPUT_IDENTITY_CONTRACT.json",
        WORKSPACE / "src/invocation_v35.py",
        WORKSPACE / "src/runner_v35.py",
        WORKSPACE / "preflight.py",
        WORKSPACE / "prepare_static_lock.py",
        WORKSPACE / "verify_static_lock.py",
        WORKSPACE / "validators/post_validate.py",
    ]
    surfaces = {path.relative_to(WORKSPACE).as_posix(): path.read_text(encoding="utf-8") for path in paths}
    result = stale_mount_literal_fixture_verdict(surfaces)
    result["record_type"] = "V35_STALE_MOUNT_LITERAL_PRECHECK"
    return result


def stale_mount_literal_fixture_verdict(surfaces: Mapping[str, str]) -> dict[str, Any]:
    stale = ("/run/nobcoder-first-worker-v" + "23/output", "/run/nobcoder-first-worker-v" + "25/output")
    findings = [
        {"path": name, "literal": literal}
        for name, source in surfaces.items()
        for literal in stale
        if literal in source
    ]
    return {
        "record_type": "V35_STALE_MOUNT_LITERAL_FIXTURE_VERDICT",
        "findings": findings,
        "status": "PASS" if not findings else "FAIL_CLOSED_BEFORE_STATIC_LOCK_AND_ATTEMPT",
    }
