"""Typed semantic preflight requirement registry for V35."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Iterable, Mapping


WORKSPACE = Path("/home/nobcoder/v0.3-first-real-security-worker-invocation-v35-20261103")
EXECUTION_IDENTITY = "V0_3_FIRST_REAL_SECURITY_WORKER_INVOCATION_V35"
GENERATION_IDENTITY = "V35_CURRENT_GOVERNANCE_BOUND_TYPED_PREFLIGHT_BINDING_GENERATION_0001"
GOVERNANCE_IDENTITY = "V0_3_FIRST_REAL_SECURITY_WORKER_INVOCATION_V34_PRELOCK_RESULTS_DIRECTORY_AND_FIXTURE_PROBE_PATH_LIFECYCLE_DEFECT_UNIT_EXECUTION_ERRATUM_AND_SUCCESSOR_DECISION_GOVERNANCE_ONLY"
GOVERNANCE_LOCK_SHA256 = "d2263268f61b9ddde99a0b60f4b43a26df1586e0c577ba2ca98c07b64c21f811"
CONTRACT = WORKSPACE / "contracts/TYPED_PREFLIGHT_REQUIREMENT_REGISTRY_CONTRACT.json"
REGISTRY = WORKSPACE / "contracts/TYPED_PREFLIGHT_REQUIREMENT_REGISTRY.json"
EXPECTED_EVALUATORS = frozenset({
    "V35_FRESH_PREFLIGHT_TYPED_REQUIREMENT_EVALUATOR_V1",
    "V35_MOUNT_OUTPUT_TYPED_REQUIREMENT_EVALUATOR_V1",
    "V35_INDEPENDENT_MOUNT_DESTINATION_EVALUATOR_V1",
})
ALLOWED_COMPONENTS = frozenset({"UNIT", "PRIMARY_VALIDATOR", "INDEPENDENT_VALIDATOR", "FRESH_PREFLIGHT", "DEPENDENCY_CLOSURE", "STATIC_LOCK_PREPARATION", "STATIC_LOCK_VERIFICATION", "LOCKED_RUNTIME"})


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _load(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"JSON object required: {path}")
    return value


def typed_preflight_registry_fixture_verdict(
    contract: Mapping[str, Any],
    registry: Mapping[str, Any],
    *,
    component: str,
) -> dict[str, Any]:
    rows = registry.get("requirements", [])
    required_fields = set(contract.get("required_fields", []))
    required_identities = set(contract.get("required_logical_requirements", []))
    identities = [row.get("logical_requirement_identity") for row in rows if isinstance(row, Mapping)]
    row_checks = []
    for row in rows if isinstance(rows, list) else []:
        owner = WORKSPACE / str(row.get("owning_contract_path", ""))
        artifact = WORKSPACE / str(row.get("artifact_path", ""))
        checks = {
            "required_fields": required_fields <= set(row),
            "generation_exact": row.get("binding_generation_identity") == GENERATION_IDENTITY,
            "governance_exact": row.get("governance_identity") == GOVERNANCE_IDENTITY and row.get("governance_lock_sha256") == GOVERNANCE_LOCK_SHA256,
            "evaluator_exact": row.get("evaluator_identity") in EXPECTED_EVALUATORS,
            "semantic_identity_typed": isinstance(row.get("semantic_predicate_identity"), str) and row.get("semantic_predicate_identity", "").startswith("V35_SEMANTIC_"),
            "verdict_semantics_typed": isinstance(row.get("expected_verdict_semantics"), str) and bool(row.get("expected_verdict_semantics")),
            "owner_regular": owner.is_file() and not owner.is_symlink(),
            "owner_digest_exact": owner.is_file() and not owner.is_symlink() and _digest(owner) == row.get("owning_contract_sha256"),
            "artifact_regular": artifact.is_file() and not artifact.is_symlink(),
            "artifact_digest_exact": artifact.is_file() and not artifact.is_symlink() and _digest(artifact) == row.get("artifact_sha256"),
            "artifact_generation_exact": row.get("artifact_generation_identity") == GENERATION_IDENTITY,
            "artifact_identity_exact": row.get("artifact_identity") == row.get("owning_contract_identity"),
            "artifact_owner_exact": row.get("artifact_owner_identity") == "V35",
            "owner_governance_digest_exact": row.get("owner_governance_digest") == GOVERNANCE_LOCK_SHA256,
        }
        row_checks.append({"logical_requirement_identity": row.get("logical_requirement_identity"), "checks": checks, "status": "PASS" if all(checks.values()) else "FAIL_CLOSED"})
    checks = {
        "component_authorized": component in ALLOWED_COMPONENTS,
        "contract_identity_exact": contract.get("contract_identity") == "V35_TYPED_PREFLIGHT_REQUIREMENT_REGISTRY_CONTRACT_V1",
        "contract_generation_exact": contract.get("binding_generation_identity") == GENERATION_IDENTITY,
        "contract_governance_exact": contract.get("governance_identity") == GOVERNANCE_IDENTITY and contract.get("governance_lock_sha256") == GOVERNANCE_LOCK_SHA256,
        "no_text_token_authority": contract.get("textual_token_search_as_authority") == "PROHIBITED" and contract.get("logical_to_semantic_rule") == "EXPLICIT_GOVERNANCE_BOUND_TYPED_MAPPING_NOT_TEXT_TOKEN_SEARCH",
        "obsolete_token_absence_not_failure": contract.get("obsolete_token_absence") == "NOT_A_FAILURE_WHEN_CURRENT_TYPED_REQUIREMENT_PASSES",
        "registry_identity_exact": registry.get("record_type") == "V35_TYPED_PREFLIGHT_REQUIREMENT_REGISTRY",
        "registry_generation_exact": registry.get("binding_generation_identity") == GENERATION_IDENTITY,
        "registry_governance_exact": registry.get("governance_identity") == GOVERNANCE_IDENTITY and registry.get("governance_lock_sha256") == GOVERNANCE_LOCK_SHA256,
        "requirement_count_exact": registry.get("requirement_count") == len(rows),
        "logical_set_exact": set(identities) == required_identities and len(identities) == len(set(identities)),
        "rows_pass": bool(row_checks) and all(row.get("status") == "PASS" for row in row_checks),
    }
    return {"record_type": "V35_TYPED_PREFLIGHT_REQUIREMENT_REGISTRY_VERDICT", "component": component, "checks": checks, "row_checks": row_checks, "status": "PASS" if all(checks.values()) else "FAIL_CLOSED_BEFORE_STATIC_LOCK_AND_ATTEMPT"}


def typed_preflight_requirement_precheck(component: str) -> dict[str, Any]:
    if component not in ALLOWED_COMPONENTS or not all(path.is_file() and not path.is_symlink() for path in (CONTRACT, REGISTRY)):
        return {"record_type": "V35_TYPED_PREFLIGHT_REQUIREMENT_PRECHECK", "component": component, "status": "FAIL_CLOSED_BEFORE_STATIC_LOCK_AND_ATTEMPT", "reason": "COMPONENT_OR_REQUIRED_ARTIFACT_INVALID"}
    result = typed_preflight_registry_fixture_verdict(_load(CONTRACT), _load(REGISTRY), component=component)
    result.update({"record_type": "V35_TYPED_PREFLIGHT_REQUIREMENT_PRECHECK", "contract_sha256": _digest(CONTRACT), "registry_sha256": _digest(REGISTRY)})
    return result
