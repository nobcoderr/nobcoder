"""Typed, governance-bound historical successor-decision registry for V35."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Mapping

from workspace_boundary_v35 import authorize_read


WORKSPACE = Path("/home/nobcoder/v0.3-first-real-security-worker-invocation-v35-20261103")
REGISTRY = WORKSPACE / "contracts/TYPED_HISTORICAL_DECISION_REGISTRY.json"
CONTRACT = WORKSPACE / "contracts/TYPED_HISTORICAL_DECISION_REGISTRY_CONTRACT.json"
REQUIRED_FIELDS = frozenset({
    "logical_decision_identity", "physical_record_type_presence",
    "physical_record_type", "artifact_role", "governance_owner",
    "subject_identity", "object_identity", "relation_semantics",
    "canonical_locator", "artifact_sha256", "artifact_size",
    "governance_identity", "governance_lock_sha256", "mapping_authority",
})
AUTHORIZED_MIRRORS = {
    "logical_decision_identity": "authorized_logical_decision_identity",
    "physical_record_type_presence": "authorized_physical_record_type_presence",
    "physical_record_type": "authorized_physical_record_type",
    "artifact_role": "authorized_artifact_role",
    "governance_owner": "authorized_governance_owner",
    "subject_identity": "authorized_subject_identity",
    "object_identity": "authorized_object_identity",
    "relation_semantics": "authorized_relation_semantics",
    "artifact_sha256": "authorized_artifact_sha256",
    "governance_identity": "authorized_governance_identity",
    "governance_lock_sha256": "authorized_governance_lock_sha256",
}


class HistoricalDecisionRelationError(RuntimeError):
    """Raised when a typed historical relation cannot be authenticated."""


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _typed_mapping_errors(row: Mapping[str, Any]) -> list[str]:
    errors: list[str] = []
    if not REQUIRED_FIELDS.issubset(row):
        errors.append("REQUIRED_BINDING_FIELD_MISSING")
    if row.get("mapping_authority") != "EXACT_GOVERNANCE_BOUND_TYPED_MAPPING":
        errors.append("MAPPING_AUTHORITY_MISMATCH")
    if row.get("logical_to_physical_rule") != "EXPLICIT_MAPPING_NOT_STRING_EQUALITY":
        errors.append("LOGICAL_TO_PHYSICAL_RULE_MISMATCH")
    for field, mirror in AUTHORIZED_MIRRORS.items():
        if field not in row or mirror not in row or row.get(field) != row.get(mirror):
            errors.append(f"AUTHORIZED_MAPPING_MISMATCH:{field}")
    presence = row.get("physical_record_type_presence")
    physical = row.get("physical_record_type")
    if presence == "ABSENT":
        if physical is not None:
            errors.append("ABSENT_RECORD_TYPE_MUST_BE_NULL")
    elif presence == "PRESENT":
        if not isinstance(physical, str) or not physical:
            errors.append("PRESENT_RECORD_TYPE_MUST_BE_NONEMPTY_STRING")
    else:
        errors.append("PHYSICAL_RECORD_TYPE_PRESENCE_INVALID")
    if row.get("artifact_role") != "TERMINAL_SUCCESSOR_DECISION":
        errors.append("ARTIFACT_ROLE_MISMATCH")
    for field in ("artifact_sha256", "governance_lock_sha256"):
        value = row.get(field)
        if not isinstance(value, str) or len(value) != 64:
            errors.append(f"{field.upper()}_INVALID")
    if not isinstance(row.get("artifact_size"), int) or int(row.get("artifact_size", 0)) <= 0:
        errors.append("ARTIFACT_SIZE_INVALID")
    return errors


def relation_fixture_verdict(rows: list[Mapping[str, Any]], logical_identity: str) -> dict[str, Any]:
    candidates = [dict(row) for row in rows if row.get("logical_decision_identity") == logical_identity]
    if len(candidates) != 1:
        return {
            "status": "FAIL_CLOSED",
            "errors": ["RELATION_MISSING_OR_AMBIGUOUS"],
            "candidate_count": len(candidates),
        }
    row = candidates[0]
    errors = _typed_mapping_errors(row)
    return {
        "status": "PASS" if not errors else "FAIL_CLOSED",
        "errors": errors,
        "candidate_count": 1,
        "binding": row,
    }


def _load_registry() -> tuple[dict[str, Any], list[Mapping[str, Any]]]:
    contract = json.loads(CONTRACT.read_text(encoding="utf-8"))
    registry = json.loads(REGISTRY.read_text(encoding="utf-8"))
    if contract.get("record_type") != "V35_TYPED_HISTORICAL_DECISION_REGISTRY_CONTRACT":
        raise HistoricalDecisionRelationError("TYPED_REGISTRY_CONTRACT_IDENTITY_MISMATCH")
    if contract.get("logical_to_physical_rule") != "EXPLICIT_MAPPING_NOT_STRING_EQUALITY":
        raise HistoricalDecisionRelationError("TYPED_REGISTRY_CONTRACT_RULE_MISMATCH")
    rows = registry.get("mappings")
    if not isinstance(rows, list) or registry.get("mapping_count") != len(rows):
        raise HistoricalDecisionRelationError("TYPED_REGISTRY_STRUCTURE_INVALID")
    identities = [row.get("logical_decision_identity") for row in rows if isinstance(row, Mapping)]
    if len(identities) != len(rows) or len(identities) != len(set(identities)):
        raise HistoricalDecisionRelationError("TYPED_REGISTRY_IDENTITY_AMBIGUITY")
    return registry, rows


def resolve_historical_decision_relation(logical_identity: str) -> dict[str, Any]:
    _, rows = _load_registry()
    verdict = relation_fixture_verdict(rows, logical_identity)
    if verdict["status"] != "PASS":
        raise HistoricalDecisionRelationError(",".join(verdict["errors"]))
    binding = verdict["binding"]
    resolved = authorize_read(
        Path(binding["canonical_locator"]),
        operation_identity=f"TYPED_HISTORICAL_DECISION_READ:{logical_identity}",
    )
    raw = resolved.read_bytes()
    if len(raw) != binding["artifact_size"]:
        raise HistoricalDecisionRelationError("ARTIFACT_SIZE_MISMATCH")
    if _sha256(raw) != binding["artifact_sha256"]:
        raise HistoricalDecisionRelationError("ARTIFACT_DIGEST_MISMATCH")
    try:
        artifact = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise HistoricalDecisionRelationError("DECISION_ARTIFACT_NOT_JSON") from exc

    present = "record_type" in artifact
    expected_presence = binding["physical_record_type_presence"]
    if present != (expected_presence == "PRESENT"):
        raise HistoricalDecisionRelationError("PHYSICAL_RECORD_TYPE_PRESENCE_MISMATCH")
    if present and artifact.get("record_type") != binding["physical_record_type"]:
        raise HistoricalDecisionRelationError("PHYSICAL_RECORD_TYPE_MISMATCH")
    if artifact.get("decision") != binding["relation_semantics"]:
        raise HistoricalDecisionRelationError("RELATION_SEMANTICS_MISMATCH")

    governance_lock = authorize_read(
        resolved.parent / "GOVERNANCE_LOCK.json",
        operation_identity=f"TYPED_HISTORICAL_DECISION_AUTHORITY_READ:{logical_identity}",
    )
    lock_raw = governance_lock.read_bytes()
    if _sha256(lock_raw) != binding["governance_lock_sha256"]:
        raise HistoricalDecisionRelationError("GOVERNANCE_LOCK_DIGEST_MISMATCH")
    governance = json.loads(lock_raw)
    if governance.get("governance_identity") != binding["governance_identity"]:
        raise HistoricalDecisionRelationError("GOVERNANCE_IDENTITY_MISMATCH")
    return {
        "status": "PASS",
        "logical_decision_identity": logical_identity,
        "physical_record_type_presence": expected_presence,
        "physical_record_type": binding["physical_record_type"],
        "binding": binding,
        "artifact": artifact,
        "resolved_origin": str(resolved),
        "resolved_sha256": _sha256(raw),
        "resolved_size": len(raw),
    }


def historical_decision_relation_precheck() -> dict[str, Any]:
    try:
        _, rows = _load_registry()
    except (HistoricalDecisionRelationError, OSError, ValueError) as exc:
        return {"status": "FAIL_CLOSED", "errors": [{"identity": "REGISTRY", "reason": str(exc)}]}
    results: list[dict[str, Any]] = []
    errors: list[dict[str, str]] = []
    for row in rows:
        identity = str(row.get("logical_decision_identity", ""))
        try:
            results.append(resolve_historical_decision_relation(identity))
        except (HistoricalDecisionRelationError, OSError, ValueError) as exc:
            errors.append({"identity": identity, "reason": str(exc)})
    return {
        "record_type": "V35_TYPED_HISTORICAL_DECISION_REGISTRY_PRECHECK",
        "status": "PASS" if not errors and len(results) == len(rows) else "FAIL_CLOSED",
        "selection_method": "EXACT_GOVERNANCE_BOUND_TYPED_MAPPING",
        "relation_count": len(results),
        "results": results,
        "errors": errors,
    }
