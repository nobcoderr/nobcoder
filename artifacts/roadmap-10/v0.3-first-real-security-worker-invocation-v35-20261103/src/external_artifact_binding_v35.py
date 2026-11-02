"""Strict governance-bound resolution of V26 external predecessor artifacts."""

from __future__ import annotations

import hashlib
import json
import os
import stat
from pathlib import Path
from typing import Any


ROOT = Path("/home/nobcoder/v0.3-first-real-security-worker-invocation-v35-20261103")
BINDING_PATH = ROOT / "contracts/CANONICAL_EXTERNAL_PREDECESSOR_ARTIFACT_BINDING.json"
CONTRACT_PATH = ROOT / "contracts/CANONICAL_EXTERNAL_PREDECESSOR_ARTIFACT_BINDING_CONTRACT.json"
EXECUTION_IDENTITY = "V0_3_FIRST_REAL_SECURITY_WORKER_INVOCATION_V35"
GENERATION_IDENTITY = "V35_CURRENT_GOVERNANCE_BOUND_TYPED_PREFLIGHT_BINDING_GENERATION_0001"
CANONICAL_PREDECESSOR = "V0_3_FIRST_REAL_SECURITY_WORKER_INVOCATION_V18"
ARTIFACT_OWNER = "V0_3_FIRST_REAL_SECURITY_WORKER_INVOCATION_V17"
RELATIONSHIP = "V17_FROZEN_HISTORY_REQUIRED_TO_VERIFY_CANONICAL_PREDECESSOR_V18"
ALLOWED_COMPONENTS = frozenset(
    {
        "BUILDER",
        "PRIMARY_VALIDATOR",
        "INDEPENDENT_VALIDATOR",
        "FRESH_PREFLIGHT",
        "DEPENDENCY_CLOSURE",
        "STATIC_LOCK_PREPARATION",
        "STATIC_LOCK_VERIFICATION",
        "LOCKED_RUNTIME",
    }
)


class ExternalArtifactBindingError(RuntimeError):
    """A fail-closed external-artifact binding failure."""


def _load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ExternalArtifactBindingError(f"cannot load exact JSON artifact {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ExternalArtifactBindingError(f"JSON artifact is not an object: {path}")
    return value


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _exact_regular_file(locator: str, expected_sha256: str, expected_size: int | None) -> tuple[Path, bytes]:
    path = Path(locator)
    if not path.is_absolute():
        raise ExternalArtifactBindingError("canonical locator is not absolute")
    try:
        before = path.lstat()
    except FileNotFoundError as exc:
        raise ExternalArtifactBindingError(f"canonical artifact is missing: {path}") from exc
    if stat.S_ISLNK(before.st_mode):
        raise ExternalArtifactBindingError(f"canonical artifact is a symlink: {path}")
    if not stat.S_ISREG(before.st_mode):
        raise ExternalArtifactBindingError(f"canonical artifact is not a regular file: {path}")
    resolved = path.resolve(strict=True)
    if resolved != path:
        raise ExternalArtifactBindingError(f"canonical locator does not equal its resolved path: {path}")
    first = path.read_bytes()
    if expected_size is not None and len(first) != expected_size:
        raise ExternalArtifactBindingError(f"size mismatch for {path}")
    if _sha256_bytes(first) != expected_sha256:
        raise ExternalArtifactBindingError(f"digest mismatch for {path}")
    second = path.read_bytes()
    after = path.lstat()
    if first != second or _sha256_bytes(second) != expected_sha256:
        raise ExternalArtifactBindingError(f"reread digest mismatch for {path}")
    if (before.st_dev, before.st_ino, before.st_size) != (after.st_dev, after.st_ino, after.st_size):
        raise ExternalArtifactBindingError(f"artifact identity changed during verification: {path}")
    return path, second


def _expected_contract_row() -> dict[str, Any]:
    contract = _load_json(CONTRACT_PATH)
    if contract.get("contract_identity") != "V35_CANONICAL_EXTERNAL_PREDECESSOR_ARTIFACT_BINDING_V1":
        raise ExternalArtifactBindingError("wrong external-artifact contract identity")
    if contract.get("canonical_predecessor_identity") != CANONICAL_PREDECESSOR:
        raise ExternalArtifactBindingError("wrong canonical predecessor in external-artifact contract")
    row = contract.get("canonical_binding_for_known_artifact")
    if not isinstance(row, dict):
        raise ExternalArtifactBindingError("missing normative known-artifact binding")
    return row


def external_artifact_candidate_verdict(
    candidate: dict[str, Any],
    *,
    candidate_count: int = 1,
    resolution_method: str = "EXACT_GOVERNANCE_BOUND_LOCATOR",
    artifact_form: str = "ORIGINAL_REGULAR_FILE",
) -> dict[str, Any]:
    """Pure regression oracle for prohibited resolution/binding substitutions."""
    normative = _expected_contract_row()
    checks = {
        "single_candidate": candidate_count == 1,
        "exact_normative_fields": all(candidate.get(key) == value for key, value in normative.items()),
        "exact_locator_method": resolution_method == "EXACT_GOVERNANCE_BOUND_LOCATOR",
        "original_regular_file": artifact_form == "ORIGINAL_REGULAR_FILE",
        "owner_distinct_but_related": candidate.get("owning_predecessor_identity") == ARTIFACT_OWNER,
        "canonical_predecessor_relation": candidate.get("relationship_to_canonical_predecessor") == RELATIONSHIP,
    }
    return {
        "status": "PASS" if all(checks.values()) else "FAIL_CLOSED",
        "checks": checks,
    }


def verify_external_predecessor_artifacts(component: str) -> dict[str, Any]:
    """Resolve and attest every external artifact using only exact frozen bindings."""
    if component not in ALLOWED_COMPONENTS:
        raise ExternalArtifactBindingError(f"unauthorized resolver component: {component}")
    binding = _load_json(BINDING_PATH)
    if binding.get("execution_identity") != EXECUTION_IDENTITY:
        raise ExternalArtifactBindingError("binding execution identity mismatch")
    if binding.get("generation_identity") != GENERATION_IDENTITY:
        raise ExternalArtifactBindingError("binding generation mismatch")
    if binding.get("canonical_predecessor_identity") != CANONICAL_PREDECESSOR:
        raise ExternalArtifactBindingError("binding canonical predecessor mismatch")
    rows = binding.get("external_artifacts")
    if not isinstance(rows, list) or len(rows) != 1 or not isinstance(rows[0], dict):
        raise ExternalArtifactBindingError("exactly one unambiguous external artifact is required")
    row = rows[0]
    normative = _expected_contract_row()
    for key, expected in normative.items():
        if row.get(key) != expected:
            raise ExternalArtifactBindingError(f"binding differs from frozen contract for {key}")
    if row.get("owning_predecessor_identity") != ARTIFACT_OWNER:
        raise ExternalArtifactBindingError("external artifact owner mismatch")
    if row.get("relationship_to_canonical_predecessor") != RELATIONSHIP:
        raise ExternalArtifactBindingError("external artifact relationship mismatch")

    artifact_path, artifact_bytes = _exact_regular_file(
        str(row["canonical_locator"]), str(row["expected_sha256"]), int(row["expected_size"])
    )
    artifact = json.loads(artifact_bytes.decode("utf-8"))
    if artifact.get("execution_identity") != ARTIFACT_OWNER:
        raise ExternalArtifactBindingError("artifact content owner mismatch")
    if artifact.get("disposition") != "FAIL_CLOSED_PRELOCK_TERMINAL_NO_RETRY_REFERENCE_ONLY":
        raise ExternalArtifactBindingError("artifact content role/disposition mismatch")
    if artifact.get("static_lock") != "NOT_ISSUED":
        raise ExternalArtifactBindingError("unexpected V17 frozen-artifact state")

    lock_path, lock_bytes = _exact_regular_file(
        str(row["authorizing_governance_lock_locator"]),
        str(row["authorizing_governance_lock_sha256"]),
        None,
    )
    lock = json.loads(lock_bytes.decode("utf-8"))
    if lock.get("governance_identity") != row.get("authorizing_governance_identity"):
        raise ExternalArtifactBindingError("authorizing governance identity mismatch")
    if lock.get("status") != "PASS_LOCKED_GOVERNANCE_ONLY":
        raise ExternalArtifactBindingError("authorizing governance is not PASS_LOCKED_GOVERNANCE_ONLY")

    decision_path, decision_bytes = _exact_regular_file(
        str(row["authorizing_successor_decision_locator"]),
        str(row["authorizing_successor_decision_sha256"]),
        None,
    )
    decision = json.loads(decision_bytes.decode("utf-8"))
    if decision.get("decision") != "TERMINALIZE_V17_AND_AUTHORIZE_DISTINCT_V18_CONDITIONALLY":
        raise ExternalArtifactBindingError("successor decision does not authorize V18")
    if decision.get("v17") != artifact.get("disposition"):
        raise ExternalArtifactBindingError("V17 artifact disposition is not bound to successor decision")
    if decision.get("v18") != "CONDITIONALLY_AUTHORIZED_NOT_CREATED_NOT_EXECUTED":
        raise ExternalArtifactBindingError("successor decision V18 state mismatch")

    return {
        "record_type": "V35_EXTERNAL_PREDECESSOR_ARTIFACT_RESOLUTION_ATTESTATION",
        "status": "PASS",
        "component": component,
        "execution_identity": EXECUTION_IDENTITY,
        "canonical_predecessor_identity": CANONICAL_PREDECESSOR,
        "binding_sha256": _sha256_bytes(BINDING_PATH.read_bytes()),
        "contract_sha256": _sha256_bytes(CONTRACT_PATH.read_bytes()),
        "resolved_artifacts": [
            {
                "logical_artifact_identity": row["logical_artifact_identity"],
                "artifact_owner_identity": row["owning_predecessor_identity"],
                "artifact_role": row["artifact_role"],
                "canonical_locator": os.fspath(artifact_path),
                "sha256": row["expected_sha256"],
                "size": row["expected_size"],
                "relationship_to_canonical_predecessor": row["relationship_to_canonical_predecessor"],
                "authorizing_governance_identity": row["authorizing_governance_identity"],
                "authorizing_governance_lock_locator": os.fspath(lock_path),
                "authorizing_governance_lock_sha256": row["authorizing_governance_lock_sha256"],
                "authorizing_successor_decision_locator": os.fspath(decision_path),
                "authorizing_successor_decision_sha256": row["authorizing_successor_decision_sha256"],
            }
        ],
        "resolution_mode": "EXACT_GOVERNANCE_BOUND_LOCATORS_ONLY_NO_FALLBACK",
        "reread_rehash": "PASS",
    }


def external_predecessor_artifact_precheck(component: str) -> dict[str, Any]:
    """Fail-closed precheck wrapper with an explicit typed result."""
    try:
        return verify_external_predecessor_artifacts(component)
    except ExternalArtifactBindingError as exc:
        return {
            "record_type": "V35_EXTERNAL_PREDECESSOR_ARTIFACT_RESOLUTION_ATTESTATION",
            "status": "FAIL_CLOSED",
            "component": component,
            "execution_identity": EXECUTION_IDENTITY,
            "canonical_predecessor_identity": CANONICAL_PREDECESSOR,
            "failure_reason": str(exc),
        }
