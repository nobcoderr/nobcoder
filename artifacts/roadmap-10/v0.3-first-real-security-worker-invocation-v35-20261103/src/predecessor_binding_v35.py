"""Canonical governance-bound V18 predecessor verification for V35."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path, PurePosixPath
from typing import Any

WORKSPACE = Path("/home/nobcoder/v0.3-first-real-security-worker-invocation-v35-20261103")
V18_WORKSPACE = Path("/home/nobcoder/v0.3-first-real-security-worker-invocation-v18-20261023")
V18_GOVERNANCE = Path("/home/nobcoder/codex-security-harness-eval/governance/v0.3-first-real-security-worker-invocation-v18-locked-runner-canonicalization-precheck-import-binding-defect-post-lock-pre-attempt-erratum-and-successor-decision-governance-v1-20261025")
V35_GOVERNANCE = Path("/home/nobcoder/codex-security-harness-eval/governance/v0.3-first-real-security-worker-invocation-v34-prelock-results-directory-and-fixture-probe-path-lifecycle-defect-unit-execution-erratum-and-successor-decision-governance-only-v1-20261103")
EXECUTION_IDENTITY = "V0_3_FIRST_REAL_SECURITY_WORKER_INVOCATION_V35"
GENERATION_IDENTITY = "V35_CURRENT_GOVERNANCE_BOUND_TYPED_PREFLIGHT_BINDING_GENERATION_0001"
EXPECTED_PREDECESSOR_IDENTITY = "V0_3_FIRST_REAL_SECURITY_WORKER_INVOCATION_V18"
EXPECTED_V18_TREE_ROOT = "c92f0bd0d7ea111d9bfd6d3d4e612e5b1cd763d70c69f47fef6a2907c0be0f4d"
EXPECTED_V18_MEMBER_COUNT = 164
EXPECTED_V18_STATIC_LOCK_SHA256 = "7b59bb4e753c0aef7f05a3fea61484b21bfc8fe30b5b255e47d1ce393d964c12"
EXPECTED_V18_GOVERNANCE_LOCK_SHA256 = "f371001972791a56e4d9b7fa92c7b0870da1b126bb16ee5f7f67b6c7d94c51b0"
EXPECTED_V18_DECISION_SHA256 = "96dbee1a08f7f1653000ef2a174b5b5a35f403d05aa3511abd0e4b5448e9779e"
EXPECTED_V35_GOVERNANCE_LOCK_SHA256 = "d2263268f61b9ddde99a0b60f4b43a26df1586e0c577ba2ca98c07b64c21f811"
EXPECTED_V35_DECISION_SHA256 = "e9672bcddb685c92f3230531eb4c131f41264f54e2ee4c6afa9f9f633bcb21b6"
ALLOWED_COMPONENTS = frozenset({"BUILDER", "UNIT", "PRIMARY_VALIDATOR", "INDEPENDENT_VALIDATOR", "FRESH_PREFLIGHT", "DEPENDENCY_CLOSURE", "STATIC_LOCK_PREPARATION", "STATIC_LOCK_VERIFICATION", "LOCKED_RUNTIME"})


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _load(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"expected JSON object: {path}")
    return value


def _component_key(relative: str) -> tuple[bytes, ...]:
    return tuple(part.encode("utf-8") for part in PurePosixPath(relative).parts)


def _normative_tree(root: Path) -> tuple[str, int]:
    rows: list[tuple[tuple[bytes, ...], str, str]] = []
    for path in root.rglob("*"):
        if path.is_file():
            relative = path.relative_to(root).as_posix()
            rows.append((_component_key(relative), relative, _digest(path)))
    rows.sort(key=lambda row: row[0])
    stream = b"".join(relative.encode() + b"\0" + digest.encode("ascii") + b"\n" for _key, relative, digest in rows)
    return hashlib.sha256(stream).hexdigest(), len(rows)


def canonical_predecessor_binding_verdict(*, component: str, authority_lock_sha256: str | None, authority_decision_sha256: str | None, explicit_predecessor_identity: str | None, candidate_identities: list[str], workspace_tree_sha256: str | None, static_lock_sha256: str | None, permit_inference: bool = False) -> dict[str, Any]:
    checks = {
        "component_authorized": component in ALLOWED_COMPONENTS,
        "authority_lock_exact": authority_lock_sha256 == EXPECTED_V35_GOVERNANCE_LOCK_SHA256,
        "authority_decision_exact": authority_decision_sha256 == EXPECTED_V35_DECISION_SHA256,
        "explicit_identity_exact": explicit_predecessor_identity == EXPECTED_PREDECESSOR_IDENTITY,
        "single_exact_candidate": candidate_identities == [EXPECTED_PREDECESSOR_IDENTITY],
        "workspace_tree_exact": workspace_tree_sha256 == EXPECTED_V18_TREE_ROOT,
        "static_lock_exact": static_lock_sha256 == EXPECTED_V18_STATIC_LOCK_SHA256,
        "inference_prohibited": permit_inference is False,
    }
    return {"record_type": "V35_CANONICAL_PREDECESSOR_BINDING_VERDICT", "component": component, "predecessor_identity": explicit_predecessor_identity, "checks": checks, "status": "PASS" if all(checks.values()) else "FAIL_CLOSED_BEFORE_STATIC_LOCK_AND_ATTEMPT"}


def canonical_predecessor_binding_precheck(component: str) -> dict[str, Any]:
    paths = {
        "binding": WORKSPACE / "contracts/CANONICAL_PREDECESSOR_BINDING.json",
        "contract": WORKSPACE / "contracts/CANONICAL_PREDECESSOR_BINDING_CONTRACT.json",
        "local_lock": WORKSPACE / "contracts/V34_TO_V35_GOVERNANCE_LOCK.json",
        "local_decision": WORKSPACE / "contracts/V34_TERMINAL_AND_V35_SUCCESSOR_DECISION.json",
        "external_lock": V35_GOVERNANCE / "GOVERNANCE_LOCK.json",
        "external_decision": V35_GOVERNANCE / "V34_TERMINAL_AND_V35_SUCCESSOR_DECISION.json",
        "v18_governance_lock": V18_GOVERNANCE / "GOVERNANCE_LOCK.json",
        "v18_decision": V18_GOVERNANCE / "V18_TERMINAL_AND_V19_SUCCESSOR_DECISION.json",
        "v18_static_lock": V18_WORKSPACE / "STATIC_EXECUTION_LOCK.json",
    }
    if component not in ALLOWED_COMPONENTS or not all(path.is_file() and not path.is_symlink() for path in paths.values()):
        return {"record_type": "V35_CANONICAL_PREDECESSOR_BINDING_RESULT", "component": component, "status": "FAIL_CLOSED_BEFORE_STATIC_LOCK_AND_ATTEMPT", "reason": "COMPONENT_OR_REQUIRED_ARTIFACT_INVALID"}
    binding = _load(paths["binding"])
    contract = _load(paths["contract"])
    decision = _load(paths["external_decision"])
    lock = _load(paths["external_lock"])
    v18_lock = _load(paths["v18_static_lock"])
    predecessor = binding.get("governance_authorized_predecessor", {})
    authority = binding.get("v35_successor_authority", {})
    first_root, first_count = _normative_tree(V18_WORKSPACE)
    second_root, second_count = _normative_tree(V18_WORKSPACE)
    verdict = canonical_predecessor_binding_verdict(component=component, authority_lock_sha256=_digest(paths["external_lock"]), authority_decision_sha256=_digest(paths["external_decision"]), explicit_predecessor_identity=predecessor.get("execution_identity"), candidate_identities=[predecessor.get("execution_identity")], workspace_tree_sha256=first_root, static_lock_sha256=_digest(paths["v18_static_lock"]))
    checks = {
        "binding_identity_exact": binding.get("binding_identity") == "V35_CANONICAL_GOVERNANCE_BOUND_PREDECESSOR_BINDING_V1",
        "execution_identity_exact": binding.get("execution_identity") == EXECUTION_IDENTITY,
        "generation_exact": binding.get("generation_identity") == GENERATION_IDENTITY,
        "contract_identity_exact": contract.get("contract_identity") == "V35_CANONICAL_PREDECESSOR_BINDING_V1",
        "contract_generation_exact": contract.get("generation_identity") == GENERATION_IDENTITY,
        "local_external_lock_equal": _digest(paths["local_lock"]) == _digest(paths["external_lock"]) == EXPECTED_V35_GOVERNANCE_LOCK_SHA256,
        "local_external_decision_equal": _digest(paths["local_decision"]) == _digest(paths["external_decision"]) == EXPECTED_V35_DECISION_SHA256,
        "successor_authority_exact": authority.get("governance_lock_sha256") == EXPECTED_V35_GOVERNANCE_LOCK_SHA256 and authority.get("successor_decision_sha256") == EXPECTED_V35_DECISION_SHA256,
        "governance_lock_state": lock.get("status") == "PASS_LOCKED_GOVERNANCE_ONLY",
        "governance_decision_exact": decision.get("status") == "PASS" and decision.get("record_type") == "V34_TERMINAL_AND_V35_SUCCESSOR_DECISION" and decision.get("v35_disposition") == "CONDITIONALLY_AUTHORIZED_NOT_CREATED_NOT_EXECUTED",
        "predecessor_identity_exact": predecessor.get("execution_identity") == EXPECTED_PREDECESSOR_IDENTITY,
        "predecessor_disposition_exact": predecessor.get("disposition") == "FAIL_CLOSED_POST_LOCK_PRE_ATTEMPT_TERMINAL_NO_RETRY_REFERENCE_ONLY",
        "tree_reread_exact": first_root == second_root == EXPECTED_V18_TREE_ROOT and first_count == second_count == EXPECTED_V18_MEMBER_COUNT,
        "static_lock_exact": _digest(paths["v18_static_lock"]) == EXPECTED_V18_STATIC_LOCK_SHA256 and v18_lock.get("record_type") == "V18_STATIC_EXECUTION_LOCK",
        "v18_governance_exact": _digest(paths["v18_governance_lock"]) == EXPECTED_V18_GOVERNANCE_LOCK_SHA256 and _digest(paths["v18_decision"]) == EXPECTED_V18_DECISION_SHA256,
        "pure_verdict_pass": verdict.get("status") == "PASS",
    }
    return {"record_type": "V35_CANONICAL_PREDECESSOR_BINDING_RESULT", "component": component, "predecessor_identity": EXPECTED_PREDECESSOR_IDENTITY, "workspace_tree_sha256": first_root, "workspace_member_count": first_count, "static_execution_lock_sha256": _digest(paths["v18_static_lock"]), "checks": checks, "status": "PASS" if all(checks.values()) else "FAIL_CLOSED_BEFORE_STATIC_LOCK_AND_ATTEMPT"}
