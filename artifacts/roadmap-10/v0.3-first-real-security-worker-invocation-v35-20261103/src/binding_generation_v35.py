"""Unified governance-bound authoritative binding generation for V35."""

from __future__ import annotations

import hashlib
import json
import os
import stat
from pathlib import Path
from typing import Any, Iterable


WORKSPACE = Path("/home/nobcoder/v0.3-first-real-security-worker-invocation-v35-20261103")
EXECUTION_IDENTITY = "V0_3_FIRST_REAL_SECURITY_WORKER_INVOCATION_V35"
GENERATION_IDENTITY = "V35_CURRENT_GOVERNANCE_BOUND_TYPED_PREFLIGHT_BINDING_GENERATION_0001"
GOVERNANCE_IDENTITY = (
    "V0_3_FIRST_REAL_SECURITY_WORKER_INVOCATION_V34_PRELOCK_RESULTS_DIRECTORY_AND_"
    "FIXTURE_PROBE_PATH_LIFECYCLE_DEFECT_UNIT_EXECUTION_ERRATUM_AND_SUCCESSOR_DECISION_"
    "GOVERNANCE_ONLY"
)
GOVERNANCE_LOCK_SHA256 = "d2263268f61b9ddde99a0b60f4b43a26df1586e0c577ba2ca98c07b64c21f811"
GOVERNANCE_DECISION_SHA256 = "e9672bcddb685c92f3230531eb4c131f41264f54e2ee4c6afa9f9f633bcb21b6"
MANIFEST_PATH = WORKSPACE / "contracts/UNIFIED_AUTHORITATIVE_BINDING_GENERATION.json"
REQUIRED_DOMAINS = frozenset(
    {
        "SUCCESSOR_SELECTOR",
        "PROMPT_BYTES_DIGEST_AND_MODE",
        "HISTORICAL_GOVERNANCE_DECISIONS",
        "CANONICAL_PREDECESSOR_ARTIFACTS",
        "EXTERNAL_TRANSITIVE_ARTIFACTS",
        "CANONICAL_MODULE_RESOLUTION_BINDINGS",
        "AUTHORITATIVE_CONTRACT_SCHEMA_DIGEST_BINDINGS",
        "MOUNT_OUTPUT_IDENTITY",
        "TYPED_PREFLIGHT_REQUIREMENTS",
        "HOST_OUTPUT_BIND_SOURCE_LIFECYCLE",
        "PRELOCK_STORAGE_LIFECYCLE",
        "TYPED_CODEX_RUNTIME_ACCEPTANCE",
        "AUTHORITATIVE_ARTIFACT_FINALIZATION",
    }
)
KNOWN_HISTORICAL_DIGESTS = {
    "V34_TO_V35_GOVERNANCE_LOCK": "d2263268f61b9ddde99a0b60f4b43a26df1586e0c577ba2ca98c07b64c21f811",
    "V34_TERMINAL_AND_V35_SUCCESSOR_DECISION": "e9672bcddb685c92f3230531eb4c131f41264f54e2ee4c6afa9f9f633bcb21b6",
    "V34_FROZEN_FAILURE_EVIDENCE_BINDING": "ca904df3e36b592a1245941e7614fb5bda889d50cfa952623f822e65abe85026",
    "V25_TO_V26_GOVERNANCE_LOCK": "fa2a563eff3b4ba836a74fcb3b2f43225d3746d87ba28fb8eec17ed7a64174cb",
    "V25_TERMINAL_AND_V26_SUCCESSOR_DECISION": "dc69e573295e97e2b1b5f67837c6e1c33ffdd2f955e2f1d6a0ffd5fc910e0d43",
    "V25_FROZEN_FAILURE_EVIDENCE_BINDING": "a579511a9c46c837c4b9e88685d5ea9d7061adf6ab9f8cc841700a0d2f4de78c",
    "V20_TERMINAL_AND_V21_SUCCESSOR_DECISION": "8c78c347a293605db31122f42482ce2caca5bb52a5e750be341377087f3aeff3",
    "V17_PRELOCK_FROZEN_EVIDENCE_BINDING": "7b112d3a2f0e69e754d23051608a0cb8fb20edc375a9d42c0c8898dd0020f360",
    "V21_EXTERNAL_PREDECESSOR_ARTIFACT_REGRESSION_MATRIX": "6facfd3c98611569f2c1ae56137a5bee2b5370f9aff5f6ded964d680abf85f22",
}
ALLOWED_COMPONENTS = frozenset(
    {
        "BUILDER",
        "UNIT",
        "PRIMARY_VALIDATOR",
        "INDEPENDENT_VALIDATOR",
        "FRESH_PREFLIGHT",
        "DEPENDENCY_CLOSURE",
        "STATIC_LOCK_PREPARATION",
        "STATIC_LOCK_VERIFICATION",
        "LOCKED_RUNTIME",
    }
)


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"expected JSON object: {path}")
    return value


def binding_fixture_verdict(
    rows: Iterable[dict[str, Any]],
    *,
    expected_generation: str = GENERATION_IDENTITY,
    expected_governance: str = GOVERNANCE_IDENTITY,
    expected_governance_digest: str = GOVERNANCE_LOCK_SHA256,
) -> dict[str, Any]:
    materialized = list(rows)
    identities = [row.get("logical_artifact_identity") for row in materialized]
    domains = {row.get("domain") for row in materialized}
    selector_rows = [row for row in materialized if row.get("domain") == "SUCCESSOR_SELECTOR"]
    prompt_rows = [row for row in materialized if row.get("logical_artifact_identity") == "V35_FINAL_WORKER_PROMPT"]
    historical_rows = [row for row in materialized if row.get("domain") == "HISTORICAL_GOVERNANCE_DECISIONS"]
    checks = {
        "non_empty": bool(materialized),
        "one_generation": all(row.get("generation_identity") == expected_generation for row in materialized),
        "one_governance_identity": all(row.get("governance_identity") == expected_governance for row in materialized),
        "one_governance_digest": all(row.get("governance_digest") == expected_governance_digest for row in materialized),
        "logical_identities_present": all(isinstance(value, str) and value for value in identities),
        "logical_identities_unique": len(identities) == len(set(identities)),
        "required_domains_complete": REQUIRED_DOMAINS <= domains,
        "selector_exact": len(selector_rows) == 1
        and selector_rows[0].get("logical_artifact_identity") == "SUCCESSOR_V35_REQUIREMENTS"
        and selector_rows[0].get("relationship") == "V34_TO_V35_SUCCESSOR_AUTHORITY",
        "prompt_mode_exact": len(prompt_rows) == 1 and prompt_rows[0].get("required_mode") == "0444",
        "historical_decision_exact": any(
            row.get("logical_artifact_identity") == "V34_TERMINAL_AND_V35_SUCCESSOR_DECISION"
            and row.get("relationship") == "AUTHORIZES_V35"
            for row in historical_rows
        ),
        "known_historical_and_external_digests_exact": all(
            row.get("sha256") == KNOWN_HISTORICAL_DIGESTS[row["logical_artifact_identity"]]
            for row in materialized
            if row.get("logical_artifact_identity") in KNOWN_HISTORICAL_DIGESTS
        ) and set(KNOWN_HISTORICAL_DIGESTS) <= set(identities),
        "no_synthetic_historical_identity": all(
            not (
                row.get("domain") in {"HISTORICAL_GOVERNANCE_DECISIONS", "EXTERNAL_TRANSITIVE_ARTIFACTS"}
                and str(row.get("logical_artifact_identity", "")).startswith("V35_SYNTHETIC")
            )
            for row in materialized
        ),
    }
    return {
        "record_type": "V35_UNIFIED_BINDING_GENERATION_FIXTURE_VERDICT",
        "status": "PASS" if all(checks.values()) else "FAIL_CLOSED_BEFORE_STATIC_LOCK_AND_ATTEMPT",
        "checks": checks,
    }


def _verify_member(row: dict[str, Any]) -> dict[str, Any]:
    locator = Path(str(row.get("canonical_locator", "")))
    expected_mode = row.get("required_mode")
    checks: dict[str, bool] = {
        "generation_exact": row.get("generation_identity") == GENERATION_IDENTITY,
        "governance_identity_exact": row.get("governance_identity") == GOVERNANCE_IDENTITY,
        "governance_digest_exact": row.get("governance_digest") == GOVERNANCE_LOCK_SHA256,
        "regular_non_symlink": locator.is_file() and not locator.is_symlink(),
    }
    if checks["regular_non_symlink"]:
        first = locator.read_bytes()
        second = locator.read_bytes()
        checks.update(
            {
                "reread_identical": first == second,
                "digest_exact": sha256_bytes(first) == row.get("sha256"),
                "size_exact": len(first) == row.get("size"),
                "mode_exact": expected_mode is None
                or stat.S_IMODE(locator.stat().st_mode) == int(str(expected_mode), 8),
            }
        )
    else:
        checks.update({"reread_identical": False, "digest_exact": False, "size_exact": False, "mode_exact": False})
    return {
        "logical_artifact_identity": row.get("logical_artifact_identity"),
        "canonical_locator": str(locator),
        "checks": checks,
        "status": "PASS" if all(checks.values()) else "FAIL_CLOSED",
    }


def unified_binding_generation_precheck(component: str) -> dict[str, Any]:
    if component not in ALLOWED_COMPONENTS or not MANIFEST_PATH.is_file() or MANIFEST_PATH.is_symlink():
        return {
            "record_type": "V35_UNIFIED_BINDING_GENERATION_ATTESTATION",
            "component": component,
            "status": "FAIL_CLOSED_BEFORE_STATIC_LOCK_AND_ATTEMPT",
            "reason": "COMPONENT_OR_MANIFEST_INVALID",
        }
    manifest = load_json(MANIFEST_PATH)
    rows = manifest.get("members", [])
    shape = binding_fixture_verdict(rows)
    member_results = [_verify_member(row) for row in rows if isinstance(row, dict)]
    checks = {
        "record_type_exact": manifest.get("record_type") == "V35_UNIFIED_AUTHORITATIVE_BINDING_GENERATION",
        "execution_identity_exact": manifest.get("execution_identity") == EXECUTION_IDENTITY,
        "generation_exact": manifest.get("generation_identity") == GENERATION_IDENTITY,
        "governance_identity_exact": manifest.get("governance_identity") == GOVERNANCE_IDENTITY,
        "governance_digest_exact": manifest.get("governance_digest") == GOVERNANCE_LOCK_SHA256,
        "governance_decision_exact": manifest.get("governance_decision_digest") == GOVERNANCE_DECISION_SHA256,
        "single_current_generation": manifest.get("current_execution_readiness_generation") == GENERATION_IDENTITY,
        "member_count_exact": manifest.get("member_count") == len(rows),
        "shape_pass": shape.get("status") == "PASS",
        "members_pass": bool(member_results) and all(row.get("status") == "PASS" for row in member_results),
        "post_bind_mutation_prohibited": manifest.get("post_bind_mutation") == "PROHIBITED",
    }
    return {
        "record_type": "V35_UNIFIED_BINDING_GENERATION_ATTESTATION",
        "component": component,
        "generation_identity": GENERATION_IDENTITY,
        "status": "PASS" if all(checks.values()) else "FAIL_CLOSED_BEFORE_STATIC_LOCK_AND_ATTEMPT",
        "checks": checks,
        "member_results": member_results,
        "manifest_sha256": sha256_file(MANIFEST_PATH),
    }


def prompt_binding_verdict(prompt_path: Path, binding: dict[str, Any], request: dict[str, Any]) -> dict[str, Any]:
    first = prompt_path.read_bytes() if prompt_path.is_file() and not prompt_path.is_symlink() else b""
    second = prompt_path.read_bytes() if first else b""
    digest = sha256_bytes(first) if first else None
    mode = stat.S_IMODE(prompt_path.stat().st_mode) if first else None
    checks = {
        "generation_exact": binding.get("generation_identity") == GENERATION_IDENTITY,
        "governance_exact": binding.get("governance_digest") == GOVERNANCE_LOCK_SHA256,
        "reread_exact": bool(first) and first == second,
        "digest_exact": digest == binding.get("first_prompt_sha256") == binding.get("reread_prompt_sha256"),
        "request_digest_exact": digest == request.get("prompt", {}).get("sha256"),
        "mode_0444": mode == 0o444 == binding.get("verified_mode"),
        "required_mode_exact": binding.get("required_mode") == "0444",
        "post_bind_mutation_prohibited": binding.get("post_bind_prompt_mutation") == "PROHIBITED",
    }
    return {
        "record_type": "V35_PROMPT_BINDING_VERDICT",
        "status": "PASS" if all(checks.values()) else "FAIL_CLOSED_BEFORE_STATIC_LOCK_AND_ATTEMPT",
        "checks": checks,
        "actual_sha256": digest,
        "actual_mode": None if mode is None else format(mode, "04o"),
    }
