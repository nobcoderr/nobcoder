"""Derived current-readiness expected-digest view for V35.

Current digests are projections of the finalized unified authoritative registry.
They are never accepted from a separately maintained expected-digest table.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterator, Mapping
from pathlib import Path
from typing import Any


WORKSPACE = Path("/home/nobcoder/v0.3-first-real-security-worker-invocation-v35-20261103")
EXECUTION_IDENTITY = "V0_3_FIRST_REAL_SECURITY_WORKER_INVOCATION_V35"
GENERATION_IDENTITY = "V35_CURRENT_GOVERNANCE_BOUND_TYPED_PREFLIGHT_BINDING_GENERATION_0001"
GOVERNANCE_LOCK_SHA256 = "d2263268f61b9ddde99a0b60f4b43a26df1586e0c577ba2ca98c07b64c21f811"
UNIFIED_REGISTRY = WORKSPACE / "contracts/UNIFIED_AUTHORITATIVE_BINDING_GENERATION.json"
CREATION_CLOSURE = WORKSPACE / "contracts/AUTHORITATIVE_ARTIFACT_CREATION_CLOSURE.json"
ARTIFACT_BINDING = WORKSPACE / "contracts/AUTHORITATIVE_ARTIFACT_DIGEST_BINDINGS.json"
VIEW_CONTRACT = WORKSPACE / "contracts/SUCCESSOR_V35_DERIVED_CURRENT_EXPECTED_DIGEST_VIEW_CONTRACT.json"
VIEW = WORKSPACE / "contracts/CURRENT_EXPECTED_DIGEST_VIEW.json"

CURRENT_KEY_IDENTITIES = {
    "successor_v35_requirements": "SUCCESSOR_V35_REQUIREMENTS",
    "typed_historical_decision_registry": "V35_TYPED_HISTORICAL_DECISION_REGISTRY",
    "typed_historical_decision_registry_contract": "V35_TYPED_HISTORICAL_DECISION_REGISTRY_CONTRACT",
    "unified_binding_generation_contract": "V35_UNIFIED_BINDING_GENERATION_CONTRACT",
    "v35_symbol_resolution_regression_matrix": "V35_SYMBOL_RESOLUTION_REGRESSION_MATRIX",
    "v35_typed_module_identity_contract": "V35_TYPED_CANONICAL_MODULE_IDENTITY_CONTRACT",
}


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _load(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"expected object: {path}")
    return value


def _registry_index(registry: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    rows = registry.get("members", [])
    return {
        str(row["logical_artifact_identity"]): row
        for row in rows
        if isinstance(row, dict) and isinstance(row.get("logical_artifact_identity"), str)
    }


def derive_current_rows(registry: Mapping[str, Any]) -> list[dict[str, Any]]:
    index = _registry_index(registry)
    source_digest = sha256_file(UNIFIED_REGISTRY)
    rows: list[dict[str, Any]] = []
    for binding_key, logical_identity in CURRENT_KEY_IDENTITIES.items():
        source = index.get(logical_identity)
        if source is None:
            raise RuntimeError(f"V35_CURRENT_REGISTRY_MEMBER_MISSING:{logical_identity}")
        locator = Path(str(source.get("canonical_locator", "")))
        if not locator.is_file() or locator.is_symlink():
            raise RuntimeError(f"V35_CURRENT_ARTIFACT_UNAVAILABLE:{logical_identity}")
        current_digest = sha256_file(locator)
        if current_digest != source.get("sha256"):
            raise RuntimeError(f"V35_CURRENT_REGISTRY_DIGEST_MISMATCH:{logical_identity}")
        rows.append(
            {
                "binding_key": binding_key,
                "logical_artifact_identity": logical_identity,
                "artifact_role": source.get("artifact_role"),
                "artifact_owner_identity": source.get("owner_identity"),
                "artifact_sha256": current_digest,
                "owner_governance_sha256": source.get("governance_digest"),
                "binding_generation_identity": source.get("generation_identity"),
                "canonical_locator": str(locator.resolve(strict=True)),
                "source_authoritative_registry_identity": "V35_UNIFIED_AUTHORITATIVE_BINDING_GENERATION",
                "source_authoritative_registry_sha256": source_digest,
                "current_historical_status": "CURRENT_EXECUTION_READINESS",
            }
        )
    return rows


def derived_view_fixture_verdict(rows: list[dict[str, Any]], registry: Mapping[str, Any]) -> dict[str, Any]:
    index = _registry_index(registry)
    keys = [row.get("binding_key") for row in rows]
    identities = [row.get("logical_artifact_identity") for row in rows]
    expected_identities = set(CURRENT_KEY_IDENTITIES.values())
    checks = {
        "exact_current_key_set": set(keys) == set(CURRENT_KEY_IDENTITIES) and len(keys) == len(set(keys)),
        "exact_current_identity_set": set(identities) == expected_identities and len(identities) == len(set(identities)),
        "one_current_generation": all(row.get("binding_generation_identity") == GENERATION_IDENTITY for row in rows),
        "one_current_governance": all(row.get("owner_governance_sha256") == GOVERNANCE_LOCK_SHA256 for row in rows),
        "current_status_only": all(row.get("current_historical_status") == "CURRENT_EXECUTION_READINESS" for row in rows),
        "registry_digests_exact": all(
            isinstance(index.get(str(row.get("logical_artifact_identity"))), dict)
            and row.get("artifact_sha256") == index[str(row.get("logical_artifact_identity"))].get("sha256")
            for row in rows
        ),
        "registry_owners_exact": all(
            isinstance(index.get(str(row.get("logical_artifact_identity"))), dict)
            and row.get("artifact_owner_identity") == index[str(row.get("logical_artifact_identity"))].get("owner_identity")
            for row in rows
        ),
        "source_registry_exact": all(
            row.get("source_authoritative_registry_identity") == "V35_UNIFIED_AUTHORITATIVE_BINDING_GENERATION"
            for row in rows
        ),
    }
    return {
        "record_type": "V35_DERIVED_CURRENT_EXPECTED_DIGEST_VIEW_FIXTURE_VERDICT",
        "checks": checks,
        "status": "PASS" if all(checks.values()) else "FAIL_CLOSED_BEFORE_UNIT_VALIDATION",
    }


def derived_current_expected_digest_view_precheck() -> dict[str, Any]:
    required = (UNIFIED_REGISTRY, CREATION_CLOSURE, ARTIFACT_BINDING, VIEW_CONTRACT, VIEW)
    if any(not path.is_file() or path.is_symlink() for path in required):
        return {
            "record_type": "V35_DERIVED_CURRENT_EXPECTED_DIGEST_VIEW_PRECHECK",
            "status": "FAIL_CLOSED_BEFORE_UNIT_VALIDATION",
            "reason": "REQUIRED_DERIVATION_INPUT_UNAVAILABLE",
        }
    registry = _load(UNIFIED_REGISTRY)
    view = _load(VIEW)
    contract = _load(VIEW_CONTRACT)
    expected = derive_current_rows(registry)
    fixture = derived_view_fixture_verdict(list(view.get("artifacts", [])), registry)
    checks = {
        "execution_identity": view.get("execution_identity") == EXECUTION_IDENTITY,
        "generation_identity": view.get("binding_generation_identity") == GENERATION_IDENTITY,
        "governance_lock": view.get("governance_lock_sha256") == GOVERNANCE_LOCK_SHA256,
        "contract_identity": contract.get("contract_identity") == "V35_DERIVED_CURRENT_READINESS_EXPECTED_DIGEST_VIEW_CONTRACT_V1",
        "source_registry_digest": view.get("source_authoritative_registry_sha256") == sha256_file(UNIFIED_REGISTRY),
        "creation_closure_digest": view.get("creation_closure_sha256") == sha256_file(CREATION_CLOSURE),
        "artifact_binding_digest": view.get("artifact_binding_sha256") == sha256_file(ARTIFACT_BINDING),
        "exact_derived_rows": view.get("artifacts") == expected,
        "fixture": fixture.get("status") == "PASS",
        "no_manual_current_table": view.get("derivation") == "PURE_PROJECTION_OF_FINALIZED_AUTHORITATIVE_REGISTRY",
        "historical_policy": view.get("historical_digest_policy") == "HISTORICAL_ONLY_NEVER_CURRENT",
        "reread_rehash": view.get("reread_rehash_verification") == "PASS",
    }
    return {
        "record_type": "V35_DERIVED_CURRENT_EXPECTED_DIGEST_VIEW_PRECHECK",
        "status": "PASS" if all(checks.values()) else "FAIL_CLOSED_BEFORE_UNIT_VALIDATION",
        "checks": checks,
        "view_sha256": sha256_file(VIEW),
        "current_artifact_count": len(expected),
        "zero_stale_current_artifact_digests": checks["exact_derived_rows"],
        "zero_stale_current_owner_governance_digests": checks["fixture"],
        "zero_mixed_generation_current_bindings": checks["fixture"],
        "zero_historical_only_selected_as_current": checks["fixture"],
    }


class DerivedExpectedDigestMapping(Mapping[str, str]):
    def __init__(self, historical: Mapping[str, str]):
        self._historical = dict(historical)

    def _current(self) -> dict[str, str]:
        verdict = derived_current_expected_digest_view_precheck()
        if verdict.get("status") != "PASS":
            raise RuntimeError(f"V35_DERIVED_CURRENT_DIGEST_VIEW_INVALID:{verdict}")
        view = _load(VIEW)
        return {str(row["binding_key"]): str(row["artifact_sha256"]) for row in view["artifacts"]}

    def __getitem__(self, key: str) -> str:
        if key in CURRENT_KEY_IDENTITIES:
            return self._current()[key]
        return self._historical[key]

    def __iter__(self) -> Iterator[str]:
        yield from dict.fromkeys((*self._historical, *CURRENT_KEY_IDENTITIES))

    def __len__(self) -> int:
        return len(set(self._historical) | set(CURRENT_KEY_IDENTITIES))


def derived_expected_digest_mapping(historical: Mapping[str, str]) -> Mapping[str, str]:
    return DerivedExpectedDigestMapping(historical)
