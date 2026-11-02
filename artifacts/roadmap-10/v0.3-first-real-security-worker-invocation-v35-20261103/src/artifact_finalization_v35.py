"""Authoritative input-member creation closure and finalization evidence for V35."""

from __future__ import annotations

import hashlib
import json
import os
import stat
from pathlib import Path
from typing import Any, Mapping


WORKSPACE = Path("/home/nobcoder/v0.3-first-real-security-worker-invocation-v35-20261103")
EXECUTION_IDENTITY = "V0_3_FIRST_REAL_SECURITY_WORKER_INVOCATION_V35"
GENERATION_IDENTITY = "V35_CURRENT_GOVERNANCE_BOUND_TYPED_PREFLIGHT_BINDING_GENERATION_0001"
GOVERNANCE_LOCK_SHA256 = "d2263268f61b9ddde99a0b60f4b43a26df1586e0c577ba2ca98c07b64c21f811"
CLOSURE = WORKSPACE / "contracts/AUTHORITATIVE_ARTIFACT_CREATION_CLOSURE.json"
BINDING = WORKSPACE / "contracts/AUTHORITATIVE_ARTIFACT_DIGEST_BINDINGS.json"
FINALIZATION_CONTRACT = WORKSPACE / "contracts/SUCCESSOR_V35_AUTHORITATIVE_ARTIFACT_FINALIZATION_LIFECYCLE_CONTRACT.json"
SYMBOL_MANIFEST = "contracts/LOCKED_ENTRYPOINT_SYMBOL_BINDING_MANIFEST.json"
DERIVED_NON_MEMBER_RECORDS = frozenset(
    {
        "AUTHORITATIVE_ARTIFACT_CREATION_CLOSURE.json",
        "AUTHORITATIVE_ARTIFACT_DIGEST_BINDINGS.json",
        "CURRENT_EXPECTED_DIGEST_VIEW.json",
        "UNIFIED_AUTHORITATIVE_BINDING_GENERATION.json",
    }
)
LIFECYCLE = (
    "ARTIFACTS_MATERIALIZING",
    "MEMBER_SET_COMPLETE",
    "CREATION_PHASE_CLOSED",
    "IMMUTABILITY_APPLIED",
    "DIGESTS_BOUND",
    "REREAD_VERIFIED",
    "READY_FOR_UNIT_VALIDATION",
)


def digest_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def digest(path: Path) -> str:
    return digest_bytes(path.read_bytes())


def authoritative_input_paths(root: Path = WORKSPACE) -> tuple[Path, ...]:
    contracts = [
        item
        for item in (root / "contracts").glob("*.json")
        if item.name not in DERIVED_NON_MEMBER_RECORDS
    ]
    schemas = list((root / "schemas").glob("*.json"))
    execution_inputs = [
        root / "fixture/fixture.json",
        root / "fixture/worker-prompt.txt",
        root / "runtime-config-candidate/config.toml",
    ]
    return tuple(
        sorted(
            (*contracts, *schemas, *execution_inputs),
            key=lambda item: item.relative_to(root).as_posix().encode("utf-8"),
        )
    )


def member_rows(root: Path = WORKSPACE) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for item in authoritative_input_paths(root):
        relative = item.relative_to(root).as_posix()
        if not item.is_file() or item.is_symlink() or item.resolve(strict=True) != item:
            raise RuntimeError(f"V35_UNSAFE_AUTHORITATIVE_MEMBER:{relative}")
        info = item.stat()
        rows.append(
            {
                "path": relative,
                "sha256": digest(item),
                "bytes": info.st_size,
                "mode": f"{stat.S_IMODE(info.st_mode):04o}",
                "uid": info.st_uid,
                "gid": info.st_gid,
            }
        )
    return rows


def finalization_fixture_verdict(candidate: Mapping[str, Any]) -> dict[str, Any]:
    checks = {
        "symbol_before_closure": candidate.get("symbol_before_closure") is True,
        "symbol_in_closed_set": candidate.get("symbol_in_closed_set") is True,
        "creation_phase_closed": candidate.get("creation_phase_closed") is True,
        "all_modes_0444": candidate.get("all_modes_0444") is True,
        "ownership_exact": candidate.get("ownership_exact") is True,
        "digests_bound_after_closure": candidate.get("digests_bound_after_closure") is True,
        "reread_rehash_exact": candidate.get("reread_rehash_exact") is True,
        "member_set_unchanged": candidate.get("member_set_unchanged") is True,
        "prompt_dependency_set_complete": candidate.get("prompt_dependency_set_complete") is True,
        "validation_after_ready": candidate.get("validation_after_ready") is True,
    }
    return {
        "record_type": "V35_AUTHORITATIVE_ARTIFACT_FINALIZATION_FIXTURE_VERDICT",
        "checks": checks,
        "status": "PASS" if all(checks.values()) else "FAIL_CLOSED_BEFORE_UNIT_VALIDATION",
    }


def authoritative_artifact_finalization_precheck() -> dict[str, Any]:
    if not CLOSURE.is_file() or CLOSURE.is_symlink() or not BINDING.is_file() or BINDING.is_symlink() or not FINALIZATION_CONTRACT.is_file() or FINALIZATION_CONTRACT.is_symlink():
        return {"record_type": "V35_AUTHORITATIVE_ARTIFACT_FINALIZATION_PRECHECK", "status": "FAIL_CLOSED_BEFORE_UNIT_VALIDATION", "reason": "CLOSURE_OR_BINDING_UNAVAILABLE"}
    closure = json.loads(CLOSURE.read_text(encoding="utf-8"))
    binding = json.loads(BINDING.read_text(encoding="utf-8"))
    contract = json.loads(FINALIZATION_CONTRACT.read_text(encoding="utf-8"))
    observed = member_rows()
    observed_index = {row["path"]: row for row in observed}
    closed_rows = closure.get("members", [])
    closed_index = {row.get("path"): row for row in closed_rows if isinstance(row, dict)}
    bound_rows = binding.get("members", [])
    bound_index = {row.get("path"): row for row in bound_rows if isinstance(row, dict)}
    expected = set(observed_index)
    exact_rows = all(
        observed_index[name]["sha256"] == closed_index.get(name, {}).get("sha256") == bound_index.get(name, {}).get("sha256")
        and observed_index[name]["bytes"] == closed_index.get(name, {}).get("bytes") == bound_index.get(name, {}).get("bytes")
        and observed_index[name]["mode"] == closed_index.get(name, {}).get("mode") == "0444"
        and observed_index[name]["uid"] == closed_index.get(name, {}).get("uid")
        and observed_index[name]["gid"] == closed_index.get(name, {}).get("gid")
        for name in expected
    )
    checks = {
        "execution_identity_exact": closure.get("execution_identity") == binding.get("execution_identity") == EXECUTION_IDENTITY,
        "generation_exact": closure.get("generation_identity") == binding.get("generation_identity") == GENERATION_IDENTITY,
        "governance_exact": closure.get("governance_lock_sha256") == binding.get("governance_lock_sha256") == GOVERNANCE_LOCK_SHA256,
        "lifecycle_exact": closure.get("lifecycle") == list(LIFECYCLE),
        "creation_phase_closed": closure.get("creation_phase_state") == "CREATION_PHASE_CLOSED",
        "derived_records_non_members": closure.get("derived_non_member_records") == sorted(DERIVED_NON_MEMBER_RECORDS),
        "member_sets_exact": set(closed_index) == set(bound_index) == expected,
        "member_counts_exact": closure.get("member_count") == binding.get("member_count") == len(expected),
        "symbol_manifest_present": SYMBOL_MANIFEST in expected,
        "prompt_present": "fixture/worker-prompt.txt" in expected,
        "config_present": "runtime-config-candidate/config.toml" in expected,
        "rows_exact_and_immutable": exact_rows,
        "closure_digest_bound": binding.get("creation_closure_sha256") == digest(CLOSURE),
        "reread_verified": binding.get("reread_and_rehash") == "PASS",
        "member_set_unchanged": binding.get("member_set_unchanged_after_binding") is True,
        "post_closure_mutation_prohibited": closure.get("post_closure_member_mutation") == "PROHIBITED",
        "normative_contract_exact": contract.get("contract_identity") == "V35_AUTHORITATIVE_ARTIFACT_CREATION_CLOSURE_FREEZE_AND_BINDING_CONTRACT_V1"
        and contract.get("successor_identity") == EXECUTION_IDENTITY
        and contract.get("authorizing_governance_lock") == GOVERNANCE_LOCK_SHA256
        and contract.get("required_authoritative_file_mode") == "0444"
        and contract.get("digest_binding_before_complete_member_set") == "PROHIBITED"
        and contract.get("late_authoritative_member") == "FAIL_CLOSED_BEFORE_VALIDATION",
    }
    return {
        "record_type": "V35_AUTHORITATIVE_ARTIFACT_FINALIZATION_PRECHECK",
        "execution_identity": EXECUTION_IDENTITY,
        "member_count": len(expected),
        "closure_sha256": digest(CLOSURE),
        "binding_sha256": digest(BINDING),
        "checks": checks,
        "status": "PASS" if all(checks.values()) else "FAIL_CLOSED_BEFORE_UNIT_VALIDATION",
    }
