#!/usr/bin/env python3
"""Close and immutably freeze the complete V35 authoritative input member set."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import stat
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent
sys.dont_write_bytecode = True
if Path.cwd().resolve() != ROOT:
    raise RuntimeError("V35_CANONICAL_CWD_REQUIRED")
bindings = json.loads((ROOT / "contracts/CANONICAL_MODULE_BINDINGS.json").read_text())
resolver_row = next(row for row in bindings["modules"] if row["canonical_logical_module_name"] == "module_resolution_v35")
resolver_path = Path(resolver_row["canonical_source_path"])
if hashlib.sha256(resolver_path.read_bytes()).hexdigest() != resolver_row["exact_source_sha256"]:
    raise RuntimeError("V35_MODULE_RESOLVER_DIGEST_MISMATCH")
spec = importlib.util.spec_from_file_location("module_resolution_v35", resolver_path)
if spec is None or spec.loader is None:
    raise RuntimeError("V35_MODULE_RESOLVER_SPEC_UNAVAILABLE")
resolver = importlib.util.module_from_spec(spec)
sys.modules["module_resolution_v35"] = resolver
spec.loader.exec_module(resolver)
resolver.load_canonical_modules("BUILDER", ("workspace_boundary_v35", "artifact_finalization_v35"))

from artifact_finalization_v35 import (  # noqa: E402
    CLOSURE, DERIVED_NON_MEMBER_RECORDS, EXECUTION_IDENTITY, FINALIZATION_CONTRACT, GENERATION_IDENTITY,
    GOVERNANCE_LOCK_SHA256, LIFECYCLE, SYMBOL_MANIFEST, authoritative_input_paths,
    digest, member_rows,
)
from workspace_boundary_v35 import guarded_chmod, guarded_json_once  # noqa: E402


def main() -> int:
    if CLOSURE.exists() or CLOSURE.is_symlink():
        raise RuntimeError("V35_CREATION_CLOSURE_ALREADY_EXISTS")
    contract = json.loads(FINALIZATION_CONTRACT.read_text(encoding="utf-8"))
    if not (
        contract.get("contract_identity") == "V35_AUTHORITATIVE_ARTIFACT_CREATION_CLOSURE_FREEZE_AND_BINDING_CONTRACT_V1"
        and contract.get("successor_identity") == EXECUTION_IDENTITY
        and contract.get("authorizing_governance_lock") == GOVERNANCE_LOCK_SHA256
        and contract.get("required_authoritative_file_mode") == "0444"
    ):
        raise RuntimeError("V35_FINALIZATION_CONTRACT_MISMATCH")
    first_paths = authoritative_input_paths()
    first_names = tuple(item.relative_to(ROOT).as_posix() for item in first_paths)
    if SYMBOL_MANIFEST not in first_names:
        raise RuntimeError("V35_SYMBOL_MANIFEST_NOT_MATERIALIZED_BEFORE_CLOSURE")
    if any((not item.is_file()) or item.is_symlink() for item in first_paths):
        raise RuntimeError("V35_AUTHORITATIVE_MEMBER_UNSAFE_BEFORE_CLOSURE")
    expected_uid, expected_gid = os.getuid(), os.getgid()
    for item in first_paths:
        if item.stat().st_uid != expected_uid or item.stat().st_gid != expected_gid:
            raise RuntimeError(f"V35_AUTHORITATIVE_OWNER_MISMATCH:{item}")
        guarded_chmod(item, 0o444, operation_identity="V35_APPLY_AUTHORITATIVE_IMMUTABILITY", generation=GENERATION_IDENTITY)
    second_paths = authoritative_input_paths()
    second_names = tuple(item.relative_to(ROOT).as_posix() for item in second_paths)
    if second_names != first_names:
        raise RuntimeError("V35_MEMBER_SET_CHANGED_DURING_CREATION_CLOSURE")
    rows = member_rows()
    if not rows or any(row["mode"] != "0444" or row["uid"] != expected_uid or row["gid"] != expected_gid for row in rows):
        raise RuntimeError("V35_IMMUTABILITY_OR_OWNERSHIP_VERIFICATION_FAILED")
    stream = "".join(f"{row['sha256']}  {row['path']}\n" for row in rows).encode("utf-8")
    payload = {
        "record_type": "V35_AUTHORITATIVE_ARTIFACT_CREATION_CLOSURE",
        "execution_identity": EXECUTION_IDENTITY,
        "generation_identity": GENERATION_IDENTITY,
        "governance_lock_sha256": GOVERNANCE_LOCK_SHA256,
        "lifecycle": list(LIFECYCLE),
        "creation_phase_state": "CREATION_PHASE_CLOSED",
        "closed_member_set_root_sha256": hashlib.sha256(stream).hexdigest(),
        "member_count": len(rows),
        "members": rows,
        "required_mode": "0444",
        "expected_uid": expected_uid,
        "expected_gid": expected_gid,
        "symbol_manifest_present_before_closure": True,
        "derived_non_member_records": sorted(DERIVED_NON_MEMBER_RECORDS),
        "post_closure_member_mutation": "PROHIBITED",
        "status": "PASS_CREATION_PHASE_CLOSED_IMMUTABILITY_APPLIED",
        "attempt_count": 0,
        "worker_invocation_count": 0,
        "codex_as_worker_invocation_count": 0,
    }
    guarded_json_once(CLOSURE, payload, operation_identity="V35_RECORD_AUTHORITATIVE_CREATION_CLOSURE", generation=GENERATION_IDENTITY)
    guarded_chmod(CLOSURE, 0o444, operation_identity="V35_FREEZE_CREATION_CLOSURE", generation=GENERATION_IDENTITY)
    print(json.dumps({"status": payload["status"], "members": len(rows), "closure_sha256": digest(CLOSURE)}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
