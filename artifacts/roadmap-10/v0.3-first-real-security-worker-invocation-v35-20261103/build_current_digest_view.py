#!/usr/bin/env python3
"""Derive and freeze V35's current expected-digest view from the final registry."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent
sys.dont_write_bytecode = True
if Path.cwd().resolve() != ROOT:
    raise RuntimeError("V35_CANONICAL_CWD_REQUIRED")
bindings = json.loads((ROOT / "contracts/CANONICAL_MODULE_BINDINGS.json").read_text(encoding="utf-8"))
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
resolver.load_canonical_modules("BUILDER", ("workspace_boundary_v35", "current_digest_view_v35"))

from current_digest_view_v35 import (  # noqa: E402
    ARTIFACT_BINDING,
    CREATION_CLOSURE,
    EXECUTION_IDENTITY,
    GENERATION_IDENTITY,
    GOVERNANCE_LOCK_SHA256,
    UNIFIED_REGISTRY,
    VIEW,
    derive_current_rows,
    derived_view_fixture_verdict,
    sha256_file,
)
from workspace_boundary_v35 import guarded_chmod, guarded_json_once  # noqa: E402


def main() -> int:
    if VIEW.exists() or VIEW.is_symlink():
        raise FileExistsError(f"append-only derived view exists: {VIEW}")
    registry = json.loads(UNIFIED_REGISTRY.read_text(encoding="utf-8"))
    first = derive_current_rows(registry)
    second = derive_current_rows(registry)
    if first != second:
        raise RuntimeError("V35_DERIVED_VIEW_REREAD_DRIFT")
    verdict = derived_view_fixture_verdict(first, registry)
    if verdict.get("status") != "PASS":
        raise RuntimeError(f"V35_DERIVED_VIEW_INVALID:{verdict}")
    payload = {
        "record_type": "V35_DERIVED_CURRENT_EXPECTED_DIGEST_VIEW",
        "execution_identity": EXECUTION_IDENTITY,
        "binding_generation_identity": GENERATION_IDENTITY,
        "governance_lock_sha256": GOVERNANCE_LOCK_SHA256,
        "source_authoritative_registry_identity": "V35_UNIFIED_AUTHORITATIVE_BINDING_GENERATION",
        "source_authoritative_registry_sha256": sha256_file(UNIFIED_REGISTRY),
        "creation_closure_sha256": sha256_file(CREATION_CLOSURE),
        "artifact_binding_sha256": sha256_file(ARTIFACT_BINDING),
        "derivation": "PURE_PROJECTION_OF_FINALIZED_AUTHORITATIVE_REGISTRY",
        "historical_digest_policy": "HISTORICAL_ONLY_NEVER_CURRENT",
        "current_artifact_count": len(first),
        "artifacts": first,
        "reread_rehash_verification": "PASS",
        "status": "PASS_EXACT_DERIVED_CURRENT_READINESS_VIEW",
        "attempt_count": 0,
        "worker_invocation_count": 0,
        "codex_as_worker_invocation_count": 0,
    }
    guarded_json_once(VIEW, payload, operation_identity="BUILD_DERIVED_CURRENT_EXPECTED_DIGEST_VIEW", generation=GENERATION_IDENTITY)
    guarded_chmod(VIEW, 0o444, operation_identity="FREEZE_DERIVED_CURRENT_EXPECTED_DIGEST_VIEW", generation=GENERATION_IDENTITY)
    reread = json.loads(VIEW.read_text(encoding="utf-8"))
    if reread != payload:
        raise RuntimeError("V35_DERIVED_VIEW_POST_WRITE_MISMATCH")
    print(json.dumps({"status": payload["status"], "artifacts": len(first), "sha256": sha256_file(VIEW)}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
