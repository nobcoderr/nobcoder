#!/usr/bin/env python3
"""Validate the exact unified V26 binding generation under the issued lock."""

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
_bindings = json.loads((ROOT / "contracts/CANONICAL_MODULE_BINDINGS.json").read_text())
_row = next(row for row in _bindings["modules"] if row["canonical_logical_module_name"] == "module_resolution_v35")
_path = Path(_row["canonical_source_path"])
if hashlib.sha256(_path.read_bytes()).hexdigest() != _row["exact_source_sha256"]:
    raise RuntimeError("V35_MODULE_RESOLVER_DIGEST_MISMATCH")
_spec = importlib.util.spec_from_file_location("module_resolution_v35", _path)
if _spec is None or _spec.loader is None:
    raise RuntimeError("V35_MODULE_RESOLVER_SPEC_UNAVAILABLE")
_resolver = importlib.util.module_from_spec(_spec)
sys.modules["module_resolution_v35"] = _resolver
_spec.loader.exec_module(_resolver)
_resolver.load_canonical_modules(
    "STATIC_LOCK_VERIFICATION",
    ("workspace_boundary_v35", "predecessor_binding_v35", "external_artifact_binding_v35",
     "binding_generation_v35", "symbol_resolution_v35", "mount_output_binding_v35",
     "preflight_requirement_registry_v35", "host_output_lifecycle_v35", "runtime_acceptance_v35", "current_digest_view_v35", "invocation_v35"),
)

from binding_generation_v35 import unified_binding_generation_precheck  # noqa: E402
from invocation_v35 import STATIC_RUN, canonical_json_sha256, load_json  # noqa: E402
from workspace_boundary_v35 import guarded_json_once  # noqa: E402


def main() -> int:
    lock = load_json(ROOT / "STATIC_EXECUTION_LOCK.json")
    attestation = unified_binding_generation_precheck("LOCKED_RUNTIME")
    checks = {
        "attestation_pass": attestation.get("status") == "PASS",
        "locked_attestation_exact": lock.get("unified_binding_generation_precheck_sha256")
        == canonical_json_sha256(attestation),
        "attempt_marker_absent": not (STATIC_RUN / "ATTEMPT_MARKER.json").exists(),
        "runtime_result_absent": not (STATIC_RUN / "runtime-result-0001.json").exists(),
    }
    result = {
        "record_type": "V35_LOCKED_UNIFIED_BINDING_GENERATION_VALIDATION",
        "execution_identity": "V0_3_FIRST_REAL_SECURITY_WORKER_INVOCATION_V35",
        "status": "PASS" if all(checks.values()) else "FAIL_CLOSED_BEFORE_ATTEMPT",
        "checks": checks,
        "attestation": attestation,
        "attempt_count": 0,
        "worker_invocation_count": 0,
        "codex_as_worker_invocation_count": 0,
    }
    guarded_json_once(
        STATIC_RUN / "locked-binding-generation-validation-0001.json",
        result,
        operation_identity="LOCKED_BINDING_GENERATION_VALIDATION",
        generation="STATIC_LOCK_0001",
    )
    print(json.dumps({"status": result["status"]}, sort_keys=True))
    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
