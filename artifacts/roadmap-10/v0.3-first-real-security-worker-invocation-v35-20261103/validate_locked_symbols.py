#!/usr/bin/env python3
"""Resolve the exact frozen runner symbol graph and execute the required precheck."""

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
     "preflight_requirement_registry_v35", "host_output_lifecycle_v35", "runtime_acceptance_v35", "current_digest_view_v35", "invocation_v35", "runner_v35"),
)

import runner_v35  # noqa: E402
from symbol_resolution_v35 import static_symbol_binding_precheck, symbol_resolution_precheck  # noqa: E402
from workspace_boundary_v35 import guarded_json_once  # noqa: E402


def main() -> int:
    resolution = symbol_resolution_precheck(vars(runner_v35), require_static_lock=True)
    static_binding = static_symbol_binding_precheck()
    lock = runner_v35.load_json(ROOT / "STATIC_EXECUTION_LOCK.json")
    canonicalization = runner_v35.v16_tree_canonicalization_precheck()
    result = {
        "record_type": "V35_LOCKED_SYMBOL_RESOLUTION_SELFTEST",
        "execution_identity": "V0_3_FIRST_REAL_SECURITY_WORKER_INVOCATION_V35",
        "symbol_resolution": resolution,
        "static_symbol_binding": static_binding,
        "static_symbol_binding_lock_match": lock.get("static_symbol_binding_precheck_sha256")
        == runner_v35.canonical_json_sha256(static_binding),
        "canonicalization_precheck": canonicalization,
        "attempt_marker_absent": not (runner_v35.STATIC_RUN / "ATTEMPT_MARKER.json").exists(),
        "runtime_result_absent": not (runner_v35.STATIC_RUN / "runtime-result-0001.json").exists(),
        "attempt_count": 0,
        "worker_invocation_count": 0,
        "codex_as_worker_invocation_count": 0,
    }
    result["status"] = "PASS" if resolution.get("status") == "PASS" and static_binding.get("status") == "PASS" and result["static_symbol_binding_lock_match"] and canonicalization.get("status") == "PASS" and result["attempt_marker_absent"] and result["runtime_result_absent"] else "FAIL_CLOSED"
    guarded_json_once(
        runner_v35.STATIC_RUN / "locked-symbol-resolution-selftest-0001.json",
        result,
        operation_identity="LOCKED_SYMBOL_RESOLUTION_SELFTEST",
        generation="STATIC_LOCK_0001",
    )
    print(json.dumps({"status": result["status"], "symbols": resolution.get("symbol_count")}, sort_keys=True))
    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
