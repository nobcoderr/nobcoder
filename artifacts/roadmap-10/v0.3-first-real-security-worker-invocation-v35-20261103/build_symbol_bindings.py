#!/usr/bin/env python3
"""Create the final AST/import-graph symbol binding manifest exactly once."""

from __future__ import annotations

import json
import hashlib
import importlib.util
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
_resolver = importlib.util.module_from_spec(_spec); sys.modules["module_resolution_v35"] = _resolver; _spec.loader.exec_module(_resolver)
_resolver.load_canonical_modules(
    "BUILDER",
    ("workspace_boundary_v35", "predecessor_binding_v35", "external_artifact_binding_v35", "binding_generation_v35",
     "historical_decision_registry_v35", "transactional_telemetry_v35", "symbol_resolution_v35",
     "mount_output_binding_v35", "preflight_requirement_registry_v35", "host_output_lifecycle_v35", "prelock_storage_lifecycle_v35", "runtime_acceptance_v35", "artifact_finalization_v35", "current_digest_view_v35", "validator_helper_contract_v35", "invocation_v35"),
)

from symbol_resolution_v35 import build_symbol_manifest  # noqa: E402
from workspace_boundary_v35 import guarded_chmod, guarded_json_once  # noqa: E402


def main() -> int:
    result = build_symbol_manifest()
    if result.get("status") != "PASS":
        raise RuntimeError(f"symbol manifest is not complete: {result.get('failures')}")
    output = ROOT / "contracts/LOCKED_ENTRYPOINT_SYMBOL_BINDING_MANIFEST.json"
    guarded_json_once(
        output,
        result,
        operation_identity="BUILD_LOCKED_ENTRYPOINT_SYMBOL_BINDING_MANIFEST",
        generation="FINAL_TYPED_SYMBOL_GRAPH_V35",
    )
    guarded_chmod(
        output,
        0o444,
        operation_identity="FREEZE_LOCKED_ENTRYPOINT_SYMBOL_BINDING_MANIFEST",
        generation="FINAL_TYPED_SYMBOL_GRAPH_V35",
    )
    print(json.dumps({"status": result["status"], "symbols": result["symbol_count"]}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
