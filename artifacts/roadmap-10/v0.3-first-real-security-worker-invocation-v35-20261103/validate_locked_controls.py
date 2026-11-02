#!/usr/bin/env python3
"""Validate locked Python/cache and workspace-write-boundary controls."""

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
     "preflight_requirement_registry_v35", "host_output_lifecycle_v35", "prelock_storage_lifecycle_v35", "runtime_acceptance_v35", "current_digest_view_v35", "validator_helper_contract_v35", "invocation_v35"),
)

from invocation_v35 import (  # noqa: E402
    STATIC_RUN,
    canonical_json_sha256,
    load_json,
    python_cache_policy_precheck,
    workspace_write_boundary_precheck,
)
from workspace_boundary_v35 import guarded_json_once  # noqa: E402
from mount_output_binding_v35 import mount_output_binding_precheck, stale_mount_literal_precheck  # noqa: E402
from preflight_requirement_registry_v35 import typed_preflight_requirement_precheck  # noqa: E402
from host_output_lifecycle_v35 import host_output_bind_source_precheck  # noqa: E402
from prelock_storage_lifecycle_v35 import prelock_storage_lifecycle_precheck  # noqa: E402
from runtime_acceptance_v35 import typed_runtime_acceptance_precheck  # noqa: E402
from validator_helper_contract_v35 import critical_validator_helper_contract_precheck, require_typed_verdict  # noqa: E402
from invocation_v35 import inspect_runtime_identity  # noqa: E402


def main() -> int:
    lock = load_json(ROOT / "STATIC_EXECUTION_LOCK.json")
    boundary = workspace_write_boundary_precheck()
    cache = python_cache_policy_precheck()
    mount_output = mount_output_binding_precheck("LOCKED_RUNTIME")
    stale_mounts = stale_mount_literal_precheck()
    typed_requirements = typed_preflight_requirement_precheck("LOCKED_RUNTIME")
    host_output = host_output_bind_source_precheck("LOCKED_RUNTIME")
    prelock_storage = prelock_storage_lifecycle_precheck("LOCKED_RUNTIME")
    runtime_authority = typed_runtime_acceptance_precheck("LOCKED_RUNTIME")
    helper_return_contract = critical_validator_helper_contract_precheck()
    runtime_identity_verdict = require_typed_verdict(inspect_runtime_identity(), "inspect_runtime_identity")
    checks = {
        "workspace_boundary_pass": boundary.get("status") == "PASS",
        "workspace_boundary_locked": lock.get("workspace_write_boundary_precheck_sha256")
        == canonical_json_sha256(boundary),
        "python_cache_policy_pass": cache.get("status") == "PASS",
        "python_cache_policy_locked": lock.get("python_cache_policy_precheck_sha256")
        == canonical_json_sha256(cache),
        "unaccounted_filesystem_mutations_zero": cache.get("unaccounted_filesystem_mutation_count") == 0,
        "mount_output_identity_pass": mount_output.get("status") == "PASS",
        "mount_output_identity_locked": lock.get("mount_output_identity_precheck_sha256") == canonical_json_sha256(mount_output),
        "zero_stale_mount_bindings": stale_mounts.get("status") == "PASS",
        "typed_preflight_requirements_pass": typed_requirements.get("status") == "PASS",
        "typed_preflight_requirements_locked": lock.get("typed_preflight_requirement_precheck_sha256") == canonical_json_sha256(typed_requirements),
        "host_output_bind_source_pass": host_output.get("status") == "PASS",
        "prelock_storage_lifecycle_pass": prelock_storage.get("status") == "PASS",
        "host_output_bind_source_locked": lock.get("host_output_bind_source_lifecycle_precheck_sha256")
        == canonical_json_sha256(host_output_bind_source_precheck("STATIC_LOCK_PREPARATION")),
        "typed_runtime_authority_pass": runtime_authority.get("status") == "PASS",
        "typed_runtime_authority_locked": lock.get("typed_runtime_acceptance_precheck_sha256")
        == canonical_json_sha256(typed_runtime_acceptance_precheck("STATIC_LOCK_PREPARATION")),
        "typed_validator_helper_return_contract_pass": helper_return_contract.get("status") == "PASS",
        "typed_validator_helper_return_contract_locked": lock.get("typed_validator_helper_return_contract_precheck_sha256") == canonical_json_sha256(helper_return_contract),
        "runtime_identity_typed_verdict_pass": runtime_identity_verdict.get("status") == "PASS",
        "runtime_identity_typed_verdict_locked": lock.get("runtime_identity_typed_verdict_sha256") == canonical_json_sha256(runtime_identity_verdict),
        "attempt_marker_absent": not (STATIC_RUN / "ATTEMPT_MARKER.json").exists(),
        "runtime_result_absent": not (STATIC_RUN / "runtime-result-0001.json").exists(),
    }
    result = {
        "record_type": "V35_LOCKED_PYTHON_CACHE_AND_WORKSPACE_BOUNDARY_VALIDATION",
        "execution_identity": "V0_3_FIRST_REAL_SECURITY_WORKER_INVOCATION_V35",
        "status": "PASS" if all(checks.values()) else "FAIL_CLOSED_BEFORE_ATTEMPT",
        "checks": checks,
        "workspace_boundary": boundary,
        "python_cache_policy": cache,
        "mount_output_identity": mount_output,
        "stale_mount_binding_check": stale_mounts,
        "typed_preflight_requirements": typed_requirements,
        "host_output_bind_source": host_output,
        "typed_runtime_authority": runtime_authority,
        "typed_validator_helper_return_contract": helper_return_contract,
        "runtime_identity_typed_verdict": runtime_identity_verdict,
        "attempt_count": 0,
        "worker_invocation_count": 0,
        "codex_as_worker_invocation_count": 0,
    }
    guarded_json_once(
        STATIC_RUN / "locked-python-cache-workspace-boundary-validation-0001.json",
        result,
        operation_identity="LOCKED_PYTHON_CACHE_AND_WORKSPACE_BOUNDARY_VALIDATION",
        generation="STATIC_LOCK_0001",
    )
    print(json.dumps({"status": result["status"]}, sort_keys=True))
    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
