"""Primary static validation for fresh V35; never invokes Codex."""
from __future__ import annotations

import ast
import hashlib
import importlib.util
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.dont_write_bytecode = True
if Path.cwd().resolve() != ROOT:
    raise RuntimeError("V35_CANONICAL_CWD_REQUIRED")
_bindings = json.loads((ROOT / "contracts/CANONICAL_MODULE_BINDINGS.json").read_text())
_row = next(row for row in _bindings["modules"] if row["canonical_logical_module_name"] == "module_resolution_v35")
_resolver_path = Path(_row["canonical_source_path"])
if hashlib.sha256(_resolver_path.read_bytes()).hexdigest() != _row["exact_source_sha256"]:
    raise RuntimeError("V35_MODULE_RESOLVER_DIGEST_MISMATCH")
_spec = importlib.util.spec_from_file_location("module_resolution_v35", _resolver_path)
if _spec is None or _spec.loader is None:
    raise RuntimeError("V35_MODULE_RESOLVER_SPEC_UNAVAILABLE")
_resolver = importlib.util.module_from_spec(_spec)
sys.modules["module_resolution_v35"] = _resolver
_spec.loader.exec_module(_resolver)
_resolver.load_canonical_modules(
    "PRIMARY_VALIDATOR",
    ("workspace_boundary_v35", "predecessor_binding_v35", "external_artifact_binding_v35", "binding_generation_v35",
     "historical_decision_registry_v35", "transactional_telemetry_v35", "symbol_resolution_v35",
     "mount_output_binding_v35", "preflight_requirement_registry_v35", "host_output_lifecycle_v35", "prelock_storage_lifecycle_v35", "runtime_acceptance_v35", "artifact_finalization_v35", "current_digest_view_v35", "validator_helper_contract_v35", "invocation_v35"),
)

from invocation_v35 import (  # noqa: E402
    AUTHORIZATION_ID, EXECUTION_IDENTITY, PREDECESSOR_PATHS, STATIC_RUN,
    append_only_json, authoritative_artifact_digest_precheck,
    authoritative_artifact_finalization_precheck,
    authoritative_predecessor_resolution_precheck, bind_destination_feasibility_precheck,
    bwrap_argv, fresh_preflight, inspect_runtime_identity,
    mount_provenance_policy_precheck, process_identity_correlation_precheck,
    independently_validate_coverage_accounting, observer_diagnostic_verdict,
    prompt_identity_binding_precheck, sha256_file, startup_lineage_policy_precheck,
    python_cache_policy_precheck,
    semantic_lifecycle_anchor_verdict,
    strict_schema_compatibility_precheck, temporal_process_identity_observer_precheck,
    token_budget_feasibility_precheck, typed_fd_annotation_grammar_precheck,
    verify_v12_reference_predecessor, verify_v13_reference_predecessor,
    verify_v14_reference_predecessor, verify_v15_reference_predecessor,
    verify_v16_reference_predecessor, verify_v17_reference_predecessor,
    verify_v18_reference_predecessor,
    verify_v19_reference_predecessor,
    verify_v20_reference_predecessor,
    verify_v24_reference_predecessor,
    verify_v25_reference_predecessor,
    verify_v26_reference_predecessor,
    canonical_predecessor_binding_precheck,
    external_predecessor_artifact_precheck,
    static_symbol_binding_precheck,
    v16_tree_canonicalization_precheck,
    workspace_write_boundary_precheck,
    unified_binding_generation_precheck,
    derived_current_expected_digest_view_precheck,
)
from module_resolution_v35 import canonical_module_resolution_precheck
from historical_decision_registry_v35 import historical_decision_relation_precheck
from mount_output_binding_v35 import mount_output_binding_precheck, stale_mount_literal_precheck
from preflight_requirement_registry_v35 import typed_preflight_requirement_precheck
from host_output_lifecycle_v35 import host_output_bind_source_precheck
from prelock_storage_lifecycle_v35 import prelock_storage_lifecycle_precheck
from runtime_acceptance_v35 import typed_runtime_acceptance_precheck
from validator_helper_contract_v35 import (
    critical_validator_helper_contract_precheck,
    require_typed_verdict,
)
from transactional_telemetry_v35 import TelemetryCompletionError, consume_completed_json


def main() -> int:
    checks: list[dict[str, object]] = []
    def check(identity: str, ok: bool, evidence: object | None = None) -> None:
        checks.append({"id": identity, "status": "PASS" if ok else "FAIL", "evidence": evidence})

    unit = json.loads((ROOT / "results/prelock/unit-fixtures-run-0001.json").read_text())
    check("S001_UNIT_PASS", unit.get("status") == "PASS", unit.get("validation_counts"))
    check("S002_EXECUTION_IDENTITY", EXECUTION_IDENTITY == "V0_3_FIRST_REAL_SECURITY_WORKER_INVOCATION_V35")
    check("S003_AUTHORIZATION_IDENTITY", AUTHORIZATION_ID == "V0_3_FIRST_REAL_SECURITY_WORKER_INVOCATION_V34_PRELOCK_RESULTS_DIRECTORY_AND_FIXTURE_PROBE_PATH_LIFECYCLE_DEFECT_UNIT_EXECUTION_ERRATUM_AND_SUCCESSOR_DECISION_GOVERNANCE_ONLY")
    check("S004_GOVERNANCE_LOCK", sha256_file(PREDECESSOR_PATHS["v35_authorization_lock"]) == "d2263268f61b9ddde99a0b60f4b43a26df1586e0c577ba2ca98c07b64c21f811")
    storage_lifecycle = prelock_storage_lifecycle_precheck("PRIMARY_VALIDATOR")
    check("S004P_PRELOCK_STORAGE_LIFECYCLE", storage_lifecycle.get("status") == "PASS", storage_lifecycle)
    generation = unified_binding_generation_precheck("PRIMARY_VALIDATOR"); check("S004A_UNIFIED_BINDING_GENERATION", generation.get("status") == "PASS", generation)
    digest_view = derived_current_expected_digest_view_precheck(); check("S004A2_DERIVED_CURRENT_EXPECTED_DIGEST_VIEW", digest_view.get("status") == "PASS", digest_view)
    relations = historical_decision_relation_precheck(); check("S004B_HISTORICAL_DECISION_RELATIONS", relations.get("status") == "PASS", relations)
    v12 = verify_v12_reference_predecessor(); check("S005_V12_IMMUTABLE", v12.get("status") == "PASS", v12)
    v13 = verify_v13_reference_predecessor(); check("S006_V13_IMMUTABLE", v13.get("status") == "PASS", v13)
    v14 = verify_v14_reference_predecessor(); check("S007_V14_IMMUTABLE", v14.get("status") == "PASS", v14)
    v15 = verify_v15_reference_predecessor(); check("S008_V15_IMMUTABLE", v15.get("status") == "PASS", v15)
    v16 = verify_v16_reference_predecessor(); check("S008A_V16_IMMUTABLE", v16.get("status") == "PASS", v16)
    v17 = verify_v17_reference_predecessor(); check("S008B_V17_IMMUTABLE", v17.get("status") == "PASS", v17)
    v18 = verify_v18_reference_predecessor(); check("S008C_V18_IMMUTABLE", v18.get("status") == "PASS", v18)
    v19 = verify_v19_reference_predecessor(); check("S008C2_V19_IMMUTABLE_HISTORY", v19.get("status") == "PASS", v19)
    v20 = verify_v20_reference_predecessor(); check("S008C2B_V20_IMMUTABLE_HISTORY", v20.get("status") == "PASS", v20)
    v24 = verify_v24_reference_predecessor(); check("S008C2C_V24_IMMUTABLE_HISTORY", v24.get("status") == "PASS", v24)
    v25 = verify_v25_reference_predecessor(); check("S008C2D_V25_IMMUTABLE_HISTORY", v25.get("status") == "PASS", v25)
    v26 = verify_v26_reference_predecessor(); check("S008C2E_V26_IMMUTABLE_HISTORY", v26.get("status") == "PASS", v26)
    canonical_predecessor = canonical_predecessor_binding_precheck("PRIMARY_VALIDATOR"); check("S008C3_CANONICAL_PREDECESSOR", canonical_predecessor.get("status") == "PASS", canonical_predecessor)
    external_predecessor = external_predecessor_artifact_precheck("PRIMARY_VALIDATOR"); check("S008C4_EXTERNAL_PREDECESSOR_ARTIFACTS", external_predecessor.get("status") == "PASS", external_predecessor)
    module_resolution = canonical_module_resolution_precheck("PRIMARY_VALIDATOR"); check("S008C5_CANONICAL_MODULE_RESOLUTION", module_resolution.get("status") == "PASS", module_resolution)
    symbols = static_symbol_binding_precheck(); check("S008D_SYMBOL_BINDINGS", symbols.get("status") == "PASS", symbols)
    finalization = authoritative_artifact_finalization_precheck(); check("S008D2_AUTHORITATIVE_ARTIFACT_FINALIZATION", finalization.get("status") == "PASS", finalization)
    helper_contract = critical_validator_helper_contract_precheck(); check("S008D3_TYPED_VALIDATOR_HELPER_RETURN_CONTRACT", helper_contract.get("status") == "PASS", helper_contract)
    canonicalization = v16_tree_canonicalization_precheck(); check("S008E_V16_NORMATIVE_CANONICALIZATION", canonicalization.get("status") == "PASS", canonicalization)
    boundary = workspace_write_boundary_precheck(); check("S009_FAIL_BEFORE_WRITE_BOUNDARY", boundary.get("status") == "PASS", boundary)
    bind_source_lifecycle = host_output_bind_source_precheck("PRIMARY_VALIDATOR", require_current_empty=True)
    check("S009B_HOST_OUTPUT_BIND_SOURCE_LIFECYCLE", bind_source_lifecycle.get("status") == "PASS", bind_source_lifecycle)
    runtime_authority = typed_runtime_acceptance_precheck("PRIMARY_VALIDATOR")
    check("S009C_TYPED_CURRENT_RUNTIME_AUTHORITY", runtime_authority.get("status") == "PASS", runtime_authority)
    cache = python_cache_policy_precheck(); check("S009A_PYTHON_CACHE_POLICY", cache.get("status") == "PASS", cache)
    for name, verdict in (
        ("RUNTIME", require_typed_verdict(inspect_runtime_identity(), "inspect_runtime_identity")), ("ARTIFACT", authoritative_artifact_digest_precheck()),
        ("PROMPT", prompt_identity_binding_precheck()), ("PREDECESSOR", authoritative_predecessor_resolution_precheck()),
        ("BIND", bind_destination_feasibility_precheck(bwrap_argv())), ("SCHEMA", strict_schema_compatibility_precheck()),
        ("FD", typed_fd_annotation_grammar_precheck()), ("STARTUP", startup_lineage_policy_precheck()),
        ("PROCESS", process_identity_correlation_precheck()), ("OBSERVER", temporal_process_identity_observer_precheck()),
        ("MOUNT", mount_provenance_policy_precheck("PRIMARY_VALIDATOR")), ("BUDGET", token_budget_feasibility_precheck()),
    ):
        check(f"S_{name}", verdict.get("status") == "PASS", verdict)
    mount_identity = mount_output_binding_precheck("PRIMARY_VALIDATOR")
    check("S_MOUNT_OUTPUT_GENERATION", mount_identity.get("status") == "PASS", mount_identity)
    stale_mounts = stale_mount_literal_precheck()
    check("S_ZERO_STALE_MOUNT_BINDINGS", stale_mounts.get("status") == "PASS", stale_mounts)
    typed_requirements = typed_preflight_requirement_precheck("PRIMARY_VALIDATOR")
    check("S_TYPED_PREFLIGHT_REQUIREMENTS", typed_requirements.get("status") == "PASS", typed_requirements)
    invariant = json.loads((ROOT / "contracts/COMPLETE_COVERAGE_INVARIANT.json").read_text())
    check("S020_COMPLETE_COVERAGE_ONLY", typed_requirements.get("status") == "PASS" and invariant.get("percentage_thresholds") == "PROHIBITED" and invariant.get("n_minus_one") == "FAIL_CLOSED")
    corpus = ROOT / "results/prelock/adversarial-selftests-run-0001"
    for mode in ("long-lived", "sequential", "overlapping", "immediate", "nested"):
        result_path = corpus / f"{mode}-0001-result.json"
        snapshot_path = corpus / f"{mode}-0001/snapshot.json"
        trace_dir = corpus / f"{mode}-0001/traces"
        result = json.loads(result_path.read_text()) if result_path.is_file() else {}
        try:
            snapshot = consume_completed_json(
                snapshot_path,
                expected_producer_identity="V35_PROC_CONNECTOR_EVENT_BOUND_PROCESS_IDENTITY_OBSERVER_V1",
                expected_fixture_identity=f"{mode}-0001",
                expected_schema_identity="V35_COMPLETE_TEMPORALLY_BOUND_PROCESS_IDENTITY_OBSERVER_SNAPSHOT",
            )
        except TelemetryCompletionError:
            snapshot = {}
        trace_ids = sorted(int(path.name.rsplit(".", 1)[1]) for path in trace_dir.glob("trace.*") if path.name.rsplit(".", 1)[-1].isdigit())
        accounting = independently_validate_coverage_accounting(trace_ids, snapshot.get("coverage_accounting", {}))
        check(f"S_SELFTEST_{mode}", result.get("status") == "PASS" and observer_diagnostic_verdict(result).get("status") == "PASS" and accounting.get("status") == "PASS", {"result": result, "accounting": accounting})
    runner = (ROOT / "src/runner_v35.py").read_text(); observer = (ROOT / "src/topology_observer_v35.py").read_text()
    check("S021_EVENT_BOUND_CAPTURE", "class ProcConnector" in observer and "PROC_CN_MCAST_LISTEN" in observer)
    check("S022_STABLE_IDENTITY", "process_start_identity" in observer and "pid_namespace_identity" in observer)
    check("S022A_DIAGNOSTIC_TELEMETRY", all(token in observer for token in ("identity_capture_attempt_count", "observer_exit_reason", "per_trace_capture_accounting", "trace_first_timestamp")))
    lifecycle = semantic_lifecycle_anchor_verdict(runner)
    check("S023_LIFECYCLE_SOURCE_ORDER", lifecycle.get("status") == "PASS", lifecycle)
    for index, path in enumerate(sorted([*ROOT.glob("*.py"), *(ROOT/"src").glob("*.py"), *(ROOT/"validators").glob("*.py"), *(ROOT/"tests").glob("*.py")]), 30):
        try: ast.parse(path.read_text()); ok=True
        except SyntaxError: ok=False
        check(f"S{index:03d}_AST_{path.name}", ok)
    check("S060_ATTEMPT_ABSENT", not (STATIC_RUN/"ATTEMPT_MARKER.json").exists())
    check("S061_RUNTIME_ABSENT", not (STATIC_RUN/"runtime-result-0001.json").exists())
    check("S062_STATIC_LOCK_ABSENT", not (ROOT/"STATIC_EXECUTION_LOCK.json").exists())
    check("S063_STATIC_RUN_EMPTY", not any(STATIC_RUN.iterdir()))
    snapshot = fresh_preflight(False); check("S064_CORE_PREFLIGHT", snapshot.get("status") == "PASS", snapshot.get("failure_ids"))
    failures=[row["id"] for row in checks if row["status"]=="FAIL"]
    result={"record_type":"V35_PRIMARY_STATIC_VALIDATION","execution_identity":EXECUTION_IDENTITY,"status":"PASS" if not failures else "FAIL_CLOSED","checks":checks,"failure_ids":failures,"validation_counts":{"total":len(checks),"passed":len(checks)-len(failures),"failed":len(failures)},"attempt_count":0,"worker_invocation_count":0,"codex_as_worker_invocation_count":0}
    append_only_json(ROOT/"results/prelock/primary-static-validation-run-0001.json",result)
    print(json.dumps(result["validation_counts"],sort_keys=True)); return 0 if not failures else 1


if __name__ == "__main__": raise SystemExit(main())
