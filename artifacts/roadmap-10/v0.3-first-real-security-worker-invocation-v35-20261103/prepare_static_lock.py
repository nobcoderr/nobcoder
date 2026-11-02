"""Issue the single V35 static lock after every fresh gate passes."""
from __future__ import annotations
import hashlib,importlib.util,json,os,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parent;sys.dont_write_bytecode=True
if Path.cwd().resolve()!=ROOT: raise RuntimeError("V35_CANONICAL_CWD_REQUIRED")
_bindings=json.loads((ROOT/"contracts/CANONICAL_MODULE_BINDINGS.json").read_text())
_row=next(row for row in _bindings["modules"] if row["canonical_logical_module_name"]=="module_resolution_v35")
_path=Path(_row["canonical_source_path"])
if hashlib.sha256(_path.read_bytes()).hexdigest()!=_row["exact_source_sha256"]: raise RuntimeError("V35_MODULE_RESOLVER_DIGEST_MISMATCH")
_spec=importlib.util.spec_from_file_location("module_resolution_v35",_path)
if _spec is None or _spec.loader is None: raise RuntimeError("V35_MODULE_RESOLVER_SPEC_UNAVAILABLE")
_resolver=importlib.util.module_from_spec(_spec);sys.modules["module_resolution_v35"]=_resolver;_spec.loader.exec_module(_resolver)
_resolver.load_canonical_modules("STATIC_LOCK_PREPARATION",("workspace_boundary_v35","predecessor_binding_v35","external_artifact_binding_v35","binding_generation_v35","symbol_resolution_v35","mount_output_binding_v35","preflight_requirement_registry_v35","host_output_lifecycle_v35","prelock_storage_lifecycle_v35","runtime_acceptance_v35","artifact_finalization_v35","current_digest_view_v35","validator_helper_contract_v35","invocation_v35"))
from invocation_v35 import *  # noqa:E402,F403
from workspace_boundary_v35 import guarded_chmod
from host_output_lifecycle_v35 import host_output_bind_source_precheck
from prelock_storage_lifecycle_v35 import prelock_storage_lifecycle_precheck
from runtime_acceptance_v35 import typed_runtime_acceptance_precheck
from validator_helper_contract_v35 import critical_validator_helper_contract_precheck,require_typed_verdict

def canonical_root(rows):return hashlib.sha256("".join(f"{r['path']}\0{r['sha256']}\n" for r in rows).encode()).hexdigest()
def main()->int:
    if (ROOT/"STATIC_EXECUTION_LOCK.json").exists():raise RuntimeError("static lock exists")
    if any(STATIC_RUN.iterdir()):raise RuntimeError("static-run not empty")
    results={"unit":ROOT/"results/prelock/unit-fixtures-run-0001.json","primary":ROOT/"results/prelock/primary-static-validation-run-0001.json","independent":ROOT/"results/prelock/independent-static-validation-run-0001.json","preflight":ROOT/"results/prelock/fresh-preflight-run-0001.json","closure":ROOT/"results/prelock/dependency-closure-run-0001.json"}
    for name,path in results.items():
        value=load_json(path);expected="READY_FOR_FINAL_CLOSURE_CHECK" if name=="closure" else "PASS"
        if value.get("status")!=expected:raise RuntimeError(f"{name} not ready")
    if verify_v14_reference_predecessor().get("status")!="PASS" or verify_v15_reference_predecessor().get("status")!="PASS" or verify_v16_reference_predecessor().get("status")!="PASS" or verify_v17_reference_predecessor().get("status")!="PASS" or verify_v18_reference_predecessor().get("status")!="PASS" or verify_v19_reference_predecessor().get("status")!="PASS" or verify_v20_reference_predecessor().get("status")!="PASS" or verify_v24_reference_predecessor().get("status")!="PASS" or verify_v25_reference_predecessor().get("status")!="PASS" or verify_v26_reference_predecessor().get("status")!="PASS":raise RuntimeError("predecessor history drift")
    canonical_predecessor=canonical_predecessor_binding_precheck("STATIC_LOCK_PREPARATION")
    if canonical_predecessor.get("status")!="PASS":raise RuntimeError(f"canonical predecessor:{canonical_predecessor}")
    external_predecessor=external_predecessor_artifact_precheck("STATIC_LOCK_PREPARATION")
    if external_predecessor.get("status")!="PASS":raise RuntimeError(f"external predecessor artifact:{external_predecessor}")
    locked_generation=unified_binding_generation_precheck("LOCKED_RUNTIME")
    locked_digest_view=derived_current_expected_digest_view_precheck()
    locked_modules=canonical_module_resolution_precheck("LOCKED_RUNTIME")
    locked_predecessor=canonical_predecessor_binding_precheck("LOCKED_RUNTIME")
    locked_external=external_predecessor_artifact_precheck("LOCKED_RUNTIME")
    if any(value.get("status")!="PASS" for value in (locked_generation,locked_digest_view,locked_modules,locked_predecessor,locked_external)):
        raise RuntimeError("locked-runtime binding attestation failed before lock")
    symbols=static_symbol_binding_precheck()
    if symbols.get("status")!="PASS":raise RuntimeError(f"symbol binding:{symbols}")
    if v16_tree_canonicalization_precheck().get("status")!="PASS":raise RuntimeError("V16 canonicalization")
    if workspace_write_boundary_precheck().get("status")!="PASS":raise RuntimeError("workspace write boundary")
    if python_cache_policy_precheck().get("status")!="PASS":raise RuntimeError("python cache policy")
    artifact_finalization=authoritative_artifact_finalization_precheck()
    if artifact_finalization.get("status")!="PASS":raise RuntimeError(f"authoritative artifact finalization:{artifact_finalization}")
    host_output_lifecycle=host_output_bind_source_precheck("STATIC_LOCK_PREPARATION",require_current_empty=True)
    prelock_storage_lifecycle=prelock_storage_lifecycle_precheck("STATIC_LOCK_PREPARATION")
    typed_runtime_authority=typed_runtime_acceptance_precheck("STATIC_LOCK_PREPARATION")
    helper_return_contract=critical_validator_helper_contract_precheck()
    runtime_identity_verdict=require_typed_verdict(inspect_runtime_identity(),"inspect_runtime_identity")
    if host_output_lifecycle.get("status")!="PASS" or prelock_storage_lifecycle.get("status")!="PASS" or typed_runtime_authority.get("status")!="PASS" or helper_return_contract.get("status")!="PASS" or runtime_identity_verdict.get("status")!="PASS":raise RuntimeError("prelock/host output lifecycle, runtime authority, or typed helper verdict")
    locked_mount_output=mount_output_binding_precheck("LOCKED_RUNTIME")
    locked_typed_requirements=typed_preflight_requirement_precheck("LOCKED_RUNTIME")
    if locked_mount_output.get("status")!="PASS" or stale_mount_literal_precheck().get("status")!="PASS" or locked_typed_requirements.get("status")!="PASS":raise RuntimeError("mount/output or typed preflight binding")
    members=[]
    for relative in expected_lock_members():
        path=ROOT/relative
        if not safe_regular_file(path):raise RuntimeError(f"unsafe member:{relative}")
        members.append({"path":relative,"sha256":sha256_file(path),"bytes":path.stat().st_size})
    members.sort(key=lambda row:row["path"])
    for row in members:guarded_chmod(ROOT/row["path"],0o444,operation_identity="STATIC_LOCK_MEMBER_FREEZE",generation="STATIC_LOCK_0001")
    for directory in sorted({(ROOT/row["path"]).parent for row in members},key=lambda p:len(p.parts),reverse=True):
        if directory not in {ROOT,STATIC_RUN}:guarded_chmod(directory,0o555,operation_identity="STATIC_LOCK_DIRECTORY_FREEZE",generation="STATIC_LOCK_0001")
    closure=dependency_closure_snapshot()
    if closure.get("status")!="PASS":raise RuntimeError(f"closure:{closure}")
    manifest={"record_type":"V35_STATIC_SOURCE_MANIFEST","execution_identity":EXECUTION_IDENTITY,"status":"PASS_COMPLETE_DEPENDENCY_CLOSURE","member_count":len(members),"members":members,"canonical_source_root_sha256":canonical_root(members)}
    append_only_json(ROOT/"STATIC_SOURCE_MANIFEST.json",manifest);guarded_chmod(ROOT/"STATIC_SOURCE_MANIFEST.json",0o444,operation_identity="STATIC_SOURCE_MANIFEST_FREEZE",generation="STATIC_LOCK_0001")
    dry=STATIC_RUN/"locked-pre-attempt-validation-0001"
    lock={"record_type":"V35_STATIC_EXECUTION_LOCK","execution_identity":EXECUTION_IDENTITY,"authorization_id":AUTHORIZATION_ID,"status":"STATIC_LOCKED_NOT_EXECUTED","source_manifest_sha256":sha256_file(ROOT/"STATIC_SOURCE_MANIFEST.json"),"canonical_source_root_sha256":manifest["canonical_source_root_sha256"],"member_count":len(members),"unified_binding_generation_precheck_sha256":canonical_json_sha256(locked_generation),"canonical_module_resolution_precheck_sha256":canonical_json_sha256(locked_modules),"canonical_predecessor_binding_precheck_sha256":canonical_json_sha256(locked_predecessor),"canonical_predecessor_identity":canonical_predecessor.get("predecessor_identity"),"canonical_predecessor_tree_sha256":canonical_predecessor.get("workspace_tree_sha256"),"canonical_predecessor_static_lock_sha256":canonical_predecessor.get("static_execution_lock_sha256"),"workspace_write_boundary_precheck_sha256":canonical_json_sha256(workspace_write_boundary_precheck()),"python_cache_policy_precheck_sha256":canonical_json_sha256(python_cache_policy_precheck()),"host_output_bind_source_lifecycle_precheck_sha256":canonical_json_sha256(host_output_lifecycle),"typed_runtime_acceptance_precheck_sha256":canonical_json_sha256(typed_runtime_authority),"mount_output_identity_precheck_sha256":canonical_json_sha256(locked_mount_output),"typed_preflight_requirement_precheck_sha256":canonical_json_sha256(locked_typed_requirements),"static_symbol_binding_precheck_sha256":canonical_json_sha256(symbols),"v16_tree_canonicalization_precheck_sha256":canonical_json_sha256(v16_tree_canonicalization_precheck()),"python_environment_sha256":canonical_json_sha256(exact_python_environment()),"strace_argv_sha256":canonical_json_sha256(strace_argv()),"dry_strace_argv_sha256":canonical_json_sha256(strace_argv(dry)),"environment_sha256":canonical_json_sha256(exact_environment()),"temporal_observer_argv_sha256":canonical_json_sha256(temporal_observer_argv()),"dry_temporal_observer_argv_sha256":canonical_json_sha256(temporal_observer_argv(dry)),"bind_destination_feasibility_precheck_sha256":canonical_json_sha256(bind_destination_feasibility_precheck(bwrap_argv())),"strict_schema_compatibility_precheck_sha256":canonical_json_sha256(strict_schema_compatibility_precheck()),"typed_fd_annotation_grammar_precheck_sha256":canonical_json_sha256(typed_fd_annotation_grammar_precheck()),"cross_namespace_process_identity_precheck_sha256":canonical_json_sha256(process_identity_correlation_precheck()),"temporal_process_identity_observer_precheck_sha256":canonical_json_sha256(temporal_process_identity_observer_precheck()),"semantic_startup_lineage_precheck_sha256":canonical_json_sha256(startup_lineage_policy_precheck()),"mount_provenance_write_precheck_sha256":canonical_json_sha256(mount_provenance_policy_precheck("LOCKED_RUNTIME")),"typed_token_budget_precheck_sha256":canonical_json_sha256(token_budget_feasibility_precheck()),"prompt_identity_binding_precheck_sha256":canonical_json_sha256(prompt_identity_binding_precheck()),"authoritative_artifact_digest_precheck_sha256":canonical_json_sha256(authoritative_artifact_digest_precheck()),"authoritative_predecessor_resolution_precheck_sha256":canonical_json_sha256(authoritative_predecessor_resolution_precheck()),"semantic_lifecycle_anchor_sha256":canonical_json_sha256(semantic_lifecycle_anchor_verdict((ROOT/"src/runner_v35.py").read_text(encoding="utf-8"))),"successor_governance_lock_sha256":EXPECTED_DIGESTS["v35_authorization_lock"],"v16_workspace_tree_root_sha256":V16_WORKSPACE_TREE_ROOT,"v16_failure_manifest_sha256":V16_FAILURE_MANIFEST_SHA256,"v17_workspace_tree_root_sha256":V17_WORKSPACE_TREE_ROOT,"v18_workspace_tree_root_sha256":"c92f0bd0d7ea111d9bfd6d3d4e612e5b1cd763d70c69f47fef6a2907c0be0f4d","validation_evidence":{name:{"path":path.relative_to(ROOT).as_posix(),"sha256":sha256_file(path),"status":load_json(path).get("status")} for name,path in results.items()},"dependency_closure":closure,"attempt_count":0,"worker_invocation_count":0,"codex_as_worker_invocation_count":0}
    lock["authoritative_artifact_finalization_precheck_sha256"]=canonical_json_sha256(artifact_finalization)
    lock["derived_current_expected_digest_view_precheck_sha256"]=canonical_json_sha256(locked_digest_view)
    lock["external_predecessor_artifact_precheck_sha256"]=canonical_json_sha256(locked_external)
    lock["typed_validator_helper_return_contract_precheck_sha256"]=canonical_json_sha256(helper_return_contract)
    lock["runtime_identity_typed_verdict_sha256"]=canonical_json_sha256(runtime_identity_verdict)
    append_only_json(ROOT/"STATIC_EXECUTION_LOCK.json",lock);guarded_chmod(ROOT/"STATIC_EXECUTION_LOCK.json",0o444,operation_identity="STATIC_EXECUTION_LOCK_FREEZE",generation="STATIC_LOCK_0001")
    print(json.dumps({"status":lock["status"],"members":len(members),"root":manifest["canonical_source_root_sha256"]},sort_keys=True));return 0
if __name__=="__main__":raise SystemExit(main())
