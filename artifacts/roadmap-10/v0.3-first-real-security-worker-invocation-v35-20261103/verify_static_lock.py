"""Independent full V35 static-lock verification."""
from __future__ import annotations
import hashlib,importlib.util,json,os,stat,sys
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
_resolver.load_canonical_modules("STATIC_LOCK_VERIFICATION",("workspace_boundary_v35","predecessor_binding_v35","external_artifact_binding_v35","binding_generation_v35","symbol_resolution_v35","mount_output_binding_v35","preflight_requirement_registry_v35","host_output_lifecycle_v35","prelock_storage_lifecycle_v35","runtime_acceptance_v35","artifact_finalization_v35","current_digest_view_v35","validator_helper_contract_v35","invocation_v35"))
from invocation_v35 import *  # noqa:E402,F403
from workspace_boundary_v35 import guarded_chmod
from host_output_lifecycle_v35 import host_output_bind_source_precheck
from runtime_acceptance_v35 import typed_runtime_acceptance_precheck
from validator_helper_contract_v35 import critical_validator_helper_contract_precheck,require_typed_verdict
def main()->int:
    lock=load_json(ROOT/"STATIC_EXECUTION_LOCK.json");manifest=load_json(ROOT/"STATIC_SOURCE_MANIFEST.json");checks=[]
    def check(name,ok,evidence=None):checks.append({"id":name,"status":"PASS" if ok else "FAIL","evidence":evidence})
    check("L001_LOCK_STATE",lock.get("status")=="STATIC_LOCKED_NOT_EXECUTED");check("L002_MANIFEST_DIGEST",lock.get("source_manifest_sha256")==sha256_file(ROOT/"STATIC_SOURCE_MANIFEST.json"))
    rows=manifest.get("members",[]);check("L003_COUNT",len(rows)==manifest.get("member_count")==lock.get("member_count"))
    root=hashlib.sha256("".join(f"{r['path']}\0{r['sha256']}\n" for r in rows).encode()).hexdigest();check("L004_ROOT",root==manifest.get("canonical_source_root_sha256")==lock.get("canonical_source_root_sha256"))
    for index,row in enumerate(rows,5):
        path=ROOT/row["path"];check(f"L{index:03d}_MEMBER_{row['path']}",safe_regular_file(path) and sha256_file(path)==row["sha256"] and stat.S_IMODE(path.stat().st_mode)&0o222==0)
    dry=STATIC_RUN/"locked-pre-attempt-validation-0001"
    canonical_predecessor=canonical_predecessor_binding_precheck("LOCKED_RUNTIME")
    unified_generation=unified_binding_generation_precheck("LOCKED_RUNTIME")
    derived_digest_view=derived_current_expected_digest_view_precheck()
    canonical_modules=canonical_module_resolution_precheck("LOCKED_RUNTIME")
    external_predecessor=external_predecessor_artifact_precheck("STATIC_LOCK_VERIFICATION")
    external_predecessor_lock=external_predecessor_artifact_precheck("LOCKED_RUNTIME")
    host_output_lifecycle=host_output_bind_source_precheck("STATIC_LOCK_PREPARATION")
    typed_runtime_authority=typed_runtime_acceptance_precheck("STATIC_LOCK_PREPARATION")
    artifact_finalization=authoritative_artifact_finalization_precheck()
    helper_return_contract=critical_validator_helper_contract_precheck()
    runtime_identity_verdict=require_typed_verdict(inspect_runtime_identity(),"inspect_runtime_identity")
    semantic={"UNIFIED_BINDING_GENERATION":unified_generation.get("status")=="PASS" and lock.get("unified_binding_generation_precheck_sha256")==canonical_json_sha256(unified_generation),"CANONICAL_MODULE_RESOLUTION":canonical_modules.get("status")=="PASS" and lock.get("canonical_module_resolution_precheck_sha256")==canonical_json_sha256(canonical_modules),"CANONICAL_PREDECESSOR":lock.get("canonical_predecessor_binding_precheck_sha256")==canonical_json_sha256(canonical_predecessor) and canonical_predecessor.get("status")=="PASS","WORKSPACE_BOUNDARY":lock.get("workspace_write_boundary_precheck_sha256")==canonical_json_sha256(workspace_write_boundary_precheck()),"PYTHON_CACHE":lock.get("python_cache_policy_precheck_sha256")==canonical_json_sha256(python_cache_policy_precheck()),"HOST_OUTPUT_BIND_SOURCE_LIFECYCLE":host_output_lifecycle.get("status")=="PASS" and lock.get("host_output_bind_source_lifecycle_precheck_sha256")==canonical_json_sha256(host_output_lifecycle),"TYPED_RUNTIME_ACCEPTANCE":typed_runtime_authority.get("status")=="PASS" and lock.get("typed_runtime_acceptance_precheck_sha256")==canonical_json_sha256(typed_runtime_authority),"MOUNT_OUTPUT_IDENTITY":lock.get("mount_output_identity_precheck_sha256")==canonical_json_sha256(mount_output_binding_precheck("LOCKED_RUNTIME")),"TYPED_PREFLIGHT_REQUIREMENTS":lock.get("typed_preflight_requirement_precheck_sha256")==canonical_json_sha256(typed_preflight_requirement_precheck("LOCKED_RUNTIME")),"ZERO_STALE_MOUNT_BINDINGS":stale_mount_literal_precheck().get("status")=="PASS","MOUNT_PROVENANCE":lock.get("mount_provenance_write_precheck_sha256")==canonical_json_sha256(mount_provenance_policy_precheck("LOCKED_RUNTIME")),"SYMBOL_BINDING":lock.get("static_symbol_binding_precheck_sha256")==canonical_json_sha256(static_symbol_binding_precheck()),"V16_CANONICALIZATION":lock.get("v16_tree_canonicalization_precheck_sha256")==canonical_json_sha256(v16_tree_canonicalization_precheck()),"PYTHON_ENV":lock.get("python_environment_sha256")==canonical_json_sha256(exact_python_environment()),"EXEC_ARGV":lock.get("strace_argv_sha256")==canonical_json_sha256(strace_argv()),"DRY_ARGV":lock.get("dry_strace_argv_sha256")==canonical_json_sha256(strace_argv(dry)),"OBSERVER":lock.get("temporal_observer_argv_sha256")==canonical_json_sha256(temporal_observer_argv()),"DRY_OBSERVER":lock.get("dry_temporal_observer_argv_sha256")==canonical_json_sha256(temporal_observer_argv(dry)),"ENV":lock.get("environment_sha256")==canonical_json_sha256(exact_environment()),"PROCESS":lock.get("cross_namespace_process_identity_precheck_sha256")==canonical_json_sha256(process_identity_correlation_precheck()),"TEMPORAL":lock.get("temporal_process_identity_observer_precheck_sha256")==canonical_json_sha256(temporal_process_identity_observer_precheck()),"ARTIFACT":lock.get("authoritative_artifact_digest_precheck_sha256")==canonical_json_sha256(authoritative_artifact_digest_precheck()),"PREDECESSOR":lock.get("authoritative_predecessor_resolution_precheck_sha256")==canonical_json_sha256(authoritative_predecessor_resolution_precheck())}
    for name,ok in semantic.items():check(f"L_{name}",ok)
    check("L_DERIVED_CURRENT_EXPECTED_DIGEST_VIEW",derived_digest_view.get("status")=="PASS" and lock.get("derived_current_expected_digest_view_precheck_sha256")==canonical_json_sha256(derived_digest_view),derived_digest_view)
    check("L_AUTHORITATIVE_ARTIFACT_FINALIZATION",artifact_finalization.get("status")=="PASS" and lock.get("authoritative_artifact_finalization_precheck_sha256")==canonical_json_sha256(artifact_finalization),artifact_finalization)
    check("L_TYPED_VALIDATOR_HELPER_RETURN_CONTRACT",helper_return_contract.get("status")=="PASS" and lock.get("typed_validator_helper_return_contract_precheck_sha256")==canonical_json_sha256(helper_return_contract),helper_return_contract)
    check("L_RUNTIME_IDENTITY_TYPED_VERDICT",runtime_identity_verdict.get("status")=="PASS" and lock.get("runtime_identity_typed_verdict_sha256")==canonical_json_sha256(runtime_identity_verdict),runtime_identity_verdict)
    check("L_EXTERNAL_PREDECESSOR",external_predecessor.get("status")=="PASS" and lock.get("external_predecessor_artifact_precheck_sha256")==canonical_json_sha256(external_predecessor_lock),external_predecessor)
    check("L_V14",verify_v14_reference_predecessor().get("status")=="PASS")
    check("L_V15",verify_v15_reference_predecessor().get("status")=="PASS")
    check("L_V16",verify_v16_reference_predecessor().get("status")=="PASS")
    check("L_V17",verify_v17_reference_predecessor().get("status")=="PASS")
    check("L_V18",verify_v18_reference_predecessor().get("status")=="PASS")
    check("L_V19_HISTORY",verify_v19_reference_predecessor().get("status")=="PASS")
    check("L_V20_HISTORY",verify_v20_reference_predecessor().get("status")=="PASS")
    check("L_V24_HISTORY",verify_v24_reference_predecessor().get("status")=="PASS")
    check("L_V25_HISTORY",verify_v25_reference_predecessor().get("status")=="PASS")
    check("L_V26_HISTORY",verify_v26_reference_predecessor().get("status")=="PASS")
    lifecycle=semantic_lifecycle_anchor_verdict((ROOT/"src/runner_v35.py").read_text(encoding="utf-8"));check("L_LIFECYCLE",lifecycle.get("status")=="PASS" and lock.get("semantic_lifecycle_anchor_sha256")==canonical_json_sha256(lifecycle),lifecycle)
    check("L_ATTEMPT_ABSENT",not(STATIC_RUN/"ATTEMPT_MARKER.json").exists());check("L_RUNTIME_ABSENT",not(STATIC_RUN/"runtime-result-0001.json").exists());check("L_STATIC_RUN_EMPTY",not any(STATIC_RUN.iterdir()))
    failures=[x["id"] for x in checks if x["status"]=="FAIL"]
    result={"record_type":"V35_STATIC_EXECUTION_LOCK_VERIFICATION","execution_identity":EXECUTION_IDENTITY,"status":"PASS" if not failures else "FAIL_CLOSED","checks":checks,"failure_ids":failures,"validation_counts":{"total":len(checks),"passed":len(checks)-len(failures),"failed":len(failures)},"attempt_count":0,"worker_invocation_count":0,"codex_as_worker_invocation_count":0}
    append_only_json(ROOT/"STATIC_EXECUTION_LOCK_VERIFICATION.json",result);guarded_chmod(ROOT/"STATIC_EXECUTION_LOCK_VERIFICATION.json",0o444,operation_identity="STATIC_LOCK_VERIFICATION_FREEZE",generation="STATIC_LOCK_0001");guarded_chmod(ROOT,0o555,operation_identity="STATIC_WORKSPACE_FREEZE",generation="STATIC_LOCK_0001")
    print(json.dumps(result["validation_counts"],sort_keys=True));return 0 if not failures else 1
if __name__=="__main__":raise SystemExit(main())
