"""Fresh V35 preflight and complete dependency-closure readiness."""
from __future__ import annotations
import hashlib,importlib.util,json,sys
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
_resolver.load_canonical_modules("FRESH_PREFLIGHT",("workspace_boundary_v35","predecessor_binding_v35","external_artifact_binding_v35","binding_generation_v35","symbol_resolution_v35","mount_output_binding_v35","preflight_requirement_registry_v35","host_output_lifecycle_v35","prelock_storage_lifecycle_v35","runtime_acceptance_v35","current_digest_view_v35","validator_helper_contract_v35","invocation_v35"))
from invocation_v35 import STATIC_RUN,WORKSPACE,append_only_json,expected_lock_members,fresh_preflight,inspect_runtime_identity
from validator_helper_contract_v35 import critical_validator_helper_contract_precheck,require_typed_verdict
from prelock_storage_lifecycle_v35 import prelock_storage_lifecycle_precheck

def main()->int:
    storage_lifecycle=prelock_storage_lifecycle_precheck("FRESH_PREFLIGHT")
    if storage_lifecycle.get("status")!="PASS":raise RuntimeError("V35_PRELOCK_STORAGE_LIFECYCLE_FAILED")
    helper_contract=critical_validator_helper_contract_precheck()
    if helper_contract.get("status")!="PASS":raise RuntimeError("V35_TYPED_VALIDATOR_HELPER_RETURN_CONTRACT_FAILED")
    runtime_verdict=require_typed_verdict(inspect_runtime_identity(),"inspect_runtime_identity")
    if runtime_verdict.get("status")!="PASS":raise RuntimeError("V35_RUNTIME_IDENTITY_VERDICT_FAILED")
    result=fresh_preflight(False);result["run_id"]="FRESH_PREFLIGHT_RUN_0001"
    result["typed_validator_helper_return_contract"]=helper_contract
    result["runtime_identity_verdict"]=runtime_verdict
    append_only_json(ROOT/"results/prelock/fresh-preflight-run-0001.json",result)
    expected=set(expected_lock_members());actual={p.relative_to(ROOT).as_posix() for p in ROOT.rglob("*") if (p.is_file() or p.is_symlink()) and not p.is_relative_to(STATIC_RUN) and p.name not in {"STATIC_SOURCE_MANIFEST.json","STATIC_EXECUTION_LOCK.json","STATIC_EXECUTION_LOCK_VERIFICATION.json"}}
    missing=sorted(expected-actual);unexpected=sorted(actual-expected)
    ready=result.get("status")=="PASS" and missing==["results/prelock/dependency-closure-run-0001.json"] and not unexpected
    closure={"record_type":"V35_DEPENDENCY_CLOSURE_READINESS","execution_identity":"V0_3_FIRST_REAL_SECURITY_WORKER_INVOCATION_V35","status":"READY_FOR_FINAL_CLOSURE_CHECK" if ready else "FAIL_CLOSED","expected_members":sorted(expected),"observed_members_before_this_append_only_record":sorted(actual),"missing_before_this_record":missing,"unexpected_members":unexpected,"unmanifested_validator_input_count":0 if ready else len(missing),"unexpected_prelock_workspace_member_count":len(unexpected),"attempt_count":0,"worker_invocation_count":0,"codex_as_worker_invocation_count":0}
    append_only_json(ROOT/"results/prelock/dependency-closure-run-0001.json",closure)
    print(json.dumps({"preflight":result["status"],"closure":closure["status"]},sort_keys=True));return 0 if ready else 1
if __name__=="__main__":raise SystemExit(main())
