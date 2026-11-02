"""Create the final-bytes-first artifact binding for fresh V35."""
from __future__ import annotations
import hashlib,importlib.util,json
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parent
sys.dont_write_bytecode=True
if Path.cwd().resolve()!=ROOT:raise RuntimeError("V35_CANONICAL_CWD_REQUIRED")
_binding=json.loads((ROOT/"contracts/CANONICAL_MODULE_BINDINGS.json").read_text())
_row=next(row for row in _binding["modules"] if row["canonical_logical_module_name"]=="module_resolution_v35")
_path=Path(_row["canonical_source_path"])
if hashlib.sha256(_path.read_bytes()).hexdigest()!=_row["exact_source_sha256"]:raise RuntimeError("V35_MODULE_RESOLVER_DIGEST_MISMATCH")
_spec=importlib.util.spec_from_file_location("module_resolution_v35",_path)
if _spec is None or _spec.loader is None:raise RuntimeError("V35_MODULE_RESOLVER_SPEC_UNAVAILABLE")
_resolver=importlib.util.module_from_spec(_spec);sys.modules["module_resolution_v35"]=_resolver;_spec.loader.exec_module(_resolver)
_resolver.load_canonical_modules("BUILDER",("workspace_boundary_v35","predecessor_binding_v35","external_artifact_binding_v35","artifact_finalization_v35"))
from workspace_boundary_v35 import guarded_chmod, guarded_json_once
from predecessor_binding_v35 import canonical_predecessor_binding_precheck
from external_artifact_binding_v35 import external_predecessor_artifact_precheck
from artifact_finalization_v35 import CLOSURE, GENERATION_IDENTITY, authoritative_input_paths, digest, member_rows
OUT=ROOT/"contracts/AUTHORITATIVE_ARTIFACT_DIGEST_BINDINGS.json"
V18=Path("/home/nobcoder/v0.3-first-real-security-worker-invocation-v18-20261023")
def digest_bytes(value:bytes)->str:return hashlib.sha256(value).hexdigest()
def main()->int:
    if OUT.exists() or OUT.is_symlink(): raise RuntimeError("authoritative artifact binding already exists")
    predecessor_binding=canonical_predecessor_binding_precheck("BUILDER")
    if predecessor_binding.get("status")!="PASS":raise RuntimeError(f"canonical predecessor:{predecessor_binding}")
    external_binding=external_predecessor_artifact_precheck("BUILDER")
    if external_binding.get("status")!="PASS":raise RuntimeError(f"external predecessor artifact:{external_binding}")
    if not CLOSURE.is_file() or CLOSURE.is_symlink(): raise RuntimeError("V35_AUTHORITATIVE_CREATION_CLOSURE_UNAVAILABLE")
    closure=json.loads(CLOSURE.read_text(encoding="utf-8"))
    paths=list(authoritative_input_paths())
    closed={row["path"]:row for row in closure.get("members",[]) if isinstance(row,dict) and isinstance(row.get("path"),str)}
    observed=member_rows();observed_index={row["path"]:row for row in observed}
    if closure.get("creation_phase_state")!="CREATION_PHASE_CLOSED" or closure.get("generation_identity")!=GENERATION_IDENTITY:raise RuntimeError("V35_INVALID_CREATION_CLOSURE_STATE")
    if set(closed)!=set(observed_index):raise RuntimeError("V35_MEMBER_SET_CHANGED_AFTER_CLOSURE")
    if any(observed_index[name]!=closed[name] for name in closed):raise RuntimeError("V35_MEMBER_CHANGED_AFTER_CLOSURE")
    if any(row.get("mode")!="0444" for row in observed):raise RuntimeError("V35_MEMBER_NOT_IMMUTABLE_BEFORE_DIGEST_BINDING")
    members=[]
    for path in paths:
        first=path.read_bytes();second=path.read_bytes()
        if first!=second:raise RuntimeError(f"reread drift:{path}")
        relative=path.relative_to(ROOT).as_posix();predecessor=V18/relative
        predecessor_sha=digest_bytes(predecessor.read_bytes()) if predecessor.is_file() and not predecessor.is_symlink() else None
        current_sha=digest_bytes(first)
        relation="NO_PREDECESSOR_ARTIFACT_FRESH_SUCCESSOR_DIGEST_BOUND" if predecessor_sha is None else ("SUCCESSOR_BYTES_IDENTICAL_PREDECESSOR_DIGEST_MAY_REMAIN_VALID" if predecessor_sha==current_sha else "SUCCESSOR_BYTES_CHANGED_FRESH_SUCCESSOR_DIGEST_BOUND")
        closed_row=closed[relative]
        members.append({"path":relative,"sha256":current_sha,"bytes":len(first),"mode":closed_row["mode"],"uid":closed_row["uid"],"gid":closed_row["gid"],"predecessor_sha256":predecessor_sha,"predecessor_relation":relation})
    if tuple(item.relative_to(ROOT).as_posix() for item in authoritative_input_paths())!=tuple(row["path"] for row in members):raise RuntimeError("V35_MEMBER_SET_CHANGED_DURING_DIGEST_BINDING")
    payload={"record_type":"FIRST_REAL_SECURITY_WORKER_V35_AUTHORITATIVE_ARTIFACT_DIGEST_BINDINGS","schema_version":"1.0","execution_identity":"V0_3_FIRST_REAL_SECURITY_WORKER_INVOCATION_V35","generation_identity":GENERATION_IDENTITY,"status":"PASS_FINAL_BYTES_BOUND_REREAD_REHASHED","digest_algorithm":"SHA-256","post_bind_mutation":"PROHIBITED","reread_and_rehash":"PASS","member_set_unchanged_after_binding":True,"binding_derivation":"CREATION_CLOSED_IMMUTABLE_FINAL_BYTES_FIRST_REREAD_REHASH","governance_lock_sha256":"d2263268f61b9ddde99a0b60f4b43a26df1586e0c577ba2ca98c07b64c21f811","creation_closure_sha256":digest(CLOSURE),"predecessor_identity":predecessor_binding["predecessor_identity"],"predecessor_workspace_tree_sha256":predecessor_binding["workspace_tree_sha256"],"predecessor_static_lock_sha256":predecessor_binding["static_execution_lock_sha256"],"canonical_predecessor_binding_status":"PASS","external_predecessor_artifact_binding_status":"PASS","external_predecessor_artifact_binding_sha256":external_binding["binding_sha256"],"member_count":len(members),"members":members,"attempt_count":0,"worker_invocation_count":0,"codex_as_worker_invocation_count":0}
    guarded_json_once(OUT,payload,operation_identity="BIND_AUTHORITATIVE_ARTIFACT_DIGESTS",generation="FINAL_BYTES_V35")
    guarded_chmod(OUT,0o444,operation_identity="FREEZE_AUTHORITATIVE_BINDING",generation="FINAL_BYTES_V35")
    print(json.dumps({"members":len(members),"status":"BOUND"},sort_keys=True));return 0
if __name__=="__main__":raise SystemExit(main())
