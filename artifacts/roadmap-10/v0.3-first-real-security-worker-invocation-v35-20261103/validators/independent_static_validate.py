"""Independent V35 validator using direct byte, trace, and AST inspection."""
from __future__ import annotations
import ast, builtins, hashlib, importlib, importlib.machinery, importlib.util, json, os, stat, sys, sysconfig
from pathlib import Path, PurePosixPath

ROOT=Path(__file__).resolve().parents[1]
sys.dont_write_bytecode=True
if Path.cwd().resolve()!=ROOT:raise RuntimeError("V35_CANONICAL_CWD_REQUIRED")
V14=Path("/home/nobcoder/v0.3-first-real-security-worker-invocation-v14-20261023")
V15=Path("/home/nobcoder/v0.3-first-real-security-worker-invocation-v15-20261023")
V16=Path("/home/nobcoder/v0.3-first-real-security-worker-invocation-v16-20261023")
V17=Path("/home/nobcoder/v0.3-first-real-security-worker-invocation-v17-20261023")
V18=Path("/home/nobcoder/v0.3-first-real-security-worker-invocation-v18-20261023")
V19=Path("/home/nobcoder/v0.3-first-real-security-worker-invocation-v19-20261025")
V24=Path("/home/nobcoder/v0.3-first-real-security-worker-invocation-v24-20261101")
V25=Path("/home/nobcoder/v0.3-first-real-security-worker-invocation-v25-20261101")
V26=Path("/home/nobcoder/v0.3-first-real-security-worker-invocation-v26-20261102")
V19_GOV=Path("/home/nobcoder/codex-security-harness-eval/governance/v0.3-first-real-security-worker-invocation-v19-authoritative-artifact-predecessor-identity-verifier-binding-defect-prelock-erratum-and-continuation-or-successor-decision-governance-v1-20261101")
V20_GOV=Path("/home/nobcoder/codex-security-harness-eval/governance/v0.3-first-real-security-worker-invocation-v20-independent-validator-external-predecessor-artifact-path-binding-defect-prelock-erratum-and-successor-decision-governance-v1-20261101")
V21_GOV=Path("/home/nobcoder/codex-security-harness-eval/governance/v0.3-first-real-security-worker-invocation-v21-independent-validator-local-module-resolution-environment-defect-prelock-erratum-and-successor-decision-governance-v1-20261101")
V22_GOV=Path("/home/nobcoder/codex-security-harness-eval/governance/v0.3-first-real-security-worker-invocation-v22-multi-contract-selector-prompt-immutability-historical-decision-verifier-and-external-artifact-digest-binding-failures-prelock-erratum-and-successor-decision-governance-v1-20261101")
V26_GOV=Path("/home/nobcoder/codex-security-harness-eval/governance/v0.3-first-real-security-worker-invocation-v26-independent-validator-standard-library-symbol-resolution-binding-defect-prelock-erratum-and-successor-decision-governance-v1-20261102")
V35_GOV=Path("/home/nobcoder/codex-security-harness-eval/governance/v0.3-first-real-security-worker-invocation-v34-prelock-results-directory-and-fixture-probe-path-lifecycle-defect-unit-execution-erratum-and-successor-decision-governance-only-v1-20261103")
V17_GOV=Path("/home/nobcoder/codex-security-harness-eval/governance/v0.3-first-real-security-worker-invocation-v17-independent-validator-v16-tree-canonicalization-order-mismatch-prelock-erratum-and-continuation-or-successor-decision-governance-v1-20261023")
RUN=ROOT/"static-run-v35"
def digest(path:Path)->str:return hashlib.sha256(path.read_bytes()).hexdigest()
def load(path:Path)->dict:return json.loads(path.read_text())
def independent_completed_json(path:Path,producer:str,fixture:str,schema:str)->dict:
    meta_path=path.with_name(path.name+".completion.json")
    if not meta_path.is_file() or meta_path.is_symlink() or not path.is_file() or path.is_symlink():return {}
    try:meta=json.loads(meta_path.read_bytes())
    except (UnicodeDecodeError,json.JSONDecodeError):return {}
    if not(meta.get("record_type")=="V35_TRANSACTIONAL_TELEMETRY_COMPLETION" and meta.get("publication_state")=="COMPLETED_ATOMICALLY_PUBLISHED" and meta.get("producer_identity")==producer and meta.get("fixture_identity")==fixture and meta.get("schema_identity")==schema and meta.get("artifact_name")==path.name):return {}
    raw=path.read_bytes()
    if len(raw)!=meta.get("artifact_size") or hashlib.sha256(raw).hexdigest()!=meta.get("artifact_sha256"):return {}
    try:value=json.loads(raw)
    except (UnicodeDecodeError,json.JSONDecodeError):return {}
    return value if isinstance(value,dict) else {}
def independent_historical_relation_precheck()->dict:
    contract=load(ROOT/"contracts/TYPED_HISTORICAL_DECISION_REGISTRY_CONTRACT.json")
    registry=load(ROOT/"contracts/TYPED_HISTORICAL_DECISION_REGISTRY.json")
    rows=registry.get("mappings",[]);failures=[]
    if contract.get("logical_to_physical_rule")!="EXPLICIT_MAPPING_NOT_STRING_EQUALITY":failures.append("CONTRACT_RULE")
    if not isinstance(rows,list) or registry.get("mapping_count")!=len(rows):return {"status":"FAIL_CLOSED","failures":["REGISTRY_SHAPE"]}
    identities=[row.get("logical_decision_identity") for row in rows if isinstance(row,dict)]
    if len(identities)!=len(rows) or len(identities)!=len(set(identities)):failures.append("IDENTITY_AMBIGUITY")
    mirrors={"logical_decision_identity":"authorized_logical_decision_identity","physical_record_type_presence":"authorized_physical_record_type_presence","physical_record_type":"authorized_physical_record_type","artifact_role":"authorized_artifact_role","governance_owner":"authorized_governance_owner","subject_identity":"authorized_subject_identity","object_identity":"authorized_object_identity","relation_semantics":"authorized_relation_semantics","artifact_sha256":"authorized_artifact_sha256","governance_identity":"authorized_governance_identity","governance_lock_sha256":"authorized_governance_lock_sha256"}
    for row in rows:
        identity=row.get("logical_decision_identity")
        if row.get("mapping_authority")!="EXACT_GOVERNANCE_BOUND_TYPED_MAPPING" or row.get("logical_to_physical_rule")!="EXPLICIT_MAPPING_NOT_STRING_EQUALITY" or any(row.get(field)!=row.get(mirror) for field,mirror in mirrors.items()):failures.append(f"MAPPING:{identity}");continue
        presence=row.get("physical_record_type_presence");physical=row.get("physical_record_type")
        if presence not in {"PRESENT","ABSENT"} or (presence=="ABSENT" and physical is not None) or (presence=="PRESENT" and (not isinstance(physical,str) or not physical)):failures.append(f"PHYSICAL_TYPE:{identity}");continue
        path=Path(str(row.get("canonical_locator","")));lock=path.parent/"GOVERNANCE_LOCK.json"
        if not path.is_absolute() or not path.is_file() or path.is_symlink() or digest(path)!=row.get("artifact_sha256") or path.stat().st_size!=row.get("artifact_size"):failures.append(f"ARTIFACT:{identity}");continue
        if not lock.is_file() or lock.is_symlink() or digest(lock)!=row.get("governance_lock_sha256"):failures.append(f"AUTHORITY:{identity}");continue
        decision=load(path);governance=load(lock);actual_present="record_type" in decision
        if actual_present!=(presence=="PRESENT") or (actual_present and decision.get("record_type")!=physical) or decision.get("decision")!=row.get("relation_semantics") or governance.get("governance_identity")!=row.get("governance_identity"):failures.append(f"RELATION:{identity}")
    return {"status":"PASS" if not failures else "FAIL_CLOSED","relation_count":len(rows)-len(failures),"failures":failures}
def independent_unified_binding_generation_precheck()->dict:
    manifest_path=ROOT/"contracts/UNIFIED_AUTHORITATIVE_BINDING_GENERATION.json"
    manifest=load(manifest_path)
    rows=manifest.get("members",[])
    required={"SUCCESSOR_SELECTOR","PROMPT_BYTES_DIGEST_AND_MODE","HISTORICAL_GOVERNANCE_DECISIONS","CANONICAL_PREDECESSOR_ARTIFACTS","EXTERNAL_TRANSITIVE_ARTIFACTS","CANONICAL_MODULE_RESOLUTION_BINDINGS","AUTHORITATIVE_CONTRACT_SCHEMA_DIGEST_BINDINGS","MOUNT_OUTPUT_IDENTITY","TYPED_PREFLIGHT_REQUIREMENTS","AUTHORITATIVE_ARTIFACT_FINALIZATION"}
    generation="V35_CURRENT_GOVERNANCE_BOUND_TYPED_PREFLIGHT_BINDING_GENERATION_0001"
    governance="V0_3_FIRST_REAL_SECURITY_WORKER_INVOCATION_V34_PRELOCK_RESULTS_DIRECTORY_AND_FIXTURE_PROBE_PATH_LIFECYCLE_DEFECT_UNIT_EXECUTION_ERRATUM_AND_SUCCESSOR_DECISION_GOVERNANCE_ONLY"
    governance_digest="d2263268f61b9ddde99a0b60f4b43a26df1586e0c577ba2ca98c07b64c21f811"
    failures=[];identities=[];domains=set()
    for row in rows if isinstance(rows,list) else []:
        identity=row.get("logical_artifact_identity");identities.append(identity);domains.add(row.get("domain"))
        path=Path(str(row.get("canonical_locator","")))
        mode=row.get("required_mode")
        if row.get("generation_identity")!=generation or row.get("governance_identity")!=governance or row.get("governance_digest")!=governance_digest:failures.append(f"AUTHORITY:{identity}")
        if not path.is_file() or path.is_symlink() or digest(path)!=row.get("sha256") or path.stat().st_size!=row.get("size"):failures.append(f"IDENTITY:{identity}")
        if mode is not None and stat.S_IMODE(path.stat().st_mode)!=int(mode,8):failures.append(f"MODE:{identity}")
    checks={
        "manifest_identity":manifest.get("record_type")=="V35_UNIFIED_AUTHORITATIVE_BINDING_GENERATION",
        "generation_exact":manifest.get("generation_identity")==manifest.get("current_execution_readiness_generation")==generation,
        "governance_exact":manifest.get("governance_identity")==governance and manifest.get("governance_digest")==governance_digest,
        "member_count_exact":manifest.get("member_count")==len(rows),
        "domains_complete":required<=domains,
        "identities_unique":len(identities)==len(set(identities)),
        "selector_exact":any(row.get("logical_artifact_identity")=="SUCCESSOR_V35_REQUIREMENTS" and row.get("relationship")=="V34_TO_V35_SUCCESSOR_AUTHORITY" for row in rows),
        "prompt_mode_exact":any(row.get("logical_artifact_identity")=="V35_FINAL_WORKER_PROMPT" and row.get("required_mode")=="0444" for row in rows),
        "historical_decision_exact":any(row.get("logical_artifact_identity")=="V34_TERMINAL_AND_V35_SUCCESSOR_DECISION" and row.get("sha256")=="e9672bcddb685c92f3230531eb4c131f41264f54e2ee4c6afa9f9f633bcb21b6" for row in rows),
        "transitive_v20_decision_exact":any(row.get("logical_artifact_identity")=="V20_TERMINAL_AND_V21_SUCCESSOR_DECISION" and row.get("sha256")=="8c78c347a293605db31122f42482ce2caca5bb52a5e750be341377087f3aeff3" and row.get("owner_identity")=="V20_GOVERNANCE" for row in rows),
        "transitive_v21_matrix_exact":any(row.get("logical_artifact_identity")=="V21_EXTERNAL_PREDECESSOR_ARTIFACT_REGRESSION_MATRIX" and row.get("sha256")=="6facfd3c98611569f2c1ae56137a5bee2b5370f9aff5f6ded964d680abf85f22" and row.get("owner_identity")=="V20_GOVERNANCE" for row in rows),
        "no_member_failure":not failures,
    }
    return {"status":"PASS" if all(checks.values()) else "FAIL_CLOSED_BEFORE_STATIC_LOCK_AND_ATTEMPT","checks":checks,"failures":failures}

def independent_derived_current_digest_view_precheck()->dict:
    registry_path=ROOT/"contracts/UNIFIED_AUTHORITATIVE_BINDING_GENERATION.json"
    view_path=ROOT/"contracts/CURRENT_EXPECTED_DIGEST_VIEW.json"
    if not registry_path.is_file() or registry_path.is_symlink() or not view_path.is_file() or view_path.is_symlink():
        return {"record_type":"V35_INDEPENDENT_DERIVED_CURRENT_DIGEST_VIEW_PRECHECK","status":"FAIL_CLOSED","reason":"REGISTRY_OR_VIEW_UNAVAILABLE"}
    registry=load(registry_path);view=load(view_path)
    registry_rows={row.get("logical_artifact_identity"):row for row in registry.get("members",[]) if isinstance(row,dict)}
    expected={
        "successor_v35_requirements":"SUCCESSOR_V35_REQUIREMENTS",
        "typed_historical_decision_registry":"V35_TYPED_HISTORICAL_DECISION_REGISTRY",
        "typed_historical_decision_registry_contract":"V35_TYPED_HISTORICAL_DECISION_REGISTRY_CONTRACT",
        "unified_binding_generation_contract":"V35_UNIFIED_BINDING_GENERATION_CONTRACT",
        "v35_symbol_resolution_regression_matrix":"V35_SYMBOL_RESOLUTION_REGRESSION_MATRIX",
        "v35_typed_module_identity_contract":"V35_TYPED_CANONICAL_MODULE_IDENTITY_CONTRACT",
    }
    rows=view.get("artifacts",[]);by_key={row.get("binding_key"):row for row in rows if isinstance(row,dict)}
    row_checks=[]
    for key,identity in expected.items():
        row=by_key.get(key,{});source=registry_rows.get(identity,{})
        locator=Path(str(source.get("canonical_locator","")))
        actual=digest(locator) if locator.is_file() and not locator.is_symlink() else None
        row_checks.append(
            row.get("logical_artifact_identity")==identity
            and row.get("artifact_sha256")==source.get("sha256")==actual
            and row.get("artifact_owner_identity")==source.get("owner_identity")
            and row.get("owner_governance_sha256")==source.get("governance_digest")=="d2263268f61b9ddde99a0b60f4b43a26df1586e0c577ba2ca98c07b64c21f811"
            and row.get("binding_generation_identity")==source.get("generation_identity")=="V35_CURRENT_GOVERNANCE_BOUND_TYPED_PREFLIGHT_BINDING_GENERATION_0001"
            and row.get("current_historical_status")=="CURRENT_EXECUTION_READINESS"
        )
    checks={
        "exact_key_set":set(by_key)==set(expected) and len(rows)==len(expected),
        "rows_independently_reconstructed":all(row_checks),
        "source_registry_digest":view.get("source_authoritative_registry_sha256")==digest(registry_path),
        "generation":view.get("binding_generation_identity")=="V35_CURRENT_GOVERNANCE_BOUND_TYPED_PREFLIGHT_BINDING_GENERATION_0001",
        "derivation":view.get("derivation")=="PURE_PROJECTION_OF_FINALIZED_AUTHORITATIVE_REGISTRY",
        "historical_not_current":view.get("historical_digest_policy")=="HISTORICAL_ONLY_NEVER_CURRENT",
    }
    return {"record_type":"V35_INDEPENDENT_DERIVED_CURRENT_DIGEST_VIEW_PRECHECK","status":"PASS" if all(checks.values()) else "FAIL_CLOSED","checks":checks,"row_count":len(rows)}

def independent_authoritative_artifact_finalization_precheck()->dict:
    derived={"AUTHORITATIVE_ARTIFACT_CREATION_CLOSURE.json","AUTHORITATIVE_ARTIFACT_DIGEST_BINDINGS.json","CURRENT_EXPECTED_DIGEST_VIEW.json","UNIFIED_AUTHORITATIVE_BINDING_GENERATION.json"}
    paths=[p for p in (ROOT/"contracts").glob("*.json") if p.name not in derived]
    paths.extend((ROOT/"schemas").glob("*.json"))
    paths.extend((ROOT/"fixture/fixture.json",ROOT/"fixture/worker-prompt.txt",ROOT/"runtime-config-candidate/config.toml"))
    paths=sorted(paths,key=lambda p:p.relative_to(ROOT).as_posix().encode("utf-8"))
    closure_path=ROOT/"contracts/AUTHORITATIVE_ARTIFACT_CREATION_CLOSURE.json"
    binding_path=ROOT/"contracts/AUTHORITATIVE_ARTIFACT_DIGEST_BINDINGS.json"
    failures=[]
    if not closure_path.is_file() or closure_path.is_symlink() or not binding_path.is_file() or binding_path.is_symlink():
        return {"status":"FAIL_CLOSED_BEFORE_UNIT_VALIDATION","failures":["CLOSURE_OR_BINDING_UNAVAILABLE"]}
    closure=load(closure_path);binding=load(binding_path)
    contract=load(ROOT/"contracts/SUCCESSOR_V35_AUTHORITATIVE_ARTIFACT_FINALIZATION_LIFECYCLE_CONTRACT.json")
    closed={row.get("path"):row for row in closure.get("members",[]) if isinstance(row,dict)}
    bound={row.get("path"):row for row in binding.get("members",[]) if isinstance(row,dict)}
    expected={p.relative_to(ROOT).as_posix() for p in paths}
    if set(closed)!=expected or set(bound)!=expected:failures.append("MEMBER_SET")
    for path in paths:
        name=path.relative_to(ROOT).as_posix();info=path.stat() if path.is_file() else None
        if info is None or path.is_symlink():failures.append(f"UNSAFE:{name}");continue
        actual={"sha256":digest(path),"bytes":info.st_size,"mode":f"{stat.S_IMODE(info.st_mode):04o}","uid":info.st_uid,"gid":info.st_gid}
        if actual.get("mode")!="0444" or any(actual.get(field)!=closed.get(name,{}).get(field) or actual.get(field)!=bound.get(name,{}).get(field) for field in actual):failures.append(f"ROW:{name}")
    checks={
        "identity":closure.get("execution_identity")==binding.get("execution_identity")=="V0_3_FIRST_REAL_SECURITY_WORKER_INVOCATION_V35",
        "generation":closure.get("generation_identity")==binding.get("generation_identity")=="V35_CURRENT_GOVERNANCE_BOUND_TYPED_PREFLIGHT_BINDING_GENERATION_0001",
        "governance":closure.get("governance_lock_sha256")==binding.get("governance_lock_sha256")=="d2263268f61b9ddde99a0b60f4b43a26df1586e0c577ba2ca98c07b64c21f811",
        "closed":closure.get("creation_phase_state")=="CREATION_PHASE_CLOSED",
        "symbol_present":"contracts/LOCKED_ENTRYPOINT_SYMBOL_BINDING_MANIFEST.json" in expected,
        "closure_bound":binding.get("creation_closure_sha256")==digest(closure_path),
        "reread":binding.get("reread_and_rehash")=="PASS" and binding.get("member_set_unchanged_after_binding") is True,
        "contract":contract.get("contract_identity")=="V35_AUTHORITATIVE_ARTIFACT_CREATION_CLOSURE_FREEZE_AND_BINDING_CONTRACT_V1" and contract.get("authorizing_governance_lock")=="d2263268f61b9ddde99a0b60f4b43a26df1586e0c577ba2ca98c07b64c21f811" and contract.get("required_authoritative_file_mode")=="0444",
        "no_failures":not failures,
    }
    return {"status":"PASS" if all(checks.values()) else "FAIL_CLOSED_BEFORE_UNIT_VALIDATION","checks":checks,"failures":failures,"member_count":len(expected)}

def independent_mount_output_binding_precheck()->dict:
    contract=load(ROOT/"contracts/SUCCESSOR_V35_GOVERNANCE_BOUND_MOUNT_OUTPUT_IDENTITY_CONTRACT.json")
    binding=load(ROOT/"contracts/MOUNT_OUTPUT_IDENTITY_BINDING.json")
    policy=load(ROOT/"contracts/MOUNT_PROVENANCE_WRITE_CONTRACT.json")
    host=str(ROOT/"static-run-v35");namespace="/run/nobcoder-first-worker-v35/output"
    authority="V0_3_FIRST_REAL_SECURITY_WORKER_INVOCATION_V34_PRELOCK_RESULTS_DIRECTORY_AND_FIXTURE_PROBE_PATH_LIFECYCLE_DEFECT_UNIT_EXECUTION_ERRATUM_AND_SUCCESSOR_DECISION_GOVERNANCE_ONLY"
    generation="V35_GOVERNANCE_BOUND_MOUNT_OUTPUT_BINDING_GENERATION_0001"
    consumers={"runner","primary_validator","independent_validator","fresh_preflight","dependency_closure","static_lock","runtime_namespace","post_validator"}
    authorized=policy.get("authorized_host_output_bind",{})
    checks={
        "contract_identity":contract.get("contract_identity")=="V35_GOVERNANCE_BOUND_MOUNT_OUTPUT_IDENTITY_CONTRACT_V1",
        "selection_governance_only":contract.get("selection_rule")=="EXACT_GOVERNANCE_SUCCESSOR_DECISION_NO_VERSION_INFERENCE",
        "execution_identity":binding.get("execution_identity")==policy.get("execution_identity")=="V0_3_FIRST_REAL_SECURITY_WORKER_INVOCATION_V35",
        "workspace_identity":binding.get("workspace_identity")=="V0_3_FIRST_REAL_SECURITY_WORKER_INVOCATION_V35_WORKSPACE" and binding.get("canonical_workspace_root")==str(ROOT),
        "logical_output":binding.get("logical_runtime_output_identity")==policy.get("logical_runtime_output_identity")=="V35_RUNTIME_OUTPUT_ROOT",
        "host_source":binding.get("host_output_path")==binding.get("mount_source_path")==authorized.get("host_source")==host,
        "namespace_destination":binding.get("namespace_output_path")==binding.get("mount_destination_path")==authorized.get("sandbox_mount_point")==namespace,
        "mount_mode":binding.get("mount_mode")=="READ_WRITE_EXACT_DECLARED_OUTPUT_BIND_ONLY" and authorized.get("write_authority")=="EXACT_DECLARED_OUTPUT_BIND_ONLY",
        "authority":binding.get("governance_identity")==contract.get("governance_identity")==authority and binding.get("governance_lock_sha256")==digest(V35_GOV/"GOVERNANCE_LOCK.json")=="d2263268f61b9ddde99a0b60f4b43a26df1586e0c577ba2ca98c07b64c21f811",
        "generation":binding.get("binding_generation_identity")==policy.get("binding_generation_identity")==generation,
        "consumers":set(binding.get("consumers",[]))==set(contract.get("required_consumers",[]))==consumers,
        "binding_source":policy.get("mount_output_binding_source")=="contracts/MOUNT_OUTPUT_IDENTITY_BINDING.json",
    }
    stale=("/run/nobcoder-first-worker-v"+"23/output","/run/nobcoder-first-worker-v"+"25/output")
    surfaces=[ROOT/"contracts/MOUNT_OUTPUT_IDENTITY_BINDING.json",ROOT/"contracts/MOUNT_PROVENANCE_WRITE_CONTRACT.json",ROOT/"contracts/SUCCESSOR_V35_GOVERNANCE_BOUND_MOUNT_OUTPUT_IDENTITY_CONTRACT.json",ROOT/"src/invocation_v35.py",ROOT/"src/runner_v35.py",ROOT/"preflight.py",ROOT/"prepare_static_lock.py",ROOT/"verify_static_lock.py",ROOT/"validators/post_validate.py"]
    findings=[{"path":path.relative_to(ROOT).as_posix(),"literal":literal} for path in surfaces for literal in stale if literal in path.read_text()]
    checks["zero_stale_successor_literals"]=not findings
    return {"status":"PASS" if all(checks.values()) else "FAIL_CLOSED_BEFORE_STATIC_LOCK_AND_ATTEMPT","checks":checks,"findings":findings}

def independent_typed_preflight_registry_precheck()->dict:
    contract=load(ROOT/"contracts/TYPED_PREFLIGHT_REQUIREMENT_REGISTRY_CONTRACT.json")
    registry=load(ROOT/"contracts/TYPED_PREFLIGHT_REQUIREMENT_REGISTRY.json")
    rows=registry.get("requirements",[]);required=set(contract.get("required_fields",[]));failures=[]
    identities=[]
    for row in rows if isinstance(rows,list) else []:
        identity=row.get("logical_requirement_identity");identities.append(identity)
        owner=ROOT/str(row.get("owning_contract_path",""))
        if not required<=set(row):failures.append(f"FIELDS:{identity}");continue
        if row.get("binding_generation_identity")!="V35_CURRENT_GOVERNANCE_BOUND_TYPED_PREFLIGHT_BINDING_GENERATION_0001":failures.append(f"GENERATION:{identity}")
        if row.get("governance_identity")!="V0_3_FIRST_REAL_SECURITY_WORKER_INVOCATION_V34_PRELOCK_RESULTS_DIRECTORY_AND_FIXTURE_PROBE_PATH_LIFECYCLE_DEFECT_UNIT_EXECUTION_ERRATUM_AND_SUCCESSOR_DECISION_GOVERNANCE_ONLY" or row.get("governance_lock_sha256")!="d2263268f61b9ddde99a0b60f4b43a26df1586e0c577ba2ca98c07b64c21f811":failures.append(f"AUTHORITY:{identity}")
        if not isinstance(row.get("semantic_predicate_identity"),str) or not row["semantic_predicate_identity"].startswith("V35_SEMANTIC_"):failures.append(f"SEMANTIC:{identity}")
        if row.get("evaluator_identity") not in {"V35_FRESH_PREFLIGHT_TYPED_REQUIREMENT_EVALUATOR_V1","V35_MOUNT_OUTPUT_TYPED_REQUIREMENT_EVALUATOR_V1","V35_INDEPENDENT_MOUNT_DESTINATION_EVALUATOR_V1"}:failures.append(f"EVALUATOR:{identity}")
        if not owner.is_file() or owner.is_symlink() or digest(owner)!=row.get("owning_contract_sha256"):failures.append(f"OWNER:{identity}")
    checks={
        "contract_identity":contract.get("contract_identity")=="V35_TYPED_PREFLIGHT_REQUIREMENT_REGISTRY_CONTRACT_V1",
        "no_text_token_authority":contract.get("textual_token_search_as_authority")=="PROHIBITED" and contract.get("logical_to_semantic_rule")=="EXPLICIT_GOVERNANCE_BOUND_TYPED_MAPPING_NOT_TEXT_TOKEN_SEARCH",
        "obsolete_token_absence_allowed":contract.get("obsolete_token_absence")=="NOT_A_FAILURE_WHEN_CURRENT_TYPED_REQUIREMENT_PASSES",
        "registry_identity":registry.get("record_type")=="V35_TYPED_PREFLIGHT_REQUIREMENT_REGISTRY",
        "count":registry.get("requirement_count")==len(rows),
        "logical_set":set(identities)==set(contract.get("required_logical_requirements",[])) and len(identities)==len(set(identities)),
        "rows":bool(rows) and not failures,
    }
    return {"status":"PASS" if all(checks.values()) else "FAIL_CLOSED_BEFORE_STATIC_LOCK_AND_ATTEMPT","checks":checks,"failures":failures}
def canonical_tree(root:Path)->tuple[str,int]:
    rows=[]
    for path in root.rglob("*"):
        if path.is_symlink():raise RuntimeError(f"symlink:{path}")
        if path.is_file():
            relative=path.relative_to(root).as_posix()
            parts=PurePosixPath(relative).parts
            if not relative or "\\" in relative or any(part in {"", ".", ".."} for part in parts):raise RuntimeError(f"noncanonical:{relative}")
            rows.append((tuple(part.encode("utf-8",errors="strict") for part in parts),relative,digest(path)))
    rows.sort(key=lambda row:row[0])
    stream=b"".join(name.encode("utf-8")+b"\x00"+sha.encode("ascii")+b"\x0a" for _,name,sha in rows)
    return hashlib.sha256(stream).hexdigest(),len(rows)

def independent_predecessor_relation_verdict(*, explicit_identity="V0_3_FIRST_REAL_SECURITY_WORKER_INVOCATION_V18", candidates=None, governance_lock_sha256="d2263268f61b9ddde99a0b60f4b43a26df1586e0c577ba2ca98c07b64c21f811", governance_decision_sha256="e9672bcddb685c92f3230531eb4c131f41264f54e2ee4c6afa9f9f633bcb21b6", artifact_tree_sha256=None, static_lock_sha256=None, inferred=False)->dict:
    """Independent oracle: no import from the primary/core predecessor verifier."""
    candidates=["V0_3_FIRST_REAL_SECURITY_WORKER_INVOCATION_V18"] if candidates is None else candidates
    artifact_tree_sha256=artifact_tree_sha256 or "c92f0bd0d7ea111d9bfd6d3d4e612e5b1cd763d70c69f47fef6a2907c0be0f4d"
    static_lock_sha256=static_lock_sha256 or "7b59bb4e753c0aef7f05a3fea61484b21bfc8fe30b5b255e47d1ce393d964c12"
    checks={
        "explicit_governance_identity":explicit_identity=="V0_3_FIRST_REAL_SECURITY_WORKER_INVOCATION_V18",
        "single_candidate":candidates==["V0_3_FIRST_REAL_SECURITY_WORKER_INVOCATION_V18"],
        "governance_lock_exact":governance_lock_sha256=="d2263268f61b9ddde99a0b60f4b43a26df1586e0c577ba2ca98c07b64c21f811",
        "governance_decision_exact":governance_decision_sha256=="e9672bcddb685c92f3230531eb4c131f41264f54e2ee4c6afa9f9f633bcb21b6",
        "artifact_tree_exact":artifact_tree_sha256=="c92f0bd0d7ea111d9bfd6d3d4e612e5b1cd763d70c69f47fef6a2907c0be0f4d",
        "static_lock_exact":static_lock_sha256=="7b59bb4e753c0aef7f05a3fea61484b21bfc8fe30b5b255e47d1ce393d964c12",
        "no_inference":inferred is False,
    }
    return {"status":"PASS" if all(checks.values()) else "FAIL_CLOSED_BEFORE_STATIC_LOCK_AND_ATTEMPT","checks":checks}

def independent_canonical_predecessor_precheck()->dict:
    binding=load(ROOT/"contracts/CANONICAL_PREDECESSOR_BINDING.json")
    contract=load(ROOT/"contracts/CANONICAL_PREDECESSOR_BINDING_CONTRACT.json")
    local_lock=ROOT/"contracts/V34_TO_V35_GOVERNANCE_LOCK.json"
    local_decision=ROOT/"contracts/V34_TERMINAL_AND_V35_SUCCESSOR_DECISION.json"
    external_lock=V35_GOV/"GOVERNANCE_LOCK.json"
    external_decision=V35_GOV/"V34_TERMINAL_AND_V35_SUCCESSOR_DECISION.json"
    root,count=canonical_tree(V18)
    predecessor=binding.get("governance_authorized_predecessor",{})
    authority=binding.get("v35_successor_authority",{})
    static_lock=V18/"STATIC_EXECUTION_LOCK.json"
    verdict=independent_predecessor_relation_verdict(
        explicit_identity=predecessor.get("execution_identity"),
        candidates=[predecessor.get("execution_identity")],
        governance_lock_sha256=digest(external_lock),
        governance_decision_sha256=digest(external_decision),
        artifact_tree_sha256=root,
        static_lock_sha256=digest(static_lock),
        inferred=False,
    )
    checks={
        "independent_typed_verdict":verdict.get("status")=="PASS",
        "binding_identity":binding.get("binding_identity")=="V35_CANONICAL_GOVERNANCE_BOUND_PREDECESSOR_BINDING_V1",
        "contract_identity":contract.get("contract_identity")=="V35_CANONICAL_PREDECESSOR_BINDING_V1",
        "component_required":"INDEPENDENT_VALIDATOR" in contract.get("required_components",[]),
        "tree_reread_exact":root==predecessor.get("workspace_tree_sha256")==contract.get("predecessor_workspace_tree_sha256") and count==predecessor.get("workspace_member_count")==164,
        "static_lock_exact":digest(static_lock)==predecessor.get("static_execution_lock_sha256"),
        "local_external_lock_bytes":local_lock.read_bytes()==external_lock.read_bytes(),
        "local_external_decision_bytes":local_decision.read_bytes()==external_decision.read_bytes(),
        "authority_exact":authority.get("governance_lock_sha256")==digest(external_lock) and authority.get("successor_decision_sha256")==digest(external_decision),
        "decision_exact":load(external_decision).get("status")=="PASS" and load(external_decision).get("record_type")=="V34_TERMINAL_AND_V35_SUCCESSOR_DECISION" and load(external_decision).get("v35_disposition")=="CONDITIONALLY_AUTHORIZED_NOT_CREATED_NOT_EXECUTED",
        "fallback_prohibited":contract.get("fallback")=="PROHIBITED" and contract.get("version_or_directory_inference")=="PROHIBITED",
    }
    return {"status":"PASS" if all(checks.values()) else "FAIL_CLOSED_BEFORE_STATIC_LOCK_AND_ATTEMPT","checks":checks,"predecessor_identity":predecessor.get("execution_identity"),"tree_root":root,"member_count":count}

def independent_external_artifact_precheck()->dict:
    """Independent exact-locator resolver; does not import the core V26 resolver."""
    binding=load(ROOT/"contracts/CANONICAL_EXTERNAL_PREDECESSOR_ARTIFACT_BINDING.json")
    contract=load(ROOT/"contracts/CANONICAL_EXTERNAL_PREDECESSOR_ARTIFACT_BINDING_CONTRACT.json")
    rows=binding.get("external_artifacts",[])
    checks={
        "binding_identity":binding.get("binding_identity")=="V35_CANONICAL_EXTERNAL_PREDECESSOR_ARTIFACT_BINDING_V1",
        "canonical_predecessor":binding.get("canonical_predecessor_identity")==contract.get("canonical_predecessor_identity")=="V0_3_FIRST_REAL_SECURITY_WORKER_INVOCATION_V18",
        "single_candidate":isinstance(rows,list) and len(rows)==1 and isinstance(rows[0],dict),
        "no_fallback":binding.get("resolution_policy")=="EXACT_GOVERNANCE_BOUND_LOCATORS_ONLY_NO_FALLBACK",
    }
    if not checks["single_candidate"]:return {"status":"FAIL_CLOSED","checks":checks}
    row=rows[0];norm=contract.get("canonical_binding_for_known_artifact",{})
    checks["normative_row_exact"]=all(row.get(key)==value for key,value in norm.items())
    def exact(locator,sha,size=None):
        path=Path(locator)
        if not path.is_absolute() or not path.exists():return None,None
        info=path.lstat()
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode) or path.resolve(strict=True)!=path:return None,None
        first=path.read_bytes();second=path.read_bytes()
        if first!=second or digest(path)!=sha or hashlib.sha256(second).hexdigest()!=sha:return None,None
        if size is not None and len(first)!=size:return None,None
        return path,json.loads(first.decode())
    artifact_path,artifact=exact(row.get("canonical_locator",""),row.get("expected_sha256",""),row.get("expected_size"))
    lock_path,lock=exact(row.get("authorizing_governance_lock_locator",""),row.get("authorizing_governance_lock_sha256",""))
    decision_path,decision=exact(row.get("authorizing_successor_decision_locator",""),row.get("authorizing_successor_decision_sha256",""))
    checks.update({
        "artifact_exact":artifact_path is not None and artifact.get("execution_identity")==row.get("owning_predecessor_identity")=="V0_3_FIRST_REAL_SECURITY_WORKER_INVOCATION_V17" and artifact.get("disposition")=="FAIL_CLOSED_PRELOCK_TERMINAL_NO_RETRY_REFERENCE_ONLY",
        "artifact_role_exact":row.get("artifact_role")=="TRANSITIVE_FROZEN_PREDECESSOR_EVIDENCE_BINDING",
        "governance_exact":lock_path is not None and lock.get("governance_identity")==row.get("authorizing_governance_identity") and lock.get("status")=="PASS_LOCKED_GOVERNANCE_ONLY",
        "successor_decision_exact":decision_path is not None and decision.get("decision")=="TERMINALIZE_V17_AND_AUTHORIZE_DISTINCT_V18_CONDITIONALLY" and decision.get("v17")==artifact.get("disposition") and decision.get("v18")=="CONDITIONALLY_AUTHORIZED_NOT_CREATED_NOT_EXECUTED",
        "transitive_relationship_exact":row.get("relationship_to_canonical_predecessor")=="V17_FROZEN_HISTORY_REQUIRED_TO_VERIFY_CANONICAL_PREDECESSOR_V18",
    })
    return {"status":"PASS" if all(checks.values()) else "FAIL_CLOSED","checks":checks,"artifact":str(artifact_path) if artifact_path else None}

def _independent_loader_identity(loader)->str|None:
    if loader is None:return None
    value=loader if isinstance(loader,type) else type(loader)
    return f"{value.__module__}.{value.__qualname__}"

def _independent_module_spec(row:dict):
    name=row.get("expected_import_name");category=row.get("module_class")
    if category in {"LOCAL_SOURCE_MODULE","LOCAL_PROJECT_MODULE"}:return importlib.machinery.PathFinder.find_spec(name,[str((ROOT/"src").resolve(strict=True))])
    if category=="PURE_PYTHON_STDLIB":return importlib.machinery.PathFinder.find_spec(name,[sysconfig.get_path("stdlib")])
    if category=="BUILTIN_MODULE":return importlib.machinery.BuiltinImporter.find_spec(name)
    if category=="FROZEN_MODULE":return importlib.machinery.FrozenImporter.find_spec(name)
    if category=="EXTENSION_MODULE":return importlib.machinery.PathFinder.find_spec(name,[str(Path(sysconfig.get_path("stdlib"))/"lib-dynload")])
    return None

def _independent_top_level_bindings(path:Path)->set[str]:
    tree=ast.parse(path.read_text(encoding="utf-8"),filename=str(path));names=set()
    for node in tree.body:
        if isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef,ast.ClassDef)):names.add(node.name)
        elif isinstance(node,ast.ImportFrom):names.update(alias.asname or alias.name for alias in node.names)
        elif isinstance(node,ast.Import):names.update(alias.asname or alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node,(ast.Assign,ast.AnnAssign)):
            targets=node.targets if isinstance(node,ast.Assign) else [node.target]
            names.update(target.id for target in targets if isinstance(target,ast.Name))
    return names

def independent_canonical_module_resolution_precheck()->dict:
    """Independent typed resolver; never imports the primary resolver."""
    binding=load(ROOT/"contracts/CANONICAL_MODULE_BINDINGS.json")
    contract=load(ROOT/"contracts/TYPED_CANONICAL_STANDARD_LIBRARY_MODULE_IDENTITY_CONTRACT.json")
    package_root=(ROOT/"src").resolve(strict=True);runtime=binding.get("pinned_runtime",{})
    python=Path(sys.executable).resolve(strict=True);stdlib=Path(sysconfig.get_path("stdlib")).resolve(strict=True)
    environment_checks={
        "bound_before_resolution":True,"cwd_exact":Path.cwd().resolve()==ROOT,
        "package_root_exact":binding.get("canonical_package_root")==str(package_root),
        "pythonpath_absent":os.environ.get("PYTHONPATH") in {None,""},
        "bytecode_disabled":sys.dont_write_bytecode and os.environ.get("PYTHONDONTWRITEBYTECODE")=="1",
        "hash_seed_exact":os.environ.get("PYTHONHASHSEED")=="0","pycache_prefix_absent":os.environ.get("PYTHONPYCACHEPREFIX") in {None,""},
        "typed_contract_exact":contract.get("contract_identity")=="V35_TYPED_CANONICAL_MODULE_IDENTITY_CONTRACT_V1",
        "count_only_prohibited":contract.get("count_only_equivalence")=="PROHIBITED",
        "runtime_identity":runtime.get("identity")=="V35_PINNED_CPYTHON_3_14_RUNTIME_0001",
        "runtime_executable":runtime.get("python_executable")==str(python) and runtime.get("python_executable_sha256")==digest(python),
        "runtime_version":runtime.get("python_version")==sys.version and runtime.get("implementation")==sys.implementation.name,
        "runtime_layout":runtime.get("stdlib_root")==str(stdlib) and runtime.get("extension_root")==str((stdlib/"lib-dynload").resolve(strict=True)),
    }
    failures=[];resolved=[];rows=binding.get("modules",[])
    names=[row.get("canonical_logical_module_name") for row in rows if isinstance(row,dict)]
    local_bound={row.get("canonical_logical_module_name") for row in rows if isinstance(row,dict) and row.get("module_class") in {"LOCAL_SOURCE_MODULE","LOCAL_PROJECT_MODULE"}}
    actual_local={path.stem for path in package_root.glob("*.py") if path.name!="__init__.py"}
    if len(names)!=len(set(names)) or local_bound!=actual_local:failures.append({"reason":"MODULE_MEMBER_SET_OR_AMBIGUITY","bound_local":sorted(local_bound),"actual_local":sorted(actual_local)})
    if not all(environment_checks.values()):failures.append({"reason":"CANONICAL_ENVIRONMENT_NOT_BOUND","checks":environment_checks})
    else:
        for row in rows:
            name=row.get("canonical_logical_module_name");category=row.get("module_class");spec=_independent_module_spec(row)
            if spec is None:failures.append({"module":name,"reason":"NOT_RESOLVABLE","module_class":category});continue
            origin=spec.origin;loader=_independent_loader_identity(spec.loader)
            source=Path(origin).resolve(strict=True) if origin not in {None,"built-in","frozen"} else None
            exports=_independent_top_level_bindings(source) if category in {"LOCAL_SOURCE_MODULE","LOCAL_PROJECT_MODULE"} else set(dir(importlib.import_module(row.get("expected_import_name"))))
            source_required=category in {"LOCAL_SOURCE_MODULE","LOCAL_PROJECT_MODULE","PURE_PYTHON_STDLIB","EXTENSION_MODULE"}
            checks={
                "class_supported":category in {"LOCAL_SOURCE_MODULE","LOCAL_PROJECT_MODULE","PURE_PYTHON_STDLIB","BUILTIN_MODULE","FROZEN_MODULE","EXTENSION_MODULE"},
                "origin_exact":origin==row.get("expected_module_origin"),"loader_exact":loader==row.get("expected_loader_identity"),
                "runtime_exact":row.get("pinned_runtime_identity")==runtime.get("identity"),
                "digest_exact":(source is not None and digest(source)==row.get("exact_source_sha256")) if source_required else row.get("exact_source_sha256") is None,
                "size_exact":(source is not None and source.stat().st_size==row.get("exact_size")) if source_required else row.get("exact_size") is None,
                "exports_exact":set(row.get("expected_exported_symbol_identities",[]))<=exports,
                "builtin_semantics":category!="BUILTIN_MODULE" or (origin=="built-in" and source is None),
                "frozen_semantics":category!="FROZEN_MODULE" or (origin=="frozen" and source is None),
            }
            if not all(checks.values()):failures.append({"module":name,"reason":"TYPED_IDENTITY_MISMATCH","module_class":category,"checks":checks})
            resolved.append({"module":name,"module_class":category,"origin":origin,"loader":loader,"sha256":digest(source) if source else None,"checks":checks})
    return {"status":"PASS" if not failures else "FAIL_CLOSED_BEFORE_STATIC_LOCK_AND_ATTEMPT","environment_checks":environment_checks,"resolved":resolved,"failures":failures,"module_count":len(resolved)}

def flattened_tree(root:Path)->tuple[str,int]:
    rows=[]
    for path in root.rglob("*"):
        if path.is_symlink():raise RuntimeError(f"symlink:{path}")
        if path.is_file():
            relative=path.relative_to(root).as_posix();rows.append((relative.encode("utf-8"),relative,digest(path)))
    rows.sort(key=lambda row:row[0])
    stream=b"".join(name.encode("utf-8")+b"\x00"+sha.encode("ascii")+b"\x0a" for _,name,sha in rows)
    return hashlib.sha256(stream).hexdigest(),len(rows)

def fixture_tree(rows,*,flattened=False,separator=b"\x00",newline=b"\x0a"):
    prepared=[]
    for name,content in rows:
        parts=PurePosixPath(name).parts
        if not name or "\\" in name or any(part in {"", ".", ".."} for part in parts):raise ValueError(name)
        key=name.encode("utf-8") if flattened else tuple(part.encode("utf-8") for part in parts)
        prepared.append((key,name,hashlib.sha256(content).hexdigest()))
    prepared.sort(key=lambda row:row[0])
    stream=b"".join(name.encode("utf-8")+separator+sha.encode("ascii")+newline for _,name,sha in prepared)
    return hashlib.sha256(stream).hexdigest()

def independent_lifecycle_verdict(source:str)->dict:
    """Independent AST visitor; it does not call or trust the primary classifier."""
    try: tree=ast.parse(source)
    except SyntaxError as exc:return {"status":"FAIL_CLOSED","reason":"AST_INVALID","error":str(exc)}
    hits={name:[] for name in "ABCDE"}
    def name_target(node,name):
        return isinstance(node,ast.Assign) and len(node.targets)==1 and isinstance(node.targets[0],ast.Name) and node.targets[0].id==name
    def named_call(value,name):
        return isinstance(value,ast.Call) and isinstance(value.func,ast.Name) and value.func.id==name
    def qualified_call(value,owner,attribute):
        return isinstance(value,ast.Call) and isinstance(value.func,ast.Attribute) and value.func.attr==attribute and isinstance(value.func.value,ast.Name) and value.func.value.id==owner
    class Visitor(ast.NodeVisitor):
        def visit_Assign(self,node):
            event=None
            if name_target(node,"observer_process") and qualified_call(node.value,"subprocess","Popen"):event="A"
            elif name_target(node,"observer_ready") and named_call(node.value,"wait_for_json"):event="B"
            elif name_target(node,"process") and qualified_call(node.value,"subprocess","Popen"):event="C"
            elif name_target(node,"trace_ready") and named_call(node.value,"any"):event="D"
            if event:hits[event].append((node.lineno,node.col_offset))
            self.generic_visit(node)
        def visit_Expr(self,node):
            value=node.value
            if named_call(value,"append_only_json") and value.args:
                operand=value.args[0]
                exact=(isinstance(operand,ast.BinOp) and isinstance(operand.op,ast.Div)
                    and isinstance(operand.left,ast.Name) and operand.left.id=="STATIC_RUN"
                    and isinstance(operand.right,ast.Constant) and operand.right.value=="ATTEMPT_MARKER.json")
                if exact:hits["E"].append((node.lineno,node.col_offset))
            self.generic_visit(node)
    Visitor().visit(tree)
    unique=all(len(hits[name])==1 for name in "ABCDE")
    positions=[hits[name][0] for name in "ABCDE"] if unique else []
    ordered=unique and all(positions[index] < positions[index+1] for index in range(4))
    return {"status":"PASS" if unique and ordered else "FAIL_CLOSED","unique":unique,"ordered":ordered,"anchors":hits}

def independent_symbol_binding_verdict(source:str,*,available_modules:set[str],static_lock_members:set[str])->dict:
    """Independent AST binding oracle; deliberately does not import the primary implementation."""
    try:tree=ast.parse(source)
    except SyntaxError as exc:return {"status":"FAIL_CLOSED","reason":f"AST_INVALID:{exc}"}
    target="v16_tree_canonicalization_precheck";imports=[];calls=[];writes=[];dynamic=[]
    for node in ast.walk(tree):
        if isinstance(node,ast.ImportFrom):
            imports.extend((node.module,alias.name,alias.asname or alias.name) for alias in node.names if alias.name==target or (alias.asname or alias.name)==target)
        elif isinstance(node,ast.Call) and isinstance(node.func,ast.Name):
            if node.func.id==target:calls.append(node.lineno)
            if node.func.id in {"__import__","eval","exec"}:dynamic.append(node.lineno)
        elif isinstance(node,(ast.Assign,ast.AnnAssign,ast.NamedExpr)):
            targets=node.targets if isinstance(node,ast.Assign) else [node.target]
            writes.extend(node.lineno for target_node in targets if isinstance(target_node,ast.Name) and target_node.id==target)
    checks={
        "exact_single_import":imports==[("invocation_v35",target,target)],
        "exact_single_call":len(calls)==1,
        "defining_module_available":"invocation_v35" in available_modules,
        "defining_source_locked":"src/invocation_v35.py" in static_lock_members,
        "not_shadowed":not writes,
        "no_dynamic_binding":not dynamic,
    }
    return {"status":"PASS" if all(checks.values()) else "FAIL_CLOSED","checks":checks,"imports":imports,"calls":calls}

def independent_complete_symbol_graph(source:str)->dict:
    """Second implementation of complete pre-attempt reachability and binding enumeration."""
    try:tree=ast.parse(source)
    except SyntaxError as exc:return {"status":"FAIL_CLOSED","reason":f"AST_INVALID:{exc}"}
    functions={node.name:node for node in tree.body if isinstance(node,ast.FunctionDef)}
    main_node=functions.get("main")
    if main_node is None:return {"status":"FAIL_CLOSED","reason":"MAIN_ABSENT"}
    marker=[]
    for node in ast.walk(main_node):
        if isinstance(node,ast.Call) and isinstance(node.func,ast.Name) and node.func.id=="append_only_json" and node.args:
            value=node.args[0]
            if isinstance(value,ast.BinOp) and isinstance(value.op,ast.Div) and isinstance(value.left,ast.Name) and value.left.id=="STATIC_RUN" and isinstance(value.right,ast.Constant) and value.right.value=="ATTEMPT_MARKER.json":marker.append(node.lineno)
    if len(marker)!=1:return {"status":"FAIL_CLOSED","reason":"ATTEMPT_MARKER_ANCHOR_AMBIGUOUS","anchors":marker}
    cutoff=marker[0];reachable={};queue=["main"];seen=set()
    while queue:
        function_name=queue.pop(0)
        if function_name in seen:continue
        seen.add(function_name);function=functions[function_name]
        local={arg.arg for arg in [*function.args.posonlyargs,*function.args.args,*function.args.kwonlyargs]}
        local.update(node.id for node in ast.walk(function) if isinstance(node,ast.Name) and isinstance(node.ctx,(ast.Store,ast.Del)))
        local.update(node.name for node in ast.walk(function) if isinstance(node,ast.ExceptHandler) and isinstance(node.name,str))
        for node in ast.walk(function):
            if function_name=="main" and getattr(node,"lineno",0)>=cutoff:continue
            if isinstance(node,ast.Name) and isinstance(node.ctx,ast.Load) and node.id not in local:reachable.setdefault(node.id,set()).add(node.lineno)
            if isinstance(node,ast.Call) and isinstance(node.func,ast.Name) and node.func.id in functions and node.func.id not in seen:queue.append(node.func.id)
    bindings={}
    for node in tree.body:
        if isinstance(node,ast.ImportFrom):
            for alias in node.names:bindings.setdefault(alias.asname or alias.name,[]).append((node.module or "",alias.name,alias.asname or alias.name,"FROM_IMPORT"))
        elif isinstance(node,ast.Import):
            for alias in node.names:bindings.setdefault(alias.asname or alias.name.split(".")[0],[]).append((alias.name,alias.name,alias.asname or alias.name.split(".")[0],"IMPORT_MODULE"))
        elif isinstance(node,(ast.FunctionDef,ast.ClassDef)):
            bindings.setdefault(node.name,[]).append(("runner_v35",node.name,node.name,"LOCAL_DEFINITION"))
        elif isinstance(node,(ast.Assign,ast.AnnAssign)):
            targets=node.targets if isinstance(node,ast.Assign) else [node.target]
            for target in targets:
                if isinstance(target,ast.Name):bindings.setdefault(target.id,[]).append(("runner_v35",target.id,target.id,"MODULE_ASSIGNMENT"))
    module_binding=load(ROOT/"contracts/CANONICAL_MODULE_BINDINGS.json")
    module_rows={row.get("canonical_logical_module_name"):row for row in module_binding.get("modules",[]) if isinstance(row,dict)}
    rows={};failures=[]
    for name in sorted(reachable,key=lambda value:value.encode("utf-8")):
        candidates=bindings.get(name,[])
        if not candidates and name in vars(builtins):candidates=[("builtins",name,name,"PYTHON_BUILTIN")]
        if len(candidates)!=1:failures.append({"symbol":name,"reason":"MISSING_OR_AMBIGUOUS","count":len(candidates)});continue
        module,imported,alias,mechanism=candidates[0]
        bound=module_rows.get(module)
        if bound is None:
            failures.append({"symbol":name,"reason":"TYPED_MODULE_BINDING_MISSING","module":module});continue
        spec=_independent_module_spec(bound)
        if spec is None:
            failures.append({"symbol":name,"reason":"MODULE_UNRESOLVABLE","module":module});continue
        origin=spec.origin;loader=_independent_loader_identity(spec.loader)
        source=Path(origin).resolve(strict=True) if origin not in {None,"built-in","frozen"} else None
        if origin!=bound.get("expected_module_origin") or loader!=bound.get("expected_loader_identity"):
            failures.append({"symbol":name,"reason":"MODULE_ORIGIN_LOADER_MISMATCH","module":module,"origin":origin,"loader":loader})
        if source is not None and digest(source)!=bound.get("exact_source_sha256"):
            failures.append({"symbol":name,"reason":"MODULE_DIGEST_MISMATCH","module":module})
        expected_export="__MODULE_OBJECT__" if mechanism=="IMPORT_MODULE" else imported
        if expected_export!="__MODULE_OBJECT__" and imported not in bound.get("expected_exported_symbol_identities",[]):
            failures.append({"symbol":name,"reason":"EXPECTED_EXPORT_MISSING","module":module})
        source_identity=(source.relative_to(ROOT).as_posix() if source is not None and source.is_relative_to(ROOT) else (str(source) if source is not None else f"PYTHON_RUNTIME::{bound.get('module_class')}"))
        local=bound.get("module_class") in {"LOCAL_SOURCE_MODULE","LOCAL_PROJECT_MODULE"}
        dependency="CURRENT_WORKSPACE_STATIC_LOCK_MEMBER" if local else "PINNED_PYTHON_RUNTIME_DEPENDENCY"
        rows[name]={
            "symbol":name,"defining_module":module,"expected_imported_name":imported,"expected_alias":alias,
            "expected_import_or_binding":mechanism,"call_or_reference_sites":sorted(reachable[name]),
            "logical_module_identity":bound.get("logical_module_identity"),"module_class":bound.get("module_class"),
            "expected_module_origin":bound.get("expected_module_origin"),"expected_loader_identity":bound.get("expected_loader_identity"),
            "pinned_runtime_identity":bound.get("pinned_runtime_identity"),"expected_exported_symbol_identity":expected_export,
            "defining_source_artifact":source_identity,"defining_source_sha256":digest(source) if source is not None else None,
            "dependency_closure_membership":dependency,"static_lock_membership":"REQUIRED" if local else "PINNED_RUNTIME_IDENTITY",
        }
    return {"status":"PASS" if not failures else "FAIL_CLOSED","rows":rows,"failures":failures,"pre_attempt_cutoff_line":cutoff}

def frozen_snapshot_verdict(snapshot_path:Path)->dict:
    snapshot=load(snapshot_path)
    rows=snapshot.get("members",[])
    expected={row["path"]:row for row in rows if isinstance(row,dict) and isinstance(row.get("path"),str)}
    actual={path.relative_to(V14).as_posix():path for path in V14.rglob("*") if path.is_file() or path.is_symlink()}
    history_preserved=(set(expected).issubset(actual) and all(not actual[name].is_symlink() and digest(actual[name])==row.get("sha256") and actual[name].stat().st_size==row.get("size") for name,row in expected.items()))
    additions=set(actual)-set(expected)
    expected_additions={"results/prelock/fresh-preflight-run-0001.json":"b75552ef68c5d5de2238ea5787b3ee7e04ae2fc098fc9c8b7666141ed3597562","results/prelock/dependency-closure-run-0001.json":"a437d4f2a8a8032ebdda5f6a6f3c83bc7a3e4f89494dc7cf1bf706ac852a972b"}
    additions_exact=(additions==set(expected_additions) and all(digest(actual[name])==sha for name,sha in expected_additions.items()))
    return {"status":"PASS" if history_preserved and additions_exact and snapshot.get("tree_root_sha256")=="7fa1cadc56eb1186fc4d9efef27f215c9369c6c94b3e09199912563abd8328d4" else "FAIL","historical_count":len(expected),"current_count":len(actual),"history_preserved":history_preserved,"additions_exact":additions_exact}

def independent_host_output_lifecycle_precheck()->dict:
    contract=load(ROOT/"contracts/HOST_OUTPUT_BIND_SOURCE_LIFECYCLE_CONTRACT.json")
    evidence_path=ROOT/"results/prelock/host-output-bind-source-lifecycle-run-0001.json"
    source=ROOT/"static-run-v35"
    if not evidence_path.is_file() or evidence_path.is_symlink() or not source.is_dir() or source.is_symlink():return {"status":"FAIL_CLOSED","reason":"SOURCE_OR_EVIDENCE_INVALID"}
    evidence=load(evidence_path);info=source.lstat()
    checks={
        "contract_identity":contract.get("contract_identity")=="V35_HOST_OUTPUT_BIND_SOURCE_LIFECYCLE_CONTRACT_V1",
        "provisioner":evidence.get("creator_component")==contract.get("creator_component")=="V35_HOST_OUTPUT_BIND_SOURCE_PROVISIONER_V1",
        "stage":evidence.get("creation_stage")==contract.get("creation_stage")=="AFTER_WORKSPACE_BOUNDARY_BEFORE_BIND_FEASIBILITY",
        "path":evidence.get("canonical_path")==contract.get("canonical_path")==str(source.resolve(strict=True)),
        "exclusive":evidence.get("creation_semantics")==contract.get("creation_semantics")=="ATOMIC_EXCLUSIVE_DIRECTORY_CREATION_NO_EXIST_OK",
        "initial_empty":evidence.get("initial_state")=="EMPTY_DIRECTORY" and evidence.get("preexisting_state") is False,
        "current_empty":not any(source.iterdir()),
        "mode":stat.S_IMODE(info.st_mode)==0o700 and evidence.get("mode")==contract.get("mode")=="0700",
        "owner":info.st_uid==evidence.get("owner_uid")==contract.get("owner_uid")==os.getuid() and info.st_gid==evidence.get("owner_gid")==contract.get("owner_gid")==os.getgid(),
        "contract_digest":evidence.get("contract_sha256")==digest(ROOT/"contracts/HOST_OUTPUT_BIND_SOURCE_LIFECYCLE_CONTRACT.json"),
    }
    return {"status":"PASS" if all(checks.values()) else "FAIL_CLOSED","checks":checks}

def independent_prelock_storage_lifecycle_precheck()->dict:
    contract_path=ROOT/"contracts/SUCCESSOR_V35_PRELOCK_RESULTS_AND_FIXTURE_PROBE_LIFECYCLE_CONTRACT.json"
    evidence_path=ROOT/"results/prelock/prelock-storage-lifecycle-run-0001.json"
    prelock=ROOT/"results/prelock";probe=ROOT/"scratch/prelock-fixtures/run-0001"
    v34_manifest=Path("/home/nobcoder/v0.3-first-real-security-worker-invocation-v34-20261103/results/prelock/PRELOCK_FAILURE_EVIDENCE_MANIFEST.json")
    if any(path.is_symlink() for path in (contract_path,evidence_path,prelock,probe,v34_manifest)) or not all(path.exists() for path in (contract_path,evidence_path,prelock,probe,v34_manifest)):
        return {"status":"FAIL_CLOSED","reason":"LIFECYCLE_ARTIFACT_OR_ROOT_UNAVAILABLE_OR_SYMLINKED"}
    contract=load(contract_path);evidence=load(evidence_path);prelock_info=prelock.lstat();probe_info=probe.lstat()
    checks={
        "contract_identity":contract.get("contract_identity")=="V35_PRELOCK_RESULTS_AND_FIXTURE_PROBE_LIFECYCLE_CONTRACT_V1",
        "successor_identity":contract.get("successor_identity")=="V0_3_FIRST_REAL_SECURITY_WORKER_INVOCATION_V35",
        "controller":evidence.get("controller_identity")==contract.get("responsible_component")=="V35_PRELOCK_STORAGE_LIFECYCLE_CONTROLLER_V1",
        "provisioners":evidence.get("provisioner_identities")==["V35_PRELOCK_EVIDENCE_ROOT_PROVISIONER_V1","V35_FIXTURE_SCRATCH_ROOT_PROVISIONER_V1"],
        "canonical_paths":evidence.get("canonical_paths")=={"prelock_evidence_root":str(prelock.resolve(strict=True)),"fixture_probe_root":str(probe.resolve(strict=True))},
        "real_directories":stat.S_ISDIR(prelock_info.st_mode) and stat.S_ISDIR(probe_info.st_mode),
        "modes":stat.S_IMODE(prelock_info.st_mode)==stat.S_IMODE(probe_info.st_mode)==0o700,
        "owners":prelock_info.st_uid==probe_info.st_uid==os.getuid() and prelock_info.st_gid==probe_info.st_gid==os.getgid(),
        "initial_empty":evidence.get("initial_emptiness")=={"prelock_evidence_root":True,"fixture_probe_root":True},
        "probe_current_empty":not any(probe.iterdir()),
        "exclusive":evidence.get("exclusive_creation") is True and evidence.get("preexisting_state_reused") is False,
        "first_writer":evidence.get("provisioning_evidence_is_first_prelock_writer") is True,
        "contract_digest":evidence.get("contract_sha256")==digest(contract_path),
        "governance":evidence.get("governance_lock_sha256")=="d2263268f61b9ddde99a0b60f4b43a26df1586e0c577ba2ca98c07b64c21f811",
        "predecessor_unchanged":evidence.get("predecessor_snapshot_digest")==evidence.get("predecessor_snapshot_after_digest")==digest(v34_manifest)=="604dcf1b0675392ed8ce724a9de424fd0f7a640c8f9da9e5250fa0c0bebaab3a",
        "zero_counters":evidence.get("attempt_count")==evidence.get("worker_invocation_count")==evidence.get("codex_as_worker_invocation_count")==0,
        "status":evidence.get("status")=="PASS",
    }
    return {"record_type":"V35_INDEPENDENT_PRELOCK_STORAGE_LIFECYCLE_PRECHECK","status":"PASS" if all(checks.values()) else "FAIL_CLOSED","checks":checks,"evidence_sha256":digest(evidence_path)}

def independent_runtime_acceptance_precheck()->dict:
    contract=load(ROOT/"contracts/TYPED_CODEX_RUNTIME_ACCEPTANCE_BINDING_CONTRACT.json")
    binding=load(ROOT/"contracts/V35_CODEX_0_166_0_RUNTIME_BINDING.json")
    acceptance_path=Path("/home/nobcoder/codex-security-harness-eval/governance/v0.3-runtime-and-model-compatibility-execution-v8-codex-0-166-0-frozen-evidence-acceptance-and-pass-locked-decision-governance-v1-20261102/GOVERNANCE_LOCK.json")
    binary=Path(binding.get("binary_locator",""));package=Path(binding.get("package_locator",""));config=ROOT/"runtime-config-candidate/config.toml"
    acceptance=load(acceptance_path)
    checks={
        "worker_identity":contract.get("worker_identity")==binding.get("execution_identity")=="V0_3_FIRST_REAL_SECURITY_WORKER_INVOCATION_V35",
        "current_field":contract.get("current_authority_field")=="codex_runtime_0_166_0" and acceptance.get("codex_runtime_0_166_0")=="COMPATIBILITY_PASS_LOCKED",
        "historical_not_current":contract.get("historical_field")=="codex_runtime_0_163_0" and contract.get("historical_field_role")=="HISTORY_ONLY_NOT_CURRENT_WORKER_AUTHORITY" and acceptance.get("codex_runtime_0_163_0") is None,
        "identity":contract.get("runtime_logical_identity")==binding.get("runtime_logical_identity")=="CODEX_RUNTIME_0_166_0_COMPATIBILITY_PASS_LOCKED",
        "binary":binary.is_file() and not binary.is_symlink() and digest(binary)==contract.get("binary_sha256")==binding.get("binary_sha256")=="b8a11fedf24b2dfb59a70c9e52b030f9a508dcd49cd2dd0d41956f4c785156b8",
        "package":package.is_file() and not package.is_symlink() and digest(package)==contract.get("package_sha256")==binding.get("package_sha256")=="ffdfc731eed492fa436a304cff8792ea3a96233a45ec9a561f6f56eaca911446",
        "config":digest(config)==contract.get("dedicated_config_sha256")==binding.get("dedicated_config_sha256")=="7ae835188ef2ab3221e15effac45375b2d6112954d022aa7776f802f7b8697c0",
        "acceptance_lock":digest(acceptance_path)==contract.get("compatibility_governance_lock_sha256")=="060b39551d4543999e79ccfd5d133d751faefc018fdc8adab718f5b9c7479a5e",
        "successor_lock":contract.get("successor_authorization_lock_sha256")=="d2263268f61b9ddde99a0b60f4b43a26df1586e0c577ba2ca98c07b64c21f811",
        "no_fallback":binding.get("fallback_to_0_163_0") is False and binding.get("automatic_latest_selection") is False and binding.get("version_string_only") is False,
    }
    return {"status":"PASS" if all(checks.values()) else "FAIL_CLOSED","checks":checks}

def independent_validator_helper_return_precheck()->dict:
    invocation_source=(ROOT/"src/invocation_v35.py").read_text(encoding="utf-8")
    tree=ast.parse(invocation_source)
    matches=[node for node in tree.body if isinstance(node,ast.FunctionDef) and node.name=="inspect_runtime_identity"]
    function=matches[0] if len(matches)==1 else None
    direct_returns=[]
    if function is not None:
        for statement in function.body:
            if isinstance(statement,ast.Return):direct_returns.append(statement)
    required={"record_type","status","checks"}
    typed=bool(direct_returns) and all(
        isinstance(node.value,ast.Dict)
        and {key.value for key in node.value.keys if isinstance(key,ast.Constant) and isinstance(key.value,str)}>=required
        for node in direct_returns
    )
    caller_results={}
    for relative in ("src/invocation_v35.py","validators/primary_static_validate.py","preflight.py","prepare_static_lock.py","verify_static_lock.py","validate_locked_controls.py","src/runner_v35.py"):
        caller_tree=ast.parse((ROOT/relative).read_text(encoding="utf-8"))
        guarded=0;direct=0
        for node in ast.walk(caller_tree):
            if isinstance(node,ast.Call) and isinstance(node.func,ast.Name) and node.func.id=="require_typed_verdict":
                if any(isinstance(child,ast.Call) and isinstance(child.func,ast.Name) and child.func.id=="inspect_runtime_identity" for child in ast.walk(node)):
                    guarded+=1
            if isinstance(node,ast.Call) and isinstance(node.func,ast.Name) and node.func.id=="inspect_runtime_identity":direct+=1
        caller_results[relative]={"guarded":guarded,"total_helper_calls":direct,"pass":guarded==direct and guarded>0}
    contract=load(ROOT/"contracts/SUCCESSOR_V35_TYPED_VALIDATOR_HELPER_RETURN_CONTRACT.json")
    matrix=load(ROOT/"contracts/V35_TYPED_VALIDATOR_HELPER_RETURN_REGRESSION_MATRIX.json")
    checks={
        "one_top_level_helper":function is not None,
        "explicit_direct_return":bool(direct_returns),
        "terminal_return_is_reachable":function is not None and isinstance(function.body[-1],ast.Return),
        "typed_verdict_shape":typed,
        "caller_type_guards":all(row["pass"] for row in caller_results.values()),
        "contract_exact":contract.get("contract_identity")=="V35_TYPED_CRITICAL_VALIDATOR_HELPER_RETURN_CONTRACT_V1" and contract.get("authorizing_governance_lock")=="EXACT_SHA256_OF_THIS_PACKAGE_GOVERNANCE_LOCK_JSON" and digest(ROOT/"contracts/SUCCESSOR_V35_TYPED_VALIDATOR_HELPER_RETURN_CONTRACT.json")=="b42fc2678dd0213b4f0bc638b1a77a2d9079b289e53277d3dec2e374801cefaa",
        "regressions_complete":matrix.get("case_count")==len(matrix.get("cases",[]))==8,
    }
    return {"record_type":"V35_INDEPENDENT_VALIDATOR_HELPER_RETURN_PRECHECK","status":"PASS" if all(checks.values()) else "FAIL_CLOSED","checks":checks,"caller_results":caller_results,"direct_return_lines":[node.lineno for node in direct_returns]}

def main()->int:
    checks=[]
    def check(identity,ok,evidence=None):checks.append({"id":identity,"status":"PASS" if ok else "FAIL","evidence":evidence})
    unit=load(ROOT/"results/prelock/unit-fixtures-run-0001.json");primary=load(ROOT/"results/prelock/primary-static-validation-run-0001.json")
    check("I001_UNIT_PASS",unit.get("status")=="PASS",unit.get("validation_counts"));check("I002_PRIMARY_PASS",primary.get("status")=="PASS",primary.get("validation_counts"))
    gov=V35_GOV
    v18_gov=Path("/home/nobcoder/codex-security-harness-eval/governance/v0.3-first-real-security-worker-invocation-v18-locked-runner-canonicalization-precheck-import-binding-defect-post-lock-pre-attempt-erratum-and-successor-decision-governance-v1-20261025")
    governance=load(gov/"GOVERNANCE_LOCK.json")
    check("I003_GOV_LOCK",digest(gov/"GOVERNANCE_LOCK.json")=="d2263268f61b9ddde99a0b60f4b43a26df1586e0c577ba2ca98c07b64c21f811")
    check("I004_GOV_STATE",governance.get("status")=="PASS_LOCKED_GOVERNANCE_ONLY")
    decision=load(gov/"V34_TERMINAL_AND_V35_SUCCESSOR_DECISION.json")
    check("I005_GOV_DECISION",decision.get("status")=="PASS" and decision.get("record_type")=="V34_TERMINAL_AND_V35_SUCCESSOR_DECISION" and decision.get("v35_disposition")=="CONDITIONALLY_AUTHORIZED_NOT_CREATED_NOT_EXECUTED")
    prelock_lifecycle=independent_prelock_storage_lifecycle_precheck();check("I005P_PRELOCK_STORAGE_LIFECYCLE",prelock_lifecycle.get("status")=="PASS",prelock_lifecycle)
    host_lifecycle=independent_host_output_lifecycle_precheck();check("I005D_HOST_OUTPUT_BIND_SOURCE_LIFECYCLE",host_lifecycle.get("status")=="PASS",host_lifecycle)
    runtime_acceptance=independent_runtime_acceptance_precheck();check("I005E_TYPED_CURRENT_RUNTIME_AUTHORITY",runtime_acceptance.get("status")=="PASS",runtime_acceptance)
    helper_returns=independent_validator_helper_return_precheck();check("I005F_TYPED_VALIDATOR_HELPER_RETURN_CONTRACT",helper_returns.get("status")=="PASS",helper_returns)
    historical_relations=independent_historical_relation_precheck();check("I005C_HISTORICAL_DECISION_RELATIONS",historical_relations.get("status")=="PASS",historical_relations)
    unified=independent_unified_binding_generation_precheck();check("I005B_UNIFIED_BINDING_GENERATION",unified.get("status")=="PASS",unified)
    digest_view=independent_derived_current_digest_view_precheck();check("I005B2_DERIVED_CURRENT_EXPECTED_DIGEST_VIEW",digest_view.get("status")=="PASS",digest_view)
    module_resolution=independent_canonical_module_resolution_precheck()
    check("I005A_CANONICAL_MODULE_RESOLUTION",module_resolution.get("status")=="PASS",module_resolution)
    frozen=frozen_snapshot_verdict(ROOT/"contracts/V14_FROZEN_EVIDENCE_SNAPSHOT_MANIFEST.json");check("I006_V14_TREE",frozen.get("status")=="PASS",frozen)
    check("I007_V14_UNIT_AND_PRIMARY",digest(V14/"results/prelock/unit-fixtures-run-0001.json")=="3b91f58fc216c396b19988d90323b0f331adab50aa28068c08e9d2b726e82804" and digest(V14/"results/prelock/primary-static-validation-run-0001.json")=="f4cbd3434d34b4c04f1fda19fb96904e4a356c9d59174fb1e7a41d54184b2cc5")
    check("I008_V14_STATIC_LOCK_ABSENT",not(V14/"STATIC_EXECUTION_LOCK.json").exists())
    v16_binding=load(ROOT/"contracts/NORMATIVE_V16_TREE_CANONICALIZATION_CONTRACT.json")
    v16_root,v16_count=canonical_tree(V16)
    flat_root,flat_count=flattened_tree(V16)
    check("I008A_V16_FROZEN",v16_root==v16_binding.get("expected_root_sha256")=="5c99e1c8c1e5048ee3a9c607e0bceffc273743b91a245bf7a913f832af0636b5" and v16_count==v16_binding.get("canonical_member_set",{}).get("regular_file_count")==146 and flat_count==v16_count and flat_root==v16_binding.get("known_non_normative_flattened_order_root_sha256")=="a5ec0db34da898d64859e0e3535d74929eed4f5b047f67f37d1fe3d90a88ea63" and flat_root!=v16_root and digest(V16/"src/__pycache__/workspace_boundary_v16.cpython-314.pyc")=="d28afe1bf85796431bdd7e8c7a0d05da01f99b74af217084372befbe178208b0" and not(V16/"STATIC_EXECUTION_LOCK.json").exists(),{"normative_root":v16_root,"alternate_root":flat_root,"member_count":v16_count})
    v17_binding=load(V17_GOV/"V17_PRELOCK_FROZEN_EVIDENCE_BINDING.json")
    v17_root,v17_count=canonical_tree(V17)
    v17_prelock=[path for path in (V17/"results/prelock").rglob("*") if path.is_file()]
    check("I008B_V17_FROZEN",v17_root==v17_binding.get("hashes",{}).get("workspace_tree")=="576f3773617ad0adab5a3488ad395b20e753f8cb24c6b04ddd97ee8a65498373" and v17_count==v17_binding.get("workspace_member_count")==150 and len(v17_prelock)==78 and all(path.stat().st_mode&0o222==0 for path in v17_prelock) and digest(V17/"results/prelock/independent-static-validation-run-0001.json")=="02e41521f90af9dc1aa55ed26d7769b07b44a6bcdf3b643d7b96b5c662be6e23" and digest(V17/"results/prelock/PRELOCK_TERMINAL_ENGINEERING_RESULT.json")=="f86711afddf68b287a5ed9cf5f327ef9de146dd1601d5497a173ba07c65d07b0" and not(V17/"STATIC_EXECUTION_LOCK.json").exists())
    v18_binding=load(ROOT/"contracts/V18_FROZEN_EVIDENCE_BINDING.json");v18_root,v18_count=canonical_tree(V18)
    v18_hashes=v18_binding.get("hashes",{})
    v18_exact=(v18_root==v18_binding.get("workspace_tree_root_sha256")=="c92f0bd0d7ea111d9bfd6d3d4e612e5b1cd763d70c69f47fef6a2907c0be0f4d" and v18_count==v18_binding.get("workspace_member_count")==164 and all(path.stat().st_mode&0o222==0 for path in V18.rglob("*") if path.is_file()) and digest(V18/"STATIC_EXECUTION_LOCK.json")==v18_hashes.get("static_lock")=="7b59bb4e753c0aef7f05a3fea61484b21bfc8fe30b5b255e47d1ce393d964c12" and digest(V18/"static-run-v18/TERMINAL_ENGINEERING_RESULT.json")==v18_hashes.get("terminal") and not list(V18.rglob("ATTEMPT_MARKER.json")))
    check("I008B2_V18_FROZEN",v18_exact,{"tree_root":v18_root,"member_count":v18_count})
    v24_binding=load(ROOT/"contracts/V24_FROZEN_FAILURE_EVIDENCE_BINDING.json");v24_hashes=v24_binding.get("hashes",{})
    v24_files={"terminal":V24/"results/prelock/PRELOCK_TERMINAL_ENGINEERING_RESULT.json","manifest":V24/"results/prelock/PRELOCK_FAILURE_EVIDENCE_MANIFEST.json","freeze":V24/"results/prelock/PRELOCK_FAILURE_EVIDENCE_FREEZE_VERIFICATION.json","unit":V24/"results/prelock/unit-fixtures-run-0001.json","registry":V24/"contracts/HISTORICAL_DECISION_RELATION_REGISTRY.json"}
    v24_exact=(v24_binding.get("state")=="FAIL_CLOSED_DURING_UNIT_VALIDATION_PRELOCK_TERMINAL_NO_RETRY_FROZEN_FAILURE_EVIDENCE" and all(path.is_file() and not path.is_symlink() and digest(path)==v24_hashes.get(name) for name,path in v24_files.items()) and all(path.stat().st_mode&0o222==0 for path in (V24/"results/prelock").rglob("*") if path.is_file()) and not(V24/"STATIC_EXECUTION_LOCK.json").exists() and not list(V24.rglob("ATTEMPT_MARKER.json")))
    check("I008B3_V24_FROZEN",v24_exact)
    v25_binding=load(ROOT/"contracts/V25_FROZEN_FAILURE_EVIDENCE_BINDING.json");v25_hashes=v25_binding.get("hashes",{})
    v25_files={"terminal":V25/"results/prelock/PRELOCK_TERMINAL_ENGINEERING_RESULT.json","manifest":V25/"results/prelock/PRELOCK_FAILURE_EVIDENCE_MANIFEST.json","freeze":V25/"results/prelock/PRELOCK_FAILURE_EVIDENCE_FREEZE_VERIFICATION.json","unit":V25/"results/prelock/unit-fixtures-run-0001.json","primary":V25/"results/prelock/primary-static-validation-run-0001.json"}
    v25_exact=(v25_binding.get("status")=="FAIL_CLOSED_DURING_PRIMARY_STATIC_VALIDATION_PRELOCK_TERMINAL_NO_RETRY_FROZEN_FAILURE_EVIDENCE" and v25_binding.get("canonical_evidence_root_sha256")=="f47e8cc6f846b6ee819f0852930e8e6d60374cb2bc30aa1710fe27dc907dc2e4" and all(path.is_file() and not path.is_symlink() and digest(path)==v25_hashes.get(name) for name,path in v25_files.items()) and all(path.stat().st_mode&0o222==0 for path in (V25/"results/prelock").rglob("*") if path.is_file()) and not(V25/"STATIC_EXECUTION_LOCK.json").exists() and not list(V25.rglob("ATTEMPT_MARKER.json")) and not list(V25.rglob("runtime-result-0001.json")))
    check("I008B4_V25_FROZEN",v25_exact)
    v26_binding=load(ROOT/"contracts/V26_FROZEN_FAILURE_EVIDENCE_BINDING.json")
    v26_files={"terminal":V26/"results/prelock/PRELOCK_TERMINAL_ENGINEERING_RESULT.json","manifest":V26/"results/prelock/PRELOCK_FAILURE_EVIDENCE_MANIFEST.json","freeze":V26/"results/prelock/PRELOCK_FAILURE_EVIDENCE_FREEZE_VERIFICATION.json"}
    v26_exact=(v26_binding.get("terminal_status")=="FAIL_CLOSED_DURING_INDEPENDENT_STATIC_VALIDATION_PRELOCK_TERMINAL_NO_RETRY_FROZEN_FAILURE_EVIDENCE" and v26_binding.get("canonical_evidence_root_sha256")=="1ff032bc531076421e45a311ede68e3593910a1e15dd868d0b3a50422ff2ac0b" and digest(v26_files["terminal"])==v26_binding.get("terminal_sha256") and digest(v26_files["manifest"])==v26_binding.get("failure_manifest_sha256") and digest(v26_files["freeze"])==v26_binding.get("freeze_verification_sha256") and all(path.stat().st_mode&0o222==0 for path in (V26/"results/prelock").rglob("*") if path.is_file()) and not(V26/"STATIC_EXECUTION_LOCK.json").exists() and not list(V26.rglob("ATTEMPT_MARKER.json")) and not list(V26.rglob("runtime-result-0001.json")))
    check("I008B5_V26_FROZEN",v26_exact)
    predecessor_relation=independent_canonical_predecessor_precheck()
    check("I008P_CANONICAL_PREDECESSOR_RELATION",predecessor_relation.get("status")=="PASS",predecessor_relation)
    external_relation=independent_external_artifact_precheck()
    check("I008Q_EXTERNAL_PREDECESSOR_ARTIFACT_RELATION",external_relation.get("status")=="PASS",external_relation)
    relation_cases={
        "EXACT":({},True),
        "BUILDER_V18_PRIMARY_V17":({"explicit_identity":"V0_3_FIRST_REAL_SECURITY_WORKER_INVOCATION_V17"},False),
        "INDEPENDENT_MISSING":({"candidates":[]},False),
        "PREFLIGHT_V17":({"explicit_identity":"V0_3_FIRST_REAL_SECURITY_WORKER_INVOCATION_V17"},False),
        "STATIC_LOCK_V17":({"explicit_identity":"V0_3_FIRST_REAL_SECURITY_WORKER_INVOCATION_V17"},False),
        "INFERRED":({"inferred":True},False),
        "MISSING_AUTHORITY":({"governance_lock_sha256":None},False),
        "AMBIGUOUS":({"candidates":["V0_3_FIRST_REAL_SECURITY_WORKER_INVOCATION_V18","V0_3_FIRST_REAL_SECURITY_WORKER_INVOCATION_V17"]},False),
        "STALE_LITERAL":({"explicit_identity":"V0_3_FIRST_REAL_SECURITY_WORKER_INVOCATION_V17"},False),
        "DIGEST_MISMATCH":({"artifact_tree_sha256":"0"*64},False),
    }
    for name,(changes,expected_pass) in relation_cases.items():
        verdict=independent_predecessor_relation_verdict(**changes)
        check(f"I_PREDECESSOR_{name}",(verdict.get("status")=="PASS") is expected_pass,verdict)
    fixture=[("root/immediate-0001/events.jsonl",b"events"),("root/immediate-0001-result.json",b"result"),("root/éclair/data",b"utf8")]
    fixture_root=fixture_tree(fixture)
    check("I008C_CANON_SHUFFLE",fixture_tree(list(reversed(fixture)))==fixture_root)
    check("I008D_CANON_COMPONENT_ORDER",fixture_tree(fixture,flattened=True)!=fixture_root)
    check("I008E_CANON_MUTATION",fixture_tree([(fixture[0][0],b"Events"),*fixture[1:]])!=fixture_root)
    check("I008F_CANON_MEMBER_SET",fixture_tree(fixture[:-1])!=fixture_root and fixture_tree([*fixture,("extra",b"x")])!=fixture_root)
    malformed=False
    try:fixture_tree([("root\\bad",b"x")])
    except ValueError:malformed=True
    check("I008G_CANON_MALFORMED_PATH",malformed)
    check("I008H_CANON_SERIALIZATION",fixture_tree(fixture,separator=b"  ")!=fixture_root and fixture_tree(fixture,newline=b"\r\n")!=fixture_root)
    check("I009_ATTEMPT_ABSENT",not(RUN/"ATTEMPT_MARKER.json").exists());check("I010_RUNTIME_ABSENT",not(RUN/"runtime-result-0001.json").exists())
    identity=load(ROOT/"contracts/IDENTITY_BINDINGS.json");check("I011_AUTH",identity["authorization"]["governance_lock_sha256"]==digest(gov/"GOVERNANCE_LOCK.json"))
    binary=Path(identity["codex_runtime"]["binary_path"]);check("I012_BINARY",binary.is_file() and not binary.is_symlink() and digest(binary)==identity["codex_runtime"]["binary_sha256"])
    prompt=ROOT/"fixture/worker-prompt.txt";request=load(ROOT/"contracts/WORKER_REQUEST.json");binding=load(ROOT/"contracts/PROMPT_IDENTITY_BINDING.json");pd=digest(prompt)
    check("I013_PROMPT",pd==request["prompt"]["sha256"]==binding["first_prompt_sha256"]==binding["reread_prompt_sha256"] and stat.S_IMODE(prompt.stat().st_mode)==0o444 and binding.get("verified_mode")==0o444)
    bound=load(ROOT/"contracts/AUTHORITATIVE_ARTIFACT_DIGEST_BINDINGS.json");rows={row["path"]:row for row in bound.get("members",[])}
    expected={p.relative_to(ROOT).as_posix() for d in("contracts","schemas") for p in(ROOT/d).glob("*.json") if p.name not in {"AUTHORITATIVE_ARTIFACT_CREATION_CLOSURE.json","AUTHORITATIVE_ARTIFACT_DIGEST_BINDINGS.json","UNIFIED_AUTHORITATIVE_BINDING_GENERATION.json"}}|{"fixture/fixture.json","fixture/worker-prompt.txt","runtime-config-candidate/config.toml"}
    check("I014_BOUND_SET",set(rows)==expected);check("I015_BOUND_HASHES",all(digest(ROOT/name)==rows[name]["sha256"] for name in expected))
    finalization=independent_authoritative_artifact_finalization_precheck();check("I015F_AUTHORITATIVE_ARTIFACT_FINALIZATION",finalization.get("status")=="PASS",finalization)
    mount_identity=independent_mount_output_binding_precheck();check("I015A_MOUNT_OUTPUT_GENERATION",mount_identity.get("status")=="PASS",mount_identity)
    typed_requirements=independent_typed_preflight_registry_precheck();check("I015B_TYPED_PREFLIGHT_REQUIREMENTS",typed_requirements.get("status")=="PASS",typed_requirements)
    invariant=load(ROOT/"contracts/COMPLETE_COVERAGE_INVARIANT.json")
    check("I016_N_OF_N",typed_requirements.get("status")=="PASS" and invariant.get("percentage_thresholds")=="PROHIBITED" and invariant.get("n_minus_one")=="FAIL_CLOSED")
    observer=(ROOT/"src/topology_observer_v35.py").read_text();runner=(ROOT/"src/runner_v35.py").read_text()
    check("I017_PROC_CONNECTOR","NETLINK_CONNECTOR" in observer and "PROC_EVENT_FORK" in observer)
    check("I018_REUSE_RESISTANCE","process_start_identity" in observer and "pid_namespace_identity" in observer)
    check("I019_ACCOUNTING",all(token in observer for token in("lineage_relevant_trace_identity_count","valid_temporal_identity_mapping_count","missing_identity_count","ambiguous_identity_count","coverage_complete")))
    cache_policy=load(ROOT/"contracts/PYTHON_RUNTIME_SIDE_EFFECT_POLICY.json")
    cache_members=[path.relative_to(ROOT).as_posix() for path in ROOT.rglob("*") if path.is_file() and (path.suffix==".pyc" or "__pycache__" in path.parts)]
    check("I019A_CACHE_POLICY",cache_policy.get("bytecode_policy")=="DETERMINISTIC_SUPPRESSION" and cache_policy.get("child_environment",{}).get("PYTHONDONTWRITEBYTECODE")=="1" and not cache_members,cache_members)
    check("I019B_CHILD_PYTHON_CONTROLS",runner.count('env=exact_python_environment()')>=4 and 'env={}' not in runner and 'str(PYTHON), "-B"' in runner)
    corpus=ROOT/"results/prelock/adversarial-selftests-run-0001"
    for mode in ("long-lived","sequential","overlapping","immediate","nested"):
        result_path=corpus/f"{mode}-0001-result.json";snapshot_path=corpus/f"{mode}-0001/snapshot.json";trace_dir=corpus/f"{mode}-0001/traces"
        result=load(result_path) if result_path.is_file() else {};snapshot=independent_completed_json(snapshot_path,"V35_PROC_CONNECTOR_EVENT_BOUND_PROCESS_IDENTITY_OBSERVER_V1",f"{mode}-0001","V35_COMPLETE_TEMPORALLY_BOUND_PROCESS_IDENTITY_OBSERVER_SNAPSHOT");coverage=snapshot.get("coverage_accounting",{})
        trace_ids=sorted(int(path.name.rsplit(".",1)[1]) for path in trace_dir.glob("trace.*") if path.name.rsplit(".",1)[-1].isdigit())
        rows=coverage.get("per_trace_capture_accounting",[]);indexed={row.get("trace_file_pid"):row for row in rows if isinstance(row,dict)}
        valid=[pid for pid in trace_ids if pid in indexed and indexed[pid].get("host_pid")==pid and isinstance(indexed[pid].get("identity_capture_attempt_timestamp_monotonic_ns"),int) and isinstance(indexed[pid].get("process_start_identity"),str) and isinstance(indexed[pid].get("pid_namespace_identity"),str) and indexed[pid].get("mapping_result")=="VALID_TEMPORAL_IDENTITY_RECORD" and indexed[pid].get("failure_reason") is None]
        complete=result.get("status")=="PASS" and result.get("observer_exit_code")==0 and isinstance(result.get("observer_exit_reason"),str) and result.get("diagnostic_complete") is True and sorted(indexed)==trace_ids and len(rows)==len(trace_ids)==len(valid) and coverage.get("lineage_relevant_trace_identity_count")==len(trace_ids) and coverage.get("valid_temporal_identity_mapping_count")==len(trace_ids) and coverage.get("missing_identity_count")==0 and coverage.get("ambiguous_identity_count")==0 and coverage.get("coverage_complete") is True
        check(f"I_SELFTEST_{mode}",complete,{"trace_count":len(trace_ids),"valid_count":len(valid),"result_status":result.get("status")})
    lifecycle=independent_lifecycle_verdict(runner)
    check("I020_SOURCE_ORDER",lifecycle.get("status")=="PASS",lifecycle)
    binding=independent_symbol_binding_verdict(runner,available_modules={"invocation_v35"},static_lock_members={"src/invocation_v35.py"})
    check("I020A_SYMBOL_BINDING",binding.get("status")=="PASS",binding)
    binding_cases={
        "MISSING_IMPORT":("v16_tree_canonicalization_precheck()",{"invocation_v35"},{"src/invocation_v35.py"},False),
        "WRONG_ALIAS":("from invocation_v35 import v16_tree_canonicalization_precheck as p\np()",{"invocation_v35"},{"src/invocation_v35.py"},False),
        "STALE_MODULE":("from invocation_v18 import v16_tree_canonicalization_precheck\nv16_tree_canonicalization_precheck()",{"invocation_v35"},{"src/invocation_v35.py"},False),
        "SHADOWED":("from invocation_v35 import v16_tree_canonicalization_precheck\nv16_tree_canonicalization_precheck=None\nv16_tree_canonicalization_precheck()",{"invocation_v35"},{"src/invocation_v35.py"},False),
        "VALIDATOR_ONLY":("from invocation_v35 import v16_tree_canonicalization_precheck\nv16_tree_canonicalization_precheck()",set(),{"src/invocation_v35.py"},False),
        "LOCK_OMISSION":("from invocation_v35 import v16_tree_canonicalization_precheck\nv16_tree_canonicalization_precheck()",{"invocation_v35"},set(),False),
        "AMBIGUOUS":("from invocation_v35 import v16_tree_canonicalization_precheck\nfrom alternate import v16_tree_canonicalization_precheck\nv16_tree_canonicalization_precheck()",{"invocation_v35","alternate"},{"src/invocation_v35.py"},False),
        "EXACT":("from invocation_v35 import v16_tree_canonicalization_precheck\nv16_tree_canonicalization_precheck()",{"invocation_v35"},{"src/invocation_v35.py"},True),
    }
    for name,(source,modules,members,expected_pass) in binding_cases.items():
        verdict=independent_symbol_binding_verdict(source,available_modules=modules,static_lock_members=members)
        check(f"I_SYMBOL_{name}",(verdict.get("status")=="PASS") is expected_pass,verdict)
    manifest=load(ROOT/"contracts/LOCKED_ENTRYPOINT_SYMBOL_BINDING_MANIFEST.json")
    manifest_rows={row.get("symbol"):row for row in manifest.get("symbols",[]) if isinstance(row,dict)}
    target=manifest_rows.get("v16_tree_canonicalization_precheck",{})
    manifest_exact=(manifest.get("status")=="PASS" and manifest.get("failure_count")==0 and manifest.get("runner_sha256")==digest(ROOT/"src/runner_v35.py") and target.get("defining_module")=="invocation_v35" and target.get("expected_alias")=="v16_tree_canonicalization_precheck" and target.get("defining_source_artifact")=="src/invocation_v35.py" and target.get("defining_source_sha256")==digest(ROOT/"src/invocation_v35.py"))
    check("I020B_SYMBOL_MANIFEST",manifest_exact,{"symbol_count":manifest.get("symbol_count"),"target":target})
    complete_graph=independent_complete_symbol_graph(runner)
    graph_fields=("symbol","defining_module","expected_imported_name","expected_alias","expected_import_or_binding","call_or_reference_sites","logical_module_identity","module_class","expected_module_origin","expected_loader_identity","pinned_runtime_identity","expected_exported_symbol_identity","defining_source_artifact","defining_source_sha256","dependency_closure_membership","static_lock_membership")
    graph_exact=(complete_graph.get("status")=="PASS" and set(complete_graph.get("rows",{}))==set(manifest_rows) and all({field:complete_graph["rows"][name].get(field) for field in graph_fields}=={field:manifest_rows[name].get(field) for field in graph_fields} for name in manifest_rows))
    check("I020C_COMPLETE_SYMBOL_GRAPH",graph_exact,{"independent_symbol_count":len(complete_graph.get("rows",{})),"manifest_symbol_count":len(manifest_rows),"failures":complete_graph.get("failures")})
    for index,path in enumerate(sorted([*ROOT.glob("*.py"),*(ROOT/"src").glob("*.py"),*(ROOT/"validators").glob("*.py"),*(ROOT/"tests").glob("*.py")]),30):
        try:ast.parse(path.read_text());ok=True
        except SyntaxError:ok=False
        check(f"I{index:03d}_AST_{path.name}",ok)
    check("I060_LOCK_ABSENT",not(ROOT/"STATIC_EXECUTION_LOCK.json").exists());check("I061_RUN_EMPTY",not any(RUN.iterdir()))
    failures=[x["id"] for x in checks if x["status"]=="FAIL"]
    result={"record_type":"V35_INDEPENDENT_STATIC_VALIDATION","execution_identity":"V0_3_FIRST_REAL_SECURITY_WORKER_INVOCATION_V35","status":"PASS" if not failures else "FAIL_CLOSED","checks":checks,"failure_ids":failures,"validation_counts":{"total":len(checks),"passed":len(checks)-len(failures),"failed":len(failures)},"attempt_count":0,"worker_invocation_count":0,"codex_as_worker_invocation_count":0}
    boundary_row=next(row for row in load(ROOT/"contracts/CANONICAL_MODULE_BINDINGS.json")["modules"] if row["canonical_logical_module_name"]=="workspace_boundary_v35")
    boundary_path=Path(boundary_row["canonical_source_path"])
    if digest(boundary_path)!=boundary_row["exact_source_sha256"]:raise RuntimeError("BOUNDARY_DIGEST_MISMATCH")
    boundary_spec=importlib.util.spec_from_file_location("v23_independent_boundary",boundary_path)
    if boundary_spec is None or boundary_spec.loader is None:raise RuntimeError("BOUNDARY_SPEC_UNAVAILABLE")
    boundary_module=importlib.util.module_from_spec(boundary_spec);boundary_spec.loader.exec_module(boundary_module)
    out=ROOT/"results/prelock/independent-static-validation-run-0001.json"
    boundary_module.guarded_json_once(out,result,operation_identity="INDEPENDENT_STATIC_VALIDATION",generation="RUN_0001")
    print(json.dumps(result["validation_counts"],sort_keys=True));return 0 if not failures else 1
if __name__=="__main__":raise SystemExit(main())
