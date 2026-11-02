#!/usr/bin/env python3
"""Build the governance-only V34 prelock/probe lifecycle adjudication."""

from governance_common import (
    IDENTITY,
    ROOT,
    V34,
    V34_IDENTITY,
    V35,
    V35_IDENTITY,
    failure_path_evidence,
    sha256,
    verify_v33_frozen,
    verify_v34_frozen,
    write_once,
)


def emit(name: str, value: dict) -> None:
    write_once(ROOT / name, value)


def main() -> int:
    v34 = verify_v34_frozen()
    v33 = verify_v33_frozen()
    evidence = failure_path_evidence()
    if v34["status"] != "PASS" or v33["status"] != "PASS" or evidence["status"] != "PASS":
        raise SystemExit("frozen evidence verification failed")
    if V35.exists():
        raise SystemExit("governance-only milestone forbids V35 creation")

    regressions = [
        "CORRECTLY_PROVISIONED_PRELOCK_ROOT_PASSES",
        "UNEXPECTEDLY_ABSENT_PRELOCK_ROOT_FAILS_CLOSED",
        "CORRECTLY_PROVISIONED_FIXTURE_PROBE_ROOT_PASSES",
        "MISSING_PROBE_PARENT_FAILS_CLOSED",
        "PROBE_PARENT_SYMLINK_FAILS_CLOSED",
        "PROBE_ESCAPING_CURRENT_WORKSPACE_FAILS_CLOSED",
        "PROBE_TARGETING_PREDECESSOR_ROOT_FAILS_CLOSED",
        "NEGATIVE_SYMLINK_FIXTURE_EXECUTES_WITH_ZERO_PREDECESSOR_MUTATION",
        "FIRST_UNIT_FAILURE_EVIDENCE_WRITABLE_AT_REQUIRED_LIFECYCLE_STAGE",
    ]

    contract = {
        "record_type": "SUCCESSOR_V35_PRELOCK_RESULTS_AND_FIXTURE_PROBE_LIFECYCLE_CONTRACT",
        "contract_identity": "V35_PRELOCK_RESULTS_AND_FIXTURE_PROBE_LIFECYCLE_CONTRACT_V1",
        "successor_identity": V35_IDENTITY,
        "authorizing_governance_identity": IDENTITY,
        "authorizing_governance_lock_sha256": "EXACT_SHA256_OF_THIS_PACKAGE_GOVERNANCE_LOCK_JSON",
        "responsible_component": "V35_PRELOCK_STORAGE_LIFECYCLE_CONTROLLER_V1",
        "provisioners": {
            "prelock_evidence_root": "V35_PRELOCK_EVIDENCE_ROOT_PROVISIONER_V1",
            "fixture_probe_root": "V35_FIXTURE_SCRATCH_ROOT_PROVISIONER_V1",
        },
        "lifecycle_order": [
            "FRESH_WORKSPACE_IDENTITY_BOUND",
            "WORKSPACE_BOUNDARY_AND_PREDECESSOR_DENY_ROOTS_VERIFIED",
            "PRELOCK_EVIDENCE_ROOT_ATOMIC_EXCLUSIVE_PROVISIONING",
            "FIXTURE_SCRATCH_ROOT_ATOMIC_EXCLUSIVE_PROVISIONING",
            "PROVISIONING_EVIDENCE_APPEND_ONLY_WRITE",
            "FIRST_UNIT_OR_VALIDATION_EVIDENCE_WRITER",
            "UNIT_FIXTURE_EXECUTION",
        ],
        "prelock_evidence_root": {
            "canonical_path": "<V35_WORKSPACE>/results/prelock",
            "path_components": ["results", "prelock"],
            "type": "REAL_DIRECTORY_NOT_SYMLINK",
            "creation": "ATOMIC_EXCLUSIVE_EXACT_COMPONENTS_NO_RECURSIVE_OR_IDEMPOTENT_CREATE",
            "preexisting_state": "PROHIBITED_FOR_FRESH_V35",
            "initial_state": "EMPTY_BEFORE_PROVISIONING_EVIDENCE",
            "mode_during_prelock": "0700",
            "owner": "EXACT_V35_WORKSPACE_UID_GID_BOUND_BY_WORKSPACE_IDENTITY",
            "availability_deadline": "BEFORE_FIRST_EVIDENCE_WRITER_AND_BEFORE_UNIT_FIXTURES",
            "write_semantics": "APPEND_ONLY_DISTINCT_RESULT_SLOTS",
        },
        "fixture_scratch_probe_root": {
            "canonical_path": "<V35_WORKSPACE>/scratch/prelock-fixtures/run-0001",
            "probe_leaf": ".predecessor-symlink-probe",
            "separate_from_authoritative_evidence_root": True,
            "type": "REAL_DIRECTORY_NOT_SYMLINK",
            "creation": "ATOMIC_EXCLUSIVE_EXACT_COMPONENTS_NO_RECURSIVE_OR_IDEMPOTENT_CREATE",
            "preexisting_state": "PROHIBITED_FOR_FRESH_V35_RUN_0001",
            "initial_state": "EMPTY",
            "mode": "0700",
            "owner": "EXACT_V35_WORKSPACE_UID_GID_BOUND_BY_WORKSPACE_IDENTITY",
            "cleanup": "ONLY_EXACT_DISPOSABLE_PROBE_LEAF_AFTER_SNAPSHOT_VERIFIED_NEGATIVE_FIXTURE",
        },
        "boundary_requirements": {
            "canonical_realpath_containment": "EXACT_V35_WORKSPACE_ONLY",
            "predecessor_roots": "EXPLICIT_READ_ONLY_DENY_WRITE_ROOTS",
            "relative_traversal": "REJECT_BEFORE_MUTATION",
            "symlink_parent_or_component": "REJECT_BEFORE_MUTATION",
            "ambiguous_or_unresolved_identity": "FAIL_CLOSED_BEFORE_MUTATION",
            "predecessor_snapshot_before_after": "EXACT_EQUALITY_REQUIRED",
        },
        "evidence": {
            "provisioning_record": "results/prelock/prelock-storage-lifecycle-run-0001.json",
            "record_is_first_prelock_writer": True,
            "record_fields": [
                "workspace_identity", "provisioner_identity", "canonical_paths", "uid", "gid",
                "modes", "initial_emptiness", "creation_order", "predecessor_snapshot_digest", "status",
            ],
            "provisioning_failure": "TYPED_FAIL_CLOSED_VERDICT_TO_PREEXISTING_WORKSPACE_GENESIS_BOOTSTRAP_JOURNAL; UNIT_MUST_NOT_START",
        },
        "prohibited_repairs": [
            "AD_HOC_MKDIR_P", "PATH_MKDIR_PARENTS_TRUE", "EXIST_OK_TRUE", "MANUAL_DIRECTORY_CREATION",
            "PREEXISTING_DIRECTORY_REUSE", "DELETE_AND_RECREATE", "COMPATIBILITY_DIRECTORY_REUSE",
        ],
        "failure_policy": "FAIL_CLOSED_BEFORE_UNIT_VALIDATION_OR_STATIC_LOCK_OR_ATTEMPT",
        "status": "NORMATIVE_FOR_CONDITIONALLY_AUTHORIZED_SUCCESSOR_ONLY",
    }

    emit("GOVERNANCE_CHARTER.json", {
        "record_type": "GOVERNANCE_CHARTER",
        "governance_identity": IDENTITY,
        "scope": "GOVERNANCE_ONLY",
        "prohibited": [
            "PATCH_V34", "RERUN_V34", "DUPLICATE_V34", "CREATE_MISSING_V34_DIRECTORIES",
            "RUN_V34_PRIMARY", "RUN_V34_INDEPENDENT", "RUN_V34_FRESH_PREFLIGHT",
            "ISSUE_V34_STATIC_LOCK", "INVOKE_SECURITY_WORKER", "INVOKE_CODEX", "CREATE_OR_EXECUTE_V35",
        ],
        "status": "ACTIVE",
    })
    emit("ROUTING_LEDGER.json", {
        "record_type": "ROUTING_LEDGER",
        "active": ["mandatory-auto-router", "authorized-security-autopilot", "codex-security-harness"],
        "deferred": [],
        "not_applicable": [
            "live-target", "recon", "exploit-execution", "external-tools", "paid-tools",
            "subagents", "parallelism", "worker-runtime", "codex-invocation",
        ],
        "reason": "LOCAL_GOVERNANCE_ONLY_FILESYSTEM_LIFECYCLE_ADJUDICATION",
        "status": "PASS",
    })
    emit("V34_FROZEN_FAILURE_EVIDENCE_BINDING.json", {
        "record_type": "V34_FROZEN_FAILURE_EVIDENCE_BINDING",
        "execution_identity": V34_IDENTITY,
        "canonical_evidence_root_sha256": "fb38ae77756d335cdd8b14ea833920b4255478f63a5d6a97544b1464eb6a9811",
        "terminal_sha256": "8c34d02a97d837c0466ff311e4d1ab197253ba7e04330db7e4ed7666a45759b3",
        "failure_manifest_sha256": "604dcf1b0675392ed8ce724a9de424fd0f7a640c8f9da9e5250fa0c0bebaab3a",
        "freeze_verification_sha256": "4f7f55ba9528b357ab8cec1082bdac6ed177f37c0d70866be788ada8960d9b45",
        "unit_failure_sha256": sha256(V34 / "results/prelock/unit-fixtures-run-0001.json"),
        "verification": v34,
        "status": "PASS",
    })
    emit("V33_FROZEN_EVIDENCE_PRESERVATION_BINDING.json", {
        "record_type": "V33_FROZEN_EVIDENCE_PRESERVATION_BINDING",
        "canonical_evidence_root_sha256": "7697ad9d1f20e8e47d6544031c229b9037dec1fd8c7ab7574d1f3091e729227d",
        "terminal_sha256": "6fc29626608e6a286e21b7b442ccc5d3c299513fa378439f23c2898630e7ad62",
        "failure_manifest_sha256": "67e9a687aae31566859e01d58a1713e91ccb6bb2876154f3dd9032ba4640c01c",
        "freeze_verification_sha256": "111604877cb22a242b4c8252a7472555dd673f9b1512d34f4cd9c1a84bfb260b",
        "verification": v33,
        "status": "PASS",
    })
    emit("V34_FAILURE_FACTS.json", {
        "record_type": "V34_FAILURE_FACTS",
        "unit": "FAIL_CLOSED_EXECUTION_ERROR",
        "failed_gate": "UNIT_HARNESS_NEGATIVE_FIXTURE_PARENT_DIRECTORY_LIFECYCLE",
        "primary": "NOT_STARTED",
        "independent": "NOT_STARTED",
        "preflight": "NOT_STARTED",
        "static_lock": "NOT_ISSUED",
        "attempt": "0/1",
        "worker": "0/1",
        "codex": "0/1",
        "attempt_marker": "ABSENT",
        "runtime_evidence": "ABSENT",
        "status": "PASS",
    })
    emit("V34_FIXTURE_PROBE_PATH_FAILURE_EVIDENCE.json", evidence)
    emit("V34_PRELOCK_RESULTS_AND_FIXTURE_PROBE_LIFECYCLE_ADJUDICATION.json", {
        "record_type": "V34_PRELOCK_RESULTS_AND_FIXTURE_PROBE_LIFECYCLE_ADJUDICATION",
        "PRELOCK_RESULTS_DIRECTORY_LIFECYCLE_DEFECT": "YES",
        "FIXTURE_PROBE_PARENT_DIRECTORY_PRECONDITION_DEFECT": "YES",
        "unit_failure_cause": "PROBE_PARENT_ABSENT_WHEN_OS_SYMLINK_ATTEMPTED",
        "responsibility": {
            "prelock_results_root": "PRELOCK_STORAGE_LIFECYCLE_CONTROLLER_BEFORE_FIRST_EVIDENCE_WRITER",
            "fixture_probe_root": "FIXTURE_SCRATCH_PROVISIONER_BEFORE_UNIT_FIXTURE_EXECUTION",
            "fixture_itself": "MUST_VERIFY_TYPED_READY_VERDICT_BEFORE_CREATING_PROBE_LEAF",
        },
        "ad_hoc_directory_workaround_authorized": False,
        "v34_source_patch_authorized": False,
        "status": "PASS",
    })
    emit("SUCCESSOR_V35_PRELOCK_RESULTS_AND_FIXTURE_PROBE_LIFECYCLE_CONTRACT.json", contract)
    emit("V34_FAILURE_AND_V35_REGRESSION_MATRIX.json", {
        "record_type": "V34_FAILURE_AND_V35_REGRESSION_MATRIX",
        "required_regressions": regressions,
        "count": len(regressions),
        "zero_predecessor_mutation_required": True,
        "typed_fail_closed_required": True,
        "carry_forward": "V34_TYPED_VALIDATOR_HELPER_RETURN_CONTRACT_AND_ALL_APPLICABLE_V1_THROUGH_V34_CONTROLS",
        "status": "PASS",
    })
    emit("V34_PRESERVED_ENGINEERING_FACTS.json", {
        "record_type": "V34_PRESERVED_ENGINEERING_FACTS",
        "facts": {
            "typed_validator_helper_return_contract_implemented": True,
            "inspect_runtime_identity_explicit_typed_return_semantics": True,
            "ast_control_flow_checks_implemented": True,
            "caller_side_verdict_type_guards_implemented": True,
            "return_control_flow_regressions": 8,
            "authoritative_artifact_creation_closure_members": 199,
            "symbol_graph_symbols": 97,
            "undeclared_pyc_or_pycache": 0,
            "attempt_marker": "ABSENT",
            "runtime_evidence": "ABSENT",
        },
        "classification": "FROZEN_ENGINEERING_FACTS_ONLY_NOT_FULL_UNIT_OR_STATIC_VALIDATION_PASS",
        "status": "PASS",
    })
    emit("V34_RUNTIME_AND_PROOF_GATE_SEPARATION_ADJUDICATION.json", {
        "record_type": "V34_RUNTIME_AND_PROOF_GATE_SEPARATION_ADJUDICATION",
        "CODEX_0_166_0_RUNTIME": "NOT_ESTABLISHED_FOR_V34_EXECUTION",
        "SECURITY_WORKER_RUNTIME": "NOT_ESTABLISHED",
        "TEMPORAL_OBSERVER_RUNTIME": "NOT_ESTABLISHED",
        "PROCESS_LINEAGE": "NOT_PROVEN",
        "PRODUCER_AUTHORIZATION": "NOT_PROVEN",
        "CONFINEMENT": "NOT_PROVEN",
        "reason": "V34_NEVER_COMPLETED_UNIT_VALIDATION_AND_NEVER_REACHED_EXECUTION",
        "status": "PASS",
    })
    emit("V34_TERMINAL_AND_V35_SUCCESSOR_DECISION.json", {
        "record_type": "V34_TERMINAL_AND_V35_SUCCESSOR_DECISION",
        "v34_disposition": "TERMINAL_IMMUTABLE_NO_RETRY",
        "v35_disposition": "CONDITIONALLY_AUTHORIZED_NOT_CREATED_NOT_EXECUTED",
        "v35_authorized_scope": "FRESH_SUCCESSOR_IMPLEMENTING_EXPLICIT_PRELOCK_EVIDENCE_AND_FIXTURE_SCRATCH_LIFECYCLES_AND_CARRYING_FORWARD_APPLICABLE_CONTROLS",
        "attempt": "0/1",
        "worker_invocation": "0/1",
        "codex_as_worker_invocation": "0/1",
        "status": "PASS",
    })
    emit("V34_IMMUTABILITY_AND_AUTHORITY_CEILING.json", {
        "record_type": "V34_IMMUTABILITY_AND_AUTHORITY_CEILING",
        "v34_write_authority": "NONE",
        "v34_retry_authority": "NONE",
        "v34_execution_authority": "NONE",
        "v35_creation_authority_during_this_milestone": "NONE",
        "v35_execution_authority_during_this_milestone": "NONE",
        "status": "PASS",
    })
    emit("NEXT_LEGAL_MILESTONE.json", {
        "record_type": "NEXT_LEGAL_MILESTONE",
        "milestone": "IMPLEMENT_FRESH_V0_3_FIRST_REAL_SECURITY_WORKER_INVOCATION_V35_ONLY_UNDER_SEPARATE_EXPLICIT_ENGINEERING_REQUEST",
        "current_state": "V35_CONDITIONALLY_AUTHORIZED_NOT_CREATED_NOT_EXECUTED",
        "status": "PASS",
    })
    print("GOVERNANCE_BUILD=PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
