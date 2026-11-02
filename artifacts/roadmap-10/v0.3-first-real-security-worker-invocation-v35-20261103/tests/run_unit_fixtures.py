"""Deterministic V1-V35 regression fixtures; never invokes Codex."""
from __future__ import annotations

import ast
import hashlib
import importlib.util
import json
import os
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
    "UNIT",
    ("workspace_boundary_v35", "predecessor_binding_v35", "external_artifact_binding_v35", "binding_generation_v35",
     "historical_decision_registry_v35", "transactional_telemetry_v35",
     "symbol_resolution_v35", "mount_output_binding_v35", "preflight_requirement_registry_v35",
     "host_output_lifecycle_v35", "runtime_acceptance_v35", "artifact_finalization_v35",
     "current_digest_view_v35", "validator_helper_contract_v35", "prelock_storage_lifecycle_v35",
     "invocation_v35", "worker_launch_gate_v35",
     "topology_observer_v35", "short_lived_child_v35", "runner_v35"),
)

from invocation_v35 import (  # noqa: E402
    AUTHORIZATION_ID,
    EXECUTION_IDENTITY,
    EXPECTED_DIGESTS,
    PREDECESSOR_PATHS,
    STATIC_RUN,
    append_only_json,
    authoritative_artifact_digest_precheck,
    authoritative_predecessor_resolution_precheck,
    bind_destination_feasibility_precheck,
    bwrap_argv,
    canonical_prompt_words,
    classify_fd_annotations,
    independently_validate_coverage_accounting,
    observer_diagnostic_verdict,
    parse_fd_annotation,
    parse_syscall_line,
    normative_component_path_key,
    normative_frozen_tree,
    flattened_non_normative_tree,
    v16_tree_canonicalization_precheck,
    process_identity_correlation_precheck,
    python_cache_policy_precheck,
    python_execution_policy_verdict,
    exact_python_environment,
    prompt_identity_binding_precheck,
    prompt_policy_verdict,
    runtime_binding_fixture_verdict,
    inspect_runtime_identity,
    sha256_file,
    semantic_lifecycle_anchor_verdict,
    startup_lineage_policy_precheck,
    strict_schema_compatibility_verdict,
    temporal_identity_coverage_verdict,
    temporal_process_identity_observer_precheck,
    token_budget_feasibility_precheck,
    typed_fd_annotation_grammar_precheck,
    v2_locked_bwrap_argv,
    verify_v1_reference_predecessor,
    verify_v2_reference_predecessor,
    verify_v3_reference_predecessor,
    verify_v4_reference_predecessor,
    verify_v5_reference_predecessor,
    verify_v6_reference_predecessor,
    verify_v7_reference_predecessor,
    verify_v8_reference_predecessor,
    verify_v9_reference_predecessor,
    verify_v10_reference_predecessor,
    verify_v11_reference_predecessor,
    verify_v12_reference_predecessor,
    verify_v13_reference_predecessor,
    verify_v14_reference_predecessor,
    verify_v15_reference_predecessor,
    verify_v16_reference_predecessor,
    verify_v17_reference_predecessor,
    verify_v18_reference_predecessor,
    verify_v19_reference_predecessor,
    verify_v20_reference_predecessor,
    verify_v24_reference_predecessor,
    verify_v25_reference_predecessor,
    verify_v26_reference_predecessor,
    workspace_write_boundary_precheck,
)
from predecessor_binding_v35 import (  # noqa: E402
    EXPECTED_PREDECESSOR_IDENTITY,
    EXPECTED_V18_STATIC_LOCK_SHA256,
    EXPECTED_V18_TREE_ROOT,
    EXPECTED_V35_DECISION_SHA256,
    EXPECTED_V35_GOVERNANCE_LOCK_SHA256,
    canonical_predecessor_binding_precheck,
    canonical_predecessor_binding_verdict,
)
from external_artifact_binding_v35 import (  # noqa: E402
    external_artifact_candidate_verdict,
    external_predecessor_artifact_precheck,
)
from runner_v35 import run_temporal_observer_selftest  # noqa: E402
from current_digest_view_v35 import (  # noqa: E402
    CURRENT_KEY_IDENTITIES,
    derived_current_expected_digest_view_precheck,
    derived_view_fixture_verdict,
)
_independent_path = ROOT / "validators/independent_static_validate.py"
_independent_spec = importlib.util.spec_from_file_location("v26_independent_fixture_module", _independent_path)
if _independent_spec is None or _independent_spec.loader is None:
    raise RuntimeError("V35_INDEPENDENT_FIXTURE_SPEC_UNAVAILABLE")
_independent = importlib.util.module_from_spec(_independent_spec)
_independent_spec.loader.exec_module(_independent)
independent_lifecycle_verdict = _independent.independent_lifecycle_verdict
from module_resolution_v35 import (  # noqa: E402
    RUNTIME_IDENTITY,
    canonical_graph_equivalence_verdict,
    canonical_module_resolution_precheck,
    module_resolution_fixture_verdict,
    typed_module_fixture_verdict,
)
from symbol_resolution_v35 import binding_fixture_verdict, static_symbol_binding_precheck  # noqa: E402
from artifact_finalization_v35 import (  # noqa: E402
    authoritative_artifact_finalization_precheck,
    finalization_fixture_verdict,
)
from workspace_boundary_v35 import (  # noqa: E402
    EXECUTION_IDENTITY as GUARD_IDENTITY,
    WORKSPACE as GUARD_WORKSPACE,
    WorkspaceBoundaryError,
    authorize_read,
    authorize_write,
    guarded_mkdir,
)
from binding_generation_v35 import (  # noqa: E402
    GENERATION_IDENTITY,
    GOVERNANCE_LOCK_SHA256,
    GOVERNANCE_IDENTITY,
    binding_fixture_verdict as unified_binding_fixture_verdict,
    unified_binding_generation_precheck,
)
from historical_decision_registry_v35 import (  # noqa: E402
    historical_decision_relation_precheck,
    relation_fixture_verdict,
)
from transactional_telemetry_v35 import (  # noqa: E402
    completion_fixture_verdict,
    failure_envelope_verdict,
)
from mount_output_binding_v35 import (  # noqa: E402
    mount_output_binding_fixture_verdict,
    mount_output_binding_precheck,
    stale_mount_literal_fixture_verdict,
    stale_mount_literal_precheck,
)
from preflight_requirement_registry_v35 import (  # noqa: E402
    typed_preflight_registry_fixture_verdict,
    typed_preflight_requirement_precheck,
)
from host_output_lifecycle_v35 import (  # noqa: E402
    host_output_bind_source_precheck,
    lifecycle_fixture_verdict as host_output_lifecycle_fixture_verdict,
    provisioning_fixture_verdict,
    provision_host_output_bind_source,
)
from runtime_acceptance_v35 import (  # noqa: E402
    runtime_acceptance_fixture_verdict,
    typed_runtime_acceptance_precheck,
)
from validator_helper_contract_v35 import (  # noqa: E402
    TypedValidatorVerdictError,
    caller_guard_verdict,
    critical_validator_helper_contract_precheck,
    helper_source_verdict,
    require_typed_verdict,
)
from prelock_storage_lifecycle_v35 import (  # noqa: E402
    CREATION_ORDER as PRELOCK_CREATION_ORDER,
    FIXTURE_PROBE_ROOT,
    PRELOCK_ROOT,
    lifecycle_fixture_verdict as prelock_lifecycle_fixture_verdict,
    prelock_storage_lifecycle_precheck,
)


def identity(pid: int, start: str | None = None, namespace: str | None = "pid:[42]") -> dict[str, object]:
    start_identity = start or f"PROC_CONNECTOR_FORK_EVENT:{pid}:1:{pid}"
    return {
        "trace_file_pid": pid,
        "process_start_identity": start_identity,
        "pid_namespace_identity": namespace,
        "stable_identity_tuple": [pid, start_identity, namespace],
        "temporal_binding_status": "PASS",
    }


def main() -> int:
    checks: list[dict[str, object]] = []

    def check(name: str, condition: bool, evidence: object | None = None) -> None:
        checks.append({"id": name, "status": "PASS" if condition else "FAIL", "evidence": evidence})

    def tree_digest(root: Path) -> str:
        rows = []
        for path in root.rglob("*"):
            if path.is_file() or path.is_symlink():
                rows.append((path.relative_to(root).as_posix(), hashlib.sha256(path.read_bytes()).hexdigest()))
        return hashlib.sha256("".join(f"{name}\0{digest}\n" for name, digest in sorted(rows)).encode()).hexdigest()

    def denied(callable_object) -> bool:
        try:
            callable_object()
        except WorkspaceBoundaryError:
            return True
        return False

    v14_root = Path("/home/nobcoder/v0.3-first-real-security-worker-invocation-v14-20261023")
    v15_root = Path("/home/nobcoder/v0.3-first-real-security-worker-invocation-v15-20261023")
    v16_root = Path("/home/nobcoder/v0.3-first-real-security-worker-invocation-v16-20261023")
    v17_root = Path("/home/nobcoder/v0.3-first-real-security-worker-invocation-v17-20261023")
    v18_root = Path("/home/nobcoder/v0.3-first-real-security-worker-invocation-v18-20261023")
    v19_root = Path("/home/nobcoder/v0.3-first-real-security-worker-invocation-v19-20261025")
    v20_root = Path("/home/nobcoder/v0.3-first-real-security-worker-invocation-v20-20261101")
    v21_root = Path("/home/nobcoder/v0.3-first-real-security-worker-invocation-v21-20261101")
    v22_root = Path("/home/nobcoder/v0.3-first-real-security-worker-invocation-v22-20261101")
    v23_root = Path("/home/nobcoder/v0.3-first-real-security-worker-invocation-v23-20261101")
    v24_root = Path("/home/nobcoder/v0.3-first-real-security-worker-invocation-v24-20261101")
    v25_root = Path("/home/nobcoder/v0.3-first-real-security-worker-invocation-v25-20261101")
    v26_root = Path("/home/nobcoder/v0.3-first-real-security-worker-invocation-v26-20261102")
    v27_root = Path("/home/nobcoder/v0.3-first-real-security-worker-invocation-v27-20261102")
    v28_root = Path("/home/nobcoder/v0.3-first-real-security-worker-invocation-v28-20261102")
    v29_root = Path("/home/nobcoder/v0.3-first-real-security-worker-invocation-v29-20261102")
    v30_root = Path("/home/nobcoder/v0.3-first-real-security-worker-invocation-v30-20261102")
    v31_root = Path("/home/nobcoder/v0.3-first-real-security-worker-invocation-v31-20261102")
    v32_root = Path("/home/nobcoder/v0.3-first-real-security-worker-invocation-v32-20261102")
    v33_root = Path("/home/nobcoder/v0.3-first-real-security-worker-invocation-v33-20261103")
    v34_root = Path("/home/nobcoder/v0.3-first-real-security-worker-invocation-v34-20261103")
    protected_roots = (
        v14_root, v15_root, v16_root, v17_root, v18_root, v19_root, v20_root, v21_root,
        v22_root, v23_root, v24_root, v25_root, v26_root, v27_root, v28_root, v29_root,
        v30_root, v31_root, v32_root, v33_root, v34_root,
    )
    prelock_lifecycle = prelock_storage_lifecycle_precheck("UNIT")
    check("U000_PRELOCK_STORAGE_LIFECYCLE_READY", prelock_lifecycle.get("status") == "PASS", prelock_lifecycle)
    check(
        "U000_PRELOCK_PROVISIONING_EVIDENCE_FIRST_WRITER",
        sorted(path.name for path in PRELOCK_ROOT.iterdir()) == ["prelock-storage-lifecycle-run-0001.json"],
    )
    fixture_base = {
        "workspace_boundary_status": "PASS",
        "prelock_root": str(PRELOCK_ROOT),
        "fixture_probe_root": str(FIXTURE_PROBE_ROOT),
        "prelock_real_directory": True,
        "prelock_symlink": False,
        "probe_real_directory": True,
        "probe_symlink": False,
        "prelock_initially_empty": True,
        "probe_initially_empty": True,
        "prelock_mode": "0700",
        "probe_mode": "0700",
        "prelock_uid": os.getuid(),
        "prelock_gid": os.getgid(),
        "probe_uid": os.getuid(),
        "probe_gid": os.getgid(),
        "exclusive_creation": True,
        "preexisting_reuse": False,
        "creation_order": PRELOCK_CREATION_ORDER,
        "current_workspace_containment": True,
        "predecessor_deny_write": True,
        "predecessor_snapshot_before": "EXACT",
        "predecessor_snapshot_after": "EXACT",
        "provisioning_evidence_is_first_prelock_writer": True,
        "first_unit_failure_evidence_writable": True,
    }
    check("U000_LIFECYCLE_EXACT_POSITIVE", prelock_lifecycle_fixture_verdict(fixture_base).get("status") == "PASS")
    lifecycle_negative_cases = {
        "ABSENT_PRELOCK_ROOT": {"prelock_real_directory": False},
        "MISSING_PROBE_PARENT": {"probe_real_directory": False},
        "PROBE_PARENT_SYMLINK": {"probe_symlink": True},
        "PROBE_ESCAPES_WORKSPACE": {"current_workspace_containment": False},
        "PROBE_TARGETS_PREDECESSOR": {"predecessor_deny_write": False},
        "PREDECESSOR_MUTATION": {"predecessor_snapshot_after": "MUTATED"},
        "FIRST_FAILURE_NOT_WRITABLE": {"first_unit_failure_evidence_writable": False},
        "PREEXISTING_REUSE": {"preexisting_reuse": True},
    }
    for name, mutation in lifecycle_negative_cases.items():
        candidate = dict(fixture_base)
        candidate.update(mutation)
        check(f"U000_LIFECYCLE_{name}_FAILS_CLOSED", prelock_lifecycle_fixture_verdict(candidate).get("status") != "PASS")
    first_failure_path = PRELOCK_ROOT / "unit-fixtures-run-0001.json"
    check(
        "U000_FIRST_UNIT_FAILURE_EVIDENCE_WRITABLE",
        authorize_write(first_failure_path, operation_identity="UNIT_FIRST_FAILURE_SLOT_PREFLIGHT", write_generation_identity="RUN_0001", expected_destination=first_failure_path).get("status") == "PASS_FAIL_BEFORE_WRITE_BOUNDARY",
    )
    predecessor_before = tuple(tree_digest(root) for root in protected_roots)
    v26_probe = ROOT / "results/prelock/workspace-boundary-positive-probe.json"
    check("U000A_V35_EXACT_DESTINATION", authorize_write(v26_probe, operation_identity="UNIT_BOUNDARY_POSITIVE", write_generation_identity="RUN_0001", expected_destination=v26_probe).get("status") == "PASS_FAIL_BEFORE_WRITE_BOUNDARY")
    check("U000B_V14_WRITE_DENIED", denied(lambda: authorize_write(v14_root/"results/prelock/forbidden-v19.json", operation_identity="UNIT_V14_DENIAL", write_generation_identity="RUN_0001", expected_destination=v14_root/"results/prelock/forbidden-v19.json")))
    check("U000C_V15_WRITE_DENIED", denied(lambda: authorize_write(v15_root/"results/prelock/forbidden-v19.json", operation_identity="UNIT_V15_DENIAL", write_generation_identity="RUN_0001", expected_destination=v15_root/"results/prelock/forbidden-v19.json")))
    check("U000C2_V16_WRITE_DENIED", denied(lambda: authorize_write(v16_root/"results/prelock/forbidden-v19.json", operation_identity="UNIT_V16_DENIAL", write_generation_identity="RUN_0001", expected_destination=v16_root/"results/prelock/forbidden-v19.json")))
    check("U000C3_V17_WRITE_DENIED", denied(lambda: authorize_write(v17_root/"results/prelock/forbidden-v19.json", operation_identity="UNIT_V17_DENIAL", write_generation_identity="RUN_0001", expected_destination=v17_root/"results/prelock/forbidden-v19.json")))
    check("U000C4_V18_WRITE_DENIED", denied(lambda: authorize_write(v18_root/"static-run-v18/forbidden-v35.json", operation_identity="UNIT_V18_DENIAL", write_generation_identity="RUN_0001", expected_destination=v18_root/"static-run-v18/forbidden-v35.json")))
    check("U000C5_V19_WRITE_DENIED", denied(lambda: authorize_write(v19_root/"results/prelock/forbidden-v35.json", operation_identity="UNIT_V19_DENIAL", write_generation_identity="RUN_0001", expected_destination=v19_root/"results/prelock/forbidden-v35.json")))
    check("U000C6_V20_WRITE_DENIED", denied(lambda: authorize_write(v20_root/"results/prelock/forbidden-v35.json", operation_identity="UNIT_V20_DENIAL", write_generation_identity="RUN_0001", expected_destination=v20_root/"results/prelock/forbidden-v35.json")))
    check("U000C7_V23_WRITE_DENIED", denied(lambda: authorize_write(v23_root/"results/prelock/forbidden-v35.json", operation_identity="UNIT_V23_DENIAL", write_generation_identity="RUN_0001", expected_destination=v23_root/"results/prelock/forbidden-v35.json")))
    check("U000C8_V24_WRITE_DENIED", denied(lambda: authorize_write(v24_root/"results/prelock/forbidden-v35.json", operation_identity="UNIT_V24_DENIAL", write_generation_identity="RUN_0001", expected_destination=v24_root/"results/prelock/forbidden-v35.json")))
    check("U000C9_V25_WRITE_DENIED", denied(lambda: authorize_write(v25_root/"results/prelock/forbidden-v35.json", operation_identity="UNIT_V25_DENIAL", write_generation_identity="RUN_0001", expected_destination=v25_root/"results/prelock/forbidden-v35.json")))
    traversal = ROOT / "results/prelock/../../v0.3-first-real-security-worker-invocation-v15-20261023/forbidden.json"
    check("U000D_RELATIVE_TRAVERSAL_DENIED", denied(lambda: authorize_write(traversal, operation_identity="UNIT_TRAVERSAL", write_generation_identity="RUN_0001", expected_destination=traversal)))
    check("U000E_IDENTITY_MISMATCH_DENIED", denied(lambda: authorize_write(v26_probe, invocation_identity="WRONG", operation_identity="UNIT_IDENTITY", write_generation_identity="RUN_0001", expected_destination=v26_probe)))
    check("U000F_WORKSPACE_MISMATCH_DENIED", denied(lambda: authorize_write(v26_probe, workspace_root=v15_root, operation_identity="UNIT_WORKSPACE", write_generation_identity="RUN_0001", expected_destination=v26_probe)))
    check("U000G_PREDECESSOR_READ_ALLOWED", authorize_read(v14_root/"results/prelock/unit-fixtures-run-0001.json", operation_identity="UNIT_PREDECESSOR_READ").is_file())
    check("U000H_PREDECESSOR_APPEND_DENIED", denied(lambda: authorize_write(v14_root/"results/prelock/v35-append.json", operation_identity="UNIT_PREDECESSOR_APPEND", write_generation_identity="RUN_0001", expected_destination=v14_root/"results/prelock/v35-append.json")))
    symlink_probe = FIXTURE_PROBE_ROOT / ".predecessor-symlink-probe"
    authorize_write(symlink_probe, operation_identity="UNIT_SYMLINK_FIXTURE_CREATE", write_generation_identity="RUN_0001", expected_destination=symlink_probe)
    os.symlink(v34_root, symlink_probe)
    try:
        check("U000I_SYMLINK_TO_PREDECESSOR_DENIED", denied(lambda: authorize_write(symlink_probe/"forbidden.json", operation_identity="UNIT_SYMLINK", write_generation_identity="RUN_0001", expected_destination=symlink_probe/"forbidden.json")))
    finally:
        symlink_probe.unlink()
    check("U000I2_FIXTURE_PROBE_ROOT_EMPTY_AFTER_NEGATIVE", not any(FIXTURE_PROBE_ROOT.iterdir()))
    predecessor_after = tuple(tree_digest(root) for root in protected_roots)
    check("U000J_REJECTIONS_ZERO_PREDECESSOR_MUTATION", predecessor_after == predecessor_before, {"before": predecessor_before, "after": predecessor_after})
    python_env = exact_python_environment()
    safe_python = python_execution_policy_verdict(["/usr/bin/python3.14", "-B", "module.py"], python_env)
    unsafe_python = python_execution_policy_verdict(["/usr/bin/python3.14", "module.py"], {})
    predecessor_cache = python_execution_policy_verdict(
        ["/usr/bin/python3.14", "-B", "module.py"],
        python_env,
        v16_root / "src/__pycache__",
    )
    check("U000K_BYTECODE_SUPPRESSION_POLICY", safe_python.get("status") == "PASS", safe_python)
    check("U000L_IMPLICIT_CACHE_UNCONTROLLED_REJECTED", unsafe_python.get("status") == "FAIL_CLOSED_BEFORE_PYTHON_EXECUTION", unsafe_python)
    check("U000M_PREDECESSOR_CACHE_DESTINATION_REJECTED", predecessor_cache.get("status") == "FAIL_CLOSED_BEFORE_PYTHON_EXECUTION", predecessor_cache)
    check("U000N_V16_IMPLICIT_PYC_PRESERVED", (v16_root / "src/__pycache__/workspace_boundary_v16.cpython-314.pyc").is_file())
    check("U000O_CACHE_PREFLIGHT", python_cache_policy_precheck().get("status") == "PASS", python_cache_policy_precheck())

    lifecycle_contract = json.loads((ROOT / "contracts/HOST_OUTPUT_BIND_SOURCE_LIFECYCLE_CONTRACT.json").read_text())
    check("U000P_HOST_OUTPUT_LIFECYCLE_CONTRACT", host_output_lifecycle_fixture_verdict(lifecycle_contract).get("status") == "PASS")
    provisioning_cases = {
        "MISSING_BEFORE_AUTHORIZED_PROVISIONING": ({"path_exists_before": False}, True),
        "PREEXISTING_SOURCE": ({"path_exists_before": True, "is_directory": True}, False),
        "WRONG_OWNER": ({"path_exists_before": False, "owner_uid": os.getuid() + 1}, False),
        "WRONG_MODE": ({"path_exists_before": False, "mode": 0o755}, False),
        "NONEMPTY_REUSED_SOURCE": ({"path_exists_before": True, "is_directory": True, "is_empty": False}, False),
        "SYMLINK_SOURCE": ({"path_exists_before": True, "is_symlink": True}, False),
        "LIFECYCLE_ORDER_VIOLATION": ({"path_exists_before": False, "lifecycle_stage": "BEFORE_WORKSPACE_BOUNDARY"}, False),
    }
    for index, (name, (kwargs, expected_pass)) in enumerate(provisioning_cases.items(), 1):
        verdict = provisioning_fixture_verdict(**kwargs)
        check(f"U000P{index}_HOST_OUTPUT_{name}", (verdict.get("status") == "PASS_TO_EXCLUSIVE_CREATE") is expected_pass, verdict)
    boundary_for_provisioning = workspace_write_boundary_precheck()
    check("U000Q_WORKSPACE_BOUNDARY_BEFORE_PROVISIONING", boundary_for_provisioning.get("status") == "PASS", boundary_for_provisioning)
    provisioning = provision_host_output_bind_source(
        workspace_boundary_status=boundary_for_provisioning.get("status", "FAIL"),
        lifecycle_stage="AFTER_WORKSPACE_BOUNDARY_BEFORE_BIND_FEASIBILITY",
    )
    check("U000R_EXCLUSIVE_HOST_OUTPUT_PROVISIONING", provisioning.get("status") == "PASS", provisioning)
    bind_source = host_output_bind_source_precheck("UNIT", require_current_empty=True)
    check("U000S_HOST_OUTPUT_PROVISIONING_EVIDENCE", bind_source.get("status") == "PASS", bind_source)

    base = "Do not call any tool. Do not access any network or target."
    variants = (
        base,
        "Do not call any tool.\nDo not access any network or target.",
        "Do   not call any tool. Do not access any network or target.",
        "Do\tnot call any tool. Do not access any network or target.",
        "Do not call any tool.\r\nDo not access any network or target.",
    )
    for index, variant in enumerate(variants, 1):
        check(f"U{index:03d}_V1_PROMPT_NORMALIZATION", prompt_policy_verdict(variant)["status"] == "PASS")
    check("U006_V1_MISSING_NETWORK", prompt_policy_verdict("Do not call any tool.")["status"] != "PASS")
    check("U007_V1_WEAKENED", prompt_policy_verdict(base + " Unless needed.")["status"] != "PASS")
    check("U008_V1_CANONICAL_WORDS", canonical_prompt_words("A\r\nB\tC") == ("a", "b", "c"))

    current_bind = bind_destination_feasibility_precheck(bwrap_argv())
    old_bind = bind_destination_feasibility_precheck(v2_locked_bwrap_argv())
    check("U009_V2_CURRENT_BIND_FEASIBLE", current_bind["status"] == "PASS", current_bind)
    check("U010_V2_EROFS_TOPOLOGY_REJECTED", old_bind["status"] == "FAIL_CLOSED", old_bind)

    valid_schema = {"type": "object", "additionalProperties": False, "required": ["x"], "properties": {"x": {"type": "string"}}}
    check("U011_V3_STRICT_SCHEMA_VALID", strict_schema_compatibility_verdict(valid_schema)["status"] == "PASS")
    check("U012_V3_UNIQUEITEMS_REJECTED", strict_schema_compatibility_verdict({**valid_schema, "uniqueItems": True})["status"] != "PASS")
    annotations = {"3<pipe:[123]>": "PIPE", "4<socket:[456]>": "SOCKET", "5<TCP:[789]>": "TCP", "6<TCPv6:[1120305]>": "TCPV6", "7<UDP:[8]>": "UDP", "8<UDPv6:[9]>": "UDPV6"}
    for offset, (token, expected) in enumerate(annotations.items(), 13):
        parsed = parse_fd_annotation(token)
        check(f"U{offset:03d}_V3_V6_FD_{expected}", parsed is not None and parsed.kind.value == expected)
    try:
        parse_fd_annotation("9<SCTP:[1]>")
        unknown_rejected = False
    except ValueError:
        unknown_rejected = True
    check("U019_V6_UNKNOWN_FD_FAILS", unknown_rejected)
    arrow = parse_syscall_line('read(3<pipe:[523996->523997]>, "x", 1) = 1')
    check("U020_V3_FD_ARROW_BALANCED", arrow is not None and arrow.name == "read")
    check("U021_V6_TCPV6_TYPED", classify_fd_annotations({1: 'read(6<TCPv6:[1120305]>, "x", 1) = 1'})["status"] == "PASS")
    check("U022_TYPED_FD_PRECHECK", typed_fd_annotation_grammar_precheck()["status"] == "PASS")
    check("U023_V4_STARTUP_LINEAGE", startup_lineage_policy_precheck()["status"] == "PASS")
    check("U024_V4_TOKEN_BUDGET", token_budget_feasibility_precheck()["status"] == "PASS")
    check("U025_V5_V19_PROCESS_IDENTITY", process_identity_correlation_precheck()["status"] == "PASS")
    check("U026_V11_V19_OBSERVER_POLICY", temporal_process_identity_observer_precheck()["status"] == "PASS")
    check("U027_V7_PROMPT_IDENTITY", prompt_identity_binding_precheck()["status"] == "PASS")
    check("U028_V8_PREDECESSOR_RESOLUTION", authoritative_predecessor_resolution_precheck()["status"] == "PASS")
    check("U029_V9_DIGEST_BINDING", authoritative_artifact_digest_precheck()["status"] == "PASS")

    canonical_predecessor = canonical_predecessor_binding_precheck("BUILDER")
    check("U_PREDECESSOR_000_CANONICAL_AUTHORITY", canonical_predecessor.get("status") == "PASS", canonical_predecessor)
    predecessor_base = {
        "component": "BUILDER",
        "authority_lock_sha256": EXPECTED_V35_GOVERNANCE_LOCK_SHA256,
        "authority_decision_sha256": EXPECTED_V35_DECISION_SHA256,
        "explicit_predecessor_identity": EXPECTED_PREDECESSOR_IDENTITY,
        "candidate_identities": [EXPECTED_PREDECESSOR_IDENTITY],
        "workspace_tree_sha256": EXPECTED_V18_TREE_ROOT,
        "static_lock_sha256": EXPECTED_V18_STATIC_LOCK_SHA256,
        "permit_inference": False,
    }
    predecessor_cases = {
        "EXACT_GOVERNANCE_V18": ({}, True),
        "BUILDER_V18_PRIMARY_V17_MISMATCH": ({"explicit_predecessor_identity": "V0_3_FIRST_REAL_SECURITY_WORKER_INVOCATION_V17"}, False),
        "INDEPENDENT_RELATION_MISSING": ({"candidate_identities": []}, False),
        "PREFLIGHT_STALE_V17": ({"component": "FRESH_PREFLIGHT", "explicit_predecessor_identity": "V0_3_FIRST_REAL_SECURITY_WORKER_INVOCATION_V17"}, False),
        "STATIC_LOCK_STALE_V17": ({"component": "STATIC_LOCK_PREPARATION", "explicit_predecessor_identity": "V0_3_FIRST_REAL_SECURITY_WORKER_INVOCATION_V17"}, False),
        "VERSION_NUMBER_INFERENCE": ({"permit_inference": True}, False),
        "MISSING_GOVERNANCE_AUTHORITY": ({"authority_lock_sha256": None}, False),
        "AMBIGUOUS_CANDIDATES": ({"candidate_identities": [EXPECTED_PREDECESSOR_IDENTITY, "V0_3_FIRST_REAL_SECURITY_WORKER_INVOCATION_V17"]}, False),
        "STALE_PREDECESSOR_LITERAL": ({"explicit_predecessor_identity": "V0_3_FIRST_REAL_SECURITY_WORKER_INVOCATION_V17"}, False),
        "ARTIFACT_DIGEST_MISMATCH": ({"workspace_tree_sha256": "0" * 64}, False),
    }
    for name, (changes, expected_pass) in predecessor_cases.items():
        arguments = dict(predecessor_base)
        arguments.update(changes)
        verdict = canonical_predecessor_binding_verdict(**arguments)
        check(f"U_PREDECESSOR_{name}", (verdict.get("status") == "PASS") is expected_pass, verdict)

    external_exact = external_predecessor_artifact_precheck("BUILDER")
    check("U_EXTERNAL_000_EXACT_RESOLUTION", external_exact.get("status") == "PASS", external_exact)
    external_binding = json.loads((ROOT/"contracts/CANONICAL_EXTERNAL_PREDECESSOR_ARTIFACT_BINDING.json").read_text())
    external_row = dict(external_binding["external_artifacts"][0])
    external_cases = {
        "CANONICAL_LOCATOR": ({}, {}, True),
        "WRONG_GOVERNANCE_DIRECTORY": ({"canonical_locator": str(Path(external_row["canonical_locator"]).parent.parent/"wrong"/Path(external_row["canonical_locator"]).name)}, {}, False),
        "WRONG_OWNER": ({"owning_predecessor_identity": "V0_3_FIRST_REAL_SECURITY_WORKER_INVOCATION_V18"}, {}, False),
        "MISSING_TRANSITIVE_RELATION": ({"relationship_to_canonical_predecessor": None}, {}, False),
        "STALE_ARTIFACT": ({"expected_sha256": "0"*64}, {}, False),
        "WRONG_DIGEST": ({"expected_sha256": "f"*64}, {}, False),
        "WRONG_SIZE": ({"expected_size": external_row["expected_size"]+1}, {}, False),
        "AMBIGUOUS": ({}, {"candidate_count": 2}, False),
        "VERSION_SYNTHESIZED_PATH": ({}, {"resolution_method": "VERSION_NUMBER_ARITHMETIC"}, False),
        "FILENAME_FALLBACK_SCAN": ({}, {"resolution_method": "FILENAME_SEARCH_OR_FALLBACK_SCAN"}, False),
        "MANUAL_COPY": ({}, {"artifact_form": "MANUAL_COPY"}, False),
        "SYMLINK_COMPATIBILITY": ({}, {"artifact_form": "SYMLINK_COMPATIBILITY_ARTIFACT"}, False),
    }
    for name,(changes,options,expected_pass) in external_cases.items():
        candidate=dict(external_row);candidate.update(changes)
        verdict=external_artifact_candidate_verdict(candidate,**options)
        check(f"U_EXTERNAL_{name}",(verdict.get("status")=="PASS") is expected_pass,verdict)

    predecessors = (
        verify_v1_reference_predecessor, verify_v2_reference_predecessor,
        verify_v3_reference_predecessor, verify_v4_reference_predecessor,
        verify_v5_reference_predecessor, verify_v6_reference_predecessor,
        verify_v7_reference_predecessor, verify_v8_reference_predecessor,
        verify_v9_reference_predecessor, verify_v10_reference_predecessor,
        verify_v11_reference_predecessor, verify_v12_reference_predecessor,
        verify_v13_reference_predecessor, verify_v14_reference_predecessor,
        verify_v15_reference_predecessor, verify_v16_reference_predecessor,
        verify_v17_reference_predecessor, verify_v18_reference_predecessor,
        verify_v19_reference_predecessor,
        verify_v20_reference_predecessor,
        verify_v24_reference_predecessor,
        verify_v25_reference_predecessor,
    )
    for offset, verifier in enumerate(predecessors, 30):
        verdict = verifier()
        check(f"U{offset:03d}_PREDECESSOR", verdict["status"] == "PASS", verdict)

    historical_registry = json.loads((ROOT / "contracts/TYPED_HISTORICAL_DECISION_REGISTRY.json").read_text())
    historical_rows = historical_registry["mappings"]
    historical_precheck = historical_decision_relation_precheck()
    check("U_V35_TYPED_HISTORICAL_RELATION_REGISTRY_PASS", historical_precheck.get("status") == "PASS", historical_precheck)
    canonical_relation = next(row for row in historical_rows if row["logical_decision_identity"] == "V20_TERMINAL_AND_V21_SUCCESSOR_DECISION")
    different_physical = {
        **canonical_relation,
        "physical_record_type_presence": "PRESENT",
        "authorized_physical_record_type_presence": "PRESENT",
        "physical_record_type": "PHYSICAL_TERMINAL_SUCCESSOR_DECISION_RECORD",
        "authorized_physical_record_type": "PHYSICAL_TERMINAL_SUCCESSOR_DECISION_RECORD",
    }
    relation_cases = {
        "PERMITTED_ABSENT_PHYSICAL_RECORD_TYPE": ([dict(canonical_relation)], True),
        "AUTHORIZED_DIFFERENT_PHYSICAL_RECORD_TYPE": ([different_physical], True),
        "MISSING": ([], False),
        "AMBIGUOUS": ([dict(canonical_relation), dict(canonical_relation)], False),
        "WRONG_LOGICAL_IDENTITY": ([{**canonical_relation, "logical_decision_identity": "WRONG"}], False),
        "WRONG_ROLE": ([{**canonical_relation, "artifact_role": "WRONG"}], False),
        "WRONG_SUBJECT": ([{**canonical_relation, "subject_identity": "WRONG"}], False),
        "WRONG_OBJECT": ([{**canonical_relation, "object_identity": "WRONG"}], False),
        "WRONG_RELATION": ([{**canonical_relation, "relation_semantics": "WRONG"}], False),
        "WRONG_GOVERNANCE_OWNER": ([{**canonical_relation, "governance_owner": "WRONG"}], False),
        "WRONG_DIGEST": ([{**canonical_relation, "artifact_sha256": "0" * 64}], False),
        "WRONG_SIZE": ([{**canonical_relation, "artifact_size": 0}], False),
        "SYNTHETIC_MAPPING": ([{**canonical_relation, "mapping_authority": "SYNTHETIC"}], False),
    }
    for name, (rows, expected_shape_pass) in relation_cases.items():
        verdict = relation_fixture_verdict(rows, "V20_TERMINAL_AND_V21_SUCCESSOR_DECISION")
        shape_pass = verdict.get("status") == "PASS"
        check(f"U_V35_HISTORICAL_RELATION_{name}", shape_pass is expected_shape_pass, verdict)

    completion_cases = {
        "EXACT": ({}, True),
        "TRUNCATED_TEMPORARY_PAYLOAD": ({"completion_present": False}, False),
        "INCOMPLETE_FINAL_ARTIFACT": ({"completion_state": "UNPUBLISHED"}, False),
        "MISSING_COMPLETION_METADATA": ({"completion_present": False}, False),
        "DIGEST_MISMATCH": ({"digest_matches": False}, False),
        "INCORRECT_PRODUCER": ({"producer_matches": False}, False),
        "INCORRECT_FIXTURE": ({"fixture_matches": False}, False),
        "MALFORMED_JSON": ({"schema_matches": False}, False),
        "PARSER_BEFORE_COMPLETION": ({"completion_state": "PAYLOAD_ONLY"}, False),
        "DUPLICATE_PUBLICATION": ({"completion_state": "AMBIGUOUS_DUPLICATE"}, False),
    }
    completion_base = {
        "completion_present": True,
        "completion_state": "COMPLETED_ATOMICALLY_PUBLISHED",
        "producer_matches": True,
        "fixture_matches": True,
        "digest_matches": True,
        "size_matches": True,
        "schema_matches": True,
    }
    for name, (changes, expected_pass) in completion_cases.items():
        verdict = completion_fixture_verdict(**{**completion_base, **changes})
        check(f"U_V35_TRANSACTIONAL_COMPLETION_{name}", (verdict.get("status") == "PASS") is expected_pass, verdict)
    valid_failure_envelope = {
        "fixture_identity": "nested-0001",
        "observer_exit_code": 2,
        "failure_stage": "OBSERVER_EXECUTION",
        "failure_reason": "EVIDENCE_BOUND_TEST_FAILURE",
        "classification": "OBSERVER_EXECUTION_FAILURE",
        "telemetry_complete": False,
        "raw_output_sha256": "0" * 64,
        "raw_output_bytes": 0,
        "available_counters": {},
    }
    check("U_V35_TYPED_FAILURE_ENVELOPE_PASS", failure_envelope_verdict(valid_failure_envelope).get("status") == "PASS")
    malformed_failure = dict(valid_failure_envelope); malformed_failure.pop("failure_stage")
    check("U_V35_MALFORMED_FAILURE_ENVELOPE_FAIL", failure_envelope_verdict(malformed_failure).get("status") == "FAIL_CLOSED")
    for offset, (name, path) in enumerate(sorted(PREDECESSOR_PATHS.items()), 50):
        check(f"U{offset:03d}_EXTERNAL_{name}", path.is_file() and sha256_file(path) == EXPECTED_DIGESTS[name])

    def fixture_tree(rows: list[tuple[str, bytes]], *, flattened: bool = False, separator: bytes = b"\x00", newline: bytes = b"\x0a") -> str:
        prepared = []
        for relative, content in rows:
            key = relative.encode("utf-8") if flattened else normative_component_path_key(relative)
            prepared.append((key, relative, hashlib.sha256(content).hexdigest()))
        prepared.sort(key=lambda row: row[0])
        stream = b"".join(
            relative.encode("utf-8") + separator + digest.encode("ascii") + newline
            for _, relative, digest in prepared
        )
        return hashlib.sha256(stream).hexdigest()

    canonical_rows = [
        ("root/immediate-0001/events.jsonl", b"events"),
        ("root/immediate-0001-result.json", b"result"),
        ("root/zeta", b"z"),
        ("root/éclair/data", b"utf8"),
    ]
    canonical_digest = fixture_tree(canonical_rows)
    check("U_CANON_001_SHUFFLED_ENUMERATION", fixture_tree(list(reversed(canonical_rows))) == canonical_digest)
    check("U_CANON_002_COMPONENT_TUPLE_NOT_FLATTENED", fixture_tree(canonical_rows, flattened=True) != canonical_digest)
    mutated_rows = [(name, b"X" + value[1:]) if index == 0 else (name, value) for index, (name, value) in enumerate(canonical_rows)]
    check("U_CANON_003_ONE_BYTE_MUTATION", fixture_tree(mutated_rows) != canonical_digest)
    check("U_CANON_004_MISSING_MEMBER", fixture_tree(canonical_rows[:-1]) != canonical_digest)
    check("U_CANON_005_EXTRA_MEMBER", fixture_tree(canonical_rows + [("extra", b"x")]) != canonical_digest)
    malformed_rejected = False
    try:
        fixture_tree([("root\\bad", b"x")])
    except ValueError:
        malformed_rejected = True
    check("U_CANON_006_MALFORMED_PATH", malformed_rejected)
    check("U_CANON_007_ALTERNATE_SERIALIZATION", fixture_tree(canonical_rows, separator=b"  ") != canonical_digest and fixture_tree(canonical_rows, newline=b"\r\n") != canonical_digest)
    actual_normative, actual_count = normative_frozen_tree(v16_root)
    actual_alternate, alternate_count = flattened_non_normative_tree(v16_root)
    check("U_CANON_008_AUTHORITATIVE_ROOT", actual_count == alternate_count == 146 and actual_normative == "5c99e1c8c1e5048ee3a9c607e0bceffc273743b91a245bf7a913f832af0636b5")
    check("U_CANON_009_ALTERNATE_ROOT_REJECTED", actual_alternate == "a5ec0db34da898d64859e0e3535d74929eed4f5b047f67f37d1fe3d90a88ea63" and actual_alternate != actual_normative)
    check("U_CANON_010_PRIMARY_PRECHECK", v16_tree_canonicalization_precheck().get("status") == "PASS", v16_tree_canonicalization_precheck())

    exact_binding = '''
from invocation_v35 import v16_tree_canonicalization_precheck
v16_tree_canonicalization_precheck()
'''
    binding_cases = {
        "EXACT_SUCCESS": (exact_binding, {"invocation_v35"}, {"src/invocation_v35.py"}, True),
        "MISSING_IMPORT": ("v16_tree_canonicalization_precheck()", {"invocation_v35"}, {"src/invocation_v35.py"}, False),
        "WRONG_ALIAS": ("from invocation_v35 import v16_tree_canonicalization_precheck as precheck\nprecheck()", {"invocation_v35"}, {"src/invocation_v35.py"}, False),
        "STALE_MODULE": ("from invocation_v18 import v16_tree_canonicalization_precheck\nv16_tree_canonicalization_precheck()", {"invocation_v35"}, {"src/invocation_v35.py"}, False),
        "SHADOWED_SYMBOL": (exact_binding + "v16_tree_canonicalization_precheck = None\n", {"invocation_v35"}, {"src/invocation_v35.py"}, False),
        "VALIDATOR_ONLY_MODULE": (exact_binding, set(), {"src/invocation_v35.py"}, False),
        "OMITTED_FROM_LOCK": (exact_binding, {"invocation_v35"}, set(), False),
        "AMBIGUOUS_IMPORT": (exact_binding + "from alternate import v16_tree_canonicalization_precheck\n", {"invocation_v35", "alternate"}, {"src/invocation_v35.py"}, False),
    }
    for offset, (name, (source, modules, members, expected_pass)) in enumerate(binding_cases.items(), 150):
        verdict = binding_fixture_verdict(source, available_modules=modules, static_lock_members=members)
        check(f"U{offset:03d}_V19_SYMBOL_{name}", (verdict.get("status") == "PASS") is expected_pass, verdict)
    static_symbols = static_symbol_binding_precheck()
    check("U158_V19_COMPLETE_PREATTEMPT_SYMBOL_BINDING", static_symbols.get("status") == "PASS", static_symbols)

    traces = tuple(range(200, 216))
    complete = [identity(pid) for pid in traces]
    complete_verdict = temporal_identity_coverage_verdict(traces, complete)
    check("U080_V19_N_OF_N_PASS", complete_verdict["status"] == "PASS" and complete_verdict["valid_temporal_identity_mapping_count"] == 16)
    missing = temporal_identity_coverage_verdict(traces, complete[:-1])
    check("U081_V19_N_MINUS_ONE_FAIL", missing["status"] == "FAIL_CLOSED" and missing["missing_identity_count"] == 1)
    ambiguous = temporal_identity_coverage_verdict(traces, [*complete, identity(traces[-1], "PROC_STAT_STARTTIME:DIFFERENT")])
    check("U082_V19_AMBIGUOUS_FAIL", ambiguous["status"] == "FAIL_CLOSED" and ambiguous["ambiguous_identity_count"] == 1)
    no_namespace = [dict(row) for row in complete]
    no_namespace[-1]["pid_namespace_identity"] = None
    no_namespace[-1]["stable_identity_tuple"] = [traces[-1], no_namespace[-1]["process_start_identity"], None]
    check("U083_V19_NAMESPACE_REQUIRED", temporal_identity_coverage_verdict(traces, no_namespace)["status"] == "FAIL_CLOSED")
    bad_start = [dict(row) for row in complete]
    bad_start[-1]["stable_identity_tuple"] = [traces[-1], "BAD", "pid:[42]"]
    check("U084_V19_START_IDENTITY_CONSISTENT", temporal_identity_coverage_verdict(traces, bad_start)["status"] == "FAIL_CLOSED")
    reused = temporal_identity_coverage_verdict([700], [identity(700, "PROC_STAT_STARTTIME:1"), identity(700, "PROC_STAT_STARTTIME:2")])
    check("U085_V19_PID_REUSE_AMBIGUOUS", reused["status"] == "FAIL_CLOSED")
    check("U086_V19_PERCENTAGE_PROHIBITED", missing.get("coverage_complete") is False)

    selftest_root = ROOT / "results/prelock/adversarial-selftests-run-0001"
    guarded_mkdir(selftest_root, operation_identity="UNIT_ADVERSARIAL_SELFTEST_ROOT", generation="RUN_0001")
    fixture_modes = ("long-lived", "sequential", "overlapping", "immediate", "nested")
    selftests = {
        mode: run_temporal_observer_selftest(
            selftest_root,
            fixture_mode=mode,
            evidence_identity=f"{mode}-0001",
        )
        for mode in fixture_modes
    }
    check("U087_V19_ALL_ADVERSARIAL_SELFTESTS_PASS", all(row.get("status") == "PASS" for row in selftests.values()), selftests)
    check("U088_V19_SELFTEST_N_OF_N", all(row.get("checks", {}).get("complete_identity_coverage") is True for row in selftests.values()))
    check("U089_V19_SELFTEST_MISSING_ZERO", all(row.get("missing_mapping_count") == 0 for row in selftests.values()))
    check("U090_V19_SELFTEST_AMBIGUOUS_ZERO", all(row.get("ambiguous_mapping_count") == 0 for row in selftests.values()))
    check("U091_V19_SELFTEST_TRACE_DENOMINATOR", all(row.get("checks", {}).get("trace_denominator_independently_enumerated") is True for row in selftests.values()))
    check("U092_V19_SELFTEST_DIAGNOSTIC_COMPLETE", all(observer_diagnostic_verdict(row)["status"] == "PASS" for row in selftests.values()))

    good_coverage = {
        "lineage_relevant_trace_identity_count": 1,
        "identity_capture_attempt_count": 1,
        "valid_temporal_identity_mapping_count": 1,
        "missing_identity_count": 0,
        "ambiguous_identity_count": 0,
        "coverage_complete": True,
        "percentage_thresholds": "PROHIBITED_AND_NOT_USED",
        "per_trace_capture_accounting": [{
            "trace_identity": "STRACE_FILE_PID:900",
            "trace_file_pid": 900,
            "host_pid": 900,
            "identity_capture_attempt_timestamp_monotonic_ns": 1,
            "process_start_identity": "PROC_STAT_STARTTIME:1",
            "pid_namespace_identity": "pid:[42]",
            "capture_outcome": "VALID_TEMPORAL_IDENTITY_RECORD",
            "mapping_result": "VALID_TEMPORAL_IDENTITY_RECORD",
            "failure_reason": None,
            "temporal_relationship": {"interval_distance_ns": 0},
        }],
    }
    check("U093_V19_INDEPENDENT_ACCOUNTING_PASS", independently_validate_coverage_accounting([900], good_coverage)["status"] == "PASS")
    bad_accounting = dict(good_coverage); bad_accounting["valid_temporal_identity_mapping_count"] = 2
    check("U094_V19_INCONSISTENT_ACCOUNTING_FAIL", independently_validate_coverage_accounting([900], bad_accounting)["status"] == "FAIL_CLOSED")
    check("U095_V19_NONZERO_OBSERVER_PASS_REJECTED", observer_diagnostic_verdict({"observer_exit_code": 1, "observer_exit_reason": "OBSERVER_INTERNAL_ERROR", "diagnostic_complete": True, "status": "PASS"})["status"] != "PASS")
    check("U096_V19_MISSING_EXIT_REASON_FAIL", observer_diagnostic_verdict({"observer_exit_code": 1, "diagnostic_complete": True, "status": "FAIL_CLOSED"})["status"] != "PASS")

    canonical_lifecycle = '''
observer_process = subprocess.Popen([])
observer_ready = wait_for_json(paths["observer_ready"])
process = subprocess.Popen([])
trace_ready = any([])
append_only_json(STATIC_RUN / "ATTEMPT_MARKER.json", {})
'''
    lifecycle_cases = {
        "CANONICAL": (canonical_lifecycle, True),
        "OBSERVER_PROCESS_COLLISION": ('''
observer_process = subprocess.Popen([])
observer_ready = wait_for_json(x)
trace_ready = any([])
append_only_json(STATIC_RUN / "ATTEMPT_MARKER.json", {})
''', False),
        "EARLY_MARKER_REFERENCE_IGNORED": ('''
exists = (STATIC_RUN / "ATTEMPT_MARKER.json").exists()
observer_process = subprocess.Popen([])
observer_ready = wait_for_json(x)
process = subprocess.Popen([])
trace_ready = any([])
append_only_json(STATIC_RUN / "ATTEMPT_MARKER.json", {})
''', True),
        "COMMENT_STRING_TRAPS_IGNORED": ('''
# process = subprocess.Popen([]); append_only_json(STATIC_RUN / "ATTEMPT_MARKER.json", {})
trap = "observer_ready = wait_for_json(x)"
observer_process = subprocess.Popen([])
observer_ready = wait_for_json(x)
process = subprocess.Popen([])
trace_ready = any([])
append_only_json(STATIC_RUN / "ATTEMPT_MARKER.json", {})
''', True),
        "DUPLICATE_C": (canonical_lifecycle.replace("trace_ready", "process = subprocess.Popen([])\ntrace_ready"), False),
        "MISSING_B": (canonical_lifecycle.replace('observer_ready = wait_for_json(paths["observer_ready"])\n', ""), False),
        "C_BEFORE_B": (canonical_lifecycle.replace('observer_ready = wait_for_json(paths["observer_ready"])\nprocess = subprocess.Popen([])', 'process = subprocess.Popen([])\nobserver_ready = wait_for_json(paths["observer_ready"])'), False),
        "D_BEFORE_C": (canonical_lifecycle.replace('process = subprocess.Popen([])\ntrace_ready = any([])', 'trace_ready = any([])\nprocess = subprocess.Popen([])'), False),
        "E_BEFORE_D": (canonical_lifecycle.replace('trace_ready = any([])\nappend_only_json(STATIC_RUN / "ATTEMPT_MARKER.json", {})', 'append_only_json(STATIC_RUN / "ATTEMPT_MARKER.json", {})\ntrace_ready = any([])'), False),
    }
    for offset, (name, (source, expected_pass)) in enumerate(lifecycle_cases.items(), 130):
        primary_lifecycle = semantic_lifecycle_anchor_verdict(source)
        independent_lifecycle = independent_lifecycle_verdict(source)
        check(
            f"U{offset:03d}_V19_LIFECYCLE_{name}",
            (primary_lifecycle.get("status") == "PASS") is expected_pass
            and (independent_lifecycle.get("status") == "PASS") is expected_pass,
            {"primary": primary_lifecycle, "independent": independent_lifecycle},
        )

    module_origin = str(ROOT / "src/invocation_v35.py")
    module_digest = hashlib.sha256((ROOT / "src/invocation_v35.py").read_bytes()).hexdigest()
    canonical_module_case = {
        "environment_bound_before_resolution": True,
        "canonical_root_present": True,
        "cwd_exact": True,
        "pythonpath_absent": True,
        "expected_origin": module_origin,
        "resolved_origin": module_origin,
        "expected_digest": module_digest,
        "resolved_digest": module_digest,
        "dependency_manifest_member": True,
        "symbol_manifest_member": True,
        "candidate_origins": [module_origin],
    }
    module_cases = {
        "EXACT_CANONICAL_SUCCESS": ({}, True),
        "WRONG_CWD": ({"cwd_exact": False}, False),
        "MISSING_PACKAGE_ROOT": ({"canonical_root_present": False}, False),
        "HOSTILE_PYTHONPATH": ({"pythonpath_absent": False}, False),
        "SHADOW_MODULE": ({"candidate_origins": ["/hostile/invocation_v35.py", module_origin]}, False),
        "DIFFERENT_ORIGIN": ({"resolved_origin": "/hostile/invocation_v35.py"}, False),
        "MANIFEST_MEMBER_UNRESOLVABLE": ({"resolved_origin": None, "resolved_digest": None}, False),
        "RESOLVABLE_ABSENT_DEPENDENCY_MANIFEST": ({"dependency_manifest_member": False}, False),
        "RESOLVABLE_ABSENT_SYMBOL_MANIFEST": ({"symbol_manifest_member": False}, False),
        "PRIMARY_INDEPENDENT_DIFFERENT_ORIGINS": ({"candidate_origins": [module_origin, "/different/invocation_v35.py"]}, False),
        "RESOLUTION_BEFORE_ENVIRONMENT_BINDING": ({"environment_bound_before_resolution": False}, False),
        "SOURCE_DIGEST_MISMATCH": ({"resolved_digest": "0" * 64}, False),
    }
    for offset, (name, (changes, expected_pass)) in enumerate(module_cases.items(), 160):
        values = {**canonical_module_case, **changes}
        verdict = module_resolution_fixture_verdict(**values)
        check(f"U{offset:03d}_V35_MODULE_{name}", (verdict.get("status") == "PASS") is expected_pass, verdict)
    module_precheck = canonical_module_resolution_precheck("UNIT")
    check("U172_V35_CANONICAL_MODULE_PRECHECK", module_precheck.get("status") == "PASS", module_precheck)

    typed_rows = {row["canonical_logical_module_name"]: row for row in _bindings["modules"]}
    def typed_verdict(name: str, row_changes=None, *, origin=None, loader=None, resolved_digest="BOUND", exports=None, runtime=RUNTIME_IDENTITY):
        row = {**typed_rows[name], **(row_changes or {})}
        digest_value = row.get("exact_source_sha256") if resolved_digest == "BOUND" else resolved_digest
        return typed_module_fixture_verdict(
            row,
            resolved_origin=row.get("expected_module_origin") if origin is None else origin,
            resolved_loader=row.get("expected_loader_identity") if loader is None else loader,
            resolved_digest=digest_value,
            exported_symbols=row.get("expected_exported_symbol_identities", []) if exports is None else exports,
            runtime_identity=runtime,
        )
    typed_cases = {
        "PURE_PYTHON_STDLIB": (typed_verdict("pathlib"), True),
        "STDLIB_SHADOWED_FROM_PROJECT": (typed_verdict("pathlib", origin=str(ROOT / "src/pathlib.py")), False),
        "BUILTIN": (typed_verdict("time"), True),
        "BUILTIN_REQUIRES_PY_SOURCE": (typed_verdict("time", {"canonical_source_path": "/tmp/time.py", "exact_source_sha256": "0" * 64}, resolved_digest=None), False),
        "EXTENSION": (typed_verdict("resource"), True),
        "EXTENSION_WRONG_LOADER": (typed_verdict("resource", loader="_frozen_importlib_external.SourceFileLoader"), False),
        "WRONG_MODULE_CLASS": (typed_verdict("time", {"module_class": "PURE_PYTHON_STDLIB"}, resolved_digest=None), False),
        "WRONG_PINNED_RUNTIME": (typed_verdict("time", runtime="OTHER_RUNTIME"), False),
        "MISSING_EXPORTED_SYMBOL": (typed_verdict("pathlib", exports=[]), False),
    }
    for offset, (name, (verdict, expected_pass)) in enumerate(typed_cases.items(), 227):
        check(f"U{offset:03d}_V35_TYPED_MODULE_{name}", (verdict.get("status") == "PASS") is expected_pass, verdict)
    expected_graph = [{"symbol": "a", "module": "json"}, {"symbol": "b", "module": "time"}]
    same_count_different = [{"symbol": "a", "module": "json"}, {"symbol": "b", "module": "resource"}]
    check("U236_V35_SAME_COUNT_DIFFERENT_ROW_REJECTED", canonical_graph_equivalence_verdict(expected_graph, same_count_different).get("status") == "FAIL_CLOSED")
    check("U237_V35_EXACT_CANONICAL_GRAPH_EQUIVALENCE", canonical_graph_equivalence_verdict(expected_graph, list(reversed(expected_graph))).get("status") == "PASS")

    unified = json.loads((ROOT / "contracts/UNIFIED_AUTHORITATIVE_BINDING_GENERATION.json").read_text())
    unified_rows = unified["members"]
    check("U173_V35_UNIFIED_GENERATION_PRECHECK", unified_binding_generation_precheck("UNIT").get("status") == "PASS")

    def mutate_unified(identity: str, **changes: object) -> list[dict[str, object]]:
        rows = [dict(row) for row in unified_rows]
        target = next(row for row in rows if row["logical_artifact_identity"] == identity)
        target.update(changes)
        return rows

    unified_cases = {
        "STALE_SUCCESSOR_SELECTOR": (mutate_unified("SUCCESSOR_V35_REQUIREMENTS", logical_artifact_identity="SUCCESSOR_V22_REQUIREMENTS"), False),
        "VERSION_NUMBER_SELECTOR_INFERENCE": (mutate_unified("SUCCESSOR_V35_REQUIREMENTS", relationship="VERSION_NUMBER_INFERENCE"), False),
        "PROMPT_CORRECT_DIGEST_MODE_0644": (mutate_unified("V35_FINAL_WORKER_PROMPT", required_mode="0644"), False),
        "PROMPT_EXACT_DIGEST_MODE_0444": (unified_rows, True),
        "STALE_HISTORICAL_DECISION": (mutate_unified("V25_TERMINAL_AND_V26_SUCCESSOR_DECISION", logical_artifact_identity="V21_TERMINAL_AND_V22_SUCCESSOR_DECISION"), False),
        "EXACT_GOVERNANCE_BOUND_HISTORICAL_DECISION": (unified_rows, True),
        "SYNTHETIC_EXTERNAL_IDENTITY": (mutate_unified("V17_PRELOCK_FROZEN_EVIDENCE_BINDING", logical_artifact_identity="V35_SYNTHETIC_EXTERNAL_BINDING"), False),
        "STALE_EXTERNAL_V20_DECISION_DIGEST": (mutate_unified("V20_TERMINAL_AND_V21_SUCCESSOR_DECISION", sha256="0" * 64), False),
        "STALE_EXTERNAL_V21_MATRIX_DIGEST": (mutate_unified("V21_EXTERNAL_PREDECESSOR_ARTIFACT_REGRESSION_MATRIX", sha256="0" * 64), False),
        "MIXED_BINDING_GENERATIONS": (mutate_unified("V35_CANONICAL_MODULE_BINDINGS", generation_identity="OTHER_GENERATION"), False),
        "FULLY_CONSISTENT_EXACT_GENERATION": (unified_rows, True),
    }
    for offset, (name, (rows, expected_pass)) in enumerate(unified_cases.items(), 180):
        verdict = unified_binding_fixture_verdict(rows)
        check(f"U{offset:03d}_V35_BINDING_{name}", (verdict.get("status") == "PASS") is expected_pass, verdict)

    mount_contract = json.loads((ROOT / "contracts/SUCCESSOR_V35_GOVERNANCE_BOUND_MOUNT_OUTPUT_IDENTITY_CONTRACT.json").read_text())
    mount_binding = json.loads((ROOT / "contracts/MOUNT_OUTPUT_IDENTITY_BINDING.json").read_text())
    mount_policy = json.loads((ROOT / "contracts/MOUNT_PROVENANCE_WRITE_CONTRACT.json").read_text())
    def mount_case(*, binding_changes=None, policy_changes=None):
        binding = {**mount_binding, **(binding_changes or {})}
        policy = json.loads(json.dumps(mount_policy)); policy.update(policy_changes or {})
        return mount_output_binding_fixture_verdict(binding, mount_contract, policy, component="UNIT")
    stale_v23 = "/run/nobcoder-first-worker-v" + "23/output"
    stale_v25 = "/run/nobcoder-first-worker-v" + "25/output"
    mount_cases = {
        "EXACT": (mount_case(), True),
        "STALE_V23": (mount_case(binding_changes={"namespace_output_path": stale_v23, "mount_destination_path": stale_v23}), False),
        "STALE_V25": (mount_case(binding_changes={"namespace_output_path": stale_v25, "mount_destination_path": stale_v25}), False),
        "WRONG_HOST_NAMESPACE_PAIR": (mount_case(binding_changes={"host_output_path": str(ROOT / "wrong-output")}), False),
        "MOUNT_MODE_MISMATCH": (mount_case(binding_changes={"mount_mode": "READ_ONLY"}), False),
    }
    for offset, (name, (verdict, expected_pass)) in enumerate(mount_cases.items(), 210):
        check(f"U{offset:03d}_V35_MOUNT_{name}", (verdict.get("status") == "PASS") is expected_pass, verdict)
    check("U215_V35_STALE_LITERAL_HIDDEN_FAIL", stale_mount_literal_fixture_verdict({"contracts/hidden.json": stale_v23}).get("status") != "PASS")
    check("U216_V35_STALE_LITERAL_LIVE_PASS", stale_mount_literal_precheck().get("status") == "PASS")
    check("U217_V35_MOUNT_PRECHECK_PASS", mount_output_binding_precheck("UNIT").get("status") == "PASS")

    typed_contract = json.loads((ROOT / "contracts/TYPED_PREFLIGHT_REQUIREMENT_REGISTRY_CONTRACT.json").read_text())
    typed_registry = json.loads((ROOT / "contracts/TYPED_PREFLIGHT_REQUIREMENT_REGISTRY.json").read_text())
    def typed_case(mutator=None, contract_changes=None):
        registry = json.loads(json.dumps(typed_registry)); contract = {**typed_contract, **(contract_changes or {})}
        if mutator is not None: mutator(registry)
        return typed_preflight_registry_fixture_verdict(contract, registry, component="UNIT")
    def mutate_row(field, value):
        return lambda registry: registry["requirements"][0].__setitem__(field, value)
    typed_cases = {
        "EXACT_CURRENT_SEMANTIC": (typed_case(), True),
        "OLD_TOKEN_NOT_AUTHORITY": (typed_case(contract_changes={"textual_token_search_as_authority": "ALLOWED"}), False),
        "OBSOLETE_TOKEN_ABSENCE_ACCEPTED": (typed_case(), True),
        "STALE_PREDICATE": (typed_case(mutate_row("semantic_predicate_identity", "V25_SEMANTIC_STALE")), False),
        "STALE_ARTIFACT_DIGEST": (typed_case(mutate_row("artifact_sha256", "0" * 64)), False),
        "STALE_OWNER_DIGEST": (typed_case(mutate_row("owner_governance_digest", "0" * 64)), False),
        "PREDECESSOR_GENERATION": (typed_case(mutate_row("binding_generation_identity", "V30_GOVERNANCE_BOUND_BINDING_GENERATION_0001")), False),
        "STALE_ARTIFACT_GENERATION": (typed_case(mutate_row("artifact_generation_identity", "V30_GOVERNANCE_BOUND_BINDING_GENERATION_0001")), False),
        "WRONG_LOGICAL_OWNER": (typed_case(mutate_row("artifact_owner_identity", "V30")), False),
        "WRONG_EVALUATOR": (typed_case(mutate_row("evaluator_identity", "V25_STALE_EVALUATOR")), False),
        "MIXED_GENERATION": (typed_case(mutate_row("binding_generation_identity", "OTHER_GENERATION")), False),
    }
    for offset, (name, (verdict, expected_pass)) in enumerate(typed_cases.items(), 358):
        check(f"U{offset:03d}_V35_TYPED_PREFLIGHT_{name}", (verdict.get("status") == "PASS") is expected_pass, verdict)
    check("U369_V35_TYPED_PREFLIGHT_PRECHECK", typed_preflight_requirement_precheck("UNIT").get("status") == "PASS")
    check("U370_V25_IMMUTABLE", verify_v25_reference_predecessor().get("status") == "PASS")
    check("U371_V26_IMMUTABLE", verify_v26_reference_predecessor().get("status") == "PASS")

    exact_runtime_binding = {
        "runtime_identity": "CODEX_RUNTIME_0_166_0_COMPATIBILITY_PASS_LOCKED",
        "version": "0.166.0",
        "binary_sha256": "b8a11fedf24b2dfb59a70c9e52b030f9a508dcd49cd2dd0d41956f4c785156b8",
        "package_sha256": "ffdfc731eed492fa436a304cff8792ea3a96233a45ec9a561f6f56eaca911446",
        "config_sha256": "7ae835188ef2ab3221e15effac45375b2d6112954d022aa7776f802f7b8697c0",
        "compatibility_state": "COMPATIBILITY_PASS_LOCKED",
        "compatibility_governance_lock_sha256": "060b39551d4543999e79ccfd5d133d751faefc018fdc8adab718f5b9c7479a5e",
        "selection_policy": "EXACT_GOVERNANCE_BOUND_IDENTITY_NO_FALLBACK_NO_LATEST",
        "fallback_runtime": None,
        "automatic_latest_selection": False,
    }
    runtime_cases = {
        "EXACT_0_166_PASS_LOCKED": (exact_runtime_binding, True),
        "STALE_0_163_BINDING": ({**exact_runtime_binding, "runtime_identity": "CODEX_RUNTIME_0_163_0_COMPATIBILITY_PASS_LOCKED", "version": "0.163.0"}, False),
        "VERSION_ONLY_0_166": ({"version": "0.166.0"}, False),
        "WRONG_0_166_BINARY_DIGEST": ({**exact_runtime_binding, "binary_sha256": "0" * 64}, False),
        "WRONG_0_166_PACKAGE_DIGEST": ({**exact_runtime_binding, "package_sha256": "0" * 64}, False),
        "UNAUTHORIZED_OTHER_RUNTIME": ({**exact_runtime_binding, "runtime_identity": "CODEX_RUNTIME_OTHER"}, False),
        "LATEST_SELECTION": ({**exact_runtime_binding, "automatic_latest_selection": True}, False),
    }
    for offset, (name, (binding, expected_pass)) in enumerate(runtime_cases.items(), 239):
        verdict = runtime_binding_fixture_verdict(binding)
        check(f"U{offset:03d}_V35_RUNTIME_BINDING_{name}", (verdict.get("status") == "PASS") is expected_pass, verdict)

    typed_runtime_contract = json.loads((ROOT / "contracts/TYPED_CODEX_RUNTIME_ACCEPTANCE_BINDING_CONTRACT.json").read_text())
    typed_runtime_cases = {
        "EXACT_TYPED_0_166": (typed_runtime_contract, True),
        "STALE_CURRENT_FIELD_0_163": ({**typed_runtime_contract, "current_authority_field": "codex_runtime_0_163_0"}, False),
        "MIXED_CURRENT_HISTORICAL": ({**typed_runtime_contract, "mixed_current_historical_binding": True}, False),
        "VERSION_ONLY": ({**typed_runtime_contract, "version_string_only": True}, False),
        "WRONG_BINARY": ({**typed_runtime_contract, "binary_sha256": "0" * 64}, False),
        "WRONG_PACKAGE": ({**typed_runtime_contract, "package_sha256": "1" * 64}, False),
        "WRONG_CONFIG": ({**typed_runtime_contract, "dedicated_config_sha256": "2" * 64}, False),
        "WRONG_ACCEPTANCE_AUTHORITY": ({**typed_runtime_contract, "compatibility_governance_lock_sha256": "3" * 64}, False),
    }
    for offset, (name, (binding, expected_pass)) in enumerate(typed_runtime_cases.items(), 246):
        verdict = runtime_acceptance_fixture_verdict(binding)
        check(f"U{offset:03d}_V35_TYPED_RUNTIME_{name}", (verdict.get("status") == "PASS") is expected_pass, verdict)
    typed_runtime = typed_runtime_acceptance_precheck("UNIT")
    check("U254_V35_TYPED_RUNTIME_ACCEPTANCE_PRECHECK", typed_runtime.get("status") == "PASS", typed_runtime)

    exact_finalization = {
        "symbol_before_closure": True,
        "symbol_in_closed_set": True,
        "creation_phase_closed": True,
        "all_modes_0444": True,
        "ownership_exact": True,
        "digests_bound_after_closure": True,
        "reread_rehash_exact": True,
        "member_set_unchanged": True,
        "prompt_dependency_set_complete": True,
        "validation_after_ready": True,
    }
    finalization_cases = {
        "EXACT_COMPLETE_SUCCESS": ({}, True),
        "MANIFEST_AFTER_CLOSURE": ({"symbol_before_closure": False}, False),
        "MANIFEST_AFTER_DIGEST_BINDING": ({"digests_bound_after_closure": False}, False),
        "MANIFEST_OMITTED": ({"symbol_in_closed_set": False}, False),
        "WRITABLE_0664": ({"all_modes_0444": False}, False),
        "NEW_MEMBER_AFTER_CLOSURE": ({"member_set_unchanged": False}, False),
        "MEMBER_REMOVED_OR_RENAMED": ({"member_set_unchanged": False}, False),
        "MEMBER_DIGEST_MUTATED": ({"reread_rehash_exact": False}, False),
        "PROMPT_EXACT_DEPENDENCY_SET_INCOMPLETE": ({"prompt_dependency_set_complete": False}, False),
        "VALIDATION_BEFORE_READY": ({"validation_after_ready": False}, False),
    }
    for offset, (name, (changes, expected_pass)) in enumerate(finalization_cases.items(), 372):
        verdict = finalization_fixture_verdict({**exact_finalization, **changes})
        check(f"U{offset:03d}_V35_ARTIFACT_FINALIZATION_{name}", (verdict.get("status") == "PASS") is expected_pass, verdict)
    finalization = authoritative_artifact_finalization_precheck()
    check("U382_V35_AUTHORITATIVE_ARTIFACT_FINALIZATION_PRECHECK", finalization.get("status") == "PASS", finalization)

    current_view = json.loads((ROOT / "contracts/CURRENT_EXPECTED_DIGEST_VIEW.json").read_text(encoding="utf-8"))
    current_rows = current_view["artifacts"]
    current_registry = json.loads((ROOT / "contracts/UNIFIED_AUTHORITATIVE_BINDING_GENERATION.json").read_text(encoding="utf-8"))
    def mutate_current_view(binding_key: str, **changes: object) -> list[dict[str, object]]:
        rows = [dict(row) for row in current_rows]
        next(row for row in rows if row["binding_key"] == binding_key).update(changes)
        return rows
    digest_cases = {
        "CURRENT_WITH_STALE_PREDECESSOR_DIGEST": (mutate_current_view("successor_v35_requirements", artifact_sha256="8901ca134535551c9417ff2194d05da8be5c155d807bdd09d6daa28a50c7346d"), False),
        "CURRENT_WITH_STALE_OWNER_GOVERNANCE": (mutate_current_view("typed_historical_decision_registry", owner_governance_sha256="0" * 64), False),
        "CURRENT_BOUND_TO_PREDECESSOR_GENERATION": (mutate_current_view("typed_historical_decision_registry_contract", binding_generation_identity="V32_CURRENT_GOVERNANCE_BOUND_TYPED_PREFLIGHT_BINDING_GENERATION_0001"), False),
        "HISTORICAL_SELECTED_AS_CURRENT": (mutate_current_view("unified_binding_generation_contract", current_historical_status="HISTORICAL_ONLY"), False),
        "MANUAL_EXPECTED_DIGEST_DIFFERS": (mutate_current_view("v35_symbol_resolution_regression_matrix", artifact_sha256="1" * 64, source_authoritative_registry_identity="MANUAL_EXPECTED_DIGEST_TABLE"), False),
        "MIXED_HISTORICAL_CURRENT_VIEW": (mutate_current_view("v35_typed_module_identity_contract", current_historical_status="HISTORICAL_ONLY", binding_generation_identity="V32_CURRENT_GOVERNANCE_BOUND_TYPED_PREFLIGHT_BINDING_GENERATION_0001"), False),
        "EXACT_COMPLETE_DERIVED_CURRENT_VIEW": (current_rows, True),
    }
    for name, (rows, expected_pass) in digest_cases.items():
        verdict = derived_view_fixture_verdict(rows, current_registry)
        check(f"U_V35_DERIVED_DIGEST_VIEW_{name}", (verdict.get("status") == "PASS") is expected_pass, verdict)
    digest_view_precheck = derived_current_expected_digest_view_precheck()
    check("U_V35_DERIVED_CURRENT_EXPECTED_DIGEST_VIEW_PRECHECK", digest_view_precheck.get("status") == "PASS", digest_view_precheck)
    check(
        "U_V35_DERIVED_CURRENT_EXPECTED_DIGEST_CORPUS_COMPLETE",
        {row["binding_key"] for row in current_rows} == set(CURRENT_KEY_IDENTITIES),
    )

    exact_helper = '''\
def inspect_runtime_identity():
    checks = {"runtime_exact": True}
    return {"record_type": "V35_RUNTIME_IDENTITY_VERDICT", "status": "PASS", "checks": checks}
'''
    helper_cases = {
        "CHECKS_CONSTRUCTED_RETURN_OMITTED": ('def inspect_runtime_identity():\n    checks = {"runtime_exact": True}\n', False),
        "IMPLICIT_NONE": ('def inspect_runtime_identity():\n    return None\n', False),
        "UNREACHABLE_RETURN": ('def inspect_runtime_identity():\n    raise RuntimeError()\n    return {"record_type":"X","status":"PASS","checks":{"x":True}}\n', False),
        "RETURN_AFTER_SIBLING_FUNCTION_DEFINITION": ('def inspect_runtime_identity():\n    checks={"x":True}\ndef sibling():\n    return {"record_type":"X","status":"PASS","checks":{"x":True}}\n', False),
        "WRONGLY_NESTED_RETURN": ('def inspect_runtime_identity():\n    def nested():\n        return {"record_type":"X","status":"PASS","checks":{"x":True}}\n', False),
        "EXACT_TYPED_REACHABLE_VERDICT": (exact_helper, True),
    }
    for name, (source, expected_pass) in helper_cases.items():
        verdict = helper_source_verdict(source, "inspect_runtime_identity")
        check(f"U_V35_HELPER_{name}", (verdict.get("status") == "PASS") is expected_pass, verdict)
    wrong_type_rejected = False
    try:
        require_typed_verdict(["not", "a", "verdict"], "fixture")
    except TypedValidatorVerdictError:
        wrong_type_rejected = True
    check("U_V35_HELPER_WRONG_RESULT_TYPE", wrong_type_rejected)
    unguarded = caller_guard_verdict('result=inspect_runtime_identity()\nstatus=result.get("status")\n', "inspect_runtime_identity")
    guarded = caller_guard_verdict('result=require_typed_verdict(inspect_runtime_identity(),"inspect_runtime_identity")\nstatus=result.get("status")\n', "inspect_runtime_identity")
    check("U_V35_HELPER_CALLER_CONSUMES_BEFORE_TYPE_GUARD", unguarded.get("status") != "PASS", unguarded)
    check("U_V35_HELPER_EXACT_GUARDED_CALLER", guarded.get("status") == "PASS", guarded)
    actual_helper_contract = critical_validator_helper_contract_precheck()
    check("U_V35_HELPER_ACTUAL_CONTRACT_PRECHECK", actual_helper_contract.get("status") == "PASS", actual_helper_contract)
    actual_runtime_verdict = require_typed_verdict(inspect_runtime_identity(), "inspect_runtime_identity")
    check("U_V35_HELPER_ACTUAL_RUNTIME_IDENTITY_VERDICT", actual_runtime_verdict.get("status") == "PASS", actual_runtime_verdict)

    for offset, path in enumerate(sorted([*ROOT.glob("*.py"), *(ROOT / "src").glob("*.py"), *(ROOT / "validators").glob("*.py"), *(ROOT / "tests").glob("*.py")]), 100):
        try:
            ast.parse(path.read_text(encoding="utf-8"))
            syntax_ok = True
        except SyntaxError:
            syntax_ok = False
        check(f"U{offset:03d}_AST_{path.name}", syntax_ok)
    runner = (ROOT / "src/runner_v35.py").read_text(encoding="utf-8")
    observer = (ROOT / "src/topology_observer_v35.py").read_text(encoding="utf-8")
    check("U120_NO_SELFTEST_DELETE", "unlink(" not in runner and "rmtree(" not in runner)
    check("U121_NO_EXIST_OK_TRUE", "exist_ok=True" not in runner)
    check("U122_PROC_CONNECTOR_CAPTURE", "class ProcConnector" in observer and "PROC_CN_MCAST_LISTEN" in observer)
    check("U123_NO_PERCENTAGE_ACCEPTANCE", "percentage_thresholds" in observer and ">=" not in observer[observer.index("def coverage_accounting"):observer.index("def run(")])
    check("U124_AUTHORIZATION_EXACT", AUTHORIZATION_ID == GOVERNANCE_IDENTITY)
    check("U125_IDENTITY_EXACT", EXECUTION_IDENTITY == "V0_3_FIRST_REAL_SECURITY_WORKER_INVOCATION_V35")
    check("U126_ATTEMPT_ABSENT", not (STATIC_RUN / "ATTEMPT_MARKER.json").exists())
    check("U127_RUNTIME_RESULT_ABSENT", not (STATIC_RUN / "runtime-result-0001.json").exists())

    failures = [item["id"] for item in checks if item["status"] == "FAIL"]
    result = {
        "record_type": "V35_UNIT_FIXTURES",
        "execution_identity": EXECUTION_IDENTITY,
        "status": "PASS" if not failures else "FAIL_CLOSED",
        "checks": checks,
        "validation_counts": {"total": len(checks), "passed": len(checks) - len(failures), "failed": len(failures)},
        "failure_ids": failures,
        "attempt_count": 0,
        "worker_invocation_count": 0,
        "codex_as_worker_invocation_count": 0,
    }
    append_only_json(ROOT / "results/prelock/unit-fixtures-run-0001.json", result)
    print(json.dumps(result["validation_counts"], sort_keys=True))
    return 0 if not failures else 1


if __name__ == "__main__":
    raise SystemExit(main())
