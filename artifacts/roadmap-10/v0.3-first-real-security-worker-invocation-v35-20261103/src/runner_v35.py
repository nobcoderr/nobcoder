"""One-shot runner for the first real, fixture-only SecurityWorker invocation."""

from __future__ import annotations

import json
import argparse
import os
import resource
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

sys.dont_write_bytecode = True
from invocation_v35 import (  # noqa: E402
    AUTHORIZATION_ID,
    authoritative_artifact_digest_precheck,
    authoritative_artifact_finalization_precheck,
    CAMPAIGN_ID,
    CODEX_BINARY,
    CODEX_CONFIG,
    CONTEXT_ROOT,
    EXECUTION_IDENTITY,
    LANE_ID,
    MODEL_IDENTITY,
    OBSERVER_EVENTS,
    OBSERVER_READY,
    OBSERVER_ROOT,
    OBSERVER_ROOT_BOUND,
    OBSERVER_SNAPSHOT,
    OBSERVER_STOP,
    PROMPT_PATH,
    PROPOSAL_AUTHORITY,
    PYTHON,
    STRACE,
    RUNTIME_IDENTITY,
    SANDBOX_CODEX_BINARY,
    STATIC_RUN,
    SHORT_LIVED_CHILD,
    TEMPORAL_OBSERVER,
    WORKER_ID,
    WORKER_LAUNCH_GO,
    WORKER_LAUNCH_READY,
    WORKSPACE,
    WORKSPACE_ID,
    append_only_json,
    authoritative_predecessor_resolution_precheck,
    canonical_predecessor_binding_precheck,
    external_predecessor_artifact_precheck,
    bind_destination_feasibility_precheck,
    canonical_json_sha256,
    classify_config_consumption,
    classify_fd_annotations,
    classify_namespace_setup_writes,
    classify_mount_provenance_writes,
    classify_semantic_process_lineage,
    controller_result,
    exact_environment,
    exact_python_environment,
    evaluate_typed_token_usage,
    fresh_preflight,
    inspect_runtime_identity,
    load_json,
    load_traces,
    mount_provenance_policy_precheck,
    operation_counters_after_success,
    parse_mountinfo,
    process_identity_correlation_precheck,
    prompt_identity_binding_precheck,
    python_cache_policy_precheck,
    sha256_file,
    bwrap_argv,
    strace_argv,
    startup_lineage_policy_precheck,
    strict_schema_compatibility_precheck,
    typed_fd_annotation_grammar_precheck,
    successful_execve_events,
    transcript_summary,
    token_budget_feasibility_precheck,
    temporal_observer_argv,
    temporal_process_identity_observer_precheck,
    v16_tree_canonicalization_precheck,
    runtime_evidence_paths,
    semantic_lifecycle_anchor_verdict,
    selftest_lifecycle_evidence_verdict,
    verify_v11_reference_predecessor,
    validate_model_output,
    worker_result_state,
    workspace_write_boundary_precheck,
)
from symbol_resolution_v35 import static_symbol_binding_precheck, symbol_resolution_precheck
from module_resolution_v35 import canonical_module_resolution_precheck
from binding_generation_v35 import unified_binding_generation_precheck
from workspace_boundary_v35 import (
    guard_output_root,
    guarded_chmod,
    guarded_mkdir,
    guarded_open_text,
)
from transactional_telemetry_v35 import (
    TelemetryCompletionError,
    consume_completed_json,
    publish_json_transactionally,
)
from mount_output_binding_v35 import mount_output_binding_precheck, stale_mount_literal_precheck
from preflight_requirement_registry_v35 import typed_preflight_requirement_precheck
from host_output_lifecycle_v35 import host_output_bind_source_precheck
from prelock_storage_lifecycle_v35 import prelock_storage_lifecycle_precheck
from runtime_acceptance_v35 import typed_runtime_acceptance_precheck
from validator_helper_contract_v35 import critical_validator_helper_contract_precheck, require_typed_verdict


OBSERVER_IDENTITY = "V35_PROC_CONNECTOR_EVENT_BOUND_PROCESS_IDENTITY_OBSERVER_V1"


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def child_limits() -> None:
    resource.setrlimit(resource.RLIMIT_CPU, (180, 180))
    resource.setrlimit(resource.RLIMIT_AS, (4 * 1024 * 1024 * 1024, 4 * 1024 * 1024 * 1024))
    resource.setrlimit(resource.RLIMIT_FSIZE, (32 * 1024 * 1024, 32 * 1024 * 1024))
    resource.setrlimit(resource.RLIMIT_NOFILE, (256, 256))


def require_pass(path: Path) -> dict[str, Any]:
    value = load_json(path)
    if value.get("status") != "PASS":
        raise RuntimeError(f"required PASS artifact is not PASS: {path}")
    return value
    return value


def verify_locked_members() -> dict[str, Any]:
    manifest = load_json(WORKSPACE / "STATIC_SOURCE_MANIFEST.json")
    mismatches: list[str] = []
    for item in manifest.get("members", []):
        path = WORKSPACE / item["path"]
        if not path.is_file() or path.is_symlink():
            mismatches.append(f"unsafe:{item['path']}")
        elif sha256_file(path) != item["sha256"]:
            mismatches.append(f"digest:{item['path']}")
    return {
        "status": "PASS" if not mismatches else "FAIL",
        "member_count": manifest.get("member_count"),
        "canonical_source_root_sha256": manifest.get("canonical_source_root_sha256"),
        "mismatches": mismatches,
    }


DRY_ROOT = STATIC_RUN / "locked-pre-attempt-validation-0001"
DRY_RESULT = STATIC_RUN / "LOCKED_PRE_ATTEMPT_VALIDATION_RESULT.json"


def prepare_runtime_output(run_root: Path) -> None:
    guard_output_root(run_root, operation_identity="PREPARE_RUNTIME_OUTPUT", generation="RUNTIME_0001")
    for name in ("xdg-cache", "xdg-config", "xdg-data"):
        guarded_mkdir(run_root / name, operation_identity=f"PREPARE_RUNTIME_OUTPUT:{name}", generation="RUNTIME_0001")


def network_event_count(traces: dict[int, str]) -> int:
    tokens = ("socket(", "connect(", "sendto(", "recvfrom(", "sendmsg(", "recvmsg(")
    return sum(1 for text in traces.values() for line in text.splitlines() if line.startswith(tokens))


def wait_for_json(
    path: Path,
    expected_state: str,
    timeout_seconds: float,
    *,
    fixture_identity: str,
) -> dict[str, Any] | None:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        if expected_state == "TRACE_CHILD_READY_WORKER_NOT_STARTED":
            try:
                value = load_json(path) if path.is_file() and not path.is_symlink() else {}
            except (OSError, UnicodeDecodeError, json.JSONDecodeError):
                value = {}
        else:
            try:
                value = consume_completed_json(
                    path,
                    expected_producer_identity=OBSERVER_IDENTITY,
                    expected_fixture_identity=fixture_identity,
                    expected_schema_identity=(
                        "TEMPORAL_PROCESS_IDENTITY_OBSERVER_READINESS"
                        if expected_state == "OBSERVER_READY"
                        else "TEMPORAL_PROCESS_IDENTITY_OBSERVER_ROOT_BINDING"
                    ),
                )
            except (OSError, TelemetryCompletionError):
                value = {}
        if value.get("state") == expected_state:
            return value
        time.sleep(0.001)
    return None


def publish_runner_telemetry(path: Path, payload: dict[str, Any], *, fixture_identity: str, schema_identity: str) -> None:
    publish_json_transactionally(
        path,
        payload,
        producer_identity="V35_RUNNER",
        fixture_identity=fixture_identity,
        schema_identity=schema_identity,
        operation_identity=f"V35_RUNNER_TELEMETRY:{path.name}",
        generation="RUNTIME_OR_SELFTEST_0001",
    )


def run_temporal_observer_selftest(
    evidence_root: Path,
    fixture_mode: str = "combined",
    evidence_identity: str = "observer-selftest-0001",
) -> dict[str, Any]:
    """Exercise the observer and retain a complete, append-only diagnostic corpus."""

    root = evidence_root / evidence_identity
    trace_dir = root / "traces"
    guard_output_root(evidence_root, operation_identity="TEMPORAL_SELFTEST_OUTPUT_ROOT", generation=evidence_identity)
    guarded_mkdir(root, operation_identity="TEMPORAL_SELFTEST_ROOT", generation=evidence_identity)
    guarded_mkdir(trace_dir, operation_identity="TEMPORAL_SELFTEST_TRACE_DIR", generation=evidence_identity)
    paths = {
        "events": root / "events.jsonl",
        "snapshot": root / "snapshot.json",
        "ready": root / "ready.json",
        "root": root / "root.json",
        "root_bound": root / "root-bound.json",
        "stop": root / "stop.json",
        "fixture_ledger": root / "fixture-expected-identity-ledger.jsonl",
        "stderr": root / "observer-stderr.txt",
    }
    argv = [
        str(PYTHON), "-B", str(TEMPORAL_OBSERVER),
        "--events", str(paths["events"]),
        "--snapshot", str(paths["snapshot"]),
        "--ready", str(paths["ready"]),
        "--root", str(paths["root"]),
        "--root-bound", str(paths["root_bound"]),
        "--stop", str(paths["stop"]),
        "--trace-dir", str(trace_dir),
        "--fixture-identity", evidence_identity,
        "--poll-interval-ns", "100000",
        "--max-correlation-slack-ns", "250000000",
    ]
    stderr_handle = guarded_open_text(paths["stderr"], operation_identity="TEMPORAL_SELFTEST_STDERR", generation=evidence_identity)
    observer = subprocess.Popen(
        argv,
        cwd=WORKSPACE,
        env=exact_python_environment(),
        stdout=subprocess.DEVNULL,
        stderr=stderr_handle,
        text=True,
    )
    child: subprocess.Popen[str] | None = None
    try:
        ready = wait_for_json(paths["ready"], "OBSERVER_READY", 5, fixture_identity=evidence_identity)
        if ready is None:
            raise RuntimeError("observer selftest readiness not attested")
        child = subprocess.Popen(
            [
                str(STRACE), "-ff", "-qq", "-yy", "--decode-pids=pidns",
                "-s", "4096", "-o", str(trace_dir / "trace"), "-e",
                "trace=%file,%process,%network,read,write,writev,close",
                str(PYTHON), "-B", str(SHORT_LIVED_CHILD),
                "--mode", fixture_mode,
                "--fixture-ledger", str(paths["fixture_ledger"]),
            ], cwd=WORKSPACE, env=exact_python_environment(),
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, text=True,
        )
        publish_runner_telemetry(paths["root"], {
            "record_type": "V35_OBSERVER_SELFTEST_ROOT",
            "execution_identity": EXECUTION_IDENTITY,
            "root_pid": child.pid,
        }, fixture_identity=evidence_identity, schema_identity="V35_OBSERVER_ROOT")
        root_bound = wait_for_json(paths["root_bound"], "OBSERVER_ROOT_BOUND", 5, fixture_identity=evidence_identity)
        child.wait(timeout=30)
        publish_runner_telemetry(
            paths["stop"],
            {"record_type": "V35_OBSERVER_STOP", "decision": "STOP_AFTER_SHORT_LIVED_CHILD_EXIT"},
            fixture_identity=evidence_identity,
            schema_identity="V35_OBSERVER_STOP",
        )
        observer.wait(timeout=5)
        stderr_handle.close()
        try:
            snapshot = consume_completed_json(
                paths["snapshot"],
                expected_producer_identity=OBSERVER_IDENTITY,
                expected_fixture_identity=evidence_identity,
                expected_schema_identity="V35_COMPLETE_TEMPORALLY_BOUND_PROCESS_IDENTITY_OBSERVER_SNAPSHOT",
            )
        except TelemetryCompletionError:
            snapshot = {}
        observations = snapshot.get("process_observations", []) if isinstance(snapshot, dict) else []
        coverage = snapshot.get("coverage_accounting", {}) if isinstance(snapshot, dict) else {}
        trace_identities = sorted(
            int(path.name.rsplit(".", 1)[1])
            for path in trace_dir.glob("trace.*")
            if path.name.rsplit(".", 1)[-1].isdigit()
        )
        fixture_rows = [
            json.loads(line)
            for line in paths["fixture_ledger"].read_text(encoding="utf-8").splitlines()
            if line.strip()
        ] if paths["fixture_ledger"].is_file() else []
        spawn_requested = sum(int(row.get("count", 0)) for row in fixture_rows if row.get("event") == "SPAWN_REQUESTED")
        spawn_succeeded = sum(1 for row in fixture_rows if row.get("event") == "SPAWN_SUCCEEDED")
        total = coverage.get("lineage_relevant_trace_identity_count")
        valid = coverage.get("valid_temporal_identity_mapping_count")
        checks = {
            "observer_ready_before_child": ready is not None,
            "root_bound_while_child_identity_available": root_bound is not None,
            "short_lived_child_exit_zero": child.returncode == 0,
            "observer_exit_zero": observer.returncode == 0,
            "trace_denominator_independently_enumerated": total == len(trace_identities)
            and trace_identities == snapshot.get("independently_enumerated_trace_visible_identities"),
            "fixture_spawn_accounting_present": spawn_requested > 0 and spawn_succeeded > 0,
            "complete_identity_coverage": isinstance(total, int) and total == valid,
            "missing_zero": coverage.get("missing_identity_count") == 0,
            "ambiguous_zero": coverage.get("ambiguous_identity_count") == 0,
            "coverage_complete_exact": coverage.get("coverage_complete") is True,
            "all_identity_records_retained_after_exit": len(observations) >= int(total or 0),
            "stable_identity_uses_start_identity_and_namespace": all(
                row.get("stable_identity_tuple") == [
                    row.get("host_pid"), row.get("process_start_identity"), row.get("pid_namespace_identity")
                ] for row in observations if row.get("trace_file_pid") in set(coverage.get("valid_trace_identities", []))
            ),
        }
        result = {
            "record_type": "V35_LOCKED_TEMPORAL_OBSERVER_ADVERSARIAL_DESCENDANT_SELFTEST",
            "execution_identity": EXECUTION_IDENTITY,
            "status": "PASS" if all(checks.values()) else "FAIL_CLOSED_BEFORE_ATTEMPT",
            "fixture_mode": fixture_mode,
            "fixture_spawn_requested_count": spawn_requested,
            "fixture_spawn_succeeded_count": spawn_succeeded,
            "lineage_relevant_trace_visible_identity_count": len(trace_identities),
            "independently_enumerated_trace_visible_identities": trace_identities,
            "identity_capture_attempt_count": coverage.get("identity_capture_attempt_count"),
            "successful_capture_count": coverage.get("successful_capture_count"),
            "valid_temporal_mapping_count": valid,
            "missing_mapping_count": coverage.get("missing_identity_count"),
            "ambiguous_mapping_count": coverage.get("ambiguous_identity_count"),
            "observer_start_state": "OBSERVER_STARTED",
            "observer_readiness_state": ready.get("state") if isinstance(ready, dict) else None,
            "observer_runtime_completion_state": snapshot.get("observer_runtime_completion_state"),
            "observer_exit_code": observer.returncode,
            "observer_exit_reason": snapshot.get("observer_exit_reason"),
            "diagnostic_complete": isinstance(observer.returncode, int)
            and isinstance(snapshot.get("observer_exit_reason"), str)
            and paths["stderr"].is_file(),
            "checks": checks,
            "observer_argv_sha256": canonical_json_sha256(argv),
            "snapshot_sha256": sha256_file(paths["snapshot"]) if paths["snapshot"].is_file() else None,
            "events_sha256": sha256_file(paths["events"]) if paths["events"].is_file() else None,
            "stderr_sha256": sha256_file(paths["stderr"]) if paths["stderr"].is_file() else None,
            "fixture_expected_identity_ledger_sha256": sha256_file(paths["fixture_ledger"])
            if paths["fixture_ledger"].is_file() else None,
            "trace_file_digests": {
                path.name: sha256_file(path) for path in sorted(trace_dir.glob("trace.*"))
            },
            "per_trace_capture_accounting": coverage.get("per_trace_capture_accounting", []),
            "attempt_count": 0,
            "worker_invocation_count": 0,
            "codex_as_worker_invocation_count": 0,
        }
    except (OSError, RuntimeError, subprocess.SubprocessError) as exc:
        if child is not None and child.poll() is None:
            child.kill()
            child.wait()
        if not paths["stop"].exists():
            publish_runner_telemetry(
                paths["stop"],
                {"record_type": "V35_OBSERVER_STOP", "decision": "STOP_FAIL_CLOSED_SELFTEST"},
                fixture_identity=evidence_identity,
                schema_identity="V35_OBSERVER_STOP",
            )
        if observer.poll() is None:
            observer.kill()
            observer.wait()
        if not stderr_handle.closed:
            stderr_handle.close()
        stderr = paths["stderr"].read_text(encoding="utf-8", errors="replace") if paths["stderr"].is_file() else ""
        try:
            snapshot = consume_completed_json(
                paths["snapshot"],
                expected_producer_identity=OBSERVER_IDENTITY,
                expected_fixture_identity=evidence_identity,
                expected_schema_identity="V35_COMPLETE_TEMPORALLY_BOUND_PROCESS_IDENTITY_OBSERVER_SNAPSHOT",
            )
        except TelemetryCompletionError:
            snapshot = {}
        result = {
            "record_type": "V35_LOCKED_TEMPORAL_OBSERVER_ADVERSARIAL_DESCENDANT_SELFTEST",
            "execution_identity": EXECUTION_IDENTITY,
            "status": "FAIL_CLOSED_BEFORE_ATTEMPT",
            "fixture_mode": fixture_mode,
            "error": {"type": type(exc).__name__, "message": str(exc)},
            "observer_stderr": stderr,
            "observer_exit_code": observer.returncode,
            "observer_exit_reason": snapshot.get("observer_exit_reason") or "OBSERVER_INTERNAL_ERROR",
            "diagnostic_complete": isinstance(observer.returncode, int)
            and bool(stderr or snapshot.get("observer_exit_reason")),
            "attempt_count": 0,
            "worker_invocation_count": 0,
            "codex_as_worker_invocation_count": 0,
        }
    result_name = (
        "observer-selftest-result-0001.json"
        if evidence_identity == "observer-selftest-0001"
        else f"{evidence_identity}-result.json"
    )
    result_path = evidence_root / result_name
    append_only_json(result_path, result)
    return result


def consume_locked_selftest_artifact() -> dict[str, Any]:
    """Consume the post-lock self-test artifact without modifying or recreating it."""

    result_path = DRY_ROOT / "observer-selftest-result-0001.json"
    summary = load_json(DRY_RESULT) if DRY_RESULT.is_file() else {}
    result = load_json(result_path) if result_path.is_file() else {}
    manifest = load_json(WORKSPACE / "STATIC_SOURCE_MANIFEST.json")
    candidates = list(STATIC_RUN.glob("*/observer-selftest-result-0001.json"))
    verdict = selftest_lifecycle_evidence_verdict(
        artifact_present=result_path.is_file() and not result_path.is_symlink(),
        artifact_status=result.get("status"),
        artifact_digest=sha256_file(result_path) if result_path.is_file() else None,
        expected_digest=summary.get("selftest_result_sha256"),
        artifact_lock_digest=summary.get("static_execution_lock_sha256"),
        current_lock_digest=sha256_file(WORKSPACE / "STATIC_EXECUTION_LOCK.json"),
        artifact_source_root=summary.get("canonical_source_root_sha256"),
        current_source_root=manifest.get("canonical_source_root_sha256"),
        artifact_observer_digest=summary.get("observer_sha256"),
        current_observer_digest=sha256_file(TEMPORAL_OBSERVER),
        candidate_count=len(candidates),
        historical_v11_preserved=verify_v11_reference_predecessor().get("status") == "PASS",
    )
    verdict["artifact_path"] = str(result_path.relative_to(STATIC_RUN))
    verdict["summary_sha256"] = sha256_file(DRY_RESULT) if DRY_RESULT.is_file() else None
    verdict["artifact"] = result
    return verdict


def topology_from_observer_snapshot(snapshot: dict[str, Any]) -> dict[str, Any]:
    host_mountinfo = parse_mountinfo(Path("/proc/self/mountinfo").read_text(encoding="utf-8"))
    observations = [dict(item) for item in snapshot.get("process_observations", []) if isinstance(item, dict)]
    runtime_candidates = [
        item for item in observations
        if item.get("exe") == str(CODEX_BINARY)
        or item.get("exe") == str(SANDBOX_CODEX_BINARY)
        or (item.get("cmdline") and item["cmdline"][0] == str(SANDBOX_CODEX_BINARY))
    ]
    runtime = max(runtime_candidates, key=lambda item: int(item.get("observation_count", 0)), default=None)
    mountinfo_text = runtime.get("mountinfo_text") if runtime else None
    runtime_mountinfo = parse_mountinfo(mountinfo_text) if isinstance(mountinfo_text, str) else []
    public = [{key: value for key, value in item.items() if key != "mountinfo_text"} for item in observations]
    coverage = snapshot.get("coverage_accounting", {})
    status = (
        "PASS" if snapshot.get("status") == "PASS"
        and coverage.get("coverage_complete") is True
        and coverage.get("missing_identity_count") == 0
        and coverage.get("ambiguous_identity_count") == 0
        and runtime is not None and runtime_mountinfo
        else "FAIL_CLOSED_RUNTIME_NAMESPACE_OR_TEMPORAL_COVERAGE_NOT_ESTABLISHED"
    )
    return {
        **{key: value for key, value in snapshot.items() if key != "process_observations"},
        "record_type": "FIRST_REAL_SECURITY_WORKER_TEMPORALLY_BOUND_RUNTIME_TOPOLOGY_CAPTURE",
        "status": status,
        "host_mount_namespace": os.readlink("/proc/self/ns/mnt"),
        "host_mountinfo_entries": host_mountinfo,
        "runtime_pid": runtime.get("host_pid") if runtime else None,
        "runtime_mount_namespace": runtime.get("mount_namespace") if runtime else None,
        "runtime_pid_namespace": runtime.get("pid_namespace_identity") if runtime else None,
        "runtime_mountinfo_entries": runtime_mountinfo,
        "process_observations": public,
        "process_observation_count": len(public),
        "process_identity_model": "V35_EVENT_BOUND_HOST_PID_START_IDENTITY_PID_NAMESPACE_V1",
        "coverage_accounting": coverage,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=("validate-pre-attempt", "execute"), default="execute")
    args = parser.parse_args(argv)
    dry_mode = args.mode == "validate-pre-attempt"
    binding_generation = unified_binding_generation_precheck("LOCKED_RUNTIME")
    if binding_generation.get("status") != "PASS":
        raise RuntimeError("unified governance-bound binding generation verification failed")
    canonical_modules = canonical_module_resolution_precheck("LOCKED_RUNTIME")
    if canonical_modules.get("status") != "PASS":
        raise RuntimeError(f"canonical module resolution failed: {canonical_modules.get('failure_reason')}")
    canonical_predecessor = canonical_predecessor_binding_precheck("LOCKED_RUNTIME")
    if canonical_predecessor.get("status") != "PASS":
        raise RuntimeError("canonical governance-bound predecessor verification failed")
    external_predecessor_artifacts = external_predecessor_artifact_precheck("LOCKED_RUNTIME")
    if external_predecessor_artifacts.get("status") != "PASS":
        raise RuntimeError("canonical external predecessor artifact resolution failed")
    boundary = workspace_write_boundary_precheck()
    prelock_storage = prelock_storage_lifecycle_precheck("LOCKED_RUNTIME")
    if prelock_storage.get("status") != "PASS":
        raise RuntimeError("V35_PRELOCK_STORAGE_LIFECYCLE_FAILED")
    if boundary.get("status") != "PASS":
        raise RuntimeError("workspace write boundary precheck failed")
    host_output_lifecycle = host_output_bind_source_precheck("LOCKED_RUNTIME")
    if host_output_lifecycle.get("status") != "PASS":
        raise RuntimeError("host output bind source lifecycle verification failed")
    runtime_authority = typed_runtime_acceptance_precheck("LOCKED_RUNTIME")
    if runtime_authority.get("status") != "PASS":
        raise RuntimeError("typed Codex runtime authority verification failed")
    helper_return_contract = critical_validator_helper_contract_precheck()
    if helper_return_contract.get("status") != "PASS":
        raise RuntimeError("typed validator-helper return contract verification failed")
    runtime_identity_verdict = require_typed_verdict(
        inspect_runtime_identity(), "inspect_runtime_identity"
    )
    if runtime_identity_verdict.get("status") != "PASS":
        raise RuntimeError("actual runtime-identity verdict failed")
    mount_output_identity = mount_output_binding_precheck("LOCKED_RUNTIME")
    if mount_output_identity.get("status") != "PASS":
        raise RuntimeError("governance-bound mount/output identity verification failed")
    stale_mount_bindings = stale_mount_literal_precheck()
    if stale_mount_bindings.get("status") != "PASS":
        raise RuntimeError("stale successor mount/output binding detected")
    typed_preflight_requirements = typed_preflight_requirement_precheck("LOCKED_RUNTIME")
    if typed_preflight_requirements.get("status") != "PASS":
        raise RuntimeError("typed semantic preflight requirement registry failed")
    cache_policy = python_cache_policy_precheck()
    if cache_policy.get("status") != "PASS":
        raise RuntimeError("python cache policy precheck failed")
    static_symbols = static_symbol_binding_precheck()
    if static_symbols.get("status") != "PASS":
        raise RuntimeError("static symbol binding precheck failed")
    symbol_resolution = symbol_resolution_precheck(globals(), require_static_lock=True)
    if symbol_resolution.get("status") != "PASS":
        raise RuntimeError(f"locked runtime symbol resolution failed: {symbol_resolution.get('failures')}")
    guard_output_root(STATIC_RUN, operation_identity="RUNNER_STATIC_RUN_BOUNDARY", generation="DRY_0001" if dry_mode else "RUNTIME_0001")
    if dry_mode:
        guarded_mkdir(DRY_ROOT, operation_identity="LOCKED_PRE_ATTEMPT_ROOT", generation="DRY_0001")
    run_root = DRY_ROOT if dry_mode else STATIC_RUN
    fixture_identity = "locked-pre-attempt-0001" if dry_mode else "runtime-0001"
    paths = runtime_evidence_paths(run_root)
    preflight = fresh_preflight(require_static_lock=True)
    verification = require_pass(WORKSPACE / "STATIC_EXECUTION_LOCK_VERIFICATION.json")
    lock = load_json(WORKSPACE / "STATIC_EXECUTION_LOCK.json")
    human = load_json(WORKSPACE / "HUMAN_GATE.json")
    source_before = verify_locked_members()
    bind_feasibility = bind_destination_feasibility_precheck(bwrap_argv())
    strict_schema = strict_schema_compatibility_precheck()
    typed_fd = typed_fd_annotation_grammar_precheck()
    process_identity = process_identity_correlation_precheck()
    temporal_policy = temporal_process_identity_observer_precheck()
    startup_lineage = startup_lineage_policy_precheck()
    mount_provenance = mount_provenance_policy_precheck("LOCKED_RUNTIME")
    token_budget = token_budget_feasibility_precheck()
    prompt_identity = prompt_identity_binding_precheck()
    artifact_identity = authoritative_artifact_digest_precheck()
    artifact_finalization = authoritative_artifact_finalization_precheck()
    predecessor_resolution = authoritative_predecessor_resolution_precheck()
    v16_canonicalization = v16_tree_canonicalization_precheck()
    lifecycle_semantics = semantic_lifecycle_anchor_verdict(
        (WORKSPACE / "src/runner_v35.py").read_text(encoding="utf-8")
    )
    observer_selftest = (
        run_temporal_observer_selftest(DRY_ROOT)
        if dry_mode
        else consume_locked_selftest_artifact()
    )
    lifecycle_pass = (
        observer_selftest.get("status") == "PASS"
        if dry_mode
        else observer_selftest.get("status") == "PASS_READ_ONLY_CONSUMPTION"
    )
    checks = {
        "post_lock_preflight": preflight.get("status") == "PASS",
        "unified_binding_generation": binding_generation.get("status") == "PASS",
        "unified_binding_generation_locked": lock.get("unified_binding_generation_precheck_sha256")
        == canonical_json_sha256(binding_generation),
        "canonical_predecessor_binding": canonical_predecessor.get("status") == "PASS",
        "canonical_module_resolution": canonical_modules.get("status") == "PASS",
        "canonical_module_resolution_locked": lock.get("canonical_module_resolution_precheck_sha256")
        == canonical_json_sha256(canonical_modules),
        "canonical_predecessor_binding_locked": lock.get("canonical_predecessor_binding_precheck_sha256")
        == canonical_json_sha256(canonical_predecessor),
        "external_predecessor_artifact_binding": external_predecessor_artifacts.get("status") == "PASS",
        "external_predecessor_artifact_binding_locked": lock.get("external_predecessor_artifact_precheck_sha256")
        == canonical_json_sha256(external_predecessor_artifacts),
        "governance_bound_mount_output_identity": mount_output_identity.get("status") == "PASS",
        "governance_bound_mount_output_identity_locked": lock.get("mount_output_identity_precheck_sha256")
        == canonical_json_sha256(mount_output_identity),
        "zero_stale_successor_mount_bindings": stale_mount_bindings.get("status") == "PASS",
        "typed_semantic_preflight_requirements": typed_preflight_requirements.get("status") == "PASS",
        "typed_semantic_preflight_requirements_locked": lock.get("typed_preflight_requirement_precheck_sha256")
        == canonical_json_sha256(typed_preflight_requirements),
        "workspace_write_boundary": boundary.get("status") == "PASS",
        "workspace_write_boundary_locked": lock.get("workspace_write_boundary_precheck_sha256") == canonical_json_sha256(boundary),
        "host_output_bind_source_lifecycle": host_output_lifecycle.get("status") == "PASS",
        "host_output_bind_source_lifecycle_locked": lock.get("host_output_bind_source_lifecycle_precheck_sha256")
        == canonical_json_sha256(host_output_bind_source_precheck("STATIC_LOCK_PREPARATION")),
        "typed_codex_runtime_authority": runtime_authority.get("status") == "PASS",
        "typed_codex_runtime_authority_locked": lock.get("typed_runtime_acceptance_precheck_sha256")
        == canonical_json_sha256(typed_runtime_acceptance_precheck("STATIC_LOCK_PREPARATION")),
        "typed_validator_helper_return_contract": helper_return_contract.get("status") == "PASS",
        "typed_validator_helper_return_contract_locked": lock.get("typed_validator_helper_return_contract_precheck_sha256")
        == canonical_json_sha256(helper_return_contract),
        "actual_runtime_identity_typed_verdict": runtime_identity_verdict.get("status") == "PASS",
        "actual_runtime_identity_typed_verdict_locked": lock.get("runtime_identity_typed_verdict_sha256")
        == canonical_json_sha256(runtime_identity_verdict),
        "python_cache_policy": cache_policy.get("status") == "PASS",
        "locked_runtime_symbol_resolution": symbol_resolution.get("status") == "PASS",
        "static_symbol_binding_locked": lock.get("static_symbol_binding_precheck_sha256")
        == canonical_json_sha256(static_symbols),
        "v16_canonicalization_symbol_runtime_callable": symbol_resolution.get("target_runtime_callable") is True,
        "python_cache_policy_locked": lock.get("python_cache_policy_precheck_sha256") == canonical_json_sha256(cache_policy),
        "python_environment_locked": lock.get("python_environment_sha256") == canonical_json_sha256(exact_python_environment()),
        "lock_verification": verification.get("status") == "PASS",
        "lock_state": lock.get("status") == "STATIC_LOCKED_NOT_EXECUTED",
        "human_gate": human.get("decision") == "AUTHORIZE_EXACTLY_ONE_FIRST_REAL_SECURITY_WORKER_INVOCATION_V35_IF_ALL_PRE_ATTEMPT_GATES_PASS",
        "source_integrity_before": source_before.get("status") == "PASS",
        "attempt_marker_absent": not (STATIC_RUN / "ATTEMPT_MARKER.json").exists(),
        "runtime_result_absent": not (STATIC_RUN / "runtime-result-0001.json").exists(),
        "exact_argv_locked": lock.get("strace_argv_sha256") == canonical_json_sha256(strace_argv()),
        "exact_environment_locked": lock.get("environment_sha256") == canonical_json_sha256(exact_environment()),
        "locked_temporal_observer_selftest_lifecycle": lifecycle_pass,
        "selftest_read_only_consumption_or_unique_production": dry_mode
        or observer_selftest.get("rewrite_performed") is False,
        "bind_destination_feasibility_precheck": bind_feasibility.get("status") == "PASS",
        "strict_schema_compatibility_precheck": strict_schema.get("status") == "PASS",
        "typed_fd_annotation_grammar_precheck": typed_fd.get("status") == "PASS",
        "cross_namespace_process_identity_precheck": process_identity.get("status") == "PASS",
        "temporal_process_identity_observer_precheck": temporal_policy.get("status") == "PASS",
        "semantic_startup_lineage_precheck": startup_lineage.get("status") == "PASS",
        "mount_provenance_write_precheck": mount_provenance.get("status") == "PASS",
        "typed_token_budget_precheck": token_budget.get("status") == "PASS",
        "prompt_identity_binding_precheck": prompt_identity.get("status") == "PASS",
        "authoritative_artifact_digest_precheck": artifact_identity.get("status") == "PASS",
        "authoritative_artifact_creation_closure_and_finalization": artifact_finalization.get("status") == "PASS",
        "authoritative_artifact_finalization_locked": lock.get("authoritative_artifact_finalization_precheck_sha256")
        == canonical_json_sha256(artifact_finalization),
        "authoritative_predecessor_resolution_precheck": predecessor_resolution.get("status") == "PASS",
        "normative_v16_tree_canonicalization_precheck": v16_canonicalization.get("status") == "PASS",
        "normative_v16_tree_canonicalization_locked": lock.get("v16_tree_canonicalization_precheck_sha256")
        == canonical_json_sha256(v16_canonicalization),
        "semantic_lifecycle_A_lt_B_lt_C_lt_D_lt_E": lifecycle_semantics.get("status") == "PASS",
        "cross_namespace_process_identity_locked": lock.get("cross_namespace_process_identity_precheck_sha256") == canonical_json_sha256(process_identity),
        "temporal_process_identity_observer_locked": lock.get("temporal_process_identity_observer_precheck_sha256")
        == canonical_json_sha256(temporal_policy),
        "temporal_observer_argv_locked": lock.get("temporal_observer_argv_sha256")
        == canonical_json_sha256(temporal_observer_argv()),
        "semantic_startup_lineage_locked": lock.get("semantic_startup_lineage_precheck_sha256") == canonical_json_sha256(startup_lineage),
        "mount_provenance_write_locked": lock.get("mount_provenance_write_precheck_sha256") == canonical_json_sha256(mount_provenance),
        "typed_token_budget_locked": lock.get("typed_token_budget_precheck_sha256") == canonical_json_sha256(token_budget),
        "typed_fd_annotation_grammar_locked": lock.get("typed_fd_annotation_grammar_precheck_sha256") == canonical_json_sha256(typed_fd),
        "prompt_identity_binding_locked": lock.get("prompt_identity_binding_precheck_sha256") == canonical_json_sha256(prompt_identity),
        "authoritative_artifact_digest_locked": lock.get("authoritative_artifact_digest_precheck_sha256") == canonical_json_sha256(artifact_identity),
        "authoritative_predecessor_resolution_locked": lock.get("authoritative_predecessor_resolution_precheck_sha256") == canonical_json_sha256(predecessor_resolution),
        "semantic_lifecycle_locked": lock.get("semantic_lifecycle_anchor_sha256") == canonical_json_sha256(lifecycle_semantics),
    }
    status = "PASS" if all(checks.values()) else "FAIL_CLOSED_ATTEMPT_REMAINS_0_OF_1"
    append_only_json(
        run_root / "pre-attempt-gates-run-0001.json",
        {
            "record_type": "FIRST_REAL_SECURITY_WORKER_INVOCATION_PRE_ATTEMPT_GATES",
            "execution_identity": EXECUTION_IDENTITY,
            "status": status,
            "checks": [{"name": key, "status": "PASS" if value else "FAIL"} for key, value in checks.items()],
            "bind_destination_feasibility_precheck": bind_feasibility,
            "strict_schema_compatibility_precheck": strict_schema,
            "typed_fd_annotation_grammar_precheck": typed_fd,
            "cross_namespace_process_identity_precheck": process_identity,
            "temporal_process_identity_observer_precheck": temporal_policy,
            "locked_temporal_observer_selftest": observer_selftest,
            "python_cache_policy_precheck": cache_policy,
            "locked_runtime_symbol_resolution_precheck": symbol_resolution,
            "static_symbol_binding_precheck": static_symbols,
            "semantic_startup_lineage_precheck": startup_lineage,
            "mount_provenance_write_precheck": mount_provenance,
            "typed_token_budget_precheck": token_budget,
            "prompt_identity_binding_precheck": prompt_identity,
            "authoritative_artifact_digest_precheck": artifact_identity,
            "authoritative_artifact_finalization_precheck": artifact_finalization,
            "authoritative_predecessor_resolution_precheck": predecessor_resolution,
            "canonical_predecessor_binding_precheck": canonical_predecessor,
            "canonical_module_resolution_precheck": canonical_modules,
            "unified_binding_generation_precheck": binding_generation,
            "external_predecessor_artifact_precheck": external_predecessor_artifacts,
            "mount_output_identity_precheck": mount_output_identity,
            "stale_mount_binding_precheck": stale_mount_bindings,
            "typed_preflight_requirement_precheck": typed_preflight_requirements,
            "host_output_bind_source_lifecycle_precheck": host_output_lifecycle,
            "typed_runtime_acceptance_precheck": runtime_authority,
            "typed_validator_helper_return_contract_precheck": helper_return_contract,
            "runtime_identity_typed_verdict": runtime_identity_verdict,
            "normative_v16_tree_canonicalization_precheck": v16_canonicalization,
            "semantic_lifecycle_anchor_precheck": lifecycle_semantics,
            "attempt_count": 0,
            "worker_invocation_count": 0,
            "codex_as_worker_invocation_count": 0,
        },
    )
    if status != "PASS":
        raise RuntimeError("pre-attempt gates failed; attempt remains 0/1")

    prepare_runtime_output(run_root)
    observer_stderr_path = run_root / "temporal-process-observer-stderr-0001.txt"
    observer_process: subprocess.Popen[str] | None = None
    with guarded_open_text(observer_stderr_path, operation_identity="RUNTIME_OBSERVER_STDERR", generation="DRY_0001" if dry_mode else "RUNTIME_0001") as observer_stderr:
        try:
            observer_process = subprocess.Popen(
                temporal_observer_argv(run_root, fixture_identity),
                text=True,
                cwd=WORKSPACE,
                env=exact_python_environment(),
                stdout=subprocess.DEVNULL,
                stderr=observer_stderr,
            )
            observer_ready = wait_for_json(paths["observer_ready"], "OBSERVER_READY", 10, fixture_identity=fixture_identity)
        except OSError as exc:
            observer_ready = None
            observer_start_error = {"type": type(exc).__name__, "message": str(exc)}
        else:
            observer_start_error = None
    observer_readiness_result = {
        "record_type": "FIRST_WORKER_V35_RUNTIME_OBSERVER_READINESS_GATE",
        "execution_identity": EXECUTION_IDENTITY,
        "status": "PASS" if observer_ready is not None and observer_process is not None and observer_process.poll() is None else "FAIL_CLOSED_BEFORE_ATTEMPT",
        "observer_ready": observer_ready,
        "observer_start_error": observer_start_error,
        "observer_argv_sha256": canonical_json_sha256(temporal_observer_argv(run_root, fixture_identity)),
        "source_integrity_after_observer_start": verify_locked_members(),
        "attempt_count": 0,
        "worker_invocation_count": 0,
        "codex_as_worker_invocation_count": 0,
    }
    append_only_json(run_root / "runtime-observer-readiness-gate-0001.json", observer_readiness_result)
    if observer_readiness_result["status"] != "PASS":
        if observer_process is not None and observer_process.poll() is None:
            publish_runner_telemetry(
                paths["observer_stop"],
                {"record_type": "V35_OBSERVER_STOP", "decision": "STOP_OBSERVER_READINESS_FAILURE"},
                fixture_identity=fixture_identity,
                schema_identity="V35_OBSERVER_STOP",
            )
            try:
                observer_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                observer_process.kill()
                observer_process.wait()
        return 1

    transcript_path = run_root / "events.jsonl"
    stderr_path = run_root / "stderr.txt"
    prompt = PROMPT_PATH.read_text(encoding="utf-8")
    request = load_json(WORKSPACE / "contracts/WORKER_REQUEST.json")
    before_usage = resource.getrusage(resource.RUSAGE_CHILDREN)
    started_at: str | None = None
    started_monotonic_ns: int | None = None
    return_code: int | None = None
    timed_out = False
    launch_error: dict[str, str] | None = None
    root_bound: dict[str, Any] | None = None
    launch_gate_ready: dict[str, Any] | None = None
    trace_ready = False
    process: subprocess.Popen[str] | None = None
    try:
        with guarded_open_text(transcript_path, operation_identity="RUNTIME_TRANSCRIPT", generation="DRY_0001" if dry_mode else "RUNTIME_0001") as stdout_handle, guarded_open_text(
            stderr_path, operation_identity="RUNTIME_STDERR", generation="DRY_0001" if dry_mode else "RUNTIME_0001"
        ) as stderr_handle:
            process = subprocess.Popen(
                strace_argv(run_root),
                text=True,
                cwd=WORKSPACE,
                env=exact_python_environment(),
                stdin=subprocess.PIPE,
                stdout=stdout_handle,
                stderr=stderr_handle,
                preexec_fn=child_limits,
            )
            publish_runner_telemetry(paths["observer_root"], {
                "record_type": "FIRST_WORKER_V35_OBSERVER_RUNTIME_ROOT",
                "execution_identity": EXECUTION_IDENTITY,
                "root_pid": process.pid,
                "root_role": "STRACE_SUPERVISOR",
            }, fixture_identity=fixture_identity, schema_identity="V35_OBSERVER_ROOT")
            root_bound = wait_for_json(paths["observer_root_bound"], "OBSERVER_ROOT_BOUND", 10, fixture_identity=fixture_identity)
            launch_gate_ready = wait_for_json(paths["worker_ready"], "TRACE_CHILD_READY_WORKER_NOT_STARTED", 10, fixture_identity=fixture_identity)
            trace_ready = any(run_root.glob("trace.*"))
            if root_bound is None or launch_gate_ready is None or not trace_ready:
                launch_error = {
                    "type": "RuntimeHandshakeFailure",
                    "message": "observer root, traced child, or trace readiness not proven",
                }
                process.kill()
                process.wait()
                return_code = process.returncode
            elif dry_mode:
                process.kill()
                process.wait()
                return_code = process.returncode
                publish_runner_telemetry(paths["observer_stop"], {
                    "record_type": "V35_OBSERVER_STOP",
                    "decision": "STOP_IMMEDIATELY_BEFORE_AUTHORITATIVE_ATTEMPT_CREATION",
                }, fixture_identity=fixture_identity, schema_identity="V35_OBSERVER_STOP")
                observer_process.wait(timeout=10)
                manifest = load_json(WORKSPACE / "STATIC_SOURCE_MANIFEST.json")
                selftest_path = DRY_ROOT / "observer-selftest-result-0001.json"
                dry_result = {
                    "record_type": "V35_LOCKED_PRE_ATTEMPT_VALIDATION_RESULT",
                    "execution_identity": EXECUTION_IDENTITY,
                    "status": "PASS",
                    "strategy": "CONSUME_LOCK_BOUND_IMMUTABLE_PASS_ARTIFACT",
                    "static_execution_lock_sha256": sha256_file(WORKSPACE / "STATIC_EXECUTION_LOCK.json"),
                    "canonical_source_root_sha256": manifest["canonical_source_root_sha256"],
                    "runner_sha256": sha256_file(WORKSPACE / "src/runner_v35.py"),
                    "observer_sha256": sha256_file(TEMPORAL_OBSERVER),
                    "selftest_result_path": str(selftest_path.relative_to(STATIC_RUN)),
                    "selftest_result_sha256": sha256_file(selftest_path),
                    "observer_ready": True,
                    "tracer_ready": True,
                    "stopped_before_attempt_marker": True,
                    "attempt_count": 0,
                    "worker_invocation_count": 0,
                    "codex_as_worker_invocation_count": 0,
                }
                append_only_json(DRY_RESULT, dry_result)
                for item in sorted(DRY_ROOT.rglob("*"), reverse=True):
                    guarded_chmod(item, 0o555 if item.is_dir() else 0o444, operation_identity="FREEZE_DRY_MEMBER", generation="DRY_0001")
                guarded_chmod(DRY_ROOT, 0o555, operation_identity="FREEZE_DRY_ROOT", generation="DRY_0001")
                guarded_chmod(DRY_RESULT, 0o444, operation_identity="FREEZE_DRY_RESULT", generation="DRY_0001")
                if (STATIC_RUN / "ATTEMPT_MARKER.json").exists():
                    raise RuntimeError("dry validation created an attempt marker")
                return 0
            else:
                started_at = utcnow()
                started_monotonic_ns = time.monotonic_ns()
                append_only_json(
                    STATIC_RUN / "ATTEMPT_MARKER.json",
                    {
                        "record_type": "FIRST_REAL_SECURITY_WORKER_INVOCATION_ATTEMPT_MARKER",
                        "execution_identity": EXECUTION_IDENTITY,
                        "attempt_count": 1,
                        "attempt_limit": 1,
                        "worker_invocation_count": 1,
                        "codex_as_worker_invocation_count": 1,
                        "state": "ATTEMPT_CONSUMED_EXECUTION_STARTING_NO_RETRY",
                        "started_at": started_at,
                        "started_monotonic_ns": started_monotonic_ns,
                        "static_execution_lock_sha256": sha256_file(WORKSPACE / "STATIC_EXECUTION_LOCK.json"),
                    },
                )
                append_only_json(paths["worker_go"], {
                    "record_type": "FIRST_WORKER_V35_LAUNCH_GATE_DECISION",
                    "execution_identity": EXECUTION_IDENTITY,
                    "decision": "GO_AFTER_OBSERVER_AND_TRACE_READY",
                    "observer_root_bound_sha256": sha256_file(paths["observer_root_bound"]),
                    "launch_gate_ready_sha256": sha256_file(paths["worker_ready"]),
                })
                process.communicate(input=prompt, timeout=180)
                return_code = process.returncode
        
    except subprocess.TimeoutExpired:
        timed_out = True
        if process is not None and process.poll() is None:
            process.kill()
            process.wait()
            return_code = process.returncode
    except OSError as exc:
        launch_error = {"type": type(exc).__name__, "message": str(exc)}
    finally:
        if not paths["observer_stop"].exists():
            publish_runner_telemetry(paths["observer_stop"], {
                "record_type": "V35_OBSERVER_STOP",
                "execution_identity": EXECUTION_IDENTITY,
                "decision": "STOP_AFTER_RUNTIME_TERMINAL_STATE",
            }, fixture_identity=fixture_identity, schema_identity="V35_OBSERVER_STOP")
        if observer_process is not None and observer_process.poll() is None:
            try:
                observer_process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                observer_process.kill()
                observer_process.wait()
    if not dry_mode and not (STATIC_RUN / "ATTEMPT_MARKER.json").is_file():
        append_only_json(
            STATIC_RUN / "pre-attempt-terminal-result-0001.json",
            {
                "record_type": "V35_PRE_ATTEMPT_TERMINAL_RESULT",
                "status": "FAIL_CLOSED_BEFORE_ATTEMPT",
                "launch_error": launch_error,
                "observer_ready": observer_ready is not None,
                "root_bound": root_bound is not None,
                "tracer_ready": trace_ready,
                "attempt_count": 0,
                "worker_invocation_count": 0,
                "codex_as_worker_invocation_count": 0,
            },
        )
        return 1
    ended_at = utcnow()
    after_usage = resource.getrusage(resource.RUSAGE_CHILDREN)

    observer_snapshot = load_json(OBSERVER_SNAPSHOT) if OBSERVER_SNAPSHOT.is_file() else {
        "status": "FAIL_CLOSED_OBSERVER_SNAPSHOT_MISSING",
        "process_observations": [],
    }
    topology = topology_from_observer_snapshot(observer_snapshot)
    append_only_json(STATIC_RUN / "runtime-topology-snapshot-0001.json", topology)
    traces = load_traces()
    parser_error: dict[str, str] | None = None
    try:
        exec_events = successful_execve_events(traces)
        namespace_writes = classify_namespace_setup_writes(traces)
        config_consumption = classify_config_consumption(traces)
        fd_annotations = classify_fd_annotations(traces)
        process_lineage = classify_semantic_process_lineage(traces, topology)
        typed_writes = classify_mount_provenance_writes(traces, namespace_writes, process_lineage, topology)
    except (TypeError, ValueError) as exc:
        parser_error = {"type": type(exc).__name__, "message": str(exc)}
        exec_events = []
        namespace_writes = {"status": "FAIL", "reason": "PARSER_ABORT"}
        config_consumption = {"status": "FAIL", "reason": "PARSER_ABORT"}
        fd_annotations = {"status": "FAIL_CLOSED", "reason": "PARSER_ABORT", "failures": [parser_error]}
        process_lineage = {"status": "FAIL_CLOSED", "reason": "PARSER_ABORT", "unexpected": []}
        typed_writes = {"status": "FAIL", "reason": "PARSER_ABORT"}
    codex_execs = [item for item in exec_events if item["executable"] == str(SANDBOX_CODEX_BINARY)]
    unexpected_execs = process_lineage.get("unexpected", [])
    transcript = transcript_summary(transcript_path) if transcript_path.is_file() else {"status": "FAIL", "tool_call_count": -1}
    last_message_path = STATIC_RUN / "last-message.json"
    model_output: dict[str, Any] | None = None
    controller_output: dict[str, Any] | None = None
    output_error: dict[str, str] | None = None
    if last_message_path.is_file():
        try:
            parsed = json.loads(last_message_path.read_text(encoding="utf-8"))
            model_output = validate_model_output(parsed)
            controller_output = controller_result(model_output)
            append_only_json(STATIC_RUN / "controller-worker-result-0001.json", controller_output)
        except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
            output_error = {"type": type(exc).__name__, "message": str(exc)}
    else:
        output_error = {"type": "MissingOutput", "message": "last-message.json not emitted"}

    result_state = worker_result_state(
        runtime_completed=return_code is not None and not timed_out and launch_error is None,
        runtime_exit=return_code,
        last_message_exists=last_message_path.is_file(),
        controller_result_exists=(STATIC_RUN / "controller-worker-result-0001.json").is_file(),
    )

    usage = transcript.get("usage", {}) if isinstance(transcript, dict) else {}
    typed_token_usage = evaluate_typed_token_usage(usage)
    network_count = network_event_count(traces)
    source_after = verify_locked_members()
    passed = all(
        (
            launch_error is None,
            not timed_out,
            return_code == 0,
            observer_process is not None and observer_process.returncode == 0,
            observer_ready is not None,
            root_bound is not None,
            launch_gate_ready is not None,
            trace_ready,
            len(codex_execs) == 1,
            not unexpected_execs,
            parser_error is None,
            namespace_writes.get("status") == "PASS",
            config_consumption.get("status") == "PASS",
            fd_annotations.get("status") == "PASS",
            topology.get("status") == "PASS",
            process_lineage.get("status") == "PASS",
            typed_writes.get("status") == "PASS",
            transcript.get("status") == "PASS",
            transcript.get("tool_call_count") == 0,
            output_error is None,
            controller_output is not None,
            result_state == "EMITTED_AND_CONTROLLER_WRAPPED",
            source_after.get("status") == "PASS",
            typed_token_usage.get("status") == "PASS",
        )
    )
    counters = operation_counters_after_success()
    runtime_result = {
        "record_type": "FIRST_REAL_SECURITY_WORKER_INVOCATION_RUNTIME_RESULT",
        "execution_identity": EXECUTION_IDENTITY,
        "status": "PASS" if passed else "FAIL_CLOSED",
        "diagnostic_complete": True,
        "attempt_count": 1,
        "worker_invocation_count": 1,
        "codex_as_worker_invocation_count": 1,
        "campaign_id": CAMPAIGN_ID,
        "lane_id": LANE_ID,
        "worker_id": WORKER_ID,
        "runtime_identity": RUNTIME_IDENTITY,
        "model_identity": MODEL_IDENTITY,
        "authorization_id": AUTHORIZATION_ID,
        "workspace_id": WORKSPACE_ID,
        "request_digest": canonical_json_sha256(request),
        "prompt_digest": sha256_file(PROMPT_PATH),
        "structured_output_digest": sha256_file(last_message_path) if last_message_path.is_file() else None,
        "controller_result_digest": sha256_file(STATIC_RUN / "controller-worker-result-0001.json") if (STATIC_RUN / "controller-worker-result-0001.json").is_file() else None,
        "config_digest": sha256_file(CODEX_CONFIG),
        "start_timestamp": started_at,
        "end_timestamp": ended_at,
        "exit_status": return_code,
        "timed_out": timed_out,
        "launch_error": launch_error,
        "output_error": output_error,
        "worker_result_state": result_state,
        "parser_error": parser_error,
        "strict_schema_compatibility_precheck": strict_schema,
        "typed_fd_annotation_grammar_precheck": typed_fd,
        "cross_namespace_process_identity_precheck": process_identity,
        "semantic_startup_lineage_precheck": startup_lineage,
        "mount_provenance_write_precheck": mount_provenance,
        "typed_token_budget_precheck": token_budget,
        "prompt_identity_binding_precheck": prompt_identity,
        "authoritative_artifact_digest_precheck": artifact_identity,
        "authoritative_predecessor_resolution_precheck": predecessor_resolution,
        "temporal_process_identity_observer_precheck": temporal_policy,
        "locked_temporal_observer_selftest": observer_selftest,
        "runtime_observer_readiness": observer_readiness_result,
        "runtime_observer_exit_status": observer_process.returncode if observer_process is not None else None,
        "runtime_observer_snapshot_digest": sha256_file(OBSERVER_SNAPSHOT) if OBSERVER_SNAPSHOT.is_file() else None,
        "runtime_observer_event_log_digest": sha256_file(OBSERVER_EVENTS) if OBSERVER_EVENTS.is_file() else None,
        "runtime_launch_handshake": {
            "observer_root_bound": root_bound,
            "traced_launch_gate_ready": launch_gate_ready,
            "trace_ready": trace_ready,
            "launch_go_digest": sha256_file(WORKER_LAUNCH_GO) if WORKER_LAUNCH_GO.is_file() else None,
        },
        "trace_file_count": len(traces),
        "semantic_codex_exec_count": len(codex_execs),
        "successful_execve_events": exec_events,
        "unexpected_execve_events": unexpected_execs,
        "semantic_process_lineage": process_lineage,
        "runtime_topology_capture": {
            "status": topology.get("status"),
            "runtime_pid": topology.get("runtime_pid"),
            "runtime_mount_namespace": topology.get("runtime_mount_namespace"),
            "runtime_pid_namespace": topology.get("runtime_pid_namespace"),
            "snapshot_digest": sha256_file(STATIC_RUN / "runtime-topology-snapshot-0001.json"),
            "temporal_observer_snapshot_digest": sha256_file(OBSERVER_SNAPSHOT) if OBSERVER_SNAPSHOT.is_file() else None,
            "temporally_observed_trace_pid_count": topology.get("trace_file_observation_count"),
            "pid_reuse_event_count": topology.get("pid_reuse_event_count"),
        },
        "namespace_setup_write_proof": namespace_writes,
        "dedicated_config_consumption_proof": config_consumption,
        "typed_fd_annotation_proof": fd_annotations,
        "typed_write_evidence": typed_writes,
        "typed_token_usage": typed_token_usage,
        "provider_transport_event_count": network_count,
        "provider_transport_classification": "PINNED_CODEX_RUNTIME_INTERNAL_NOT_TARGET_OR_WORKER_TOOL_NETWORK",
        "target_network_event_count": 0,
        "worker_tool_network_event_count": 0,
        "transcript": transcript,
        "resource_usage": {
            "user_cpu_seconds": max(0.0, after_usage.ru_utime - before_usage.ru_utime),
            "system_cpu_seconds": max(0.0, after_usage.ru_stime - before_usage.ru_stime),
            "max_rss_kib": after_usage.ru_maxrss,
            "provider_reported_input_tokens": typed_token_usage.get("fields", {}).get("input_tokens"),
            "provider_reported_output_tokens": typed_token_usage.get("fields", {}).get("output_tokens"),
            "provider_reported_reasoning_output_tokens": typed_token_usage.get("fields", {}).get("reasoning_output_tokens"),
            "computed_total_tokens": typed_token_usage.get("computed_total_tokens"),
        },
        "workspace_effects": {
            "locked_source_before": source_before,
            "locked_source_after": source_after,
            "writable_host_bind_count": 1,
            "declared_output_root": str(STATIC_RUN),
        },
        "model_output": model_output,
        "controller_result": controller_output,
        "proposal_authority": PROPOSAL_AUTHORITY,
        "authority_denial_events": [],
        "operation_counters": counters,
    }
    append_only_json(STATIC_RUN / "runtime-result-0001.json", runtime_result)
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
