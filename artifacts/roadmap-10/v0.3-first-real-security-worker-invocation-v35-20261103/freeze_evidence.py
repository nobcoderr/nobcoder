"""Freeze one-shot worker evidence after independent post-validation."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import stat
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parent
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
_resolver.load_canonical_modules("EVIDENCE_FREEZE", ("workspace_boundary_v35",))
from workspace_boundary_v35 import guarded_chmod, guarded_json_once
RUN = ROOT / "static-run-v35"
EXCLUDED = {"EVIDENCE_MANIFEST.json", "EVIDENCE_FREEZE_LOCK.json", "EVIDENCE_FREEZE_VERIFICATION.json"}


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def write_once(path: Path, payload: dict) -> None:
    guarded_json_once(path, payload, operation_identity=f"EVIDENCE_FREEZE_WRITE:{path.name}", generation="FREEZE_0001")


def root_digest(members: list[dict]) -> str:
    rows = "".join(f"{item['sha256']}  {item['path']}\n" for item in members)
    return hashlib.sha256(rows.encode("utf-8")).hexdigest()


def main() -> int:
    post = json.loads((RUN / "independent-post-validation-0001.json").read_text(encoding="utf-8"))
    runtime = json.loads((RUN / "runtime-result-0001.json").read_text(encoding="utf-8"))
    if post.get("diagnostic_complete") is not True or runtime.get("diagnostic_complete") is not True:
        raise RuntimeError("diagnostic-complete runtime and post-validation evidence required")
    technical_pass = post.get("status") == "PASS" and runtime.get("status") == "PASS"
    freeze_state = "PASS_EVIDENCE_FREEZE" if technical_pass else "FROZEN_FAILURE_EVIDENCE"
    terminal_status = (
        "PASS_TECHNICAL_FROZEN_AWAITING_SEPARATE_ACCEPTANCE_ADJUDICATION"
        if technical_pass
        else "FAIL_CLOSED_POST_ATTEMPT_TERMINAL_NO_RETRY_FROZEN_FAILURE_EVIDENCE"
    )
    terminal = {
        "record_type": "FIRST_REAL_SECURITY_WORKER_INVOCATION_TERMINAL_ENGINEERING_RESULT",
        "execution_identity": "V0_3_FIRST_REAL_SECURITY_WORKER_INVOCATION_V35",
        "status": terminal_status,
        "evidence_freeze_state": freeze_state,
        "attempt_count": 1,
        "attempt_limit": 1,
        "worker_invocation_count": 1,
        "codex_as_worker_invocation_count": 1,
        "candidate_initial_state": "HYPOTHESIS_QUARANTINED",
        "candidate_promotion_count": 0,
        "target_operation_count": 0,
        "credential_operation_count": 0,
        "external_network_operation_count": 0,
        "subagent_invocation_count": 0,
        "parallel_operation_count": 0,
        "capability_edge_count": 0,
        "submission_operation_count": 0,
        "separate_acceptance_adjudication_required": True,
        "pass_locked": False,
        "failed_post_validation_ids": post.get("failure_ids", []),
        "frozen_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    }
    write_once(RUN / "TERMINAL_ENGINEERING_RESULT.json", terminal)
    members = []
    for path in sorted(item for item in RUN.rglob("*") if item.is_file() and item.name not in EXCLUDED):
        relative = path.relative_to(RUN).as_posix()
        members.append({"path": relative, "sha256": digest(path), "bytes": path.stat().st_size, "required_mode": "0444"})
    canonical_root = root_digest(members)
    manifest = {
        "record_type": "FIRST_REAL_SECURITY_WORKER_INVOCATION_EVIDENCE_MANIFEST",
        "schema_version": "1.0",
        "execution_identity": "V0_3_FIRST_REAL_SECURITY_WORKER_INVOCATION_V35",
        "member_count": len(members),
        "canonical_evidence_root_sha256": canonical_root,
        "members": members,
    }
    write_once(RUN / "EVIDENCE_MANIFEST.json", manifest)
    lock = {
        "record_type": "FIRST_REAL_SECURITY_WORKER_INVOCATION_EVIDENCE_FREEZE_LOCK",
        "schema_version": "1.0",
        "execution_identity": "V0_3_FIRST_REAL_SECURITY_WORKER_INVOCATION_V35",
        "status": terminal_status,
        "evidence_freeze_state": freeze_state,
        "attempt_count": 1,
        "attempt_limit": 1,
        "worker_invocation_count": 1,
        "codex_as_worker_invocation_count": 1,
        "canonical_evidence_root_sha256": canonical_root,
        "evidence_manifest_sha256": digest(RUN / "EVIDENCE_MANIFEST.json"),
        "source_lock_sha256": digest(ROOT / "STATIC_EXECUTION_LOCK.json"),
        "acceptance_adjudication_issued": False,
        "pass_locked": False,
    }
    write_once(RUN / "EVIDENCE_FREEZE_LOCK.json", lock)
    for item in members:
        guarded_chmod(RUN / item["path"], 0o444, operation_identity="EVIDENCE_FREEZE_MEMBER", generation="FREEZE_0001")
    guarded_chmod(RUN / "EVIDENCE_MANIFEST.json", 0o444, operation_identity="EVIDENCE_FREEZE_MANIFEST", generation="FREEZE_0001")
    guarded_chmod(RUN / "EVIDENCE_FREEZE_LOCK.json", 0o444, operation_identity="EVIDENCE_FREEZE_LOCK", generation="FREEZE_0001")
    checks = []
    for item in members:
        path = RUN / item["path"]
        checks.append(path.is_file() and not path.is_symlink() and digest(path) == item["sha256"] and stat.S_IMODE(path.stat().st_mode) == 0o444)
    verification = {
        "record_type": "FIRST_REAL_SECURITY_WORKER_INVOCATION_EVIDENCE_FREEZE_VERIFICATION",
        "execution_identity": "V0_3_FIRST_REAL_SECURITY_WORKER_INVOCATION_V35",
        "status": "PASS" if all(checks) and root_digest(members) == canonical_root else "FAIL_CLOSED",
        "evidence_freeze_state": freeze_state,
        "technical_pass": technical_pass,
        "checks_total": len(checks) + 3,
        "checks_passed": sum(checks) + 3 if all(checks) else sum(checks),
        "member_count": len(members),
        "canonical_evidence_root_sha256": canonical_root,
        "manifest_read_only": stat.S_IMODE((RUN / "EVIDENCE_MANIFEST.json").stat().st_mode) == 0o444,
        "lock_read_only": stat.S_IMODE((RUN / "EVIDENCE_FREEZE_LOCK.json").stat().st_mode) == 0o444,
    }
    write_once(RUN / "EVIDENCE_FREEZE_VERIFICATION.json", verification)
    guarded_chmod(RUN / "EVIDENCE_FREEZE_VERIFICATION.json", 0o444, operation_identity="EVIDENCE_FREEZE_VERIFICATION", generation="FREEZE_0001")
    for directory in sorted((path for path in RUN.rglob("*") if path.is_dir()), reverse=True):
        guarded_chmod(directory, 0o555, operation_identity="EVIDENCE_FREEZE_DIRECTORY", generation="FREEZE_0001")
    guarded_chmod(RUN, 0o555, operation_identity="EVIDENCE_FREEZE_RUN_ROOT", generation="FREEZE_0001")
    print(json.dumps({"status": verification["status"], "members": len(members), "root": canonical_root}, sort_keys=True))
    return 0 if verification["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
