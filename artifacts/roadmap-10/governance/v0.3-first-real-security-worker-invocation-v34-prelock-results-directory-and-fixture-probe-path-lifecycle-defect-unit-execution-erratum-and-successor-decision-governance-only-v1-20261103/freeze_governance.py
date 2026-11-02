#!/usr/bin/env python3
"""Freeze the validated V34 governance-only package append-only."""

import hashlib
import os

from governance_common import IDENTITY, ROOT, V34, V35, load, sha256, verify_v33_frozen, verify_v34_frozen, write_once


def main() -> int:
    validations = [
        "PRIMARY_GOVERNANCE_VALIDATION.json",
        "NEGATIVE_GOVERNANCE_FIXTURES.json",
        "INDEPENDENT_GOVERNANCE_VALIDATION.json",
        "READ_ONLY_INTEGRITY_VERIFICATION.json",
    ]
    if verify_v34_frozen()["status"] != "PASS" or verify_v33_frozen()["status"] != "PASS":
        raise SystemExit("historical frozen evidence verification failed")
    if not all(load(ROOT / name)["status"] == "PASS" for name in validations):
        raise SystemExit("governance readiness failed")
    if V35.exists() or (V34 / "STATIC_EXECUTION_LOCK.json").exists() or any(V34.rglob("ATTEMPT_MARKER.json")):
        raise SystemExit("governance authority ceiling violated")

    reserved = {"GOVERNANCE_ARTIFACT_MANIFEST.json", "GOVERNANCE_LOCK.json", "FINAL_FREEZE_VERIFICATION.json"}
    members = [
        {"path": path.name, "sha256": sha256(path), "bytes": path.stat().st_size}
        for path in sorted(
            (path for path in ROOT.iterdir() if path.is_file() and path.name not in reserved),
            key=lambda path: path.name.encode("utf-8"),
        )
    ]
    rows = "".join(f"{row['sha256']}  {row['path']}\n" for row in members)
    root_sha = hashlib.sha256(rows.encode("utf-8")).hexdigest()
    write_once(ROOT / "GOVERNANCE_ARTIFACT_MANIFEST.json", {
        "record_type": "GOVERNANCE_ARTIFACT_MANIFEST",
        "governance_identity": IDENTITY,
        "members": members,
        "member_count": len(members),
        "canonical_governance_root_sha256": root_sha,
        "status": "PASS",
    })
    lock = {
        "record_type": "V34_PRELOCK_RESULTS_DIRECTORY_AND_FIXTURE_PROBE_PATH_LIFECYCLE_DEFECT_ERRATUM_AND_V35_SUCCESSOR_DECISION_GOVERNANCE_LOCK",
        "governance_identity": IDENTITY,
        "status": "PASS_LOCKED_GOVERNANCE_ONLY",
        "canonical_governance_root_sha256": root_sha,
        "governance_artifact_manifest_sha256": sha256(ROOT / "GOVERNANCE_ARTIFACT_MANIFEST.json"),
        "PRELOCK_RESULTS_DIRECTORY_LIFECYCLE_DEFECT": "YES",
        "FIXTURE_PROBE_PARENT_DIRECTORY_PRECONDITION_DEFECT": "YES",
        "v34_disposition": "TERMINAL_IMMUTABLE_NO_RETRY",
        "v35_disposition": "CONDITIONALLY_AUTHORIZED_NOT_CREATED_NOT_EXECUTED",
        "attempt": "0/1",
        "worker_invocation": "0/1",
        "codex_as_worker_invocation": "0/1",
        "SECURITY_WORKER_RUNTIME": "NOT_ESTABLISHED",
        "TEMPORAL_OBSERVER_RUNTIME": "NOT_ESTABLISHED",
        "PROCESS_LINEAGE": "NOT_PROVEN",
        "PRODUCER_AUTHORIZATION": "NOT_PROVEN",
        "CONFINEMENT": "NOT_PROVEN",
        "next_legal_milestone": "IMPLEMENT_FRESH_V35_ONLY_UNDER_SEPARATE_EXPLICIT_ENGINEERING_REQUEST",
    }
    write_once(ROOT / "GOVERNANCE_LOCK.json", lock)
    write_once(ROOT / "FINAL_FREEZE_VERIFICATION.json", {
        "record_type": "FINAL_FREEZE_VERIFICATION",
        "manifest_sha256": sha256(ROOT / "GOVERNANCE_ARTIFACT_MANIFEST.json"),
        "governance_lock_sha256": sha256(ROOT / "GOVERNANCE_LOCK.json"),
        "member_count": len(members),
        "canonical_governance_root_sha256": root_sha,
        "v34_reverified": True,
        "v33_reverified": True,
        "v35_absent": True,
        "status": "PASS",
    })
    for path in ROOT.iterdir():
        if path.is_file():
            os.chmod(path, 0o444)
    os.chmod(ROOT, 0o555)
    print(f"GOVERNANCE_FREEZE=PASS ROOT={root_sha} LOCK_SHA256={sha256(ROOT / 'GOVERNANCE_LOCK.json')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
