#!/usr/bin/env python3
"""Read-only final verifier for the frozen V34 governance package."""

import hashlib
import stat

from governance_common import ROOT, V34, V35, load, sha256, verify_v33_frozen, verify_v34_frozen


def main() -> int:
    manifest = load(ROOT / "GOVERNANCE_ARTIFACT_MANIFEST.json")
    lock = load(ROOT / "GOVERNANCE_LOCK.json")
    final = load(ROOT / "FINAL_FREEZE_VERIFICATION.json")
    rows = "".join(f"{row['sha256']}  {row['path']}\n" for row in manifest["members"])
    root_sha = hashlib.sha256(rows.encode("utf-8")).hexdigest()
    exact = all(
        (ROOT / row["path"]).is_file()
        and not (ROOT / row["path"]).is_symlink()
        and sha256(ROOT / row["path"]) == row["sha256"]
        and (ROOT / row["path"]).stat().st_size == row["bytes"]
        and stat.S_IMODE((ROOT / row["path"]).stat().st_mode) == 0o444
        for row in manifest["members"]
    )
    checks = {
        "F001_ROOT": root_sha == manifest["canonical_governance_root_sha256"] == lock["canonical_governance_root_sha256"] == final["canonical_governance_root_sha256"],
        "F002_MANIFEST": sha256(ROOT / "GOVERNANCE_ARTIFACT_MANIFEST.json") == lock["governance_artifact_manifest_sha256"] == final["manifest_sha256"],
        "F003_LOCK": sha256(ROOT / "GOVERNANCE_LOCK.json") == final["governance_lock_sha256"],
        "F004_MEMBERS": exact and len(manifest["members"]) == manifest["member_count"] == final["member_count"],
        "F005_READ_ONLY": stat.S_IMODE(ROOT.stat().st_mode) == 0o555 and all(stat.S_IMODE(path.stat().st_mode) == 0o444 for path in ROOT.iterdir() if path.is_file()),
        "F006_PRELOCK_DEFECT": lock["PRELOCK_RESULTS_DIRECTORY_LIFECYCLE_DEFECT"] == "YES",
        "F007_PROBE_DEFECT": lock["FIXTURE_PROBE_PARENT_DIRECTORY_PRECONDITION_DEFECT"] == "YES",
        "F008_DECISION": lock["v34_disposition"] == "TERMINAL_IMMUTABLE_NO_RETRY" and lock["v35_disposition"] == "CONDITIONALLY_AUTHORIZED_NOT_CREATED_NOT_EXECUTED",
        "F009_RUNTIME_NOT_ESTABLISHED": lock["SECURITY_WORKER_RUNTIME"] == lock["TEMPORAL_OBSERVER_RUNTIME"] == "NOT_ESTABLISHED",
        "F010_PROOFS_NOT_PROVEN": lock["PROCESS_LINEAGE"] == lock["PRODUCER_AUTHORIZATION"] == lock["CONFINEMENT"] == "NOT_PROVEN",
        "F011_V34_FROZEN": verify_v34_frozen()["status"] == "PASS",
        "F012_V33_FROZEN": verify_v33_frozen()["status"] == "PASS",
        "F013_NO_V34_EXECUTION": not (V34 / "STATIC_EXECUTION_LOCK.json").exists() and not any(V34.rglob("ATTEMPT_MARKER.json")) and not any(V34.rglob("runtime-result-0001.json")),
        "F014_V35_ABSENT": not V35.exists(),
        "F015_FINAL": final["status"] == "PASS",
    }
    passed = sum(checks.values())
    status = "PASS" if all(checks.values()) else "FAIL_CLOSED"
    print(f"FINAL_FREEZE_VERIFICATION={passed}/{len(checks)} {status}")
    print(f"GOVERNANCE_ROOT_SHA256={root_sha}")
    print(f"GOVERNANCE_LOCK_SHA256={sha256(ROOT / 'GOVERNANCE_LOCK.json')}")
    return 0 if status == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
