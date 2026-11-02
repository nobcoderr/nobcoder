"""Bind the final immutable prompt bytes into WorkerRequest exactly once."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import stat
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent
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
_resolver.load_canonical_modules("BUILDER", ("workspace_boundary_v35",))
from workspace_boundary_v35 import authorize_write, guarded_chmod, guarded_json_once  # noqa: E402
PROMPT = ROOT / "fixture/worker-prompt.txt"
REQUEST = ROOT / "contracts/WORKER_REQUEST.json"
BINDING = ROOT / "contracts/PROMPT_IDENTITY_BINDING.json"
EXECUTION_IDENTITY = "V0_3_FIRST_REAL_SECURITY_WORKER_INVOCATION_V35"
GENERATION_IDENTITY = "V35_CURRENT_GOVERNANCE_BOUND_TYPED_PREFLIGHT_BINDING_GENERATION_0001"
GOVERNANCE_IDENTITY = (
    "V0_3_FIRST_REAL_SECURITY_WORKER_INVOCATION_V34_PRELOCK_RESULTS_DIRECTORY_AND_"
    "FIXTURE_PROBE_PATH_LIFECYCLE_DEFECT_UNIT_EXECUTION_ERRATUM_AND_SUCCESSOR_DECISION_"
    "GOVERNANCE_ONLY"
)
GOVERNANCE_DIGEST = "d2263268f61b9ddde99a0b60f4b43a26df1586e0c577ba2ca98c07b64c21f811"
UNBOUND = "UNBOUND_FINAL_PROMPT_SHA256"
UNBOUND_FIXTURE = "UNBOUND_FINAL_FIXTURE_SHA256"


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def safe_regular(path: Path) -> bool:
    try:
        info = path.lstat()
    except FileNotFoundError:
        return False
    return stat.S_ISREG(info.st_mode) and not stat.S_ISLNK(info.st_mode)


def canonical_json_bytes(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")


def main() -> int:
    if BINDING.exists() or BINDING.is_symlink():
        raise RuntimeError("prompt identity already bound")
    if not safe_regular(PROMPT) or not safe_regular(REQUEST):
        raise RuntimeError("prompt or request is missing, symlinked, or non-regular")
    if PROMPT.resolve(strict=True) != PROMPT or REQUEST.resolve(strict=True) != REQUEST:
        raise RuntimeError("prompt or request canonical path mismatch")

    final_prompt_bytes = PROMPT.read_bytes()
    first_digest = sha256_bytes(final_prompt_bytes)
    request = json.loads(REQUEST.read_text(encoding="utf-8"))
    if request.get("prompt", {}).get("sha256") != UNBOUND:
        raise RuntimeError("WorkerRequest is not in the exact unbound state")
    if request.get("prompt", {}).get("path") != "fixture/worker-prompt.txt":
        raise RuntimeError("WorkerRequest prompt path mismatch")
    if request.get("authorization_id") != (
        GOVERNANCE_IDENTITY
    ):
        raise RuntimeError("WorkerRequest authorization mismatch")

    request["prompt"]["sha256"] = first_digest
    output_schema = ROOT / request["output_schema"]["path"]
    if not safe_regular(output_schema):
        raise RuntimeError("output schema is missing, symlinked, or non-regular")
    if request["output_schema"].get("sha256") != "UNBOUND_FINAL_OUTPUT_SCHEMA_SHA256":
        raise RuntimeError("WorkerRequest output schema is not in the exact unbound state")
    request["output_schema"]["sha256"] = sha256_bytes(output_schema.read_bytes())
    fixture = ROOT / request["fixture"]["path"]
    if not safe_regular(fixture):
        raise RuntimeError("fixture is missing, symlinked, or non-regular")
    if request["fixture"].get("sha256") != UNBOUND_FIXTURE:
        raise RuntimeError("WorkerRequest fixture is not in the exact unbound state")
    request["fixture"]["sha256"] = sha256_bytes(fixture.read_bytes())
    request_bytes = canonical_json_bytes(request)
    temporary = REQUEST.with_name(".WORKER_REQUEST.json.prompt-bind.tmp")
    if temporary.exists() or temporary.is_symlink():
        raise RuntimeError("unexpected prompt-binding temporary file")
    authorize_write(temporary, operation_identity="BIND_FINAL_PROMPT_TEMPORARY", write_generation_identity="PROMPT_BIND_V35", expected_destination=temporary)
    authorize_write(REQUEST, operation_identity="BIND_FINAL_PROMPT_REQUEST_REPLACE", write_generation_identity="PROMPT_BIND_V35", expected_destination=REQUEST)
    with temporary.open("xb") as handle:
        handle.write(request_bytes)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, REQUEST)

    reread_prompt_bytes = PROMPT.read_bytes()
    reread_digest = sha256_bytes(reread_prompt_bytes)
    bound_request = json.loads(REQUEST.read_text(encoding="utf-8"))
    bound_digest = bound_request.get("prompt", {}).get("sha256")
    if not (first_digest == reread_digest == bound_digest):
        raise RuntimeError("prompt identity mismatch after bind")

    request_digest = sha256_bytes(REQUEST.read_bytes())
    binding = {
        "record_type": "FIRST_REAL_SECURITY_WORKER_PROMPT_IDENTITY_BINDING",
        "schema_version": "1.0",
        "execution_identity": EXECUTION_IDENTITY,
        "generation_identity": GENERATION_IDENTITY,
        "governance_identity": GOVERNANCE_IDENTITY,
        "governance_digest": GOVERNANCE_DIGEST,
        "status": "PASS_FINAL_PROMPT_BOUND_REREAD_REHASHED",
        "binding_order": [
            "FINALIZE_PROMPT_BYTES",
            "REJECT_SYMLINK_OR_NON_REGULAR_PROMPT",
            "COMPUTE_SHA256_FROM_FINAL_PROMPT_BYTES",
            "BIND_COMPUTED_DIGEST_INTO_WORKER_REQUEST",
            "REREAD_PROMPT_FROM_BOUND_CANONICAL_PATH",
            "REHASH_REREAD_BYTES",
            "COMPARE_ACTUAL_BOUND_AND_REREAD_DIGESTS",
            "APPLY_EXACT_IMMUTABLE_MODE_0444",
            "VERIFY_EXACT_IMMUTABLE_MODE_0444",
            "FREEZE_REQUEST_AND_BINDING_RECORD_READ_ONLY",
            "ONLY_THEN_ALLOW_VALIDATION_TO_PASS"
        ],
        "prompt_path": "fixture/worker-prompt.txt",
        "prompt_canonical_path": str(PROMPT),
        "prompt_byte_length": len(final_prompt_bytes),
        "first_prompt_sha256": first_digest,
        "worker_request_bound_prompt_sha256": bound_digest,
        "reread_prompt_sha256": reread_digest,
        "worker_request_sha256": request_digest,
        "all_prompt_digests_equal": True,
        "digest_source": "FINAL_PROMPT_BYTES_COMPUTED_NOT_HAND_ENTERED",
        "post_bind_prompt_mutation": "PROHIBITED",
        "required_mode": "0444",
        "attempt_count": 0,
        "worker_invocation_count": 0,
        "codex_as_worker_invocation_count": 0
    }
    guarded_chmod(PROMPT, 0o444, operation_identity="FREEZE_FINAL_PROMPT", generation="PROMPT_BIND_V35")
    if stat.S_IMODE(PROMPT.stat().st_mode) != 0o444:
        raise RuntimeError("FINAL_PROMPT_MODE_NOT_0444")
    binding["verified_mode"] = 0o444
    guarded_json_once(BINDING, binding, operation_identity="BIND_FINAL_PROMPT_EVIDENCE", generation="PROMPT_BIND_V35")
    guarded_chmod(REQUEST, 0o444, operation_identity="FREEZE_WORKER_REQUEST", generation="PROMPT_BIND_V35")
    guarded_chmod(BINDING, 0o444, operation_identity="FREEZE_PROMPT_BINDING", generation="PROMPT_BIND_V35")
    print(json.dumps({
        "status": binding["status"],
        "prompt_sha256": first_digest,
        "worker_request_sha256": request_digest,
        "attempt_count": 0,
        "worker_invocation_count": 0,
        "codex_as_worker_invocation_count": 0
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
