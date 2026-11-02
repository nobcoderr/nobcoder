"""Write-once transactional telemetry publication and completion-gated consumption."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any, Mapping

from workspace_boundary_v35 import authorize_write, guarded_open_binary


class TelemetryPublicationError(RuntimeError):
    """Raised when telemetry cannot be safely published without replacement."""


class TelemetryCompletionError(RuntimeError):
    """Raised before parsing when completion proof is missing or invalid."""


def completion_path(payload_path: Path) -> Path:
    return payload_path.with_name(payload_path.name + ".completion.json")


def unpublished_path(final_path: Path) -> Path:
    return final_path.with_name("." + final_path.name + ".unpublished")


def _canonical_json_bytes(payload: Mapping[str, Any]) -> bytes:
    return (json.dumps(dict(payload), sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode("utf-8")


def _fsync_directory(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _publish_no_replace(temp: Path, final: Path, *, operation_identity: str, generation: str) -> None:
    authorize_write(final, operation_identity=operation_identity, write_generation_identity=generation, expected_destination=final)
    if final.exists() or final.is_symlink():
        raise TelemetryPublicationError("DUPLICATE_PUBLICATION_FINAL_EXISTS")
    try:
        os.link(temp, final, follow_symlinks=False)
    except FileExistsError as exc:
        raise TelemetryPublicationError("DUPLICATE_PUBLICATION_RACE") from exc
    _fsync_directory(final.parent)
    os.unlink(temp)
    _fsync_directory(final.parent)


def publish_json_transactionally(
    final_path: Path,
    payload: Mapping[str, Any],
    *,
    producer_identity: str,
    fixture_identity: str,
    schema_identity: str,
    operation_identity: str,
    generation: str,
) -> dict[str, Any]:
    """Publish payload first and its exact completion proof last, without overwrite."""
    final_path = final_path.absolute()
    meta_path = completion_path(final_path)
    payload_temp = unpublished_path(final_path)
    meta_temp = unpublished_path(meta_path)
    for path in (final_path, meta_path, payload_temp, meta_temp):
        if path.exists() or path.is_symlink():
            raise TelemetryPublicationError(f"PUBLICATION_PATH_ALREADY_EXISTS:{path.name}")
    raw = _canonical_json_bytes(payload)
    digest = hashlib.sha256(raw).hexdigest()
    with guarded_open_binary(payload_temp, operation_identity=f"{operation_identity}:UNPUBLISHED_PAYLOAD", generation=generation) as handle:
        handle.write(raw)
        handle.flush()
        os.fsync(handle.fileno())
    if payload_temp.read_bytes() != raw:
        raise TelemetryPublicationError("UNPUBLISHED_PAYLOAD_REREAD_MISMATCH")
    _publish_no_replace(payload_temp, final_path, operation_identity=f"{operation_identity}:ATOMIC_PAYLOAD_PUBLISH", generation=generation)
    completion = {
        "record_type": "V35_TRANSACTIONAL_TELEMETRY_COMPLETION",
        "publication_state": "COMPLETED_ATOMICALLY_PUBLISHED",
        "producer_identity": producer_identity,
        "fixture_identity": fixture_identity,
        "schema_identity": schema_identity,
        "artifact_name": final_path.name,
        "artifact_sha256": digest,
        "artifact_size": len(raw),
        "write_generation_identity": generation,
        "consumer_rule": "COMPLETION_PROOF_REQUIRED_BEFORE_PARSE",
    }
    meta_raw = _canonical_json_bytes(completion)
    with guarded_open_binary(meta_temp, operation_identity=f"{operation_identity}:UNPUBLISHED_COMPLETION", generation=generation) as handle:
        handle.write(meta_raw)
        handle.flush()
        os.fsync(handle.fileno())
    if meta_temp.read_bytes() != meta_raw:
        raise TelemetryPublicationError("UNPUBLISHED_COMPLETION_REREAD_MISMATCH")
    _publish_no_replace(meta_temp, meta_path, operation_identity=f"{operation_identity}:ATOMIC_COMPLETION_PUBLISH", generation=generation)
    return completion


def consume_completed_json(
    final_path: Path,
    *,
    expected_producer_identity: str,
    expected_fixture_identity: str,
    expected_schema_identity: str,
) -> dict[str, Any]:
    """Validate completion proof and exact bytes before the only JSON parse."""
    meta_path = completion_path(final_path)
    if not meta_path.is_file() or meta_path.is_symlink():
        raise TelemetryCompletionError("COMPLETION_METADATA_MISSING_OR_UNSAFE")
    try:
        completion = json.loads(meta_path.read_bytes())
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise TelemetryCompletionError("COMPLETION_METADATA_MALFORMED") from exc
    exact = {
        "record_type": completion.get("record_type") == "V35_TRANSACTIONAL_TELEMETRY_COMPLETION",
        "publication_state": completion.get("publication_state") == "COMPLETED_ATOMICALLY_PUBLISHED",
        "producer_identity": completion.get("producer_identity") == expected_producer_identity,
        "fixture_identity": completion.get("fixture_identity") == expected_fixture_identity,
        "schema_identity": completion.get("schema_identity") == expected_schema_identity,
        "artifact_name": completion.get("artifact_name") == final_path.name,
    }
    if not all(exact.values()):
        raise TelemetryCompletionError("COMPLETION_METADATA_IDENTITY_MISMATCH")
    if not final_path.is_file() or final_path.is_symlink():
        raise TelemetryCompletionError("COMPLETED_ARTIFACT_MISSING_OR_UNSAFE")
    raw = final_path.read_bytes()
    if len(raw) != completion.get("artifact_size"):
        raise TelemetryCompletionError("COMPLETED_ARTIFACT_SIZE_MISMATCH")
    if hashlib.sha256(raw).hexdigest() != completion.get("artifact_sha256"):
        raise TelemetryCompletionError("COMPLETED_ARTIFACT_DIGEST_MISMATCH")
    try:
        payload = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise TelemetryCompletionError("COMPLETED_ARTIFACT_MALFORMED_JSON") from exc
    if not isinstance(payload, dict):
        raise TelemetryCompletionError("COMPLETED_ARTIFACT_SCHEMA_NOT_OBJECT")
    return payload


def failure_envelope_verdict(payload: Mapping[str, Any]) -> dict[str, Any]:
    required = {
        "fixture_identity", "observer_exit_code", "failure_stage", "failure_reason",
        "classification", "telemetry_complete", "raw_output_sha256",
        "raw_output_bytes", "available_counters",
    }
    classifications = {
        "OBSERVER_EXECUTION_FAILURE", "TELEMETRY_PUBLICATION_FAILURE",
        "TELEMETRY_SERIALIZATION_FAILURE", "TELEMETRY_PARSER_FAILURE",
    }
    errors: list[str] = []
    if not required.issubset(payload):
        errors.append("FAILURE_ENVELOPE_FIELD_MISSING")
    if payload.get("classification") not in classifications:
        errors.append("FAILURE_CLASSIFICATION_INVALID")
    if not isinstance(payload.get("available_counters"), dict):
        errors.append("AVAILABLE_COUNTERS_INVALID")
    digest = payload.get("raw_output_sha256")
    if not isinstance(digest, str) or len(digest) != 64:
        errors.append("RAW_OUTPUT_DIGEST_INVALID")
    return {"status": "PASS" if not errors else "FAIL_CLOSED", "errors": errors}


def completion_fixture_verdict(
    *, completion_present: bool, completion_state: str | None, producer_matches: bool,
    fixture_matches: bool, digest_matches: bool, size_matches: bool, schema_matches: bool,
) -> dict[str, Any]:
    checks = {
        "completion_present": completion_present,
        "completion_state": completion_state == "COMPLETED_ATOMICALLY_PUBLISHED",
        "producer_matches": producer_matches,
        "fixture_matches": fixture_matches,
        "digest_matches": digest_matches,
        "size_matches": size_matches,
        "schema_matches": schema_matches,
    }
    return {"status": "PASS" if all(checks.values()) else "FAIL_CLOSED", "checks": checks}
