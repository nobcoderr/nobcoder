"""Fail-before-write workspace identity boundary for every V35 artifact producer."""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, BinaryIO, TextIO

EXECUTION_IDENTITY = "V0_3_FIRST_REAL_SECURITY_WORKER_INVOCATION_V35"
WORKSPACE = Path("/home/nobcoder/v0.3-first-real-security-worker-invocation-v35-20261103")
PREDECESSOR_DENY_WRITE_ROOTS = tuple(
    Path(f"/home/nobcoder/v0.3-first-real-security-worker-invocation-v{version}-20261020")
    for version in range(1, 14)
) + (
    Path("/home/nobcoder/v0.3-first-real-security-worker-invocation-v12-20261023"),
    Path("/home/nobcoder/v0.3-first-real-security-worker-invocation-v13-20261023"),
    Path("/home/nobcoder/v0.3-first-real-security-worker-invocation-v14-20261023"),
    Path("/home/nobcoder/v0.3-first-real-security-worker-invocation-v15-20261023"),
    Path("/home/nobcoder/v0.3-first-real-security-worker-invocation-v16-20261023"),
    Path("/home/nobcoder/v0.3-first-real-security-worker-invocation-v17-20261023"),
    Path("/home/nobcoder/v0.3-first-real-security-worker-invocation-v18-20261023"),
    Path("/home/nobcoder/v0.3-first-real-security-worker-invocation-v19-20261025"),
    Path("/home/nobcoder/v0.3-first-real-security-worker-invocation-v20-20261101"),
    Path("/home/nobcoder/v0.3-first-real-security-worker-invocation-v21-20261101"),
    Path("/home/nobcoder/v0.3-first-real-security-worker-invocation-v22-20261101"),
    Path("/home/nobcoder/v0.3-first-real-security-worker-invocation-v23-20261101"),
    Path("/home/nobcoder/v0.3-first-real-security-worker-invocation-v24-20261101"),
    Path("/home/nobcoder/v0.3-first-real-security-worker-invocation-v25-20261101"),
    Path("/home/nobcoder/v0.3-first-real-security-worker-invocation-v26-20261102"),
    Path("/home/nobcoder/v0.3-first-real-security-worker-invocation-v27-20261102"),
    Path("/home/nobcoder/v0.3-first-real-security-worker-invocation-v28-20261102"),
    Path("/home/nobcoder/v0.3-first-real-security-worker-invocation-v29-20261102"),
    Path("/home/nobcoder/v0.3-first-real-security-worker-invocation-v30-20261102"),
    Path("/home/nobcoder/v0.3-first-real-security-worker-invocation-v31-20261102"),
    Path("/home/nobcoder/v0.3-first-real-security-worker-invocation-v32-20261102"),
    Path("/home/nobcoder/v0.3-first-real-security-worker-invocation-v33-20261103"),
    Path("/home/nobcoder/v0.3-first-real-security-worker-invocation-v34-20261103"),
    Path("/home/nobcoder/v12-validation/v12-frozen-20260828-132245"),
)


class WorkspaceBoundaryError(RuntimeError):
    """Raised before mutation when invocation, workspace, or destination differs."""


def _inside(candidate: Path, root: Path) -> bool:
    try:
        candidate.relative_to(root)
        return True
    except ValueError:
        return False


def _resolve_nonexistent_leaf(path: Path) -> Path:
    """Resolve every existing/symlinked ancestor and retain absent suffix bytes."""
    missing: list[str] = []
    cursor = path
    while not cursor.exists() and not cursor.is_symlink():
        if cursor == cursor.parent:
            raise WorkspaceBoundaryError("DESTINATION_HAS_NO_RESOLVABLE_ANCESTOR")
        missing.append(cursor.name)
        cursor = cursor.parent
    resolved = cursor.resolve(strict=True)
    for component in reversed(missing):
        resolved = resolved / component
    return resolved


def _validate_common(
    *,
    invocation_identity: str | None,
    workspace_root: Path | None,
    destination: Path,
    operation_identity: str | None,
    write_generation_identity: str | None,
) -> tuple[Path, Path]:
    if invocation_identity != EXECUTION_IDENTITY:
        raise WorkspaceBoundaryError("INVOCATION_IDENTITY_MISMATCH_OR_UNRESOLVED")
    if workspace_root is None:
        raise WorkspaceBoundaryError("WORKSPACE_IDENTITY_UNRESOLVED")
    expected_root = WORKSPACE.resolve(strict=True)
    supplied_root = workspace_root.resolve(strict=True)
    if supplied_root != expected_root:
        raise WorkspaceBoundaryError("CANONICAL_WORKSPACE_ROOT_MISMATCH")
    if not destination.is_absolute():
        raise WorkspaceBoundaryError("ABSOLUTE_DESTINATION_REQUIRED")
    if ".." in destination.parts:
        raise WorkspaceBoundaryError("RELATIVE_PATH_TRAVERSAL_PROHIBITED")
    if not operation_identity or not operation_identity.strip():
        raise WorkspaceBoundaryError("OPERATION_IDENTITY_REQUIRED")
    if not write_generation_identity or not write_generation_identity.strip():
        raise WorkspaceBoundaryError("WRITE_GENERATION_IDENTITY_REQUIRED")
    return expected_root, _resolve_nonexistent_leaf(destination)


def authorize_write(
    destination: Path,
    *,
    operation_identity: str,
    write_generation_identity: str,
    invocation_identity: str | None = EXECUTION_IDENTITY,
    workspace_root: Path | None = WORKSPACE,
    expected_destination: Path | None = None,
) -> dict[str, str]:
    """Authorize one exact canonical V35 destination without mutating anything."""
    expected_root, resolved = _validate_common(
        invocation_identity=invocation_identity,
        workspace_root=workspace_root,
        destination=destination,
        operation_identity=operation_identity,
        write_generation_identity=write_generation_identity,
    )
    if not _inside(resolved, expected_root) or resolved == expected_root:
        raise WorkspaceBoundaryError("DESTINATION_OUTSIDE_EXACT_V35_WORKSPACE")
    for root in PREDECESSOR_DENY_WRITE_ROOTS:
        if not root.exists():
            continue
        denied = root.resolve(strict=True)
        if _inside(resolved, denied) or resolved == denied:
            raise WorkspaceBoundaryError("DESTINATION_INSIDE_PREDECESSOR_DENY_WRITE_ROOT")
    if expected_destination is None:
        raise WorkspaceBoundaryError("EXPECTED_CANONICAL_OUTPUT_PATH_REQUIRED")
    expected = _resolve_nonexistent_leaf(expected_destination)
    if resolved != expected:
        raise WorkspaceBoundaryError("CANONICAL_OUTPUT_PATH_MISMATCH")
    return {
        "status": "PASS_FAIL_BEFORE_WRITE_BOUNDARY",
        "execution_identity": EXECUTION_IDENTITY,
        "canonical_workspace_root": str(expected_root),
        "canonical_destination": str(resolved),
        "operation_identity": operation_identity,
        "write_generation_identity": write_generation_identity,
    }


def authorize_read(
    source: Path,
    *,
    operation_identity: str,
    invocation_identity: str | None = EXECUTION_IDENTITY,
    workspace_root: Path | None = WORKSPACE,
) -> Path:
    """Allow an explicitly identified read, including an immutable predecessor read."""
    _, resolved = _validate_common(
        invocation_identity=invocation_identity,
        workspace_root=workspace_root,
        destination=source,
        operation_identity=operation_identity,
        write_generation_identity="READ_ONLY_NO_WRITE_GENERATION",
    )
    if not resolved.exists() or not resolved.is_file() or resolved.is_symlink():
        raise WorkspaceBoundaryError("READ_SOURCE_NOT_SAFE_REGULAR")
    return resolved


def guard_output_root(path: Path, *, operation_identity: str, generation: str) -> dict[str, str]:
    """Bind a directory used by a child artifact producer before that child starts."""
    marker = path / ".workspace-boundary-probe"
    return authorize_write(
        marker,
        operation_identity=operation_identity,
        write_generation_identity=generation,
        expected_destination=marker,
    )


def guarded_mkdir(path: Path, *, operation_identity: str, generation: str, mode: int = 0o700) -> None:
    authorize_write(path, operation_identity=operation_identity, write_generation_identity=generation, expected_destination=path)
    path.mkdir(mode=mode, parents=True, exist_ok=False)


def guarded_mkdir_exact_leaf(path: Path, *, operation_identity: str, generation: str, mode: int = 0o700) -> None:
    """Create one exact absent leaf with a single exclusive mkdir syscall."""
    authorize_write(path, operation_identity=operation_identity, write_generation_identity=generation, expected_destination=path)
    if not path.parent.is_dir() or path.parent.is_symlink():
        raise WorkspaceBoundaryError("OUTPUT_PARENT_MUST_PREEXIST_AS_REAL_DIRECTORY")
    os.mkdir(path, mode=mode)


def guarded_open_text(path: Path, *, operation_identity: str, generation: str) -> TextIO:
    authorize_write(path, operation_identity=operation_identity, write_generation_identity=generation, expected_destination=path)
    if not path.parent.is_dir() or path.parent.is_symlink():
        raise WorkspaceBoundaryError("OUTPUT_PARENT_MUST_PREEXIST_AS_REAL_DIRECTORY")
    return path.open("x", encoding="utf-8", newline="\n")


def guarded_open_binary(path: Path, *, operation_identity: str, generation: str) -> BinaryIO:
    authorize_write(path, operation_identity=operation_identity, write_generation_identity=generation, expected_destination=path)
    if not path.parent.is_dir() or path.parent.is_symlink():
        raise WorkspaceBoundaryError("OUTPUT_PARENT_MUST_PREEXIST_AS_REAL_DIRECTORY")
    return path.open("xb")


def guarded_json_once(
    path: Path,
    payload: Any,
    *,
    operation_identity: str,
    generation: str,
) -> None:
    with guarded_open_text(path, operation_identity=operation_identity, generation=generation) as handle:
        json.dump(payload, handle, indent=2, sort_keys=True)
        handle.write("\n")


def guarded_append_jsonl(
    path: Path,
    payload: Any,
    *,
    operation_identity: str,
    generation: str,
) -> None:
    authorize_write(path, operation_identity=operation_identity, write_generation_identity=generation, expected_destination=path)
    if not path.parent.is_dir() or path.parent.is_symlink():
        raise WorkspaceBoundaryError("OUTPUT_PARENT_MUST_PREEXIST_AS_REAL_DIRECTORY")
    flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_CLOEXEC
    fd = os.open(path, flags, 0o600)
    try:
        os.write(fd, (json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n").encode())
        os.fsync(fd)
    finally:
        os.close(fd)


def guarded_chmod(path: Path, mode: int, *, operation_identity: str, generation: str) -> None:
    if path.resolve(strict=True) == WORKSPACE.resolve(strict=True):
        guard_output_root(path, operation_identity=operation_identity, generation=generation)
    else:
        authorize_write(path, operation_identity=operation_identity, write_generation_identity=generation, expected_destination=path)
    os.chmod(path, mode)

