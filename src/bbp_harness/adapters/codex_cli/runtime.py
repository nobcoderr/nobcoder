from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Mapping, Protocol


PROJECT_ROOT = Path(__file__).resolve().parents[4]
DEFAULT_LOCK_PATH = PROJECT_ROOT / "toolchain" / "codex.lock.json"


class RuntimePolicyError(RuntimeError):
    """The requested runtime action is not authorized by the frozen policy."""


@dataclass(frozen=True, slots=True)
class CodexWorkerRequest:
    selected_workspace: Path
    working_directory: Path
    schema_path: Path
    last_message_path: Path
    transcript_path: Path
    stderr_path: Path
    prompt: str
    sandbox: str
    timeout_seconds: int
    public_web_research: bool = False
    model: str | None = None
    skip_git_repo_check: bool = False
    environment: Mapping[str, str] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class CodexInvocationResult:
    exit_code: int
    argv: tuple[str, ...]
    error: str = ""
    process_started: bool = False


class WorkerRuntime(Protocol):
    def invoke(self, request: CodexWorkerRequest) -> CodexInvocationResult: ...


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


class CodexCliRuntime:
    """The sole Codex-specific argv, identity, and process boundary.

    An installed binary or matching hash is insufficient authority. Invocation
    additionally requires a PASS_LOCKED runtime lock and explicit local enablement.
    """

    def __init__(
        self,
        binary: str = "codex",
        *,
        lock_path: Path = DEFAULT_LOCK_PATH,
        execution_authorized: bool = False,
    ):
        self.binary = binary
        self.lock_path = lock_path.resolve()
        self.execution_authorized = execution_authorized

    def _load_lock(self) -> dict[str, object]:
        try:
            raw = json.loads(self.lock_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise RuntimePolicyError(f"runtime lock unavailable or invalid: {exc}") from exc
        if not isinstance(raw, dict) or raw.get("runtime") != "codex-cli":
            raise RuntimePolicyError("runtime lock is not a codex-cli lock")
        return raw

    def _resolved_binary(self) -> Path | None:
        candidate = shutil.which(self.binary)
        if candidate is None:
            explicit = Path(self.binary).expanduser()
            if explicit.is_file():
                candidate = str(explicit)
        return Path(candidate).resolve() if candidate else None

    def identity_report(self) -> dict[str, object]:
        try:
            lock = self._load_lock()
        except RuntimePolicyError as exc:
            return {
                "status": "FAIL_CLOSED",
                "identity_match": False,
                "invocation_authorized": False,
                "error": str(exc),
                "lock_path": str(self.lock_path),
            }

        binary_record = lock.get("binary")
        config_record = lock.get("configuration")
        package_record = lock.get("package_metadata")
        if not all(isinstance(item, dict) for item in (binary_record, config_record, package_record)):
            return {
                "status": "FAIL_CLOSED",
                "identity_match": False,
                "invocation_authorized": False,
                "error": "runtime lock is missing typed identity records",
                "lock_path": str(self.lock_path),
            }

        binary = self._resolved_binary()
        expected_binary = Path(str(binary_record["path"])).resolve()
        binary_exists = bool(binary and binary.is_file())
        binary_digest = _sha256(binary) if binary_exists and binary is not None else ""
        binary_path_match = bool(binary and binary == expected_binary)
        binary_digest_match = binary_digest == str(binary_record.get("sha256", ""))

        config_path = Path(str(config_record["path"])).resolve()
        config_digest = _sha256(config_path) if config_path.is_file() else ""
        config_digest_match = config_digest == str(config_record.get("sha256", ""))

        package_path = Path(str(package_record["path"])).resolve()
        package_digest = _sha256(package_path) if package_path.is_file() else ""
        package_digest_match = package_digest == str(package_record.get("sha256", ""))

        required_settings_ok = config_record.get("observed_required_setting_status") == "PASS"
        identity_match = all(
            (
                binary_exists,
                binary_path_match,
                binary_digest_match,
                config_digest_match,
                package_digest_match,
            )
        )
        compatibility_pass = lock.get("compatibility_state") == "PASS_LOCKED"
        lock_authorized = lock.get("runtime_invocation_authorized") is True
        invocation_authorized = all(
            (identity_match, required_settings_ok, compatibility_pass, lock_authorized, self.execution_authorized)
        )
        if not identity_match:
            status = "FAIL_CLOSED"
        elif invocation_authorized:
            status = "PASS_LOCKED_RUNTIME"
        else:
            status = "CANDIDATE_IDENTITY_MATCH_NOT_AUTHORIZED"
        return {
            "status": status,
            "runtime_identity": lock.get("identity", ""),
            "version": lock.get("version", ""),
            "lock_path": str(self.lock_path),
            "binary_path": str(binary) if binary else "",
            "binary_sha256": binary_digest,
            "binary_path_match": binary_path_match,
            "binary_digest_match": binary_digest_match,
            "config_sha256": config_digest,
            "config_digest_match": config_digest_match,
            "package_metadata_sha256": package_digest,
            "package_metadata_digest_match": package_digest_match,
            "required_settings_ok": required_settings_ok,
            "compatibility_state": lock.get("compatibility_state", "UNKNOWN"),
            "identity_match": identity_match,
            "lock_authorized": lock_authorized,
            "local_execution_authorized": self.execution_authorized,
            "invocation_authorized": invocation_authorized,
        }

    def build_argv(self, request: CodexWorkerRequest) -> tuple[str, ...]:
        if request.sandbox not in {"read-only", "workspace-write"}:
            raise RuntimePolicyError(f"unsupported Codex sandbox: {request.sandbox}")
        binary = self._resolved_binary()
        executable = str(binary) if binary else self.binary
        command = [
            executable,
            "-a",
            "never",
            "--enable",
            "skip_host_skill_discovery",
            "--disable",
            "plugins",
            "--add-dir",
            str(request.selected_workspace.resolve()),
        ]
        if request.public_web_research:
            command.append("--search")
        command.extend(
            [
                "exec",
                "--ignore-user-config",
                "--ephemeral",
                "--json",
                "--color",
                "never",
                "--output-schema",
                str(request.schema_path.resolve()),
                "--output-last-message",
                str(request.last_message_path.resolve()),
                "-s",
                request.sandbox,
                "-C",
                str(request.working_directory.resolve()),
            ]
        )
        if request.model:
            command.extend(["-m", request.model])
        if request.skip_git_repo_check:
            command.append("--skip-git-repo-check")
        command.append("-")
        return tuple(command)

    def invoke(self, request: CodexWorkerRequest) -> CodexInvocationResult:
        argv = self.build_argv(request)
        identity = self.identity_report()
        if identity.get("invocation_authorized") is not True:
            return CodexInvocationResult(
                exit_code=126,
                argv=argv,
                error=f"Codex runtime invocation denied: {identity.get('status', 'FAIL_CLOSED')}",
                process_started=False,
            )
        for output in (request.transcript_path, request.stderr_path, request.last_message_path):
            if output.exists() or output.is_symlink():
                return CodexInvocationResult(
                    exit_code=126,
                    argv=argv,
                    error=f"Codex runtime output collision: {output}",
                    process_started=False,
                )
        environment = dict(request.environment) if request.environment else os.environ.copy()
        try:
            with request.transcript_path.open("x", encoding="utf-8") as stdout_handle, request.stderr_path.open(
                "x", encoding="utf-8"
            ) as stderr_handle:
                completed = subprocess.run(
                    list(argv),
                    input=request.prompt,
                    text=True,
                    stdout=stdout_handle,
                    stderr=stderr_handle,
                    timeout=request.timeout_seconds,
                    check=False,
                    env=environment,
                )
            return CodexInvocationResult(
                exit_code=completed.returncode,
                argv=argv,
                process_started=True,
            )
        except subprocess.TimeoutExpired:
            return CodexInvocationResult(
                exit_code=124,
                argv=argv,
                error=f"worker timed out after {request.timeout_seconds}s",
                process_started=True,
            )
        except OSError as exc:
            return CodexInvocationResult(
                exit_code=127,
                argv=argv,
                error=f"failed to execute Codex: {exc}",
                process_started=False,
            )
