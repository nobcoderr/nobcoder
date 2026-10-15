from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from bbp_harness.adapters.codex_cli import CodexCliRuntime, CodexWorkerRequest


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class CodexCliAdapterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.binary = self.root / "codex"
        self.binary.write_bytes(b"fixture-codex-binary")
        self.binary.chmod(0o755)
        self.config = self.root / "config.toml"
        self.config.write_text("check_for_update_on_startup = false\n", encoding="utf-8")
        self.package = self.root / "codex-package.json"
        self.package.write_text('{"version":"fixture"}\n', encoding="utf-8")
        self.lock = self.root / "codex.lock.json"
        self.lock.write_text(
            json.dumps(
                {
                    "runtime": "codex-cli",
                    "identity": "FIXTURE_CODEX_RUNTIME",
                    "version": "fixture",
                    "binary": {"path": str(self.binary), "sha256": digest(self.binary)},
                    "configuration": {
                        "path": str(self.config),
                        "sha256": digest(self.config),
                        "observed_required_setting_status": "PASS",
                    },
                    "package_metadata": {"path": str(self.package), "sha256": digest(self.package)},
                    "compatibility_state": "PASS_LOCKED",
                    "runtime_invocation_authorized": False,
                },
                sort_keys=True,
            ),
            encoding="utf-8",
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def request(self) -> CodexWorkerRequest:
        workspace = self.root / "workspace"
        workspace.mkdir(exist_ok=True)
        schema = self.root / "schema.json"
        schema.write_text("{}\n", encoding="utf-8")
        return CodexWorkerRequest(
            selected_workspace=workspace,
            working_directory=workspace,
            schema_path=schema,
            last_message_path=self.root / "last-message.json",
            transcript_path=self.root / "events.jsonl",
            stderr_path=self.root / "stderr.txt",
            prompt="fixture only",
            sandbox="read-only",
            timeout_seconds=10,
            skip_git_repo_check=True,
            environment={"PATH": "/usr/bin"},
        )

    def test_identity_match_does_not_authorize_runtime(self) -> None:
        runtime = CodexCliRuntime(str(self.binary), lock_path=self.lock, execution_authorized=False)
        report = runtime.identity_report()
        self.assertTrue(report["identity_match"])
        self.assertEqual(report["status"], "CANDIDATE_IDENTITY_MATCH_NOT_AUTHORIZED")
        self.assertFalse(report["invocation_authorized"])

    def test_exact_argv_is_built_only_by_adapter(self) -> None:
        runtime = CodexCliRuntime(str(self.binary), lock_path=self.lock)
        argv = runtime.build_argv(self.request())
        self.assertEqual(argv[0], str(self.binary))
        self.assertEqual(argv[1:3], ("-a", "never"))
        self.assertIn("--ignore-user-config", argv)
        self.assertIn("--ephemeral", argv)
        self.assertEqual(argv[-2:], ("--skip-git-repo-check", "-"))

    def test_denied_invocation_never_starts_process_or_writes_outputs(self) -> None:
        runtime = CodexCliRuntime(str(self.binary), lock_path=self.lock, execution_authorized=False)
        request = self.request()
        result = runtime.invoke(request)
        self.assertEqual(result.exit_code, 126)
        self.assertFalse(result.process_started)
        self.assertIn("denied", result.error)
        self.assertFalse(request.transcript_path.exists())
        self.assertFalse(request.stderr_path.exists())
        self.assertFalse(request.last_message_path.exists())

    def test_binary_drift_fails_closed(self) -> None:
        self.binary.write_bytes(b"mutated")
        runtime = CodexCliRuntime(str(self.binary), lock_path=self.lock)
        report = runtime.identity_report()
        self.assertEqual(report["status"], "FAIL_CLOSED")
        self.assertFalse(report["binary_digest_match"])


if __name__ == "__main__":
    unittest.main()
