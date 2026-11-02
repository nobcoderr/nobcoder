"""Typed current Codex runtime authority for every V35 readiness component."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Mapping


WORKSPACE = Path("/home/nobcoder/v0.3-first-real-security-worker-invocation-v35-20261103")
EXECUTION_IDENTITY = "V0_3_FIRST_REAL_SECURITY_WORKER_INVOCATION_V35"
GENERATION_IDENTITY = "V35_CURRENT_GOVERNANCE_BOUND_TYPED_PREFLIGHT_BINDING_GENERATION_0001"
CONTRACT = WORKSPACE / "contracts/TYPED_CODEX_RUNTIME_ACCEPTANCE_BINDING_CONTRACT.json"
BINDING = WORKSPACE / "contracts/V35_CODEX_0_166_0_RUNTIME_BINDING.json"
ACCEPTANCE_LOCK = Path("/home/nobcoder/codex-security-harness-eval/governance/v0.3-runtime-and-model-compatibility-execution-v8-codex-0-166-0-frozen-evidence-acceptance-and-pass-locked-decision-governance-v1-20261102/GOVERNANCE_LOCK.json")
SUCCESSOR_LOCK = Path("/home/nobcoder/codex-security-harness-eval/governance/v0.3-first-real-security-worker-invocation-v34-prelock-results-directory-and-fixture-probe-path-lifecycle-defect-unit-execution-erratum-and-successor-decision-governance-only-v1-20261103/GOVERNANCE_LOCK.json")
CODEX_BINARY = Path("/home/nobcoder/.codex/packages/standalone/releases/0.166.0-x86_64-unknown-linux-musl/bin/codex")
CODEX_PACKAGE = CODEX_BINARY.parent.parent / "codex-package.json"
CODEX_CONFIG = WORKSPACE / "runtime-config-candidate/config.toml"
CURRENT_FIELD = "codex_runtime_0_166_0"
HISTORICAL_FIELD = "codex_runtime_0_163_0"
RUNTIME_IDENTITY = "CODEX_RUNTIME_0_166_0_COMPATIBILITY_PASS_LOCKED"
EXPECTED_BINARY_SHA256 = "b8a11fedf24b2dfb59a70c9e52b030f9a508dcd49cd2dd0d41956f4c785156b8"
EXPECTED_PACKAGE_SHA256 = "ffdfc731eed492fa436a304cff8792ea3a96233a45ec9a561f6f56eaca911446"
EXPECTED_CONFIG_SHA256 = "7ae835188ef2ab3221e15effac45375b2d6112954d022aa7776f802f7b8697c0"
EXPECTED_ACCEPTANCE_LOCK_SHA256 = "060b39551d4543999e79ccfd5d133d751faefc018fdc8adab718f5b9c7479a5e"
EXPECTED_SUCCESSOR_LOCK_SHA256 = "d2263268f61b9ddde99a0b60f4b43a26df1586e0c577ba2ca98c07b64c21f811"
ALLOWED_COMPONENTS = frozenset({"BUILDER", "UNIT", "PRIMARY_VALIDATOR", "INDEPENDENT_VALIDATOR", "FRESH_PREFLIGHT", "DEPENDENCY_CLOSURE", "STATIC_LOCK_PREPARATION", "STATIC_LOCK_VERIFICATION", "LOCKED_RUNTIME", "POST_VALIDATOR"})


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _load(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"JSON object required: {path}")
    return value


def runtime_acceptance_fixture_verdict(candidate: Mapping[str, Any]) -> dict[str, Any]:
    checks = {
        "worker_identity": candidate.get("worker_identity") == EXECUTION_IDENTITY,
        "generation": candidate.get("binding_generation_identity") == GENERATION_IDENTITY,
        "logical_identity": candidate.get("runtime_logical_identity") == RUNTIME_IDENTITY,
        "version": candidate.get("runtime_version") == "0.166.0",
        "current_field": candidate.get("current_authority_field") == CURRENT_FIELD,
        "current_state": candidate.get("current_authority_state") == "COMPATIBILITY_PASS_LOCKED",
        "historical_not_current": candidate.get("historical_field") == HISTORICAL_FIELD and candidate.get("historical_field_role") == "HISTORY_ONLY_NOT_CURRENT_WORKER_AUTHORITY",
        "binary": candidate.get("binary_sha256") == EXPECTED_BINARY_SHA256,
        "package": candidate.get("package_sha256") == EXPECTED_PACKAGE_SHA256,
        "config": candidate.get("dedicated_config_sha256") == EXPECTED_CONFIG_SHA256,
        "acceptance_authority": candidate.get("compatibility_governance_lock_sha256") == EXPECTED_ACCEPTANCE_LOCK_SHA256,
        "successor_authority": candidate.get("successor_authorization_lock_sha256") == EXPECTED_SUCCESSOR_LOCK_SHA256,
        "not_version_only": candidate.get("version_string_only") is False,
        "no_fallback": candidate.get("fallback_runtime") is None,
        "no_mixed_binding": candidate.get("mixed_current_historical_binding") is False,
    }
    return {"record_type": "V35_TYPED_CODEX_RUNTIME_ACCEPTANCE_FIXTURE_VERDICT", "checks": checks, "status": "PASS" if all(checks.values()) else "FAIL_CLOSED_BEFORE_STATIC_LOCK_AND_ATTEMPT"}


def typed_runtime_acceptance_precheck(component: str) -> dict[str, Any]:
    required = (CONTRACT, BINDING, ACCEPTANCE_LOCK, SUCCESSOR_LOCK, CODEX_BINARY, CODEX_PACKAGE, CODEX_CONFIG)
    if component not in ALLOWED_COMPONENTS or not all(path.is_file() and not path.is_symlink() for path in required):
        return {"record_type": "V35_TYPED_CODEX_RUNTIME_ACCEPTANCE_PRECHECK", "component": component, "status": "FAIL_CLOSED_BEFORE_STATIC_LOCK_AND_ATTEMPT", "reason": "COMPONENT_OR_REQUIRED_ARTIFACT_INVALID"}
    contract = _load(CONTRACT)
    binding = _load(BINDING)
    acceptance = _load(ACCEPTANCE_LOCK)
    candidate = dict(contract)
    checks = {
        "fixture_verdict": runtime_acceptance_fixture_verdict(candidate).get("status") == "PASS",
        "binding_execution": binding.get("execution_identity") == EXECUTION_IDENTITY,
        "binding_runtime_identity": binding.get("runtime_logical_identity") == RUNTIME_IDENTITY,
        "binding_version": binding.get("version") == "0.166.0",
        "binding_binary": binding.get("binary_sha256") == EXPECTED_BINARY_SHA256 == _sha256(CODEX_BINARY),
        "binding_package": binding.get("package_sha256") == EXPECTED_PACKAGE_SHA256 == _sha256(CODEX_PACKAGE),
        "binding_config": binding.get("dedicated_config_sha256") == EXPECTED_CONFIG_SHA256 == _sha256(CODEX_CONFIG),
        "acceptance_lock": _sha256(ACCEPTANCE_LOCK) == EXPECTED_ACCEPTANCE_LOCK_SHA256,
        "successor_lock": _sha256(SUCCESSOR_LOCK) == EXPECTED_SUCCESSOR_LOCK_SHA256,
        "current_field_pass_locked": acceptance.get(CURRENT_FIELD) == "COMPATIBILITY_PASS_LOCKED",
        "historical_field_not_selected": acceptance.get(HISTORICAL_FIELD) is None,
        "no_version_only": binding.get("version_string_only") is False,
        "no_fallback": binding.get("fallback_to_0_163_0") is False and binding.get("automatic_latest_selection") is False,
    }
    return {"record_type": "V35_TYPED_CODEX_RUNTIME_ACCEPTANCE_PRECHECK", "component": component, "current_authority_field": CURRENT_FIELD, "runtime_identity": RUNTIME_IDENTITY, "checks": checks, "status": "PASS" if all(checks.values()) else "FAIL_CLOSED_BEFORE_STATIC_LOCK_AND_ATTEMPT"}
