#!/usr/bin/env python3
"""Emit the single append-only V35 authoritative binding generation manifest."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import stat
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent
SRC = ROOT / "src"
OUT = ROOT / "contracts/UNIFIED_AUTHORITATIVE_BINDING_GENERATION.json"


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"module spec unavailable: {name}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def main() -> int:
    if OUT.exists() or OUT.is_symlink():
        raise FileExistsError(f"append-only generation exists: {OUT}")
    bindings = json.loads((ROOT / "contracts/CANONICAL_MODULE_BINDINGS.json").read_text())
    resolver_row = next(row for row in bindings["modules"] if row["canonical_logical_module_name"] == "module_resolution_v35")
    resolver_path = Path(resolver_row["canonical_source_path"])
    if digest(resolver_path) != resolver_row["exact_source_sha256"]:
        raise RuntimeError("V35_MODULE_RESOLVER_DIGEST_MISMATCH")
    resolver = load_module("module_resolution_v35", resolver_path)
    resolver.load_canonical_modules("BUILDER", ("workspace_boundary_v35", "binding_generation_v35"))
    binding_module = sys.modules["binding_generation_v35"]
    boundary = sys.modules["workspace_boundary_v35"]
    gov = Path(
        "/home/nobcoder/codex-security-harness-eval/governance/"
        "v0.3-first-real-security-worker-invocation-v34-prelock-results-directory-and-fixture-"
        "probe-path-lifecycle-defect-unit-execution-erratum-and-successor-decision-"
        "governance-only-v1-20261103"
    )
    v25_gov = Path(
        "/home/nobcoder/codex-security-harness-eval/governance/"
        "v0.3-first-real-security-worker-invocation-v25-stale-successor-mount-output-path-"
        "binding-defect-and-core-preflight-mount-contract-propagation-failure-prelock-erratum-and-successor-"
        "decision-governance-v1-20261101"
    )
    v20_gov = Path(
        "/home/nobcoder/codex-security-harness-eval/governance/"
        "v0.3-first-real-security-worker-invocation-v20-independent-validator-external-"
        "predecessor-artifact-path-binding-defect-prelock-erratum-and-successor-decision-"
        "governance-v1-20261101"
    )
    v17_gov = Path(
        "/home/nobcoder/codex-security-harness-eval/governance/"
        "v0.3-first-real-security-worker-invocation-v17-independent-validator-v16-tree-"
        "canonicalization-order-mismatch-prelock-erratum-and-continuation-or-successor-"
        "decision-governance-v1-20261023"
    )
    v18 = Path("/home/nobcoder/v0.3-first-real-security-worker-invocation-v18-20261023")
    entries = [
        ("SUCCESSOR_SELECTOR", "SUCCESSOR_V35_REQUIREMENTS", ROOT / "contracts/SUCCESSOR_V35_REQUIREMENTS.json", "V35", "SUCCESSOR_CONTRACT_SELECTOR", "V34_TO_V35_SUCCESSOR_AUTHORITY"),
        ("PROMPT_BYTES_DIGEST_AND_MODE", "V35_FINAL_WORKER_PROMPT", ROOT / "fixture/worker-prompt.txt", "V35", "FINAL_PROMPT_BYTES", "CURRENT_EXECUTION_INPUT"),
        ("PROMPT_BYTES_DIGEST_AND_MODE", "V35_PROMPT_IDENTITY_BINDING", ROOT / "contracts/PROMPT_IDENTITY_BINDING.json", "V35", "PROMPT_IDENTITY_AND_MODE_BINDING", "CURRENT_EXECUTION_READINESS"),
        ("PROMPT_BYTES_DIGEST_AND_MODE", "V35_WORKER_REQUEST", ROOT / "contracts/WORKER_REQUEST.json", "V35", "WORKER_REQUEST", "CURRENT_EXECUTION_INPUT"),
        ("HISTORICAL_GOVERNANCE_DECISIONS", "V34_TERMINAL_AND_V35_SUCCESSOR_DECISION", gov / "V34_TERMINAL_AND_V35_SUCCESSOR_DECISION.json", "V35_GOVERNANCE", "SUCCESSOR_DECISION", "AUTHORIZES_V35"),
        ("HISTORICAL_GOVERNANCE_DECISIONS", "V34_TO_V35_GOVERNANCE_LOCK", gov / "GOVERNANCE_LOCK.json", "V35_GOVERNANCE", "SUCCESSOR_GOVERNANCE_AUTHORITY", "AUTHORIZES_V35"),
        ("HISTORICAL_GOVERNANCE_DECISIONS", "V34_FROZEN_FAILURE_EVIDENCE_BINDING", gov / "V34_FROZEN_FAILURE_EVIDENCE_BINDING.json", "V34_GOVERNANCE", "FROZEN_FAILURE_EVIDENCE_BINDING", "IMMUTABLE_PREDECESSOR_HISTORY"),
        ("HISTORICAL_GOVERNANCE_DECISIONS", "V25_TERMINAL_AND_V26_SUCCESSOR_DECISION", v25_gov / "V25_TERMINAL_AND_V26_SUCCESSOR_DECISION.json", "V25_GOVERNANCE", "SUCCESSOR_DECISION", "AUTHORIZES_V26"),
        ("HISTORICAL_GOVERNANCE_DECISIONS", "V25_TO_V26_GOVERNANCE_LOCK", v25_gov / "GOVERNANCE_LOCK.json", "V25_GOVERNANCE", "SUCCESSOR_GOVERNANCE_AUTHORITY", "AUTHORIZES_V26"),
        ("HISTORICAL_GOVERNANCE_DECISIONS", "V35_TYPED_HISTORICAL_DECISION_REGISTRY_CONTRACT", ROOT / "contracts/TYPED_HISTORICAL_DECISION_REGISTRY_CONTRACT.json", "V35", "TYPED_HISTORICAL_DECISION_REGISTRY_CONTRACT", "CARRIED_FORWARD_TYPED_RELATIONS"),
        ("HISTORICAL_GOVERNANCE_DECISIONS", "V35_TYPED_HISTORICAL_DECISION_REGISTRY", ROOT / "contracts/TYPED_HISTORICAL_DECISION_REGISTRY.json", "V35", "TYPED_HISTORICAL_DECISION_REGISTRY", "CARRIED_FORWARD_TYPED_RELATIONS"),
        ("HISTORICAL_GOVERNANCE_DECISIONS", "V25_FROZEN_FAILURE_EVIDENCE_BINDING", v25_gov / "V25_FROZEN_FAILURE_EVIDENCE_BINDING.json", "V25_GOVERNANCE", "FROZEN_FAILURE_EVIDENCE_BINDING", "IMMUTABLE_PREDECESSOR_HISTORY"),
        ("MOUNT_OUTPUT_IDENTITY", "V35_MOUNT_OUTPUT_IDENTITY_BINDING", ROOT / "contracts/MOUNT_OUTPUT_IDENTITY_BINDING.json", "V35", "MOUNT_OUTPUT_IDENTITY_BINDING", "CURRENT_EXECUTION_READINESS"),
        ("TYPED_PREFLIGHT_REQUIREMENTS", "V35_TYPED_PREFLIGHT_REQUIREMENT_REGISTRY", ROOT / "contracts/TYPED_PREFLIGHT_REQUIREMENT_REGISTRY.json", "V35", "TYPED_PREFLIGHT_REQUIREMENT_REGISTRY", "CURRENT_EXECUTION_READINESS"),
        ("HOST_OUTPUT_BIND_SOURCE_LIFECYCLE", "V35_HOST_OUTPUT_BIND_SOURCE_LIFECYCLE_CONTRACT", ROOT / "contracts/HOST_OUTPUT_BIND_SOURCE_LIFECYCLE_CONTRACT.json", "V35_GOVERNANCE", "HOST_OUTPUT_BIND_SOURCE_LIFECYCLE_CONTRACT", "CURRENT_EXECUTION_READINESS"),
        ("PRELOCK_STORAGE_LIFECYCLE", "V35_PRELOCK_STORAGE_LIFECYCLE_CONTRACT", ROOT / "contracts/SUCCESSOR_V35_PRELOCK_RESULTS_AND_FIXTURE_PROBE_LIFECYCLE_CONTRACT.json", "V35_GOVERNANCE", "PRELOCK_RESULTS_AND_FIXTURE_PROBE_LIFECYCLE_CONTRACT", "CURRENT_EXECUTION_READINESS"),
        ("TYPED_CODEX_RUNTIME_ACCEPTANCE", "V35_TYPED_CODEX_RUNTIME_ACCEPTANCE_BINDING_CONTRACT", ROOT / "contracts/TYPED_CODEX_RUNTIME_ACCEPTANCE_BINDING_CONTRACT.json", "V35_GOVERNANCE", "TYPED_CURRENT_RUNTIME_AUTHORITY_CONTRACT", "CURRENT_EXECUTION_READINESS"),
        ("TYPED_CODEX_RUNTIME_ACCEPTANCE", "V35_CODEX_0_166_0_RUNTIME_BINDING", ROOT / "contracts/V35_CODEX_0_166_0_RUNTIME_BINDING.json", "V35", "EXACT_RUNTIME_IDENTITY_BINDING", "CURRENT_EXECUTION_READINESS"),
        ("HISTORICAL_GOVERNANCE_DECISIONS", "V20_TERMINAL_AND_V21_SUCCESSOR_DECISION", v20_gov / "V20_TERMINAL_AND_V21_SUCCESSOR_DECISION.json", "V20_GOVERNANCE", "HISTORICAL_SUCCESSOR_DECISION", "TRANSITIVE_HISTORY"),
        ("CANONICAL_PREDECESSOR_ARTIFACTS", "V35_CANONICAL_PREDECESSOR_BINDING", ROOT / "contracts/CANONICAL_PREDECESSOR_BINDING.json", "V35", "CANONICAL_PREDECESSOR_BINDING", "BINDS_V18"),
        ("CANONICAL_PREDECESSOR_ARTIFACTS", "V18_STATIC_EXECUTION_LOCK", v18 / "STATIC_EXECUTION_LOCK.json", "V18", "FROZEN_PREDECESSOR_STATIC_LOCK", "CANONICAL_PREDECESSOR"),
        ("EXTERNAL_TRANSITIVE_ARTIFACTS", "V17_PRELOCK_FROZEN_EVIDENCE_BINDING", v17_gov / "V17_PRELOCK_FROZEN_EVIDENCE_BINDING.json", "V17", "TRANSITIVE_FROZEN_EVIDENCE", "AUTHORIZED_RELATION_TO_V18"),
        ("EXTERNAL_TRANSITIVE_ARTIFACTS", "V21_EXTERNAL_PREDECESSOR_ARTIFACT_REGRESSION_MATRIX", v20_gov / "V21_EXTERNAL_PREDECESSOR_ARTIFACT_REGRESSION_MATRIX.json", "V20_GOVERNANCE", "TRANSITIVE_REGRESSION_MATRIX", "AUTHORIZED_RELATION_TO_V18"),
        ("CANONICAL_MODULE_RESOLUTION_BINDINGS", "V35_CANONICAL_MODULE_BINDINGS", ROOT / "contracts/CANONICAL_MODULE_BINDINGS.json", "V35", "CANONICAL_MODULE_BINDINGS", "CURRENT_RUNTIME_GRAPH"),
        ("AUTHORITATIVE_CONTRACT_SCHEMA_DIGEST_BINDINGS", "V35_TYPED_CANONICAL_MODULE_IDENTITY_CONTRACT", ROOT / "contracts/TYPED_CANONICAL_STANDARD_LIBRARY_MODULE_IDENTITY_CONTRACT.json", "V35", "TYPED_MODULE_IDENTITY_CONTRACT", "CURRENT_EXECUTION_READINESS"),
        ("AUTHORITATIVE_CONTRACT_SCHEMA_DIGEST_BINDINGS", "V35_SYMBOL_RESOLUTION_REGRESSION_MATRIX", ROOT / "contracts/V35_STANDARD_LIBRARY_SYMBOL_RESOLUTION_REGRESSION_MATRIX.json", "V35", "SYMBOL_RESOLUTION_REGRESSION_MATRIX", "CURRENT_EXECUTION_READINESS"),
        ("AUTHORITATIVE_CONTRACT_SCHEMA_DIGEST_BINDINGS", "V35_UNIFIED_BINDING_GENERATION_CONTRACT", ROOT / "contracts/UNIFIED_GOVERNANCE_BOUND_AUTHORITATIVE_BINDING_GENERATION_CONTRACT.json", "V35", "UNIFIED_BINDING_GENERATION_CONTRACT", "CURRENT_EXECUTION_READINESS"),
        ("AUTHORITATIVE_CONTRACT_SCHEMA_DIGEST_BINDINGS", "V35_DERIVED_CURRENT_EXPECTED_DIGEST_VIEW_CONTRACT", ROOT / "contracts/SUCCESSOR_V35_DERIVED_CURRENT_EXPECTED_DIGEST_VIEW_CONTRACT.json", "V35_GOVERNANCE", "DERIVED_CURRENT_DIGEST_VIEW_CONTRACT", "AUTHORIZES_REGISTRY_DERIVED_CURRENT_READINESS"),
        ("AUTHORITATIVE_CONTRACT_SCHEMA_DIGEST_BINDINGS", "V35_DERIVED_CURRENT_EXPECTED_DIGEST_REGRESSION_MATRIX", ROOT / "contracts/V35_DERIVED_CURRENT_EXPECTED_DIGEST_REGRESSION_MATRIX.json", "V35", "DERIVED_CURRENT_DIGEST_VIEW_REGRESSION_MATRIX", "CURRENT_EXECUTION_READINESS"),
        ("AUTHORITATIVE_CONTRACT_SCHEMA_DIGEST_BINDINGS", "V35_TYPED_VALIDATOR_HELPER_RETURN_REGRESSION_MATRIX", ROOT / "contracts/V35_TYPED_VALIDATOR_HELPER_RETURN_REGRESSION_MATRIX.json", "V35", "TYPED_VALIDATOR_HELPER_RETURN_REGRESSION_MATRIX", "CURRENT_EXECUTION_READINESS"),
        ("AUTHORITATIVE_CONTRACT_SCHEMA_DIGEST_BINDINGS", "SUCCESSOR_V35_TYPED_VALIDATOR_HELPER_RETURN_CONTRACT", ROOT / "contracts/SUCCESSOR_V35_TYPED_VALIDATOR_HELPER_RETURN_CONTRACT.json", "V35_GOVERNANCE", "TYPED_VALIDATOR_HELPER_RETURN_CONTRACT", "CURRENT_EXECUTION_READINESS"),
        ("AUTHORITATIVE_CONTRACT_SCHEMA_DIGEST_BINDINGS", "V35_TYPED_PREFLIGHT_REGISTRY_CONTRACT", ROOT / "contracts/TYPED_PREFLIGHT_REQUIREMENT_REGISTRY_CONTRACT.json", "V35", "TYPED_PREFLIGHT_REGISTRY_CONTRACT", "CURRENT_EXECUTION_READINESS"),
        ("AUTHORITATIVE_CONTRACT_SCHEMA_DIGEST_BINDINGS", "V35_SUCCESSOR_TYPED_PREFLIGHT_GENERATION_CONTRACT", ROOT / "contracts/SUCCESSOR_V35_TYPED_PREFLIGHT_BINDING_GENERATION_CONTRACT.json", "V35_GOVERNANCE", "SUCCESSOR_TYPED_PREFLIGHT_GENERATION_CONTRACT", "AUTHORIZES_CURRENT_GENERATION"),
        ("AUTHORITATIVE_CONTRACT_SCHEMA_DIGEST_BINDINGS", "V35_AUTHORITATIVE_ARTIFACT_DIGEST_BINDINGS", ROOT / "contracts/AUTHORITATIVE_ARTIFACT_DIGEST_BINDINGS.json", "V35", "CONTRACT_SCHEMA_DIGEST_BINDINGS", "CURRENT_EXECUTION_READINESS"),
        ("AUTHORITATIVE_ARTIFACT_FINALIZATION", "V35_AUTHORITATIVE_ARTIFACT_FINALIZATION_LIFECYCLE_CONTRACT", ROOT / "contracts/SUCCESSOR_V35_AUTHORITATIVE_ARTIFACT_FINALIZATION_LIFECYCLE_CONTRACT.json", "V35_GOVERNANCE", "ARTIFACT_FINALIZATION_LIFECYCLE_CONTRACT", "AUTHORIZES_CREATION_CLOSURE"),
        ("AUTHORITATIVE_ARTIFACT_FINALIZATION", "V35_AUTHORITATIVE_ARTIFACT_CREATION_CLOSURE", ROOT / "contracts/AUTHORITATIVE_ARTIFACT_CREATION_CLOSURE.json", "V35", "AUTHORITATIVE_MEMBER_SET_CREATION_CLOSURE", "CURRENT_EXECUTION_READINESS"),
    ]
    rows = []
    for domain, identity, path, owner, role, relationship in entries:
        if not path.is_file() or path.is_symlink():
            raise RuntimeError(f"required exact artifact unavailable: {path}")
        first = path.read_bytes()
        second = path.read_bytes()
        if first != second:
            raise RuntimeError(f"artifact changed during binding: {path}")
        required_mode = "0444" if identity == "V35_FINAL_WORKER_PROMPT" else None
        rows.append(
            {
                "generation_identity": binding_module.GENERATION_IDENTITY,
                "governance_identity": binding_module.GOVERNANCE_IDENTITY,
                "governance_digest": binding_module.GOVERNANCE_LOCK_SHA256,
                "domain": domain,
                "logical_artifact_identity": identity,
                "owner_identity": owner,
                "artifact_role": role,
                "canonical_locator": str(path.resolve(strict=True)),
                "sha256": hashlib.sha256(first).hexdigest(),
                "size": len(first),
                "required_mode": required_mode,
                "relationship": relationship,
                "consumer_set": sorted(binding_module.ALLOWED_COMPONENTS),
            }
        )
    shape = binding_module.binding_fixture_verdict(rows)
    if shape.get("status") != "PASS":
        raise RuntimeError(f"unified generation incomplete: {shape}")
    payload = {
        "record_type": "V35_UNIFIED_AUTHORITATIVE_BINDING_GENERATION",
        "execution_identity": binding_module.EXECUTION_IDENTITY,
        "generation_identity": binding_module.GENERATION_IDENTITY,
        "current_execution_readiness_generation": binding_module.GENERATION_IDENTITY,
        "governance_identity": binding_module.GOVERNANCE_IDENTITY,
        "governance_digest": binding_module.GOVERNANCE_LOCK_SHA256,
        "governance_decision_digest": binding_module.GOVERNANCE_DECISION_SHA256,
        "selection_policy": "EXACT_GOVERNANCE_BOUND_IDENTITIES_ONLY_NO_FALLBACK",
        "member_count": len(rows),
        "members": rows,
        "post_bind_mutation": "PROHIBITED",
        "status": "PASS_COMPLETE_EXACT_UNIFIED_GENERATION",
        "attempt_count": 0,
        "worker_invocation_count": 0,
        "codex_as_worker_invocation_count": 0,
    }
    boundary.guarded_json_once(
        OUT,
        payload,
        operation_identity="BUILD_UNIFIED_AUTHORITATIVE_BINDING_GENERATION",
        generation=binding_module.GENERATION_IDENTITY,
    )
    boundary.guarded_chmod(
        OUT,
        0o444,
        operation_identity="FREEZE_UNIFIED_AUTHORITATIVE_BINDING_GENERATION",
        generation=binding_module.GENERATION_IDENTITY,
    )
    print(json.dumps({"status": "PASS", "members": len(rows), "sha256": digest(OUT)}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
