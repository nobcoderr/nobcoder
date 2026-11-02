"""Pure contracts and semantic helpers for one bounded SecurityWorker invocation."""

from __future__ import annotations

import ast
import hashlib
import ipaddress
import json
import os
import re
import stat
import time
import tomllib
import unicodedata
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Iterable, Mapping

from workspace_boundary_v35 import (
    EXECUTION_IDENTITY as BOUNDARY_EXECUTION_IDENTITY,
    WORKSPACE as BOUNDARY_WORKSPACE,
    authorize_read,
    authorize_write,
    guard_output_root,
    guarded_json_once,
)
from symbol_resolution_v35 import static_symbol_binding_precheck
from predecessor_binding_v35 import (
    canonical_predecessor_binding_precheck,
    canonical_predecessor_binding_verdict,
)
from external_artifact_binding_v35 import external_predecessor_artifact_precheck
from module_resolution_v35 import canonical_module_resolution_precheck
from binding_generation_v35 import (
    GENERATION_IDENTITY,
    prompt_binding_verdict,
    unified_binding_generation_precheck,
)
from artifact_finalization_v35 import (
    authoritative_artifact_finalization_precheck,
    authoritative_input_paths,
)
from current_digest_view_v35 import (
    derived_current_expected_digest_view_precheck,
    derived_expected_digest_mapping,
)
from historical_decision_registry_v35 import (
    historical_decision_relation_precheck,
    resolve_historical_decision_relation,
)
from mount_output_binding_v35 import (
    HOST_OUTPUT as GOVERNANCE_BOUND_HOST_OUTPUT,
    NAMESPACE_OUTPUT as GOVERNANCE_BOUND_NAMESPACE_OUTPUT,
    mount_output_binding_precheck,
    stale_mount_literal_precheck,
)
from preflight_requirement_registry_v35 import typed_preflight_requirement_precheck
from host_output_lifecycle_v35 import (
    host_output_bind_source_precheck,
    lifecycle_fixture_verdict as host_output_lifecycle_fixture_verdict,
    provision_host_output_bind_source,
)
from runtime_acceptance_v35 import (
    CURRENT_FIELD as CURRENT_RUNTIME_ACCEPTANCE_FIELD,
    HISTORICAL_FIELD as HISTORICAL_RUNTIME_ACCEPTANCE_FIELD,
    runtime_acceptance_fixture_verdict,
    typed_runtime_acceptance_precheck,
)
from validator_helper_contract_v35 import require_typed_verdict


WORKSPACE = Path("/home/nobcoder/v0.3-first-real-security-worker-invocation-v35-20261103")
STATIC_RUN = GOVERNANCE_BOUND_HOST_OUTPUT
V11_WORKSPACE = Path("/home/nobcoder/v0.3-first-real-security-worker-invocation-v11-20261020")
V12_WORKSPACE = Path("/home/nobcoder/v0.3-first-real-security-worker-invocation-v12-20261023")
V13_WORKSPACE = Path("/home/nobcoder/v0.3-first-real-security-worker-invocation-v13-20261023")
V14_WORKSPACE = Path("/home/nobcoder/v0.3-first-real-security-worker-invocation-v14-20261023")
V15_WORKSPACE = Path("/home/nobcoder/v0.3-first-real-security-worker-invocation-v15-20261023")
V16_WORKSPACE = Path("/home/nobcoder/v0.3-first-real-security-worker-invocation-v16-20261023")
V17_WORKSPACE = Path("/home/nobcoder/v0.3-first-real-security-worker-invocation-v17-20261023")
V18_WORKSPACE = Path("/home/nobcoder/v0.3-first-real-security-worker-invocation-v18-20261023")
V19_WORKSPACE = Path("/home/nobcoder/v0.3-first-real-security-worker-invocation-v19-20261025")
V20_WORKSPACE = Path("/home/nobcoder/v0.3-first-real-security-worker-invocation-v20-20261101")
V21_WORKSPACE = Path("/home/nobcoder/v0.3-first-real-security-worker-invocation-v21-20261101")
V22_WORKSPACE = Path("/home/nobcoder/v0.3-first-real-security-worker-invocation-v22-20261101")
V23_WORKSPACE = Path("/home/nobcoder/v0.3-first-real-security-worker-invocation-v23-20261101")
V24_WORKSPACE = Path("/home/nobcoder/v0.3-first-real-security-worker-invocation-v24-20261101")
V25_WORKSPACE = Path("/home/nobcoder/v0.3-first-real-security-worker-invocation-v25-20261101")
V26_WORKSPACE = Path("/home/nobcoder/v0.3-first-real-security-worker-invocation-v26-20261102")
FIXTURE_ROOT = WORKSPACE / "fixture"
CONTEXT_ROOT = FIXTURE_ROOT / "context"
CONFIG_ROOT = WORKSPACE / "runtime-config-candidate"
CODEX_CONFIG = CONFIG_ROOT / "config.toml"
MODEL_OUTPUT_SCHEMA = WORKSPACE / "schemas/WORKER_MODEL_OUTPUT.schema.json"
CONTROLLER_RESULT_SCHEMA = WORKSPACE / "schemas/CONTROLLER_WORKER_RESULT.schema.json"
PROMPT_PATH = FIXTURE_ROOT / "worker-prompt.txt"
FIXTURE_PATH = FIXTURE_ROOT / "fixture.json"

CODEX_BINARY = Path(
    "/home/nobcoder/.codex/packages/standalone/releases/"
    "0.166.0-x86_64-unknown-linux-musl/bin/codex"
)
CODEX_PACKAGE_ROOT = CODEX_BINARY.parent.parent
CODEX_PACKAGE = CODEX_PACKAGE_ROOT / "codex-package.json"
CODEX_AUTH = Path("/home/nobcoder/.codex/auth.json")
BWRAP = Path("/usr/bin/bwrap")
STRACE = Path("/usr/bin/strace")
PYTHON = Path("/usr/bin/python3.14")
TEMPORAL_OBSERVER = WORKSPACE / "src/topology_observer_v35.py"
WORKER_LAUNCH_GATE = WORKSPACE / "src/worker_launch_gate_v35.py"
SHORT_LIVED_CHILD = WORKSPACE / "src/short_lived_child_v35.py"

OBSERVER_EVENTS = STATIC_RUN / "temporal-process-observer-events-0001.jsonl"
OBSERVER_SNAPSHOT = STATIC_RUN / "temporal-process-observer-snapshot-0001.json"
OBSERVER_READY = STATIC_RUN / "temporal-process-observer-ready-0001.json"
OBSERVER_ROOT = STATIC_RUN / "temporal-process-observer-root-0001.json"
OBSERVER_ROOT_BOUND = STATIC_RUN / "temporal-process-observer-root-bound-0001.json"
OBSERVER_STOP = STATIC_RUN / "temporal-process-observer-stop-0001.json"
WORKER_LAUNCH_READY = STATIC_RUN / "worker-launch-gate-ready-0001.json"
WORKER_LAUNCH_GO = STATIC_RUN / "worker-launch-gate-go-0001.json"

EXECUTION_IDENTITY = "V0_3_FIRST_REAL_SECURITY_WORKER_INVOCATION_V35"
AUTHORIZATION_ID = (
    "V0_3_FIRST_REAL_SECURITY_WORKER_INVOCATION_V34_PRELOCK_RESULTS_DIRECTORY_AND_"
    "FIXTURE_PROBE_PATH_LIFECYCLE_DEFECT_UNIT_EXECUTION_ERRATUM_AND_SUCCESSOR_DECISION_"
    "GOVERNANCE_ONLY"
)
CAMPAIGN_ID = "RC-FIRST-WORKER-FIXTURE-V35"
LANE_ID = "RL-STRUCTURED-PROPOSAL-FIXTURE-V35"
WORKER_ID = "SW-CODEX-FIRST-WORKER-V35"
WORKSPACE_ID = "WS-FIRST-WORKER-FIXTURE-V35"
RUNTIME_IDENTITY = "CODEX_RUNTIME_0_166_0_COMPATIBILITY_PASS_LOCKED"
MODEL_IDENTITY = "gpt-6.1-sol"
FIXTURE_EVIDENCE_ID = "FIXTURE-EVIDENCE-0001"
CANDIDATE_INITIAL_STATE = "HYPOTHESIS_QUARANTINED"
PROPOSAL_AUTHORITY = "PROPOSAL_ONLY_NON_AUTHORITATIVE"

SUPPORTED_STRICT_SCHEMA_KEYWORDS = frozenset(
    {
        "$schema",
        "additionalProperties",
        "const",
        "description",
        "items",
        "maxItems",
        "minItems",
        "minLength",
        "properties",
        "required",
        "title",
        "type",
    }
)

PROMPT_REQUIRED_PROPOSITIONS = {
    "tool_denial": (("do", "not", "call", "any", "tool"),),
    "network_and_target_denial": (
        ("do", "not", "access", "any", "network", "or", "target"),
        (
            ("do", "not", "access", "any", "network"),
            ("do", "not", "access", "any", "target"),
        ),
    ),
}
PROMPT_WEAKENING_OR_INVERSION_MARKERS = (
    "unless",
    "except",
    "if needed",
    "may access",
    "allowed",
    "permitted",
    "optional",
)

SANDBOX_RUN = GOVERNANCE_BOUND_NAMESPACE_OUTPUT
SANDBOX_BASE = SANDBOX_RUN.parent
SANDBOX_WORK = SANDBOX_BASE / "work"
SANDBOX_CONTEXT = SANDBOX_WORK / "context"
SANDBOX_FIXTURE = SANDBOX_WORK / "fixture"
SANDBOX_SCHEMAS = SANDBOX_WORK / "schemas"
SANDBOX_CODEX_ROOT = SANDBOX_BASE / "codex-runtime-0.166.0"
SANDBOX_CODEX_BINARY = SANDBOX_CODEX_ROOT / "bin/codex"
SANDBOX_CODEX_HOME = Path("/home/nobcoder/.codex")
HOST_UID = os.getuid()
HOST_GID = os.getgid()

_HISTORICAL_EXPECTED_DIGESTS = {
    "authorization_lock": "f371001972791a56e4d9b7fa92c7b0870da1b126bb16ee5f7f67b6c7d94c51b0",
    "authorization_manifest": "a176b9fda98a3db0f6bd7874367c6a6f932ee390c0f2978484b288cf971f7ebe",
    "successor_v19_requirements": "380d1109d6a8dd7375a4cc30e277eb5c0205f0f2e8691a2c3d366d54e434cef2",
    "locked_entrypoint_symbol_resolution_contract": "c34c16fd81f712fa5afff9369c9b2d961fda7440b96d12ea2c7df4dedd3c5d93",
    "v19_import_binding_regression_matrix": "4d983b7e7209e0b684e8959a619ee5501e383a9da3471bad054e6c06744e7242",
    "v18_frozen_evidence_binding": "52a5c1cd0a87a5d7d2314db17579fb4acb45cbf52ef2c5476c069f5d3756e7ca",
    "v18_successor_decision": "96dbee1a08f7f1653000ef2a174b5b5a35f403d05aa3511abd0e4b5448e9779e",
    "v35_authorization_lock": "d2263268f61b9ddde99a0b60f4b43a26df1586e0c577ba2ca98c07b64c21f811",
    "v35_authorization_manifest": "41e03f31a302c2be001c7a7de6b550c8537a72cce340b8670bd7140af3f263f6",
    "v21_frozen_failure_evidence_binding": "84d15a077e59c36fdd38b96559f4a92a008702e68a47fa1f6bcbdd75baa71de1",
    "v34_to_v35_successor_decision": "e9672bcddb685c92f3230531eb4c131f41264f54e2ee4c6afa9f9f633bcb21b6",
    "v26_defect_adjudication": "d036f6eb30acde4e67b48b0dcd41faa7deb5c8c3e1a2b08d081946d9de209b76",
    "v26_frozen_failure_evidence_binding": "41c792d8ef7f99405aa95b3a82e22e5a11dcc6a335573a2786782d82df54ea66",
    "v26_nine_unresolved_bindings": "4e143a3b51e37180a080a50ec4548aa08eaa766ca4d88e3594828e9ac248f56f",
    "transactional_telemetry_contract": "262ab489a83e466e8aeadcb48f3643337aa6b720bfadef5d3941a363348ffb46",
    "canonical_external_predecessor_artifact_binding_contract": "5ea43ebe5acc1e5e3f8472323b03f50f3e1ab1101d0ebe2fe1b243a23cd345ad",
    "v20_frozen_failure_evidence_binding": "969ba8ff99c32c1ebff455aff717f4199be53641371c2c8880a7ced99485bfb1",
    "v20_to_v21_successor_decision": "8c78c347a293605db31122f42482ce2caca5bb52a5e750be341377087f3aeff3",
    "v21_external_predecessor_artifact_regression_matrix": "6facfd3c98611569f2c1ae56137a5bee2b5370f9aff5f6ded964d680abf85f22",
    "v23_predecessor_binding_regression_matrix": "3a6e1c49d78ee0b0563a36bb65ce13c133bf2a9ebad899c32a5fc95f6a4d75e8",
    "v19_frozen_failure_evidence_binding": "19449baac7e71149dcee7cf55b32d84a4e36a23d7eb009d18f23ffe14064dd01",
    "v19_to_v20_successor_decision": "bb59b30c4549d786e9e52872ac828c64fc002d3896abf6e06a564ceafd104e10",
    "v17_authorization_lock": "053abd247ab8b80624abe58346707deeb2cda5b9848ee245d9dc146c02624080",
    "normative_v16_tree_contract": "53319e1eff0e2c052d84f7471da98a3165aa732261632412029aaceed45644ff",
    "v17_frozen_prelock_binding": "7b112d3a2f0e69e754d23051608a0cb8fb20edc375a9d42c0c8898dd0020f360",
    "v17_successor_decision": "8e0d1d19e6f443e8d2985bb884d437877bacd94da61541731af5d5046f75235f",
    "v16_canonicalization_regression_matrix": "12172c5826165d5b3d945ee0fce88187ba2117893c82bbedf10aa11eb5fe42a8",
    "i008a_canonicalization_adjudication": "e1fc3f4091cf289fabd534358c4f0b8a9499e76e4d79309242ddb6d56f3d35e9",
    "v16_authorization_lock": "56d646be912bf3fd67f970c3e396c5036bd30c4826bff3eee6ff487921aaaccd",
    "v16_authorization_manifest": "7704142c8ac8ed959085fd49ecff67ebbd3373e5f1250245e229a9137aeca144",
    "successor_v19_python_cache_contract": "20e8d36a128e159d7ef909d4f07add5bc5c24aecfd06348d52200fadc3a5bb98",
    "v19_workspace_write_boundary_contract": "94b7c7ac285affbd9b155c90ed0aac99c9d905432a699f16b62c35698c707741",
    "v14_v15_v19_regression_matrix": "8f479c99ebfdd168663edd89a813af06c45aacf8e5d6d5e407b46ae1b9339ea3",
    "v14_current_drift_adjudication": "b36113c1ee959cea47e40ac7c2d2c0c6debeb6306a37819e3d310ec57543772d",
    "v14_preincident_identity": "f03083f8a5c0d8e1708ef17a14bd842ab4fbd137b485235f478245483ded47a0",
    "v15_frozen_prelock_binding": "df2ade0fe8fc20895f4bc1b788f7f266bbc009f32d910ccf07a8bdaf070478f4",
    "v14_authorization_lock": "7d134a0721b2168e5a48a6cfc2c5e7f1fa02a35b96379a16a53cc69695be8b43",
    "v14_authorization_manifest": "a1f4eb0fcc83c89b2eeb5b3bc83302ec1c98b53f7d0acba128e5af36978bd9c7",
    "v14_frozen_evidence_snapshot_manifest": "fef3de2e74c40dff0076e2d7dde91c848cb64eb157cdfe7e60c54419a16dd34e",
    "v14_frozen_evidence_binding": "2f9b4a057de8fe09be811017a800d0dc7529c5339319ec1509d93ee8012dee81",
    "v13_authorization_lock": "3e841cf6ae437db8922a15c7939ecb7cb56e933a8db7eb1a3751b4cbb9a68b30",
    "v13_authorization_manifest": "e7f1f2f073c92be1c7e46e7af5dea5881ab09286166f3b3959f126f316b98964",
    "complete_coverage_invariant": "bbc5ea2bda294e9b8308a0349f63fc0cb73a86ec9bd5aef4cfb3f3ea0085dba4",
    "v13_failure_decomposition": "009e42e94bcffcbbc9134f9cd7ce8ca40b28bfe2a758a8bf903f2e194ed23aa3",
    "v13_frozen_evidence_binding": "5073dcf3d4cbc1adafb24e3a226a8d86f5ce1221e5d1ef2e89c6cf9ffd3af3b3",
    "v10_terminal_evidence_binding": "f77e6bd57f7f6ce8ba437184c7d7e316a5d4f1ee67b4feb39d1084f21d8e7b47",
    "v9_prelock_evidence_binding": "b3b2f509bd0c12d358065a8697943b25906338a81b278f5c3c9a84fc16cdb7a1",
    "v8_prelock_evidence_binding": "0a6aeff52c3146d82fc18dcc9b40397d4ccdcfadf1a6c5a7315ad2b399449d4b",
    "v7_prelock_evidence_binding": "ce9975e2763c95b95f836f57b09f7e597cfef55c6b74b6d28465fd41db0f9129",
    "v6_terminal_evidence_binding": "3e6b4fd240bbc61e1ff6517208da72cffb63b60eeac557ae89d09cf2879d92e6",
    "v5_terminal_evidence_binding": "4979f35fe962816715821fdd96722c14bbf03e8f8a865230aa9f5c0064a1c2b0",
    "v4_terminal_evidence_binding": "43748a8a45d210a613461027f01b87742af1b1944bf69e794b7da7b4c102838e",
    "v3_terminal_evidence_binding": "4726ddcf3d1ee3d964cdac9291e797f00d9c0e59236fae25ddf307583c92d0a8",
    "v2_terminal_evidence_binding": "94d4320bb083f7b643d99e918dfcaeec152e43a73cb49a2c78b5cd56e5d72609",
    "runtime_substrate_lock": "8383ec457c0838fba668693ae9c837edf1a8c50222c524176dc60b9afda9191e",
    "codex_compatibility_acceptance_lock": "060b39551d4543999e79ccfd5d133d751faefc018fdc8adab718f5b9c7479a5e",
    "codex_compatibility_acceptance_manifest": "c32c1c786e4372103ed392f25aef029c777a8afe2ef9afe2dd738b2f640d6b86",
    "security_worker_runtime_lock": "cc7928e67b9d5c74f04a750d8faae5bbdf97f2dd7fd4337885ddf10f85d6e8f7",
    "control_plane_lock": "54e61cc5186ee5620a9d5116e4fa2650affef6e7919ca594ecd3921ff9671e2f",
    "fixture_runner_lock": "14ebdff93e45f275f14b1c6be6594bdbbf7d69921edb56e89329337e16bd2da4",
    "codex_binary": "b8a11fedf24b2dfb59a70c9e52b030f9a508dcd49cd2dd0d41956f4c785156b8",
    "codex_package": "ffdfc731eed492fa436a304cff8792ea3a96233a45ec9a561f6f56eaca911446",
    "codex_config": "7ae835188ef2ab3221e15effac45375b2d6112954d022aa7776f802f7b8697c0",
    "bwrap": "042763bc80c8a895a497e6f801af003d585ea5588a580f7a4349d9ab2aa22980",
    "strace": "705e89a26e9f6a48f2908760d78801cbaa263f9b8c6738e392fb95902479cddf",
    "python": "36103f0154f128cf946c4fdc4ea2dc21eb30a48d42dd83541a6b751f005fa60d",
}

# The six current-readiness keys are deliberately absent from this historical
# table. They are resolved from the frozen derived view of the authoritative
# registry, so predecessor digests cannot become current authority.
EXPECTED_DIGESTS = derived_expected_digest_mapping(_HISTORICAL_EXPECTED_DIGESTS)

V14_GOVERNANCE = Path(
    "/home/nobcoder/codex-security-harness-eval/governance/"
    "v0.3-first-real-security-worker-invocation-v14-primary-validator-lifecycle-source-"
    "order-anchor-defect-prelock-erratum-and-continuation-or-successor-decision-"
    "governance-v1-20261023"
)
V15_GOVERNANCE = Path(
    "/home/nobcoder/codex-security-harness-eval/governance/"
    "v0.3-first-real-security-worker-invocation-v15-predecessor-v14-append-only-"
    "drift-and-cross-workspace-command-targeting-prelock-erratum-and-successor-"
    "decision-governance-v1-20261023"
)
V16_GOVERNANCE = Path(
    "/home/nobcoder/codex-security-harness-eval/governance/"
    "v0.3-first-real-security-worker-invocation-v16-implicit-python-bytecode-cache-"
    "write-boundary-coverage-gap-prelock-erratum-and-continuation-or-successor-"
    "decision-governance-v1-20261023"
)
V17_GOVERNANCE = Path(
    "/home/nobcoder/codex-security-harness-eval/governance/"
    "v0.3-first-real-security-worker-invocation-v17-independent-validator-v16-tree-"
    "canonicalization-order-mismatch-prelock-erratum-and-continuation-or-successor-"
    "decision-governance-v1-20261023"
)
V18_GOVERNANCE = Path(
    "/home/nobcoder/codex-security-harness-eval/governance/"
    "v0.3-first-real-security-worker-invocation-v18-locked-runner-canonicalization-"
    "precheck-import-binding-defect-post-lock-pre-attempt-erratum-and-successor-"
    "decision-governance-v1-20261025"
)
V19_GOVERNANCE = Path(
    "/home/nobcoder/codex-security-harness-eval/governance/"
    "v0.3-first-real-security-worker-invocation-v19-authoritative-artifact-predecessor-"
    "identity-verifier-binding-defect-prelock-erratum-and-continuation-or-successor-"
    "decision-governance-v1-20261101"
)
V20_GOVERNANCE = Path(
    "/home/nobcoder/codex-security-harness-eval/governance/"
    "v0.3-first-real-security-worker-invocation-v20-independent-validator-external-"
    "predecessor-artifact-path-binding-defect-prelock-erratum-and-successor-decision-"
    "governance-v1-20261101"
)
V21_GOVERNANCE = Path(
    "/home/nobcoder/codex-security-harness-eval/governance/"
    "v0.3-first-real-security-worker-invocation-v21-independent-validator-local-module-"
    "resolution-environment-defect-prelock-erratum-and-successor-decision-"
    "governance-v1-20261101"
)
V22_GOVERNANCE = Path(
    "/home/nobcoder/codex-security-harness-eval/governance/"
    "v0.3-first-real-security-worker-invocation-v22-multi-contract-selector-prompt-"
    "immutability-historical-decision-verifier-and-external-artifact-digest-binding-"
    "failures-prelock-erratum-and-successor-decision-governance-v1-20261101"
)
V23_GOVERNANCE = Path(
    "/home/nobcoder/codex-security-harness-eval/governance/"
    "v0.3-first-real-security-worker-invocation-v23-historical-decision-relation-"
    "binding-defect-and-nested-adversarial-temporal-selftest-evidence-pipeline-"
    "failure-prelock-erratum-and-successor-decision-governance-v1-20261101"
)
V26_GOVERNANCE = Path(
    "/home/nobcoder/codex-security-harness-eval/governance/"
    "v0.3-first-real-security-worker-invocation-v26-independent-validator-standard-library-"
    "symbol-resolution-binding-defect-prelock-erratum-and-successor-decision-"
    "governance-v1-20261102"
)
V35_GOVERNANCE = Path(
    "/home/nobcoder/codex-security-harness-eval/governance/"
    "v0.3-first-real-security-worker-invocation-v34-prelock-results-directory-and-fixture-"
    "probe-path-lifecycle-defect-unit-execution-erratum-and-successor-decision-"
    "governance-only-v1-20261103"
)
V13_GOVERNANCE = Path(
    "/home/nobcoder/codex-security-harness-eval/governance/"
    "v0.3-first-real-security-worker-invocation-v13-adversarial-multi-short-lived-temporal-"
    "identity-selftest-failure-and-complete-coverage-incompleteness-prelock-erratum-and-"
    "continuation-or-successor-decision-governance-v1-20261023"
)
V12_GOVERNANCE = Path(
    "/home/nobcoder/codex-security-harness-eval/governance/"
    "v0.3-first-real-security-worker-invocation-v12-incomplete-temporally-bound-process-"
    "identity-coverage-process-lineage-runtime-topology-producer-authorization-and-"
    "confinement-incompleteness-post-attempt-erratum-and-successor-decision-governance-v1-20261023"
)
V12_GOVERNANCE_LOCK_SHA256 = "003173b70a5d2524694a5063269b3cfc705c0daae3aa0b2cdb37768abe3b4555"
PREDECESSOR_PATHS = {
    "authorization_lock": V18_GOVERNANCE / "GOVERNANCE_LOCK.json",
    "authorization_manifest": V18_GOVERNANCE / "GOVERNANCE_ARTIFACT_MANIFEST.json",
    "successor_v19_requirements": V18_GOVERNANCE / "SUCCESSOR_V19_REQUIREMENTS.json",
    "locked_entrypoint_symbol_resolution_contract": V18_GOVERNANCE / "LOCKED_ENTRYPOINT_SYMBOL_RESOLUTION_CONTRACT.json",
    "v19_import_binding_regression_matrix": V18_GOVERNANCE / "V19_IMPORT_BINDING_REGRESSION_MATRIX.json",
    "v18_frozen_evidence_binding": V18_GOVERNANCE / "V18_FROZEN_EVIDENCE_BINDING.json",
    "v18_successor_decision": V18_GOVERNANCE / "V18_TERMINAL_AND_V19_SUCCESSOR_DECISION.json",
    "v35_authorization_lock": V35_GOVERNANCE / "GOVERNANCE_LOCK.json",
    "v35_authorization_manifest": V35_GOVERNANCE / "GOVERNANCE_ARTIFACT_MANIFEST.json",
    "successor_v35_requirements": WORKSPACE / "contracts/SUCCESSOR_V35_REQUIREMENTS.json",
    "unified_binding_generation_contract": WORKSPACE / "contracts/UNIFIED_GOVERNANCE_BOUND_AUTHORITATIVE_BINDING_GENERATION_CONTRACT.json",
    "v21_frozen_failure_evidence_binding": V21_GOVERNANCE / "V21_FROZEN_FAILURE_EVIDENCE_BINDING.json",
    "v34_to_v35_successor_decision": V35_GOVERNANCE / "V34_TERMINAL_AND_V35_SUCCESSOR_DECISION.json",
    "v26_defect_adjudication": V26_GOVERNANCE / "INDEPENDENT_VALIDATOR_STANDARD_LIBRARY_SYMBOL_RESOLUTION_BINDING_DEFECT_ADJUDICATION.json",
    "typed_historical_decision_registry_contract": WORKSPACE / "contracts/TYPED_HISTORICAL_DECISION_REGISTRY_CONTRACT.json",
    "typed_historical_decision_registry": WORKSPACE / "contracts/TYPED_HISTORICAL_DECISION_REGISTRY.json",
    "v26_frozen_failure_evidence_binding": V26_GOVERNANCE / "V26_FROZEN_FAILURE_EVIDENCE_BINDING.json",
    "v35_typed_module_identity_contract": WORKSPACE / "contracts/TYPED_CANONICAL_STANDARD_LIBRARY_MODULE_IDENTITY_CONTRACT.json",
    "v35_symbol_resolution_regression_matrix": WORKSPACE / "contracts/V35_STANDARD_LIBRARY_SYMBOL_RESOLUTION_REGRESSION_MATRIX.json",
    "v26_nine_unresolved_bindings": V26_GOVERNANCE / "NINE_UNRESOLVED_STANDARD_LIBRARY_BINDINGS.json",
    "transactional_telemetry_contract": V23_GOVERNANCE / "ADVERSARIAL_SELFTEST_TRANSACTIONAL_TELEMETRY_CONTRACT.json",
    "canonical_external_predecessor_artifact_binding_contract": V20_GOVERNANCE / "CANONICAL_EXTERNAL_PREDECESSOR_ARTIFACT_BINDING_CONTRACT.json",
    "v20_frozen_failure_evidence_binding": V20_GOVERNANCE / "V20_FROZEN_FAILURE_EVIDENCE_BINDING.json",
    "v20_to_v21_successor_decision": V20_GOVERNANCE / "V20_TERMINAL_AND_V21_SUCCESSOR_DECISION.json",
    "v21_external_predecessor_artifact_regression_matrix": V20_GOVERNANCE / "V21_EXTERNAL_PREDECESSOR_ARTIFACT_REGRESSION_MATRIX.json",
    "v19_frozen_failure_evidence_binding": V19_GOVERNANCE / "V19_FROZEN_FAILURE_EVIDENCE_BINDING.json",
    "v19_to_v20_successor_decision": V19_GOVERNANCE / "V19_TERMINAL_AND_V20_SUCCESSOR_DECISION.json",
    "v17_authorization_lock": V17_GOVERNANCE / "GOVERNANCE_LOCK.json",
    "normative_v16_tree_contract": V17_GOVERNANCE / "NORMATIVE_V16_TREE_CANONICALIZATION_CONTRACT.json",
    "v17_frozen_prelock_binding": V17_GOVERNANCE / "V17_PRELOCK_FROZEN_EVIDENCE_BINDING.json",
    "v17_successor_decision": V17_GOVERNANCE / "V17_TERMINAL_AND_V18_SUCCESSOR_DECISION.json",
    "v16_canonicalization_regression_matrix": V17_GOVERNANCE / "V16_CANONICALIZATION_REGRESSION_MATRIX.json",
    "i008a_canonicalization_adjudication": V17_GOVERNANCE / "I008A_CANONICALIZATION_ORDER_ADJUDICATION.json",
    "v16_authorization_lock": V16_GOVERNANCE / "GOVERNANCE_LOCK.json",
    "v16_authorization_manifest": V16_GOVERNANCE / "GOVERNANCE_ARTIFACT_MANIFEST.json",
    "successor_v19_python_cache_contract": WORKSPACE / "contracts/SUCCESSOR_V19_PYTHON_CACHE_AND_WRITE_BOUNDARY_CONTRACT.json",
    "v19_workspace_write_boundary_contract": V15_GOVERNANCE / "V16_WORKSPACE_WRITE_BOUNDARY_CONTRACT.json",
    "v14_v15_v19_regression_matrix": V15_GOVERNANCE / "V14_V15_FAILURE_AND_V16_REGRESSION_MATRIX.json",
    "v14_current_drift_adjudication": V15_GOVERNANCE / "V14_CURRENT_APPEND_ONLY_DRIFT_ADJUDICATION.json",
    "v14_preincident_identity": V15_GOVERNANCE / "V14_PREINCIDENT_FROZEN_IDENTITY.json",
    "v15_frozen_prelock_binding": V15_GOVERNANCE / "V15_FROZEN_PRELOCK_EVIDENCE_BINDING.json",
    "v14_authorization_lock": V14_GOVERNANCE / "GOVERNANCE_LOCK.json",
    "v14_authorization_manifest": V14_GOVERNANCE / "GOVERNANCE_ARTIFACT_MANIFEST.json",
    "v14_frozen_evidence_snapshot_manifest": V14_GOVERNANCE / "V14_FROZEN_EVIDENCE_SNAPSHOT_MANIFEST.json",
    "v14_frozen_evidence_binding": V14_GOVERNANCE / "V14_FROZEN_EVIDENCE_BINDING.json",
    "v13_authorization_lock": V13_GOVERNANCE / "GOVERNANCE_LOCK.json",
    "v13_authorization_manifest": V13_GOVERNANCE / "GOVERNANCE_ARTIFACT_MANIFEST.json",
    "complete_coverage_invariant": V13_GOVERNANCE / "COMPLETE_COVERAGE_INVARIANT.json",
    "v13_failure_decomposition": V13_GOVERNANCE / "ADVERSARIAL_SELFTEST_FAILURE_DECOMPOSITION.json",
    "v13_frozen_evidence_binding": V13_GOVERNANCE / "V13_FROZEN_EVIDENCE_BINDING.json",
    "v10_terminal_evidence_binding": Path("/home/nobcoder/codex-security-harness-eval/governance/v0.3-first-real-security-worker-invocation-v10-temporally-bound-proc-topology-observation-coverage-gap-process-lineage-and-producer-authorization-incompleteness-post-attempt-erratum-and-successor-decision-governance-v1-20261020/V10_TERMINAL_EVIDENCE_BINDING.json"),
    "v9_prelock_evidence_binding": Path("/home/nobcoder/codex-security-harness-eval/governance/v0.3-first-real-security-worker-invocation-v9-contract-and-schema-expected-digest-identity-mismatch-and-pre-preflight-validation-coverage-gap-erratum-and-successor-decision-governance-v1-20261020/V9_PRELOCK_EVIDENCE_BINDING.json"),
    "v8_prelock_evidence_binding": Path("/home/nobcoder/codex-security-harness-eval/governance/v0.3-first-real-security-worker-invocation-v8-predecessor-compatibility-lock-path-binding-mismatch-prelock-erratum-and-successor-or-continuation-decision-governance-v1-20261020/V8_PRELOCK_EVIDENCE_BINDING.json"),
    "v7_prelock_evidence_binding": Path("/home/nobcoder/codex-security-harness-eval/governance/v0.3-first-real-security-worker-invocation-v7-prompt-identity-digest-mismatch-prelock-erratum-and-successor-or-continuation-decision-governance-v1-20261020/V7_PRELOCK_EVIDENCE_BINDING.json"),
    "v6_terminal_evidence_binding": Path("/home/nobcoder/codex-security-harness-eval/governance/v0.3-first-real-security-worker-invocation-v6-tcpv6-fd-annotation-grammar-and-downstream-classifier-incompleteness-post-validation-failure-erratum-and-successor-decision-governance-v1-20261020/V6_TERMINAL_EVIDENCE_BINDING.json"),
    "v5_terminal_evidence_binding": Path("/home/nobcoder/codex-security-harness-eval/governance/v0.3-first-real-security-worker-invocation-v5-cross-namespace-pid-ppid-correlation-and-dependent-mount-write-classification-post-validation-failure-erratum-and-successor-decision-governance-v1-20261020/V5_TERMINAL_EVIDENCE_BINDING.json"),
    "v4_terminal_evidence_binding": Path("/home/nobcoder/codex-security-harness-eval/governance/v0.3-first-real-security-worker-invocation-v4-startup-process-lineage-ephemeral-tmpfs-write-classification-token-budget-semantics-and-post-validation-failure-erratum-and-successor-decision-governance-v1-20261020/V4_TERMINAL_EVIDENCE_BINDING.json"),
    "v3_terminal_evidence_binding": Path("/home/nobcoder/codex-security-harness-eval/governance/v0.3-first-real-security-worker-invocation-v3-strict-response-schema-compatibility-fd-annotation-trace-grammar-and-diagnostic-post-validation-failure-erratum-and-successor-decision-governance-v1-20261020/V3_TERMINAL_EVIDENCE_BINDING.json"),
    "v2_terminal_evidence_binding": Path("/home/nobcoder/codex-security-harness-eval/governance/v0.3-first-real-security-worker-invocation-v2-runtime-bind-destination-construction-failure-and-incomplete-post-validation-erratum-and-successor-decision-governance-v1-20261020/V2_TERMINAL_EVIDENCE_BINDING.json"),
    "runtime_substrate_lock": Path("/home/nobcoder/codex-security-harness-eval/governance/v0.3-runtime-substrate-validation-v5-frozen-evidence-acceptance-and-pass-locked-decision-governance-v1-20261017/GOVERNANCE_LOCK.json"),
    "security_worker_runtime_lock": Path("/home/nobcoder/codex-security-harness-eval/governance/v0.3-security-worker-runtime-v1-frozen-evidence-acceptance-and-pass-locked-decision-governance-v1-20261020/GOVERNANCE_LOCK.json"),
    "control_plane_lock": Path("/home/nobcoder/codex-security-harness-eval/governance/v0.3-a-minimal-serial-campaign-control-plane-v2-freeze-acceptance-and-final-pass-locked-decision-governance-v2-20261015/GOVERNANCE_LOCK.json"),
    "fixture_runner_lock": Path("/home/nobcoder/codex-security-harness-eval/governance/v0.3-a-fixture-only-serial-campaign-execution-v2-frozen-evidence-acceptance-and-pass-locked-decision-governance-v1-20261016/GOVERNANCE_LOCK.json"),
}

VALIDATOR_CONTINUATION_GOVERNANCE_IDENTITY = (
    "V0_3_FIRST_REAL_SECURITY_WORKER_INVOCATION_V35_INDEPENDENT_VALIDATOR_V11_TREE_"
    "CANONICALIZATION_MISMATCH_PRELOCK_ERRATUM_AND_CONTINUATION_OR_SUCCESSOR_DECISION_GOVERNANCE_ONLY"
)
PROVENANCE_CONTINUATION_GOVERNANCE_IDENTITY = (
    "V0_3_FIRST_REAL_SECURITY_WORKER_INVOCATION_V35_CONTINUATION_RUN_SLOT_AND_STATIC_LOCK_"
    "PROVENANCE_BINDING_GAP_PRELOCK_ERRATUM_AND_CONTINUATION_DECISION_GOVERNANCE_ONLY"
)
HISTORICAL_PRELOCK_DIGESTS = {
    "results/prelock/unit-fixtures-run-0001.json": "b429af4eaff9403139ef41ba9145436ab4dac8778139d5b93f0e5ea632d3c36d",
    "results/prelock/primary-static-validation-run-0001.json": "81f3f6a449cf11dbc4faba8a070638fac2406e461d15e9753e89ba821d9e41ac",
    "results/prelock/independent-static-validation-run-0001.json": "56b1b6572dec7d83afbab91f427a336f7897db1fd5de94c2e3a14fee1a09346f",
}
PARTIAL_RUN_0002_DIGESTS = {
    "results/prelock/unit-fixtures-run-0002.json": "ebd5ff3a8251f59ae617bf0acfaa09f29f043bfb5bd000ee97b603cd056d3838",
}
CONTINUATION_GENERATION_ID = "V35_CONTINUATION_VALIDATION_GENERATION_RUN_0003"
CONTINUATION_SLOT = "run-0003"
CONTINUATION_CHAIN_FAMILIES = ("unit", "primary", "independent", "preflight", "closure")

CANONICAL_COMPATIBILITY_ACCEPTANCE_IDENTITY = "CODEX_RUNTIME_0_166_0_COMPATIBILITY_ACCEPTANCE"
CANONICAL_COMPATIBILITY_ACCEPTANCE_PATH = Path(
    "/home/nobcoder/codex-security-harness-eval/governance/"
    "v0.3-runtime-and-model-compatibility-execution-v8-codex-0-166-0-frozen-evidence-"
    "acceptance-and-pass-locked-decision-governance-v1-20261102/GOVERNANCE_LOCK.json"
)
CANONICAL_COMPATIBILITY_ACCEPTANCE_MANIFEST = CANONICAL_COMPATIBILITY_ACCEPTANCE_PATH.with_name(
    "GOVERNANCE_ARTIFACT_MANIFEST.json"
)
CANONICAL_COMPATIBILITY_GOVERNANCE_IDENTITY = (
    "V0_3_RUNTIME_AND_MODEL_COMPATIBILITY_EXECUTION_V8_CODEX_0_166_0_FROZEN_EVIDENCE_"
    "ACCEPTANCE_AND_PASS_LOCKED_DECISION_GOVERNANCE_ONLY"
)

SECURITY_WORKER_RUNTIME_SOURCE = Path("/home/nobcoder/v0.3-security-worker-runtime-v1-20261020")
SECURITY_WORKER_RUNTIME_ROOT = "974a483222726e40ffa0178b4b05d9e0ba8b361b40d53b74ca1d628cc92bcaf2"
V1_WORKSPACE = Path("/home/nobcoder/v0.3-first-real-security-worker-invocation-v1-20261020")
V1_CANONICAL_TREE_ROOT = "5604319bd56eb78cb1b4ef7bbeb578d34911b655901415affdd0950729ea0dfa"
V1_MEMBER_COUNT = 29
V2_WORKSPACE = Path("/home/nobcoder/v0.3-first-real-security-worker-invocation-v2-20261020")
V2_CANONICAL_TREE_ROOT = "f581655b70b77785d8b24c00b33af19ea8f24736f014bfe29ca2b36d4f1783be"
V2_MEMBER_COUNT = 42
V3_WORKSPACE = Path("/home/nobcoder/v0.3-first-real-security-worker-invocation-v3-20261020")
V3_CANONICAL_TREE_ROOT = "0af79bcff56147b6978db81ec6f7d951977cc357c9407bc2bee2a1fd71e9150e"
V3_MEMBER_COUNT = 100
V4_WORKSPACE = Path("/home/nobcoder/v0.3-first-real-security-worker-invocation-v4-20261020")
V4_CANONICAL_TREE_ROOT = "e2a319dfc6c31af46b8f0f136eb8ed2045f9c72b07625b0bbd25434e62726cac"
V4_MEMBER_COUNT = 104
V5_WORKSPACE = Path("/home/nobcoder/v0.3-first-real-security-worker-invocation-v5-20261020")
V5_CANONICAL_TREE_ROOT = "ec95c4806ce0b8bef7690de362bb4a8c25a6b785faf5ae47b23a5fa60abf6927"
V5_MEMBER_COUNT = 117
V6_WORKSPACE = Path("/home/nobcoder/v0.3-first-real-security-worker-invocation-v6-20261020")
V6_CANONICAL_TREE_ROOT = "0a2c0a29535150ce4abac1914752b3ae670655028fd1fecaa317826bed874522"
V6_MEMBER_COUNT = 115
V7_WORKSPACE = Path("/home/nobcoder/v0.3-first-real-security-worker-invocation-v7-20261020")
V7_CANONICAL_TREE_ROOT = "770e0cf5baa0935714fac0883a01c702d0d165508a503eb63d137c9c262cc736"
V7_MEMBER_COUNT = 39
V8_WORKSPACE = Path("/home/nobcoder/v0.3-first-real-security-worker-invocation-v8-20261020")
V8_CANONICAL_TREE_ROOT = "249a313cb1dc70c8d4ae0e84b119d83775d0e94eda35e5dfa85d2201cb728272"
V8_MEMBER_COUNT = 41
V9_WORKSPACE = Path("/home/nobcoder/v0.3-first-real-security-worker-invocation-v9-20261020")
V9_CANONICAL_TREE_ROOT = "fda938e26d02db9597cce34b027d8cc81db40db1d91164d0770dc7d41f25ab4e"
V9_MEMBER_COUNT = 50
V10_WORKSPACE = Path("/home/nobcoder/v0.3-first-real-security-worker-invocation-v10-20261020")
V10_CANONICAL_TREE_ROOT = "0150c34f0f8d6f7adce038714f07ef4b9acb1c76d0f0a1e051b1b30346261e91"
V10_MEMBER_COUNT = 127
V11_CANONICAL_TREE_ROOT = "6b41bc493b1876468de57cb82cb3b7de9bf811450f9579ee5e493473d75023ef"
V11_MEMBER_COUNT = 72
V11_STATIC_LOCK_SHA256 = "3da68aa2f89327b30bbbd35eaa354b3701a5d395c06a5e9dd6bb96a72ec31b96"
V11_OBSERVER_SELFTEST_SHA256 = "4565dc9cc0717a210324f646069b3e6ce10b6e954273059331ff2aede755c4c9"
V12_CANONICAL_TREE_ROOT = "869500949833341b4b2a37ceb520b411ae7312ac28c2c7eab00a4ac42bfb02d0"
V12_MEMBER_COUNT = 179
V12_STATIC_LOCK_SHA256 = "ad78706d95aff27db7bffb68f195cd191e4dcd7c7b86f266f0d4738d269c3611"
V12_FAILURE_EVIDENCE_FREEZE_SHA256 = "90f03eb5c38dc94064338943cc02426c2cddb63fe22e6fa725b981e335a6f517"
V13_CANONICAL_TREE_ROOT = "9efaac543137663806696dc3e69cf16b262d81f78609a57f2ca495cacd8187fb"
V13_MEMBER_COUNT = 58
V13_UNIT_FAILURE_SHA256 = "9c10ed8482d4df350ac11d82e0fabe0cc2a83005641007852cb43008068f86b8"
V14_FROZEN_TREE_ROOT = "7fa1cadc56eb1186fc4d9efef27f215c9369c6c94b3e09199912563abd8328d4"
V14_MEMBER_COUNT = 135
V14_UNIT_PASS_SHA256 = "3b91f58fc216c396b19988d90323b0f331adab50aa28068c08e9d2b726e82804"
V14_PRIMARY_FAILURE_SHA256 = "f4cbd3434d34b4c04f1fda19fb96904e4a356c9d59174fb1e7a41d54184b2cc5"
V14_CURRENT_MEMBER_COUNT = 137
V14_CURRENT_TREE_ROOT = "3660b20463a2f83dec08c04ac0ff74d553263a7e1c82ddf725b8cdffa460af68"
V14_UNAUTHORIZED_ADDITIONS = {
    "results/prelock/fresh-preflight-run-0001.json": "b75552ef68c5d5de2238ea5787b3ee7e04ae2fc098fc9c8b7666141ed3597562",
    "results/prelock/dependency-closure-run-0001.json": "a437d4f2a8a8032ebdda5f6a6f3c83bc7a3e4f89494dc7cf1bf706ac852a972b",
}
V15_FROZEN_FILES = {
    "results/prelock/unit-fixtures-run-0001.json": "38e3b1c71dee5c0d0c91f4134e439f2f0442626faa23747ac306063b9cdaa6cc",
    "results/prelock/primary-static-validation-run-0001.json": "a308968912f1e7722d2bf700c5aaf3256c176b1d4f584a4b269596a0fd8c17c9",
    "results/prelock/independent-static-validation-run-0001.json": "69053c72214931839eab7743d90e11147cd03ab46cf6fd09fcda9633720d0381",
    "results/prelock/PRELOCK_TERMINAL_ENGINEERING_RESULT.json": "ece516b4641d1f1b2506e9025620e595f09dc1782373abcd23cecab177eaf601",
    "results/prelock/PRELOCK_FAILURE_EVIDENCE_MANIFEST.json": "6011559bd1522fd9d71934383b8df587fc558fb379c8608627877c457c7db443",
}
V16_WORKSPACE_TREE_ROOT = "5c99e1c8c1e5048ee3a9c607e0bceffc273743b91a245bf7a913f832af0636b5"
V16_WORKSPACE_MEMBER_COUNT = 146
V16_FAILURE_MANIFEST_SHA256 = "b39a41077ea660427d8cf55faab94286b48cfe0adb9e73a9133a814f6e80268c"
V16_UNIT_PASS_SHA256 = "da3eec46df7120c3f3a105aa2ad69b9ec7979b7c0bb94f772494e9395ec4e31f"
V16_PRIMARY_FAILURE_SHA256 = "e693592d8306d4b639f08c49c9b18b175f9dc9630ed4205b4712904a67bbf218"
V16_TERMINAL_RESULT_SHA256 = "b2b323a18168d7d7d69d5a18a08daaec228a4bac799fc28d5034d8eb69958de8"
V16_IMPLICIT_PYC_SHA256 = "d28afe1bf85796431bdd7e8c7a0d05da01f99b74af217084372befbe178208b0"
V16_NON_NORMATIVE_FLATTENED_ROOT = "a5ec0db34da898d64859e0e3535d74929eed4f5b047f67f37d1fe3d90a88ea63"
V17_WORKSPACE_TREE_ROOT = "576f3773617ad0adab5a3488ad395b20e753f8cb24c6b04ddd97ee8a65498373"
V17_WORKSPACE_MEMBER_COUNT = 150
V17_PRELOCK_MEMBER_COUNT = 78
V17_UNIT_PASS_SHA256 = "71d7fb3d18653cea15dfe6312e30affa8b911b9d1520f09c3449766e084df445"
V17_PRIMARY_PASS_SHA256 = "31f3911b6a0ad0d5781debafbfb781eb865cd7c966aa7723b8bb05cde3006ff9"
V17_INDEPENDENT_FAILURE_SHA256 = "02e41521f90af9dc1aa55ed26d7769b07b44a6bcdf3b643d7b96b5c662be6e23"
V17_TERMINAL_RESULT_SHA256 = "f86711afddf68b287a5ed9cf5f327ef9de146dd1601d5497a173ba07c65d07b0"

AUTHORITATIVE_ARTIFACT_DIGEST_BINDING = (
    WORKSPACE / "contracts/AUTHORITATIVE_ARTIFACT_DIGEST_BINDINGS.json"
)

OPERATION_KEYS = (
    "candidate_promotions",
    "capability_edges",
    "codex_worker_invocations",
    "credential_operations",
    "daybreak_invocations",
    "exploit_replays",
    "external_network_operations",
    "parallel_operations",
    "subagent_invocations",
    "submission_operations",
    "target_operations",
    "worker_invocations",
)

FORBIDDEN_OUTPUT_KEYS = frozenset(
    {
        "state",
        "verdict",
        "severity",
        "strong",
        "validated",
        "report_ready",
        "authority",
        "authorization",
        "capability_edge",
        "promote",
    }
)

LEGACY_SOURCE_PATHS = (
    "bind_authoritative_artifact_digests.py",
    "bind_final_prompt.py",
    "build_module_bindings.py",
    "build_symbol_bindings.py",
    "HUMAN_GATE.json",
    "ROUTING_LEDGER.json",
    "contracts/AUTHORITY_CEILING.json",
    "contracts/AUTHORITATIVE_PREDECESSOR_REGISTRY.json",
    "contracts/AUTHORITATIVE_PREDECESSOR_RESOLUTION_CONTRACT.json",
    "contracts/ARTIFACT_DIGEST_BINDING_CONTRACT.json",
    "contracts/AUTHORITATIVE_ARTIFACT_DIGEST_BINDINGS.json",
    "contracts/CONTINUATION_VALIDATION_EVIDENCE_PROVENANCE_CONTRACT.json",
    "contracts/EVIDENCE_CONTRACT.json",
    "contracts/EXECUTION_CONTRACT.json",
    "contracts/IDENTITY_BINDINGS.json",
    "contracts/OPERATION_COUNTERS.json",
    "contracts/PROMPT_IDENTITY_BINDING.json",
    "contracts/PROMPT_IDENTITY_BINDING_CONTRACT.json",
    "contracts/PROMPT_POLICY_CONTRACT.json",
    "contracts/EXPECTED_EXECUTION_PLAN.json",
    "contracts/BIND_DESTINATION_FEASIBILITY_CONTRACT.json",
    "contracts/STRICT_SCHEMA_COMPATIBILITY_CONTRACT.json",
    "contracts/TRACE_AND_DIAGNOSTIC_CONTRACT.json",
    "contracts/TYPED_FD_ANNOTATION_CONTRACT.json",
    "contracts/PROCESS_LINEAGE_CONTRACT.json",
    "contracts/CROSS_NAMESPACE_PROCESS_IDENTITY_CONTRACT.json",
    "contracts/SELFTEST_LIFECYCLE_EVIDENCE_CONTRACT.json",
    "contracts/TEMPORAL_PROCESS_IDENTITY_OBSERVER_CONTRACT.json",
    "contracts/TEMPORAL_TRACE_CORRELATION_CONTRACT.json",
    "contracts/MOUNT_PROVENANCE_WRITE_CONTRACT.json",
    "contracts/TOKEN_BUDGET_CONTRACT.json",
    "contracts/FAILURE_EVIDENCE_FREEZE_CONTRACT.json",
    "contracts/GATE_SEPARATION_CONTRACT.json",
    "contracts/LIFECYCLE_SOURCE_ORDER_CONTRACT.json",
    "contracts/LOCKED_ENTRYPOINT_SYMBOL_BINDING_MANIFEST.json",
    "contracts/LOCKED_ENTRYPOINT_SYMBOL_RESOLUTION_CONTRACT.json",
    "contracts/SUCCESSOR_V19_REQUIREMENTS.json",
    "contracts/SUCCESSOR_V35_REQUIREMENTS.json",
    "contracts/CANONICAL_PREDECESSOR_BINDING.json",
    "contracts/CANONICAL_PREDECESSOR_BINDING_CONTRACT.json",
    "contracts/CANONICAL_EXTERNAL_PREDECESSOR_ARTIFACT_BINDING.json",
    "contracts/CANONICAL_EXTERNAL_PREDECESSOR_ARTIFACT_BINDING_CONTRACT.json",
    "contracts/CANONICAL_MODULE_BINDINGS.json",
    "contracts/CANONICAL_VALIDATION_MODULE_RESOLUTION_CONTRACT.json",
    "contracts/V21_FROZEN_FAILURE_EVIDENCE_BINDING.json",
    "contracts/V21_MODULE_RESOLUTION_DEFECT_ADJUDICATION.json",
    "contracts/V21_TERMINAL_AND_V22_SUCCESSOR_DECISION.json",
    "contracts/V21_TO_V22_GOVERNANCE_ARTIFACT_MANIFEST.json",
    "contracts/V21_TO_V22_GOVERNANCE_LOCK.json",
    "contracts/V22_MODULE_RESOLUTION_REGRESSION_MATRIX.json",
    "contracts/V20_FROZEN_FAILURE_EVIDENCE_BINDING.json",
    "contracts/V20_TERMINAL_AND_V21_SUCCESSOR_DECISION.json",
    "contracts/V20_TO_V21_GOVERNANCE_ARTIFACT_MANIFEST.json",
    "contracts/V20_TO_V21_GOVERNANCE_LOCK.json",
    "contracts/V21_EXTERNAL_PREDECESSOR_ARTIFACT_REGRESSION_MATRIX.json",
    "contracts/V19_FROZEN_FAILURE_EVIDENCE_BINDING.json",
    "contracts/V19_TERMINAL_AND_V20_SUCCESSOR_DECISION.json",
    "contracts/V19_TO_V20_GOVERNANCE_ARTIFACT_MANIFEST.json",
    "contracts/V19_TO_V20_GOVERNANCE_LOCK.json",
    "contracts/V21_PREDECESSOR_BINDING_REGRESSION_MATRIX.json",
    "contracts/NORMATIVE_V16_TREE_CANONICALIZATION_CONTRACT.json",
    "contracts/V16_CANONICALIZATION_REGRESSION_MATRIX.json",
    "contracts/I008A_CANONICALIZATION_ORDER_ADJUDICATION.json",
    "contracts/V17_PRELOCK_FROZEN_EVIDENCE_BINDING.json",
    "contracts/V17_TERMINAL_AND_V18_SUCCESSOR_DECISION.json",
    "contracts/V18_FROZEN_EVIDENCE_BINDING.json",
    "contracts/V18_TERMINAL_AND_V19_SUCCESSOR_DECISION.json",
    "contracts/V19_IMPORT_BINDING_REGRESSION_MATRIX.json",
    "contracts/V19_IMPORT_BINDING_REGRESSION_MATRIX.json",
    "contracts/SUCCESSOR_V19_PYTHON_CACHE_AND_WRITE_BOUNDARY_CONTRACT.json",
    "contracts/SUCCESSOR_V35_PYTHON_CACHE_AND_WRITE_BOUNDARY_CONTRACT.json",
    "contracts/RUNTIME_FILESYSTEM_MUTATION_ACCOUNTING_CONTRACT.json",
    "contracts/PYTHON_RUNTIME_SIDE_EFFECT_POLICY.json",
    "contracts/V16_FAILURE_AND_V19_REGRESSION_MATRIX.json",
    "contracts/V16_FAILURE_AND_V21_REGRESSION_MATRIX.json",
    "contracts/V16_FROZEN_PRELOCK_EVIDENCE_BINDING.json",
    "contracts/V19_WORKSPACE_WRITE_BOUNDARY_CONTRACT.json",
    "contracts/V35_WORKSPACE_WRITE_BOUNDARY_CONTRACT.json",
    "contracts/V14_V15_FAILURE_AND_V19_REGRESSION_MATRIX.json",
    "contracts/V14_V15_FAILURE_AND_V21_REGRESSION_MATRIX.json",
    "contracts/V14_CURRENT_APPEND_ONLY_DRIFT_ADJUDICATION.json",
    "contracts/V14_PREINCIDENT_FROZEN_IDENTITY.json",
    "contracts/V15_FROZEN_PRELOCK_EVIDENCE_BINDING.json",
    "contracts/V14_FROZEN_EVIDENCE_BINDING.json",
    "contracts/V14_FROZEN_EVIDENCE_SNAPSHOT_MANIFEST.json",
    "contracts/COMPLETE_COVERAGE_INVARIANT.json",
    "contracts/ADVERSARIAL_SELFTEST_FAILURE_DECOMPOSITION.json",
    "contracts/WORKER_REQUEST.json",
    "fixture/context/AGENTS.md",
    "fixture/fixture.json",
    "fixture/worker-prompt.txt",
    "freeze_evidence.py",
    "preflight.py",
    "prepare_static_lock.py",
    "runtime-config-candidate/config.toml",
    "schemas/CONTROLLER_WORKER_RESULT.schema.json",
    "schemas/CONTINUATION_VALIDATION_EVIDENCE_PROVENANCE.schema.json",
    "schemas/SELFTEST_LIFECYCLE_EVIDENCE.schema.json",
    "schemas/WORKER_MODEL_OUTPUT.schema.json",
    "src/__init__.py",
    "src/invocation_v35.py",
    "src/module_resolution_v35.py",
    "src/external_artifact_binding_v35.py",
    "src/predecessor_binding_v35.py",
    "src/runner_v35.py",
    "src/short_lived_child_v35.py",
    "src/symbol_resolution_v35.py",
    "src/topology_observer_v35.py",
    "src/worker_launch_gate_v35.py",
    "src/workspace_boundary_v35.py",
    "validate_locked_pre_attempt.py",
    "validate_locked_external_artifacts.py",
    "validate_locked_symbols.py",
    "tests/run_unit_fixtures.py",
    "validators/independent_static_validate.py",
    "validators/post_validate.py",
    "validators/primary_static_validate.py",
    "verify_static_lock.py",
)

# V26 freezes the complete fresh-workspace source set instead of inheriting
# stale successor filenames from an earlier invocation. Runtime evidence,
# validation results, and lock outputs are separately versioned below.
SOURCE_PATHS = tuple(
    sorted(
        path.relative_to(WORKSPACE).as_posix()
        for path in WORKSPACE.rglob("*")
        if path.is_file()
        and not path.is_relative_to(WORKSPACE / "results")
        and not path.is_relative_to(STATIC_RUN)
        and path.name not in {
            "STATIC_SOURCE_MANIFEST.json",
            "STATIC_EXECUTION_LOCK.json",
            "STATIC_EXECUTION_LOCK_VERIFICATION.json",
        }
        and "__pycache__" not in path.parts
        and path.suffix != ".pyc"
    )
)

PRELOCK_RESULT_PATHS = (
    "results/prelock/prelock-storage-lifecycle-run-0001.json",
    "results/prelock/host-output-bind-source-lifecycle-run-0001.json",
    "results/prelock/unit-fixtures-run-0001.json",
    "results/prelock/primary-static-validation-run-0001.json",
    "results/prelock/independent-static-validation-run-0001.json",
    "results/prelock/fresh-preflight-run-0001.json",
    "results/prelock/dependency-closure-run-0001.json",
)

LOCK_OUTPUTS = {
    "STATIC_SOURCE_MANIFEST.json",
    "STATIC_EXECUTION_LOCK.json",
    "STATIC_EXECUTION_LOCK_VERIFICATION.json",
}
PRELOCK_SELFTEST_ROOT = WORKSPACE / "results/prelock/adversarial-selftests-run-0001"


class ContractViolation(ValueError):
    """Structured input or output violated a frozen contract."""


def semantic_lifecycle_anchor_verdict(source: str) -> dict[str, Any]:
    """Primary AST classifier for the five authoritative runner lifecycle events."""

    try:
        tree = ast.parse(source)
    except SyntaxError as exc:
        return {"status": "FAIL_CLOSED", "reason": "RUNNER_AST_INVALID", "error": str(exc)}

    anchors: dict[str, list[tuple[int, int]]] = {name: [] for name in "ABCDE"}

    def direct_call(node: ast.AST, function: str, owner: str | None = None) -> bool:
        if not isinstance(node, ast.Call):
            return False
        if owner is None:
            return isinstance(node.func, ast.Name) and node.func.id == function
        return (
            isinstance(node.func, ast.Attribute)
            and node.func.attr == function
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == owner
        )

    def exact_assignment(node: ast.AST, target: str, function: str, owner: str | None = None) -> bool:
        return (
            isinstance(node, ast.Assign)
            and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name)
            and node.targets[0].id == target
            and direct_call(node.value, function, owner)
        )

    def exact_attempt_creation(node: ast.AST) -> bool:
        if not isinstance(node, ast.Expr) or not direct_call(node.value, "append_only_json"):
            return False
        call = node.value
        if not call.args:
            return False
        operand = call.args[0]
        return (
            isinstance(operand, ast.BinOp)
            and isinstance(operand.op, ast.Div)
            and isinstance(operand.left, ast.Name)
            and operand.left.id == "STATIC_RUN"
            and isinstance(operand.right, ast.Constant)
            and operand.right.value == "ATTEMPT_MARKER.json"
        )

    for node in ast.walk(tree):
        event = None
        if exact_assignment(node, "observer_process", "Popen", "subprocess"):
            event = "A"
        elif exact_assignment(node, "observer_ready", "wait_for_json"):
            event = "B"
        elif exact_assignment(node, "process", "Popen", "subprocess"):
            event = "C"
        elif exact_assignment(node, "trace_ready", "any"):
            event = "D"
        elif exact_attempt_creation(node):
            event = "E"
        if event is not None:
            anchors[event].append((node.lineno, node.col_offset))

    unique = all(len(anchors[name]) == 1 for name in "ABCDE")
    positions = [anchors[name][0] for name in "ABCDE"] if unique else []
    ordered = unique and positions == sorted(positions)
    checks = {
        "exactly_one_authoritative_anchor_each": unique,
        "exact_order_A_lt_B_lt_C_lt_D_lt_E": ordered,
    }
    return {
        "status": "PASS" if all(checks.values()) else "FAIL_CLOSED",
        "checks": checks,
        "anchors": {name: [{"line": line, "column": column} for line, column in values] for name, values in anchors.items()},
        "ordered_positions": [{"line": line, "column": column} for line, column in positions],
    }


def canonical_prompt_words(text: str) -> tuple[str, ...]:
    """Normalize representation while preserving the words that carry policy semantics."""

    normalized = unicodedata.normalize("NFKC", text.replace("\r\n", "\n").replace("\r", "\n")).casefold()
    return tuple(re.findall(r"[a-z0-9]+(?:[-'][a-z0-9]+)*", normalized))


def _has_word_sequence(words: tuple[str, ...], sequence: tuple[str, ...]) -> bool:
    width = len(sequence)
    return any(words[index : index + width] == sequence for index in range(len(words) - width + 1))


def prompt_policy_verdict(text: str) -> dict[str, Any]:
    """Return a deterministic, fail-closed verdict for the frozen prompt restrictions.

    Newlines, CRLF, tabs, repeated spaces, wrapping, and the contracted two-sentence
    network/target form are representation variants. Weakening or inversion remains a
    semantic failure even when a required phrase is also present.
    """

    words = canonical_prompt_words(text)
    canonical_text = " ".join(words)
    tool_denial = _has_word_sequence(words, PROMPT_REQUIRED_PROPOSITIONS["tool_denial"][0])
    network_variants = PROMPT_REQUIRED_PROPOSITIONS["network_and_target_denial"]
    combined = _has_word_sequence(words, network_variants[0])
    separate = all(_has_word_sequence(words, clause) for clause in network_variants[1])
    weakening_markers = [
        marker
        for marker in PROMPT_WEAKENING_OR_INVERSION_MARKERS
        if marker in canonical_text
    ]
    checks = {
        "tool_denial": tool_denial,
        "network_and_target_denial": combined or separate,
        "no_weakening_or_inversion_marker": not weakening_markers,
    }
    return {
        "status": "PASS" if all(checks.values()) else "FAIL_CLOSED",
        "checks": checks,
        "matched_network_form": "COMBINED" if combined else "SEPARATE" if separate else "NONE",
        "weakening_or_inversion_markers": weakening_markers,
        "canonical_word_count": len(words),
    }


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def canonical_json_sha256(value: Any) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def append_only_json(path: Path, payload: Mapping[str, Any]) -> None:
    relative = path.relative_to(WORKSPACE).as_posix() if path.is_absolute() else str(path)
    guarded_json_once(
        path,
        dict(payload),
        operation_identity=f"APPEND_ONLY_JSON:{relative}",
        generation=f"V35_ARTIFACT:{relative}",
    )


def safe_regular_file(path: Path) -> bool:
    try:
        info = path.lstat()
    except FileNotFoundError:
        return False
    return stat.S_ISREG(info.st_mode) and not stat.S_ISLNK(info.st_mode)


def normative_component_path_key(relative_posix_path: str) -> tuple[bytes, ...]:
    """Exact frozen V16 ordering: compare UTF-8 path components as a tuple."""
    if not relative_posix_path or "\\" in relative_posix_path:
        raise ValueError("non-canonical relative POSIX path")
    parts = tuple(relative_posix_path.split("/"))
    if any(part in {"", ".", ".."} for part in parts):
        raise ValueError("non-canonical relative POSIX path component")
    return tuple(part.encode("utf-8", errors="strict") for part in parts)


def normative_frozen_tree(root: Path) -> tuple[str, int]:
    """Recompute a tree from exact file bytes and normative component ordering."""
    rows: list[tuple[tuple[bytes, ...], str, str]] = []
    for path in root.rglob("*"):
        if path.is_symlink():
            raise ValueError(f"symlink is not a canonical member: {path}")
        if path.is_file():
            relative = path.relative_to(root).as_posix()
            rows.append((normative_component_path_key(relative), relative, sha256_file(path)))
    rows.sort(key=lambda row: row[0])
    serialized = b"".join(
        relative.encode("utf-8") + b"\x00" + digest.encode("ascii") + b"\x0a"
        for _, relative, digest in rows
    )
    return hashlib.sha256(serialized).hexdigest(), len(rows)


def flattened_non_normative_tree(root: Path) -> tuple[str, int]:
    """Regression oracle for the explicitly rejected flattened-path ordering."""
    rows: list[tuple[bytes, str, str]] = []
    for path in root.rglob("*"):
        if path.is_symlink():
            raise ValueError(f"symlink is not a canonical member: {path}")
        if path.is_file():
            relative = path.relative_to(root).as_posix()
            rows.append((relative.encode("utf-8"), relative, sha256_file(path)))
    rows.sort(key=lambda row: row[0])
    serialized = b"".join(
        relative.encode("utf-8") + b"\x00" + digest.encode("ascii") + b"\x0a"
        for _, relative, digest in rows
    )
    return hashlib.sha256(serialized).hexdigest(), len(rows)


def selftest_lifecycle_evidence_verdict(
    *,
    artifact_present: bool,
    artifact_status: str | None,
    artifact_digest: str | None,
    expected_digest: str | None,
    artifact_lock_digest: str | None,
    current_lock_digest: str | None,
    artifact_source_root: str | None,
    current_source_root: str | None,
    artifact_observer_digest: str | None,
    current_observer_digest: str | None,
    candidate_count: int,
    historical_v11_preserved: bool,
) -> dict[str, Any]:
    """Adjudicate read-only self-test consumption without path-based trust."""

    checks = {
        "artifact_present": artifact_present,
        "artifact_pass": artifact_status == "PASS",
        "artifact_digest_exact": artifact_digest is not None and artifact_digest == expected_digest,
        "current_static_lock_exact": artifact_lock_digest is not None
        and artifact_lock_digest == current_lock_digest,
        "current_source_root_exact": artifact_source_root is not None
        and artifact_source_root == current_source_root,
        "current_observer_identity_exact": artifact_observer_digest is not None
        and artifact_observer_digest == current_observer_digest,
        "exactly_one_candidate": candidate_count == 1,
        "historical_v11_preserved": historical_v11_preserved,
    }
    return {
        "status": "PASS_READ_ONLY_CONSUMPTION" if all(checks.values()) else "FAIL_CLOSED_BEFORE_ATTEMPT",
        "strategy": "CONSUME_LOCK_BOUND_IMMUTABLE_PASS_ARTIFACT",
        "checks": checks,
        "rewrite_performed": False,
        "attempt_count": 0,
        "worker_invocation_count": 0,
        "codex_as_worker_invocation_count": 0,
    }


def continuation_provenance_selection_verdict(
    *,
    historical_present: bool,
    historical_digest_match: bool,
    partial_history_present: bool,
    partial_history_digest_match: bool,
    authorities_valid: bool,
    mutation_scope_valid: bool,
    current_candidates: list[Mapping[str, Any]],
    selected_generation: str,
) -> dict[str, Any]:
    """Select only the governance-bound complete run-0003 generation."""

    expected_families = set(CONTINUATION_CHAIN_FAMILIES)
    admissible = [
        item for item in current_candidates
        if item.get("generation") == CONTINUATION_SLOT
        and item.get("status") in {"PASS", "READY_FOR_FINAL_CLOSURE_CHECK"}
        and item.get("digest_match") is True
        and item.get("produced_after_authority") is True
        and item.get("authority_binding_match") is True
        and item.get("scope_binding_match") is True
        and item.get("generation_identity") == CONTINUATION_GENERATION_ID
    ]
    families = [str(item.get("family")) for item in admissible]
    checks = {
        "historical_present": historical_present,
        "historical_digest_match": historical_digest_match,
        "partial_history_present": partial_history_present,
        "partial_history_digest_match": partial_history_digest_match,
        "authorities_valid": authorities_valid,
        "mutation_scope_valid": mutation_scope_valid,
        "selected_generation_explicit": selected_generation == CONTINUATION_SLOT,
        "exact_complete_family_set": set(families) == expected_families and len(families) == len(expected_families),
        "no_mixed_generation": all(item.get("generation") == CONTINUATION_SLOT for item in current_candidates),
        "exactly_one_per_family": all(families.count(name) == 1 for name in expected_families),
    }
    return {
        "status": "PASS" if all(checks.values()) else "FAIL_CLOSED_BEFORE_STATIC_LOCK",
        "checks": checks,
        "selected_generation": CONTINUATION_SLOT if all(checks.values()) else None,
        "selected_families": sorted(families),
        "historical_role": "IMMUTABLE_ADMISSIBLE_HISTORY",
        "partial_run_0002_role": "IMMUTABLE_INCOMPLETE_HISTORY_NOT_CURRENT_READINESS",
        "supersession_scope": "RUN_0003_SUPERSEDES_PRIOR_RUNS_FOR_EXECUTION_READINESS_ONLY_NOT_HISTORY",
    }


def continuation_governance_authority_records() -> list[dict[str, Any]]:
    specifications = (
        (
            "VALIDATOR_ONLY_CONTINUATION_AUTHORITY",
            PREDECESSOR_PATHS["i006_continuation_governance_lock"],
            EXPECTED_DIGESTS["i006_continuation_governance_lock"],
            VALIDATOR_CONTINUATION_GOVERNANCE_IDENTITY,
            "CONTINUATION_V19_INDEPENDENT_VALIDATOR_CANONICALIZATION_ONLY_CORRECTION_AUTHORIZED",
        ),
        (
            "STATIC_LOCK_PROVENANCE_CONTINUATION_AUTHORITY",
            PREDECESSOR_PATHS["provenance_continuation_governance_lock"],
            EXPECTED_DIGESTS["provenance_continuation_governance_lock"],
            PROVENANCE_CONTINUATION_GOVERNANCE_IDENTITY,
            "CONTINUATION_V19_VALIDATION_AND_STATIC_LOCK_PROVENANCE_CORRECTION_AUTHORIZED",
        ),
    )
    records: list[dict[str, Any]] = []
    for role, path, expected_digest, identity, decision in specifications:
        safe = safe_regular_file(path)
        artifact = load_json(path) if safe else {}
        actual_digest = sha256_file(path) if safe else None
        checks = {
            "safe_regular": safe,
            "digest_match": actual_digest == expected_digest,
            "identity_match": artifact.get("governance_identity") == identity,
            "status_pass_locked": artifact.get("status") == "PASS_LOCKED_GOVERNANCE_ONLY",
            "decision_match": artifact.get("decision") == decision,
        }
        records.append({
            "role": role,
            "path": str(path),
            "sha256": actual_digest,
            "expected_sha256": expected_digest,
            "governance_identity": artifact.get("governance_identity"),
            "status": artifact.get("status"),
            "lock_mtime_ns": path.stat().st_mtime_ns if safe else None,
            "checks": checks,
            "verdict": "PASS" if all(checks.values()) else "FAIL_CLOSED",
        })
    return records


def continuation_mutation_scope_attestation() -> dict[str, Any]:
    snapshot = load_json(PREDECESSOR_PATHS["i006_continuation_snapshot"])
    previous_scope = load_json(PREDECESSOR_PATHS["i006_continuation_scope_lock"])
    current_scope = load_json(PREDECESSOR_PATHS["provenance_continuation_scope_lock"])
    baseline = {item["path"]: item["sha256"] for item in snapshot.get("members", [])}
    mutable = set(previous_scope.get("source_mutation_allowlist", [])) | set(current_scope.get("mutable_allowlist", []))
    allowed_additions = set(current_scope.get("new_file_allowlist", [])) | set(current_scope.get("append_only_output_allowlist", [])) | {
        "results/prelock/unit-fixtures-run-0002.json",
    }
    actual = {
        path.relative_to(WORKSPACE).as_posix()
        for path in WORKSPACE.rglob("*")
        if (path.is_file() or path.is_symlink()) and not path.is_relative_to(STATIC_RUN)
    }
    protected_drift = sorted(
        relative
        for relative, expected_digest in baseline.items()
        if relative not in mutable
        and (not safe_regular_file(WORKSPACE / relative) or sha256_file(WORKSPACE / relative) != expected_digest)
    )
    historical_drift = sorted(
        relative
        for relative, expected_digest in HISTORICAL_PRELOCK_DIGESTS.items()
        if not safe_regular_file(WORKSPACE / relative) or sha256_file(WORKSPACE / relative) != expected_digest
    )
    unexpected = sorted(actual - set(baseline) - allowed_additions - mutable)
    missing_baseline = sorted(relative for relative in baseline if relative not in actual)
    changed_authorized = sorted(
        relative
        for relative, expected_digest in baseline.items()
        if relative in mutable
        and safe_regular_file(WORKSPACE / relative)
        and sha256_file(WORKSPACE / relative) != expected_digest
    )
    checks = {
        "governance_scope_exact": set(current_scope.get("mutable_allowlist", [])) == {
            "bind_authoritative_artifact_digests.py", "contracts/AUTHORITATIVE_ARTIFACT_DIGEST_BINDINGS.json",
            "contracts/CONTINUATION_VALIDATION_EVIDENCE_PROVENANCE_CONTRACT.json", "preflight.py",
            "prepare_static_lock.py", "schemas/CONTINUATION_VALIDATION_EVIDENCE_PROVENANCE.schema.json",
            "src/invocation_v35.py", "tests/run_unit_fixtures.py", "validators/independent_static_validate.py",
            "validators/primary_static_validate.py", "verify_static_lock.py",
        },
        "protected_members_byte_identical": not protected_drift,
        "historical_run_0001_byte_identical": not historical_drift,
        "partial_run_0002_byte_identical": all(
            safe_regular_file(WORKSPACE / relative) and sha256_file(WORKSPACE / relative) == expected
            for relative, expected in PARTIAL_RUN_0002_DIGESTS.items()
        ),
        "no_unexpected_members": not unexpected,
        "no_missing_baseline_members": not missing_baseline,
        "changed_existing_members_authorized": set(changed_authorized).issubset(mutable),
    }
    return {
        "status": "PASS" if all(checks.values()) else "FAIL_CLOSED",
        "checks": checks,
        "protected_member_drift_count": len(protected_drift),
        "protected_member_drift": protected_drift,
        "historical_run_0001_drift": historical_drift,
        "unexpected_member_count": len(unexpected),
        "unexpected_members": unexpected,
        "missing_baseline_members": missing_baseline,
        "authorized_changed_existing_members": changed_authorized,
        "mutable_allowlist": sorted(mutable),
    }


def continuation_evidence_metadata(family: str) -> dict[str, Any]:
    if family not in CONTINUATION_CHAIN_FAMILIES:
        raise ContractViolation(f"unknown continuation validation family: {family}")
    authorities = continuation_governance_authority_records()
    scope = continuation_mutation_scope_attestation()
    if any(item["verdict"] != "PASS" for item in authorities) or scope["status"] != "PASS":
        raise ContractViolation("continuation governance authority or mutation scope is not admissible")
    return {
        "record_type": "V35_CONTINUATION_VALIDATION_EVIDENCE_PROVENANCE",
        "produced_at_unix_ns": time.time_ns(),
        "validation_generation": CONTINUATION_SLOT,
        "validation_generation_identity": CONTINUATION_GENERATION_ID,
        "validation_family": family,
        "complete_chain_members": list(CONTINUATION_CHAIN_FAMILIES),
        "authority_chain": [
            {
                "role": item["role"],
                "path": item["path"],
                "sha256": item["sha256"],
                "governance_identity": item["governance_identity"],
                "status": item["status"],
                "lock_mtime_ns": item["lock_mtime_ns"],
            }
            for item in authorities
        ],
        "historical_validation": {
            "identity": "independent-static-validation-run-0001.json",
            "status": "FAIL_CLOSED",
            "role": "IMMUTABLE_HISTORICAL_FAILURE_EVIDENCE",
            "sha256": HISTORICAL_PRELOCK_DIGESTS["results/prelock/independent-static-validation-run-0001.json"],
        },
        "partial_run_0002": {"identity": "unit-fixtures-run-0002.json", "role": "IMMUTABLE_INCOMPLETE_HISTORY_NOT_CURRENT_READINESS", "sha256": PARTIAL_RUN_0002_DIGESTS["results/prelock/unit-fixtures-run-0002.json"]},
        "current_admissible_generation": {"identity": CONTINUATION_SLOT, "role": "CURRENT_EXECUTION_READINESS_GENERATION"},
        "mutation_scope_attestation": {
            "status": scope["status"],
            "unexpected_member_count": scope["unexpected_member_count"],
            "protected_member_drift_count": scope["protected_member_drift_count"],
        },
    }


def continuation_validation_provenance_precheck(
    required_current: tuple[str, ...] = ("unit", "primary", "independent"),
) -> dict[str, Any]:
    authorities = continuation_governance_authority_records()
    scope = continuation_mutation_scope_attestation()
    result_paths = {
        "unit": WORKSPACE / "results/prelock/unit-fixtures-run-0003.json",
        "primary": WORKSPACE / "results/prelock/primary-static-validation-run-0003.json",
        "independent": WORKSPACE / "results/prelock/independent-static-validation-run-0003.json",
        "preflight": WORKSPACE / "results/prelock/fresh-preflight-run-0003.json",
        "closure": WORKSPACE / "results/prelock/dependency-closure-run-0003.json",
    }
    expected_status = {"unit": "PASS", "primary": "PASS", "independent": "PASS", "preflight": "PASS", "closure": "READY_FOR_FINAL_CLOSURE_CHECK"}
    max_authority_mtime = max((item["lock_mtime_ns"] or 0) for item in authorities)
    current: dict[str, Any] = {}
    for name in required_current:
        path = result_paths[name]
        safe = safe_regular_file(path)
        value = load_json(path) if safe else {}
        provenance = value.get("continuation_provenance", {}) if isinstance(value, Mapping) else {}
        authority_chain = provenance.get("authority_chain", []) if isinstance(provenance, Mapping) else []
        authority_binding_match = (
            len(authority_chain) == 2
            and [item.get("sha256") for item in authority_chain]
            == [EXPECTED_DIGESTS["i006_continuation_governance_lock"], EXPECTED_DIGESTS["provenance_continuation_governance_lock"]]
        )
        produced_at = provenance.get("produced_at_unix_ns") if isinstance(provenance, Mapping) else None
        current[name] = {
            "path": str(path),
            "safe_regular": safe,
            "status": value.get("status"),
            "expected_status": expected_status[name],
            "sha256": sha256_file(path) if safe else None,
            "authority_binding_match": authority_binding_match,
            "produced_after_authority": isinstance(produced_at, int) and produced_at > max_authority_mtime and safe and path.stat().st_mtime_ns >= max_authority_mtime,
            "scope_binding_match": provenance.get("mutation_scope_attestation", {}).get("status") == "PASS" if isinstance(provenance, Mapping) else False,
            "generation": provenance.get("validation_generation") if isinstance(provenance, Mapping) else None,
            "generation_identity": provenance.get("validation_generation_identity") if isinstance(provenance, Mapping) else None,
            "family": provenance.get("validation_family") if isinstance(provenance, Mapping) else None,
            "complete_chain_match": provenance.get("complete_chain_members") == list(CONTINUATION_CHAIN_FAMILIES) if isinstance(provenance, Mapping) else False,
        }
    candidates = [{**current[name], "identity": Path(current[name]["path"]).name, "digest_match": current[name]["safe_regular"]} for name in required_current]
    selection = continuation_provenance_selection_verdict(
        historical_present=safe_regular_file(WORKSPACE / "results/prelock/independent-static-validation-run-0001.json"),
        historical_digest_match=not scope["historical_run_0001_drift"],
        partial_history_present=all(safe_regular_file(WORKSPACE / relative) for relative in PARTIAL_RUN_0002_DIGESTS),
        partial_history_digest_match=all(sha256_file(WORKSPACE / relative) == expected for relative, expected in PARTIAL_RUN_0002_DIGESTS.items()),
        authorities_valid=all(item["verdict"] == "PASS" for item in authorities),
        current_candidates=candidates if set(required_current) == set(CONTINUATION_CHAIN_FAMILIES) else [],
        mutation_scope_valid=scope["status"] == "PASS",
        selected_generation=CONTINUATION_SLOT,
    )
    checks = {
        "authority_chain_pass": all(item["verdict"] == "PASS" for item in authorities),
        "mutation_scope_pass": scope["status"] == "PASS",
        "historical_run_0001_immutable": not scope["historical_run_0001_drift"],
        "required_current_results_present": all(current[name]["safe_regular"] for name in required_current),
        "required_current_results_status": all(current[name]["status"] == expected_status[name] for name in required_current),
        "required_current_results_after_authority": all(current[name]["produced_after_authority"] for name in required_current),
        "required_current_results_authority_bound": all(current[name]["authority_binding_match"] for name in required_current),
        "required_current_results_scope_bound": all(current[name]["scope_binding_match"] for name in required_current),
        "required_current_results_generation_bound": all(current[name]["generation"] == CONTINUATION_SLOT and current[name]["generation_identity"] == CONTINUATION_GENERATION_ID and current[name]["family"] == name and current[name]["complete_chain_match"] for name in required_current),
        "current_selection_pass": selection["status"] == "PASS" if set(required_current) == set(CONTINUATION_CHAIN_FAMILIES) else True,
    }
    return {
        "status": "PASS" if all(checks.values()) else "FAIL_CLOSED_BEFORE_STATIC_LOCK",
        "checks": checks,
        "authority_chain": authorities,
        "mutation_scope_attestation": scope,
        "current_results": current,
        "current_selection": selection,
        "historical_run_0001_digests": HISTORICAL_PRELOCK_DIGESTS,
        "partial_run_0002_digests": PARTIAL_RUN_0002_DIGESTS,
    }


def authoritative_artifact_paths() -> tuple[str, ...]:
    """Return the creation-closed V35 authoritative input-member identity set."""

    return tuple(path.relative_to(WORKSPACE).as_posix() for path in authoritative_input_paths())


def authoritative_artifact_digest_binding_verdict(
    *,
    binding: Mapping[str, Any],
    current_bytes: Mapping[str, bytes],
    reread_bytes: Mapping[str, bytes],
    predecessor_bytes: Mapping[str, bytes | None],
) -> dict[str, Any]:
    """Validate final-bytes-first successor digest binding without trusting a manifest."""

    rows = binding.get("members") if isinstance(binding, Mapping) else None
    rows = rows if isinstance(rows, list) else []
    indexed = {
        row.get("path"): row
        for row in rows
        if isinstance(row, Mapping) and isinstance(row.get("path"), str)
    }
    expected_paths = set(current_bytes)
    checks: dict[str, bool] = {
        "status_pass": binding.get("status") == "PASS_FINAL_BYTES_BOUND_REREAD_REHASHED",
        "execution_identity_exact": binding.get("execution_identity") == EXECUTION_IDENTITY,
        "generation_identity_exact": binding.get("generation_identity") == GENERATION_IDENTITY,
        "governance_lock_exact": binding.get("governance_lock_sha256") == EXPECTED_DIGESTS["v35_authorization_lock"],
        "predecessor_identity_exact": binding.get("predecessor_identity") == "V0_3_FIRST_REAL_SECURITY_WORKER_INVOCATION_V18",
        "predecessor_workspace_tree_exact": binding.get("predecessor_workspace_tree_sha256") == "c92f0bd0d7ea111d9bfd6d3d4e612e5b1cd763d70c69f47fef6a2907c0be0f4d",
        "predecessor_static_lock_exact": binding.get("predecessor_static_lock_sha256") == "7b59bb4e753c0aef7f05a3fea61484b21bfc8fe30b5b255e47d1ce393d964c12",
        "canonical_predecessor_binding_pass": binding.get("canonical_predecessor_binding_status") == "PASS",
        "sha256_algorithm": binding.get("digest_algorithm") == "SHA-256",
        "member_set_exact": set(indexed) == expected_paths,
        "member_count_exact": binding.get("member_count") == len(expected_paths) == len(rows),
        "post_bind_mutation_prohibited": binding.get("post_bind_mutation") == "PROHIBITED",
        "reread_and_rehash_pass": binding.get("reread_and_rehash") == "PASS",
        "zero_execution_counts": binding.get("attempt_count") == 0
        and binding.get("worker_invocation_count") == 0
        and binding.get("codex_as_worker_invocation_count") == 0,
    }
    failures: list[dict[str, str]] = []
    for relative in sorted(expected_paths):
        first = current_bytes[relative]
        reread = reread_bytes.get(relative)
        predecessor = predecessor_bytes.get(relative)
        row = indexed.get(relative, {})
        current_digest = hashlib.sha256(first).hexdigest()
        reread_digest = hashlib.sha256(reread).hexdigest() if isinstance(reread, bytes) else None
        predecessor_digest = hashlib.sha256(predecessor).hexdigest() if isinstance(predecessor, bytes) else None
        if predecessor is None:
            expected_relation = "NO_PREDECESSOR_ARTIFACT_FRESH_SUCCESSOR_DIGEST_BOUND"
        elif predecessor == first:
            expected_relation = "SUCCESSOR_BYTES_IDENTICAL_PREDECESSOR_DIGEST_MAY_REMAIN_VALID"
        else:
            expected_relation = "SUCCESSOR_BYTES_CHANGED_FRESH_SUCCESSOR_DIGEST_BOUND"
        member_checks = {
            "bound_digest_matches_final_bytes": row.get("sha256") == current_digest,
            "reread_digest_matches": reread == first and reread_digest == current_digest,
            "byte_count_matches": row.get("bytes") == len(first),
            "predecessor_digest_matches": row.get("predecessor_sha256") == predecessor_digest,
            "predecessor_relation_matches": row.get("predecessor_relation") == expected_relation,
            "changed_bytes_do_not_retain_predecessor_digest": not (
                predecessor is not None and predecessor != first and row.get("sha256") == predecessor_digest
            ),
        }
        if not all(member_checks.values()):
            failures.append({
                "path": relative,
                "reason": ",".join(key for key, value in member_checks.items() if not value),
            })
    checks["all_member_digests_and_relations"] = not failures
    return {
        "status": "PASS" if all(checks.values()) else "FAIL_CLOSED_BEFORE_FRESH_PREFLIGHT_AND_ATTEMPT",
        "checks": checks,
        "failures": failures,
        "member_count": len(rows),
        "attempt_count_if_failed": 0,
        "worker_invocation_count_if_failed": 0,
        "codex_as_worker_invocation_count_if_failed": 0,
    }


def authoritative_artifact_digest_precheck() -> dict[str, Any]:
    """Reread and independently rehash every bound contract/schema/fixture artifact."""

    contract_path = WORKSPACE / "contracts/ARTIFACT_DIGEST_BINDING_CONTRACT.json"
    paths = authoritative_artifact_paths()
    required = (AUTHORITATIVE_ARTIFACT_DIGEST_BINDING, contract_path)
    if not all(safe_regular_file(path) for path in required):
        return {
            "status": "FAIL_CLOSED_BEFORE_FRESH_PREFLIGHT_AND_ATTEMPT",
            "reason": "BINDING_OR_CONTRACT_MISSING_SYMLINKED_OR_NONREGULAR",
            "attempt_count_if_failed": 0,
            "worker_invocation_count_if_failed": 0,
            "codex_as_worker_invocation_count_if_failed": 0,
        }
    binding = load_json(AUTHORITATIVE_ARTIFACT_DIGEST_BINDING)
    contract = load_json(contract_path)
    current: dict[str, bytes] = {}
    reread: dict[str, bytes] = {}
    predecessors: dict[str, bytes | None] = {}
    unsafe: list[str] = []
    writable: list[str] = []
    for relative in paths:
        path = WORKSPACE / relative
        if not safe_regular_file(path) or path.resolve(strict=True) != path:
            unsafe.append(relative)
            continue
        current[relative] = path.read_bytes()
        reread[relative] = path.read_bytes()
        predecessor = V18_WORKSPACE / relative
        predecessors[relative] = predecessor.read_bytes() if safe_regular_file(predecessor) else None
        if stat.S_IMODE(path.stat().st_mode) & 0o222:
            writable.append(relative)
    verdict = authoritative_artifact_digest_binding_verdict(
        binding=binding,
        current_bytes=current,
        reread_bytes=reread,
        predecessor_bytes=predecessors,
    )
    expected_order = [
        "CONSTRUCT_FINAL_SUCCESSOR_ARTIFACT",
        "FINALIZE_EXACT_BYTES",
        "PROHIBIT_POST_FINALIZATION_MUTATION",
        "COMPUTE_SHA256_FROM_FINAL_EXACT_BYTES",
        "BIND_SHA256_TO_SUCCESSOR_IDENTITY",
        "REREAD_EXACT_ARTIFACT",
        "REHASH_REREAD_BYTES",
        "REQUIRE_FIRST_BOUND_AND_REREAD_DIGEST_EQUALITY",
        "VALIDATE_ADMISSIBLE_DEPENDENCY",
    ]
    contract_checks = {
        "artifact_set_complete": len(current) == len(paths) and not unsafe,
        "all_bound_artifacts_read_only": not writable,
        "normative_order_exact": contract.get("normative_order") == expected_order,
        "post_bind_mutation_prohibited": contract.get("post_bind_mutation") == "PROHIBITED",
        "inheritance_changed_requires_fresh": contract.get("digest_inheritance", {}).get(
            "successor_bytes_differ_from_predecessor_bytes"
        ) == "FRESH_SUCCESSOR_DIGEST_BINDING_REQUIRED",
        "inheritance_by_filename_role_prohibited": contract.get(
            "digest_inheritance_by_filename_role_or_predecessor_relationship"
        ) == "PROHIBITED",
    }
    request = load_json(WORKSPACE / "contracts/WORKER_REQUEST.json")
    contract_checks["worker_request_schema_digest_matches"] = (
        request.get("output_schema", {}).get("sha256") == sha256_file(MODEL_OUTPUT_SCHEMA)
    )
    status = "PASS" if verdict.get("status") == "PASS" and all(contract_checks.values()) else (
        "FAIL_CLOSED_BEFORE_FRESH_PREFLIGHT_AND_ATTEMPT"
    )
    return {
        "record_type": "FIRST_REAL_SECURITY_WORKER_V35_ARTIFACT_DIGEST_PRECHECK",
        "status": status,
        "contract_checks": contract_checks,
        "binding_verdict": verdict,
        "unsafe": unsafe,
        "writable": writable,
        "member_count": len(current),
        "binding_record_sha256": sha256_file(AUTHORITATIVE_ARTIFACT_DIGEST_BINDING),
        "attempt_count_if_failed": 0,
        "worker_invocation_count_if_failed": 0,
        "codex_as_worker_invocation_count_if_failed": 0,
    }


def tree_root(path: Path, *, exclude: frozenset[str] = frozenset()) -> str:
    rows: list[str] = []
    for member in sorted(item for item in path.rglob("*") if item.is_file()):
        relative = member.relative_to(path).as_posix()
        if relative in exclude:
            continue
        rows.append(f"{sha256_file(member)}  {relative}\n")
    return hashlib.sha256("".join(rows).encode("utf-8")).hexdigest()


def authoritative_predecessor_resolution_verdict(
    *,
    canonical_identity: str,
    registry: Mapping[str, Any],
    artifact_is_safe_regular: bool,
    manifest_is_safe_regular: bool,
    first_artifact_bytes: bytes,
    reread_artifact_bytes: bytes,
    actual_manifest_sha256: str | None,
) -> dict[str, Any]:
    """Resolve one canonical predecessor without path synthesis or fallback."""

    artifacts = registry.get("artifacts") if isinstance(registry, Mapping) else None
    entry = artifacts.get(canonical_identity) if isinstance(artifacts, Mapping) else None
    entry = entry if isinstance(entry, Mapping) else {}
    try:
        artifact = json.loads(first_artifact_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        artifact = {}
    expected_digest = entry.get("artifact_sha256")
    first_digest = hashlib.sha256(first_artifact_bytes).hexdigest()
    reread_digest = hashlib.sha256(reread_artifact_bytes).hexdigest()
    checks = {
        "canonical_identity_exact": registry.get("canonical_identity") == canonical_identity,
        "canonical_registry_entry_exists": bool(entry),
        "fallback_prohibited": registry.get("fallback_resolution") == "PROHIBITED",
        "execution_number_path_derivation_prohibited": registry.get("path_derivation_from_execution_number") == "PROHIBITED",
        "artifact_path_exact": entry.get("artifact_path") == str(CANONICAL_COMPATIBILITY_ACCEPTANCE_PATH),
        "manifest_path_exact": entry.get("manifest_path") == str(CANONICAL_COMPATIBILITY_ACCEPTANCE_MANIFEST),
        "artifact_safe_regular": artifact_is_safe_regular,
        "manifest_safe_regular": manifest_is_safe_regular,
        "first_digest_exact": first_digest == expected_digest == EXPECTED_DIGESTS["codex_compatibility_acceptance_lock"],
        "manifest_digest_exact": actual_manifest_sha256 == entry.get("manifest_sha256") == EXPECTED_DIGESTS["codex_compatibility_acceptance_manifest"],
        "governance_identity_exact": artifact.get("governance_identity") == entry.get("governance_identity") == CANONICAL_COMPATIBILITY_GOVERNANCE_IDENTITY,
        "pass_locked_state_exact": artifact.get("status") == entry.get("required_status") == "PASS_LOCKED_GOVERNANCE_ONLY",
        "compatibility_state_exact": artifact.get(CURRENT_RUNTIME_ACCEPTANCE_FIELD) == entry.get("compatibility_state") == "COMPATIBILITY_PASS_LOCKED",
        "historical_runtime_field_not_current_authority": HISTORICAL_RUNTIME_ACCEPTANCE_FIELD not in artifact,
        "runtime_identity_exact": entry.get("runtime_identity") == RUNTIME_IDENTITY,
        "reread_bytes_exact": first_artifact_bytes == reread_artifact_bytes,
        "reread_digest_exact": reread_digest == expected_digest,
    }
    return {
        "record_type": "AUTHORITATIVE_PREDECESSOR_RESOLUTION_RESULT",
        "status": "PASS" if all(checks.values()) else "FAIL_CLOSED_BEFORE_ATTEMPT",
        "canonical_identity": canonical_identity,
        "checks": checks,
        "first_artifact_sha256": first_digest,
        "reread_artifact_sha256": reread_digest,
        "attempt_count_if_failed": 0,
        "worker_invocation_count_if_failed": 0,
        "codex_as_worker_invocation_count_if_failed": 0,
    }


def authoritative_predecessor_resolution_precheck() -> dict[str, Any]:
    registry_path = WORKSPACE / "contracts/AUTHORITATIVE_PREDECESSOR_REGISTRY.json"
    if not safe_regular_file(registry_path):
        return {"status": "FAIL_CLOSED_BEFORE_ATTEMPT", "reason": "REGISTRY_MISSING_OR_UNSAFE"}
    registry = load_json(registry_path)
    if not isinstance(registry, Mapping):
        return {"status": "FAIL_CLOSED_BEFORE_ATTEMPT", "reason": "REGISTRY_NOT_OBJECT"}
    artifacts = registry.get("artifacts")
    entry = artifacts.get(CANONICAL_COMPATIBILITY_ACCEPTANCE_IDENTITY) if isinstance(artifacts, Mapping) else None
    if not isinstance(entry, Mapping):
        return {"status": "FAIL_CLOSED_BEFORE_ATTEMPT", "reason": "CANONICAL_IDENTITY_UNRESOLVED_NO_FALLBACK"}
    artifact_path = Path(str(entry.get("artifact_path", "")))
    manifest_path = Path(str(entry.get("manifest_path", "")))
    artifact_safe = safe_regular_file(artifact_path)
    manifest_safe = safe_regular_file(manifest_path)
    first_bytes = artifact_path.read_bytes() if artifact_safe else b""
    manifest_digest = sha256_file(manifest_path) if manifest_safe else None
    reread_bytes = artifact_path.read_bytes() if artifact_safe else b""
    result = authoritative_predecessor_resolution_verdict(
        canonical_identity=CANONICAL_COMPATIBILITY_ACCEPTANCE_IDENTITY,
        registry=registry,
        artifact_is_safe_regular=artifact_safe,
        manifest_is_safe_regular=manifest_safe,
        first_artifact_bytes=first_bytes,
        reread_artifact_bytes=reread_bytes,
        actual_manifest_sha256=manifest_digest,
    )
    typed_runtime = typed_runtime_acceptance_precheck("FRESH_PREFLIGHT")
    result["typed_current_runtime_authority"] = typed_runtime
    if typed_runtime.get("status") != "PASS":
        result["status"] = "FAIL_CLOSED_BEFORE_ATTEMPT"
    return result


def verify_v1_reference_predecessor() -> dict[str, Any]:
    members = sorted(item for item in V1_WORKSPACE.rglob("*") if item.is_file()) if V1_WORKSPACE.is_dir() else []
    actual_root = tree_root(V1_WORKSPACE) if members else None
    checks = {
        "workspace_present": V1_WORKSPACE.is_dir() and not V1_WORKSPACE.is_symlink(),
        "member_count": len(members) == V1_MEMBER_COUNT,
        "canonical_tree_root": actual_root == V1_CANONICAL_TREE_ROOT,
    }
    return {
        "status": "PASS" if all(checks.values()) else "FAIL",
        "checks": checks,
        "actual_member_count": len(members),
        "expected_member_count": V1_MEMBER_COUNT,
        "actual_tree_root_sha256": actual_root,
        "expected_tree_root_sha256": V1_CANONICAL_TREE_ROOT,
    }


def verify_v2_reference_predecessor() -> dict[str, Any]:
    """Reopen the failed V2 lineage without mutating or reclassifying it."""

    members = sorted(item for item in V2_WORKSPACE.rglob("*") if item.is_file()) if V2_WORKSPACE.is_dir() else []
    actual_root = tree_root(V2_WORKSPACE) if members else None
    checks = {
        "workspace_present": V2_WORKSPACE.is_dir() and not V2_WORKSPACE.is_symlink(),
        "member_count": len(members) == V2_MEMBER_COUNT,
        "canonical_tree_root": actual_root == V2_CANONICAL_TREE_ROOT,
    }
    return {
        "status": "PASS" if all(checks.values()) else "FAIL",
        "checks": checks,
        "actual_member_count": len(members),
        "expected_member_count": V2_MEMBER_COUNT,
        "actual_tree_root_sha256": actual_root,
        "expected_tree_root_sha256": V2_CANONICAL_TREE_ROOT,
        "disposition": "FAIL_CLOSED_TERMINAL_NO_RETRY_REFERENCE_ONLY",
    }


def verify_v3_reference_predecessor() -> dict[str, Any]:
    """Bind the immutable V3 failure lineage by complete content-addressed tree."""

    members = sorted(item for item in V3_WORKSPACE.rglob("*") if item.is_file()) if V3_WORKSPACE.is_dir() else []
    actual_root = tree_root(V3_WORKSPACE) if members else None
    checks = {
        "workspace_present": V3_WORKSPACE.is_dir() and not V3_WORKSPACE.is_symlink(),
        "member_count": len(members) == V3_MEMBER_COUNT,
        "canonical_tree_root": actual_root == V3_CANONICAL_TREE_ROOT,
    }
    return {
        "status": "PASS" if all(checks.values()) else "FAIL",
        "checks": checks,
        "actual_member_count": len(members),
        "expected_member_count": V3_MEMBER_COUNT,
        "actual_tree_root_sha256": actual_root,
        "expected_tree_root_sha256": V3_CANONICAL_TREE_ROOT,
        "disposition": "FAIL_CLOSED_TERMINAL_NO_RETRY_REFERENCE_ONLY",
    }


def verify_v4_reference_predecessor() -> dict[str, Any]:
    """Bind the immutable V4 post-attempt failure without reclassification."""

    members = sorted(item for item in V4_WORKSPACE.rglob("*") if item.is_file()) if V4_WORKSPACE.is_dir() else []
    actual_root = tree_root(V4_WORKSPACE) if members else None
    checks = {
        "workspace_present": V4_WORKSPACE.is_dir() and not V4_WORKSPACE.is_symlink(),
        "member_count": len(members) == V4_MEMBER_COUNT,
        "canonical_tree_root": actual_root == V4_CANONICAL_TREE_ROOT,
    }
    return {
        "status": "PASS" if all(checks.values()) else "FAIL",
        "checks": checks,
        "actual_member_count": len(members),
        "expected_member_count": V4_MEMBER_COUNT,
        "actual_tree_root_sha256": actual_root,
        "expected_tree_root_sha256": V4_CANONICAL_TREE_ROOT,
        "disposition": "FAIL_CLOSED_POST_ATTEMPT_TERMINAL_NO_RETRY_REFERENCE_ONLY",
    }


def verify_v5_reference_predecessor() -> dict[str, Any]:
    """Verify the frozen V5 failure workspace without modifying or reclassifying it."""

    members = [path for path in V5_WORKSPACE.rglob("*") if path.is_file() or path.is_symlink()]
    actual_root = tree_root(V5_WORKSPACE) if V5_WORKSPACE.is_dir() else None
    binding = PREDECESSOR_PATHS["v5_terminal_evidence_binding"]
    checks = {
        "workspace_present": V5_WORKSPACE.is_dir() and not V5_WORKSPACE.is_symlink(),
        "member_count": len(members) == V5_MEMBER_COUNT,
        "canonical_tree_root": actual_root == V5_CANONICAL_TREE_ROOT,
        "terminal_binding_exact": safe_regular_file(binding)
        and sha256_file(binding) == EXPECTED_DIGESTS["v5_terminal_evidence_binding"],
    }
    return {
        "status": "PASS" if all(checks.values()) else "FAIL",
        "checks": checks,
        "actual_member_count": len(members),
        "expected_member_count": V5_MEMBER_COUNT,
        "actual_tree_root_sha256": actual_root,
        "expected_tree_root_sha256": V5_CANONICAL_TREE_ROOT,
        "disposition": "FAIL_CLOSED_POST_ATTEMPT_TERMINAL_NO_RETRY_REFERENCE_ONLY",
    }


def verify_v6_reference_predecessor() -> dict[str, Any]:
    """Verify the frozen V6 failure without reparsing or reclassifying its evidence."""

    members = [path for path in V6_WORKSPACE.rglob("*") if path.is_file() or path.is_symlink()]
    actual_root = tree_root(V6_WORKSPACE) if V6_WORKSPACE.is_dir() else None
    binding = PREDECESSOR_PATHS["v6_terminal_evidence_binding"]
    checks = {
        "workspace_present": V6_WORKSPACE.is_dir() and not V6_WORKSPACE.is_symlink(),
        "member_count": len(members) == V6_MEMBER_COUNT,
        "canonical_tree_root": actual_root == V6_CANONICAL_TREE_ROOT,
        "terminal_binding_exact": safe_regular_file(binding)
        and sha256_file(binding) == EXPECTED_DIGESTS["v6_terminal_evidence_binding"],
    }
    return {
        "status": "PASS" if all(checks.values()) else "FAIL",
        "checks": checks,
        "actual_member_count": len(members),
        "expected_member_count": V6_MEMBER_COUNT,
        "actual_tree_root_sha256": actual_root,
        "expected_tree_root_sha256": V6_CANONICAL_TREE_ROOT,
        "disposition": "FAIL_CLOSED_POST_ATTEMPT_TERMINAL_NO_RETRY_REFERENCE_ONLY",
    }


def verify_v7_reference_predecessor() -> dict[str, Any]:
    """Bind the fail-closed V7 prelock lineage without continuation or mutation."""

    members = [path for path in V7_WORKSPACE.rglob("*") if path.is_file() or path.is_symlink()]
    actual_root = tree_root(V7_WORKSPACE) if V7_WORKSPACE.is_dir() else None
    binding = PREDECESSOR_PATHS["v7_prelock_evidence_binding"]
    checks = {
        "workspace_present": V7_WORKSPACE.is_dir() and not V7_WORKSPACE.is_symlink(),
        "member_count": len(members) == V7_MEMBER_COUNT,
        "canonical_tree_root": actual_root == V7_CANONICAL_TREE_ROOT,
        "prelock_binding_exact": safe_regular_file(binding)
        and sha256_file(binding) == EXPECTED_DIGESTS["v7_prelock_evidence_binding"],
        "static_lock_absent": not (V7_WORKSPACE / "STATIC_EXECUTION_LOCK.json").exists(),
        "attempt_marker_absent": not (V7_WORKSPACE / "static-run-v7/ATTEMPT_MARKER.json").exists(),
    }
    return {
        "status": "PASS" if all(checks.values()) else "FAIL",
        "checks": checks,
        "actual_member_count": len(members),
        "expected_member_count": V7_MEMBER_COUNT,
        "actual_tree_root_sha256": actual_root,
        "expected_tree_root_sha256": V7_CANONICAL_TREE_ROOT,
        "disposition": "FAIL_CLOSED_PRELOCK_REFERENCE_PREDECESSOR",
        "continuation": "PROHIBITED",
    }


def verify_v8_reference_predecessor() -> dict[str, Any]:
    """Bind V8 as the immutable failed predecessor; never continue it."""

    members = [path for path in V8_WORKSPACE.rglob("*") if path.is_file() or path.is_symlink()]
    actual_root = tree_root(V8_WORKSPACE) if V8_WORKSPACE.is_dir() else None
    binding = PREDECESSOR_PATHS["v8_prelock_evidence_binding"]
    checks = {
        "workspace_present": V8_WORKSPACE.is_dir() and not V8_WORKSPACE.is_symlink(),
        "member_count": len(members) == V8_MEMBER_COUNT,
        "canonical_tree_root": actual_root == V8_CANONICAL_TREE_ROOT,
        "prelock_binding_exact": safe_regular_file(binding)
        and sha256_file(binding) == EXPECTED_DIGESTS["v8_prelock_evidence_binding"],
        "static_lock_absent": not (V8_WORKSPACE / "STATIC_EXECUTION_LOCK.json").exists(),
        "attempt_marker_absent": not (V8_WORKSPACE / "static-run-v8/ATTEMPT_MARKER.json").exists(),
    }
    return {
        "status": "PASS" if all(checks.values()) else "FAIL",
        "checks": checks,
        "actual_member_count": len(members),
        "expected_member_count": V8_MEMBER_COUNT,
        "actual_tree_root_sha256": actual_root,
        "expected_tree_root_sha256": V8_CANONICAL_TREE_ROOT,
        "disposition": "FAIL_CLOSED_PRELOCK_REFERENCE_PREDECESSOR",
        "continuation": "PROHIBITED",
    }


def verify_v9_reference_predecessor() -> dict[str, Any]:
    """Bind V9 as the immutable failed predecessor; never continue or mutate it."""

    members = [path for path in V9_WORKSPACE.rglob("*") if path.is_file() or path.is_symlink()]
    actual_root = tree_root(V9_WORKSPACE) if V9_WORKSPACE.is_dir() else None
    binding = PREDECESSOR_PATHS["v9_prelock_evidence_binding"]
    checks = {
        "workspace_present": V9_WORKSPACE.is_dir() and not V9_WORKSPACE.is_symlink(),
        "member_count": len(members) == V9_MEMBER_COUNT,
        "canonical_tree_root": actual_root == V9_CANONICAL_TREE_ROOT,
        "prelock_binding_exact": safe_regular_file(binding)
        and sha256_file(binding) == EXPECTED_DIGESTS["v9_prelock_evidence_binding"],
        "static_lock_absent": not (V9_WORKSPACE / "STATIC_EXECUTION_LOCK.json").exists(),
        "attempt_marker_absent": not (V9_WORKSPACE / "static-run-v9/ATTEMPT_MARKER.json").exists(),
    }
    return {
        "status": "PASS" if all(checks.values()) else "FAIL",
        "checks": checks,
        "actual_member_count": len(members),
        "expected_member_count": V9_MEMBER_COUNT,
        "actual_tree_root_sha256": actual_root,
        "expected_tree_root_sha256": V9_CANONICAL_TREE_ROOT,
        "disposition": "FAIL_CLOSED_PRELOCK_REFERENCE_PREDECESSOR",
        "continuation": "PROHIBITED",
    }


def verify_v10_reference_predecessor() -> dict[str, Any]:
    """Bind the immutable, frozen V10 post-attempt failure as V11's predecessor."""

    members = [path for path in V10_WORKSPACE.rglob("*") if path.is_file() or path.is_symlink()]
    actual_root = tree_root(V10_WORKSPACE) if V10_WORKSPACE.is_dir() else None
    binding_path = PREDECESSOR_PATHS["v10_terminal_evidence_binding"]
    binding = load_json(binding_path) if safe_regular_file(binding_path) else {}
    checks = {
        "workspace_present": V10_WORKSPACE.is_dir() and not V10_WORKSPACE.is_symlink(),
        "member_count": len(members) == V10_MEMBER_COUNT,
        "canonical_tree_root": actual_root == V10_CANONICAL_TREE_ROOT,
        "terminal_binding_exact": safe_regular_file(binding_path)
        and sha256_file(binding_path) == EXPECTED_DIGESTS["v10_terminal_evidence_binding"],
        "binding_identity_exact": binding.get("execution_identity")
        == "V0_3_FIRST_REAL_SECURITY_WORKER_INVOCATION_V10",
        "binding_tree_root_exact": binding.get("canonical_tree_root_sha256") == V10_CANONICAL_TREE_ROOT,
        "attempt_consumed": (V10_WORKSPACE / "static-run-v10/ATTEMPT_MARKER.json").is_file(),
        "failure_evidence_frozen": (V10_WORKSPACE / "static-run-v10/EVIDENCE_FREEZE_LOCK.json").is_file(),
    }
    return {
        "status": "PASS" if all(checks.values()) else "FAIL",
        "checks": checks,
        "actual_member_count": len(members),
        "expected_member_count": V10_MEMBER_COUNT,
        "actual_tree_root_sha256": actual_root,
        "expected_tree_root_sha256": V10_CANONICAL_TREE_ROOT,
        "disposition": "FAIL_CLOSED_POST_ATTEMPT_TERMINAL_NO_RETRY_REFERENCE_ONLY",
        "continuation": "PROHIBITED",
    }


def verify_v11_reference_predecessor() -> dict[str, Any]:
    """Bind V11's locked pre-attempt failure without mutating its workspace."""

    members = [path for path in V11_WORKSPACE.rglob("*") if path.is_file() or path.is_symlink()]
    actual_root = tree_root(V11_WORKSPACE) if V11_WORKSPACE.is_dir() else None
    lock_path = V11_WORKSPACE / "STATIC_EXECUTION_LOCK.json"
    selftest_path = V11_WORKSPACE / "static-run-v11/observer-selftest-result-0001.json"
    checks = {
        "workspace_present": V11_WORKSPACE.is_dir() and not V11_WORKSPACE.is_symlink(),
        "member_count": len(members) == V11_MEMBER_COUNT,
        "canonical_tree_root": actual_root == V11_CANONICAL_TREE_ROOT,
        "static_lock_immutable_identity": safe_regular_file(lock_path)
        and sha256_file(lock_path) == V11_STATIC_LOCK_SHA256,
        "historical_selftest_immutable": safe_regular_file(selftest_path)
        and sha256_file(selftest_path) == V11_OBSERVER_SELFTEST_SHA256,
        "attempt_marker_absent": not (V11_WORKSPACE / "static-run-v11/ATTEMPT_MARKER.json").exists(),
        "runtime_result_absent": not (V11_WORKSPACE / "static-run-v11/runtime-result-0001.json").exists(),
        "terminal_no_retry_reference_state": True,
    }
    return {
        "status": "PASS" if all(checks.values()) else "FAIL",
        "checks": checks,
        "actual_member_count": len(members),
        "expected_member_count": V11_MEMBER_COUNT,
        "actual_tree_root_sha256": actual_root,
        "expected_tree_root_sha256": V11_CANONICAL_TREE_ROOT,
        "disposition": "FAIL_CLOSED_PRE_ATTEMPT_TERMINAL_NO_RETRY_REFERENCE_ONLY",
        "continuation": "PROHIBITED",
    }


def verify_v12_reference_predecessor() -> dict[str, Any]:
    """Bind the immutable V12 post-attempt frozen failure and its V13 authority."""

    members = [path for path in V12_WORKSPACE.rglob("*") if path.is_file() or path.is_symlink()]
    actual_root = tree_root(V12_WORKSPACE) if V12_WORKSPACE.is_dir() else None
    lock_path = V12_WORKSPACE / "STATIC_EXECUTION_LOCK.json"
    freeze_path = V12_WORKSPACE / "static-run-v12/EVIDENCE_FREEZE_LOCK.json"
    governance_path = V12_GOVERNANCE / "GOVERNANCE_LOCK.json"
    governance = load_json(governance_path) if safe_regular_file(governance_path) else {}
    checks = {
        "workspace_present": V12_WORKSPACE.is_dir() and not V12_WORKSPACE.is_symlink(),
        "workspace_read_only": stat.S_IMODE(V12_WORKSPACE.stat().st_mode) & 0o222 == 0,
        "member_count": len(members) == V12_MEMBER_COUNT,
        "canonical_tree_root": actual_root == V12_CANONICAL_TREE_ROOT,
        "static_lock_exact": safe_regular_file(lock_path) and sha256_file(lock_path) == V12_STATIC_LOCK_SHA256,
        "failure_evidence_freeze_exact": safe_regular_file(freeze_path)
        and sha256_file(freeze_path) == V12_FAILURE_EVIDENCE_FREEZE_SHA256,
        "attempt_consumed": (V12_WORKSPACE / "static-run-v12/ATTEMPT_MARKER.json").is_file(),
        "governance_lock_exact": safe_regular_file(governance_path)
        and sha256_file(governance_path) == V12_GOVERNANCE_LOCK_SHA256,
        "governance_status": governance.get("status") == "PASS_LOCKED_GOVERNANCE_ONLY",
        "governance_decision": governance.get("decision")
        == "TERMINALIZE_V12_AND_AUTHORIZE_DISTINCT_FIRST_REAL_SECURITY_WORKER_INVOCATION_V13_CONDITIONALLY",
    }
    return {
        "status": "PASS" if all(checks.values()) else "FAIL",
        "checks": checks,
        "actual_member_count": len(members),
        "expected_member_count": V12_MEMBER_COUNT,
        "actual_tree_root_sha256": actual_root,
        "expected_tree_root_sha256": V12_CANONICAL_TREE_ROOT,
        "disposition": "FAIL_CLOSED_POST_ATTEMPT_TERMINAL_NO_RETRY_FROZEN_FAILURE_EVIDENCE",
        "continuation": "PROHIBITED",
    }


def verify_v13_reference_predecessor() -> dict[str, Any]:
    """Bind V13's frozen unit failure without mutating or reinterpreting it."""

    members = [path for path in V13_WORKSPACE.rglob("*") if path.is_file() or path.is_symlink()]
    actual_root = tree_root(V13_WORKSPACE) if V13_WORKSPACE.is_dir() else None
    unit_path = V13_WORKSPACE / "results/prelock/unit-fixtures-run-0001.json"
    binding_path = PREDECESSOR_PATHS["v13_frozen_evidence_binding"]
    governance_path = PREDECESSOR_PATHS["v13_authorization_lock"]
    governance = load_json(governance_path) if safe_regular_file(governance_path) else {}
    checks = {
        "workspace_present": V13_WORKSPACE.is_dir() and not V13_WORKSPACE.is_symlink(),
        "member_count": len(members) == V13_MEMBER_COUNT,
        "canonical_tree_root": actual_root == V13_CANONICAL_TREE_ROOT,
        "historical_unit_failure_exact": safe_regular_file(unit_path)
        and sha256_file(unit_path) == V13_UNIT_FAILURE_SHA256,
        "frozen_evidence_binding_exact": safe_regular_file(binding_path)
        and sha256_file(binding_path) == EXPECTED_DIGESTS["v13_frozen_evidence_binding"],
        "static_lock_absent": not (V13_WORKSPACE / "STATIC_EXECUTION_LOCK.json").exists(),
        "attempt_marker_absent": not (V13_WORKSPACE / "static-run-v13/ATTEMPT_MARKER.json").exists(),
        "governance_lock_exact": safe_regular_file(governance_path)
        and sha256_file(governance_path) == EXPECTED_DIGESTS["v13_authorization_lock"],
        "governance_status": governance.get("status") == "PASS_LOCKED_GOVERNANCE_ONLY",
        "governance_decision": governance.get("decision")
        == "TERMINALIZE_V13_AND_AUTHORIZE_DISTINCT_V14_CONDITIONALLY",
    }
    return {
        "status": "PASS" if all(checks.values()) else "FAIL",
        "checks": checks,
        "actual_member_count": len(members),
        "expected_member_count": V13_MEMBER_COUNT,
        "actual_tree_root_sha256": actual_root,
        "expected_tree_root_sha256": V13_CANONICAL_TREE_ROOT,
        "disposition": "FAIL_CLOSED_DURING_UNIT_VALIDATION_PRELOCK_TERMINAL_REFERENCE_PREDECESSOR",
        "continuation": "PROHIBITED",
    }


def verify_v14_reference_predecessor() -> dict[str, Any]:
    """Preserve pre-incident V14 identity while admitting exactly two incident additions."""

    snapshot_path = PREDECESSOR_PATHS["v14_frozen_evidence_snapshot_manifest"]
    binding_path = PREDECESSOR_PATHS["v14_frozen_evidence_binding"]
    old_governance_path = PREDECESSOR_PATHS["v14_authorization_lock"]
    incident_path = PREDECESSOR_PATHS["v14_current_drift_adjudication"]
    snapshot = load_json(snapshot_path) if safe_regular_file(snapshot_path) else {}
    binding = load_json(binding_path) if safe_regular_file(binding_path) else {}
    old_governance = load_json(old_governance_path) if safe_regular_file(old_governance_path) else {}
    incident = load_json(incident_path) if safe_regular_file(incident_path) else {}
    rows = snapshot.get("members", []) if isinstance(snapshot, Mapping) else []
    expected = {row["path"]: row for row in rows if isinstance(row, Mapping) and isinstance(row.get("path"), str)}
    actual = {
        path.relative_to(V14_WORKSPACE).as_posix(): path
        for path in V14_WORKSPACE.rglob("*")
        if path.is_file() or path.is_symlink()
    } if V14_WORKSPACE.is_dir() else {}
    additions = set(actual) - set(expected)
    missing = set(expected) - set(actual)
    historical_match = all(
        name in actual
        and safe_regular_file(actual[name])
        and sha256_file(actual[name]) == row.get("sha256")
        and actual[name].stat().st_size == row.get("size")
        for name, row in expected.items()
    )
    addition_match = additions == set(V14_UNAUTHORIZED_ADDITIONS) and all(
        safe_regular_file(actual[name]) and sha256_file(actual[name]) == digest
        for name, digest in V14_UNAUTHORIZED_ADDITIONS.items()
    )
    canonical_rows = [
        (path.relative_to(V14_WORKSPACE).as_posix(), sha256_file(path))
        for path in sorted(actual.values())
    ]
    current_root = hashlib.sha256(
        "".join(f"{name}\0{digest}\n" for name, digest in canonical_rows).encode()
    ).hexdigest()
    checks = {
        "workspace_present": V14_WORKSPACE.is_dir() and not V14_WORKSPACE.is_symlink(),
        "historical_snapshot_exact": safe_regular_file(snapshot_path)
        and sha256_file(snapshot_path) == EXPECTED_DIGESTS["v14_frozen_evidence_snapshot_manifest"],
        "historical_binding_exact": safe_regular_file(binding_path)
        and sha256_file(binding_path) == EXPECTED_DIGESTS["v14_frozen_evidence_binding"],
        "historical_member_count": len(expected) == V14_MEMBER_COUNT,
        "historical_members_preserved": historical_match and not missing,
        "exact_two_preserved_additions": addition_match,
        "current_member_count": len(actual) == V14_CURRENT_MEMBER_COUNT,
        "current_tree_root": current_root == V14_CURRENT_TREE_ROOT,
        "incident_adjudication_exact": safe_regular_file(incident_path)
        and sha256_file(incident_path) == EXPECTED_DIGESTS["v14_current_drift_adjudication"],
        "incident_identity_distinct": incident.get("identity_distinction", {}).get("identities_are_distinct") is True,
        "unit_evidence_exact": binding.get("unit", {}).get("sha256") == V14_UNIT_PASS_SHA256,
        "primary_failure_exact": binding.get("primary", {}).get("sha256") == V14_PRIMARY_FAILURE_SHA256,
        "static_lock_absent": not (V14_WORKSPACE / "STATIC_EXECUTION_LOCK.json").exists(),
        "attempt_marker_absent": not (V14_WORKSPACE / "static-run-v14/ATTEMPT_MARKER.json").exists(),
        "old_governance_exact": safe_regular_file(old_governance_path)
        and sha256_file(old_governance_path) == EXPECTED_DIGESTS["v14_authorization_lock"],
        "old_governance_decision": old_governance.get("decision")
        == "TERMINALIZE_V14_AND_AUTHORIZE_DISTINCT_V15_CONDITIONALLY",
    }
    return {
        "status": "PASS" if all(checks.values()) else "FAIL",
        "checks": checks,
        "historical_member_count": len(expected),
        "current_member_count": len(actual),
        "historical_tree_root_sha256": V14_FROZEN_TREE_ROOT,
        "current_tree_root_sha256": current_root,
        "preserved_unauthorized_additions": sorted(additions),
        "disposition": "HISTORICAL_PREINCIDENT_IDENTITY_PLUS_PRESERVED_UNAUTHORIZED_APPEND_ONLY_INCIDENT_EVIDENCE",
    }


def verify_v15_reference_predecessor() -> dict[str, Any]:
    """Bind the immutable terminal V15 failure without interpreting it as runtime evidence."""
    files = {
        relative: V15_WORKSPACE / relative
        for relative in V15_FROZEN_FILES
    }
    hashes = {
        relative: sha256_file(path) if safe_regular_file(path) else None
        for relative, path in files.items()
    }
    terminal = load_json(files["results/prelock/PRELOCK_TERMINAL_ENGINEERING_RESULT.json"]) if safe_regular_file(files["results/prelock/PRELOCK_TERMINAL_ENGINEERING_RESULT.json"]) else {}
    static_run = V15_WORKSPACE / "static-run-v15"
    checks = {
        "workspace_present": V15_WORKSPACE.is_dir() and not V15_WORKSPACE.is_symlink(),
        "frozen_files_exact": hashes == V15_FROZEN_FILES,
        "terminal_state_exact": terminal.get("status") == "FAIL_CLOSED_PRELOCK_TERMINAL_NO_RETRY_PREDECESSOR_IMMUTABILITY_VIOLATION",
        "static_lock_absent": not (V15_WORKSPACE / "STATIC_EXECUTION_LOCK.json").exists(),
        "attempt_marker_absent": not (static_run / "ATTEMPT_MARKER.json").exists(),
        "runtime_absent": not (static_run / "runtime-result-0001.json").exists(),
        "static_run_empty": not static_run.exists() or not any(path.is_file() for path in static_run.rglob("*")),
        "authorization_lock_exact": safe_regular_file(PREDECESSOR_PATHS["authorization_lock"])
        and sha256_file(PREDECESSOR_PATHS["authorization_lock"]) == EXPECTED_DIGESTS["authorization_lock"],
    }
    return {
        "status": "PASS" if all(checks.values()) else "FAIL",
        "checks": checks,
        "hashes": hashes,
        "disposition": "FAIL_CLOSED_PRELOCK_TERMINAL_NO_RETRY_PREDECESSOR_IMMUTABILITY_VIOLATION",
        "attempt": "0_OF_1",
        "worker_invocation": "0_OF_1",
        "codex_as_worker_invocation": "0_OF_1",
    }


def verify_v16_reference_predecessor() -> dict[str, Any]:
    """Verify the complete immutable V16 failure tree, including its historical pyc."""
    binding_path = WORKSPACE / "contracts/V16_FROZEN_PRELOCK_EVIDENCE_BINDING.json"
    binding = load_json(binding_path) if safe_regular_file(binding_path) else {}
    paths = {
        "unit": V16_WORKSPACE / "results/prelock/unit-fixtures-run-0001.json",
        "primary": V16_WORKSPACE / "results/prelock/primary-static-validation-run-0001.json",
        "terminal": V16_WORKSPACE / "results/prelock/PRELOCK_TERMINAL_ENGINEERING_RESULT.json",
        "failure_manifest": V16_WORKSPACE / "results/prelock/PRELOCK_FAILURE_EVIDENCE_MANIFEST.json",
        "implicit_pyc": V16_WORKSPACE / "src/__pycache__/workspace_boundary_v16.cpython-314.pyc",
    }
    hashes = {name: sha256_file(path) if safe_regular_file(path) else None for name, path in paths.items()}
    try:
        actual_root, member_count = normative_frozen_tree(V16_WORKSPACE)
    except (OSError, ValueError, UnicodeError):
        actual_root, member_count = None, 0
    checks = {
        "binding_exact": binding.get("workspace_tree_root_sha256") == V16_WORKSPACE_TREE_ROOT
        and binding.get("workspace_member_count") == V16_WORKSPACE_MEMBER_COUNT,
        "workspace_tree_exact": actual_root == V16_WORKSPACE_TREE_ROOT,
        "alternate_flattened_root_rejected": actual_root != V16_NON_NORMATIVE_FLATTENED_ROOT,
        "member_count_exact": member_count == V16_WORKSPACE_MEMBER_COUNT,
        "unit_exact": hashes["unit"] == V16_UNIT_PASS_SHA256,
        "primary_exact": hashes["primary"] == V16_PRIMARY_FAILURE_SHA256,
        "terminal_exact": hashes["terminal"] == V16_TERMINAL_RESULT_SHA256,
        "failure_manifest_exact": hashes["failure_manifest"] == V16_FAILURE_MANIFEST_SHA256,
        "implicit_pyc_preserved_exact": hashes["implicit_pyc"] == V16_IMPLICIT_PYC_SHA256,
        "static_lock_absent": not (V16_WORKSPACE / "STATIC_EXECUTION_LOCK.json").exists(),
        "attempt_absent": not (V16_WORKSPACE / "static-run-v16/ATTEMPT_MARKER.json").exists(),
    }
    return {
        "status": "PASS" if all(checks.values()) else "FAIL",
        "checks": checks,
        "hashes": hashes,
        "actual_tree_root_sha256": actual_root,
        "member_count": member_count,
        "disposition": "FAIL_CLOSED_PRELOCK_TERMINAL_NO_RETRY_REFERENCE_ONLY",
    }


def verify_v17_reference_predecessor() -> dict[str, Any]:
    """Verify immutable V17 terminal evidence without accepting its failed validator."""
    binding = load_json(WORKSPACE / "contracts/V17_PRELOCK_FROZEN_EVIDENCE_BINDING.json")
    decision = load_json(WORKSPACE / "contracts/V17_TERMINAL_AND_V18_SUCCESSOR_DECISION.json")
    paths = {
        "unit": V17_WORKSPACE / "results/prelock/unit-fixtures-run-0001.json",
        "primary": V17_WORKSPACE / "results/prelock/primary-static-validation-run-0001.json",
        "independent": V17_WORKSPACE / "results/prelock/independent-static-validation-run-0001.json",
        "terminal": V17_WORKSPACE / "results/prelock/PRELOCK_TERMINAL_ENGINEERING_RESULT.json",
    }
    hashes = {name: sha256_file(path) if safe_regular_file(path) else None for name, path in paths.items()}
    try:
        root, member_count = normative_frozen_tree(V17_WORKSPACE)
    except (OSError, ValueError, UnicodeError):
        root, member_count = None, 0
    prelock_members = [path for path in (V17_WORKSPACE / "results/prelock").rglob("*") if path.is_file()]
    checks = {
        "binding_exact": binding.get("hashes", {}).get("workspace_tree") == V17_WORKSPACE_TREE_ROOT
        and binding.get("workspace_member_count") == V17_WORKSPACE_MEMBER_COUNT,
        "workspace_tree_exact": root == V17_WORKSPACE_TREE_ROOT,
        "workspace_member_count_exact": member_count == V17_WORKSPACE_MEMBER_COUNT,
        "prelock_member_count_exact": len(prelock_members) == V17_PRELOCK_MEMBER_COUNT,
        "prelock_members_read_only": all(stat.S_IMODE(path.stat().st_mode) & 0o222 == 0 for path in prelock_members),
        "unit_exact": hashes["unit"] == V17_UNIT_PASS_SHA256,
        "primary_exact": hashes["primary"] == V17_PRIMARY_PASS_SHA256,
        "independent_failure_exact": hashes["independent"] == V17_INDEPENDENT_FAILURE_SHA256,
        "terminal_exact": hashes["terminal"] == V17_TERMINAL_RESULT_SHA256,
        "terminal_decision_exact": decision.get("decision") == "TERMINALIZE_V17_AND_AUTHORIZE_DISTINCT_V18_CONDITIONALLY"
        and decision.get("v17_continuation") == "PROHIBITED",
        "static_lock_absent": not (V17_WORKSPACE / "STATIC_EXECUTION_LOCK.json").exists(),
        "attempt_absent": not (V17_WORKSPACE / "static-run-v17/ATTEMPT_MARKER.json").exists(),
        "runtime_absent": not (V17_WORKSPACE / "static-run-v17/runtime-result-0001.json").exists(),
        "authorization_lock_exact": safe_regular_file(PREDECESSOR_PATHS["authorization_lock"])
        and sha256_file(PREDECESSOR_PATHS["authorization_lock"]) == EXPECTED_DIGESTS["authorization_lock"],
    }
    return {
        "status": "PASS" if all(checks.values()) else "FAIL",
        "checks": checks,
        "hashes": hashes,
        "actual_tree_root_sha256": root,
        "member_count": member_count,
        "disposition": "FAIL_CLOSED_PRELOCK_TERMINAL_NO_RETRY_REFERENCE_ONLY",
    }


def verify_v18_reference_predecessor() -> dict[str, Any]:
    """Verify V18's immutable post-lock, pre-attempt terminal identity."""
    binding = load_json(WORKSPACE / "contracts/V18_FROZEN_EVIDENCE_BINDING.json")
    decision = load_json(WORKSPACE / "contracts/V18_TERMINAL_AND_V19_SUCCESSOR_DECISION.json")
    relative_paths = {
        "unit": "results/prelock/unit-fixtures-run-0001.json",
        "primary": "results/prelock/primary-static-validation-run-0001.json",
        "independent": "results/prelock/independent-static-validation-run-0001.json",
        "static_lock": "STATIC_EXECUTION_LOCK.json",
        "lock_verification": "STATIC_EXECUTION_LOCK_VERIFICATION.json",
        "locked_pre_attempt": "static-run-v18/LOCKED_PRE_ATTEMPT_VALIDATION_RESULT.json",
        "terminal": "static-run-v18/TERMINAL_ENGINEERING_RESULT.json",
        "evidence_verification": "static-run-v18/EVIDENCE_FREEZE_VERIFICATION.json",
    }
    actual_hashes = {
        name: sha256_file(V18_WORKSPACE / relative) if safe_regular_file(V18_WORKSPACE / relative) else None
        for name, relative in relative_paths.items()
    }
    expected_hashes = binding.get("hashes", {})
    try:
        tree_root, member_count = normative_frozen_tree(V18_WORKSPACE)
    except (OSError, ValueError, UnicodeError):
        tree_root, member_count = None, 0
    terminal = load_json(V18_WORKSPACE / relative_paths["terminal"]) if safe_regular_file(V18_WORKSPACE / relative_paths["terminal"]) else {}
    checks = {
        "binding_identity": binding.get("execution_identity") == "V0_3_FIRST_REAL_SECURITY_WORKER_INVOCATION_V18",
        "workspace_tree_exact": tree_root == binding.get("workspace_tree_root_sha256") == "c92f0bd0d7ea111d9bfd6d3d4e612e5b1cd763d70c69f47fef6a2907c0be0f4d",
        "workspace_member_count_exact": member_count == binding.get("workspace_member_count") == 164,
        "all_members_read_only": all(stat.S_IMODE(path.stat().st_mode) & 0o222 == 0 for path in V18_WORKSPACE.rglob("*") if path.is_file()),
        "frozen_hashes_exact": all(actual_hashes[name] == expected_hashes.get(name) for name in actual_hashes),
        "terminal_state_exact": terminal.get("status") == "FAIL_CLOSED_POST_LOCK_PRE_ATTEMPT_ENTRYPOINT_IMPORT_BINDING_DEFECT_TERMINAL_NO_RETRY_FROZEN_FAILURE_EVIDENCE",
        "attempt_zero": terminal.get("attempt_count") == terminal.get("worker_invocation_count") == terminal.get("codex_as_worker_invocation_count") == terminal.get("semantic_codex_execve_count") == 0,
        "attempt_marker_absent": not list(V18_WORKSPACE.rglob("ATTEMPT_MARKER.json")),
        "decision_exact": decision.get("decision") == "TERMINALIZE_V18_AND_AUTHORIZE_DISTINCT_V19_CONDITIONALLY" and decision.get("v18_continuation") == "PROHIBITED",
        "authorization_lock_exact": safe_regular_file(PREDECESSOR_PATHS["authorization_lock"]) and sha256_file(PREDECESSOR_PATHS["authorization_lock"]) == EXPECTED_DIGESTS["authorization_lock"],
    }
    return {
        "status": "PASS" if all(checks.values()) else "FAIL",
        "checks": checks,
        "hashes": actual_hashes,
        "actual_tree_root_sha256": tree_root,
        "member_count": member_count,
        "disposition": "FAIL_CLOSED_POST_LOCK_PRE_ATTEMPT_TERMINAL_NO_RETRY_REFERENCE_ONLY",
    }


def verify_v19_reference_predecessor() -> dict[str, Any]:
    """Verify V19 as immutable history without making it V26's artifact predecessor."""

    binding_path = WORKSPACE / "contracts/V19_FROZEN_FAILURE_EVIDENCE_BINDING.json"
    decision_path = WORKSPACE / "contracts/V19_TERMINAL_AND_V20_SUCCESSOR_DECISION.json"
    binding = load_json(binding_path) if safe_regular_file(binding_path) else {}
    decision = load_json(decision_path) if safe_regular_file(decision_path) else {}
    try:
        actual_root, actual_count = normative_frozen_tree(V19_WORKSPACE)
    except (OSError, ValueError, UnicodeError):
        actual_root, actual_count = None, 0
    evidence_root = V19_WORKSPACE / "results/prelock"
    evidence_members = [path for path in evidence_root.rglob("*") if path.is_file()]
    checks = {
        "binding_identity_exact": binding.get("execution_identity") == "V0_3_FIRST_REAL_SECURITY_WORKER_INVOCATION_V19",
        "binding_disposition_exact": binding.get("disposition") == "FAIL_CLOSED_DURING_UNIT_VALIDATION_PRELOCK_TERMINAL_NO_RETRY_FROZEN_FAILURE_EVIDENCE",
        "workspace_tree_exact": actual_root == binding.get("workspace_tree_root_sha256") == "830ca3de6980cb553725fbc97f79ac453a238f511c133c1a0ab5f751690601a5",
        "workspace_member_count_exact": actual_count == binding.get("workspace_member_count") == 163,
        "evidence_member_count_exact": len(evidence_members) == binding.get("prelock_member_count") == 78,
        "evidence_read_only": all(stat.S_IMODE(path.stat().st_mode) & 0o222 == 0 for path in evidence_members),
        "decision_exact": decision.get("decision") == "TERMINALIZE_V19_AND_AUTHORIZE_DISTINCT_V20_CONDITIONALLY",
        "continuation_prohibited": decision.get("v19_continuation") == "PROHIBITED",
        "static_lock_absent": not (V19_WORKSPACE / "STATIC_EXECUTION_LOCK.json").exists(),
        "attempt_marker_absent": not list(V19_WORKSPACE.rglob("ATTEMPT_MARKER.json")),
    }
    return {
        "record_type": "V19_IMMUTABLE_REFERENCE_VERIFICATION_RESULT",
        "status": "PASS" if all(checks.values()) else "FAIL_CLOSED",
        "checks": checks,
        "actual_tree_root_sha256": actual_root,
        "member_count": actual_count,
        "artifact_predecessor_for_v35": False,
    }


def verify_v20_reference_predecessor() -> dict[str, Any]:
    """Verify the terminal V20 engineering identity and frozen prelock evidence."""
    binding_path = WORKSPACE / "contracts/V20_FROZEN_FAILURE_EVIDENCE_BINDING.json"
    binding = load_json(binding_path) if safe_regular_file(binding_path) else {}
    try:
        relation = resolve_historical_decision_relation("V20_TERMINAL_AND_V21_SUCCESSOR_DECISION")
        decision = relation.get("artifact", {})
    except (OSError, RuntimeError, ValueError):
        relation = {"status": "FAIL_CLOSED"}
        decision = {}
    try:
        actual_root, actual_count = normative_frozen_tree(V20_WORKSPACE)
    except (OSError, ValueError, UnicodeError):
        actual_root, actual_count = None, 0
    hashes = binding.get("bound_hashes", {})
    files = {
        "terminal": V20_WORKSPACE / "results/prelock/PRELOCK_TERMINAL_ENGINEERING_RESULT.json",
        "failure_manifest": V20_WORKSPACE / "results/prelock/PRELOCK_FAILURE_EVIDENCE_MANIFEST.json",
        "freeze_verification": V20_WORKSPACE / "results/prelock/PRELOCK_FAILURE_EVIDENCE_FREEZE_VERIFICATION.json",
        "failure_record": V20_WORKSPACE / "results/prelock/independent-static-validation-execution-failure-run-0001.json",
        "primary": V20_WORKSPACE / "results/prelock/primary-static-validation-run-0001.json",
        "unit": V20_WORKSPACE / "results/prelock/unit-fixtures-run-0001.json",
    }
    checks = {
        "binding_identity_exact": binding.get("execution_identity") == "V0_3_FIRST_REAL_SECURITY_WORKER_INVOCATION_V20",
        "binding_disposition_exact": binding.get("disposition") == "FAIL_CLOSED_DURING_INDEPENDENT_STATIC_VALIDATION_PRELOCK_TERMINAL_NO_RETRY_FROZEN_FAILURE_EVIDENCE",
        "workspace_tree_exact": actual_root == binding.get("workspace_tree_sha256") == "6a8c7a4516e81a8890d22948e7bd6f55c429cf9f83682b761b33afb4ff0eb192",
        "workspace_member_count_exact": actual_count == binding.get("workspace_member_count") == 179,
        "frozen_hashes_exact": all(safe_regular_file(path) and sha256_file(path) == hashes.get(name) for name, path in files.items()),
        "decision_relation_registry_exact": relation.get("status") == "PASS",
        "decision_exact": decision.get("decision") == "TERMINALIZE_V20_AND_AUTHORIZE_DISTINCT_V21_CONDITIONALLY",
        "continuation_prohibited": decision.get("v20_continuation") == "PROHIBITED",
        "static_lock_absent": not (V20_WORKSPACE / "STATIC_EXECUTION_LOCK.json").exists(),
        "attempt_marker_absent": not list(V20_WORKSPACE.rglob("ATTEMPT_MARKER.json")),
    }
    return {
        "record_type": "V20_IMMUTABLE_REFERENCE_VERIFICATION_RESULT",
        "status": "PASS" if all(checks.values()) else "FAIL_CLOSED",
        "checks": checks,
        "actual_tree_root_sha256": actual_root,
        "member_count": actual_count,
        "historical_decision_relation": relation,
        "artifact_predecessor_for_v35": False,
    }


def verify_v24_reference_predecessor() -> dict[str, Any]:
    """Verify the exact frozen V24 terminal evidence without modifying history."""
    binding = load_json(WORKSPACE / "contracts/V24_FROZEN_FAILURE_EVIDENCE_BINDING.json")
    files = {
        "terminal": V24_WORKSPACE / "results/prelock/PRELOCK_TERMINAL_ENGINEERING_RESULT.json",
        "manifest": V24_WORKSPACE / "results/prelock/PRELOCK_FAILURE_EVIDENCE_MANIFEST.json",
        "freeze": V24_WORKSPACE / "results/prelock/PRELOCK_FAILURE_EVIDENCE_FREEZE_VERIFICATION.json",
        "unit": V24_WORKSPACE / "results/prelock/unit-fixtures-run-0001.json",
        "registry": V24_WORKSPACE / "contracts/HISTORICAL_DECISION_RELATION_REGISTRY.json",
    }
    expected = binding.get("hashes", {})
    results_root = V24_WORKSPACE / "results/prelock"
    checks = {
        "binding_identity_exact": binding.get("execution_identity") == "V0_3_FIRST_REAL_SECURITY_WORKER_INVOCATION_V24",
        "terminal_state_exact": binding.get("state") == "FAIL_CLOSED_DURING_UNIT_VALIDATION_PRELOCK_TERMINAL_NO_RETRY_FROZEN_FAILURE_EVIDENCE",
        "frozen_hashes_exact": all(safe_regular_file(path) and sha256_file(path) == expected.get(name) for name, path in files.items()),
        "evidence_read_only": all(stat.S_IMODE(path.stat().st_mode) & 0o222 == 0 for path in results_root.rglob("*") if path.is_file()),
        "static_lock_absent": not (V24_WORKSPACE / "STATIC_EXECUTION_LOCK.json").exists(),
        "attempt_marker_absent": not list(V24_WORKSPACE.rglob("ATTEMPT_MARKER.json")),
        "runtime_evidence_absent": not list(V24_WORKSPACE.rglob("runtime-result-0001.json")),
        "counters_zero": binding.get("attempt") == binding.get("worker") == binding.get("codex") == "0_OF_1",
    }
    return {
        "record_type": "V24_IMMUTABLE_REFERENCE_VERIFICATION_RESULT",
        "status": "PASS" if all(checks.values()) else "FAIL_CLOSED",
        "checks": checks,
        "artifact_predecessor_for_v35": False,
    }


def verify_v25_reference_predecessor() -> dict[str, Any]:
    """Verify V25 terminal evidence and execution counters without mutating history."""
    binding = load_json(WORKSPACE / "contracts/V25_FROZEN_FAILURE_EVIDENCE_BINDING.json")
    files = {
        "terminal": V25_WORKSPACE / "results/prelock/PRELOCK_TERMINAL_ENGINEERING_RESULT.json",
        "manifest": V25_WORKSPACE / "results/prelock/PRELOCK_FAILURE_EVIDENCE_MANIFEST.json",
        "freeze": V25_WORKSPACE / "results/prelock/PRELOCK_FAILURE_EVIDENCE_FREEZE_VERIFICATION.json",
        "unit": V25_WORKSPACE / "results/prelock/unit-fixtures-run-0001.json",
        "primary": V25_WORKSPACE / "results/prelock/primary-static-validation-run-0001.json",
    }
    expected = binding.get("hashes", {})
    results_root = V25_WORKSPACE / "results/prelock"
    checks = {
        "binding_identity_exact": binding.get("execution_identity") == "V0_3_FIRST_REAL_SECURITY_WORKER_INVOCATION_V25",
        "terminal_state_exact": binding.get("status") == "FAIL_CLOSED_DURING_PRIMARY_STATIC_VALIDATION_PRELOCK_TERMINAL_NO_RETRY_FROZEN_FAILURE_EVIDENCE",
        "frozen_hashes_exact": all(safe_regular_file(path) and sha256_file(path) == expected.get(name) for name, path in files.items()),
        "evidence_read_only": all(stat.S_IMODE(path.stat().st_mode) & 0o222 == 0 for path in results_root.rglob("*") if path.is_file()),
        "canonical_evidence_root_exact": binding.get("canonical_evidence_root_sha256") == "f47e8cc6f846b6ee819f0852930e8e6d60374cb2bc30aa1710fe27dc907dc2e4",
        "static_lock_absent": not (V25_WORKSPACE / "STATIC_EXECUTION_LOCK.json").exists(),
        "attempt_marker_absent": not list(V25_WORKSPACE.rglob("ATTEMPT_MARKER.json")),
        "runtime_evidence_absent": not list(V25_WORKSPACE.rglob("runtime-result-0001.json")),
        "counters_zero": binding.get("execution", {}).get("attempt") == binding.get("execution", {}).get("worker") == binding.get("execution", {}).get("codex") == "0/1",
    }
    return {
        "record_type": "V25_IMMUTABLE_REFERENCE_VERIFICATION_RESULT",
        "status": "PASS" if all(checks.values()) else "FAIL_CLOSED",
        "checks": checks,
        "artifact_predecessor_for_v35": False,
    }


def verify_v26_reference_predecessor() -> dict[str, Any]:
    """Verify exact V26 terminal pre-lock evidence without mutating history."""
    binding = load_json(WORKSPACE / "contracts/V26_FROZEN_FAILURE_EVIDENCE_BINDING.json")
    files = {
        "terminal": V26_WORKSPACE / "results/prelock/PRELOCK_TERMINAL_ENGINEERING_RESULT.json",
        "manifest": V26_WORKSPACE / "results/prelock/PRELOCK_FAILURE_EVIDENCE_MANIFEST.json",
        "freeze": V26_WORKSPACE / "results/prelock/PRELOCK_FAILURE_EVIDENCE_FREEZE_VERIFICATION.json",
        "unit": V26_WORKSPACE / "results/prelock/unit-fixtures-run-0001.json",
        "primary": V26_WORKSPACE / "results/prelock/primary-static-validation-run-0001.json",
        "independent": V26_WORKSPACE / "results/prelock/independent-static-validation-run-0001.json",
    }
    expected = {
        "terminal": binding.get("terminal_sha256"),
        "manifest": binding.get("failure_manifest_sha256"),
        "freeze": binding.get("freeze_verification_sha256"),
        "unit": "68a229764d7ce43bcb442c90f4fc63aae434c8d1663a2623042da399383213b5",
        "primary": "f889435792d5f2b09c8c82820b65a6ff39ce32ad4a1e1db72ccf65bbd1dc482e",
        "independent": "f957590f07a642e6702bab62898e9d06e56b2247a151bfb9dd169d534c9e89cb",
    }
    results_root = V26_WORKSPACE / "results/prelock"
    checks = {
        "binding_identity_exact": binding.get("execution_identity") == "V0_3_FIRST_REAL_SECURITY_WORKER_INVOCATION_V26",
        "terminal_state_exact": binding.get("terminal_status") == "FAIL_CLOSED_DURING_INDEPENDENT_STATIC_VALIDATION_PRELOCK_TERMINAL_NO_RETRY_FROZEN_FAILURE_EVIDENCE",
        "failed_gate_exact": binding.get("failed_gate") == "I020C_COMPLETE_SYMBOL_GRAPH",
        "frozen_hashes_exact": all(safe_regular_file(path) and sha256_file(path) == expected[name] for name, path in files.items()),
        "evidence_read_only": all(stat.S_IMODE(path.stat().st_mode) & 0o222 == 0 for path in results_root.rglob("*") if path.is_file()),
        "canonical_evidence_root_exact": binding.get("canonical_evidence_root_sha256") == "1ff032bc531076421e45a311ede68e3593910a1e15dd868d0b3a50422ff2ac0b",
        "static_lock_absent": not (V26_WORKSPACE / "STATIC_EXECUTION_LOCK.json").exists(),
        "attempt_marker_absent": not list(V26_WORKSPACE.rglob("ATTEMPT_MARKER.json")),
        "runtime_evidence_absent": not list(V26_WORKSPACE.rglob("runtime-result-0001.json")),
        "counters_zero": binding.get("attempt") == binding.get("worker") == binding.get("codex") == "0/1",
    }
    return {
        "record_type": "V26_IMMUTABLE_REFERENCE_VERIFICATION_RESULT",
        "status": "PASS" if all(checks.values()) else "FAIL_CLOSED",
        "checks": checks,
        "artifact_predecessor_for_v35": False,
    }


def v16_tree_canonicalization_precheck() -> dict[str, Any]:
    """Primary V19 recomputation of the frozen V16 tree under the normative contract."""
    contract = load_json(WORKSPACE / "contracts/NORMATIVE_V16_TREE_CANONICALIZATION_CONTRACT.json")
    try:
        normative_root, member_count = normative_frozen_tree(V16_WORKSPACE)
        alternate_root, alternate_count = flattened_non_normative_tree(V16_WORKSPACE)
    except (OSError, ValueError, UnicodeError) as exc:
        return {"status": "FAIL_CLOSED", "error": f"{type(exc).__name__}:{exc}"}
    checks = {
        "contract_identity": contract.get("contract_identity") == "V16_FROZEN_TREE_CANONICALIZATION_V1",
        "member_count": member_count == alternate_count == V16_WORKSPACE_MEMBER_COUNT,
        "component_tuple_ordering": contract.get("ordering", {}).get("algorithm")
        == "LEXICOGRAPHIC_TUPLE_OF_UTF8_ENCODED_POSIX_PATH_COMPONENTS",
        "record_serialization": contract.get("record")
        == "UTF8_RELATIVE_POSIX_PATH || NUL_0X00 || ASCII_DIGEST || LF_0X0A",
        "normative_root": normative_root == contract.get("expected_root_sha256") == V16_WORKSPACE_TREE_ROOT,
        "alternate_root_observed": alternate_root == V16_NON_NORMATIVE_FLATTENED_ROOT,
        "alternate_root_rejected": normative_root != alternate_root,
        "independent_recomputation_required": contract.get("independent_recomputation_required") is True,
        "hardcoding_prohibited": contract.get("hardcoded_root_or_trust_core_result") == "PROHIBITED",
    }
    return {
        "status": "PASS" if all(checks.values()) else "FAIL_CLOSED",
        "checks": checks,
        "member_count": member_count,
        "normative_root_sha256": normative_root,
        "rejected_alternate_root_sha256": alternate_root,
    }


def workspace_write_boundary_precheck() -> dict[str, Any]:
    """Prove the exact V26 root and predecessor deny-write semantics without writing."""
    contract_path = WORKSPACE / "contracts/V35_WORKSPACE_WRITE_BOUNDARY_CONTRACT.json"
    good = WORKSPACE / "results/prelock/.boundary-precheck-probe"
    failures: dict[str, str] = {}
    try:
        good_attestation = authorize_write(
            good,
            operation_identity="PREFLIGHT_WORKSPACE_BOUNDARY",
            write_generation_identity="V35_PREFLIGHT_GENERATION_0001",
            expected_destination=good,
        )
    except Exception as exc:
        good_attestation = {}
        failures["exact_v35_destination"] = f"{type(exc).__name__}:{exc}"
    for label, destination in {
        "v14_write": V14_WORKSPACE / "results/prelock/forbidden-v19.json",
        "v15_write": V15_WORKSPACE / "results/prelock/forbidden-v19.json",
        "v16_write": V16_WORKSPACE / "results/prelock/forbidden-v19.json",
        "v17_write": V17_WORKSPACE / "results/prelock/forbidden-v19.json",
        "v18_write": V18_WORKSPACE / "static-run-v18/forbidden-v35.json",
        "v19_write": V19_WORKSPACE / "results/prelock/forbidden-v35.json",
        "v20_write": V20_WORKSPACE / "results/prelock/forbidden-v35.json",
        "v21_write": V21_WORKSPACE / "results/prelock/forbidden-v35.json",
        "v22_write": V22_WORKSPACE / "results/prelock/forbidden-v35.json",
        "v23_write": V23_WORKSPACE / "results/prelock/forbidden-v35.json",
        "v24_write": V24_WORKSPACE / "results/prelock/forbidden-v35.json",
        "v25_write": V25_WORKSPACE / "results/prelock/forbidden-v35.json",
    }.items():
        try:
            authorize_write(
                destination,
                operation_identity=f"NEGATIVE_{label.upper()}",
                write_generation_identity="V35_NEGATIVE_PREFLIGHT",
                expected_destination=destination,
            )
        except Exception as exc:
            failures[label] = f"REJECTED:{type(exc).__name__}:{exc}"
        else:
            failures[label] = "UNEXPECTEDLY_ACCEPTED"
    read_results: dict[str, str] = {}
    for label, source in {
        "v14_incident_evidence": V14_WORKSPACE / "results/prelock/fresh-preflight-run-0001.json",
        "v15_terminal_evidence": V15_WORKSPACE / "results/prelock/PRELOCK_TERMINAL_ENGINEERING_RESULT.json",
        "v16_failure_manifest": V16_WORKSPACE / "results/prelock/PRELOCK_FAILURE_EVIDENCE_MANIFEST.json",
        "v17_terminal_evidence": V17_WORKSPACE / "results/prelock/PRELOCK_TERMINAL_ENGINEERING_RESULT.json",
        "v18_terminal_evidence": V18_WORKSPACE / "static-run-v18/TERMINAL_ENGINEERING_RESULT.json",
        "v19_terminal_evidence": V19_WORKSPACE / "results/prelock/PRELOCK_TERMINAL_ENGINEERING_RESULT.json",
        "v25_terminal_evidence": V25_WORKSPACE / "results/prelock/PRELOCK_TERMINAL_ENGINEERING_RESULT.json",
    }.items():
        try:
            read_results[label] = str(authorize_read(source, operation_identity=f"READ_{label.upper()}"))
        except Exception as exc:
            read_results[label] = f"FAILED:{type(exc).__name__}:{exc}"
    checks = {
        "boundary_identity_exact": BOUNDARY_EXECUTION_IDENTITY == EXECUTION_IDENTITY,
        "boundary_workspace_exact": BOUNDARY_WORKSPACE.resolve(strict=True) == WORKSPACE.resolve(strict=True),
        "contract_exact": safe_regular_file(contract_path)
        and load_json(contract_path).get("record_type") == "V35_FAIL_BEFORE_WRITE_WORKSPACE_IDENTITY_GUARD_CONTRACT"
        and load_json(contract_path).get("failure_semantics") == "FAIL_CLOSED_BEFORE_ANY_FILESYSTEM_MUTATION",
        "exact_v35_destination_accepted": good_attestation.get("status") == "PASS_FAIL_BEFORE_WRITE_BOUNDARY",
        "v14_write_rejected": failures.get("v14_write", "").startswith("REJECTED:"),
        "v15_write_rejected": failures.get("v15_write", "").startswith("REJECTED:"),
        "v16_write_rejected": failures.get("v16_write", "").startswith("REJECTED:"),
        "v17_write_rejected": failures.get("v17_write", "").startswith("REJECTED:"),
        "v18_write_rejected": failures.get("v18_write", "").startswith("REJECTED:"),
        "v19_write_rejected": failures.get("v19_write", "").startswith("REJECTED:"),
        "v20_write_rejected": failures.get("v20_write", "").startswith("REJECTED:"),
        "v21_write_rejected": failures.get("v21_write", "").startswith("REJECTED:"),
        "v22_write_rejected": failures.get("v22_write", "").startswith("REJECTED:"),
        "v23_write_rejected": failures.get("v23_write", "").startswith("REJECTED:"),
        "v24_write_rejected": failures.get("v24_write", "").startswith("REJECTED:"),
        "v25_write_rejected": failures.get("v25_write", "").startswith("REJECTED:"),
        "predecessor_reads_allowed": all(not value.startswith("FAILED:") for value in read_results.values()),
        "precheck_probe_not_created": not good.exists(),
    }
    return {
        "record_type": "V35_WORKSPACE_WRITE_BOUNDARY_PREFLIGHT",
        "status": "PASS" if all(checks.values()) else "FAIL_CLOSED_BEFORE_WRITE",
        "checks": checks,
        "good_attestation": good_attestation,
        "negative_results": failures,
        "predecessor_read_results": read_results,
        "attempt_count_if_failed": 0,
        "worker_invocation_count_if_failed": 0,
        "codex_as_worker_invocation_count_if_failed": 0,
    }
def prompt_identity_binding_precheck() -> dict[str, Any]:
    """Reopen the final-prompt-first binding using exact bytes and typed artifacts."""

    request_path = WORKSPACE / "contracts/WORKER_REQUEST.json"
    binding_path = WORKSPACE / "contracts/PROMPT_IDENTITY_BINDING.json"
    contract_path = WORKSPACE / "contracts/PROMPT_IDENTITY_BINDING_CONTRACT.json"
    paths = (PROMPT_PATH, request_path, binding_path, contract_path)
    if not all(safe_regular_file(path) for path in paths):
        return {
            "status": "FAIL_CLOSED",
            "reason": "MISSING_SYMLINKED_OR_NON_REGULAR_PROMPT_IDENTITY_ARTIFACT",
            "attempt_count_if_failed": 0,
            "worker_invocation_count_if_failed": 0,
            "codex_as_worker_invocation_count_if_failed": 0,
        }
    request = load_json(request_path)
    binding = load_json(binding_path)
    contract = load_json(contract_path)
    actual_prompt_digest = sha256_file(PROMPT_PATH)
    actual_request_digest = sha256_file(request_path)
    bound_digest = request.get("prompt", {}).get("sha256")
    artifact_identity = authoritative_artifact_digest_precheck()
    expected_order = [
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
        "ONLY_THEN_ALLOW_VALIDATION_TO_PASS",
    ]
    checks = {
        "canonical_prompt_path": PROMPT_PATH.resolve(strict=True) == PROMPT_PATH,
        "authoritative_artifact_identity_pass": artifact_identity.get("status") == "PASS",
        "request_bound_digest_matches_prompt": bound_digest == actual_prompt_digest,
        "binding_first_digest_matches": binding.get("first_prompt_sha256") == actual_prompt_digest,
        "binding_bound_digest_matches": binding.get("worker_request_bound_prompt_sha256") == actual_prompt_digest,
        "binding_reread_digest_matches": binding.get("reread_prompt_sha256") == actual_prompt_digest,
        "binding_request_digest_matches": binding.get("worker_request_sha256") == actual_request_digest,
        "binding_byte_length_matches": binding.get("prompt_byte_length") == PROMPT_PATH.stat().st_size,
        "binding_status_pass": binding.get("status") == "PASS_FINAL_PROMPT_BOUND_REREAD_REHASHED",
        "binding_generation_exact": binding.get("generation_identity") == GENERATION_IDENTITY,
        "binding_mode_exact": binding.get("required_mode") == "0444" and binding.get("verified_mode") == 0o444,
        "typed_prompt_binding_verdict": prompt_binding_verdict(PROMPT_PATH, binding, request).get("status") == "PASS",
        "binding_order_exact": binding.get("binding_order") == expected_order,
        "binding_computed_not_hand_entered": binding.get("digest_source") == "FINAL_PROMPT_BYTES_COMPUTED_NOT_HAND_ENTERED",
        "post_bind_mutation_prohibited": binding.get("post_bind_prompt_mutation") == "PROHIBITED",
        "bound_artifacts_read_only": all(stat.S_IMODE(path.stat().st_mode) == 0o444 for path in (PROMPT_PATH, request_path, binding_path)),
        "contract_order_exact": contract.get("binding_order") == expected_order,
        "contract_final_prompt_first": contract.get("final_prompt_first_digest_binding") == "REQUIRED",
        "contract_digest_hand_entry_prohibited": contract.get("digest_hand_entry") == "PROHIBITED",
        "contract_stale_reuse_prohibited": contract.get("stale_or_manual_digest_reuse") == "PROHIBITED",
        "zero_execution_counts": binding.get("attempt_count") == 0
        and binding.get("worker_invocation_count") == 0
        and binding.get("codex_as_worker_invocation_count") == 0,
    }
    return {
        "status": "PASS" if all(checks.values()) else "FAIL_CLOSED",
        "contract": "FINAL_PROMPT_FIRST_DIGEST_BINDING_V1",
        "checks": checks,
        "actual_prompt_sha256": actual_prompt_digest,
        "worker_request_bound_prompt_sha256": bound_digest,
        "reread_prompt_sha256": binding.get("reread_prompt_sha256"),
        "worker_request_sha256": actual_request_digest,
        "authoritative_artifact_digest_binding_sha256": artifact_identity.get("binding_record_sha256"),
        "attempt_count_if_failed": 0,
        "worker_invocation_count_if_failed": 0,
        "codex_as_worker_invocation_count_if_failed": 0,
    }


def prompt_identity_binding_verdict(
    *,
    final_prompt_bytes: bytes,
    bound_prompt_sha256: str,
    reread_prompt_bytes: bytes | None,
    digest_source: str,
    post_bind_prompt_mutation: str,
    prompt_is_regular_file: bool = True,
    prompt_is_symlink: bool = False,
) -> dict[str, Any]:
    """Pure fail-closed oracle for final-prompt-first identity regressions."""

    first_digest = hashlib.sha256(final_prompt_bytes).hexdigest()
    reread_digest = (
        hashlib.sha256(reread_prompt_bytes).hexdigest()
        if isinstance(reread_prompt_bytes, bytes)
        else None
    )
    checks = {
        "prompt_regular_file": prompt_is_regular_file,
        "prompt_not_symlink": not prompt_is_symlink,
        "bound_digest_matches_final_bytes": bound_prompt_sha256 == first_digest,
        "reread_performed": reread_digest is not None,
        "reread_digest_matches_final_bytes": reread_digest == first_digest,
        "digest_computed_not_hand_entered": digest_source
        == "FINAL_PROMPT_BYTES_COMPUTED_NOT_HAND_ENTERED",
        "post_bind_prompt_mutation_prohibited": post_bind_prompt_mutation == "PROHIBITED",
    }
    return {
        "status": "PASS" if all(checks.values()) else "FAIL_CLOSED",
        "checks": checks,
        "first_prompt_sha256": first_digest,
        "bound_prompt_sha256": bound_prompt_sha256,
        "reread_prompt_sha256": reread_digest,
    }


def exact_environment() -> dict[str, str]:
    return {
        "CODEX_HOME": str(SANDBOX_CODEX_HOME),
        "HOME": "/home/nobcoder",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "NO_COLOR": "1",
        "RUST_BACKTRACE": "0",
        "TEMP": "/tmp",
        "TMP": "/tmp",
        "TMPDIR": "/tmp",
        "XDG_CACHE_HOME": f"{SANDBOX_RUN}/xdg-cache",
        "XDG_CONFIG_HOME": f"{SANDBOX_RUN}/xdg-config",
        "XDG_DATA_HOME": f"{SANDBOX_RUN}/xdg-data",
    }


def exact_python_environment() -> dict[str, str]:
    """Exact host-Python child environment with deterministic bytecode suppression."""
    return {
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONHASHSEED": "0",
    }


def python_execution_policy_verdict(
    argv: Iterable[str],
    environment: Mapping[str, str],
    cache_destination: Path | None = None,
) -> dict[str, Any]:
    """Pure oracle for Python child execution; it performs no filesystem mutation."""
    values = list(argv)
    env = dict(environment)
    cache_allowed = cache_destination is None
    checks = {
        "exact_interpreter": len(values) >= 2 and values[0] == str(PYTHON),
        "bytecode_flag": len(values) >= 2 and values[1] == "-B",
        "bytecode_environment": env.get("PYTHONDONTWRITEBYTECODE") == "1",
        "deterministic_hash_seed": env.get("PYTHONHASHSEED") == "0",
        "no_cache_prefix": "PYTHONPYCACHEPREFIX" not in env,
        "suppression_has_no_cache_destination": cache_allowed,
    }
    return {
        "status": "PASS" if all(checks.values()) else "FAIL_CLOSED_BEFORE_PYTHON_EXECUTION",
        "checks": checks,
        "filesystem_mutation_performed": False,
    }


def python_cache_policy_precheck() -> dict[str, Any]:
    """Prove the frozen suppression design and zero unaccounted Python cache writes."""
    policy_path = WORKSPACE / "contracts/PYTHON_RUNTIME_SIDE_EFFECT_POLICY.json"
    successor_path = WORKSPACE / "contracts/SUCCESSOR_V35_PYTHON_CACHE_AND_WRITE_BOUNDARY_CONTRACT.json"
    accounting_path = WORKSPACE / "contracts/RUNTIME_FILESYSTEM_MUTATION_ACCOUNTING_CONTRACT.json"
    policy = load_json(policy_path) if safe_regular_file(policy_path) else {}
    successor = load_json(successor_path) if safe_regular_file(successor_path) else {}
    accounting = load_json(accounting_path) if safe_regular_file(accounting_path) else {}
    runner_source = (WORKSPACE / "src/runner_v35.py").read_text(encoding="utf-8")
    cache_paths = sorted(
        path.relative_to(WORKSPACE).as_posix()
        for path in WORKSPACE.rglob("*")
        if path.is_file() and (path.suffix == ".pyc" or "__pycache__" in path.parts)
    )
    py_env = exact_python_environment()
    checks = {
        "deterministic_suppression_selected": policy.get("bytecode_policy") == "DETERMINISTIC_SUPPRESSION",
        "python_minus_b_required": policy.get("interpreter_argv_requirement") == "EXACT_PYTHON_BINARY_FOLLOWED_BY_MINUS_B",
        "exact_environment": py_env == {
            "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8",
            "PYTHONDONTWRITEBYTECODE": "1", "PYTHONHASHSEED": "0",
        },
        "no_pycacheprefix": "PYTHONPYCACHEPREFIX" not in py_env,
        "worker_gate_uses_minus_b": worker_launch_gate_argv()[0:2] == [str(PYTHON), "-B"],
        "observer_uses_minus_b": temporal_observer_argv()[0:2] == [str(PYTHON), "-B"],
        "worker_gate_policy_pass": python_execution_policy_verdict(
            worker_launch_gate_argv(), py_env
        ).get("status") == "PASS",
        "observer_policy_pass": python_execution_policy_verdict(
            temporal_observer_argv(), py_env
        ).get("status") == "PASS",
        "runner_has_no_empty_child_env": "env={}" not in runner_source,
        "runner_uses_exact_python_environment": runner_source.count("env=exact_python_environment()") >= 4,
        "normative_successor_contract": successor.get("selection") == "EXACT_GOVERNANCE_BOUND_SUCCESSOR_CONTRACT"
        and successor.get("selector_authority") == "V34_TERMINAL_AND_V35_SUCCESSOR_DECISION"
        and successor.get("generation_identity") == GENERATION_IDENTITY
        and successor.get("governance_authority_sha256") == EXPECTED_DIGESTS["v35_authorization_lock"],
        "mutation_accounting_zero": accounting.get("unaccounted_filesystem_mutation_count_required") == 0,
        "no_cache_artifacts": not cache_paths,
    }
    return {
        "record_type": "V35_PYTHON_CACHE_POLICY_PREFLIGHT",
        "status": "PASS" if all(checks.values()) else "FAIL_CLOSED_UNACCOUNTED_MUTATION",
        "checks": checks,
        "python_environment": py_env,
        "cache_paths": cache_paths,
        "unaccounted_filesystem_mutation_count": len(cache_paths),
    }


def codex_argv() -> list[str]:
    return [
        str(SANDBOX_CODEX_BINARY),
        "-a",
        "never",
        "--enable",
        "skip_host_skill_discovery",
        "--disable",
        "plugins",
        "--add-dir",
        str(SANDBOX_FIXTURE),
        "exec",
        "--ephemeral",
        "--json",
        "--color",
        "never",
        "--output-schema",
        str(SANDBOX_SCHEMAS / MODEL_OUTPUT_SCHEMA.name),
        "--output-last-message",
        str(SANDBOX_RUN / "last-message.json"),
        "-s",
        "read-only",
        "-C",
        str(SANDBOX_CONTEXT),
        "-m",
        MODEL_IDENTITY,
        "--skip-git-repo-check",
        "-",
    ]


def runtime_evidence_paths(run_root: Path = STATIC_RUN) -> dict[str, Path]:
    return {
        "events": run_root / "temporal-process-observer-events-0001.jsonl",
        "snapshot": run_root / "temporal-process-observer-snapshot-0001.json",
        "observer_ready": run_root / "temporal-process-observer-ready-0001.json",
        "observer_root": run_root / "temporal-process-observer-root-0001.json",
        "observer_root_bound": run_root / "temporal-process-observer-root-bound-0001.json",
        "observer_stop": run_root / "temporal-process-observer-stop-0001.json",
        "worker_ready": run_root / "worker-launch-gate-ready-0001.json",
        "worker_go": run_root / "worker-launch-gate-go-0001.json",
        "trace_prefix": run_root / "trace",
    }


def bwrap_argv(run_root: Path = STATIC_RUN) -> list[str]:
    argv = [
        str(BWRAP),
        "--unshare-user",
        "--unshare-pid",
        "--unshare-ipc",
        "--unshare-uts",
        "--die-with-parent",
        "--new-session",
        "--cap-drop",
        "ALL",
        "--ro-bind",
        "/",
        "/",
        "--tmpfs",
        "/home/nobcoder",
        "--dir",
        str(SANDBOX_CODEX_HOME),
        "--ro-bind",
        str(CODEX_AUTH),
        str(SANDBOX_CODEX_HOME / "auth.json"),
        "--ro-bind",
        str(CODEX_CONFIG),
        str(SANDBOX_CODEX_HOME / "config.toml"),
        "--tmpfs",
        "/run",
        "--dir",
        str(SANDBOX_BASE),
        "--dir",
        str(SANDBOX_CODEX_ROOT),
        "--ro-bind",
        str(CODEX_PACKAGE_ROOT),
        str(SANDBOX_CODEX_ROOT),
        "--dir",
        str(SANDBOX_RUN),
        "--bind",
        str(run_root),
        str(SANDBOX_RUN),
        "--dir",
        str(SANDBOX_WORK),
        "--dir",
        str(SANDBOX_CONTEXT),
        "--ro-bind",
        str(CONTEXT_ROOT),
        str(SANDBOX_CONTEXT),
        "--dir",
        str(SANDBOX_FIXTURE),
        "--ro-bind",
        str(FIXTURE_ROOT),
        str(SANDBOX_FIXTURE),
        "--dir",
        str(SANDBOX_SCHEMAS),
        "--ro-bind",
        str(WORKSPACE / "schemas"),
        str(SANDBOX_SCHEMAS),
        "--proc",
        "/proc",
        "--dev",
        "/dev",
        "--tmpfs",
        "/tmp",
        "--tmpfs",
        "/var/tmp",
        "--clearenv",
    ]
    for key, value in sorted(exact_environment().items()):
        argv.extend(["--setenv", key, value])
    argv.extend(["--chdir", str(SANDBOX_CONTEXT), "--", *codex_argv()])
    return argv


def worker_launch_gate_argv(run_root: Path = STATIC_RUN) -> list[str]:
    paths = runtime_evidence_paths(run_root)
    return [
        str(PYTHON),
        "-B",
        str(WORKER_LAUNCH_GATE),
        "--ready",
        str(paths["worker_ready"]),
        "--go",
        str(paths["worker_go"]),
        "--timeout-seconds",
        "30",
        "--",
        *bwrap_argv(run_root),
    ]


def temporal_observer_argv(run_root: Path = STATIC_RUN, fixture_identity: str = "runtime-0001") -> list[str]:
    paths = runtime_evidence_paths(run_root)
    return [
        str(PYTHON),
        "-B",
        str(TEMPORAL_OBSERVER),
        "--events",
        str(paths["events"]),
        "--snapshot",
        str(paths["snapshot"]),
        "--ready",
        str(paths["observer_ready"]),
        "--root",
        str(paths["observer_root"]),
        "--root-bound",
        str(paths["observer_root_bound"]),
        "--stop",
        str(paths["observer_stop"]),
        "--trace-dir",
        str(run_root),
        "--fixture-identity",
        fixture_identity,
        "--poll-interval-ns",
        "100000",
        "--max-correlation-slack-ns",
        "250000000",
    ]


def strace_argv(run_root: Path = STATIC_RUN) -> list[str]:
    paths = runtime_evidence_paths(run_root)
    return [
        str(STRACE),
        "-ff",
        "-qq",
        "-yy",
        "--decode-pids=pidns",
        "-s",
        "4096",
        "-o",
        str(paths["trace_prefix"]),
        "-e",
        "trace=%file,%process,%network,read,write,writev,close",
        *worker_launch_gate_argv(run_root),
    ]


@dataclass(frozen=True)
class BwrapOperation:
    option: str
    operands: tuple[str, ...]


BWRAP_ARITY = {
    "--unshare-user": 0,
    "--unshare-pid": 0,
    "--unshare-ipc": 0,
    "--unshare-uts": 0,
    "--die-with-parent": 0,
    "--new-session": 0,
    "--cap-drop": 1,
    "--ro-bind": 2,
    "--tmpfs": 1,
    "--dir": 1,
    "--bind": 2,
    "--proc": 1,
    "--dev": 1,
    "--clearenv": 0,
    "--setenv": 2,
    "--chdir": 1,
}


def parse_bwrap(argv: Iterable[str]) -> tuple[list[BwrapOperation], list[str]]:
    values = list(argv)
    if not values or values[0] != str(BWRAP):
        raise ContractViolation("unexpected bubblewrap executable")
    operations: list[BwrapOperation] = []
    cursor = 1
    while cursor < len(values):
        token = values[cursor]
        if token == "--":
            command = values[cursor + 1 :]
            if not command:
                raise ContractViolation("missing bubblewrap command")
            return operations, command
        if token not in BWRAP_ARITY:
            raise ContractViolation(f"unknown bubblewrap option: {token}")
        arity = BWRAP_ARITY[token]
        operands = values[cursor + 1 : cursor + 1 + arity]
        if len(operands) != arity:
            raise ContractViolation(f"malformed {token}")
        operations.append(BwrapOperation(token, tuple(operands)))
        cursor += arity + 1
    raise ContractViolation("missing bubblewrap option terminator")


def _canonical_absolute_path(value: str) -> bool:
    path = Path(value)
    return path.is_absolute() and str(path) == value and ".." not in path.parts


def _within(path: str, root: str) -> bool:
    value = Path(path)
    base = Path(root)
    return value == base or base in value.parents


def bind_destination_feasibility_precheck(argv: Iterable[str]) -> dict[str, Any]:
    """Evaluate bind destinations in bubblewrap's ordered construction namespace.

    Host/caller-side source operands are checked before considering any sandbox
    paths created by earlier options.  Missing destinations may only be created
    below a previously established writable mount.  A destination explicitly
    prepared by ``--dir`` is recorded separately from an implicit mountpoint.
    """

    try:
        operations, _command = parse_bwrap(argv)
    except ContractViolation as exc:
        return {"status": "FAIL_CLOSED", "reason": "ARGV_PARSE", "detail": str(exc)}

    created_dirs: set[str] = set()
    created_files: set[str] = set()
    prepared_dirs: set[str] = set()
    writable_roots: set[str] = set()
    readonly_roots: set[str] = set()
    opaque_roots: set[str] = set()
    events: list[dict[str, Any]] = []
    failures: list[dict[str, Any]] = []

    def masked_by_created_mount(path: str) -> bool:
        return any(_within(path, root) and path != root for root in opaque_roots)

    def sandbox_kind(path: str) -> str | None:
        if path in created_dirs:
            return "DIRECTORY"
        if path in created_files:
            return "FILE"
        if not masked_by_created_mount(path):
            host = Path(path)
            if host.is_dir() and not host.is_symlink():
                return "DIRECTORY"
            if host.is_file() and not host.is_symlink():
                return "FILE"
        return None

    def writable_parent(path: str) -> bool:
        parent = str(Path(path).parent)
        eligible = [root for root in writable_roots if _within(parent, root)]
        if not eligible:
            return False
        most_specific = max(eligible, key=lambda item: len(Path(item).parts))
        blocking = [root for root in readonly_roots if _within(parent, root)]
        return not blocking or len(Path(most_specific).parts) > max(len(Path(item).parts) for item in blocking)

    def ensure_destination(path: str, expected_kind: str, *, require_prepared: bool = False) -> bool:
        if not _canonical_absolute_path(path):
            failures.append({"reason": "NON_CANONICAL_DESTINATION", "path": path})
            return False
        observed = sandbox_kind(path)
        if observed is None:
            if not writable_parent(path):
                failures.append({"reason": "DESTINATION_ABSENT_UNDER_NON_WRITABLE_TOPOLOGY", "path": path})
                return False
            (created_dirs if expected_kind == "DIRECTORY" else created_files).add(path)
            observed = expected_kind
        if observed != expected_kind:
            failures.append({"reason": "DESTINATION_TYPE_MISMATCH", "path": path, "expected": expected_kind, "observed": observed})
            return False
        if require_prepared and path not in prepared_dirs:
            failures.append({"reason": "DESTINATION_NOT_EXPLICITLY_PREPARED", "path": path})
            return False
        return True

    for index, operation in enumerate(operations):
        option = operation.option
        operands = operation.operands
        event: dict[str, Any] = {"operation_index": index, "option": option, "operands": list(operands)}
        if option == "--dir":
            destination = operands[0]
            ok = ensure_destination(destination, "DIRECTORY")
            if ok:
                created_dirs.add(destination)
                prepared_dirs.add(destination)
            event["status"] = "PASS" if ok else "FAIL"
        elif option == "--tmpfs":
            destination = operands[0]
            ok = ensure_destination(destination, "DIRECTORY")
            if ok:
                created_dirs = {item for item in created_dirs if not (_within(item, destination) and item != destination)}
                created_files = {item for item in created_files if not _within(item, destination)}
                prepared_dirs = {item for item in prepared_dirs if not (_within(item, destination) and item != destination)}
                created_dirs.add(destination)
                writable_roots.add(destination)
                opaque_roots.add(destination)
                readonly_roots = {item for item in readonly_roots if not _within(item, destination)}
            event["status"] = "PASS" if ok else "FAIL"
        elif option in {"--ro-bind", "--bind"}:
            source, destination = operands
            source_path = Path(source)
            source_kind = (
                "DIRECTORY" if source_path.is_dir() and not source_path.is_symlink()
                else "FILE" if source_path.is_file() and not source_path.is_symlink()
                else None
            )
            source_ok = _canonical_absolute_path(source) and source_kind is not None
            if not source_ok:
                failures.append({"reason": "SOURCE_NOT_RESOLVABLE_IN_CALLER_NAMESPACE", "path": source})
            require_prepared = destination in {str(SANDBOX_CODEX_ROOT), str(SANDBOX_RUN)}
            destination_ok = source_kind is not None and ensure_destination(destination, source_kind, require_prepared=require_prepared)
            ok = source_ok and destination_ok
            if ok:
                if source_kind == "DIRECTORY":
                    created_dirs.add(destination)
                else:
                    created_files.add(destination)
                if option == "--ro-bind":
                    readonly_roots.add(destination)
                    if destination != "/":
                        opaque_roots.add(destination)
                    writable_roots = {item for item in writable_roots if not _within(item, destination)}
                else:
                    writable_roots.add(destination)
                    opaque_roots.add(destination)
                    readonly_roots = {item for item in readonly_roots if not _within(item, destination)}
            event.update({"source_kind": source_kind, "source_namespace": "HOST_CALLER", "status": "PASS" if ok else "FAIL"})
        elif option in {"--proc", "--dev"}:
            destination = operands[0]
            ok = ensure_destination(destination, "DIRECTORY")
            event["status"] = "PASS" if ok else "FAIL"
        else:
            event["status"] = "NOT_APPLICABLE"
        events.append(event)

    runtime_bind = [
        item for item in events
        if item["option"] == "--ro-bind"
        and item["operands"] == [str(CODEX_PACKAGE_ROOT), str(SANDBOX_CODEX_ROOT)]
    ]
    output_bind = [
        item for item in events
        if item["option"] == "--bind"
        and item["operands"] == [str(STATIC_RUN), str(SANDBOX_RUN)]
    ]
    invariants = {
        "runtime_bind_exactly_once": len(runtime_bind) == 1,
        "runtime_source_host_resolvable": CODEX_PACKAGE_ROOT.is_dir() and not CODEX_PACKAGE_ROOT.is_symlink(),
        "runtime_destination_prepared_before_bind": str(SANDBOX_CODEX_ROOT) in prepared_dirs,
        "runtime_destination_under_authorized_run_tmpfs": _within(str(SANDBOX_CODEX_ROOT), "/run"),
        "output_bind_exactly_once": len(output_bind) == 1,
        "output_destination_prepared_before_bind": str(SANDBOX_RUN) in prepared_dirs,
        "all_bind_sources_host_caller_namespace": all(
            event.get("source_namespace") == "HOST_CALLER"
            for event in events if event["option"] in {"--ro-bind", "--bind"}
        ),
        "no_failed_destination_event": not failures,
    }
    return {
        "status": "PASS" if all(invariants.values()) else "FAIL_CLOSED",
        "contract": "BIND_DESTINATION_FEASIBILITY_PRECHECK_V1",
        "invariants": invariants,
        "failures": failures,
        "ordered_events": events,
        "attempt_count_if_failed": 0,
        "worker_invocation_count_if_failed": 0,
        "codex_as_worker_invocation_count_if_failed": 0,
    }


def v2_locked_bwrap_argv() -> list[str]:
    """Return the frozen V2 bubblewrap argv without executing predecessor code."""

    lock = load_json(V2_WORKSPACE / "STATIC_EXECUTION_LOCK.json")
    argv = lock.get("strace_argv")
    if not isinstance(argv, list) or str(BWRAP) not in argv:
        raise ContractViolation("V2 locked argv unavailable")
    start = argv.index(str(BWRAP))
    return [str(item) for item in argv[start:]]


def validate_execution_plan(argv: Iterable[str]) -> dict[str, Any]:
    try:
        operations, command = parse_bwrap(argv)
    except ContractViolation as exc:
        return {"status": "FAIL", "reason": str(exc)}
    binds = [item for item in operations if item.option == "--bind"]
    ro_binds = [item for item in operations if item.option == "--ro-bind"]
    env = {item.operands[0]: item.operands[1] for item in operations if item.option == "--setenv"}
    feasibility = bind_destination_feasibility_precheck(argv)
    checks = {
        "exact_codex_command": command == codex_argv(),
        "one_writable_host_bind": binds == [BwrapOperation("--bind", (str(STATIC_RUN), str(SANDBOX_RUN)))],
        "host_root_read_only": BwrapOperation("--ro-bind", ("/", "/")) in ro_binds,
        "target_absent": not any("target" in operand.lower() for item in operations for operand in item.operands),
        "worker_tool_network_default_deny": "--search" not in command,
        "provider_network_not_mislabeled_as_target": not any(item.option == "--unshare-net" for item in operations),
        "home_masked": BwrapOperation("--tmpfs", ("/home/nobcoder",)) in operations,
        "auth_read_only_runtime_internal": BwrapOperation("--ro-bind", (str(CODEX_AUTH), str(SANDBOX_CODEX_HOME / "auth.json"))) in ro_binds,
        "dedicated_config_read_only": BwrapOperation("--ro-bind", (str(CODEX_CONFIG), str(SANDBOX_CODEX_HOME / "config.toml"))) in ro_binds,
        "fixture_read_only": BwrapOperation("--ro-bind", (str(FIXTURE_ROOT), str(SANDBOX_FIXTURE))) in ro_binds,
        "context_read_only": BwrapOperation("--ro-bind", (str(CONTEXT_ROOT), str(SANDBOX_CONTEXT))) in ro_binds,
        "exact_environment": env == exact_environment(),
        "exact_cwd": BwrapOperation("--chdir", (str(SANDBOX_CONTEXT),)) in operations,
        "clearenv_once": sum(item.option == "--clearenv" for item in operations) == 1,
        "no_unsandboxed_fallback": "read-only" in command,
        "no_daybreak": all("daybreak" not in token.lower() for token in command),
        "exact_model": ["-m", MODEL_IDENTITY] in [command[index : index + 2] for index in range(len(command) - 1)],
        "bind_destination_feasibility": feasibility["status"] == "PASS",
    }
    return {
        "status": "PASS" if all(checks.values()) else "FAIL",
        "checks": checks,
        "bind_destination_feasibility": feasibility,
    }


def inspect_runtime_identity() -> dict[str, Any]:
    package: dict[str, Any] | None = None
    if safe_regular_file(CODEX_PACKAGE):
        loaded = load_json(CODEX_PACKAGE)
        package = loaded if isinstance(loaded, dict) else None
    try:
        config = tomllib.loads(CODEX_CONFIG.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError):
        config = {}
    auth_mode = stat.S_IMODE(CODEX_AUTH.stat().st_mode) if safe_regular_file(CODEX_AUTH) else None
    checks = {
        "codex_binary_regular": safe_regular_file(CODEX_BINARY),
        "codex_binary_executable": safe_regular_file(CODEX_BINARY) and os.access(CODEX_BINARY, os.X_OK),
        "codex_binary_digest": safe_regular_file(CODEX_BINARY) and sha256_file(CODEX_BINARY) == EXPECTED_DIGESTS["codex_binary"],
        "codex_package_digest": safe_regular_file(CODEX_PACKAGE) and sha256_file(CODEX_PACKAGE) == EXPECTED_DIGESTS["codex_package"],
        "codex_package_version": package is not None and package.get("version") == "0.166.0",
        "dedicated_config_digest": safe_regular_file(CODEX_CONFIG) and sha256_file(CODEX_CONFIG) == EXPECTED_DIGESTS["codex_config"],
        "model_pinned_by_argv_or_exact_config": config.get("model") in (None, MODEL_IDENTITY)
        and "daybreak" not in str(config.get("model", "")).lower(),
        "update_check_disabled": config.get("check_for_update_on_startup") is False,
        "runtime_auth_opaque_regular_0600": safe_regular_file(CODEX_AUTH) and auth_mode == 0o600,
    }
    return {
        "record_type": "V35_RUNTIME_IDENTITY_VERDICT",
        "status": "PASS" if all(checks.values()) else "FAIL_CLOSED_BEFORE_STATIC_LOCK_AND_ATTEMPT",
        "checks": checks,
        "binary_path": str(CODEX_BINARY),
        "binary_sha256": sha256_file(CODEX_BINARY) if safe_regular_file(CODEX_BINARY) else None,
        "package_sha256": sha256_file(CODEX_PACKAGE) if safe_regular_file(CODEX_PACKAGE) else None,
        "config_sha256": sha256_file(CODEX_CONFIG) if safe_regular_file(CODEX_CONFIG) else None,
        "provider_auth_evidence": "EXISTENCE_TYPE_MODE_ONLY_CONTENT_AND_DIGEST_NOT_CAPTURED",
        "model": config.get("model"),
        "codex_as_worker_invocation_count": 0,
    }


def runtime_binding_fixture_verdict(binding: Mapping[str, Any]) -> dict[str, Any]:
    """Pure fail-closed oracle for the exact accepted Codex 0.166.0 identity."""
    required = {
        "runtime_identity": RUNTIME_IDENTITY,
        "version": "0.166.0",
        "binary_sha256": EXPECTED_DIGESTS["codex_binary"],
        "package_sha256": EXPECTED_DIGESTS["codex_package"],
        "config_sha256": EXPECTED_DIGESTS["codex_config"],
        "compatibility_state": "COMPATIBILITY_PASS_LOCKED",
        "compatibility_governance_lock_sha256": EXPECTED_DIGESTS["codex_compatibility_acceptance_lock"],
        "selection_policy": "EXACT_GOVERNANCE_BOUND_IDENTITY_NO_FALLBACK_NO_LATEST",
    }
    checks = {field: binding.get(field) == expected for field, expected in required.items()}
    checks.update(
        {
            "not_version_only": set(required) <= set(binding),
            "fallback_prohibited": binding.get("fallback_runtime") is None,
            "latest_selection_prohibited": binding.get("automatic_latest_selection") is False,
        }
    )
    return {
        "record_type": "V35_CODEX_0_166_0_RUNTIME_BINDING_FIXTURE_VERDICT",
        "status": "PASS" if all(checks.values()) else "FAIL_CLOSED_BEFORE_STATIC_LOCK_AND_ATTEMPT",
        "checks": checks,
    }


def prelock_selftest_artifact_paths() -> tuple[str, ...]:
    if not PRELOCK_SELFTEST_ROOT.is_dir() or PRELOCK_SELFTEST_ROOT.is_symlink():
        return ()
    return tuple(
        sorted(
            path.relative_to(WORKSPACE).as_posix()
            for path in PRELOCK_SELFTEST_ROOT.rglob("*")
            if path.is_file() or path.is_symlink()
        )
    )


def expected_lock_members() -> tuple[str, ...]:
    return tuple(sorted((*SOURCE_PATHS, *PRELOCK_RESULT_PATHS, *prelock_selftest_artifact_paths())))


def imported_local_modules() -> tuple[str, ...]:
    local = {
        path.stem: path.relative_to(WORKSPACE).as_posix()
        for path in (WORKSPACE / "src").glob("*.py")
        if path.name != "__init__.py"
    }
    observed: set[str] = set()
    for relative in SOURCE_PATHS:
        if not relative.endswith(".py"):
            continue
        tree = ast.parse((WORKSPACE / relative).read_text(encoding="utf-8"), filename=relative)
        for node in ast.walk(tree):
            names: list[str] = []
            if isinstance(node, ast.Import):
                names = [alias.name.split(".", 1)[0] for alias in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module:
                names = [node.module.split(".", 1)[0]]
            for name in names:
                if name in local:
                    observed.add(local[name])
    return tuple(sorted(observed))


def dependency_closure_snapshot() -> dict[str, Any]:
    expected = set(expected_lock_members())
    actual = {
        path.relative_to(WORKSPACE).as_posix()
        for path in WORKSPACE.rglob("*")
        if (path.is_file() or path.is_symlink())
        and not path.is_relative_to(STATIC_RUN)
        and path.relative_to(WORKSPACE).as_posix() not in LOCK_OUTPUTS
    }
    missing = sorted(expected - actual)
    unexpected = sorted(actual - expected)
    unsafe = sorted(relative for relative in expected if not safe_regular_file(WORKSPACE / relative))
    writable = sorted(
        relative
        for relative in expected
        if safe_regular_file(WORKSPACE / relative) and stat.S_IMODE((WORKSPACE / relative).stat().st_mode) & 0o222
    )
    imports = set(imported_local_modules())
    unmanifested_imports = sorted(imports - expected)
    canonical_predecessor = canonical_predecessor_binding_precheck("DEPENDENCY_CLOSURE")
    external_predecessor_artifacts = external_predecessor_artifact_precheck("DEPENDENCY_CLOSURE")
    canonical_modules = canonical_module_resolution_precheck("DEPENDENCY_CLOSURE")
    unified_generation = unified_binding_generation_precheck("DEPENDENCY_CLOSURE")
    derived_digest_view = derived_current_expected_digest_view_precheck()
    mount_output_identity = mount_output_binding_precheck("DEPENDENCY_CLOSURE")
    typed_preflight_requirements = typed_preflight_requirement_precheck("DEPENDENCY_CLOSURE")
    host_output_lifecycle = host_output_bind_source_precheck(
        "DEPENDENCY_CLOSURE", require_current_empty=True
    )
    typed_runtime_authority = typed_runtime_acceptance_precheck("DEPENDENCY_CLOSURE")
    stale_mount_bindings = stale_mount_literal_precheck()
    external = {
        "codex_binary": (CODEX_BINARY, EXPECTED_DIGESTS["codex_binary"]),
        "codex_package": (CODEX_PACKAGE, EXPECTED_DIGESTS["codex_package"]),
        "bwrap": (BWRAP, EXPECTED_DIGESTS["bwrap"]),
        "strace": (STRACE, EXPECTED_DIGESTS["strace"]),
        "python": (PYTHON, EXPECTED_DIGESTS["python"]),
        "codex_compatibility_acceptance_lock": (
            CANONICAL_COMPATIBILITY_ACCEPTANCE_PATH,
            EXPECTED_DIGESTS["codex_compatibility_acceptance_lock"],
        ),
        "codex_compatibility_acceptance_manifest": (
            CANONICAL_COMPATIBILITY_ACCEPTANCE_MANIFEST,
            EXPECTED_DIGESTS["codex_compatibility_acceptance_manifest"],
        ),
        **{name: (path, EXPECTED_DIGESTS[name]) for name, path in PREDECESSOR_PATHS.items()},
    }
    external_results: dict[str, Any] = {}
    unlocked: list[str] = []
    for name, (path, expected_digest) in external.items():
        actual_digest = sha256_file(path) if safe_regular_file(path) else None
        passed = actual_digest == expected_digest
        external_results[name] = {
            "path": str(path),
            "expected_sha256": expected_digest,
            "actual_sha256": actual_digest,
            "status": "PASS" if passed else "FAIL",
        }
        if not passed:
            unlocked.append(name)
    counters = {
        "unlocked_runtime_dependency_count": len(unlocked),
        "unmanifested_validator_input_count": len(unmanifested_imports),
        "writable_lock_member_count": len(writable),
        "unexpected_prelock_workspace_member_count": len(unexpected),
    }
    status = "PASS" if not missing and not unsafe and all(value == 0 for value in counters.values()) and canonical_predecessor.get("status") == "PASS" and external_predecessor_artifacts.get("status") == "PASS" and canonical_modules.get("status") == "PASS" and unified_generation.get("status") == "PASS" and derived_digest_view.get("status") == "PASS" and mount_output_identity.get("status") == "PASS" and typed_preflight_requirements.get("status") == "PASS" and host_output_lifecycle.get("status") == "PASS" and typed_runtime_authority.get("status") == "PASS" and stale_mount_bindings.get("status") == "PASS" else "FAIL_CLOSED"
    return {
        "status": status,
        "mandatory_zero_counters": counters,
        "expected_members": sorted(expected),
        "actual_authoritative_members": sorted(actual),
        "missing_members": missing,
        "unexpected_members": unexpected,
        "unsafe_members": unsafe,
        "writable_members": writable,
        "imported_local_modules": sorted(imports),
        "unmanifested_validator_inputs": unmanifested_imports,
        "external_dependencies": external_results,
        "unlocked_external_dependencies": unlocked,
        "canonical_predecessor_binding": canonical_predecessor,
        "external_predecessor_artifact_binding": external_predecessor_artifacts,
        "canonical_module_resolution": canonical_modules,
        "unified_binding_generation": unified_generation,
        "derived_current_expected_digest_view": derived_digest_view,
        "mount_output_identity": mount_output_identity,
        "typed_preflight_requirements": typed_preflight_requirements,
        "host_output_bind_source_lifecycle": host_output_lifecycle,
        "typed_runtime_acceptance_authority": typed_runtime_authority,
        "stale_mount_bindings": stale_mount_bindings,
    }


def strict_schema_compatibility_verdict(schema: Any) -> dict[str, Any]:
    """Validate the exact provider-compatible strict-schema subset without invoking Codex."""

    rejected: list[dict[str, str]] = []
    seen: set[str] = set()

    def walk(node: Any, path: str) -> None:
        if not isinstance(node, Mapping):
            rejected.append({"path": path, "reason": "SCHEMA_NODE_NOT_OBJECT"})
            return
        for key, value in node.items():
            if key not in SUPPORTED_STRICT_SCHEMA_KEYWORDS:
                rejected.append({"path": f"{path}/{key}", "reason": "UNSUPPORTED_SCHEMA_KEYWORD"})
                continue
            seen.add(key)
            if key == "properties":
                if not isinstance(value, Mapping):
                    rejected.append({"path": f"{path}/properties", "reason": "PROPERTIES_NOT_OBJECT"})
                else:
                    for property_name, property_schema in value.items():
                        if not isinstance(property_name, str) or not property_name:
                            rejected.append({"path": f"{path}/properties", "reason": "INVALID_PROPERTY_NAME"})
                            continue
                        walk(property_schema, f"{path}/properties/{property_name}")
            elif key == "items":
                walk(value, f"{path}/items")
            elif key == "additionalProperties" and isinstance(value, Mapping):
                walk(value, f"{path}/additionalProperties")

    walk(schema, "$")
    return {
        "status": "PASS" if not rejected else "FAIL_CLOSED",
        "contract": "PINNED_CODEX_0_163_0_STRICT_RESPONSE_SCHEMA_SUBSET_V1",
        "supported_keywords": sorted(SUPPORTED_STRICT_SCHEMA_KEYWORDS),
        "observed_keywords": sorted(seen),
        "rejected": rejected,
        "unique_items_rejected": any(item["path"].endswith("/uniqueItems") for item in rejected),
        "attempt_count_if_failed": 0,
        "worker_invocation_count_if_failed": 0,
        "codex_as_worker_invocation_count_if_failed": 0,
    }


def strict_schema_compatibility_precheck() -> dict[str, Any]:
    schema = load_json(MODEL_OUTPUT_SCHEMA)
    verdict = strict_schema_compatibility_verdict(schema)
    return {
        **verdict,
        "schema_path": str(MODEL_OUTPUT_SCHEMA),
        "schema_sha256": sha256_file(MODEL_OUTPUT_SCHEMA),
    }


def worker_result_state(
    *,
    runtime_completed: bool,
    runtime_exit: int | None,
    last_message_exists: bool,
    controller_result_exists: bool,
) -> str:
    """Return a typed result state even when provider/runtime output is absent."""

    if last_message_exists and controller_result_exists and runtime_completed and runtime_exit == 0:
        return "EMITTED_AND_CONTROLLER_WRAPPED"
    if not last_message_exists and not controller_result_exists and runtime_completed:
        return "NOT_EMITTED_DUE_TO_RUNTIME_FAILURE"
    if not runtime_completed and not last_message_exists and not controller_result_exists:
        return "NOT_EMITTED_DUE_TO_LAUNCH_OR_TIMEOUT_FAILURE"
    return "INCONSISTENT_OUTPUT_ARTIFACT_STATE_FAIL_CLOSED"


def _reject_recursive_keys(value: Any) -> None:
    if isinstance(value, Mapping):
        for key, item in value.items():
            if key in FORBIDDEN_OUTPUT_KEYS:
                raise ContractViolation(f"authority-bearing output key prohibited: {key}")
            _reject_recursive_keys(item)
    elif isinstance(value, list):
        for item in value:
            _reject_recursive_keys(item)


def _exact_keys(value: Mapping[str, Any], required: frozenset[str], label: str) -> None:
    if not isinstance(value, Mapping) or frozenset(value) != required:
        raise ContractViolation(f"{label} keys must be exactly {sorted(required)}")


def validate_model_output(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ContractViolation("worker output must be an object")
    _reject_recursive_keys(value)
    required = frozenset(
        {
            "status",
            "summary",
            "proposals",
            "requested_operations",
            "commands_requested",
            "files_changed",
            "unresolved_questions",
        }
    )
    _exact_keys(value, required, "worker output")
    if value["status"] != "PROPOSAL_COMPLETE" or not isinstance(value["summary"], str) or not value["summary"].strip():
        raise ContractViolation("worker output status or summary invalid")
    for name in ("requested_operations", "commands_requested", "files_changed"):
        if value[name] != []:
            raise ContractViolation(f"{name} must be empty")
    if not isinstance(value["unresolved_questions"], list) or any(not isinstance(item, str) for item in value["unresolved_questions"]):
        raise ContractViolation("unresolved_questions must be an array of strings")
    proposals = value["proposals"]
    if not isinstance(proposals, list) or len(proposals) != 1:
        raise ContractViolation("exactly one proposal required")
    proposal = proposals[0]
    proposal_keys = frozenset(
        {"candidate_id", "hypothesis", "falsifier", "claimed_capability", "claimed_impact", "evidence_refs"}
    )
    _exact_keys(proposal, proposal_keys, "proposal")
    for name in ("candidate_id", "hypothesis", "falsifier"):
        if not isinstance(proposal[name], str) or not proposal[name].strip():
            raise ContractViolation(f"proposal {name} invalid")
    for name, required_status in (("claimed_capability", "UNPROVEN"), ("claimed_impact", "NONE_PROVEN")):
        item = proposal[name]
        _exact_keys(item, frozenset({"status", "description"}), name)
        if item["status"] != required_status or not isinstance(item["description"], str) or not item["description"].strip():
            raise ContractViolation(f"{name} must remain {required_status}")
    if proposal["evidence_refs"] != [FIXTURE_EVIDENCE_ID]:
        raise ContractViolation("proposal must reference only the frozen fixture evidence")
    return value


def controller_result(model_output: Mapping[str, Any]) -> dict[str, Any]:
    valid = validate_model_output(dict(model_output))
    proposals = []
    for proposal in valid["proposals"]:
        proposals.append(
            {
                **proposal,
                "authority": PROPOSAL_AUTHORITY,
                "candidate_initial_state": CANDIDATE_INITIAL_STATE,
            }
        )
    return {
        "status": valid["status"],
        "campaign_id": CAMPAIGN_ID,
        "lane_id": LANE_ID,
        "worker_id": WORKER_ID,
        "runtime_identity": RUNTIME_IDENTITY,
        "authorization_id": AUTHORIZATION_ID,
        "workspace_id": WORKSPACE_ID,
        "authority": PROPOSAL_AUTHORITY,
        "proposals": proposals,
    }


class SyscallFamily(str, Enum):
    PATHNAME_BEARING_NUMERIC_RETURN = "PATHNAME_BEARING_NUMERIC_RETURN"
    NON_PATH_NUMERIC_RETURN = "NON_PATH_NUMERIC_RETURN"
    NON_RETURNING_PROCESS_TERMINATION = "NON_RETURNING_PROCESS_TERMINATION"


class EvidenceClass(str, Enum):
    FILESYSTEM_PATHNAME_BEARING_SYSCALL_OPERAND = "FILESYSTEM_PATHNAME_BEARING_SYSCALL_OPERAND"
    FD_ANNOTATION = "FD_ANNOTATION"
    FD_PIPE_PAYLOAD = "FD_PIPE_PAYLOAD"
    STDERR_TEXT = "STDERR_TEXT"
    GENERIC_SYSCALL_OPERAND = "GENERIC_SYSCALL_OPERAND"
    NAMESPACE_CONTROL_PATH = "NAMESPACE_CONTROL_PATH"
    FILESYSTEM_FD_WRITE_TARGET = "FILESYSTEM_FD_WRITE_TARGET"
    NON_RETURNING_TERMINATION_EVENT = "NON_RETURNING_TERMINATION_EVENT"
    PID_NAMESPACE_RESULT_ANNOTATION = "PID_NAMESPACE_RESULT_ANNOTATION"


class FdAnnotationKind(str, Enum):
    FILESYSTEM_PATH = "FILESYSTEM_PATH"
    PIPE = "PIPE"
    SOCKET = "SOCKET"
    UNIX_STREAM = "UNIX_STREAM"
    TCP = "TCP"
    TCPV6 = "TCPV6"
    UDP = "UDP"
    UDPV6 = "UDPV6"
    ANON_INODE = "ANON_INODE"
    EVENTFD = "EVENTFD"


@dataclass(frozen=True)
class ParsedSyscall:
    name: str
    family: SyscallFamily
    args: tuple[str, ...]
    result: str
    return_value: int | None
    succeeded: bool | None
    raw: str


@dataclass(frozen=True)
class TypedEvidence:
    evidence_class: EvidenceClass
    syscall: str
    argument_index: int
    value: str
    raw: str


@dataclass(frozen=True)
class ParsedFdAnnotation:
    descriptor: int
    kind: FdAnnotationKind
    value: str
    raw_annotation: str
    form: str


PATH_OPERANDS: dict[str, tuple[int, ...]] = {
    "access": (0,), "chdir": (0,), "chmod": (0,), "chown": (0,), "creat": (0,),
    "execve": (0,), "faccessat2": (1,), "fchmodat": (1,), "fchownat": (1,),
    "inotify_add_watch": (1,),
    "link": (0, 1), "linkat": (1, 3), "lstat": (0,), "mkdir": (0,),
    "mkdirat": (1,), "mknod": (0,), "mknodat": (1,), "mount": (1,),
    "newfstatat": (1,), "open": (0,), "openat": (1,), "pivot_root": (0, 1),
    "readlink": (0,), "rename": (0, 1), "renameat": (1, 3), "renameat2": (1, 3),
    "stat": (0,), "statfs": (0,), "symlink": (1,), "symlinkat": (2,),
    "truncate": (0,), "umount": (0,), "umount2": (0,), "unlink": (0,), "unlinkat": (1,),
}
NON_PATH_NUMERIC = {
    "accept", "accept4", "bind", "clone", "clone3", "close", "connect", "fork",
    "getcwd", "getpeername", "getsockname", "getsockopt", "kill", "listen", "pread64",
    "read", "readv", "recvmmsg", "recvfrom", "recvmsg", "restart_syscall", "sendmmsg",
    "sendmsg", "sendto", "setsockopt", "shutdown", "socket", "socketpair", "tgkill",
    "vfork", "wait4", "write", "writev",
}
TERMINATION = {"exit", "exit_group"}
SYSCALL_LINE = re.compile(r"^(?P<name>[A-Za-z0-9_]+)\((?P<args>.*)\)\s+=\s+(?P<result>.+)$")
FD_ANNOTATION = re.compile(r"^-?[0-9]+<(?P<annotation>.+)>$")
NUMERIC_RETURN = re.compile(r"^(?P<value>-?[0-9]+)(?P<tail>.*)$")
PID_RESULT_ANNOTATION = re.compile(r"^(?P<namespace_pid>[1-9][0-9]*)<(?P<host_pid>[1-9][0-9]*)>$")
CLONE_USER = re.compile(r"^clone\(.*CLONE_NEWUSER.*\) = (?:[1-9][0-9]*<)?(?P<pid>[1-9][0-9]*)(?:>)?$")
NETWORK_FD_KINDS = frozenset(
    {FdAnnotationKind.SOCKET, FdAnnotationKind.TCP, FdAnnotationKind.TCPV6, FdAnnotationKind.UDP, FdAnnotationKind.UDPV6}
)


def _parse_network_endpoint(value: str, *, version: int) -> tuple[str, int] | None:
    """Parse one exact strace network endpoint without free-text inference."""

    if version == 4:
        match = re.fullmatch(r"(?P<address>[0-9]{1,3}(?:\.[0-9]{1,3}){3}):(?P<port>[0-9]{1,5})", value)
    else:
        match = re.fullmatch(r"\[(?P<address>[0-9A-Fa-f:.]+)\]:(?P<port>[0-9]{1,5})", value)
    if match is None:
        return None
    try:
        address = ipaddress.ip_address(match.group("address"))
    except ValueError:
        return None
    port = int(match.group("port"))
    if address.version != version or not 0 <= port <= 65535:
        return None
    return str(address), port


def _network_annotation_form(body: str, *, version: int) -> str | None:
    if re.fullmatch(r"[0-9]+", body):
        return "OBJECT_ID"
    parts = body.split("->")
    if len(parts) not in {1, 2} or any(_parse_network_endpoint(part, version=version) is None for part in parts):
        return None
    return "BOUND_ENDPOINT" if len(parts) == 1 else "CONNECTED_ENDPOINT_PAIR"


def split_syscall_arguments(value: str) -> tuple[str, ...]:
    if value == "":
        return ()
    output: list[str] = []
    start = 0
    quote = False
    escape = False
    depth = {"[": 0, "{": 0, "(": 0, "<": 0}
    pairs = {"]": "[", "}": "{", ")": "(", ">": "<"}
    for index, char in enumerate(value):
        if quote:
            if escape:
                escape = False
            elif char == "\\":
                escape = True
            elif char == '"':
                quote = False
            continue
        if char == '"':
            quote = True
        elif char in depth:
            depth[char] += 1
        elif char in pairs:
            if char == ">" and index > 0 and value[index - 1] in {"-", "="}:
                # strace uses both ``A->B`` inside FD annotations and ``old => new``
                # inside in/out operands.  Neither arrow closes an angle annotation.
                continue
            opener = pairs[char]
            if depth[opener] == 0:
                raise ValueError("unbalanced syscall arguments")
            depth[opener] -= 1
        elif char == "," and all(level == 0 for level in depth.values()):
            output.append(value[start:index].strip())
            start = index + 1
    if quote or any(depth.values()):
        raise ValueError("ambiguous syscall arguments")
    output.append(value[start:].strip())
    return tuple(output)


def parse_fd_annotation(token: str) -> ParsedFdAnnotation | None:
    """Dispatch a pinned strace ``-yy`` annotation by class, then exact grammar."""

    match = FD_ANNOTATION.fullmatch(token)
    if match is None:
        return None
    descriptor_text = token.split("<", 1)[0]
    descriptor = int(descriptor_text)
    annotation = match.group("annotation")
    filesystem = re.fullmatch(r"(?P<path>/[^<]*)(?:<char [0-9]+:[0-9]+>)?", annotation)
    if filesystem:
        return ParsedFdAnnotation(descriptor, FdAnnotationKind.FILESYSTEM_PATH, filesystem.group("path"), annotation, "ABSOLUTE_PATH")
    if re.fullmatch(r"pipe:\[[0-9]+\]", annotation):
        return ParsedFdAnnotation(descriptor, FdAnnotationKind.PIPE, annotation, annotation, "OBJECT_ID")
    if re.fullmatch(r"socket:\[[0-9]+\]", annotation):
        return ParsedFdAnnotation(descriptor, FdAnnotationKind.SOCKET, annotation, annotation, "OBJECT_ID")
    if re.fullmatch(r"UNIX-STREAM:\[[0-9]+(?:->[0-9]+)?\]", annotation):
        form = "PEER_PAIR" if "->" in annotation else "OBJECT_ID"
        return ParsedFdAnnotation(descriptor, FdAnnotationKind.UNIX_STREAM, annotation, annotation, form)
    network_classes = (
        ("TCPv6", FdAnnotationKind.TCPV6, 6),
        ("UDPv6", FdAnnotationKind.UDPV6, 6),
        ("TCP", FdAnnotationKind.TCP, 4),
        ("UDP", FdAnnotationKind.UDP, 4),
    )
    for prefix, kind, version in network_classes:
        class_match = re.fullmatch(rf"{re.escape(prefix)}:\[(?P<body>.*)\]", annotation)
        if class_match is None:
            continue
        form = _network_annotation_form(class_match.group("body"), version=version)
        if form is None:
            raise ValueError(f"malformed {prefix} FD annotation grammar: {annotation}")
        return ParsedFdAnnotation(descriptor, kind, annotation, annotation, form)
    if re.fullmatch(r"anon_inode:(?:\[[A-Za-z0-9_-]+\]|[A-Za-z0-9_-]+)", annotation):
        return ParsedFdAnnotation(descriptor, FdAnnotationKind.ANON_INODE, annotation, annotation, "KERNEL_OBJECT_CLASS")
    if re.fullmatch(
        r"\{eventfd-count=(?:0x[0-9a-f]+|[0-9]+), eventfd-id=[0-9]+, eventfd-semaphore=[0-9]+\}",
        annotation,
    ):
        return ParsedFdAnnotation(descriptor, FdAnnotationKind.EVENTFD, annotation, annotation, "EVENTFD_FIELD_TUPLE")
    raise ValueError(f"unknown FD annotation grammar: {annotation}")


def typed_fd_annotation_grammar_precheck() -> dict[str, Any]:
    """Prove the explicit V8 annotation table and frozen V6 regression before attempt."""

    contract_path = WORKSPACE / "contracts/TYPED_FD_ANNOTATION_CONTRACT.json"
    contract = load_json(contract_path)
    expected_classes = {kind.value for kind in FdAnnotationKind}
    positives = {
        "7<pipe:[123]>": FdAnnotationKind.PIPE,
        "7<socket:[123]>": FdAnnotationKind.SOCKET,
        "7<UNIX-STREAM:[523996->523997]>": FdAnnotationKind.UNIX_STREAM,
        "7<TCP:[123]>": FdAnnotationKind.TCP,
        "7<TCPv6:[1120305]>": FdAnnotationKind.TCPV6,
        "7<UDP:[123]>": FdAnnotationKind.UDP,
        "7<UDPv6:[123]>": FdAnnotationKind.UDPV6,
        "7<TCP:[10.0.2.15:33946->104.18.32.47:443]>": FdAnnotationKind.TCP,
        "7<UDPv6:[[::]:38531]>": FdAnnotationKind.UDPV6,
        "7<UDPv6:[[fd17:625c:f037:2::1]:53576->[2606:4700:4408::1]:65535]>": FdAnnotationKind.UDPV6,
        "7<anon_inode:[eventpoll]>": FdAnnotationKind.ANON_INODE,
        "7<{eventfd-count=0x1, eventfd-id=2, eventfd-semaphore=0}>": FdAnnotationKind.EVENTFD,
        "7</dev/null<char 1:3>>": FdAnnotationKind.FILESYSTEM_PATH,
    }
    malformed = (
        "7<TCPv6:[]>",
        "7<TCPv6:[abc]>",
        "7<TCPv8:[123]>",
        "7<tcpv6:[123]>",
        "7<TCPv6:[123]junk>",
        "7<UNKNOWN:[123]>",
        "7<TCP:[999.999.999.999:443]>",
        "7<UDPv6:[[gggg::1]:53]>",
    )
    positive_failures: list[str] = []
    for token, expected_kind in positives.items():
        try:
            parsed = parse_fd_annotation(token)
        except ValueError:
            parsed = None
        if parsed is None or parsed.kind != expected_kind:
            positive_failures.append(token)
    negative_failures: list[str] = []
    for token in malformed:
        try:
            parse_fd_annotation(token)
        except ValueError:
            continue
        negative_failures.append(token)
    v6_occurrences = 0
    v6_traces: dict[int, str] = {}
    v6_trace_root = V6_WORKSPACE / "static-run-v6"
    if v6_trace_root.is_dir():
        for trace in sorted(v6_trace_root.glob("trace.*")):
            try:
                trace_pid = int(trace.name.split(".", 1)[1])
            except (IndexError, ValueError):
                continue
            trace_text = trace.read_text(encoding="utf-8", errors="replace")
            v6_traces[trace_pid] = trace_text
            v6_occurrences += trace_text.count("<TCPv6:[1120305]>")
    v6_replay = classify_fd_annotations(v6_traces) if v6_traces else {
        "status": "FAIL_CLOSED",
        "parsed_annotation_count": 0,
        "class_counts": {},
        "failures": [{"error": "FROZEN_V6_TRACE_CORPUS_ABSENT"}],
    }
    checks = {
        "contract_identity": contract.get("execution_identity") == EXECUTION_IDENTITY,
        "exact_class_set": set(contract.get("classes", {})) == expected_classes,
        "class_dispatch_first": contract.get("class_dispatch") == "ANNOTATION_CLASS_BEFORE_EXACT_CLASS_GRAMMAR",
        "free_text_prohibited": contract.get("free_text_or_permissive_catch_all") == "PROHIBITED",
        "unknown_fail_closed": contract.get("unknown_or_malformed_annotation") == "FAIL_CLOSED",
        "fd_annotation_not_pathname": contract.get("annotation_is_pathname") is False,
        "fd_annotation_not_process_identity": contract.get("annotation_is_process_identity") is False,
        "fd_annotation_not_mount_identity": contract.get("annotation_is_mount_identity") is False,
        "fd_annotation_not_producer_identity": contract.get("annotation_is_producer_identity") is False,
        "network_annotation_not_network_verdict": contract.get("network_annotation_alone_is_network_verdict") is False,
        "all_positive_examples_typed": not positive_failures,
        "all_unknown_or_malformed_examples_rejected": not negative_failures,
        "v6_tcpv6_regression_observed": v6_occurrences > 0,
        "v6_tcpv6_regression_typed": parse_fd_annotation("7<TCPv6:[1120305]>").kind == FdAnnotationKind.TCPV6,
        "v6_full_trace_corpus_typed": (
            v6_replay.get("status") == "PASS"
            and v6_replay.get("parsed_annotation_count", 0) > 0
            and v6_replay.get("class_counts", {}).get("TCPV6", 0) > 0
            and v6_replay.get("failures") == []
        ),
    }
    return {
        "status": "PASS" if all(checks.values()) else "FAIL_CLOSED",
        "contract_path": str(contract_path),
        "contract_sha256": sha256_file(contract_path),
        "checks": checks,
        "positive_failure_tokens": positive_failures,
        "negative_failure_tokens": negative_failures,
        "frozen_v6_tcpv6_occurrence_count": v6_occurrences,
        "frozen_v6_trace_file_count": len(v6_traces),
        "frozen_v6_trace_replay": v6_replay,
        "attempt_count_if_failed": 0,
        "worker_invocation_count_if_failed": 0,
        "codex_as_worker_invocation_count_if_failed": 0,
    }


def syscall_family(name: str) -> SyscallFamily:
    if name in TERMINATION:
        return SyscallFamily.NON_RETURNING_PROCESS_TERMINATION
    if name in PATH_OPERANDS:
        return SyscallFamily.PATHNAME_BEARING_NUMERIC_RETURN
    if name in NON_PATH_NUMERIC:
        return SyscallFamily.NON_PATH_NUMERIC_RETURN
    raise ValueError(f"unknown syscall family: {name}")


def parse_syscall_line(line: str) -> ParsedSyscall | None:
    if line.startswith(("+++", "---", "<...")) or "<unfinished ...>" in line:
        return None
    match = SYSCALL_LINE.match(line)
    if not match:
        return None
    name = match.group("name")
    args = split_syscall_arguments(match.group("args"))
    family = syscall_family(name)
    result = match.group("result")
    if family == SyscallFamily.NON_RETURNING_PROCESS_TERMINATION:
        if len(args) != 1 or not re.fullmatch(r"-?[0-9]+", args[0]) or result != "?":
            raise ValueError(f"invalid non-returning {name} grammar")
        return ParsedSyscall(name, family, args, result, None, None, line)
    numeric = NUMERIC_RETURN.match(result)
    if numeric is None:
        raise ValueError(f"non-numeric result for {family.value}: {name}")
    return_value = int(numeric.group("value"))
    tail = numeric.group("tail")
    if tail.startswith("<"):
        pid_annotation = PID_RESULT_ANNOTATION.fullmatch(result)
        if name in {"clone", "clone3", "fork", "vfork"}:
            if pid_annotation is None:
                raise ValueError(f"invalid PID namespace result annotation for {name}")
        elif parse_fd_annotation(result) is None:
            raise ValueError(f"invalid annotated numeric result for {name}")
    elif tail and not tail.startswith(" "):
        raise ValueError(f"invalid numeric result suffix for {name}")
    return ParsedSyscall(name, family, args, result, return_value, return_value >= 0, line)


def pid_result_host_pid(event: ParsedSyscall) -> int | None:
    """Return the host PID bound by strace ``--decode-pids=pidns``."""

    if event.name not in {"clone", "clone3", "fork", "vfork"} or event.succeeded is not True:
        return None
    match = PID_RESULT_ANNOTATION.fullmatch(event.result)
    if match is not None:
        return int(match.group("host_pid"))
    return event.return_value if isinstance(event.return_value, int) and event.return_value > 0 else None


def decode_c_string(token: str) -> str:
    if not (len(token) >= 2 and token[0] == token[-1] == '"'):
        raise ValueError("operand is not complete quoted text")
    value = ast.literal_eval(token)
    if not isinstance(value, str):
        raise ValueError("operand is not text")
    return value


def decode_execve_argv(token: str) -> tuple[str, ...]:
    """Decode a complete strace argv vector; truncation or non-text fails closed."""

    value = ast.literal_eval(token)
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise ValueError("execve argv is not a complete string vector")
    return tuple(value)


def typed_evidence_for_event(event: ParsedSyscall) -> list[TypedEvidence]:
    if event.family == SyscallFamily.NON_RETURNING_PROCESS_TERMINATION:
        return [TypedEvidence(EvidenceClass.NON_RETURNING_TERMINATION_EVENT, event.name, 0, event.args[0], event.raw)]
    evidence: list[TypedEvidence] = []
    for index in PATH_OPERANDS.get(event.name, ()):
        if index >= len(event.args):
            raise ValueError(f"missing pathname operand for {event.name}")
        evidence.append(TypedEvidence(EvidenceClass.FILESYSTEM_PATHNAME_BEARING_SYSCALL_OPERAND, event.name, index, decode_c_string(event.args[index]), event.raw))
    for index, token in enumerate(event.args):
        annotation = parse_fd_annotation(token)
        if annotation is not None:
            evidence.append(TypedEvidence(EvidenceClass.FD_ANNOTATION, event.name, index, annotation.value, event.raw))
            if event.name in {"write", "writev"} and annotation.kind == FdAnnotationKind.FILESYSTEM_PATH:
                kind = EvidenceClass.NAMESPACE_CONTROL_PATH if annotation.value.startswith("/proc/") else EvidenceClass.FILESYSTEM_FD_WRITE_TARGET
                evidence.append(TypedEvidence(kind, event.name, index, annotation.value, event.raw))
    if event.name in {"write", "writev"}:
        if len(event.args) < 2:
            raise ValueError(f"missing data payload for {event.name}")
        fd = event.args[0]
        parsed_fd = parse_fd_annotation(fd)
        payload_class = EvidenceClass.FD_PIPE_PAYLOAD if parsed_fd is not None and parsed_fd.kind == FdAnnotationKind.PIPE else EvidenceClass.GENERIC_SYSCALL_OPERAND
        evidence.append(TypedEvidence(payload_class, event.name, 1, event.args[1], event.raw))
        if parsed_fd is not None and parsed_fd.descriptor == 2 and parsed_fd.kind == FdAnnotationKind.PIPE:
            evidence.append(TypedEvidence(EvidenceClass.STDERR_TEXT, event.name, 1, event.args[1], event.raw))
    return evidence


def classify_fd_annotations(traces: Mapping[int, str]) -> dict[str, Any]:
    """Parse every syntactically typed FD token and retain class/form counts."""

    class_counts = {kind.value: 0 for kind in FdAnnotationKind}
    form_counts: dict[str, int] = {}
    parsed_count = 0
    failures: list[dict[str, Any]] = []
    for trace_pid, text in sorted(traces.items()):
        for line_number, line in enumerate(text.splitlines(), 1):
            try:
                event = parse_syscall_line(line)
                if event is None:
                    continue
                tokens = list(event.args)
                if event.name not in {"clone", "clone3", "fork", "vfork"}:
                    tokens.append(event.result)
                for token in tokens:
                    if FD_ANNOTATION.fullmatch(token) is None:
                        continue
                    annotation = parse_fd_annotation(token)
                    if annotation is None:
                        raise ValueError("FD-shaped token was not classified")
                    parsed_count += 1
                    class_counts[annotation.kind.value] += 1
                    form_key = f"{annotation.kind.value}:{annotation.form}"
                    form_counts[form_key] = form_counts.get(form_key, 0) + 1
            except (TypeError, ValueError) as exc:
                failures.append(
                    {
                        "trace_pid": trace_pid,
                        "line_number": line_number,
                        "error_type": type(exc).__name__,
                        "error": str(exc),
                    }
                )
                break
    return {
        "status": "PASS" if not failures and parsed_count > 0 else "FAIL_CLOSED",
        "parsed_annotation_count": parsed_count,
        "class_counts": class_counts,
        "form_counts": dict(sorted(form_counts.items())),
        "failures": failures,
        "fd_annotation_is_pathname": False,
        "fd_annotation_is_process_identity": False,
        "fd_annotation_is_mount_identity": False,
        "fd_annotation_is_producer_identity": False,
        "network_annotation_alone_is_network_verdict": False,
        "free_text_or_permissive_catch_all_used": False,
    }


def _parsed_execve_events(traces: Mapping[int, str]) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for pid, text in sorted(traces.items()):
        for line in text.splitlines():
            event = parse_syscall_line(line)
            if event is None or event.name != "execve":
                continue
            if not event.args or event.succeeded is None:
                raise ValueError("malformed execve event")
            if len(event.args) < 2:
                raise ValueError("execve argv missing")
            events.append({
                "trace_pid": pid,
                "executable": decode_c_string(event.args[0]),
                "argv": list(decode_execve_argv(event.args[1])),
                "succeeded": event.succeeded,
                "raw": line,
            })
    return events


def load_traces() -> dict[int, str]:
    traces: dict[int, str] = {}
    for path in sorted(STATIC_RUN.glob("trace.*")):
        try:
            pid = int(path.name.rsplit(".", 1)[1])
        except (IndexError, ValueError):
            continue
        traces[pid] = path.read_text(encoding="utf-8", errors="replace")
    return traces


def successful_execve_events(traces: Mapping[int, str]) -> list[dict[str, Any]]:
    return [
        {"trace_pid": item["trace_pid"], "executable": item["executable"], "argv": item["argv"], "raw": item["raw"]}
        for item in _parsed_execve_events(traces)
        if item["succeeded"]
    ]


def process_parent_map(traces: Mapping[int, str]) -> dict[int, int]:
    """Build host-PID parent edges only from typed successful process creation events."""

    parents: dict[int, int] = {}
    for parent_pid, text in sorted(traces.items()):
        for line in text.splitlines():
            event = parse_syscall_line(line)
            if event is None or event.name not in {"clone", "clone3", "fork", "vfork"}:
                continue
            child_pid = pid_result_host_pid(event)
            if child_pid is None:
                continue
            if child_pid in parents and parents[child_pid] != parent_pid:
                raise ValueError(f"ambiguous parent for host PID {child_pid}")
            parents[child_pid] = parent_pid
    return parents


PROCESS_IDENTITY_FIELDS = (
    "local_pid",
    "host_pid",
    "parent_local_pid",
    "parent_host_pid",
    "trace_file_pid",
    "namespace_id",
    "proc_topology_identity",
    "proc_starttime",
    "process_start_identity",
    "process_start_identity_kind",
    "pid_namespace_identity",
    "executable_identity",
    "observation_source",
    "trace_event_timestamp_or_bounded_interval",
    "immutable_record_digest",
    "temporal_binding_status",
)


def temporal_identity_coverage_verdict(
    trace_identities: Iterable[int], records: Iterable[Mapping[str, Any]]
) -> dict[str, Any]:
    """Apply the frozen V13 N/N, missing-zero, ambiguous-zero rule."""

    required = {int(value) for value in trace_identities}
    indexed: dict[int, list[Mapping[str, Any]]] = {}
    for record in records:
        trace_pid = record.get("trace_file_pid")
        if isinstance(trace_pid, int) and trace_pid in required:
            indexed.setdefault(trace_pid, []).append(record)
    valid: list[int] = []
    missing: list[int] = []
    ambiguous: list[int] = []
    for trace_pid in sorted(required):
        candidates = [
            row for row in indexed.get(trace_pid, [])
            if row.get("temporal_binding_status") == "PASS"
            and isinstance(row.get("process_start_identity"), str)
            and isinstance(row.get("pid_namespace_identity"), str)
            and row.get("stable_identity_tuple") == [
                trace_pid, row.get("process_start_identity"), row.get("pid_namespace_identity")
            ]
        ]
        if len(candidates) == 1:
            valid.append(trace_pid)
        elif len(candidates) == 0:
            missing.append(trace_pid)
        else:
            ambiguous.append(trace_pid)
    checks = {
        "valid_equals_complete_trace_set": len(valid) == len(required),
        "missing_zero": len(missing) == 0,
        "ambiguous_zero": len(ambiguous) == 0,
        "percentage_threshold_not_used": True,
    }
    return {
        "status": "PASS" if all(checks.values()) else "FAIL_CLOSED",
        "checks": checks,
        "lineage_relevant_trace_identity_count": len(required),
        "valid_temporal_identity_mapping_count": len(valid),
        "missing_identity_count": len(missing),
        "ambiguous_identity_count": len(ambiguous),
        "valid_trace_identities": valid,
        "missing_trace_identities": missing,
        "ambiguous_trace_identities": ambiguous,
        "coverage_complete": all(checks.values()),
    }


def independently_validate_coverage_accounting(
    trace_identities: Iterable[int], coverage: Mapping[str, Any]
) -> dict[str, Any]:
    """Recompute N-of-N coverage from the per-trace ledger, never its summary."""

    expected = sorted({int(value) for value in trace_identities})
    rows = coverage.get("per_trace_capture_accounting", [])
    rows = [dict(row) for row in rows if isinstance(row, Mapping)]
    by_pid: dict[int, list[dict[str, Any]]] = {}
    for row in rows:
        pid = row.get("trace_file_pid")
        if isinstance(pid, int):
            by_pid.setdefault(pid, []).append(row)
    valid: list[int] = []
    missing: list[int] = []
    ambiguous: list[int] = []
    malformed: list[int] = []
    for pid in expected:
        candidates = by_pid.get(pid, [])
        if len(candidates) != 1:
            (missing if not candidates else ambiguous).append(pid)
            continue
        row = candidates[0]
        required_fields = (
            isinstance(row.get("trace_identity"), str),
            row.get("host_pid") == pid,
            isinstance(row.get("identity_capture_attempt_timestamp_monotonic_ns"), int),
            isinstance(row.get("process_start_identity"), str),
            isinstance(row.get("pid_namespace_identity"), str),
            row.get("capture_outcome") == "VALID_TEMPORAL_IDENTITY_RECORD",
            row.get("mapping_result") == "VALID_TEMPORAL_IDENTITY_RECORD",
            row.get("failure_reason") is None,
            isinstance(row.get("temporal_relationship"), Mapping),
        )
        if all(required_fields):
            valid.append(pid)
        else:
            malformed.append(pid)
    checks = {
        "ledger_member_set_exact": sorted(by_pid) == expected,
        "one_capture_attempt_record_per_trace_identity": all(len(by_pid.get(pid, [])) == 1 for pid in expected),
        "valid_equals_denominator": len(valid) == len(expected),
        "missing_zero": not missing,
        "ambiguous_zero": not ambiguous,
        "malformed_zero": not malformed,
        "summary_denominator_matches": coverage.get("lineage_relevant_trace_identity_count") == len(expected),
        "summary_attempt_count_matches": coverage.get("identity_capture_attempt_count") == len(rows) == len(expected),
        "summary_valid_matches": coverage.get("valid_temporal_identity_mapping_count") == len(valid),
        "summary_missing_matches": coverage.get("missing_identity_count") == len(missing) + len(malformed),
        "summary_ambiguous_matches": coverage.get("ambiguous_identity_count") == len(ambiguous),
        "coverage_complete_exact": coverage.get("coverage_complete") is True,
        "percentage_threshold_prohibited": coverage.get("percentage_thresholds") == "PROHIBITED_AND_NOT_USED",
    }
    return {
        "status": "PASS" if all(checks.values()) else "FAIL_CLOSED",
        "checks": checks,
        "trace_identities": expected,
        "valid_trace_identities": valid,
        "missing_trace_identities": missing,
        "ambiguous_trace_identities": ambiguous,
        "malformed_trace_identities": malformed,
    }


def observer_diagnostic_verdict(record: Mapping[str, Any]) -> dict[str, Any]:
    """Require a numeric exit and typed reason for every observer terminal state."""

    exit_code = record.get("observer_exit_code")
    exit_reason = record.get("observer_exit_reason")
    checks = {
        "numeric_exit_code": isinstance(exit_code, int),
        "typed_exit_reason": isinstance(exit_reason, str) and bool(exit_reason),
        "diagnostic_complete": record.get("diagnostic_complete") is True,
        "nonzero_is_not_pass": not (isinstance(exit_code, int) and exit_code != 0 and record.get("status") == "PASS"),
    }
    return {"status": "PASS" if all(checks.values()) else "FAIL_CLOSED_DIAGNOSTIC_INCOMPLETE", "checks": checks}


def correlate_cross_namespace_process_identities(
    traces: Mapping[int, str], topology: Mapping[str, Any]
) -> dict[str, Any]:
    """Bind every strace file to a host task and namespace-local identity.

    The trace suffix is treated only as the observer-visible task identifier.
    It becomes a host PID identity only when a temporally bound ``/proc`` task
    observation with the same identifier proves the mapping.  Namespace-local
    PIDs, parent identities, namespace inode and task-group identity remain
    separate evidence fields; no numeric equality is inferred across namespaces.
    """

    raw_observations = topology.get("process_observations", [])
    by_trace: dict[int, list[dict[str, Any]]] = {}
    for item in raw_observations:
        if not isinstance(item, Mapping):
            continue
        trace_file_pid = item.get("trace_file_pid")
        if isinstance(trace_file_pid, int):
            by_trace.setdefault(trace_file_pid, []).append(dict(item))

    mappings: list[dict[str, Any]] = []
    failures: list[dict[str, Any]] = []
    for trace_file_pid in sorted(traces):
        observations = by_trace.get(trace_file_pid, [])
        identities = {
            str(item.get("proc_topology_identity"))
            for item in observations
            if isinstance(item.get("proc_topology_identity"), str)
        }
        if not observations:
            failures.append({
                "trace_file_pid": trace_file_pid,
                "reason": "NO_TEMPORALLY_BOUND_PROC_TOPOLOGY_OBSERVATION",
            })
            continue
        if len(identities) != 1:
            failures.append({
                "trace_file_pid": trace_file_pid,
                "reason": "AMBIGUOUS_OR_MISSING_PROC_TOPOLOGY_IDENTITY",
                "identity_count": len(identities),
            })
            continue
        selected = max(
            observations,
            key=lambda item: int(item.get("last_observed_at_monotonic_ns", 0)),
        )
        # ``local_pid`` and ``proc_starttime`` can be unavailable for an
        # extremely short-lived task. V13 accepts the frozen contract's exact
        # equivalent only when a proc-connector fork event supplies a unique
        # start identity and the namespace is evidence-bound through the
        # traced creation edge. All other identity fields remain mandatory.
        exact_equivalent = selected.get("process_start_identity_kind") == "PROC_CONNECTOR_FORK_EVENT_EXACT_EQUIVALENT"
        nullable_for_exact_equivalent = {"local_pid", "parent_local_pid", "proc_starttime"} if exact_equivalent else set()
        missing = [
            field for field in PROCESS_IDENTITY_FIELDS
            if selected.get(field) is None and field not in nullable_for_exact_equivalent
        ]
        if missing:
            failures.append({
                "trace_file_pid": trace_file_pid,
                "reason": "REQUIRED_IDENTITY_FIELD_MISSING",
                "missing": missing,
            })
            continue
        if selected.get("host_pid") != trace_file_pid:
            failures.append({
                "trace_file_pid": trace_file_pid,
                "reason": "TRACE_FILE_PID_NOT_BOUND_TO_HOST_TASK_ID",
                "observed_host_pid": selected.get("host_pid"),
            })
            continue
        namespace_id = selected.get("namespace_id")
        if not isinstance(namespace_id, str) or not re.fullmatch(r"pid:\[[0-9]+\]", namespace_id):
            failures.append({
                "trace_file_pid": trace_file_pid,
                "reason": "INVALID_NAMESPACE_IDENTITY",
                "namespace_id": namespace_id,
            })
            continue
        first_seen = selected.get("first_observed_at_monotonic_ns")
        last_seen = selected.get("last_observed_at_monotonic_ns")
        if not isinstance(first_seen, int) or not isinstance(last_seen, int) or first_seen > last_seen:
            failures.append({
                "trace_file_pid": trace_file_pid,
                "reason": "INVALID_TEMPORAL_BINDING",
            })
            continue
        expected_stable = [
            selected.get("host_pid"),
            selected.get("process_start_identity"),
            selected.get("pid_namespace_identity"),
        ]
        if selected.get("stable_identity_tuple") != expected_stable:
            failures.append({
                "trace_file_pid": trace_file_pid,
                "reason": "STABLE_PROCESS_IDENTITY_TUPLE_MISMATCH",
            })
            continue
        if selected.get("proc_topology_identity") != canonical_json_sha256({
            "host_pid": selected.get("host_pid"),
            "process_start_identity": selected.get("process_start_identity"),
            "pid_namespace_identity": selected.get("pid_namespace_identity"),
        }):
            failures.append({
                "trace_file_pid": trace_file_pid,
                "reason": "PROC_TOPOLOGY_IDENTITY_DIGEST_MISMATCH",
            })
            continue
        temporal = selected.get("trace_event_timestamp_or_bounded_interval")
        if (
            selected.get("temporal_binding_status") != "PASS"
            or not isinstance(temporal, Mapping)
            or not isinstance(temporal.get("interval_distance_ns"), int)
            or not isinstance(temporal.get("max_correlation_slack_ns"), int)
            or temporal["interval_distance_ns"] > temporal["max_correlation_slack_ns"]
        ):
            failures.append({
                "trace_file_pid": trace_file_pid,
                "reason": "TRACE_OBSERVATION_NOT_TEMPORALLY_BOUND",
            })
            continue
        digest_material = {
            key: value
            for key, value in selected.items()
            if key not in {"immutable_record_digest", "mountinfo_text"}
        }
        if selected.get("immutable_record_digest") != canonical_json_sha256(digest_material):
            failures.append({
                "trace_file_pid": trace_file_pid,
                "reason": "IMMUTABLE_PROCESS_OBSERVATION_DIGEST_MISMATCH",
            })
            continue
        mappings.append({
            field: selected[field] for field in PROCESS_IDENTITY_FIELDS
        } | {
            "host_thread_group_id": selected.get("host_thread_group_id"),
            "local_thread_group_id": selected.get("local_thread_group_id"),
            "parent_relation": selected.get("parent_relation"),
            "first_observed_at_monotonic_ns": first_seen,
            "last_observed_at_monotonic_ns": last_seen,
            "evidence_refs": [
                f"TRACE_FILE_IDENTITY:trace.{trace_file_pid}",
                f"PROC_TOPOLOGY:{selected['proc_topology_identity']}",
                f"NAMESPACE_IDENTITY:{namespace_id}",
                f"TEMPORAL_OBSERVATION:{selected['immutable_record_digest']}",
            ],
        })

    mapped_trace_pids = {int(item["trace_file_pid"]) for item in mappings}
    required_trace_pids = set(int(pid) for pid in traces)
    checks = {
        "every_trace_file_identity_mapped": mapped_trace_pids == required_trace_pids,
        "no_ambiguous_or_missing_mapping": not failures,
        "trace_file_pid_and_local_pid_are_distinct_fields": True,
        "single_pid_field_not_canonical_across_namespaces": True,
        "mapping_evidence_refs_present": all(item.get("evidence_refs") for item in mappings),
        "namespace_identity_present": all(item.get("namespace_id") for item in mappings),
        "proc_topology_identity_present": all(item.get("proc_topology_identity") for item in mappings),
        "every_mapping_temporally_bound": all(item.get("temporal_binding_status") == "PASS" for item in mappings),
        "stable_identity_tuple_includes_start_identity_and_namespace": all(
            isinstance(item.get("process_start_identity"), str)
            and item.get("pid_namespace_identity") == item.get("namespace_id")
            for item in mappings
        ),
    }
    return {
        "status": "PASS" if all(checks.values()) else "FAIL_CLOSED",
        "checks": checks,
        "mappings": mappings,
        "failures": failures,
        "trace_file_count": len(required_trace_pids),
        "mapped_trace_file_count": len(mapped_trace_pids),
        "local_pid_equals_host_pid_assumption": "PROHIBITED_AND_NOT_USED",
    }


def _ancestor_chain(pid: int, parents: Mapping[int, int]) -> tuple[int, ...]:
    chain: list[int] = []
    seen = {pid}
    current = pid
    for _ in range(256):
        parent = parents.get(current)
        if parent is None:
            return tuple(chain)
        if parent in seen:
            raise ValueError("process lineage cycle")
        chain.append(parent)
        seen.add(parent)
        current = parent
    raise ValueError("process lineage depth exceeded")


def startup_argv_role(executable: str, argv: tuple[str, ...]) -> str | None:
    """Classify exact Codex shell-snapshot startup roles from executable plus argv."""

    if executable == str(PYTHON) and argv == tuple(worker_launch_gate_argv()):
        return "V11_TRACED_LAUNCH_GATE"
    if executable == "/usr/bin/zsh" and len(argv) == 3 and argv[1] == "-lc":
        script = argv[2]
        if "__codex_snapshot_command" in script and "# Snapshot file" in script:
            return "CODEX_SHELL_SNAPSHOT_GENERATOR"
    exact_roles = {
        ("/usr/bin/run-parts", ("run-parts", "--list", "--regex", "^[a-zA-Z0-9_][a-zA-Z0-9._-]*\\.sh$", "/etc/profile.d")): "PROFILE_SCRIPT_ENUMERATOR",
        ("/usr/bin/tr", ("tr", ":", "\\n")): "PROFILE_PATH_NORMALIZER",
        ("/usr/bin/grep", ("grep", "-q", "^/sbin$")): "PROFILE_PATH_MEMBERSHIP_CHECK",
        ("/usr/bin/kali-motd", ("kali-motd",)): "PROFILE_MOTD_HELPER",
        ("/usr/bin/wc", ("wc", "-l")): "SHELL_SNAPSHOT_COUNT_HELPER",
        ("/usr/bin/tr", ("tr", "-d", " ")): "SHELL_SNAPSHOT_SPACE_TRIM_HELPER",
        ("/usr/bin/sed", ("sed", "s/^/setopt /")): "SHELL_SNAPSHOT_RENDER_HELPER",
    }
    exact = exact_roles.get((executable, argv))
    if exact is not None:
        return exact
    if executable == "/usr/bin/zsh" and len(argv) == 3 and argv[1] == "-c":
        command = argv[2]
        if command.startswith("set -e; . \"") and "/home/nobcoder/.codex/shell_snapshots/" in command:
            return "CODEX_SHELL_SNAPSHOT_CONSUMER"
    return None


def classify_semantic_process_lineage(
    traces: Mapping[int, str], topology: Mapping[str, Any]
) -> dict[str, Any]:
    """Classify execs through evidence-bound host/local process identities."""

    execs = successful_execve_events(traces)
    correlation = correlate_cross_namespace_process_identities(traces, topology)
    mappings = {
        int(item["trace_file_pid"]): dict(item)
        for item in correlation.get("mappings", [])
        if isinstance(item, Mapping) and isinstance(item.get("trace_file_pid"), int)
    }
    parents = {
        int(item["host_pid"]): int(item["parent_host_pid"])
        for item in mappings.values()
        if isinstance(item.get("host_pid"), int) and isinstance(item.get("parent_host_pid"), int)
    }
    bwrap_events = [item for item in execs if item["executable"] == str(BWRAP)]
    runtime_events = [item for item in execs if item["executable"] == str(SANDBOX_CODEX_BINARY)]
    if correlation.get("status") != "PASS" or len(bwrap_events) != 1 or len(runtime_events) != 1:
        return {
            "status": "FAIL_CLOSED",
            "reason": "PROCESS_IDENTITY_CORRELATION_OR_EXEC_CARDINALITY",
            "launcher_count": len(bwrap_events),
            "runtime_count": len(runtime_events),
            "cross_namespace_process_identity": correlation,
            "classified": [],
            "unexpected": execs,
        }
    launcher_pid = int(bwrap_events[0]["trace_pid"])
    runtime_pid = int(runtime_events[0]["trace_pid"])
    runtime_chain = _ancestor_chain(runtime_pid, parents)
    runtime_identity = mappings.get(runtime_pid)
    runtime_mount_namespace = topology.get("runtime_mount_namespace")
    runtime_pid_namespace = runtime_identity.get("namespace_id") if runtime_identity else None
    classified: list[dict[str, Any]] = []
    unexpected: list[dict[str, Any]] = []

    for item in execs:
        pid = int(item["trace_pid"])
        executable = str(item["executable"])
        argv = tuple(str(value) for value in item.get("argv", []))
        chain = _ancestor_chain(pid, parents)
        identity = mappings.get(pid)
        parent_pid = identity.get("parent_host_pid") if identity else None
        observed_pid_ns = identity.get("namespace_id") if identity else None
        role = startup_argv_role(executable, argv)
        if executable == str(PYTHON) and role == "V11_TRACED_LAUNCH_GATE":
            process_class = "CONTROLLED_LAUNCH_GATE"
            lifecycle = "TRACE_READY_BEFORE_WORKER"
            namespace_id = observed_pid_ns
            valid = identity is not None and pid == launcher_pid
        elif executable == str(BWRAP) and pid == launcher_pid:
            process_class = "LAUNCHER"
            lifecycle = "SANDBOX_SETUP"
            role = "PINNED_BWRAP_LAUNCHER"
            namespace_id = observed_pid_ns
            valid = bool(identity) and bool(argv) and argv[0] == str(BWRAP)
        elif pid == runtime_pid:
            process_class = "PINNED_RUNTIME"
            lifecycle = "RUNTIME_START"
            role = "EXACT_CODEX_WORKER_RUNTIME"
            namespace_id = runtime_mount_namespace
            valid = (
                identity is not None
                and launcher_pid in runtime_chain
                and argv == tuple(codex_argv())
                and runtime_mount_namespace is not None
                and runtime_pid_namespace is not None
            )
        else:
            process_class = "EXPECTED_RUNTIME_STARTUP_CHILD" if role is not None else "UNEXPECTED_EXECUTABLE"
            lifecycle = "CODEX_SHELL_SNAPSHOT_STARTUP"
            namespace_id = observed_pid_ns
            valid = (
                identity is not None
                and role is not None
                and runtime_pid in chain
                and parent_pid is not None
                and namespace_id is not None
                and observed_pid_ns == runtime_pid_namespace
            )
        record = {
            "pid": pid,
            "local_pid": identity.get("local_pid") if identity else None,
            "host_pid": identity.get("host_pid") if identity else None,
            "parent_local_pid": identity.get("parent_local_pid") if identity else None,
            "parent_host_pid": parent_pid,
            "trace_file_pid": identity.get("trace_file_pid") if identity else pid,
            "namespace_id": identity.get("namespace_id") if identity else None,
            "proc_topology_identity": identity.get("proc_topology_identity") if identity else None,
            "evidence_refs": identity.get("evidence_refs", []) if identity else [],
            "ancestor_runtime_pid": runtime_pid if pid == runtime_pid or runtime_pid in chain else None,
            "executable_identity": executable,
            "argv": list(argv),
            "argv_role": role,
            "process_class": process_class,
            "lifecycle_phase": lifecycle,
            "mount_namespace_id": runtime_mount_namespace if pid == runtime_pid or runtime_pid in chain else None,
            "pid_namespace_id": observed_pid_ns,
            "ancestor_chain": list(chain),
            "status": "PASS" if valid else "FAIL_CLOSED",
        }
        classified.append(record)
        if not valid:
            unexpected.append(record)

    expected_children = [item for item in classified if item["process_class"] == "EXPECTED_RUNTIME_STARTUP_CHILD"]
    checks = {
        "launcher_exactly_one": len(bwrap_events) == 1,
        "runtime_exactly_one": len(runtime_events) == 1,
        "runtime_descends_from_launcher": launcher_pid in runtime_chain,
        "runtime_namespace_captured": runtime_mount_namespace is not None and runtime_pid_namespace is not None,
        "cross_namespace_identity_correlation": correlation.get("status") == "PASS",
        "every_parent_edge_evidence_bound": all(item.get("evidence_refs") for item in classified),
        "controlled_launch_gate_exactly_one": sum(
            item.get("process_class") == "CONTROLLED_LAUNCH_GATE" for item in classified
        ) == 1,
        "startup_children_observed": len(expected_children) >= 1,
        "all_execs_semantically_classified": not unexpected,
        "flat_executable_allowlist_not_used": True,
    }
    return {
        "status": "PASS" if all(checks.values()) else "FAIL_CLOSED",
        "checks": checks,
        "launcher_pid": launcher_pid,
        "runtime_pid": runtime_pid,
        "runtime_mount_namespace": runtime_mount_namespace,
        "runtime_pid_namespace": runtime_pid_namespace,
        "parent_map": {str(key): value for key, value in sorted(parents.items())},
        "cross_namespace_process_identity": correlation,
        "identity_mappings": correlation.get("mappings", []),
        "classified": classified,
        "unexpected": unexpected,
    }


def startup_lineage_policy_precheck() -> dict[str, Any]:
    contract = load_json(WORKSPACE / "contracts/PROCESS_LINEAGE_CONTRACT.json")
    required = {
        "LOCAL_PID", "HOST_PID", "PARENT_LOCAL_PID", "PARENT_HOST_PID",
        "TRACE_FILE_PID", "NAMESPACE_ID", "PROC_TOPOLOGY_IDENTITY",
        "ANCESTOR_RUNTIME_PID", "EXECUTABLE_IDENTITY", "ARGV_ROLE", "LIFECYCLE_PHASE",
        "PROC_STARTTIME", "TEMPORAL_OBSERVATION", "IMMUTABLE_RECORD_DIGEST",
    }
    checks = {
        "flat_allowlist_prohibited": contract.get("flat_executable_allowlist") == "PROHIBITED",
        "required_evidence_exact": set(contract.get("required_evidence", [])) == required,
        "unknown_lineage_fail_closed": contract.get("unknown_or_broken_lineage") == "FAIL_CLOSED",
        "local_host_pid_equality_prohibited": contract.get("local_pid_equals_host_pid_assumption") == "PROHIBITED",
        "mapping_evidence_bound": contract.get("host_pid_local_pid_mapping") == "EVIDENCE_BOUND",
        "runtime_role_recognized": startup_argv_role("/usr/bin/zsh", ("/usr/bin/zsh", "-lc", "# Snapshot file\n__codex_snapshot_command")) == "CODEX_SHELL_SNAPSHOT_GENERATOR",
        "launch_gate_role_recognized": startup_argv_role(str(PYTHON), tuple(worker_launch_gate_argv()))
        == "V11_TRACED_LAUNCH_GATE",
        "unknown_role_rejected": startup_argv_role("/usr/bin/sh", ("sh", "-c", "true")) is None,
    }
    return {"status": "PASS" if all(checks.values()) else "FAIL_CLOSED", "checks": checks}


def process_identity_correlation_precheck() -> dict[str, Any]:
    """Exercise the V19 N/N correlation gate without invoking the worker."""

    def identity(pid: int, start: str | None = None, namespace: str | None = "pid:[4026532408]") -> dict[str, Any]:
        start_identity = start or f"PROC_CONNECTOR_FORK_EVENT:{pid}:1:{pid}"
        return {
            "trace_file_pid": pid,
            "process_start_identity": start_identity,
            "pid_namespace_identity": namespace,
            "stable_identity_tuple": [pid, start_identity, namespace],
            "temporal_binding_status": "PASS",
        }

    trace_ids = tuple(range(100, 112))
    complete_records = [identity(pid) for pid in trace_ids]
    positive = temporal_identity_coverage_verdict(trace_ids, complete_records)
    n_minus_one = temporal_identity_coverage_verdict(trace_ids, complete_records[:-1])
    ambiguous = temporal_identity_coverage_verdict(trace_ids, [*complete_records, identity(trace_ids[-1], "PROC_STAT_STARTTIME:999")])
    missing_namespace = [dict(row) for row in complete_records]
    missing_namespace[-1]["pid_namespace_identity"] = None
    missing_namespace[-1]["stable_identity_tuple"] = [trace_ids[-1], missing_namespace[-1]["process_start_identity"], None]
    missing_namespace_result = temporal_identity_coverage_verdict(trace_ids, missing_namespace)
    inconsistent_start = [dict(row) for row in complete_records]
    inconsistent_start[-1]["stable_identity_tuple"] = [trace_ids[-1], "DIFFERENT_START_IDENTITY", "pid:[4026532408]"]
    inconsistent_start_result = temporal_identity_coverage_verdict(trace_ids, inconsistent_start)
    reused = temporal_identity_coverage_verdict(
        [700],
        [identity(700, "PROC_STAT_STARTTIME:10"), identity(700, "PROC_STAT_STARTTIME:11")],
    )
    v12_runtime = load_json(V12_WORKSPACE / "static-run-v12/runtime-result-0001.json")
    v12_lineage = v12_runtime.get("semantic_process_lineage", {}).get("cross_namespace_process_identity", {})
    v12_counts = {
        "lineage_relevant_trace_identity_count": v12_lineage.get("trace_file_count"),
        "valid_temporal_identity_mapping_count": v12_lineage.get("mapped_trace_file_count"),
        "missing_identity_count": len(v12_lineage.get("failures", [])),
    }
    checks = {
        "complete_n_of_n_passes": positive.get("status") == "PASS"
        and positive.get("lineage_relevant_trace_identity_count") == 12
        and positive.get("valid_temporal_identity_mapping_count") == 12,
        "n_minus_one_fails": n_minus_one.get("status") == "FAIL_CLOSED"
        and n_minus_one.get("missing_identity_count") == 1,
        "ambiguous_fails": ambiguous.get("status") == "FAIL_CLOSED"
        and ambiguous.get("ambiguous_identity_count") == 1,
        "missing_namespace_fails": missing_namespace_result.get("status") == "FAIL_CLOSED",
        "inconsistent_start_identity_fails": inconsistent_start_result.get("status") == "FAIL_CLOSED",
        "pid_reuse_without_disambiguation_fails": reused.get("status") == "FAIL_CLOSED",
        "v12_58_of_68_reproduced": v12_counts.get("lineage_relevant_trace_identity_count") == 68
        and v12_counts.get("valid_temporal_identity_mapping_count") == 58
        and v12_counts.get("missing_identity_count") == 10,
        "percentage_thresholds_prohibited": positive.get("coverage_complete") is True
        and n_minus_one.get("coverage_complete") is False,
    }
    return {
        "status": "PASS" if all(checks.values()) else "FAIL_CLOSED",
        "checks": checks,
        "positive_fixture": positive,
        "n_minus_one_fixture": n_minus_one,
        "ambiguous_fixture": ambiguous,
        "missing_namespace_fixture": missing_namespace_result,
        "inconsistent_start_fixture": inconsistent_start_result,
        "pid_reuse_fixture": reused,
        "v12_frozen_coverage": v12_counts,
    }

    # Historical implementation retained below as source-only regression
    # context; the authoritative V13 path returns above.
    """Prove evidence-bound temporal identity and historical mismatch regressions."""

    contract = load_json(WORKSPACE / "contracts/CROSS_NAMESPACE_PROCESS_IDENTITY_CONTRACT.json")
    synthetic_traces = {402362: "", 402363: "", 402447: ""}

    def observation(
        host_pid: int,
        local_pid: int,
        parent_host_pid: int,
        parent_local_pid: int,
        starttime: int,
        first_seen: int,
        last_seen: int,
    ) -> dict[str, Any]:
        namespace = "pid:[4026532408]"
        stable = [host_pid, starttime, namespace]
        item: dict[str, Any] = {
            "local_pid": local_pid,
            "host_pid": host_pid,
            "parent_local_pid": parent_local_pid,
            "parent_host_pid": parent_host_pid,
            "trace_file_pid": host_pid,
            "namespace_id": namespace,
            "pid_namespace_identity": namespace,
            "proc_starttime": starttime,
            "proc_topology_identity": canonical_json_sha256({
                "host_pid": host_pid,
                "proc_starttime": starttime,
                "pid_namespace_identity": namespace,
            }),
            "stable_identity_tuple": stable,
            "host_thread_group_id": host_pid,
            "local_thread_group_id": local_pid,
            "parent_relation": "PROCESS_PARENT" if local_pid != 1 else "PROCESS_PARENT_CROSS_NAMESPACE",
            "first_observed_at_monotonic_ns": first_seen,
            "last_observed_at_monotonic_ns": last_seen,
            "observation_timestamp_monotonic_ns": first_seen,
            "executable_identity": {
                "path": "/fixture/process",
                "device": 1,
                "inode": host_pid,
                "mode": 32768,
                "identity_sha256": canonical_json_sha256({"host_pid": host_pid}),
            },
            "observation_source": "HOST_PROC_TASK_LIVE_READ",
            "trace_event_timestamp_or_bounded_interval": {
                "source": "HOST_OBSERVER_TRACE_FILE_LIFETIME",
                "first_observed_at_monotonic_ns": first_seen,
                "last_observed_at_monotonic_ns": last_seen,
                "interval_distance_ns": 0,
                "max_correlation_slack_ns": 250_000_000,
            },
            "temporal_binding_status": "PASS",
        }
        item["immutable_record_digest"] = canonical_json_sha256(item)
        return item

    observations = [
        observation(402362, 1, 402361, 402361, 1001, 1, 2),
        observation(402363, 2, 402362, 1, 1002, 2, 3),
        observation(402447, 34, 402363, 2, 1003, 3, 4),
    ]
    positive = correlate_cross_namespace_process_identities(
        synthetic_traces, {"process_observations": observations}
    )
    missing_namespace = [dict(item) for item in observations]
    missing_namespace[1]["namespace_id"] = None
    missing = correlate_cross_namespace_process_identities(
        synthetic_traces, {"process_observations": missing_namespace}
    )
    ambiguous = [dict(item) for item in observations]
    duplicate = dict(observations[1])
    duplicate["proc_starttime"] = 9999
    duplicate["stable_identity_tuple"] = [402363, 9999, "pid:[4026532408]"]
    duplicate["proc_topology_identity"] = canonical_json_sha256({
        "host_pid": 402363,
        "proc_starttime": 9999,
        "pid_namespace_identity": "pid:[4026532408]",
    })
    duplicate["immutable_record_digest"] = canonical_json_sha256({
        key: value for key, value in duplicate.items() if key != "immutable_record_digest"
    })
    ambiguous.append(duplicate)
    ambiguous_result = correlate_cross_namespace_process_identities(
        synthetic_traces, {"process_observations": ambiguous}
    )
    v5_topology_path = V5_WORKSPACE / "static-run-v5/runtime-topology-snapshot-0001.json"
    v5_topology = load_json(v5_topology_path)
    v5_traces: dict[int, str] = {}
    for path in sorted((V5_WORKSPACE / "static-run-v5").glob("trace.*")):
        try:
            v5_traces[int(path.name.rsplit(".", 1)[1])] = path.read_text(encoding="utf-8", errors="replace")
        except (IndexError, ValueError):
            continue
    v5_regression = correlate_cross_namespace_process_identities(v5_traces, v5_topology)
    v10_topology = load_json(V10_WORKSPACE / "static-run-v10/runtime-topology-snapshot-0001.json")
    v10_traces: dict[int, str] = {}
    for path in sorted((V10_WORKSPACE / "static-run-v10").glob("trace.*")):
        try:
            v10_traces[int(path.name.rsplit(".", 1)[1])] = path.read_text(encoding="utf-8", errors="replace")
        except (IndexError, ValueError):
            continue
    v10_regression = correlate_cross_namespace_process_identities(v10_traces, v10_topology)
    checks = {
        "required_fields_exact": set(contract.get("identity_fields", [])) == set(PROCESS_IDENTITY_FIELDS),
        "local_host_equality_prohibited": contract.get("rules", {}).get("local_pid_equals_host_pid_without_evidence") == "PROHIBITED",
        "mapping_evidence_required": contract.get("rules", {}).get("mapping_requires_evidence_refs") is True,
        "unknown_lineage_fail_closed": contract.get("rules", {}).get("unknown_lineage") == "FAIL_CLOSED",
        "synthetic_mapping_pass": positive.get("status") == "PASS",
        "runtime_local_two_not_host_pid": any(
            item.get("local_pid") == 2 and item.get("host_pid") == 402363
            for item in positive.get("mappings", [])
        ),
        "trace_file_pid_and_local_pid_separate": any(
            item.get("trace_file_pid") == 402363 and item.get("local_pid") == 2
            for item in positive.get("mappings", [])
        ),
        "runtime_host_parent_bound": any(
            item.get("host_pid") == 402363 and item.get("parent_host_pid") == 402362
            for item in positive.get("mappings", [])
        ),
        "startup_child_host_parent_bound": any(
            item.get("host_pid") == 402447 and item.get("parent_host_pid") == 402363
            for item in positive.get("mappings", [])
        ),
        "missing_namespace_rejected": missing.get("status") == "FAIL_CLOSED",
        "ambiguous_mapping_rejected": ambiguous_result.get("status") == "FAIL_CLOSED",
        "v5_legacy_topology_reproduces_failure": v5_regression.get("status") == "FAIL_CLOSED",
        "v10_missing_temporal_observations_reproduces_failure": v10_regression.get("status") == "FAIL_CLOSED"
        and v10_regression.get("mapped_trace_file_count") == 0,
    }
    return {
        "status": "PASS" if all(checks.values()) else "FAIL_CLOSED",
        "checks": checks,
        "positive_fixture": positive,
        "missing_namespace_fixture": missing,
        "ambiguous_mapping_fixture": ambiguous_result,
        "v5_regression": {
            "status": v5_regression.get("status"),
            "mapped_trace_file_count": v5_regression.get("mapped_trace_file_count"),
            "trace_file_count": v5_regression.get("trace_file_count"),
        },
        "v10_regression": {
            "status": v10_regression.get("status"),
            "mapped_trace_file_count": v10_regression.get("mapped_trace_file_count"),
            "trace_file_count": v10_regression.get("trace_file_count"),
        },
    }


def temporal_process_identity_observer_precheck() -> dict[str, Any]:
    """Validate V19 event-bound capture, telemetry, and N-of-N semantics."""

    observer = load_json(WORKSPACE / "contracts/TEMPORAL_PROCESS_IDENTITY_OBSERVER_CONTRACT.json")
    correlation = load_json(WORKSPACE / "contracts/TEMPORAL_TRACE_CORRELATION_CONTRACT.json")
    expected_order = [
        "OBSERVER_CREATED",
        "PROC_CONNECTOR_SUBSCRIBED",
        "OBSERVER_READY",
        "TRACE_CHILD_READY",
        "ATTEMPT_MARKER",
        "WORKER_EXECUTION",
    ]
    identity_fields = {
        "trace_identity", "trace_first_timestamp", "trace_last_timestamp",
        "identity_capture_attempt_timestamp_monotonic_ns", "proc_lookup_result",
        "host_pid", "parent_host_pid", "process_start_identity", "process_start_identity_kind",
        "pid_namespace_identity", "executable_identity",
        "observation_timestamp_monotonic_ns", "trace_event_timestamp_or_bounded_interval",
        "identity_capture_attempted", "identity_capture_result", "observation_source", "immutable_record_digest",
    }
    same_numeric_distinct = (
        (700, "PROC_STAT_STARTTIME:10", "pid:[1]") != (700, "PROC_STAT_STARTTIME:11", "pid:[1]")
        and (700, "PROC_STAT_STARTTIME:10", "pid:[1]") != (700, "PROC_STAT_STARTTIME:10", "pid:[2]")
    )
    checks = {
        "observer_sources_safe_regular": all(
            safe_regular_file(path) for path in (TEMPORAL_OBSERVER, WORKER_LAUNCH_GATE, SHORT_LIVED_CHILD)
        ),
        "observer_order_exact": observer.get("observer_start_order") == expected_order,
        "readiness_failure_before_attempt": observer.get("readiness_failure") == "FAIL_CLOSED_BEFORE_ATTEMPT",
        "postrun_snapshot_insufficient": observer.get("post_run_proc_snapshot_only") == "INSUFFICIENT",
        "stable_identity_tuple_exact": observer.get("stable_identity_tuple")
        == ["host_pid", "process_start_identity", "pid_namespace_identity"],
        "required_fields_complete": set(observer.get("per_process_required_fields", [])) == identity_fields,
        "pid_reuse_distinct": same_numeric_distinct
        and observer.get("pid_reuse_semantics")
        == "SAME_NUMERIC_PID_WITH_DIFFERENT_START_IDENTITY_OR_NAMESPACE_IS_DISTINCT_IDENTITY",
        "proc_connector_before_trace": observer.get("proc_connector_subscription")
        == "REQUIRED_BEFORE_TRACED_PROCESS_CREATION",
        "best_effort_polling_only_prohibited": observer.get("later_best_effort_proc_polling_as_only_mechanism")
        == "PROHIBITED",
        "complete_coverage_required": observer.get("coverage_accounting", {}).get("missing_identity_count") == 0
        and observer.get("coverage_accounting", {}).get("ambiguous_identity_count") == 0
        and observer.get("coverage_accounting", {}).get("identity_capture_attempt_count")
        == "MUST_EQUAL_LINEAGE_RELEVANT_TRACE_IDENTITY_COUNT",
        "diagnostic_complete_terminal_state": observer.get("observer_terminal_diagnostics", {}).get("numeric_exit_code") == "REQUIRED"
        and observer.get("observer_terminal_diagnostics", {}).get("typed_exit_reason") == "REQUIRED"
        and observer.get("observer_terminal_diagnostics", {}).get("stderr_artifact") == "REQUIRED",
        "typed_failure_classes_complete": set(observer.get("typed_failure_reasons", [])) == {
            "PROCESS_EXITED_BEFORE_CAPTURE", "PROC_ENTRY_NOT_VISIBLE",
            "NAMESPACE_IDENTITY_UNAVAILABLE", "START_IDENTITY_UNAVAILABLE",
            "TRACE_CORRELATION_FAILED", "OBSERVER_INTERNAL_ERROR",
            "TEMPORAL_WINDOW_VIOLATION", "UNKNOWN_EVIDENCE_BOUND_FAILURE",
        },
        "missing_trace_observation_fail_closed": correlation.get("missing_temporal_observation") == "FAIL_CLOSED",
        "mount_and_producer_separate": correlation.get("mount_provenance_is_separate_gate") is True
        and correlation.get("producer_authorization_is_separate_gate") is True,
        "trace_pid_not_identity": correlation.get("trace_pid_is_not_process_identity_without_observer_evidence") is True,
    }
    return {
        "status": "PASS" if all(checks.values()) else "FAIL_CLOSED_BEFORE_ATTEMPT",
        "checks": checks,
        "attempt_count_if_failed": 0,
        "worker_invocation_count_if_failed": 0,
        "codex_as_worker_invocation_count_if_failed": 0,
    }


def _unescape_mountinfo(value: str) -> str:
    return re.sub(r"\\([0-7]{3})", lambda match: chr(int(match.group(1), 8)), value)


def parse_mountinfo(text: str) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    for line_number, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        fields = line.split()
        try:
            separator = fields.index("-")
        except ValueError as exc:
            raise ValueError(f"mountinfo line {line_number} lacks separator") from exc
        if separator < 6 or len(fields) < separator + 4:
            raise ValueError(f"mountinfo line {line_number} malformed")
        entries.append({
            "mount_id": int(fields[0]),
            "parent_mount_id": int(fields[1]),
            "device": fields[2],
            "root": _unescape_mountinfo(fields[3]),
            "mount_point": _unescape_mountinfo(fields[4]),
            "mount_options": fields[5].split(","),
            "optional_fields": fields[6:separator],
            "filesystem_type": fields[separator + 1],
            "mount_source": _unescape_mountinfo(fields[separator + 2]),
            "super_options": fields[separator + 3].split(","),
        })
    if not entries:
        raise ValueError("mountinfo contains no entries")
    return entries


def resolve_mount(path: str, entries: Iterable[Mapping[str, Any]]) -> dict[str, Any] | None:
    candidates = [
        dict(entry)
        for entry in entries
        if isinstance(entry.get("mount_point"), str) and _within(path, str(entry["mount_point"]))
    ]
    if not candidates:
        return None
    return max(candidates, key=lambda entry: len(Path(str(entry["mount_point"])).parts))


def mount_provenance_policy_precheck(component: str = "FRESH_PREFLIGHT") -> dict[str, Any]:
    contract = load_json(WORKSPACE / "contracts/MOUNT_PROVENANCE_WRITE_CONTRACT.json")
    identity_binding = mount_output_binding_precheck(component)
    stale_literals = stale_mount_literal_precheck()
    synthetic = parse_mountinfo(
        "10 1 0:10 / / rw - ext4 /dev/root rw\n"
        "20 10 0:20 / /home/nobcoder rw - tmpfs tmpfs rw\n"
        "21 10 0:21 / /dev rw - tmpfs tmpfs rw\n"
        "22 10 8:1 /fixture-output /run/nobcoder-first-worker-v35/output rw - ext4 /dev/root rw\n"
    )
    home = resolve_mount("/home/nobcoder/.codex/state.json", synthetic)
    dev = resolve_mount("/dev/null", synthetic)
    output = resolve_mount(str(SANDBOX_RUN / "events.jsonl"), synthetic)
    checks = {
        "path_only_prohibited": contract.get("path_string_only_inference") == "PROHIBITED",
        "home_blanket_prohibited": contract.get("home_prefix_exemption") == "PROHIBITED",
        "unknown_fail_closed": contract.get("unknown_mount_or_backing_provenance") == "FAIL_CLOSED",
        "tmpfs_resolves_semantically": home is not None and home.get("mount_point") == "/home/nobcoder" and home.get("filesystem_type") == "tmpfs",
        "private_dev_resolves_semantically": dev is not None and dev.get("mount_point") == "/dev" and dev.get("filesystem_type") == "tmpfs",
        "output_bind_resolves_semantically": output is not None and output.get("mount_point") == str(SANDBOX_RUN) and output.get("root") == "/fixture-output",
        "output_bind_exact_destination": contract.get("authorized_host_output_bind", {}).get("sandbox_mount_point") == str(SANDBOX_RUN),
        "runtime_descendant_inheritance_typed": contract.get("producer_lineage", {}).get("runtime_descendant_resolution") == "NEAREST_TYPED_EXEC_ANCESTOR",
        "mount_provenance_separate_gate": contract.get("mount_provenance_gate", {}).get("separate_gate") is True,
        "producer_authorization_separate_gate": contract.get("producer_authorization_gate", {}).get("separate_gate") is True,
        "partial_gate_not_authorization": contract.get("partial_gate_pass_is_not_authorization") is True,
        "both_gates_required": contract.get("final_write_authorization") == "MOUNT_PROVENANCE_GATE_PASS_AND_PRODUCER_AUTHORIZATION_GATE_PASS",
        "governance_bound_identity": identity_binding.get("status") == "PASS",
        "zero_stale_successor_bindings": stale_literals.get("status") == "PASS",
    }
    return {
        "status": "PASS" if all(checks.values()) else "FAIL_CLOSED",
        "checks": checks,
        "mount_output_identity": identity_binding,
        "stale_literal_check": stale_literals,
    }


def effective_producer_lineage(trace_pid: int, lineage: Mapping[str, Any]) -> dict[str, Any] | None:
    """Resolve a trace task to an evidence-bound typed exec ancestor."""

    classified = {
        int(item["pid"]): dict(item)
        for item in lineage.get("classified", [])
        if isinstance(item, Mapping) and isinstance(item.get("pid"), int)
    }
    direct = classified.get(trace_pid)
    if direct is not None:
        return {**direct, "lineage_resolution": "DIRECT_TYPED_EXEC", "typed_exec_ancestor_pid": trace_pid}
    identities = {
        int(item["trace_file_pid"]): dict(item)
        for item in lineage.get("identity_mappings", [])
        if isinstance(item, Mapping) and isinstance(item.get("trace_file_pid"), int)
    }
    identity = identities.get(trace_pid)
    if identity is None or not identity.get("evidence_refs"):
        return None
    thread_group = identity.get("host_thread_group_id")
    if isinstance(thread_group, int) and thread_group != trace_pid:
        ancestor = classified.get(thread_group)
        if ancestor is not None:
            return {
                **ancestor,
                "lineage_resolution": "EVIDENCE_BOUND_THREAD_GROUP_LEADER",
                "typed_exec_ancestor_pid": thread_group,
                "observed_trace_pid": trace_pid,
                "producer_identity": identity,
            }
    raw_parents = lineage.get("parent_map", {})
    try:
        parents = {int(child): int(parent) for child, parent in raw_parents.items()}
        chain = _ancestor_chain(trace_pid, parents)
    except (TypeError, ValueError):
        return None
    for ancestor_pid in chain:
        ancestor = classified.get(ancestor_pid)
        if ancestor is not None:
            return {
                **ancestor,
                "lineage_resolution": "NEAREST_TYPED_EXEC_ANCESTOR",
                "typed_exec_ancestor_pid": ancestor_pid,
                "observed_trace_pid": trace_pid,
                "observed_ancestor_chain": list(chain),
                "producer_identity": identity,
            }
    return None


def classify_mount_provenance_writes(
    traces: Mapping[int, str],
    namespace: Mapping[str, Any],
    lineage: Mapping[str, Any],
    topology: Mapping[str, Any],
) -> dict[str, Any]:
    """Evaluate mount provenance and producer lineage as independent gates."""

    runtime_entries = topology.get("runtime_mountinfo_entries", [])
    host_entries = topology.get("host_mountinfo_entries", [])
    runtime_mount_namespace = topology.get("runtime_mount_namespace")
    host_mount_namespace = topology.get("host_mount_namespace")
    runtime_mount_by_id = {
        int(item["mount_id"]): dict(item)
        for item in runtime_entries
        if isinstance(item, Mapping) and isinstance(item.get("mount_id"), int)
    }
    expected_namespace = {tuple(item) for item in namespace.get("expected", [])}
    supervisor = namespace.get("supervisor_pid")
    authorized: list[dict[str, Any]] = []
    rejected: list[dict[str, Any]] = []
    parse_failures: list[dict[str, Any]] = []
    mount_gate_records: list[dict[str, Any]] = []
    producer_gate_records: list[dict[str, Any]] = []
    namespace_count = 0
    class_counts = {
        "AUTHORIZED_HOST_OUTPUT_WRITE": 0,
        "AUTHORIZED_NAMESPACE_SETUP_WRITE": 0,
        "EPHEMERAL_SANDBOX_TMPFS_WRITE": 0,
        "PRIVATE_DEV_OBJECT_WRITE": 0,
        "HOST_BACKED_FILESYSTEM_WRITE": 0,
        "UNKNOWN_WRITE_PROVENANCE": 0,
    }
    termination_events: list[dict[str, Any]] = []

    for trace_pid, text in sorted(traces.items()):
        producer = effective_producer_lineage(trace_pid, lineage)
        for line in text.splitlines():
            try:
                event = parse_syscall_line(line)
                if event is None:
                    continue
                evidence = typed_evidence_for_event(event)
            except ValueError as exc:
                parse_failures.append({"trace_file_pid": trace_pid, "line": line, "reason": str(exc)})
                continue
            if event.family == SyscallFamily.NON_RETURNING_PROCESS_TERMINATION:
                termination_events.append({"trace_file_pid": trace_pid, "syscall": event.name, "status": int(event.args[0]), "result": event.result})
                continue
            if event.succeeded is not True or event.name not in {"write", "writev"}:
                continue

            namespace_paths = [item.value for item in evidence if item.evidence_class == EvidenceClass.NAMESPACE_CONTROL_PATH]
            file_targets = [item.value for item in evidence if item.evidence_class == EvidenceClass.FILESYSTEM_FD_WRITE_TARGET]
            for path in namespace_paths:
                value = (path, f"{event.args[1]}, {event.args[2]}", int(event.return_value))
                exact_namespace_write = trace_pid == supervisor and event.name == "write" and value in expected_namespace
                producer_identity = producer.get("producer_identity", producer) if producer else None
                producer_refs = (
                    producer_identity.get("evidence_refs", [])
                    if isinstance(producer_identity, Mapping)
                    else []
                )
                namespace_producer_pass = (
                    exact_namespace_write
                    and lineage.get("status") == "PASS"
                    and isinstance(producer_identity, Mapping)
                    and producer_identity.get("trace_file_pid") == trace_pid
                    and isinstance(producer_identity.get("host_pid"), int)
                    and isinstance(producer_identity.get("local_pid"), int)
                    and isinstance(producer_identity.get("namespace_id"), str)
                    and bool(producer_refs)
                )
                mount_record = {
                    "trace_file_pid": trace_pid,
                    "path": path,
                    "class": "AUTHORIZED_NAMESPACE_SETUP_WRITE" if exact_namespace_write else "UNKNOWN_WRITE_PROVENANCE",
                    "mount_id": None,
                    "filesystem_type": "proc",
                    "mount_source": "proc",
                    "mount_point": "/proc",
                    "mount_namespace": "BWRAP_SETUP_NAMESPACE",
                    "backing_provenance": "BWRAP_USER_NAMESPACE_CONTROL" if exact_namespace_write else "UNRESOLVED",
                    "topology_role": "EXACT_NAMESPACE_CONTROL_PATH" if exact_namespace_write else "UNKNOWN",
                    "status": "PASS" if exact_namespace_write else "FAIL_CLOSED",
                }
                producer_record = {
                    "trace_file_pid": trace_pid,
                    "host_pid": producer_identity.get("host_pid") if isinstance(producer_identity, Mapping) else None,
                    "local_pid": producer_identity.get("local_pid") if isinstance(producer_identity, Mapping) else None,
                    "namespace_id": producer_identity.get("namespace_id") if isinstance(producer_identity, Mapping) else None,
                    "process_class": "LAUNCHER",
                    "lifecycle_phase": "NAMESPACE_SETUP",
                    "evidence_refs": [*producer_refs, "EXACT_NAMESPACE_SETUP_WRITE_PROOF"],
                    "status": "PASS" if namespace_producer_pass else "FAIL_CLOSED",
                }
                mount_gate_records.append(mount_record)
                producer_gate_records.append(producer_record)
                final_pass = exact_namespace_write and namespace_producer_pass
                if final_pass:
                    namespace_count += 1
                    class_counts["AUTHORIZED_NAMESPACE_SETUP_WRITE"] += 1
                    authorized.append({
                        "trace_file_pid": trace_pid,
                        "path": path,
                        "class": "AUTHORIZED_NAMESPACE_SETUP_WRITE",
                        "mount_provenance_gate": mount_record,
                        "producer_authorization_gate": producer_record,
                        "final_authorization": "PASS",
                    })
                else:
                    class_counts["UNKNOWN_WRITE_PROVENANCE"] += 1
                    rejected.append({
                        "trace_file_pid": trace_pid,
                        "path": path,
                        "reason": "UNAUTHORIZED_PROC_WRITE",
                        "mount_provenance_gate": mount_record,
                        "producer_authorization_gate": producer_record,
                        "final_authorization": "FAIL_CLOSED",
                    })

            for path in file_targets:
                runtime_mount = resolve_mount(path, runtime_entries) if runtime_entries else None
                host_mount = resolve_mount(path, host_entries) if host_entries else None
                exact_sandbox_output_mount = (
                    runtime_mount is not None
                    and runtime_mount.get("mount_point") == str(SANDBOX_RUN)
                    and "rw" in runtime_mount.get("mount_options", [])
                    and _within(path, str(SANDBOX_RUN))
                )
                inherited_host_output_fd = _within(path, str(STATIC_RUN)) and host_mount is not None
                home_tmpfs = (
                    runtime_mount is not None
                    and runtime_mount.get("mount_point") == "/home/nobcoder"
                    and runtime_mount.get("filesystem_type") == "tmpfs"
                    and runtime_mount.get("mount_source") == "tmpfs"
                )
                parent_mount = (
                    runtime_mount_by_id.get(int(runtime_mount["parent_mount_id"]))
                    if runtime_mount is not None and isinstance(runtime_mount.get("parent_mount_id"), int)
                    else None
                )
                private_dev_object = (
                    path == "/dev/null"
                    and runtime_mount is not None
                    and runtime_mount.get("mount_point") == "/dev/null"
                    and runtime_mount.get("root") == "/null"
                    and runtime_mount.get("filesystem_type") == "devtmpfs"
                    and runtime_mount.get("mount_source") == "udev"
                    and parent_mount is not None
                    and parent_mount.get("mount_point") == "/dev"
                    and parent_mount.get("filesystem_type") == "tmpfs"
                    and parent_mount.get("mount_source") == "tmpfs"
                )

                if exact_sandbox_output_mount or inherited_host_output_fd:
                    classification = "AUTHORIZED_HOST_OUTPUT_WRITE"
                    mount = runtime_mount if exact_sandbox_output_mount else host_mount
                    namespace_id = runtime_mount_namespace if exact_sandbox_output_mount else host_mount_namespace
                    backing = "DECLARED_SINGLE_HOST_OUTPUT_BIND" if exact_sandbox_output_mount else "INHERITED_CONTROLLER_OUTPUT_FD"
                    topology_role = "DECLARED_HOST_OUTPUT_BIND"
                    mount_pass = True
                elif home_tmpfs:
                    classification = "EPHEMERAL_SANDBOX_TMPFS_WRITE"
                    mount = runtime_mount
                    namespace_id = runtime_mount_namespace
                    backing = "SANDBOX_TMPFS_NO_HOST_BACKING"
                    topology_role = "EPHEMERAL_HOME_TMPFS"
                    mount_pass = True
                elif private_dev_object:
                    classification = "PRIVATE_DEV_OBJECT_WRITE"
                    mount = runtime_mount
                    namespace_id = runtime_mount_namespace
                    backing = "BWRAP_PRIVATE_DEV_CANONICAL_DEVICE_OBJECT"
                    topology_role = "PRIVATE_DEV_SUBMOUNT_UNDER_TMPFS"
                    mount_pass = True
                elif runtime_mount is not None:
                    classification = "HOST_BACKED_FILESYSTEM_WRITE"
                    mount = runtime_mount
                    namespace_id = runtime_mount_namespace
                    backing = "NON_AUTHORIZED_RUNTIME_MOUNT"
                    topology_role = "UNAUTHORIZED_RUNTIME_MOUNT"
                    mount_pass = False
                else:
                    classification = "UNKNOWN_WRITE_PROVENANCE"
                    mount = None
                    namespace_id = None
                    backing = "UNRESOLVED"
                    topology_role = "UNKNOWN"
                    mount_pass = False

                producer_identity = producer.get("producer_identity", producer) if producer else None
                producer_class = producer.get("process_class") if producer else None
                lifecycle = producer.get("lifecycle_phase") if producer else None
                producer_refs = producer_identity.get("evidence_refs", []) if isinstance(producer_identity, Mapping) else []
                producer_pass = (
                    lineage.get("status") == "PASS"
                    and producer_class in {"PINNED_RUNTIME", "EXPECTED_RUNTIME_STARTUP_CHILD"}
                    and isinstance(producer_identity, Mapping)
                    and producer_identity.get("trace_file_pid") == trace_pid
                    and isinstance(producer_identity.get("host_pid"), int)
                    and isinstance(producer_identity.get("local_pid"), int)
                    and isinstance(producer_identity.get("namespace_id"), str)
                    and bool(producer_refs)
                )
                mount_record = {
                    "trace_file_pid": trace_pid,
                    "path": path,
                    "class": classification,
                    "mount_id": mount.get("mount_id") if mount else None,
                    "filesystem_type": mount.get("filesystem_type") if mount else None,
                    "mount_source": mount.get("mount_source") if mount else None,
                    "mount_point": mount.get("mount_point") if mount else None,
                    "mount_namespace": namespace_id,
                    "backing_provenance": backing,
                    "topology_role": topology_role,
                    "status": "PASS" if mount_pass else "FAIL_CLOSED",
                }
                producer_record = {
                    "trace_file_pid": trace_pid,
                    "host_pid": producer_identity.get("host_pid") if isinstance(producer_identity, Mapping) else None,
                    "local_pid": producer_identity.get("local_pid") if isinstance(producer_identity, Mapping) else None,
                    "namespace_id": producer_identity.get("namespace_id") if isinstance(producer_identity, Mapping) else None,
                    "process_class": producer_class,
                    "lifecycle_phase": lifecycle,
                    "evidence_refs": producer_refs,
                    "status": "PASS" if producer_pass else "FAIL_CLOSED",
                }
                mount_gate_records.append(mount_record)
                producer_gate_records.append(producer_record)
                class_counts[classification] += 1
                combined = {
                    "trace_file_pid": trace_pid,
                    "path": path,
                    "class": classification,
                    "mount_provenance_gate": mount_record,
                    "producer_authorization_gate": producer_record,
                    "final_authorization": "PASS" if mount_pass and producer_pass else "FAIL_CLOSED",
                }
                if mount_pass and producer_pass:
                    authorized.append(combined)
                else:
                    rejected.append({
                        **combined,
                        "reason": "MOUNT_PROVENANCE_FAIL" if not mount_pass else "PRODUCER_LINEAGE_NOT_AUTHORIZED",
                    })

    mount_failures = [item for item in mount_gate_records if item.get("status") != "PASS"]
    producer_failures = [item for item in producer_gate_records if item.get("status") != "PASS"]
    mount_provenance_gate = {
        "status": "PASS" if not mount_failures else "FAIL_CLOSED",
        "record_count": len(mount_gate_records),
        "failure_count": len(mount_failures),
        "failures": mount_failures,
    }
    producer_authorization_gate = {
        "status": "PASS" if not producer_failures else "FAIL_CLOSED",
        "record_count": len(producer_gate_records),
        "failure_count": len(producer_failures),
        "failures": producer_failures,
    }
    final_gate = {
        "status": "PASS" if not rejected and mount_provenance_gate["status"] == "PASS" and producer_authorization_gate["status"] == "PASS" else "FAIL_CLOSED",
        "rule": "MOUNT_PROVENANCE_GATE_PASS_AND_PRODUCER_AUTHORIZATION_GATE_PASS",
        "authorized_write_count": len(authorized),
        "rejected_write_count": len(rejected),
    }
    checks = {
        "namespace_writes_exact": namespace_count == 5,
        "runtime_mount_namespace_captured": isinstance(runtime_mount_namespace, str),
        "host_mount_namespace_captured": isinstance(host_mount_namespace, str),
        "runtime_mountinfo_present": bool(runtime_entries),
        "host_mountinfo_present": bool(host_entries),
        "mount_provenance_gate_pass": mount_provenance_gate["status"] == "PASS",
        "producer_authorization_gate_pass": producer_authorization_gate["status"] == "PASS",
        "final_write_authorization_pass": final_gate["status"] == "PASS",
        "no_rejected_write": not rejected,
        "no_parse_failure": not parse_failures,
        "termination_events_present": bool(termination_events),
        "path_only_inference_not_used": True,
    }
    return {
        "status": "PASS" if all(checks.values()) else "FAIL_CLOSED",
        "checks": checks,
        "namespace_write_count": namespace_count,
        "authorized_write_count": len(authorized),
        "class_counts": class_counts,
        "mount_provenance_gate": mount_provenance_gate,
        "producer_lineage_authorization_gate": producer_authorization_gate,
        "final_write_authorization_gate": final_gate,
        "authorized": authorized,
        "rejected": rejected,
        "parse_failures": parse_failures,
        "termination_events": termination_events,
        "free_text_or_regex_path_inference": "PROHIBITED_AND_NOT_USED",
    }


def expected_namespace_writes(pid: int) -> list[tuple[str, str, int]]:
    root = f"/proc/{pid}"
    return [
        (f"{root}/uid_map", f'"0 {HOST_UID} 1\\n", 9', 9),
        (f"{root}/setgroups", '"deny\\n", 5', 5),
        (f"{root}/gid_map", f'"0 {HOST_GID} 1\\n", 9', 9),
        (f"{root}/uid_map", f'"{HOST_UID} 0 1\\n", 9', 9),
        (f"{root}/gid_map", f'"{HOST_GID} 0 1\\n", 9', 9),
    ]


def classify_namespace_setup_writes(traces: Mapping[int, str]) -> dict[str, Any]:
    execs = _parsed_execve_events(traces)
    bwrap = [item for item in execs if item["succeeded"] and item["executable"] == str(BWRAP)]
    if len(bwrap) != 1:
        return {"status": "FAIL", "reason": "BWRAP_EXECVE_CARDINALITY", "count": len(bwrap)}
    launcher_pid = int(bwrap[0]["trace_pid"])
    supervisors = [
        int(match.group("pid"))
        for line in traces.get(launcher_pid, "").splitlines()
        if (match := CLONE_USER.match(line))
    ]
    if len(supervisors) != 1 or supervisors[0] not in traces:
        return {"status": "FAIL", "reason": "SUPERVISOR_LINEAGE", "pids": supervisors}
    supervisor = supervisors[0]
    observed: list[tuple[str, str, int]] = []
    invalid: list[dict[str, Any]] = []
    for trace_pid, text in sorted(traces.items()):
        for line in text.splitlines():
            event = parse_syscall_line(line)
            if event is None or event.name not in {"write", "writev"}:
                continue
            typed = typed_evidence_for_event(event)
            paths = [item.value for item in typed if item.evidence_class == EvidenceClass.NAMESPACE_CONTROL_PATH]
            if not paths:
                continue
            if event.name != "write" or len(paths) != 1 or trace_pid != supervisor or event.return_value is None or len(event.args) < 3:
                invalid.append({"trace_pid": trace_pid, "line": line, "reason": "WRONG_PRODUCER_OR_FORM"})
                continue
            observed.append((paths[0], f"{event.args[1]}, {event.args[2]}", event.return_value))
    expected = expected_namespace_writes(supervisor)
    return {
        "status": "PASS" if observed == expected and not invalid else "FAIL",
        "launcher_pid": launcher_pid,
        "supervisor_pid": supervisor,
        "expected": expected,
        "observed": observed,
        "invalid": invalid,
    }


def classify_config_consumption(traces: Mapping[int, str]) -> dict[str, Any]:
    selected: list[dict[str, Any]] = []
    consumed: list[dict[str, Any]] = []
    parse_failures: list[dict[str, Any]] = []
    config_path = str(SANDBOX_CODEX_HOME / "config.toml")
    for trace_pid, text in sorted(traces.items()):
        for line in text.splitlines():
            try:
                event = parse_syscall_line(line)
                if event is None:
                    continue
                evidence = typed_evidence_for_event(event)
            except ValueError as exc:
                parse_failures.append({"trace_pid": trace_pid, "line": line, "reason": str(exc)})
                continue
            if event.name in {"open", "openat"} and event.succeeded is True:
                paths = [item.value for item in evidence if item.evidence_class == EvidenceClass.FILESYSTEM_PATHNAME_BEARING_SYSCALL_OPERAND]
                if config_path in paths:
                    selected.append({"trace_pid": trace_pid, "line": line})
            if event.name == "read" and event.return_value is not None and event.return_value > 0:
                annotations = [item.value for item in evidence if item.evidence_class == EvidenceClass.FD_ANNOTATION]
                if config_path in annotations:
                    consumed.append({"trace_pid": trace_pid, "line": line, "bytes": event.return_value})
    return {
        "status": "PASS" if selected and consumed and not parse_failures else "FAIL",
        "exists": safe_regular_file(CODEX_CONFIG),
        "selected": bool(selected),
        "consumed": bool(consumed),
        "selected_events": selected,
        "consumed_events": consumed,
        "parse_failures": parse_failures,
    }


def classify_typed_write_evidence(traces: Mapping[int, str], namespace: Mapping[str, Any]) -> dict[str, Any]:
    """Classify writes from typed syscall operands; never infer paths from payload text."""

    expected_namespace = {tuple(item) for item in namespace.get("expected", [])}
    supervisor = namespace.get("supervisor_pid")
    namespace_count = 0
    authorized: list[dict[str, Any]] = []
    rejected: list[dict[str, Any]] = []
    parse_failures: list[dict[str, Any]] = []
    evidence_counts = {item.value: 0 for item in EvidenceClass}
    allowed_roots = (str(SANDBOX_RUN), str(STATIC_RUN), "/tmp", "/var/tmp")
    termination_events: list[dict[str, Any]] = []
    for trace_pid, text in sorted(traces.items()):
        for line in text.splitlines():
            try:
                event = parse_syscall_line(line)
                if event is None:
                    continue
                evidence = typed_evidence_for_event(event)
            except ValueError as exc:
                parse_failures.append({"trace_pid": trace_pid, "line": line, "reason": str(exc)})
                continue
            for item in evidence:
                evidence_counts[item.evidence_class.value] += 1
            if event.family == SyscallFamily.NON_RETURNING_PROCESS_TERMINATION:
                termination_events.append({"trace_pid": trace_pid, "syscall": event.name, "status": int(event.args[0]), "result": event.result})
                continue
            if event.succeeded is not True or event.name not in {"write", "writev"}:
                continue
            namespace_paths = [item.value for item in evidence if item.evidence_class == EvidenceClass.NAMESPACE_CONTROL_PATH]
            file_targets = [item.value for item in evidence if item.evidence_class == EvidenceClass.FILESYSTEM_FD_WRITE_TARGET]
            for path in namespace_paths:
                value = (path, f"{event.args[1]}, {event.args[2]}", int(event.return_value))
                if trace_pid == supervisor and event.name == "write" and value in expected_namespace:
                    namespace_count += 1
                    authorized.append({"trace_pid": trace_pid, "path": path, "class": "AUTHORIZED_NAMESPACE_SETUP_WRITE"})
                else:
                    rejected.append({"trace_pid": trace_pid, "path": path, "reason": "UNAUTHORIZED_PROC_WRITE"})
            for path in file_targets:
                if any(_within(path, root) for root in allowed_roots):
                    authorized.append({"trace_pid": trace_pid, "path": path, "class": "AUTHORIZED_OUTPUT_WRITE"})
                else:
                    rejected.append({"trace_pid": trace_pid, "path": path, "reason": "OUT_OF_SCOPE_FD_WRITE"})
    status = "PASS" if namespace_count == 5 and not rejected and not parse_failures and termination_events else "FAIL"
    return {
        "status": status,
        "namespace_write_count": namespace_count,
        "authorized_write_count": len(authorized),
        "authorized": authorized,
        "rejected": rejected,
        "parse_failures": parse_failures,
        "termination_events": termination_events,
        "typed_evidence_counts": evidence_counts,
        "free_text_or_regex_path_inference": "PROHIBITED_AND_NOT_USED",
    }


def transcript_summary(path: Path) -> dict[str, Any]:
    event_types: list[str] = []
    item_types: list[str] = []
    tool_events: list[dict[str, Any]] = []
    usage: dict[str, Any] = {}
    thread_ids: list[str] = []
    errors: list[str] = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
        if not line.strip():
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError as exc:
            errors.append(f"line {line_number}: {exc}")
            continue
        event_type = str(event.get("type", ""))
        event_types.append(event_type)
        if event_type == "thread.started" and isinstance(event.get("thread_id"), str):
            thread_ids.append(event["thread_id"])
        item = event.get("item")
        if isinstance(item, dict):
            item_type = str(item.get("type", ""))
            item_types.append(item_type)
            lowered = item_type.lower()
            if any(token in lowered for token in ("tool", "command", "web_search", "file_change", "mcp")):
                tool_events.append({"event_type": event_type, "item_type": item_type, "line": line_number})
        if event_type == "turn.completed" and isinstance(event.get("usage"), dict):
            usage = event["usage"]
    return {
        "status": "PASS" if not errors and len(thread_ids) == 1 else "FAIL",
        "event_types": event_types,
        "item_types": item_types,
        "tool_events": tool_events,
        "tool_call_count": len(tool_events),
        "thread_ids": thread_ids,
        "usage": usage,
        "parse_errors": errors,
    }


def token_budget_contract() -> dict[str, Any]:
    return load_json(WORKSPACE / "contracts/TOKEN_BUDGET_CONTRACT.json")


def token_budget_feasibility_precheck() -> dict[str, Any]:
    contract = token_budget_contract()
    limits = contract.get("limits", {})
    baseline = contract.get("v4_frozen_baseline", {})
    semantics = contract.get("measurement_semantics", {})
    required_limits = (
        "input_token_limit", "output_token_limit", "reasoning_output_token_limit", "total_token_limit"
    )
    checks = {
        "accounting_source_exact": contract.get("accounting_source") == "CODEX_JSONL_TURN_COMPLETED_USAGE",
        "limits_positive_integers": all(isinstance(limits.get(key), int) and limits[key] > 0 for key in required_limits),
        "total_formula_non_overlapping": semantics.get("total_formula") == "input_tokens + output_tokens",
        "reasoning_declared_subset": semantics.get("reasoning_output_tokens") == "PROVIDER_REPORTED_SUBSET_OF_OUTPUT_NOT_ADDED_TO_TOTAL",
        "cached_input_declared_subset": contract.get("cached_input_policy") == "REPORTED_SUBSET_OF_INPUT_TOKENS_NOT_ADDED_TO_TOTAL",
        "cache_write_declared": contract.get("cache_write_input_policy") == "REPORTED_AUXILIARY_FIELD_MUST_EQUAL_ZERO_NOT_ADDED_TO_TOTAL",
        "over_budget_fail_closed": contract.get("over_budget_action") == "FAIL_CLOSED_TERMINAL_NO_RETRY_AND_FREEZE_FAILURE_EVIDENCE",
        "frozen_baseline_typed": all(isinstance(baseline.get(key), int) and baseline[key] >= 0 for key in ("input_tokens", "output_tokens", "reasoning_output_tokens", "total_tokens")),
        "baseline_formula": baseline.get("total_tokens") == baseline.get("input_tokens", -1) + baseline.get("output_tokens", -1),
        "input_headroom": isinstance(limits.get("input_token_limit"), int) and limits["input_token_limit"] - baseline.get("input_tokens", limits["input_token_limit"]) >= 8192,
        "output_headroom": isinstance(limits.get("output_token_limit"), int) and limits["output_token_limit"] - baseline.get("output_tokens", limits["output_token_limit"]) >= 1024,
        "total_headroom": isinstance(limits.get("total_token_limit"), int) and limits["total_token_limit"] - baseline.get("total_tokens", limits["total_token_limit"]) >= 8192,
        "prompt_bounded": PROMPT_PATH.stat().st_size <= 8192,
        "fixture_context_bounded": sum(path.stat().st_size for path in CONTEXT_ROOT.rglob("*") if path.is_file()) <= 65536,
    }
    return {
        "status": "PASS" if all(checks.values()) else "FAIL_CLOSED",
        "checks": checks,
        "accounting_source": contract.get("accounting_source"),
        "limits": limits,
        "measurement_semantics": semantics,
        "baseline": baseline,
        "attempt_count_if_failed": 0,
        "worker_invocation_count_if_failed": 0,
        "codex_as_worker_invocation_count_if_failed": 0,
    }


def evaluate_typed_token_usage(usage: Mapping[str, Any]) -> dict[str, Any]:
    contract = token_budget_contract()
    limits = contract["limits"]
    fields = {
        "input_tokens": usage.get("input_tokens"),
        "output_tokens": usage.get("output_tokens"),
        "reasoning_output_tokens": usage.get("reasoning_output_tokens", 0),
        "cached_input_tokens": usage.get("cached_input_tokens", 0),
        "cache_write_input_tokens": usage.get("cache_write_input_tokens", 0),
    }
    typed = all(isinstance(value, int) and value >= 0 for value in fields.values())
    total = fields["input_tokens"] + fields["output_tokens"] if typed else None
    checks = {
        "all_usage_fields_nonnegative_integers": typed,
        "cached_input_is_subset": typed and fields["cached_input_tokens"] <= fields["input_tokens"],
        "reasoning_is_output_subset": typed and fields["reasoning_output_tokens"] <= fields["output_tokens"],
        "cache_write_input_zero": typed and fields["cache_write_input_tokens"] == 0,
        "input_within_limit": typed and fields["input_tokens"] <= limits["input_token_limit"],
        "output_within_limit": typed and fields["output_tokens"] <= limits["output_token_limit"],
        "reasoning_within_limit": typed and fields["reasoning_output_tokens"] <= limits["reasoning_output_token_limit"],
        "total_within_limit": typed and total <= limits["total_token_limit"],
    }
    return {
        "status": "PASS" if all(checks.values()) else "FAIL_CLOSED_OVER_BUDGET_OR_AMBIGUOUS",
        "accounting_source": contract["accounting_source"],
        "fields": fields,
        "computed_total_tokens": total,
        "total_formula": contract["measurement_semantics"]["total_formula"],
        "limits": limits,
        "checks": checks,
        "over_budget_action": contract["over_budget_action"],
    }


def operation_counters_after_success() -> dict[str, int]:
    counters = {key: 0 for key in OPERATION_KEYS}
    counters["worker_invocations"] = 1
    counters["codex_worker_invocations"] = 1
    return counters


def verify_security_worker_runtime_source() -> dict[str, Any]:
    manifest_path = SECURITY_WORKER_RUNTIME_SOURCE / "SOURCE_MANIFEST.json"
    if not safe_regular_file(manifest_path):
        return {"status": "FAIL", "reason": "MISSING_SOURCE_MANIFEST"}
    manifest = load_json(manifest_path)
    failures: list[str] = []
    if manifest.get("canonical_source_root_sha256") != SECURITY_WORKER_RUNTIME_ROOT:
        failures.append("ROOT_MISMATCH")
    members = manifest.get("members")
    if not isinstance(members, list) or manifest.get("member_count") != len(members):
        failures.append("MEMBER_CARDINALITY")
        members = []
    for item in members:
        relative = item.get("path")
        path = SECURITY_WORKER_RUNTIME_SOURCE / str(relative)
        if not safe_regular_file(path):
            failures.append(f"UNSAFE:{relative}")
            continue
        if sha256_file(path) != item.get("sha256"):
            failures.append(f"DIGEST:{relative}")
        if stat.S_IMODE(path.stat().st_mode) != 0o444:
            failures.append(f"MODE:{relative}")
    return {
        "status": "PASS" if not failures else "FAIL",
        "canonical_source_root_sha256": manifest.get("canonical_source_root_sha256"),
        "member_count": len(members),
        "failures": failures,
    }


def preflight_workspace_snapshot(require_static_lock: bool) -> dict[str, Any]:
    if require_static_lock:
        expected = set(expected_lock_members()) | LOCK_OUTPUTS
    else:
        expected = set(SOURCE_PATHS) | {
            relative for relative in PRELOCK_RESULT_PATHS if (WORKSPACE / relative).exists()
        } | set(prelock_selftest_artifact_paths())
    actual = {
        path.relative_to(WORKSPACE).as_posix()
        for path in WORKSPACE.rglob("*")
        if (path.is_file() or path.is_symlink()) and not path.is_relative_to(STATIC_RUN)
    }
    return {
        "status": "PASS" if actual == expected else "FAIL",
        "expected_count": len(expected),
        "actual_count": len(actual),
        "missing": sorted(expected - actual),
        "unexpected": sorted(actual - expected),
    }


def fresh_preflight(require_static_lock: bool = False) -> dict[str, Any]:
    checks: dict[str, dict[str, Any]] = {}

    def record(name: str, passed: bool, **evidence: Any) -> None:
        checks[name] = {"status": "PASS" if passed else "FAIL", **evidence}

    record("workspace_exact", WORKSPACE.is_dir() and not WORKSPACE.is_symlink(), path=str(WORKSPACE))
    record("static_run_exact", STATIC_RUN.is_dir() and not STATIC_RUN.is_symlink(), path=str(STATIC_RUN))
    unified_generation = unified_binding_generation_precheck("FRESH_PREFLIGHT")
    record(
        "unified_governance_bound_binding_generation",
        unified_generation.get("status") == "PASS",
        precheck=unified_generation,
    )
    derived_digest_view = derived_current_expected_digest_view_precheck()
    record(
        "derived_current_expected_digest_view",
        derived_digest_view.get("status") == "PASS"
        and derived_digest_view.get("zero_stale_current_artifact_digests") is True
        and derived_digest_view.get("zero_stale_current_owner_governance_digests") is True
        and derived_digest_view.get("zero_mixed_generation_current_bindings") is True
        and derived_digest_view.get("zero_historical_only_selected_as_current") is True,
        precheck=derived_digest_view,
    )
    historical_relations = historical_decision_relation_precheck()
    record(
        "canonical_historical_decision_relation_registry",
        historical_relations.get("status") == "PASS",
        precheck=historical_relations,
    )
    canonical_predecessor = canonical_predecessor_binding_precheck("FRESH_PREFLIGHT")
    record(
        "canonical_governance_bound_predecessor",
        canonical_predecessor.get("status") == "PASS",
        precheck=canonical_predecessor,
    )
    external_predecessor_artifacts = external_predecessor_artifact_precheck("FRESH_PREFLIGHT")
    record(
        "canonical_external_predecessor_artifact_resolution",
        external_predecessor_artifacts.get("status") == "PASS",
        precheck=external_predecessor_artifacts,
    )
    canonical_modules = canonical_module_resolution_precheck("FRESH_PREFLIGHT")
    record(
        "canonical_module_resolution_environment",
        canonical_modules.get("status") == "PASS",
        precheck=canonical_modules,
    )
    run_members = sorted(path.name for path in STATIC_RUN.iterdir()) if STATIC_RUN.is_dir() else ["MISSING"]
    record("attempt_marker_absent", "ATTEMPT_MARKER.json" not in run_members, members=run_members)
    record("runtime_result_absent", "runtime-result-0001.json" not in run_members)
    snapshot = preflight_workspace_snapshot(require_static_lock)
    record("exact_workspace_set", snapshot["status"] == "PASS", snapshot=snapshot)
    for name, path in PREDECESSOR_PATHS.items():
        actual = sha256_file(path) if safe_regular_file(path) else None
        record(name, actual == EXPECTED_DIGESTS[name], path=str(path), expected=EXPECTED_DIGESTS[name], actual=actual)
    predecessor_resolution = authoritative_predecessor_resolution_precheck()
    record(
        "authoritative_predecessor_resolution_precheck",
        predecessor_resolution.get("status") == "PASS",
        precheck=predecessor_resolution,
    )
    runtime = require_typed_verdict(inspect_runtime_identity(), "inspect_runtime_identity")
    record("exact_runtime_identity", runtime["status"] == "PASS", runtime=runtime)
    for name, path in (("bwrap", BWRAP), ("strace", STRACE), ("python", PYTHON)):
        actual = sha256_file(path) if safe_regular_file(path) else None
        record(name, actual == EXPECTED_DIGESTS[name], path=str(path), expected=EXPECTED_DIGESTS[name], actual=actual)
    artifact_identity = authoritative_artifact_digest_precheck()
    record(
        "authoritative_artifact_digest_precheck",
        artifact_identity.get("status") == "PASS",
        precheck=artifact_identity,
    )
    artifact_finalization = authoritative_artifact_finalization_precheck()
    record(
        "authoritative_artifact_creation_closure_and_finalization",
        artifact_finalization.get("status") == "PASS",
        precheck=artifact_finalization,
    )
    prompt_policy = prompt_policy_verdict(PROMPT_PATH.read_text(encoding="utf-8"))
    record("canonical_prompt_policy", prompt_policy["status"] == "PASS", policy=prompt_policy)
    prompt_identity = prompt_identity_binding_precheck()
    record("prompt_identity_binding_precheck", prompt_identity["status"] == "PASS", precheck=prompt_identity)
    source = verify_security_worker_runtime_source()
    record("security_worker_runtime_source", source["status"] == "PASS", source=source)
    v1_reference = verify_v1_reference_predecessor()
    record("v1_reference_predecessor_immutable", v1_reference["status"] == "PASS", predecessor=v1_reference)
    v2_reference = verify_v2_reference_predecessor()
    record("v2_reference_predecessor_immutable", v2_reference["status"] == "PASS", predecessor=v2_reference)
    v3_reference = verify_v3_reference_predecessor()
    record("v3_reference_predecessor_immutable", v3_reference["status"] == "PASS", predecessor=v3_reference)
    v4_reference = verify_v4_reference_predecessor()
    record("v4_reference_predecessor_immutable", v4_reference["status"] == "PASS", predecessor=v4_reference)
    v5_reference = verify_v5_reference_predecessor()
    record("v5_reference_predecessor_immutable", v5_reference["status"] == "PASS", predecessor=v5_reference)
    v6_reference = verify_v6_reference_predecessor()
    record("v6_reference_predecessor_immutable", v6_reference["status"] == "PASS", predecessor=v6_reference)
    v7_reference = verify_v7_reference_predecessor()
    record("v7_reference_predecessor_immutable", v7_reference["status"] == "PASS", predecessor=v7_reference)
    v8_reference = verify_v8_reference_predecessor()
    record("v8_reference_predecessor_immutable", v8_reference["status"] == "PASS", predecessor=v8_reference)
    v9_reference = verify_v9_reference_predecessor()
    record("v9_reference_predecessor_immutable", v9_reference["status"] == "PASS", predecessor=v9_reference)
    v10_reference = verify_v10_reference_predecessor()
    record("v10_reference_predecessor_immutable", v10_reference["status"] == "PASS", predecessor=v10_reference)
    v11_reference = verify_v11_reference_predecessor()
    record("v11_reference_predecessor_immutable", v11_reference["status"] == "PASS", predecessor=v11_reference)
    v12_reference = verify_v12_reference_predecessor()
    record("v12_reference_predecessor_immutable", v12_reference["status"] == "PASS", predecessor=v12_reference)
    v13_reference = verify_v13_reference_predecessor()
    record("v13_reference_predecessor_immutable", v13_reference["status"] == "PASS", predecessor=v13_reference)
    v14_reference = verify_v14_reference_predecessor()
    record("v14_reference_predecessor_immutable", v14_reference["status"] == "PASS", predecessor=v14_reference)
    v15_reference = verify_v15_reference_predecessor()
    record("v15_reference_predecessor_immutable", v15_reference["status"] == "PASS", predecessor=v15_reference)
    v16_reference = verify_v16_reference_predecessor()
    record("v16_reference_predecessor_immutable", v16_reference["status"] == "PASS", predecessor=v16_reference)
    v17_reference = verify_v17_reference_predecessor()
    record("v17_reference_predecessor_immutable", v17_reference["status"] == "PASS", predecessor=v17_reference)
    v18_reference = verify_v18_reference_predecessor()
    record("v18_reference_predecessor_immutable", v18_reference["status"] == "PASS", predecessor=v18_reference)
    v19_reference = verify_v19_reference_predecessor()
    record("v19_terminal_history_immutable", v19_reference["status"] == "PASS", predecessor=v19_reference)
    v20_reference = verify_v20_reference_predecessor()
    record("v20_terminal_history_immutable", v20_reference["status"] == "PASS", predecessor=v20_reference)
    v24_reference = verify_v24_reference_predecessor()
    record("v24_terminal_history_immutable", v24_reference["status"] == "PASS", predecessor=v24_reference)
    v25_reference = verify_v25_reference_predecessor()
    record("v25_terminal_history_immutable", v25_reference["status"] == "PASS", predecessor=v25_reference)
    v26_reference = verify_v26_reference_predecessor()
    record("v26_terminal_history_immutable", v26_reference["status"] == "PASS", predecessor=v26_reference)
    symbol_binding = static_symbol_binding_precheck()
    record("complete_pre_attempt_symbol_binding", symbol_binding["status"] == "PASS", precheck=symbol_binding)
    v16_canonicalization = v16_tree_canonicalization_precheck()
    record(
        "normative_v16_tree_component_tuple_canonicalization",
        v16_canonicalization["status"] == "PASS",
        precheck=v16_canonicalization,
    )
    workspace_boundary = workspace_write_boundary_precheck()
    record(
        "fail_before_write_workspace_identity_boundary",
        workspace_boundary["status"] == "PASS",
        precheck=workspace_boundary,
    )
    host_output_lifecycle = host_output_bind_source_precheck("FRESH_PREFLIGHT", require_current_empty=not require_static_lock)
    record(
        "host_output_bind_source_lifecycle_and_provenance",
        host_output_lifecycle.get("status") == "PASS",
        precheck=host_output_lifecycle,
    )
    typed_runtime_authority = typed_runtime_acceptance_precheck("FRESH_PREFLIGHT")
    record(
        "typed_current_codex_runtime_acceptance_authority",
        typed_runtime_authority.get("status") == "PASS",
        precheck=typed_runtime_authority,
    )
    cache_policy = python_cache_policy_precheck()
    record(
        "python_cache_and_runtime_side_effect_policy",
        cache_policy["status"] == "PASS",
        precheck=cache_policy,
    )
    lifecycle = semantic_lifecycle_anchor_verdict(
        (WORKSPACE / "src/runner_v35.py").read_text(encoding="utf-8")
    )
    record("semantic_lifecycle_A_lt_B_lt_C_lt_D_lt_E", lifecycle["status"] == "PASS", lifecycle=lifecycle)
    plan = validate_execution_plan(bwrap_argv())
    record("semantic_execution_plan", plan["status"] == "PASS", plan=plan)
    v5_feasibility = bind_destination_feasibility_precheck(bwrap_argv())
    record("bind_destination_feasibility_precheck", v5_feasibility["status"] == "PASS", feasibility=v5_feasibility)
    v2_regression = bind_destination_feasibility_precheck(v2_locked_bwrap_argv())
    record(
        "v2_ero_fs_topology_rejected_before_attempt",
        v2_regression["status"] == "FAIL_CLOSED"
        and any(item.get("reason") == "DESTINATION_ABSENT_UNDER_NON_WRITABLE_TOPOLOGY" for item in v2_regression.get("failures", [])),
        regression=v2_regression,
    )
    strict_schema = strict_schema_compatibility_precheck()
    record("strict_schema_compatibility_precheck", strict_schema["status"] == "PASS", precheck=strict_schema)
    typed_fd = typed_fd_annotation_grammar_precheck()
    record("typed_fd_annotation_grammar_precheck", typed_fd["status"] == "PASS", precheck=typed_fd)
    lineage_policy = startup_lineage_policy_precheck()
    record("semantic_startup_lineage_policy_precheck", lineage_policy["status"] == "PASS", precheck=lineage_policy)
    process_identity = process_identity_correlation_precheck()
    record("cross_namespace_process_identity_precheck", process_identity["status"] == "PASS", precheck=process_identity)
    temporal_observer = temporal_process_identity_observer_precheck()
    record("temporal_process_identity_observer_precheck", temporal_observer["status"] == "PASS", precheck=temporal_observer)
    mount_identity = mount_output_binding_precheck("FRESH_PREFLIGHT")
    record("governance_bound_mount_output_identity", mount_identity["status"] == "PASS", precheck=mount_identity)
    stale_mounts = stale_mount_literal_precheck()
    record("zero_stale_successor_mount_bindings", stale_mounts["status"] == "PASS", precheck=stale_mounts)
    typed_requirements = typed_preflight_requirement_precheck("FRESH_PREFLIGHT")
    record("typed_semantic_preflight_requirement_registry", typed_requirements["status"] == "PASS", precheck=typed_requirements)
    mount_policy = mount_provenance_policy_precheck("FRESH_PREFLIGHT")
    record("mount_provenance_write_policy_precheck", mount_policy["status"] == "PASS", precheck=mount_policy)
    token_budget = token_budget_feasibility_precheck()
    record("typed_token_budget_feasibility_precheck", token_budget["status"] == "PASS", precheck=token_budget)
    coverage_invariant = load_json(WORKSPACE / "contracts/COMPLETE_COVERAGE_INVARIANT.json")
    record(
        "v26_complete_temporal_identity_coverage_contract",
        typed_requirements.get("status") == "PASS"
        and coverage_invariant.get("percentage_thresholds") == "PROHIBITED"
        and coverage_invariant.get("n_minus_one") == "FAIL_CLOSED",
        typed_registry=typed_requirements,
        invariant=coverage_invariant,
    )
    request = load_json(WORKSPACE / "contracts/WORKER_REQUEST.json")
    record(
        "structured_request_bindings",
        request.get("campaign_id") == CAMPAIGN_ID
        and request.get("lane_id") == LANE_ID
        and request.get("worker_id") == WORKER_ID
        and request.get("runtime_identity") == RUNTIME_IDENTITY
        and request.get("authorization_id") == AUTHORIZATION_ID
        and request.get("requested_operations") == [],
    )
    counters = load_json(WORKSPACE / "contracts/OPERATION_COUNTERS.json").get("operation_counters", {})
    record("operation_counters_exact_zero", set(counters) == set(OPERATION_KEYS) and all(value == 0 for value in counters.values()))
    human = load_json(WORKSPACE / "HUMAN_GATE.json")
    record(
        "human_gate",
        human.get("decision") == "AUTHORIZE_EXACTLY_ONE_FIRST_REAL_SECURITY_WORKER_INVOCATION_V35_IF_ALL_PRE_ATTEMPT_GATES_PASS"
        and human.get("worker_invocation_limit") == 1
        and human.get("target_access_authorized") is False,
    )
    cache_paths = sorted(
        str(path.relative_to(WORKSPACE))
        for pattern in ("__pycache__", "*.pyc")
        for path in WORKSPACE.rglob(pattern)
    )
    record("python_cache_absent", not cache_paths, paths=cache_paths)
    record("fixture_has_no_target", load_json(FIXTURE_PATH).get("target") is None)
    record("no_daybreak_identity", "daybreak" not in MODEL_IDENTITY.lower())
    if require_static_lock:
        lock_path = WORKSPACE / "STATIC_EXECUTION_LOCK.json"
        verification_path = WORKSPACE / "STATIC_EXECUTION_LOCK_VERIFICATION.json"
        record("static_lock_present", safe_regular_file(lock_path))
        record("lock_verification_present", safe_regular_file(verification_path))
        closure = dependency_closure_snapshot()
        record("dependency_closure_complete", closure["status"] == "PASS", closure=closure)
        if safe_regular_file(lock_path):
            lock = load_json(lock_path)
            record("lock_state", lock.get("status") == "STATIC_LOCKED_NOT_EXECUTED")
            record("lock_argv", lock.get("strace_argv_sha256") == canonical_json_sha256(strace_argv()))
            record("lock_environment", lock.get("environment_sha256") == canonical_json_sha256(exact_environment()))
            record(
                "lock_strict_schema_precheck",
                lock.get("strict_schema_compatibility_precheck_sha256")
                == canonical_json_sha256(strict_schema_compatibility_precheck()),
            )
            record(
                "lock_process_identity_precheck",
                lock.get("cross_namespace_process_identity_precheck_sha256")
                == canonical_json_sha256(process_identity_correlation_precheck()),
            )
            record(
                "lock_temporal_observer_precheck",
                lock.get("temporal_process_identity_observer_precheck_sha256")
                == canonical_json_sha256(temporal_process_identity_observer_precheck()),
            )
            record(
                "lock_temporal_observer_argv",
                lock.get("temporal_observer_argv_sha256")
                == canonical_json_sha256(temporal_observer_argv()),
            )
            record(
                "lock_startup_lineage_precheck",
                lock.get("semantic_startup_lineage_precheck_sha256")
                == canonical_json_sha256(startup_lineage_policy_precheck()),
            )
            record(
                "lock_mount_provenance_precheck",
                lock.get("mount_provenance_write_precheck_sha256")
                == canonical_json_sha256(mount_provenance_policy_precheck("LOCKED_RUNTIME")),
            )
            record(
                "lock_mount_output_identity_precheck",
                lock.get("mount_output_identity_precheck_sha256")
                == canonical_json_sha256(mount_output_binding_precheck("LOCKED_RUNTIME")),
            )
            record(
                "lock_typed_preflight_requirement_precheck",
                lock.get("typed_preflight_requirement_precheck_sha256")
                == canonical_json_sha256(typed_preflight_requirement_precheck("LOCKED_RUNTIME")),
            )
            record(
                "lock_derived_current_expected_digest_view_precheck",
                lock.get("derived_current_expected_digest_view_precheck_sha256")
                == canonical_json_sha256(derived_current_expected_digest_view_precheck()),
            )
            record(
                "lock_host_output_bind_source_lifecycle_precheck",
                lock.get("host_output_bind_source_lifecycle_precheck_sha256")
                == canonical_json_sha256(host_output_bind_source_precheck("STATIC_LOCK_PREPARATION")),
            )
            record(
                "lock_typed_runtime_acceptance_precheck",
                lock.get("typed_runtime_acceptance_precheck_sha256")
                == canonical_json_sha256(typed_runtime_acceptance_precheck("STATIC_LOCK_PREPARATION")),
            )
            record(
                "lock_token_budget_precheck",
                lock.get("typed_token_budget_precheck_sha256")
                == canonical_json_sha256(token_budget_feasibility_precheck()),
            )
            record(
                "lock_prompt_identity_precheck",
                lock.get("prompt_identity_binding_precheck_sha256")
                == canonical_json_sha256(prompt_identity_binding_precheck()),
            )
            record(
                "lock_canonical_predecessor_binding",
                lock.get("canonical_predecessor_binding_precheck_sha256")
                == canonical_json_sha256(canonical_predecessor_binding_precheck("STATIC_LOCK_PREPARATION")),
            )
            record(
                "lock_external_predecessor_artifact_binding",
                lock.get("external_predecessor_artifact_precheck_sha256")
                == canonical_json_sha256(external_predecessor_artifact_precheck("STATIC_LOCK_PREPARATION")),
            )
            record(
                "lock_authoritative_predecessor_precheck",
                lock.get("authoritative_predecessor_resolution_precheck_sha256")
                == canonical_json_sha256(authoritative_predecessor_resolution_precheck()),
            )
            record(
                "lock_authoritative_artifact_digest_precheck",
                lock.get("authoritative_artifact_digest_precheck_sha256")
                == canonical_json_sha256(authoritative_artifact_digest_precheck()),
            )
            record(
                "lock_semantic_lifecycle_anchors",
                lock.get("semantic_lifecycle_anchor_sha256")
                == canonical_json_sha256(semantic_lifecycle_anchor_verdict(
                    (WORKSPACE / "src/runner_v35.py").read_text(encoding="utf-8")
                )),
            )
    failures = [name for name, result in checks.items() if result["status"] == "FAIL"]
    return {
        "record_type": "FIRST_REAL_SECURITY_WORKER_INVOCATION_FRESH_PREFLIGHT",
        "execution_identity": EXECUTION_IDENTITY,
        "status": "PASS" if not failures else "FAIL_CLOSED_BEFORE_ATTEMPT",
        "checks": checks,
        "failure_ids": failures,
        "validation_counts": {
            "total": len(checks),
            "passed": len(checks) - len(failures),
            "failed": len(failures),
        },
        "attempt_count": 0,
        "worker_invocation_count": 0,
        "codex_as_worker_invocation_count": 0,
    }
