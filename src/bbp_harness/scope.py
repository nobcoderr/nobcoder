from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .util import canonical_json, sha256_text


STANDING_AUTHORIZATION_SOURCE = "user_supplied_official_bug_bounty_scope"
STANDING_AUTHORIZATION_MODE = "standing_authorization"


SCOPE_TEMPLATE: dict[str, Any] = {
    "version": 1,
    "authorization": {
        "confirmed": True,
        "type": "bug_bounty_or_owned",
        "source": STANDING_AUTHORIZATION_SOURCE,
        "confirmation_mode": STANDING_AUTHORIZATION_MODE,
        "program": "",
    },
    "asset": {
        "type": "repository",
        "path": ".",
        "name": "",
        "in_scope": True,
        "production_or_release_mapping": "UNPROVEN",
    },
    "allowed_actions": {
        "source_review": True,
        "public_web_research": True,
        "local_build": False,
        "local_tests": False,
        "network": False,
        "browser": False,
        "state_changing_poc": False,
        "destructive": False,
    },
    "limits": {
        "max_concurrency": 3,
        "max_requests_per_second": 0,
        "time_budget_minutes": 240,
        "token_budget": None,
    },
    "exclusions": [],
    "stop_conditions": [
        "scope ambiguity",
        "unexpected third-party data",
        "destructive effect",
        "credential collection",
        "rate or budget breach",
    ],
    "researcher_owned_resources_only": True,
    "notes": (
        "Standing authorization requires no additional authorization confirmation; "
        "keep exact official program boundaries encoded in this scope card."
    ),
}


class ScopeError(ValueError):
    def __init__(self, reasons: list[str]):
        super().__init__("; ".join(reasons))
        self.reasons = reasons


def _has_standing_authorization(authorization: dict[str, Any]) -> bool:
    return (
        authorization.get("confirmation_mode") == STANDING_AUTHORIZATION_MODE
        and authorization.get("source") == STANDING_AUTHORIZATION_SOURCE
    )


def _authorization_is_confirmed(authorization: dict[str, Any]) -> bool:
    return authorization.get("confirmed") is True or _has_standing_authorization(authorization)


@dataclass(slots=True)
class ScopeCard:
    path: Path
    raw: dict[str, Any]
    digest: str
    program: str
    asset: str
    allowed_methods: list[str]
    exclusions: list[str]
    limits: dict[str, Any]
    stop_conditions: list[str]

    @property
    def network_allowed(self) -> bool:
        return bool(self.raw.get("allowed_actions", {}).get("network", False))

    @property
    def local_tests_allowed(self) -> bool:
        return bool(self.raw.get("allowed_actions", {}).get("local_tests", False))

    @property
    def source_review_allowed(self) -> bool:
        return bool(self.raw.get("allowed_actions", {}).get("source_review", False))

    @property
    def authorization_confirmed(self) -> bool:
        authorization = self.raw.get("authorization", {})
        return isinstance(authorization, dict) and _authorization_is_confirmed(authorization)

    def to_record(self) -> dict[str, Any]:
        return {
            "source_path": str(self.path),
            "scope_hash": self.digest,
            "authorization_confirmed": self.authorization_confirmed,
            "program": self.program,
            "asset": self.asset,
            "allowed_methods": self.allowed_methods,
            "exclusions": self.exclusions,
            "rate_limits": self.limits,
            "stop_conditions": self.stop_conditions,
            "raw": self.raw,
        }


def scope_path(target_root: Path) -> Path:
    return target_root / ".bbpresearch" / "scope.yaml"


def load_scope(target_root: Path, require_confirmed: bool = True) -> ScopeCard:
    path = scope_path(target_root)
    if not path.exists():
        raise ScopeError([f"missing scope file: {path}"])
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ScopeError(
            [
                f"scope file must use JSON-compatible YAML: {exc}",
                "run bbp-harness init again in a clean fixture or repair the file",
            ]
        ) from exc
    if not isinstance(raw, dict):
        raise ScopeError(["scope root must be an object"])
    reasons: list[str] = []
    authorization = raw.get("authorization")
    asset = raw.get("asset")
    actions = raw.get("allowed_actions")
    limits = raw.get("limits")
    if not isinstance(authorization, dict):
        reasons.append("authorization object is required")
        authorization = {}
    source = str(authorization.get("source", "")).strip()
    if not source or source.startswith("REPLACE_"):
        reasons.append("authorization.source must identify the policy or ownership evidence")
    confirmation_mode = str(authorization.get("confirmation_mode", "")).strip()
    if confirmation_mode and confirmation_mode != STANDING_AUTHORIZATION_MODE:
        reasons.append("authorization.confirmation_mode is not recognized")
    explicitly_confirmed = authorization.get("confirmed") is True
    if not explicitly_confirmed:
        if confirmation_mode == STANDING_AUTHORIZATION_MODE and source != STANDING_AUTHORIZATION_SOURCE:
            reasons.append(
                "standing authorization requires source=user_supplied_official_bug_bounty_scope"
            )
        if source == STANDING_AUTHORIZATION_SOURCE and confirmation_mode != STANDING_AUTHORIZATION_MODE:
            reasons.append(
                "user-supplied official scope source requires confirmation_mode=standing_authorization"
            )
    if require_confirmed and not _authorization_is_confirmed(authorization):
        reasons.append(
            "authorization is not confirmed and no valid standing authorization evidence is present"
        )
    if not isinstance(asset, dict):
        reasons.append("asset object is required")
        asset = {}
    if asset.get("in_scope") is not True:
        reasons.append("asset.in_scope must be true")
    declared = (target_root / str(asset.get("path", "."))).resolve()
    if declared != target_root.resolve():
        reasons.append(f"asset.path resolves to {declared}, expected target root {target_root.resolve()}")
    if not isinstance(actions, dict):
        reasons.append("allowed_actions object is required")
        actions = {}
    if actions.get("source_review") is not True:
        reasons.append("allowed_actions.source_review must be true")
    if actions.get("destructive") is True:
        reasons.append("destructive actions cannot be enabled by the harness")
    if not isinstance(limits, dict):
        reasons.append("limits object is required")
        limits = {}
    concurrency = limits.get("max_concurrency", 0)
    if not isinstance(concurrency, int) or not 1 <= concurrency <= 16:
        reasons.append("limits.max_concurrency must be an integer from 1 to 16")
    stop_conditions = raw.get("stop_conditions", [])
    if not isinstance(stop_conditions, list) or not stop_conditions:
        reasons.append("at least one stop condition is required")
        stop_conditions = []
    if raw.get("researcher_owned_resources_only") is not True:
        reasons.append("researcher_owned_resources_only must be true")
    if reasons:
        raise ScopeError(reasons)
    allowed_methods = sorted(key for key, value in actions.items() if value is True)
    return ScopeCard(
        path=path,
        raw=raw,
        digest=sha256_text(canonical_json(raw)),
        program=str(authorization.get("program", "")),
        asset=str(asset.get("name") or target_root.name),
        allowed_methods=allowed_methods,
        exclusions=[str(item) for item in raw.get("exclusions", [])],
        limits=limits,
        stop_conditions=[str(item) for item in stop_conditions],
    )
