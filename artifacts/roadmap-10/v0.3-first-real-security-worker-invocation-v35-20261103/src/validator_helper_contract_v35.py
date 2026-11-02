"""Typed return and control-flow contract for V35 critical validator helpers."""

from __future__ import annotations

import ast
import hashlib
import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any


WORKSPACE = Path("/home/nobcoder/v0.3-first-real-security-worker-invocation-v35-20261103")
CONTRACT = WORKSPACE / "contracts/SUCCESSOR_V35_TYPED_VALIDATOR_HELPER_RETURN_CONTRACT.json"
REGRESSION_MATRIX = WORKSPACE / "contracts/V35_TYPED_VALIDATOR_HELPER_RETURN_REGRESSION_MATRIX.json"
INVOCATION_SOURCE = WORKSPACE / "src/invocation_v35.py"
PRIMARY_SOURCE = WORKSPACE / "validators/primary_static_validate.py"
PREFLIGHT_SOURCE = WORKSPACE / "preflight.py"
RUNNER_SOURCE = WORKSPACE / "src/runner_v35.py"
LOCK_PREPARATION_SOURCE = WORKSPACE / "prepare_static_lock.py"
LOCK_VERIFICATION_SOURCE = WORKSPACE / "verify_static_lock.py"
LOCKED_CONTROLS_SOURCE = WORKSPACE / "validate_locked_controls.py"
GOVERNANCE_LOCK_SHA256 = "d2263268f61b9ddde99a0b60f4b43a26df1586e0c577ba2ca98c07b64c21f811"
NORMATIVE_CONTRACT_SHA256 = "b42fc2678dd0213b4f0bc638b1a77a2d9079b289e53277d3dec2e374801cefaa"

# The frozen defect and successor contract identify this helper as the critical
# verdict producer. Its three execution-readiness consumers are explicit so a
# static PASS cannot be obtained from a helper that the actual paths do not use.
CRITICAL_HELPER_INVENTORY = (
    {
        "logical_helper_identity": "V35_CRITICAL_HELPER::inspect_runtime_identity",
        "function_name": "inspect_runtime_identity",
        "defining_source": str(INVOCATION_SOURCE),
        "required_record_type": "V35_RUNTIME_IDENTITY_VERDICT",
        "call_sites": (
            str(INVOCATION_SOURCE),
            str(PRIMARY_SOURCE),
            str(PREFLIGHT_SOURCE),
            str(LOCK_PREPARATION_SOURCE),
            str(LOCK_VERIFICATION_SOURCE),
            str(LOCKED_CONTROLS_SOURCE),
            str(RUNNER_SOURCE),
        ),
    },
)


class TypedValidatorVerdictError(RuntimeError):
    """Raised before any verdict field is consumed."""


def require_typed_verdict(value: object, helper_identity: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise TypedValidatorVerdictError(f"{helper_identity}:VERDICT_OBJECT_REQUIRED")
    result = dict(value)
    if not isinstance(result.get("record_type"), str) or not result["record_type"]:
        raise TypedValidatorVerdictError(f"{helper_identity}:RECORD_TYPE_REQUIRED")
    if not isinstance(result.get("status"), str) or not result["status"]:
        raise TypedValidatorVerdictError(f"{helper_identity}:STATUS_REQUIRED")
    checks = result.get("checks")
    if not isinstance(checks, Mapping) or not checks:
        raise TypedValidatorVerdictError(f"{helper_identity}:NONEMPTY_CHECKS_MAPPING_REQUIRED")
    if not all(isinstance(key, str) and isinstance(item, bool) for key, item in checks.items()):
        raise TypedValidatorVerdictError(f"{helper_identity}:BOOLEAN_CHECK_ROWS_REQUIRED")
    return result


def _direct_returns(function: ast.FunctionDef | ast.AsyncFunctionDef) -> list[ast.Return]:
    rows: list[ast.Return] = []

    class ReturnVisitor(ast.NodeVisitor):
        def visit_Return(self, node: ast.Return) -> None:  # noqa: N802
            rows.append(node)

        def visit_FunctionDef(self, node: ast.FunctionDef) -> None:  # noqa: N802
            if node is function:
                self.generic_visit(node)

        def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:  # noqa: N802
            if node is function:
                self.generic_visit(node)

        def visit_Lambda(self, node: ast.Lambda) -> None:  # noqa: N802
            return

    ReturnVisitor().visit(function)
    return rows


def _statement_terminates(statement: ast.stmt) -> bool:
    if isinstance(statement, (ast.Return, ast.Raise)):
        return True
    if isinstance(statement, ast.If):
        return bool(statement.orelse) and _block_terminates(statement.body) and _block_terminates(statement.orelse)
    if isinstance(statement, ast.Match):
        has_catch_all = any(
            isinstance(case.pattern, ast.MatchAs) and case.pattern.name is None and case.guard is None
            for case in statement.cases
        )
        return has_catch_all and bool(statement.cases) and all(_block_terminates(case.body) for case in statement.cases)
    if isinstance(statement, ast.Try):
        if statement.finalbody and _block_terminates(statement.finalbody):
            return True
        return (
            _block_terminates(statement.body)
            and all(_block_terminates(handler.body) for handler in statement.handlers)
            and (not statement.orelse or _block_terminates(statement.orelse))
        )
    return False


def _block_terminates(statements: list[ast.stmt]) -> bool:
    for statement in statements:
        if _statement_terminates(statement):
            return True
    return False


def helper_source_verdict(source: str, function_name: str) -> dict[str, Any]:
    try:
        tree = ast.parse(source)
    except SyntaxError as exc:
        return {
            "record_type": "V35_VALIDATOR_HELPER_SOURCE_VERDICT",
            "status": "FAIL_CLOSED_BEFORE_STATIC_LOCK_AND_ATTEMPT",
            "checks": {"source_parses": False},
            "reason": f"SYNTAX_ERROR:{exc.msg}",
        }
    matches = [
        node for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == function_name
    ]
    function = matches[0] if len(matches) == 1 else None
    returns = _direct_returns(function) if function is not None else []
    reachable_return_lines: set[int] = set()
    if function is not None:
        for statement in function.body:
            if isinstance(statement, ast.Return):
                reachable_return_lines.add(statement.lineno)
            if _statement_terminates(statement):
                break
    reachable_returns = [node for node in returns if node.lineno in reachable_return_lines]
    typed_shapes = [
        isinstance(node.value, ast.Dict)
        and {key.value for key in node.value.keys if isinstance(key, ast.Constant) and isinstance(key.value, str)}
        >= {"record_type", "status", "checks"}
        for node in reachable_returns
    ]
    checks = {
        "source_parses": True,
        "one_top_level_helper": function is not None,
        "reachable_explicit_return_present": bool(reachable_returns),
        "no_unreachable_return": len(reachable_returns) == len(returns),
        "no_implicit_fallthrough": function is not None and _block_terminates(function.body),
        "return_belongs_to_intended_function": bool(reachable_returns),
        "typed_verdict_shape_statically_present": bool(typed_shapes) and all(typed_shapes),
    }
    return {
        "record_type": "V35_VALIDATOR_HELPER_SOURCE_VERDICT",
        "function_name": function_name,
        "status": "PASS" if all(checks.values()) else "FAIL_CLOSED_BEFORE_STATIC_LOCK_AND_ATTEMPT",
        "checks": checks,
        "direct_return_lines": [node.lineno for node in returns],
        "reachable_return_lines": sorted(reachable_return_lines),
    }


def caller_guard_verdict(source: str, helper_name: str) -> dict[str, Any]:
    try:
        tree = ast.parse(source)
    except SyntaxError:
        tree = ast.Module(body=[], type_ignores=[])
    parents: dict[ast.AST, ast.AST] = {}
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            parents[child] = parent
    guarded_calls: list[int] = []
    unguarded_calls: list[int] = []
    for node in ast.walk(tree):
        if not (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == helper_name
        ):
            continue
        ancestor = parents.get(node)
        guarded = False
        while ancestor is not None:
            if (
                isinstance(ancestor, ast.Call)
                and isinstance(ancestor.func, ast.Name)
                and ancestor.func.id == "require_typed_verdict"
            ):
                guarded = True
                guarded_calls.append(ancestor.lineno)
                break
            ancestor = parents.get(ancestor)
        if not guarded:
            unguarded_calls.append(node.lineno)
    checks = {
        "guarded_call_present": bool(guarded_calls),
        "no_direct_unguarded_helper_call": not unguarded_calls,
    }
    return {
        "record_type": "V35_VALIDATOR_HELPER_CALLER_GUARD_VERDICT",
        "status": "PASS" if all(checks.values()) else "FAIL_CLOSED_BEFORE_STATIC_LOCK_AND_ATTEMPT",
        "checks": checks,
        "guarded_call_lines": guarded_calls,
        "unguarded_call_lines": unguarded_calls,
    }


def critical_validator_helper_contract_precheck() -> dict[str, Any]:
    contract = json.loads(CONTRACT.read_text(encoding="utf-8"))
    matrix = json.loads(REGRESSION_MATRIX.read_text(encoding="utf-8"))
    helper_rows = []
    caller_rows = []
    for row in CRITICAL_HELPER_INVENTORY:
        helper_rows.append(
            helper_source_verdict(Path(row["defining_source"]).read_text(encoding="utf-8"), row["function_name"])
        )
        for call_site in row["call_sites"]:
            caller_rows.append(caller_guard_verdict(Path(call_site).read_text(encoding="utf-8"), row["function_name"]))
    checks = {
        "contract_identity": contract.get("contract_identity") == "V35_TYPED_CRITICAL_VALIDATOR_HELPER_RETURN_CONTRACT_V1",
        "contract_source_exact": hashlib.sha256(CONTRACT.read_bytes()).hexdigest() == NORMATIVE_CONTRACT_SHA256,
        "contract_authority": contract.get("authorizing_governance_lock") == "EXACT_SHA256_OF_THIS_PACKAGE_GOVERNANCE_LOCK_JSON"
        and GOVERNANCE_LOCK_SHA256 == "d2263268f61b9ddde99a0b60f4b43a26df1586e0c577ba2ca98c07b64c21f811",
        "inventory_explicit": contract.get("critical_helper_inventory") == "EXPLICIT_COMPLETE_INVENTORY_REQUIRED_BEFORE_UNIT_OR_STATIC_VALIDATION",
        "regression_matrix_complete": matrix.get("case_count") == 8 and len(matrix.get("cases", [])) == 8,
        "helper_control_flow_pass": bool(helper_rows) and all(row.get("status") == "PASS" for row in helper_rows),
        "caller_guards_pass": bool(caller_rows) and all(row.get("status") == "PASS" for row in caller_rows),
    }
    return {
        "record_type": "V35_CRITICAL_VALIDATOR_HELPER_RETURN_CONTRACT_PRECHECK",
        "status": "PASS" if all(checks.values()) else "FAIL_CLOSED_BEFORE_STATIC_LOCK_AND_ATTEMPT",
        "checks": checks,
        "critical_helper_inventory": list(CRITICAL_HELPER_INVENTORY),
        "helper_results": helper_rows,
        "caller_results": caller_rows,
    }
