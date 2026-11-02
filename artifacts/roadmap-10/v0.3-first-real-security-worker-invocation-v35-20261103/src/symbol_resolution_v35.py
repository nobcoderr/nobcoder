"""AST/import-graph and typed module binding proof for the locked V35 entrypoint."""

from __future__ import annotations

import ast
import builtins
import hashlib
import importlib
import inspect
import json
from pathlib import Path
from typing import Any, Mapping

from module_resolution_v35 import RUNTIME_IDENTITY, binding_rows


WORKSPACE = Path("/home/nobcoder/v0.3-first-real-security-worker-invocation-v35-20261103")
RUNNER = WORKSPACE / "src/runner_v35.py"
MANIFEST = WORKSPACE / "contracts/LOCKED_ENTRYPOINT_SYMBOL_BINDING_MANIFEST.json"
STATIC_MANIFEST = WORKSPACE / "STATIC_SOURCE_MANIFEST.json"
TARGET_SYMBOL = "v16_tree_canonicalization_precheck"


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def binding_fixture_verdict(
    source: str,
    *,
    available_modules: set[str],
    static_lock_members: set[str],
) -> dict[str, Any]:
    """Small deterministic oracle for import/binding regression fixtures."""
    try:
        tree = ast.parse(source)
    except SyntaxError as exc:
        return {"status": "FAIL_CLOSED", "reason": f"AST_INVALID:{exc}"}
    imports = []
    calls = []
    assignments = []
    dynamic = False
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            for alias in node.names:
                imports.append((node.module, alias.name, alias.asname or alias.name))
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == TARGET_SYMBOL:
            calls.append(node.lineno)
        elif isinstance(node, (ast.Assign, ast.AnnAssign, ast.NamedExpr)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            assignments.extend(target.id for target in targets if isinstance(target, ast.Name) and target.id == TARGET_SYMBOL)
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in {"__import__", "eval", "exec"}:
            dynamic = True
    exact = [row for row in imports if row == ("invocation_v35", TARGET_SYMBOL, TARGET_SYMBOL)]
    checks = {
        "exact_single_import": len(exact) == 1,
        "exact_single_call": len(calls) == 1,
        "module_available": "invocation_v35" in available_modules,
        "defining_artifact_locked": "src/invocation_v35.py" in static_lock_members,
        "not_shadowed": not assignments,
        "no_dynamic_fallback": not dynamic,
        "unambiguous": len(imports) == 1,
    }
    return {"status": "PASS" if all(checks.values()) else "FAIL_CLOSED", "checks": checks}


def _module_source(module_name: str) -> Path | None:
    module = importlib.import_module(module_name)
    raw = getattr(module, "__file__", None)
    if not raw:
        return None
    path = Path(raw)
    if path.suffix == ".pyc" and path.with_suffix(".py").is_file():
        path = path.with_suffix(".py")
    return path.resolve(strict=True) if path.is_file() else None


def _import_bindings(tree: ast.Module) -> dict[str, list[dict[str, Any]]]:
    result: dict[str, list[dict[str, Any]]] = {}
    for node in tree.body:
        if isinstance(node, ast.ImportFrom):
            module = node.module or ""
            for alias in node.names:
                bound = alias.asname or alias.name
                result.setdefault(bound, []).append(
                    {
                        "mechanism": "FROM_IMPORT",
                        "defining_module": module,
                        "imported_name": alias.name,
                        "expected_alias": bound,
                        "line": node.lineno,
                    }
                )
        elif isinstance(node, ast.Import):
            for alias in node.names:
                bound = alias.asname or alias.name.split(".")[0]
                result.setdefault(bound, []).append(
                    {
                        "mechanism": "IMPORT_MODULE",
                        "defining_module": alias.name,
                        "imported_name": alias.name,
                        "expected_alias": bound,
                        "line": node.lineno,
                    }
                )
    return result


def _top_level_definitions(tree: ast.Module) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            result[node.name] = {
                "mechanism": "LOCAL_DEFINITION",
                "defining_module": "runner_v35",
                "imported_name": node.name,
                "expected_alias": node.name,
                "line": node.lineno,
            }
        elif isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for target in targets:
                if isinstance(target, ast.Name):
                    result[target.id] = {
                        "mechanism": "MODULE_ASSIGNMENT",
                        "defining_module": "runner_v35",
                        "imported_name": target.id,
                        "expected_alias": target.id,
                        "line": node.lineno,
                    }
    return result


def _attempt_marker_line(main_node: ast.FunctionDef) -> int:
    hits = []
    for node in ast.walk(main_node):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Name) or node.func.id != "append_only_json" or not node.args:
            continue
        operand = node.args[0]
        if (
            isinstance(operand, ast.BinOp)
            and isinstance(operand.op, ast.Div)
            and isinstance(operand.left, ast.Name)
            and operand.left.id == "STATIC_RUN"
            and isinstance(operand.right, ast.Constant)
            and operand.right.value == "ATTEMPT_MARKER.json"
        ):
            hits.append(node.lineno)
    if len(hits) != 1:
        raise ValueError(f"authoritative attempt marker anchor count is {len(hits)}")
    return hits[0]


def _reachable_names(tree: ast.Module) -> tuple[dict[str, list[int]], int]:
    functions = {node.name: node for node in tree.body if isinstance(node, ast.FunctionDef)}
    main_node = functions.get("main")
    if main_node is None:
        raise ValueError("runner main function absent")
    cutoff = _attempt_marker_line(main_node)
    names: dict[str, set[int]] = {}
    queued = ["main"]
    visited: set[str] = set()
    while queued:
        name = queued.pop(0)
        if name in visited:
            continue
        visited.add(name)
        function = functions[name]
        local_names = {
            arg.arg
            for arg in (
                list(function.args.posonlyargs)
                + list(function.args.args)
                + list(function.args.kwonlyargs)
            )
        }
        if function.args.vararg:
            local_names.add(function.args.vararg.arg)
        if function.args.kwarg:
            local_names.add(function.args.kwarg.arg)
        local_names.update(
            node.id
            for node in ast.walk(function)
            if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del))
        )
        local_names.update(
            node.name
            for node in ast.walk(function)
            if isinstance(node, ast.ExceptHandler) and isinstance(node.name, str)
        )
        for node in ast.walk(function):
            if name == "main" and getattr(node, "lineno", 0) >= cutoff:
                continue
            if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load) and node.id not in local_names:
                names.setdefault(node.id, set()).add(node.lineno)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in functions:
                queued.append(node.func.id)
    return {name: sorted(lines) for name, lines in names.items()}, cutoff


def build_symbol_manifest(runtime_globals: Mapping[str, Any] | None = None) -> dict[str, Any]:
    tree = ast.parse(RUNNER.read_text(encoding="utf-8"), filename=str(RUNNER))
    imports = _import_bindings(tree)
    locals_ = _top_level_definitions(tree)
    reachable, cutoff = _reachable_names(tree)
    rows = []
    failures = []
    runtime = dict(runtime_globals or {})
    modules = binding_rows()
    for name in sorted(reachable, key=lambda value: value.encode("utf-8")):
        candidates = imports.get(name, []) + ([locals_[name]] if name in locals_ else [])
        if name in vars(builtins) and not candidates:
            candidates = [{"mechanism": "PYTHON_BUILTIN", "defining_module": "builtins", "imported_name": name, "expected_alias": name, "line": None}]
        if len(candidates) != 1:
            failures.append({"symbol": name, "reason": "MISSING_OR_AMBIGUOUS_STATIC_BINDING", "candidate_count": len(candidates)})
            continue
        binding = dict(candidates[0])
        module_name = binding["defining_module"]
        module_row = modules.get(module_name)
        if module_row is None:
            failures.append({"symbol": name, "reason": "TYPED_CANONICAL_MODULE_BINDING_MISSING", "module": module_name})
            continue
        raw_source = module_row.get("canonical_source_path")
        source = Path(raw_source) if isinstance(raw_source, str) else None
        source_identity = (
            source.relative_to(WORKSPACE).as_posix()
            if source is not None and source.is_relative_to(WORKSPACE)
            else (str(source) if source is not None else f"PYTHON_RUNTIME::{module_row['module_class']}")
        )
        dependency_class = (
            "CURRENT_WORKSPACE_STATIC_LOCK_MEMBER"
            if module_row["module_class"] in {"LOCAL_SOURCE_MODULE", "LOCAL_PROJECT_MODULE"}
            else "PINNED_PYTHON_RUNTIME_DEPENDENCY"
        )
        expected_export = "__MODULE_OBJECT__" if binding["mechanism"] == "IMPORT_MODULE" else binding["imported_name"]
        if expected_export != "__MODULE_OBJECT__" and expected_export not in module_row.get("expected_exported_symbol_identities", []):
            failures.append({"symbol": name, "reason": "EXPECTED_EXPORTED_SYMBOL_NOT_BOUND", "module": module_name})
        resolved = None
        if runtime_globals is not None:
            resolved = (name in runtime and runtime[name] is not None) or name in vars(builtins)
            if not resolved:
                failures.append({"symbol": name, "reason": "LOCKED_RUNTIME_SYMBOL_UNRESOLVED"})
        rows.append(
            {
                "symbol": name,
                "defining_module": module_name,
                "expected_import_or_binding": binding["mechanism"],
                "expected_imported_name": binding["imported_name"],
                "expected_alias": binding["expected_alias"],
                "binding_line": binding["line"],
                "logical_module_identity": module_row["logical_module_identity"],
                "module_class": module_row["module_class"],
                "expected_module_origin": module_row["expected_module_origin"],
                "expected_loader_identity": module_row["expected_loader_identity"],
                "pinned_runtime_identity": module_row["pinned_runtime_identity"],
                "expected_exported_symbol_identity": expected_export,
                "defining_source_artifact": source_identity,
                "defining_source_sha256": sha256_file(source) if source is not None else None,
                "call_or_reference_sites": reachable[name],
                "dependency_closure_membership": dependency_class,
                "static_lock_membership": "REQUIRED" if dependency_class == "CURRENT_WORKSPACE_STATIC_LOCK_MEMBER" else "PINNED_RUNTIME_IDENTITY",
                "locked_runtime_resolution": "PASS" if resolved is True else ("NOT_YET_EXECUTED" if resolved is None else "FAIL"),
                "callable": bool(callable(runtime.get(name))) if runtime_globals is not None else None,
            }
        )
    target_rows = [row for row in rows if row["symbol"] == TARGET_SYMBOL]
    if len(target_rows) != 1 or target_rows[0]["defining_module"] != "invocation_v35" or target_rows[0]["expected_alias"] != TARGET_SYMBOL:
        failures.append({"symbol": TARGET_SYMBOL, "reason": "TARGET_BINDING_NOT_EXACT"})
    return {
        "record_type": "V35_LOCKED_ENTRYPOINT_SYMBOL_BINDING_MANIFEST",
        "execution_identity": "V0_3_FIRST_REAL_SECURITY_WORKER_INVOCATION_V35",
        "runner": "src/runner_v35.py",
        "runner_sha256": sha256_file(RUNNER),
        "pre_attempt_cutoff_line": cutoff,
        "symbol_count": len(rows),
        "symbols": rows,
        "failure_count": len(failures),
        "failures": failures,
        "status": "PASS" if not failures else "FAIL_CLOSED",
    }


def symbol_resolution_precheck(runtime_globals: Mapping[str, Any], require_static_lock: bool) -> dict[str, Any]:
    if not MANIFEST.is_file():
        return {"status": "FAIL_CLOSED", "reason": "SYMBOL_BINDING_MANIFEST_MISSING"}
    expected = json.loads(MANIFEST.read_text(encoding="utf-8"))
    actual = build_symbol_manifest(runtime_globals)
    failures = list(actual.get("failures", []))
    expected_rows = {row["symbol"]: row for row in expected.get("symbols", [])}
    actual_rows = {row["symbol"]: row for row in actual.get("symbols", [])}
    if set(expected_rows) != set(actual_rows):
        failures.append({"reason": "SYMBOL_SET_DRIFT"})
    for symbol in sorted(set(expected_rows) & set(actual_rows)):
        for field in (
            "defining_module",
            "expected_import_or_binding",
            "expected_imported_name",
            "expected_alias",
            "defining_source_artifact",
            "defining_source_sha256",
            "logical_module_identity",
            "module_class",
            "expected_module_origin",
            "expected_loader_identity",
            "pinned_runtime_identity",
            "expected_exported_symbol_identity",
            "call_or_reference_sites",
            "dependency_closure_membership",
            "static_lock_membership",
        ):
            if expected_rows[symbol].get(field) != actual_rows[symbol].get(field):
                failures.append({"symbol": symbol, "reason": f"BINDING_DRIFT:{field}"})
    lock_members = set()
    if require_static_lock:
        if not STATIC_MANIFEST.is_file():
            failures.append({"reason": "STATIC_SOURCE_MANIFEST_MISSING"})
        else:
            lock_members = {row.get("path") for row in json.loads(STATIC_MANIFEST.read_text(encoding="utf-8")).get("members", [])}
            for row in actual_rows.values():
                if row["dependency_closure_membership"] == "CURRENT_WORKSPACE_STATIC_LOCK_MEMBER" and row["defining_source_artifact"] not in lock_members:
                    failures.append({"symbol": row["symbol"], "reason": "DEFINING_ARTIFACT_OMITTED_FROM_STATIC_LOCK"})
    target = actual_rows.get(TARGET_SYMBOL, {})
    target_callable = callable(runtime_globals.get(TARGET_SYMBOL))
    if not target_callable:
        failures.append({"symbol": TARGET_SYMBOL, "reason": "TARGET_NOT_CALLABLE_IN_LOCKED_RUNTIME"})
    return {
        "record_type": "V35_LOCKED_RUNTIME_SYMBOL_RESOLUTION_PRECHECK",
        "execution_identity": "V0_3_FIRST_REAL_SECURITY_WORKER_INVOCATION_V35",
        "require_static_lock": require_static_lock,
        "symbol_count": len(actual_rows),
        "runtime_resolved_count": sum(1 for row in actual_rows.values() if row.get("locked_runtime_resolution") == "PASS"),
        "static_lock_member_count": len(lock_members) if require_static_lock else None,
        "target_symbol": TARGET_SYMBOL,
        "target_runtime_callable": target_callable,
        "target_defining_module": target.get("defining_module"),
        "failures": failures,
        "status": "PASS" if not failures else "FAIL_CLOSED",
    }


def static_symbol_binding_precheck() -> dict[str, Any]:
    if not MANIFEST.is_file():
        return {"status": "FAIL_CLOSED", "reason": "SYMBOL_BINDING_MANIFEST_MISSING"}
    expected = json.loads(MANIFEST.read_text(encoding="utf-8"))
    actual = build_symbol_manifest()
    comparable_fields = (
        "symbol",
        "defining_module",
        "expected_import_or_binding",
        "expected_imported_name",
        "expected_alias",
        "binding_line",
        "defining_source_artifact",
        "defining_source_sha256",
        "logical_module_identity",
        "module_class",
        "expected_module_origin",
        "expected_loader_identity",
        "pinned_runtime_identity",
        "expected_exported_symbol_identity",
        "call_or_reference_sites",
        "dependency_closure_membership",
        "static_lock_membership",
    )
    expected_rows = [{field: row.get(field) for field in comparable_fields} for row in expected.get("symbols", [])]
    actual_rows = [{field: row.get(field) for field in comparable_fields} for row in actual.get("symbols", [])]
    checks = {
        "expected_manifest_pass": expected.get("status") == "PASS" and expected.get("failure_count") == 0,
        "current_static_analysis_pass": actual.get("status") == "PASS" and actual.get("failure_count") == 0,
        "runner_digest_exact": expected.get("runner_sha256") == actual.get("runner_sha256") == sha256_file(RUNNER),
        "symbol_set_and_bindings_exact": expected_rows == actual_rows,
        "target_present_exactly_once": sum(1 for row in actual_rows if row.get("symbol") == TARGET_SYMBOL) == 1,
    }
    return {
        "record_type": "V35_STATIC_SYMBOL_BINDING_PRECHECK",
        "checks": checks,
        "symbol_count": len(actual_rows),
        "status": "PASS" if all(checks.values()) else "FAIL_CLOSED",
    }
