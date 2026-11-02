#!/usr/bin/env python3
"""Build V35 typed canonical project/runtime module bindings exactly once."""
from __future__ import annotations

import ast
import builtins
import hashlib
import importlib.machinery
import importlib.util
import json
import sys
import sysconfig
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SRC = ROOT / "src"
RUNNER = SRC / "runner_v35.py"
OUT = ROOT / "contracts/CANONICAL_MODULE_BINDINGS.json"
GENERATION = "V35_CURRENT_GOVERNANCE_BOUND_TYPED_PREFLIGHT_BINDING_GENERATION_0001"
RUNTIME_IDENTITY = "V35_PINNED_CPYTHON_3_14_RUNTIME_0001"


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def loader_identity(loader: object | None) -> str | None:
    if loader is None:
        return None
    value = loader if isinstance(loader, type) else type(loader)
    return f"{value.__module__}.{value.__qualname__}"


def reachable_imports() -> tuple[dict[str, set[str]], set[str]]:
    tree = ast.parse(RUNNER.read_text(encoding="utf-8"), filename=str(RUNNER))
    functions = {node.name: node for node in tree.body if isinstance(node, ast.FunctionDef)}
    main = functions["main"]
    marker = []
    for node in ast.walk(main):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "append_only_json" and node.args:
            value = node.args[0]
            if isinstance(value, ast.BinOp) and isinstance(value.op, ast.Div) and isinstance(value.left, ast.Name) and value.left.id == "STATIC_RUN" and isinstance(value.right, ast.Constant) and value.right.value == "ATTEMPT_MARKER.json":
                marker.append(node.lineno)
    if len(marker) != 1:
        raise RuntimeError("authoritative attempt-marker anchor must be unique")
    reachable: set[str] = set()
    queue = ["main"]
    seen: set[str] = set()
    while queue:
        name = queue.pop(0)
        if name in seen:
            continue
        seen.add(name)
        function = functions[name]
        local = {arg.arg for arg in [*function.args.posonlyargs, *function.args.args, *function.args.kwonlyargs]}
        local.update(node.id for node in ast.walk(function) if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)))
        local.update(node.name for node in ast.walk(function) if isinstance(node, ast.ExceptHandler) and isinstance(node.name, str))
        for node in ast.walk(function):
            if name == "main" and getattr(node, "lineno", 0) >= marker[0]:
                continue
            if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load) and node.id not in local:
                reachable.add(node.id)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in functions:
                queue.append(node.func.id)
    imports: dict[str, tuple[str, str | None]] = {}
    for node in tree.body:
        if isinstance(node, ast.ImportFrom):
            for alias in node.names:
                imports[alias.asname or alias.name] = (node.module or "", alias.name)
        elif isinstance(node, ast.Import):
            for alias in node.names:
                imports[alias.asname or alias.name.split(".")[0]] = (alias.name, None)
    exports: dict[str, set[str]] = {}
    for symbol in reachable:
        if symbol in imports:
            module, imported = imports[symbol]
            exports.setdefault(module, set())
            if imported is not None:
                exports[module].add(imported)
    top_level: set[str] = set()
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            top_level.add(node.name)
        elif isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            top_level.update(target.id for target in targets if isinstance(target, ast.Name))
    local_exports = {name for name in reachable if name in top_level and name not in imports}
    if local_exports:
        exports["runner_v35"] = local_exports
    builtin_exports = {name for name in reachable if name in vars(builtins) and name not in imports and name not in top_level}
    return exports, builtin_exports


def runtime_spec(name: str) -> tuple[str, importlib.machinery.ModuleSpec]:
    spec = importlib.machinery.BuiltinImporter.find_spec(name)
    if spec is not None:
        return "BUILTIN_MODULE", spec
    spec = importlib.machinery.FrozenImporter.find_spec(name)
    if spec is not None:
        return "FROZEN_MODULE", spec
    stdlib = Path(sysconfig.get_path("stdlib")).resolve(strict=True)
    dynload = (stdlib / "lib-dynload").resolve(strict=True)
    spec = importlib.machinery.PathFinder.find_spec(name, [str(stdlib)])
    if spec is None:
        spec = importlib.machinery.PathFinder.find_spec(name, [str(dynload)])
    if spec is None or spec.origin is None:
        raise RuntimeError(f"canonical stdlib module unresolved: {name}")
    return ("EXTENSION_MODULE" if spec.origin.endswith(".so") else "PURE_PYTHON_STDLIB"), spec


def main() -> int:
    if OUT.exists():
        raise FileExistsError(f"append-only output exists: {OUT}")
    exports, builtin_exports = reachable_imports()
    local_names = sorted(path.stem for path in SRC.glob("*.py") if path.name != "__init__.py")
    rows = []
    for name in local_names:
        source = (SRC / f"{name}.py").resolve(strict=True)
        rows.append({
            "logical_module_identity": f"V35_LOCAL_SOURCE_MODULE::{name}",
            "module_class": "LOCAL_SOURCE_MODULE",
            "module_category": "LOCAL_SOURCE_MODULE",
            "generation_identity": GENERATION,
            "canonical_logical_module_name": name,
            "canonical_package_root": str(SRC),
            "canonical_source_path": str(source),
            "expected_import_name": name,
            "expected_module_origin": str(source),
            "expected_origin_semantics": "EXACT_LOCAL_PROJECT_SOURCE_PATH",
            "expected_loader_identity": "_frozen_importlib_external.SourceFileLoader",
            "expected_exported_symbol_identities": sorted(exports.get(name, set())),
            "exact_source_sha256": digest(source),
            "exact_size": source.stat().st_size,
            "pinned_runtime_identity": RUNTIME_IDENTITY,
            "runtime_identity": RUNTIME_IDENTITY,
            "dependency_manifest_membership": "REQUIRED",
            "symbol_manifest_membership": "REQUIRED" if name in exports else "NOT_REACHABLE_SYMBOL_OWNER",
            "static_lock_membership": "REQUIRED",
        })
    runtime_names = sorted(name for name in exports if name not in local_names)
    if builtin_exports:
        runtime_names.append("builtins")
        exports["builtins"] = builtin_exports
    for name in sorted(set(runtime_names)):
        module_class, spec = runtime_spec(name)
        source = Path(spec.origin).resolve(strict=True) if spec.origin not in {None, "built-in", "frozen"} else None
        rows.append({
            "logical_module_identity": f"PYTHON_3_14_RUNTIME_MODULE::{name}",
            "module_class": module_class,
            "module_category": module_class,
            "generation_identity": GENERATION,
            "canonical_logical_module_name": name,
            "canonical_package_root": None,
            "canonical_source_path": str(source) if source else None,
            "expected_import_name": name,
            "expected_module_origin": spec.origin,
            "expected_origin_semantics": {
                "PURE_PYTHON_STDLIB": "EXACT_PINNED_STDLIB_SOURCE_PATH",
                "EXTENSION_MODULE": "EXACT_PINNED_EXTENSION_BINARY_PATH",
                "BUILTIN_MODULE": "BUILT_IN_ORIGIN_NO_NORMAL_SOURCE",
                "FROZEN_MODULE": "FROZEN_ORIGIN_NO_NORMAL_SOURCE",
            }[module_class],
            "expected_loader_identity": loader_identity(spec.loader),
            "expected_exported_symbol_identities": sorted(exports.get(name, set())),
            "exact_source_sha256": digest(source) if source else None,
            "exact_size": source.stat().st_size if source else None,
            "pinned_runtime_identity": RUNTIME_IDENTITY,
            "runtime_identity": RUNTIME_IDENTITY,
            "dependency_manifest_membership": "REQUIRED",
            "symbol_manifest_membership": "REQUIRED",
            "static_lock_membership": "PINNED_RUNTIME_IDENTITY",
        })
    python = Path(sys.executable).resolve(strict=True)
    stdlib = Path(sysconfig.get_path("stdlib")).resolve(strict=True)
    payload = {
        "record_type": "V35_TYPED_CANONICAL_MODULE_BINDINGS",
        "execution_identity": "V0_3_FIRST_REAL_SECURITY_WORKER_INVOCATION_V35",
        "generation_identity": GENERATION,
        "canonical_workspace_root": str(ROOT),
        "canonical_package_root": str(SRC),
        "pinned_runtime": {
            "identity": RUNTIME_IDENTITY,
            "python_executable": str(python),
            "python_executable_sha256": digest(python),
            "python_version": sys.version,
            "implementation": sys.implementation.name,
            "cache_tag": sys.implementation.cache_tag,
            "magic_number_hex": importlib.util.MAGIC_NUMBER.hex(),
            "stdlib_root": str(stdlib),
            "extension_root": str((stdlib / "lib-dynload").resolve(strict=True)),
        },
        "authorized_resolution_environment": {
            "identity": "V35_CANONICAL_TYPED_MODULE_ENVIRONMENT_V1",
            "canonical_workspace_root": str(ROOT),
            "canonical_package_root": str(SRC),
            "cwd": str(ROOT),
            "PYTHONPATH": "ABSENT",
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONHASHSEED": "0",
            "PYTHONPYCACHEPREFIX": "ABSENT",
            "sys_path_mutation": "PROHIBITED",
        },
        "project_module_count": sum(row["module_class"] == "LOCAL_SOURCE_MODULE" for row in rows),
        "runtime_module_count": sum(row["module_class"] != "LOCAL_SOURCE_MODULE" for row in rows),
        "module_count": len(rows),
        "modules": sorted(rows, key=lambda row: row["canonical_logical_module_name"].encode()),
        "count_only_graph_equivalence": "PROHIBITED",
        "status": "FINAL_BYTES_FIRST_TYPED_BINDING",
    }
    path = SRC / "workspace_boundary_v35.py"
    spec = importlib.util.spec_from_file_location("workspace_boundary_v35", path)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    module.guarded_json_once(OUT, payload, operation_identity="BUILD_TYPED_CANONICAL_MODULE_BINDINGS", generation="CANONICAL_MODULE_BINDINGS_V35")
    print(json.dumps({"status": "PASS", "modules": len(rows), "project": payload["project_module_count"], "runtime": payload["runtime_module_count"]}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
