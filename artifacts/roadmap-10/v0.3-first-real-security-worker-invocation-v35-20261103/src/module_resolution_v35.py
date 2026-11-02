"""Typed canonical project and Python-runtime module resolution for V35."""
from __future__ import annotations

import hashlib
import importlib
import importlib.machinery
import importlib.util
import json
import os
import stat
import sys
import sysconfig
from pathlib import Path
from typing import Any, Iterable, Mapping

WORKSPACE = Path("/home/nobcoder/v0.3-first-real-security-worker-invocation-v35-20261103")
PACKAGE_ROOT = WORKSPACE / "src"
BINDING_PATH = WORKSPACE / "contracts/CANONICAL_MODULE_BINDINGS.json"
CONTRACT_PATH = WORKSPACE / "contracts/TYPED_CANONICAL_STANDARD_LIBRARY_MODULE_IDENTITY_CONTRACT.json"
EXECUTION_IDENTITY = "V0_3_FIRST_REAL_SECURITY_WORKER_INVOCATION_V35"
GENERATION_IDENTITY = "V35_CURRENT_GOVERNANCE_BOUND_TYPED_PREFLIGHT_BINDING_GENERATION_0001"
RUNTIME_IDENTITY = "V35_PINNED_CPYTHON_3_14_RUNTIME_0001"
MODULE_CLASSES = frozenset({"LOCAL_SOURCE_MODULE", "LOCAL_PROJECT_MODULE", "PURE_PYTHON_STDLIB", "BUILTIN_MODULE", "EXTENSION_MODULE", "FROZEN_MODULE"})
ALLOWED_COMPONENTS = frozenset({"BUILDER", "UNIT", "PRIMARY_VALIDATOR", "INDEPENDENT_VALIDATOR", "FRESH_PREFLIGHT", "DEPENDENCY_CLOSURE", "STATIC_LOCK_PREPARATION", "STATIC_LOCK_VERIFICATION", "LOCKED_RUNTIME", "POST_VALIDATOR", "EVIDENCE_FREEZE"})


class CanonicalModuleResolutionError(RuntimeError):
    pass


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _load(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise CanonicalModuleResolutionError(f"JSON_OBJECT_REQUIRED:{path}")
    return value


def _loader_identity(loader: object | None) -> str | None:
    if loader is None:
        return None
    value = loader if isinstance(loader, type) else type(loader)
    return f"{value.__module__}.{value.__qualname__}"


def _safe_regular(path: Path) -> bool:
    try:
        info = path.lstat()
        return stat.S_ISREG(info.st_mode) and not stat.S_ISLNK(info.st_mode) and path.resolve(strict=True) == path
    except OSError:
        return False


def _runtime_identity(binding: Mapping[str, Any]) -> dict[str, bool]:
    runtime = binding.get("pinned_runtime", {})
    python = Path(sys.executable).resolve(strict=True)
    stdlib = Path(sysconfig.get_path("stdlib")).resolve(strict=True)
    return {
        "identity": runtime.get("identity") == RUNTIME_IDENTITY,
        "python_executable": runtime.get("python_executable") == str(python),
        "python_digest": runtime.get("python_executable_sha256") == _sha256(python),
        "python_version": runtime.get("python_version") == sys.version,
        "implementation": runtime.get("implementation") == sys.implementation.name,
        "cache_tag": runtime.get("cache_tag") == sys.implementation.cache_tag,
        "magic_number": runtime.get("magic_number_hex") == importlib.util.MAGIC_NUMBER.hex(),
        "stdlib_root": runtime.get("stdlib_root") == str(stdlib),
        "extension_root": runtime.get("extension_root") == str((stdlib / "lib-dynload").resolve(strict=True)),
    }


def binding_rows() -> dict[str, dict[str, Any]]:
    binding = _load(BINDING_PATH)
    if binding.get("execution_identity") != EXECUTION_IDENTITY or binding.get("generation_identity") != GENERATION_IDENTITY:
        raise CanonicalModuleResolutionError("BINDING_IDENTITY_MISMATCH")
    if not all(_runtime_identity(binding).values()):
        raise CanonicalModuleResolutionError("PINNED_RUNTIME_IDENTITY_MISMATCH")
    rows = binding.get("modules")
    if not isinstance(rows, list) or not rows:
        raise CanonicalModuleResolutionError("MODULE_BINDINGS_ABSENT")
    indexed = {}
    for row in rows:
        name = row.get("canonical_logical_module_name") if isinstance(row, dict) else None
        if not isinstance(name, str) or name in indexed or row.get("module_class") not in MODULE_CLASSES or row.get("module_category") != row.get("module_class") or row.get("runtime_identity") != row.get("pinned_runtime_identity"):
            raise CanonicalModuleResolutionError("MALFORMED_OR_AMBIGUOUS_MODULE_BINDING")
        indexed[name] = row
    return indexed


def canonical_environment_verdict(component: str, *, cwd: str | None = None, pythonpath: str | None = None, package_root: str | None = None) -> dict[str, Any]:
    checks = {
        "component_authorized": component in ALLOWED_COMPONENTS,
        "cwd_exact": (os.getcwd() if cwd is None else cwd) == str(WORKSPACE),
        "canonical_package_root_exact": (str(PACKAGE_ROOT) if package_root is None else package_root) == str(PACKAGE_ROOT),
        "pythonpath_absent": (os.environ.get("PYTHONPATH") if pythonpath is None else pythonpath) in {None, ""},
        "bytecode_disabled": sys.dont_write_bytecode and os.environ.get("PYTHONDONTWRITEBYTECODE") == "1",
        "hash_seed_exact": os.environ.get("PYTHONHASHSEED") == "0",
        "pycache_prefix_absent": os.environ.get("PYTHONPYCACHEPREFIX") in {None, ""},
    }
    return {"record_type": "V35_CANONICAL_TYPED_MODULE_ENVIRONMENT_VERDICT", "component": component, "checks": checks, "status": "PASS" if all(checks.values()) else "FAIL_CLOSED_BEFORE_MODULE_RESOLUTION"}


def bind_canonical_environment(component: str) -> dict[str, Any]:
    verdict = canonical_environment_verdict(component)
    if verdict["status"] != "PASS":
        raise CanonicalModuleResolutionError(f"CANONICAL_ENVIRONMENT_REJECTED:{verdict['checks']}")
    contract = _load(CONTRACT_PATH)
    if contract.get("contract_identity") != "V35_TYPED_CANONICAL_MODULE_IDENTITY_CONTRACT_V1":
        raise CanonicalModuleResolutionError("TYPED_CONTRACT_IDENTITY_MISMATCH")
    required_classes = set(contract.get("required_module_classes", []))
    if not required_classes <= MODULE_CLASSES:
        raise CanonicalModuleResolutionError("TYPED_CONTRACT_MODULE_CLASS_COVERAGE_MISMATCH")
    if contract.get("count_only_equivalence") != "PROHIBITED" or contract.get("per_symbol_equivalence") != "EXACT_ROW_IDENTITY_REQUIRED":
        raise CanonicalModuleResolutionError("TYPED_CONTRACT_GRAPH_EQUIVALENCE_RULE_MISMATCH")
    binding = _load(BINDING_PATH)
    runtime_checks = _runtime_identity(binding)
    if not all(runtime_checks.values()):
        raise CanonicalModuleResolutionError(f"PINNED_RUNTIME_REJECTED:{runtime_checks}")
    return {**verdict, "runtime_checks": runtime_checks, "binding_sha256": _sha256(BINDING_PATH), "contract_sha256": _sha256(CONTRACT_PATH), "canonical_workspace_root": str(WORKSPACE), "canonical_package_root": str(PACKAGE_ROOT)}


def typed_module_fixture_verdict(row: Mapping[str, Any], *, resolved_origin: str | None, resolved_loader: str | None, resolved_digest: str | None, exported_symbols: Iterable[str], runtime_identity: str = RUNTIME_IDENTITY) -> dict[str, Any]:
    category = row.get("module_class")
    source_required = category in {"LOCAL_SOURCE_MODULE", "LOCAL_PROJECT_MODULE", "PURE_PYTHON_STDLIB", "EXTENSION_MODULE"}
    checks = {
        "module_class": category in MODULE_CLASSES,
        "module_class_category_consistent": row.get("module_category") == category,
        "runtime_identity": row.get("pinned_runtime_identity") == runtime_identity == RUNTIME_IDENTITY,
        "origin": resolved_origin == row.get("expected_module_origin"),
        "loader": resolved_loader == row.get("expected_loader_identity"),
        "digest": (resolved_digest == row.get("exact_source_sha256")) if source_required else (resolved_digest is None and row.get("exact_source_sha256") is None),
        "exports": set(row.get("expected_exported_symbol_identities", [])) <= set(exported_symbols),
        "builtin_no_source": category != "BUILTIN_MODULE" or (row.get("canonical_source_path") is None and row.get("exact_source_sha256") is None and row.get("expected_module_origin") == "built-in"),
        "frozen_no_source": category != "FROZEN_MODULE" or (row.get("canonical_source_path") is None and row.get("exact_source_sha256") is None and row.get("expected_module_origin") == "frozen"),
    }
    return {"record_type": "V35_TYPED_MODULE_FIXTURE_VERDICT", "checks": checks, "status": "PASS" if all(checks.values()) else "FAIL_CLOSED"}


def module_resolution_fixture_verdict(*, environment_bound_before_resolution: bool, canonical_root_present: bool, cwd_exact: bool, pythonpath_absent: bool, expected_origin: str, resolved_origin: str | None, expected_digest: str, resolved_digest: str | None, dependency_manifest_member: bool, symbol_manifest_member: bool, candidate_origins: Iterable[str]) -> dict[str, Any]:
    """Carried-forward local-module environment regression oracle."""
    candidates = list(candidate_origins)
    checks = {
        "environment_bound_before_resolution": environment_bound_before_resolution,
        "canonical_root_present": canonical_root_present,
        "cwd_exact": cwd_exact,
        "pythonpath_absent": pythonpath_absent,
        "origin_exact": resolved_origin == expected_origin,
        "digest_exact": resolved_digest == expected_digest,
        "dependency_manifest_member": dependency_manifest_member,
        "symbol_manifest_member": symbol_manifest_member,
        "single_exact_origin": candidates == [expected_origin],
    }
    return {"record_type": "V35_LOCAL_MODULE_RESOLUTION_FIXTURE_VERDICT", "checks": checks, "status": "PASS" if all(checks.values()) else "FAIL_CLOSED"}


def canonical_graph_equivalence_verdict(expected_rows: Iterable[Mapping[str, Any]], actual_rows: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    """Require exact canonical row equivalence; equal cardinality is insufficient."""
    def canonical(rows: Iterable[Mapping[str, Any]]) -> list[str]:
        return sorted(json.dumps(dict(row), sort_keys=True, separators=(",", ":")) for row in rows)
    expected = canonical(expected_rows)
    actual = canonical(actual_rows)
    checks = {"count_equal": len(expected) == len(actual), "canonical_rows_equal": expected == actual}
    return {"record_type": "V35_CANONICAL_GRAPH_EQUIVALENCE_VERDICT", "checks": checks, "status": "PASS" if all(checks.values()) else "FAIL_CLOSED"}


def _spec_for(row: Mapping[str, Any]) -> importlib.machinery.ModuleSpec:
    name = row["expected_import_name"]
    category = row["module_class"]
    if category in {"LOCAL_SOURCE_MODULE", "LOCAL_PROJECT_MODULE"}:
        spec = importlib.machinery.PathFinder.find_spec(name, [str(PACKAGE_ROOT)])
    elif category == "BUILTIN_MODULE":
        spec = importlib.machinery.BuiltinImporter.find_spec(name)
    elif category == "FROZEN_MODULE":
        spec = importlib.machinery.FrozenImporter.find_spec(name)
    elif category == "PURE_PYTHON_STDLIB":
        spec = importlib.machinery.PathFinder.find_spec(name, [sysconfig.get_path("stdlib")])
    elif category == "EXTENSION_MODULE":
        spec = importlib.machinery.PathFinder.find_spec(name, [str(Path(sysconfig.get_path("stdlib")) / "lib-dynload")])
    else:
        spec = None
    if spec is None:
        raise CanonicalModuleResolutionError(f"MODULE_NOT_RESOLVABLE:{name}:{category}")
    return spec


def resolve_module(name: str, *, component: str, environment: dict[str, Any] | None = None) -> dict[str, Any]:
    environment = environment or bind_canonical_environment(component)
    if environment.get("status") != "PASS" or environment.get("component") != component:
        raise CanonicalModuleResolutionError("ENVIRONMENT_NOT_BOUND_FOR_COMPONENT")
    row = binding_rows().get(name)
    if row is None:
        raise CanonicalModuleResolutionError(f"UNBOUND_LOGICAL_MODULE:{name}")
    spec = _spec_for(row)
    origin = spec.origin
    loader = _loader_identity(spec.loader)
    source = Path(origin).resolve(strict=True) if origin not in {None, "built-in", "frozen"} else None
    if source is not None and not _safe_regular(source):
        raise CanonicalModuleResolutionError(f"UNSAFE_MODULE_SOURCE:{name}")
    module = importlib.import_module(name) if row["module_class"] not in {"LOCAL_SOURCE_MODULE", "LOCAL_PROJECT_MODULE"} else None
    if module is not None:
        actual_spec = getattr(module, "__spec__", None)
        if actual_spec is None or actual_spec.origin != origin or _loader_identity(actual_spec.loader) != loader:
            raise CanonicalModuleResolutionError(f"IMPORTED_MODULE_IDENTITY_MISMATCH:{name}")
        exports = dir(module)
    else:
        exports = row.get("expected_exported_symbol_identities", [])
    verdict = typed_module_fixture_verdict(row, resolved_origin=origin, resolved_loader=loader, resolved_digest=_sha256(source) if source else None, exported_symbols=exports)
    if verdict["status"] != "PASS":
        raise CanonicalModuleResolutionError(f"TYPED_MODULE_IDENTITY_REJECTED:{name}:{verdict['checks']}")
    return {"logical_module_identity": row["logical_module_identity"], "canonical_logical_module_name": name, "module_class": row["module_class"], "origin": origin, "loader_identity": loader, "sha256": _sha256(source) if source else None, "size": source.stat().st_size if source else None, "expected_exported_symbol_identities": row.get("expected_exported_symbol_identities", []), "status": "PASS"}


def canonical_module_resolution_precheck(component: str) -> dict[str, Any]:
    try:
        environment = bind_canonical_environment(component)
        rows = binding_rows()
        local = {name for name, row in rows.items() if row["module_class"] in {"LOCAL_SOURCE_MODULE", "LOCAL_PROJECT_MODULE"}}
        actual_local = {path.stem for path in PACKAGE_ROOT.glob("*.py") if path.name != "__init__.py"}
        if local != actual_local:
            raise CanonicalModuleResolutionError(f"LOCAL_MODULE_MEMBER_SET_MISMATCH:missing={sorted(actual_local-local)}:extra={sorted(local-actual_local)}")
        resolutions = [resolve_module(name, component=component, environment=environment) for name in sorted(rows)]
        counts = {category: sum(row["module_class"] == category for row in rows.values()) for category in sorted(MODULE_CLASSES)}
        return {"record_type": "V35_TYPED_CANONICAL_MODULE_RESOLUTION_ATTESTATION", "execution_identity": EXECUTION_IDENTITY, "component": component, "environment": environment, "module_count": len(resolutions), "module_class_counts": counts, "modules": resolutions, "status": "PASS"}
    except (CanonicalModuleResolutionError, OSError, ValueError, json.JSONDecodeError) as exc:
        return {"record_type": "V35_TYPED_CANONICAL_MODULE_RESOLUTION_ATTESTATION", "execution_identity": EXECUTION_IDENTITY, "component": component, "failure_reason": str(exc), "status": "FAIL_CLOSED_BEFORE_STATIC_LOCK_AND_ATTEMPT"}


def load_canonical_modules(component: str, names: Iterable[str]) -> dict[str, Any]:
    environment = bind_canonical_environment(component)
    rows = binding_rows()
    loaded = []
    for name in names:
        row = rows.get(name)
        if row is None or row.get("module_class") not in {"LOCAL_SOURCE_MODULE", "LOCAL_PROJECT_MODULE"}:
            raise CanonicalModuleResolutionError(f"LOCAL_SOURCE_MODULE_REQUIRED:{name}")
        resolution = resolve_module(name, component=component, environment=environment)
        origin = Path(resolution["origin"])
        existing = sys.modules.get(name)
        if existing is not None:
            existing_origin = Path(getattr(existing, "__file__", "")).resolve(strict=True)
            if existing_origin != origin:
                raise CanonicalModuleResolutionError(f"SHADOW_MODULE_ALREADY_LOADED:{name}")
            loaded.append(resolution); continue
        spec = importlib.util.spec_from_file_location(name, origin)
        if spec is None or spec.loader is None or Path(spec.origin or "").resolve(strict=True) != origin:
            raise CanonicalModuleResolutionError(f"FILE_SPEC_REJECTED:{name}")
        module = importlib.util.module_from_spec(spec); sys.modules[name] = module
        try:
            spec.loader.exec_module(module)
        except Exception:
            sys.modules.pop(name, None); raise
        if Path(getattr(module, "__file__", "")).resolve(strict=True) != origin or _sha256(origin) != resolution["sha256"]:
            sys.modules.pop(name, None); raise CanonicalModuleResolutionError(f"LOADED_MODULE_IDENTITY_MISMATCH:{name}")
        loaded.append(resolution)
    return {"status": "PASS", "component": component, "loaded_modules": loaded}
