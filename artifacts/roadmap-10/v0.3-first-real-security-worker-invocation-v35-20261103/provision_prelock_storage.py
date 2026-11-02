#!/usr/bin/env python3
"""Provision V35 prelock evidence and fixture scratch roots exactly once."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent
sys.dont_write_bytecode = True
if Path.cwd().resolve() != ROOT:
    raise RuntimeError("V35_CANONICAL_CWD_REQUIRED")
bindings = json.loads((ROOT / "contracts/CANONICAL_MODULE_BINDINGS.json").read_text(encoding="utf-8"))
resolver_row = next(row for row in bindings["modules"] if row["canonical_logical_module_name"] == "module_resolution_v35")
resolver_path = Path(resolver_row["canonical_source_path"])
if hashlib.sha256(resolver_path.read_bytes()).hexdigest() != resolver_row["exact_source_sha256"]:
    raise RuntimeError("V35_MODULE_RESOLVER_DIGEST_MISMATCH")
spec = importlib.util.spec_from_file_location("module_resolution_v35", resolver_path)
if spec is None or spec.loader is None:
    raise RuntimeError("V35_MODULE_RESOLVER_SPEC_UNAVAILABLE")
resolver = importlib.util.module_from_spec(spec)
sys.modules["module_resolution_v35"] = resolver
spec.loader.exec_module(resolver)
resolver.load_canonical_modules("BUILDER", ("workspace_boundary_v35", "prelock_storage_lifecycle_v35"))

from prelock_storage_lifecycle_v35 import provision_prelock_storage  # noqa: E402


def main() -> int:
    result = provision_prelock_storage()
    print(json.dumps(result, sort_keys=True))
    return 0 if result.get("status") == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
