from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any


MANIFEST_SIGNALS: dict[str, tuple[list[str], list[str]]] = {
    "package.json": (["javascript", "typescript", "nodejs"], []),
    "deno.json": (["typescript", "deno"], []),
    "go.mod": (["go"], []),
    "Cargo.toml": (["rust"], []),
    "pyproject.toml": (["python"], []),
    "requirements.txt": (["python"], []),
    "pom.xml": (["java", "maven"], []),
    "build.gradle": (["java", "kotlin", "gradle"], []),
    "build.gradle.kts": (["kotlin", "gradle"], []),
    "CMakeLists.txt": (["c", "cpp", "cmake"], []),
    "go.work": (["go", "monorepo"], []),
    "foundry.toml": (["solidity", "evm", "foundry"], ["web3"]),
    "hardhat.config.ts": (["typescript", "solidity", "evm"], ["web3"]),
    "wrangler.toml": (["cloudflare-workers"], ["edge-runtime"]),
    "wrangler.jsonc": (["cloudflare-workers"], ["edge-runtime"]),
    "Dockerfile": (["container"], ["deployment"]),
}


EXTENSION_LANGUAGES = {
    ".ts": "typescript",
    ".tsx": "typescript",
    ".js": "javascript",
    ".jsx": "javascript",
    ".py": "python",
    ".go": "go",
    ".rs": "rust",
    ".c": "c",
    ".cc": "cpp",
    ".cpp": "cpp",
    ".h": "c-cpp",
    ".hpp": "cpp",
    ".java": "java",
    ".kt": "kotlin",
    ".sol": "solidity",
    ".rb": "ruby",
    ".php": "php",
    ".cs": "csharp",
}


def _git(target: Path, *args: str) -> str:
    try:
        result = subprocess.run(
            ["git", "-C", str(target), *args],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return ""
    return result.stdout.strip() if result.returncode == 0 else ""


def _package_terms(path: Path) -> list[str]:
    try:
        package = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    dependencies: set[str] = set()
    for key in ("dependencies", "devDependencies", "peerDependencies"):
        value = package.get(key, {})
        if isinstance(value, dict):
            dependencies.update(str(name).lower() for name in value)
    terms: list[str] = []
    mappings = {
        "@cloudflare/workers-types": "cloudflare-workers",
        "hono": "http-routing",
        "express": "web-api",
        "fastify": "web-api",
        "ws": "websocket",
        "jsonwebtoken": "jwt-authentication",
        "next": "nextjs",
        "react": "browser-ui",
    }
    for dependency, term in mappings.items():
        if dependency in dependencies:
            terms.append(term)
    return terms


def fingerprint_target(target: Path, max_files: int = 5000) -> dict[str, Any]:
    target = target.resolve()
    languages: dict[str, int] = {}
    runtimes: set[str] = set()
    platforms: set[str] = set()
    manifests: list[str] = []
    file_count = 0
    ignored = {".git", "node_modules", "vendor", "dist", "build", ".venv", "target"}
    for path in target.rglob("*"):
        if any(part in ignored for part in path.relative_to(target).parts):
            continue
        if not path.is_file():
            continue
        file_count += 1
        if file_count > max_files:
            break
        relative = path.relative_to(target).as_posix()
        language = EXTENSION_LANGUAGES.get(path.suffix.lower())
        if language:
            languages[language] = languages.get(language, 0) + 1
        if path.name in MANIFEST_SIGNALS:
            manifests.append(relative)
            runtime_signals, platform_signals = MANIFEST_SIGNALS[path.name]
            runtimes.update(runtime_signals)
            platforms.update(platform_signals)
        if path.name == "package.json":
            runtimes.update(_package_terms(path))
    commit = _git(target, "rev-parse", "HEAD")
    branch = _git(target, "branch", "--show-current")
    remote = _git(target, "remote", "get-url", "origin")
    dirty = bool(_git(target, "status", "--porcelain"))
    dominant = [name for name, _ in sorted(languages.items(), key=lambda item: (-item[1], item[0]))[:5]]
    query_terms = sorted(set(dominant) | runtimes | platforms)
    return {
        "target": str(target),
        "git": {
            "is_repository": bool(commit),
            "commit": commit,
            "branch": branch,
            "remote": remote,
            "dirty": dirty,
        },
        "languages": languages,
        "dominant_languages": dominant,
        "runtimes": sorted(runtimes),
        "platforms": sorted(platforms),
        "manifests": sorted(manifests),
        "files_sampled": min(file_count, max_files),
        "truncated": file_count > max_files,
        "knowledge_query_terms": query_terms,
    }
