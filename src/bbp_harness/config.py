from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .util import atomic_write_text, pretty_json


@dataclass(slots=True)
class HarnessPaths:
    home: Path
    state_dir: Path
    database: Path
    evidence_dir: Path
    runs_dir: Path
    workspaces_dir: Path
    config_file: Path

    @classmethod
    def discover(cls, home: Path | None = None) -> "HarnessPaths":
        base = (home or Path(os.environ.get("BBP_AI_HOME", "~/.bbp-ai"))).expanduser().resolve()
        state_dir = base / "state"
        return cls(
            home=base,
            state_dir=state_dir,
            database=state_dir / "research.db",
            evidence_dir=base / "evidence",
            runs_dir=base / "runs",
            workspaces_dir=base / "workspaces",
            config_file=base / "config.json",
        )

    def ensure(self) -> None:
        for path in (
            self.home,
            self.state_dir,
            self.evidence_dir,
            self.runs_dir,
            self.workspaces_dir,
        ):
            path.mkdir(parents=True, exist_ok=True)
            path.chmod(0o700)


@dataclass(slots=True)
class HarnessConfig:
    knowledge_roots: list[str] = field(default_factory=list)
    report_databases: list[str] = field(default_factory=list)
    codex_binary: str = "codex"
    codex_runtime_execution_authorized: bool = False
    model: str | None = None
    max_concurrency: int = 3
    worker_timeout_seconds: int = 1800
    knowledge_top_k: int = 8
    max_knowledge_chars_per_doc: int = 1200
    max_worker_attempts: int = 2
    stale_lease_seconds: int = 3600

    @classmethod
    def defaults(cls) -> "HarnessConfig":
        user_home = Path.home()
        candidates = [user_home / "skill", user_home / ".codex" / "skills"]
        reports = [
            user_home / ".local" / "share" / "codex" / "hacktivity" / "corpus.sqlite3",
            user_home / ".local" / "share" / "codex" / "public-disclosures" / "corpus.sqlite3",
        ]
        return cls(
            knowledge_roots=[str(path) for path in candidates if path.exists()],
            report_databases=[str(path) for path in reports if path.exists()],
        )

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "HarnessConfig":
        known = {name for name in cls.__dataclass_fields__}
        return cls(**{key: value for key, value in raw.items() if key in known})

    def to_dict(self) -> dict[str, Any]:
        return {
            "knowledge_roots": self.knowledge_roots,
            "report_databases": self.report_databases,
            "codex_binary": self.codex_binary,
            "codex_runtime_execution_authorized": self.codex_runtime_execution_authorized,
            "model": self.model,
            "max_concurrency": self.max_concurrency,
            "worker_timeout_seconds": self.worker_timeout_seconds,
            "knowledge_top_k": self.knowledge_top_k,
            "max_knowledge_chars_per_doc": self.max_knowledge_chars_per_doc,
            "max_worker_attempts": self.max_worker_attempts,
            "stale_lease_seconds": self.stale_lease_seconds,
        }


def load_config(paths: HarnessPaths) -> HarnessConfig:
    paths.ensure()
    if not paths.config_file.exists():
        config = HarnessConfig.defaults()
        atomic_write_text(paths.config_file, pretty_json(config.to_dict()))
        return config
    with paths.config_file.open("r", encoding="utf-8") as handle:
        return HarnessConfig.from_dict(json.load(handle))
