from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator, Sequence

from .util import canonical_json, utcnow


SCHEMA_VERSION = 1


class ClosingConnection(sqlite3.Connection):
    """Commit or roll back like sqlite3.Connection, then always close."""

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> bool:
        try:
            return bool(super().__exit__(exc_type, exc, traceback))
        finally:
            self.close()


SCHEMA_SQL = r"""
CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS targets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    root_path TEXT NOT NULL UNIQUE,
    repo_url TEXT NOT NULL DEFAULT '',
    repo_commit TEXT NOT NULL DEFAULT '',
    branch TEXT NOT NULL DEFAULT '',
    dirty INTEGER NOT NULL DEFAULT 0,
    fingerprint_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS campaigns (
    id TEXT PRIMARY KEY,
    target_id INTEGER NOT NULL REFERENCES targets(id),
    objective TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('INITIALIZED','ACTIVE','PAUSED','BLOCKED','COMPLETE','ABORTED')),
    scope_status TEXT NOT NULL CHECK (scope_status IN ('PROVEN','UNPROVEN','OUT_OF_SCOPE')),
    novel_discovery_mode INTEGER NOT NULL DEFAULT 0,
    max_workers INTEGER NOT NULL DEFAULT 3,
    max_waves INTEGER NOT NULL DEFAULT 4,
    time_budget_minutes INTEGER,
    token_budget INTEGER,
    started_at TEXT,
    completed_at TEXT,
    last_error TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS scope (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    campaign_id TEXT NOT NULL REFERENCES campaigns(id),
    source_path TEXT NOT NULL,
    scope_hash TEXT NOT NULL,
    authorization_confirmed INTEGER NOT NULL,
    program TEXT NOT NULL DEFAULT '',
    asset TEXT NOT NULL DEFAULT '',
    allowed_methods_json TEXT NOT NULL DEFAULT '[]',
    exclusions_json TEXT NOT NULL DEFAULT '[]',
    rate_limits_json TEXT NOT NULL DEFAULT '{}',
    stop_conditions_json TEXT NOT NULL DEFAULT '[]',
    raw_json TEXT NOT NULL,
    verified_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS runs (
    id TEXT PRIMARY KEY,
    campaign_id TEXT NOT NULL REFERENCES campaigns(id),
    kind TEXT NOT NULL,
    status TEXT NOT NULL,
    summary TEXT NOT NULL DEFAULT '',
    error TEXT NOT NULL DEFAULT '',
    started_at TEXT NOT NULL,
    completed_at TEXT
);

CREATE TABLE IF NOT EXISTS attack_surfaces (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    campaign_id TEXT NOT NULL REFERENCES campaigns(id),
    surface_key TEXT NOT NULL,
    kind TEXT NOT NULL,
    name TEXT NOT NULL,
    location TEXT NOT NULL DEFAULT '',
    trust_boundary TEXT NOT NULL DEFAULT '',
    protected_sink TEXT NOT NULL DEFAULT '',
    evidence_json TEXT NOT NULL DEFAULT '[]',
    status TEXT NOT NULL DEFAULT 'UNREVIEWED',
    UNIQUE(campaign_id, surface_key)
);

CREATE TABLE IF NOT EXISTS research_paths (
    id TEXT PRIMARY KEY,
    campaign_id TEXT NOT NULL REFERENCES campaigns(id),
    attack_surface TEXT NOT NULL,
    hypothesis_family TEXT NOT NULL,
    trust_boundary TEXT NOT NULL DEFAULT '',
    release_component TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL CHECK (status IN ('ACTIVE','PROMISING','BLOCKED','EXHAUSTED','KILLED','VALIDATED','STOPPED')),
    status_reason TEXT NOT NULL DEFAULT '',
    unblock_evidence_json TEXT NOT NULL DEFAULT '[]',
    material_new_evidence_json TEXT NOT NULL DEFAULT '[]',
    assigned_roles_json TEXT NOT NULL DEFAULT '[]',
    wave_id TEXT NOT NULL DEFAULT '',
    root_cause_family TEXT NOT NULL DEFAULT '',
    zero_evidence_waves INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS hypotheses (
    id TEXT PRIMARY KEY,
    campaign_id TEXT NOT NULL REFERENCES campaigns(id),
    research_path_id TEXT REFERENCES research_paths(id),
    worker_run_id TEXT,
    title TEXT NOT NULL,
    statement TEXT NOT NULL,
    falsifier TEXT NOT NULL,
    root_cause_family TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'OPEN',
    priority INTEGER NOT NULL DEFAULT 50,
    evidence_json TEXT NOT NULL DEFAULT '[]',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS experiments (
    id TEXT PRIMARY KEY,
    campaign_id TEXT NOT NULL REFERENCES campaigns(id),
    hypothesis_id TEXT REFERENCES hypotheses(id),
    candidate_id TEXT,
    kind TEXT NOT NULL,
    status TEXT NOT NULL,
    plan_json TEXT NOT NULL DEFAULT '{}',
    result_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL,
    completed_at TEXT
);

CREATE TABLE IF NOT EXISTS candidates (
    id TEXT PRIMARY KEY,
    campaign_id TEXT NOT NULL REFERENCES campaigns(id),
    hypothesis_id TEXT REFERENCES hypotheses(id),
    title TEXT NOT NULL,
    class TEXT NOT NULL DEFAULT 'unknown',
    root_cause_family TEXT NOT NULL DEFAULT '',
    state TEXT NOT NULL,
    verdict TEXT NOT NULL DEFAULT 'UNRATED',
    kill_code TEXT NOT NULL DEFAULT '',
    kill_reason TEXT NOT NULL DEFAULT '',
    attacker_control TEXT NOT NULL DEFAULT 'UNPROVEN',
    reachability TEXT NOT NULL DEFAULT 'UNPROVEN',
    protected_boundary TEXT NOT NULL DEFAULT 'UNPROVEN',
    capability_delta TEXT NOT NULL DEFAULT 'UNPROVEN',
    reproduction_attempts INTEGER NOT NULL DEFAULT 0,
    reproduction_successes INTEGER NOT NULL DEFAULT 0,
    negative_control TEXT NOT NULL DEFAULT 'NOT_RUN',
    counterfactual TEXT NOT NULL DEFAULT 'NOT_RUN',
    skeptic TEXT NOT NULL DEFAULT 'NOT_RUN',
    prior_art TEXT NOT NULL DEFAULT 'NOT_CHECKED',
    evidence_gate TEXT NOT NULL DEFAULT 'NOT_RUN',
    impact_gate TEXT NOT NULL DEFAULT 'NOT_RUN',
    manual_status TEXT NOT NULL DEFAULT 'NOT_TESTED',
    severity_status TEXT NOT NULL DEFAULT 'PROVISIONAL',
    severity_locked INTEGER NOT NULL DEFAULT 0,
    triager_proof TEXT NOT NULL DEFAULT 'NOT_RUN',
    report_ready INTEGER NOT NULL DEFAULT 0,
    dossier_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS candidate_transitions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    candidate_id TEXT NOT NULL REFERENCES candidates(id),
    from_state TEXT NOT NULL,
    to_state TEXT NOT NULL,
    reason TEXT NOT NULL,
    evidence_json TEXT NOT NULL DEFAULT '[]',
    actor TEXT NOT NULL DEFAULT 'state-machine',
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS evidence (
    id TEXT PRIMARY KEY,
    campaign_id TEXT NOT NULL REFERENCES campaigns(id),
    candidate_id TEXT REFERENCES candidates(id),
    worker_run_id TEXT,
    kind TEXT NOT NULL,
    uri TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    size_bytes INTEGER NOT NULL,
    mime_type TEXT NOT NULL DEFAULT 'application/octet-stream',
    summary TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    UNIQUE(campaign_id, sha256, kind)
);

CREATE TABLE IF NOT EXISTS burned_paths (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    campaign_id TEXT NOT NULL REFERENCES campaigns(id),
    path_key TEXT NOT NULL,
    reason TEXT NOT NULL,
    kill_code TEXT NOT NULL,
    evidence_json TEXT NOT NULL DEFAULT '[]',
    reopen_condition TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    UNIQUE(campaign_id, path_key)
);

CREATE TABLE IF NOT EXISTS prior_art (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    campaign_id TEXT NOT NULL REFERENCES campaigns(id),
    candidate_id TEXT REFERENCES candidates(id),
    source_type TEXT NOT NULL,
    title TEXT NOT NULL,
    url TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL,
    root_cause_match TEXT NOT NULL DEFAULT '',
    evidence_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS worker_jobs (
    id TEXT PRIMARY KEY,
    campaign_id TEXT NOT NULL REFERENCES campaigns(id),
    role TEXT NOT NULL,
    lane TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL CHECK (status IN ('PENDING','READY','RUNNING','PASS','FAIL','BLOCKED','KILLED','CANCELLED')),
    priority INTEGER NOT NULL DEFAULT 50,
    depends_on_json TEXT NOT NULL DEFAULT '[]',
    input_json TEXT NOT NULL DEFAULT '{}',
    budget_json TEXT NOT NULL DEFAULT '{}',
    attempts INTEGER NOT NULL DEFAULT 0,
    max_attempts INTEGER NOT NULL DEFAULT 2,
    leased_at TEXT,
    last_error TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS worker_runs (
    id TEXT PRIMARY KEY,
    campaign_id TEXT NOT NULL REFERENCES campaigns(id),
    job_id TEXT NOT NULL REFERENCES worker_jobs(id),
    role TEXT NOT NULL,
    lane TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL,
    session_id TEXT NOT NULL DEFAULT '',
    prompt_sha256 TEXT NOT NULL,
    input_json TEXT NOT NULL DEFAULT '{}',
    output_json TEXT NOT NULL DEFAULT '{}',
    output_schema TEXT NOT NULL DEFAULT '',
    transcript_path TEXT NOT NULL DEFAULT '',
    last_message_path TEXT NOT NULL DEFAULT '',
    workspace TEXT NOT NULL DEFAULT '',
    exit_code INTEGER,
    started_at TEXT NOT NULL,
    completed_at TEXT,
    error TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY,
    campaign_id TEXT NOT NULL REFERENCES campaigns(id),
    candidate_id TEXT NOT NULL REFERENCES candidates(id),
    severity TEXT NOT NULL,
    title TEXT NOT NULL,
    status TEXT NOT NULL,
    report_path TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    UNIQUE(campaign_id, candidate_id)
);

CREATE TABLE IF NOT EXISTS knowledge_documents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_type TEXT NOT NULL,
    source_uri TEXT NOT NULL UNIQUE,
    title TEXT NOT NULL,
    tags TEXT NOT NULL DEFAULT '',
    content TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    mtime REAL NOT NULL DEFAULT 0,
    metadata_json TEXT NOT NULL DEFAULT '{}',
    indexed_at TEXT NOT NULL
);

CREATE VIRTUAL TABLE IF NOT EXISTS knowledge_fts USING fts5(
    doc_id UNINDEXED,
    title,
    tags,
    content,
    tokenize='porter unicode61'
);

CREATE TABLE IF NOT EXISTS knowledge_routes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    campaign_id TEXT REFERENCES campaigns(id),
    worker_role TEXT NOT NULL,
    query TEXT NOT NULL,
    top_k INTEGER NOT NULL,
    results_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS events (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    campaign_id TEXT,
    entity_type TEXT NOT NULL,
    entity_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    payload_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS eval_cases (
    id TEXT PRIMARY KEY,
    suite TEXT NOT NULL,
    target_path TEXT NOT NULL,
    target_revision TEXT NOT NULL DEFAULT '',
    expected_class TEXT NOT NULL,
    expected_candidate_key TEXT NOT NULL DEFAULT '',
    public_metadata_json TEXT NOT NULL DEFAULT '{}',
    secret_ground_truth_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS eval_runs (
    id TEXT PRIMARY KEY,
    suite TEXT NOT NULL,
    harness_version TEXT NOT NULL,
    status TEXT NOT NULL,
    started_at TEXT NOT NULL,
    completed_at TEXT,
    metrics_json TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS eval_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    eval_run_id TEXT NOT NULL REFERENCES eval_runs(id),
    case_id TEXT NOT NULL REFERENCES eval_cases(id),
    observed_class TEXT NOT NULL,
    found INTEGER NOT NULL,
    reproduced INTEGER NOT NULL,
    correctly_triaged INTEGER NOT NULL,
    false_positive INTEGER NOT NULL,
    elapsed_seconds REAL NOT NULL DEFAULT 0,
    token_cost INTEGER NOT NULL DEFAULT 0,
    details_json TEXT NOT NULL DEFAULT '{}',
    UNIQUE(eval_run_id, case_id)
);

CREATE INDEX IF NOT EXISTS idx_campaigns_target ON campaigns(target_id, created_at);
CREATE INDEX IF NOT EXISTS idx_candidates_campaign_state ON candidates(campaign_id, state);
CREATE INDEX IF NOT EXISTS idx_jobs_campaign_status ON worker_jobs(campaign_id, status, priority);
CREATE INDEX IF NOT EXISTS idx_runs_campaign ON worker_runs(campaign_id, started_at);
CREATE INDEX IF NOT EXISTS idx_events_campaign ON events(campaign_id, sequence);
CREATE INDEX IF NOT EXISTS idx_knowledge_sha ON knowledge_documents(sha256);
"""


class Database:
    def __init__(self, path: Path):
        self.path = path

    def connect(self) -> sqlite3.Connection:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(self.path, timeout=30, factory=ClosingConnection)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA synchronous=NORMAL")
        return connection

    def migrate(self) -> None:
        with self.connect() as connection:
            connection.executescript(SCHEMA_SQL)
            connection.execute(
                "INSERT INTO meta(key, value) VALUES('schema_version', ?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (str(SCHEMA_VERSION),),
            )

    @contextmanager
    def transaction(self, immediate: bool = False) -> Iterator[sqlite3.Connection]:
        connection = self.connect()
        try:
            connection.execute("BEGIN IMMEDIATE" if immediate else "BEGIN")
            yield connection
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()

    def execute(self, sql: str, parameters: Sequence[Any] = ()) -> None:
        with self.connect() as connection:
            connection.execute(sql, parameters)

    def one(self, sql: str, parameters: Sequence[Any] = ()) -> sqlite3.Row | None:
        with self.connect() as connection:
            return connection.execute(sql, parameters).fetchone()

    def all(self, sql: str, parameters: Sequence[Any] = ()) -> list[sqlite3.Row]:
        with self.connect() as connection:
            return list(connection.execute(sql, parameters).fetchall())

    def event(
        self,
        campaign_id: str | None,
        entity_type: str,
        entity_id: str,
        event_type: str,
        payload: dict[str, Any] | list[Any] | None = None,
        connection: sqlite3.Connection | None = None,
    ) -> None:
        values = (
            campaign_id,
            entity_type,
            entity_id,
            event_type,
            canonical_json(payload or {}),
            utcnow(),
        )
        sql = (
            "INSERT INTO events(campaign_id, entity_type, entity_id, event_type, payload_json, created_at) "
            "VALUES(?,?,?,?,?,?)"
        )
        if connection is not None:
            connection.execute(sql, values)
        else:
            with self.connect() as owned:
                owned.execute(sql, values)

    def integrity_check(self) -> str:
        row = self.one("PRAGMA integrity_check")
        return str(row[0]) if row else "unknown"

    def summary(self) -> dict[str, int | str]:
        tables = (
            "targets",
            "campaigns",
            "research_paths",
            "hypotheses",
            "candidates",
            "worker_jobs",
            "worker_runs",
            "evidence",
            "burned_paths",
            "findings",
            "knowledge_documents",
        )
        result: dict[str, int | str] = {"integrity": self.integrity_check()}
        with self.connect() as connection:
            for table in tables:
                result[table] = int(connection.execute(f"SELECT count(*) FROM {table}").fetchone()[0])
        return result


def decode_json_column(row: sqlite3.Row, column: str, fallback: Any) -> Any:
    try:
        return json.loads(row[column])
    except (KeyError, TypeError, json.JSONDecodeError):
        return fallback
