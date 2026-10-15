from __future__ import annotations

import json
import re
import sqlite3
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import quote

from .db import Database
from .util import canonical_json, sha256_text, truncate, utcnow


TEXT_SUFFIXES = {
    ".md",
    ".txt",
    ".json",
    ".yaml",
    ".yml",
    ".toml",
    ".py",
    ".rs",
    ".go",
    ".js",
    ".ts",
    ".tsx",
    ".java",
    ".kt",
    ".sol",
    ".sh",
}

TEXT_NAMES = {"SKILL.md", "INSTRUCTIONS.md", "AGENTS.md", "CLAUDE.md"}
IGNORED_PARTS = {".git", "node_modules", ".venv", "__pycache__", "dist", "build"}


class KnowledgeIndex:
    def __init__(self, database: Database, max_file_bytes: int = 512 * 1024):
        self.database = database
        self.max_file_bytes = max_file_bytes

    def index_roots(self, roots: Iterable[str | Path]) -> dict[str, int]:
        counters = {"files_seen": 0, "documents_indexed": 0, "documents_unchanged": 0, "errors": 0}
        for raw_root in roots:
            root = Path(raw_root).expanduser().resolve()
            if not root.exists():
                counters["errors"] += 1
                continue
            for path in self._iter_files(root):
                counters["files_seen"] += 1
                try:
                    changed = self.index_file(path, root)
                except (OSError, UnicodeDecodeError):
                    counters["errors"] += 1
                    continue
                counters["documents_indexed" if changed else "documents_unchanged"] += 1
        return counters

    def _iter_files(self, root: Path) -> Iterable[Path]:
        for path in root.rglob("*"):
            try:
                relative_parts = path.relative_to(root).parts
            except ValueError:
                continue
            if any(part in IGNORED_PARTS for part in relative_parts):
                continue
            if not path.is_file():
                continue
            if path.name in TEXT_NAMES or path.suffix.lower() in TEXT_SUFFIXES:
                try:
                    if path.stat().st_size <= self.max_file_bytes:
                        yield path
                except OSError:
                    continue

    def index_file(self, path: Path, root: Path | None = None) -> bool:
        data = path.read_bytes()
        text = data.decode("utf-8")
        digest = sha256_text(text)
        source_uri = str(path.resolve())
        current = self.database.one("SELECT sha256 FROM knowledge_documents WHERE source_uri=?", (source_uri,))
        if current is not None and current["sha256"] == digest:
            return False
        title, tags = self._metadata_from_text(path, text, root)
        self._upsert_document(
            source_type="file",
            source_uri=source_uri,
            title=title,
            tags=tags,
            content=text,
            digest=digest,
            mtime=path.stat().st_mtime,
            metadata={"root": str(root) if root else "", "relative": str(path.relative_to(root)) if root else path.name},
        )
        return True

    @staticmethod
    def _metadata_from_text(path: Path, text: str, root: Path | None) -> tuple[str, str]:
        title = path.stem.replace("-", " ").replace("_", " ")
        tags: set[str] = set(part.lower() for part in path.parts[-5:-1])
        frontmatter = re.match(r"^---\s*\n(.*?)\n---", text, flags=re.DOTALL)
        if frontmatter:
            for line in frontmatter.group(1).splitlines():
                key, _, value = line.partition(":")
                if key.strip() == "name" and value.strip():
                    title = value.strip().strip('"\'')
                if key.strip() in {"name", "description", "tags"}:
                    tags.update(re.findall(r"[a-zA-Z][a-zA-Z0-9_-]{2,}", value.lower()))
        if root:
            tags.add(root.name.lower())
        return title, " ".join(sorted(tags))

    def index_report_databases(self, paths: Iterable[str | Path]) -> dict[str, int]:
        counters = {"databases_seen": 0, "reports_seen": 0, "documents_indexed": 0, "documents_unchanged": 0, "errors": 0}
        for raw_path in paths:
            path = Path(raw_path).expanduser().resolve()
            if not path.exists():
                counters["errors"] += 1
                continue
            counters["databases_seen"] += 1
            try:
                with self.database.connect() as target_connection:
                    for document in self._report_documents(path):
                        counters["reports_seen"] += 1
                        current = target_connection.execute(
                            "SELECT sha256 FROM knowledge_documents WHERE source_uri=?",
                            (document["source_uri"],),
                        ).fetchone()
                        if current is not None and current["sha256"] == document["digest"]:
                            counters["documents_unchanged"] += 1
                            continue
                        self._upsert_document(connection=target_connection, **document)
                        counters["documents_indexed"] += 1
            except (sqlite3.Error, OSError):
                counters["errors"] += 1
        return counters

    def _report_documents(self, path: Path) -> Iterable[dict[str, Any]]:
        connection = sqlite3.connect(f"file:{quote(str(path))}?mode=ro", uri=True)
        connection.row_factory = sqlite3.Row
        try:
            columns = {row[1] for row in connection.execute("PRAGMA table_info(reports)")}
            if {"report_id", "program_handle", "hacktivity_summary"}.issubset(columns):
                query = (
                    "SELECT report_id, title, url, program_handle, program_name, cwe, severity_rating, "
                    "hacktivity_summary, disclosed_at, source_digest FROM reports"
                )
                for row in connection.execute(query):
                    tags = " ".join(
                        str(item)
                        for item in ("hackerone", row["program_handle"], row["cwe"], row["severity_rating"])
                        if item
                    )
                    content = "\n".join(
                        str(item)
                        for item in (row["title"], row["program_name"], row["cwe"], row["hacktivity_summary"])
                        if item
                    )
                    yield {
                        "source_type": "hackerone-report",
                        "source_uri": f"sqlite://{path}#reports/{row['report_id']}",
                        "title": row["title"],
                        "tags": tags,
                        "content": content,
                        "digest": row["source_digest"] or sha256_text(content),
                        "mtime": path.stat().st_mtime,
                        "metadata": {
                            "url": row["url"],
                            "program": row["program_handle"],
                            "disclosed_at": row["disclosed_at"],
                            "evidence_tier": "PUBLIC_REPORT_METADATA",
                        },
                    }
            elif {"source", "source_id", "vulnerability_class", "summary"}.issubset(columns):
                query = (
                    "SELECT source, source_id, title, url, program, platform, vulnerability_class, weakness, "
                    "severity, tags_json, summary, published_at, evidence_tier, source_digest FROM reports"
                )
                for row in connection.execute(query):
                    tags = " ".join(
                        str(item)
                        for item in (
                            row["source"],
                            row["platform"],
                            row["vulnerability_class"],
                            row["weakness"],
                            row["severity"],
                            row["tags_json"],
                        )
                        if item
                    )
                    content = "\n".join(
                        str(item)
                        for item in (row["title"], row["program"], row["vulnerability_class"], row["weakness"], row["summary"])
                        if item
                    )
                    yield {
                        "source_type": "public-disclosure",
                        "source_uri": f"sqlite://{path}#reports/{row['source']}/{row['source_id']}",
                        "title": row["title"],
                        "tags": tags,
                        "content": content,
                        "digest": row["source_digest"] or sha256_text(content),
                        "mtime": path.stat().st_mtime,
                        "metadata": {
                            "url": row["url"],
                            "program": row["program"],
                            "published_at": row["published_at"],
                            "evidence_tier": row["evidence_tier"],
                        },
                    }
            else:
                raise sqlite3.DatabaseError(f"unsupported report schema in {path}")
        finally:
            connection.close()

    def _upsert_document(
        self,
        *,
        source_type: str,
        source_uri: str,
        title: str,
        tags: str,
        content: str,
        digest: str,
        mtime: float,
        metadata: dict[str, Any],
        connection: sqlite3.Connection | None = None,
    ) -> None:
        if connection is not None:
            self._upsert_document_on_connection(
                connection,
                source_type=source_type,
                source_uri=source_uri,
                title=title,
                tags=tags,
                content=content,
                digest=digest,
                mtime=mtime,
                metadata=metadata,
            )
            return
        with self.database.transaction(immediate=True) as owned_connection:
            self._upsert_document_on_connection(
                owned_connection,
                source_type=source_type,
                source_uri=source_uri,
                title=title,
                tags=tags,
                content=content,
                digest=digest,
                mtime=mtime,
                metadata=metadata,
            )

    @staticmethod
    def _upsert_document_on_connection(
        connection: sqlite3.Connection,
        *,
        source_type: str,
        source_uri: str,
        title: str,
        tags: str,
        content: str,
        digest: str,
        mtime: float,
        metadata: dict[str, Any],
    ) -> None:
        existing = connection.execute(
            "SELECT id FROM knowledge_documents WHERE source_uri=?", (source_uri,)
        ).fetchone()
        if existing:
            doc_id = int(existing["id"])
            connection.execute(
                """
                UPDATE knowledge_documents
                SET source_type=?, title=?, tags=?, content=?, sha256=?, mtime=?, metadata_json=?, indexed_at=?
                WHERE id=?
                """,
                (source_type, title, tags, content, digest, mtime, canonical_json(metadata), utcnow(), doc_id),
            )
            connection.execute("DELETE FROM knowledge_fts WHERE doc_id=?", (str(doc_id),))
        else:
            cursor = connection.execute(
                """
                INSERT INTO knowledge_documents(
                    source_type, source_uri, title, tags, content, sha256, mtime, metadata_json, indexed_at
                ) VALUES(?,?,?,?,?,?,?,?,?)
                """,
                (source_type, source_uri, title, tags, content, digest, mtime, canonical_json(metadata), utcnow()),
            )
            doc_id = int(cursor.lastrowid)
        connection.execute(
            "INSERT INTO knowledge_fts(doc_id, title, tags, content) VALUES(?,?,?,?)",
            (str(doc_id), title, tags, content),
        )

    def query(self, query: str, top_k: int = 8, max_chars: int = 1200) -> list[dict[str, Any]]:
        terms = []
        for term in re.findall(r"[a-zA-Z0-9][a-zA-Z0-9_.:/-]{1,63}", query.lower()):
            normalized = term.replace('"', "")
            if normalized not in terms:
                terms.append(normalized)
        if not terms:
            return []
        expression = " OR ".join(f'"{term}"' for term in terms[:24])
        sql = """
            SELECT d.id, d.source_type, d.source_uri, d.title, d.tags, d.content,
                   d.metadata_json, bm25(knowledge_fts, 0.0, 4.0, 2.0, 1.0) AS score
            FROM knowledge_fts
            JOIN knowledge_documents d ON d.id = CAST(knowledge_fts.doc_id AS INTEGER)
            WHERE knowledge_fts MATCH ?
            ORDER BY score ASC, d.id ASC
            LIMIT ?
        """
        try:
            rows = self.database.all(sql, (expression, top_k))
        except sqlite3.OperationalError:
            return []
        results: list[dict[str, Any]] = []
        for row in rows:
            try:
                metadata = json.loads(row["metadata_json"])
            except json.JSONDecodeError:
                metadata = {}
            results.append(
                {
                    "id": row["id"],
                    "source_type": row["source_type"],
                    "source_uri": row["source_uri"],
                    "title": row["title"],
                    "tags": row["tags"],
                    "snippet": truncate(row["content"], max_chars),
                    "score": row["score"],
                    "metadata": metadata,
                }
            )
        return results

    def route(
        self,
        query: str,
        worker_role: str,
        top_k: int,
        campaign_id: str | None = None,
        max_chars: int = 1200,
    ) -> list[dict[str, Any]]:
        results = self.query(query, top_k=top_k, max_chars=max_chars)
        with self.database.connect() as connection:
            connection.execute(
                """
                INSERT INTO knowledge_routes(campaign_id, worker_role, query, top_k, results_json, created_at)
                VALUES(?,?,?,?,?,?)
                """,
                (campaign_id, worker_role, query, top_k, canonical_json(results), utcnow()),
            )
        return results
