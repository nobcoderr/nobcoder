from __future__ import annotations

import mimetypes
import shutil
from pathlib import Path

from .config import HarnessPaths
from .db import Database
from .ids import new_id
from .util import sha256_file, utcnow


class EvidenceStore:
    def __init__(self, database: Database, paths: HarnessPaths):
        self.database = database
        self.paths = paths

    def add_file(
        self,
        campaign_id: str,
        source: Path,
        kind: str,
        *,
        candidate_id: str | None = None,
        worker_run_id: str | None = None,
        summary: str = "",
    ) -> dict[str, str | int]:
        source = source.resolve()
        digest = sha256_file(source)
        destination = self.paths.evidence_dir / "sha256" / digest[:2] / digest[2:4] / digest
        destination.parent.mkdir(parents=True, exist_ok=True)
        if not destination.exists():
            shutil.copyfile(source, destination)
            destination.chmod(0o600)
        evidence_id = new_id("E")
        size = destination.stat().st_size
        mime_type = mimetypes.guess_type(source.name)[0] or "application/octet-stream"
        with self.database.transaction(immediate=True) as connection:
            existing = connection.execute(
                "SELECT id, uri FROM evidence WHERE campaign_id=? AND sha256=? AND kind=?",
                (campaign_id, digest, kind),
            ).fetchone()
            if existing:
                return {"id": existing["id"], "uri": existing["uri"], "sha256": digest, "size_bytes": size}
            connection.execute(
                """
                INSERT INTO evidence(
                    id, campaign_id, candidate_id, worker_run_id, kind, uri, sha256,
                    size_bytes, mime_type, summary, created_at
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    evidence_id,
                    campaign_id,
                    candidate_id,
                    worker_run_id,
                    kind,
                    str(destination),
                    digest,
                    size,
                    mime_type,
                    summary,
                    utcnow(),
                ),
            )
            self.database.event(
                campaign_id,
                "evidence",
                evidence_id,
                "EVIDENCE_ADDED",
                {"kind": kind, "sha256": digest, "source_name": source.name},
                connection,
            )
        return {"id": evidence_id, "uri": str(destination), "sha256": digest, "size_bytes": size}
