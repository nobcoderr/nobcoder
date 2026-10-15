from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from typing import Any

from .db import Database
from .ids import new_id
from .util import canonical_json, utcnow


TERMINAL_JOB_STATES = {"PASS", "FAIL", "BLOCKED", "KILLED", "CANCELLED"}


class Scheduler:
    def __init__(self, database: Database):
        self.database = database

    def create_job(
        self,
        campaign_id: str,
        role: str,
        *,
        lane: str = "",
        priority: int = 50,
        depends_on: list[str] | None = None,
        input_data: dict[str, Any] | None = None,
        budget: dict[str, Any] | None = None,
        max_attempts: int = 2,
        job_id: str | None = None,
    ) -> str:
        identity = job_id or new_id("J")
        dependencies = depends_on or []
        status = "READY" if not dependencies else "PENDING"
        now = utcnow()
        with self.database.transaction(immediate=True) as connection:
            connection.execute(
                """
                INSERT INTO worker_jobs(
                    id, campaign_id, role, lane, status, priority, depends_on_json,
                    input_json, budget_json, max_attempts, created_at, updated_at
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    identity,
                    campaign_id,
                    role,
                    lane,
                    status,
                    priority,
                    canonical_json(dependencies),
                    canonical_json(input_data or {}),
                    canonical_json(budget or {}),
                    max_attempts,
                    now,
                    now,
                ),
            )
            self.database.event(
                campaign_id,
                "worker_job",
                identity,
                "JOB_CREATED",
                {"role": role, "lane": lane, "depends_on": dependencies},
                connection,
            )
        return identity

    def refresh(self, campaign_id: str) -> dict[str, int]:
        ready = 0
        blocked = 0
        with self.database.transaction(immediate=True) as connection:
            pending = connection.execute(
                "SELECT * FROM worker_jobs WHERE campaign_id=? AND status='PENDING' ORDER BY priority, created_at",
                (campaign_id,),
            ).fetchall()
            for job in pending:
                dependencies = json.loads(job["depends_on_json"])
                if not dependencies:
                    next_status = "READY"
                else:
                    rows = connection.execute(
                        f"SELECT id, status FROM worker_jobs WHERE id IN ({','.join('?' for _ in dependencies)})",
                        dependencies,
                    ).fetchall()
                    status_by_id = {row["id"]: row["status"] for row in rows}
                    missing = [item for item in dependencies if item not in status_by_id]
                    failed = [item for item, status in status_by_id.items() if status in {"FAIL", "BLOCKED", "KILLED", "CANCELLED"}]
                    if missing or failed:
                        next_status = "BLOCKED"
                    elif all(status_by_id[item] == "PASS" for item in dependencies):
                        next_status = "READY"
                    else:
                        continue
                reason = "dependency failed or missing" if next_status == "BLOCKED" else ""
                connection.execute(
                    "UPDATE worker_jobs SET status=?, last_error=?, updated_at=? WHERE id=?",
                    (next_status, reason, utcnow(), job["id"]),
                )
                if next_status == "READY":
                    ready += 1
                else:
                    blocked += 1
        return {"ready": ready, "blocked": blocked}

    def reset_stale_leases(self, stale_seconds: int) -> int:
        cutoff = datetime.now(UTC) - timedelta(seconds=stale_seconds)
        with self.database.transaction(immediate=True) as connection:
            rows = connection.execute(
                "SELECT id, campaign_id, attempts, max_attempts FROM worker_jobs WHERE status='RUNNING' AND leased_at<?",
                (cutoff.isoformat(timespec="seconds"),),
            ).fetchall()
            for row in rows:
                next_status = "READY" if row["attempts"] < row["max_attempts"] else "FAIL"
                connection.execute(
                    "UPDATE worker_jobs SET status=?, leased_at=NULL, last_error='stale lease recovered', updated_at=? WHERE id=?",
                    (next_status, utcnow(), row["id"]),
                )
                self.database.event(
                    row["campaign_id"],
                    "worker_job",
                    row["id"],
                    "STALE_LEASE_RECOVERED",
                    {"new_status": next_status},
                    connection,
                )
        return len(rows)

    def claim_ready(self, campaign_id: str, limit: int) -> list[dict[str, Any]]:
        claimed: list[dict[str, Any]] = []
        with self.database.transaction(immediate=True) as connection:
            rows = connection.execute(
                """
                SELECT * FROM worker_jobs
                WHERE campaign_id=? AND status='READY' AND attempts < max_attempts
                ORDER BY priority ASC, created_at ASC
                LIMIT ?
                """,
                (campaign_id, limit),
            ).fetchall()
            now = utcnow()
            for row in rows:
                updated = connection.execute(
                    """
                    UPDATE worker_jobs
                    SET status='RUNNING', leased_at=?, attempts=attempts+1, updated_at=?
                    WHERE id=? AND status='READY'
                    """,
                    (now, now, row["id"]),
                )
                if updated.rowcount != 1:
                    continue
                item = dict(row)
                item["status"] = "RUNNING"
                item["attempts"] = int(row["attempts"]) + 1
                claimed.append(item)
                self.database.event(
                    campaign_id,
                    "worker_job",
                    row["id"],
                    "JOB_CLAIMED",
                    {"attempt": item["attempts"]},
                    connection,
                )
        return claimed

    def finish(self, job_id: str, status: str, error: str = "") -> None:
        if status not in TERMINAL_JOB_STATES:
            raise ValueError(f"invalid terminal job status: {status}")
        with self.database.transaction(immediate=True) as connection:
            job = connection.execute("SELECT * FROM worker_jobs WHERE id=?", (job_id,)).fetchone()
            if not job:
                raise KeyError(job_id)
            connection.execute(
                "UPDATE worker_jobs SET status=?, leased_at=NULL, last_error=?, updated_at=? WHERE id=?",
                (status, error, utcnow(), job_id),
            )
            self.database.event(
                job["campaign_id"],
                "worker_job",
                job_id,
                "JOB_FINISHED",
                {"status": status, "error": error},
                connection,
            )

    def cancel_lane(self, campaign_id: str, lane: str, reason: str) -> int:
        with self.database.transaction(immediate=True) as connection:
            rows = connection.execute(
                "SELECT id FROM worker_jobs WHERE campaign_id=? AND lane=? AND status IN ('PENDING','READY')",
                (campaign_id, lane),
            ).fetchall()
            connection.execute(
                """
                UPDATE worker_jobs SET status='CANCELLED', last_error=?, updated_at=?
                WHERE campaign_id=? AND lane=? AND status IN ('PENDING','READY')
                """,
                (reason, utcnow(), campaign_id, lane),
            )
            for row in rows:
                self.database.event(
                    campaign_id,
                    "worker_job",
                    row["id"],
                    "JOB_CANCELLED",
                    {"lane": lane, "reason": reason},
                    connection,
                )
        return len(rows)

    def counts(self, campaign_id: str) -> dict[str, int]:
        rows = self.database.all(
            "SELECT status, count(*) AS count FROM worker_jobs WHERE campaign_id=? GROUP BY status",
            (campaign_id,),
        )
        return {row["status"]: int(row["count"]) for row in rows}
