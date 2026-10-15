from __future__ import annotations

import tempfile
from pathlib import Path

from bbp_harness.config import HarnessConfig, HarnessPaths
from bbp_harness.db import Database
from bbp_harness.util import utcnow


class HarnessFixture:
    def __init__(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.paths = HarnessPaths.discover(self.root / "state-home")
        self.paths.ensure()
        self.database = Database(self.paths.database)
        self.database.migrate()
        self.config = HarnessConfig(
            knowledge_roots=[],
            report_databases=[],
            max_concurrency=3,
            worker_timeout_seconds=30,
            knowledge_top_k=4,
        )

    def close(self) -> None:
        self.temporary.cleanup()

    def seed_campaign(self, campaign_id: str = "CAM-test") -> str:
        now = utcnow()
        target = self.root / "target"
        target.mkdir(exist_ok=True)
        with self.database.connect() as connection:
            connection.execute(
                "INSERT INTO targets(root_path, created_at, updated_at) VALUES(?,?,?)",
                (str(target), now, now),
            )
            target_id = connection.execute("SELECT id FROM targets WHERE root_path=?", (str(target),)).fetchone()[0]
            connection.execute(
                """
                INSERT INTO campaigns(
                    id, target_id, objective, status, scope_status, max_workers,
                    max_waves, created_at, updated_at
                ) VALUES(?,?,?,'ACTIVE','PROVEN',3,4,?,?)
                """,
                (campaign_id, target_id, "test objective", now, now),
            )
        return campaign_id
