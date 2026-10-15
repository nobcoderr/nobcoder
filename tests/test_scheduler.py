from __future__ import annotations

import unittest

from bbp_harness.scheduler import Scheduler

from .helpers import HarnessFixture


class SchedulerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = HarnessFixture()
        self.campaign_id = self.fixture.seed_campaign()
        self.scheduler = Scheduler(self.fixture.database)

    def tearDown(self) -> None:
        self.fixture.close()

    def test_dependency_controls_readiness(self) -> None:
        first = self.scheduler.create_job(self.campaign_id, "mapper")
        second = self.scheduler.create_job(self.campaign_id, "researcher", depends_on=[first])
        self.assertEqual(self.scheduler.counts(self.campaign_id), {"PENDING": 1, "READY": 1})
        claimed = self.scheduler.claim_ready(self.campaign_id, 1)
        self.assertEqual(claimed[0]["id"], first)
        self.scheduler.finish(first, "PASS")
        refresh = self.scheduler.refresh(self.campaign_id)
        self.assertEqual(refresh["ready"], 1)
        self.assertEqual(self.fixture.database.one("SELECT status FROM worker_jobs WHERE id=?", (second,))[0], "READY")

    def test_failed_dependency_blocks_consumer(self) -> None:
        first = self.scheduler.create_job(self.campaign_id, "mapper")
        second = self.scheduler.create_job(self.campaign_id, "researcher", depends_on=[first])
        self.scheduler.claim_ready(self.campaign_id, 1)
        self.scheduler.finish(first, "FAIL", "fixture failure")
        self.scheduler.refresh(self.campaign_id)
        self.assertEqual(self.fixture.database.one("SELECT status FROM worker_jobs WHERE id=?", (second,))[0], "BLOCKED")


if __name__ == "__main__":
    unittest.main()
