from __future__ import annotations

import unittest

from .helpers import HarnessFixture


class DatabaseTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = HarnessFixture()

    def tearDown(self) -> None:
        self.fixture.close()

    def test_schema_and_integrity(self) -> None:
        summary = self.fixture.database.summary()
        self.assertEqual(summary["integrity"], "ok")
        self.assertEqual(summary["campaigns"], 0)
        self.assertIn("knowledge_documents", summary)

    def test_events_are_append_only_sequences(self) -> None:
        self.fixture.database.event(None, "system", "one", "TEST", {"value": 1})
        self.fixture.database.event(None, "system", "two", "TEST", {"value": 2})
        rows = self.fixture.database.all("SELECT sequence, entity_id FROM events ORDER BY sequence")
        self.assertEqual([row["entity_id"] for row in rows], ["one", "two"])
        self.assertLess(rows[0]["sequence"], rows[1]["sequence"])


if __name__ == "__main__":
    unittest.main()
