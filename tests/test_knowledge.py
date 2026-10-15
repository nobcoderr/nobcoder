from __future__ import annotations

import unittest

from bbp_harness.knowledge import KnowledgeIndex

from .helpers import HarnessFixture


class KnowledgeIndexTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = HarnessFixture()
        self.knowledge = KnowledgeIndex(self.fixture.database)

    def tearDown(self) -> None:
        self.fixture.close()

    def test_indexes_and_retrieves_top_k(self) -> None:
        root = self.fixture.root / "knowledge"
        root.mkdir()
        (root / "authz.md").write_text("object authorization tenant policy protected resource", encoding="utf-8")
        (root / "parser.md").write_text("canonicalization serializer protocol framing", encoding="utf-8")
        result = self.knowledge.index_roots([root])
        self.assertEqual(result["documents_indexed"], 2)
        matches = self.knowledge.query("tenant authorization", top_k=1)
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0]["title"], "authz")

    def test_reindex_unchanged_is_idempotent(self) -> None:
        root = self.fixture.root / "knowledge"
        root.mkdir()
        (root / "SKILL.md").write_text("---\nname: example-skill\n---\nbody", encoding="utf-8")
        first = self.knowledge.index_roots([root])
        second = self.knowledge.index_roots([root])
        self.assertEqual(first["documents_indexed"], 1)
        self.assertEqual(second["documents_unchanged"], 1)
        self.assertEqual(self.fixture.database.one("SELECT count(*) FROM knowledge_documents")[0], 1)


if __name__ == "__main__":
    unittest.main()
