import os
import shutil
import tempfile
import unittest

from osnit.importdb import import_db
from osnit.ingest import import_path
from osnit.store import Store
from tests import helpers


class TestFts5Search(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.tmpdir, "test_fts.db")
        self.store = Store(self.db_path)

    def tearDown(self):
        try:
            self.store.close()
        except Exception:
            pass
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_direct_index_and_search(self):
        self.store.index_document_fts(
            source_id=10,
            file_path="data/archive/dump.sql",
            location_ref="table=wp_users:line=145",
            raw_text="id: 145 | user_login: yoni | email: yoni@example.com | national_id: 123456782 | notes: test order"
        )

        # 1. Search by national ID
        res_id = self.store.search_fts("123456782")
        self.assertEqual(len(res_id), 1)
        self.assertEqual(res_id[0]["source_id"], 10)
        self.assertEqual(res_id[0]["location_ref"], "table=wp_users:line=145")
        self.assertIn("<b>123456782</b>", res_id[0]["snippet"])

        # 2. Search by email
        res_email = self.store.search_fts("yoni@example.com")
        self.assertEqual(len(res_email), 1)
        self.assertEqual(res_email[0]["file_path"], "data/archive/dump.sql")

        # 3. Search by notes term
        res_notes = self.store.search_fts("order")
        self.assertEqual(len(res_notes), 1)

    def test_batch_indexing(self):
        items = [
            (1, "a.csv", "table=contacts:line=1", "name: Dana Cohen | phone: 0501112233"),
            (1, "a.csv", "table=contacts:line=2", "name: Ron Levi | phone: 0524445566"),
            (2, "b.csv", "table=orders:line=1", "order_id: 9988 | note: delivery to Tel Aviv"),
        ]
        self.store.index_documents_fts_batch(items)

        # Search across different files/tables
        res1 = self.store.search_fts("Dana")
        self.assertEqual(len(res1), 1)
        self.assertEqual(res1[0]["location_ref"], "table=contacts:line=1")

        res2 = self.store.search_fts("delivery")
        self.assertEqual(len(res2), 1)
        self.assertEqual(res2[0]["location_ref"], "table=orders:line=1")

    def test_import_db_automatically_indexes_all_rows(self):
        srv, base, store, eng, svc, _ = helpers.make([])
        try:
            csv_path = os.path.join(self.tmpdir, "orders.csv")
            with open(csv_path, "w", encoding="utf-8") as f:
                f.write("order_num,customer,comment\n")
                f.write("ORD-101,Yonatan Hayat,deliver before 5pm\n")
                f.write("ORD-102,Dana Levi,gate code is 1234\n")

            import_db(eng, csv_path, label="orders")

            # Search term from comment column (unmapped raw column)
            res = store.search_fts("gate code")
            self.assertGreaterEqual(len(res), 1)
            match = res[0]
            self.assertIn("line=2", match["location_ref"])
            self.assertIn("orders", match["location_ref"])
            self.assertIn("1234", match["raw_text"])
        finally:
            srv.shutdown()

    def test_import_path_indexes_document(self):
        srv, base, store, eng, svc, _ = helpers.make([])
        try:
            doc_path = os.path.join(self.tmpdir, "report.txt")
            with open(doc_path, "w", encoding="utf-8") as f:
                f.write("CONFIDENTIAL REPORT: Subject Yonatan Hayat met with director at Tel Aviv office.")

            import_path(eng, doc_path)

            res = store.search_fts("CONFIDENTIAL")
            self.assertGreaterEqual(len(res), 1)
            self.assertIn("report.txt", res[0]["file_path"])
            self.assertIn("<b>CONFIDENTIAL</b>", res[0]["snippet"])
        finally:
            srv.shutdown()

    def test_safe_query_syntax(self):
        # Must not raise sqlite3.OperationalError on punctuation or unmatched quotes
        res = self.store.search_fts('test "unmatched (bracket) @domain.com *?^')
        self.assertIsInstance(res, list)


if __name__ == "__main__":
    unittest.main()
