import os
import tempfile
import unittest

from osnit.detect import detect
from osnit.importqueue import ImportQueue, estimate_total
from tests import helpers

SQL = """CREATE TABLE `contacts` (`id` int, `full_name` varchar(80), `email` varchar(80), `phone` varchar(30));
INSERT INTO `contacts` (`id`,`full_name`,`email`,`phone`) VALUES
(1,'יונתן חייט','yonatan.hayat@alpha.co.il','050-8317945'),
(2,'דנה לוי','dana@gamma.co.il','054-6613972');"""


class Queue(unittest.TestCase):
    def setUp(self):
        self.srv, self.base, self.store, self.eng, self.svc, _ = helpers.make([])
        self.dir = tempfile.mkdtemp()
        self.q = ImportQueue(self.eng, inbox=os.path.join(self.dir, "inbox"))

    def tearDown(self):
        self.srv.shutdown()

    def test_sql_dump_detect_estimate_and_import(self):
        p = os.path.join(self.dir, "old.sql")
        with open(p, "w", encoding="utf-8") as f:
            f.write(SQL)
        d = detect(SQL.encode(), "old.sql")
        self.assertEqual(d["kind"], "sql_dump")
        self.assertIn("name", d["tables"][0]["recognised"])
        self.assertEqual(estimate_total(p), 2)
        job = self.q.add_file(p, delete_raw=True, move=True)
        self.assertEqual(job["detected"]["kind"], "sql_dump")
        self.q.run_pending()
        row = self.q.list()[0]
        self.assertEqual(row["state"], "done")
        self.assertEqual(row["records"], 2)
        self.assertEqual(row["done"], row["total"])
        self.assertTrue(self.store.q1("SELECT 1 FROM entities WHERE key='yonatan.hayat@alpha.co.il'"))

    def test_upload_bytes_and_progress_fields(self):
        self.q.add_bytes("name,phone,email\nאבי כהן,050-8317945,avi@x.co.il\n".encode(), "list.csv")
        self.q.run_pending()
        row = self.q.list()[0]
        self.assertEqual(row["state"], "done")
        self.assertEqual(row["records"], 1)
        self.assertEqual(row["detected"], "csv")

    def test_inbox_autopickup(self):
        with open(os.path.join(self.q.inbox, "drop.jsonl"), "w", encoding="utf-8") as f:
            f.write('{"name":"רונית לוי","email":"ronit@bgu.ac.il"}\n')
        self.q.run_pending()
        self.assertEqual(self.q.list()[0]["state"], "done")
        self.assertTrue(self.store.q1("SELECT 1 FROM entities WHERE key='ronit@bgu.ac.il'"))

    def test_bad_file_marks_error_not_crash(self):
        self.q.add_bytes(b"\x00\x01\x02 not a real db contents here", "junk.sqlite")
        self.q.run_pending()
        self.assertEqual(self.q.list()[0]["state"], "error")
        self.assertTrue(self.q.list()[0]["error"])
