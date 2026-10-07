import os
import tempfile
import unittest

import openpyxl

from osnit.detect import detect
from osnit.importdb import import_db
from osnit.xlsx import read_xlsx
from tests import helpers


class Excel(unittest.TestCase):
    def setUp(self):
        self.srv, self.base, self.store, self.eng, self.svc, _ = helpers.make([])
        self.dir = tempfile.mkdtemp()

    def tearDown(self):
        self.srv.shutdown()

    def make(self, rows, name="c.xlsx"):
        wb = openpyxl.Workbook()
        ws = wb.active
        for r in rows:
            ws.append(r)
        p = os.path.join(self.dir, name)
        wb.save(p)
        return p

    def test_contacts_sheet_becomes_records(self):
        p = self.make([["שם מלא", "נייד", "דוא\"ל", "חברה"],
                       ["יונתן חייט", "050-8317945", "yonatan@alpha.co.il", "אלפא"],
                       ["דנה לוי", "054-6613972", "dana@gamma.co.il", "גמא"]])
        with open(p, "rb") as f:
            self.assertEqual(detect(f.read(4096), "c.xlsx")["kind"], "xlsx")
        res = import_db(self.eng, p, label="excel")
        self.assertEqual(res["records"], 2)
        self.assertTrue(self.store.q1("SELECT 1 FROM entities WHERE key='yonatan@alpha.co.il'"))
        # name is tied to its own row's phone, not the other row's
        rel = self.store.q("""SELECT p.key pk, o.key ok FROM relations r
            JOIN entities p ON p.id=r.a_id JOIN entities o ON o.id=r.b_id
            WHERE r.kind='contact'""")
        pairs = {(x["pk"], x["ok"]) for x in rel} | {(x["ok"], x["pk"]) for x in rel}
        self.assertIn(("חייט יונתנ", "+972508317945"), pairs)
        self.assertNotIn(("חייט יונתנ", "+972546613972"), pairs)

    def test_header_offset_columns(self):
        # gaps and extra columns still map by header
        p = self.make([["id", "full name", "", "phone", "email"],
                       ["7", "Dana Cohen", "", "03-5551234", "dana@x.co.il"]])
        res = import_db(self.eng, p)
        self.assertEqual(res["records"], 1)
        self.assertTrue(self.store.q1("SELECT 1 FROM entities WHERE key='dana@x.co.il'"))

    def test_reader_rows(self):
        p = self.make([["a", "b"], ["1", "2"], ["", ""], ["3", "4"]])
        sheets = list(read_xlsx(p))
        self.assertEqual(sheets[0][1], ["a", "b"])
        self.assertEqual(len(sheets[0][2]), 2)   # blank row dropped
