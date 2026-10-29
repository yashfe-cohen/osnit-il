"""Microsoft Access (.mdb / .accdb): the pure-Python reader against ground truth written by Jackcess, and the deep
import — fact tables take their parent's identity through the foreign key."""
import json
import os
import shutil
import tempfile
import unittest
import zipfile
from datetime import datetime
from decimal import Decimal

from osnit.detect import detect
from osnit.importdb import cheap_count
from osnit.importqueue import ImportQueue
from osnit.mdb import AccessDB, AccessError, access_tables, display
from osnit.semantic import header_type
from tests import helpers

HERE = os.path.dirname(__file__)


def _same(v, j, t):
    """Our native value vs the Jackcess dump (strings; BYTE signed there, unsigned in Access)."""
    if j is None or v is None:
        return v is None and j is None
    if t == "BOOLEAN":
        return ("true" if v else "false") == j
    if t in ("OLE", "BINARY"):
        return j == f"bytes:{len(v)}"
    if t == "DOUBLE":
        return float(j) == v
    if t == "FLOAT":
        return abs(float(j) - v) <= 1e-6 * max(1, abs(v))
    if t in ("MONEY", "NUMERIC"):
        return Decimal(j) == v
    if t == "SHORT_DATE_TIME":
        return abs((datetime.fromisoformat(j) - v).total_seconds()) < 0.002
    if t == "BYTE":
        return int(j) % 256 == v
    if t in ("LONG", "INT", "BIG_INT"):
        return int(j) == v
    return str(v) == j


class AccessReader(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.mkdtemp()
        with zipfile.ZipFile(os.path.join(HERE, "access", "samples.zip")) as z:
            z.extractall(cls.dir)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.dir, ignore_errors=True)

    def path(self, name):
        return os.path.join(self.dir, name)

    def test_every_value_matches_ground_truth(self):
        # Jet 4 (.mdb) and ACE (.accdb): Hebrew compressed/plain text, memos inline / one page / page chains,
        # deleted rows, rows moved by an update (overflow), GUID, NUMERIC, MONEY, dates, OLE, a 120-column table
        for name in ("sample.mdb", "sample.accdb"):
            with open(self.path(name + ".json"), encoding="utf-8") as f:
                truth = json.load(f)
            with AccessDB(self.path(name)) as db:
                self.assertEqual(sorted(db.table_names()), sorted(truth))
                for tn, tr in truth.items():
                    cols = [c.name for c in db.table(tn).columns]
                    self.assertEqual(cols, tr["cols"], tn)
                    got = sorted(([r[c] for c in cols] for r in db.rows(tn)), key=lambda r: str(r[0]))
                    want = sorted(tr["rows"], key=lambda r: str(r[0]))
                    self.assertEqual(len(got), len(want), (name, tn))
                    for a, b in zip(got, want):
                        for c, t, x, y in zip(cols, tr["types"], a, b):
                            self.assertTrue(_same(x, y, t), (name, tn, c, x, y))
                self.assertIn(("הזמנות", "לקוח", "לקוחות", "מזהה"), db.relationships())

    def test_counts_detection_and_display(self):
        self.assertEqual(cheap_count(self.path("sample.accdb"))["לקוחות"], (59, True))
        with open(self.path("sample.mdb"), "rb") as f:
            self.assertEqual(detect(f.read(16384), "x.bin")["kind"], "access")
        self.assertEqual(display(Decimal("-4.8700")), "-4.87")
        self.assertEqual(display(datetime(1990, 5, 1)), "1990-05-01")
        self.assertEqual(display(b"\x01\x02"), "[קובץ / נתון בינארי, 2 בתים]")
        bad = self.path("not.mdb")
        with open(bad, "wb") as f:
            f.write(b"hello" * 100)
        with self.assertRaises(AccessError):
            AccessDB(bad)

    def test_fact_table_takes_its_parents_identity(self):
        tables = {t: (cols, list(rows)) for t, cols, rows in access_tables(self.path("sample.mdb"))}
        cols, rows = tables["הזמנות"]
        self.assertIn("לקוחות.שם מלא", cols)
        first = next(r for r in rows if r["לקוח"] == 2)
        self.assertEqual(first["לקוחות.שם מלא"], "שרה כהן")
        self.assertEqual(first["לקוחות.Email"], "user1@gmail.com")
        self.assertNotIn("לקוחות.שם מלא", tables["לקוחות"][0])     # a table with its own identity is not joined
        self.assertFalse(any("." in c for c in tables["Products"][0]))

    def test_product_name_is_not_a_person(self):
        for h in ("ProductName", "CategoryName", "שם_מוצר", "שם קובץ"):
            self.assertNotEqual(header_type(h)[0], "name", h)
        for h in ("CustomerName", "ContactName", "שם_לקוח", "שם מלא"):
            self.assertEqual(header_type(h)[0], "name", h)


class AccessImport(unittest.TestCase):
    def setUp(self):
        self.srv, self.base, self.store, self.eng, self.svc, _ = helpers.make([])
        self.dir = tempfile.mkdtemp()
        with zipfile.ZipFile(os.path.join(HERE, "access", "samples.zip")) as z:
            z.extract("sample.accdb", self.dir)
        self.q = ImportQueue(self.eng, inbox=os.path.join(self.dir, "inbox"))

    def tearDown(self):
        self.srv.shutdown()
        shutil.rmtree(self.dir, ignore_errors=True)

    def test_import_links_orders_to_the_customer(self):
        job = self.q.add_file(os.path.join(self.dir, "sample.accdb"), review=True)
        self.assertEqual(job["detected"]["kind"], "access")
        self.q.run_pending()
        a = json.loads(self.store.q1("SELECT preview FROM imports WHERE id=?", (job["id"],))["preview"])
        tables = {t["table"]: t for t in a["tables"]}
        types = {c["name"]: c["type"] for c in tables["לקוחות"]["columns"]}
        self.assertEqual((types["שם מלא"], types["Email"], types["ת_ז"]), ("name", "email", "national_id"))
        self.assertEqual(tables["הזמנות"]["rows"], 120)
        self.assertTrue(self.q.approve(job["id"]))
        self.q.run_pending()
        st = self.store.q1("SELECT state, error FROM imports WHERE id=?", (job["id"],))
        self.assertEqual(st["state"], "done", st["error"])
        p = self.store.q1("SELECT id FROM entities WHERE type='person' AND display='שרה כהן'")
        linked = {r["display"] for r in self.store.q(
            "SELECT o.display FROM relations x JOIN entities o ON o.id = CASE WHEN x.a_id=? THEN x.b_id ELSE x.a_id END "
            "WHERE (x.a_id=? OR x.b_id=?) AND o.type='address'", (p["id"],) * 3)}
        self.assertIn("הרצל 43, חיפה", linked)                  # an order's shipping address -> its customer
        self.assertIsNone(self.store.q1("SELECT 1 FROM entities WHERE type='person' AND display LIKE 'מוצר%'"))


if __name__ == "__main__":
    unittest.main()
