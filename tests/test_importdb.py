import json
import os
import sqlite3
import tempfile
import unittest

from osnit.importdb import detect_columns, import_db, parse_ts
from tests import helpers


def make_sqlite(path):
    con = sqlite3.connect(path)
    con.execute('CREATE TABLE people("שם מלא" TEXT, "טלפון" TEXT, "מייל" TEXT, "חברה" TEXT, "תפקיד" TEXT, url TEXT, found_at TEXT)')
    con.executemany("INSERT INTO people VALUES(?,?,?,?,?,?,?)", [
        ("יונתן חייט", "050-8317945", "yonatan.hayat@alpha.co.il", 'אלפא בע"מ', 'מנכ"ל', "https://alpha.co.il/team", "2019-03-04"),
        ("חייט יונתן", "052-4471893", "info@alpha.co.il", "", "", "", "2021-06-01"),
        ("דנה לוי", "054-6613972", "dana@gamma.co.il", "גמא", "מהנדסת", "", "04/05/2020"),
        ("", "", "", "", "", "", ""),
    ])
    con.execute("CREATE TABLE pages(url TEXT, content TEXT, collected_at INTEGER)")
    con.execute("INSERT INTO pages VALUES(?,?,?)", ("https://news.example.org/a",
                "<p>Jonathan Hayat, CEO of Alpha Ltd. Contact jhayat@alpha.co.il</p>", 1546300800))
    con.commit()
    con.close()


class ImportDb(unittest.TestCase):
    def setUp(self):
        self.srv, self.base, self.store, self.eng, self.svc, _ = helpers.make([])
        self.dir = tempfile.mkdtemp()

    def tearDown(self):
        self.srv.shutdown()

    def test_columns_and_dates(self):
        cm = detect_columns(["שם מלא", "Phone_Number", "E_Mail", "company", "notes"])
        self.assertEqual(cm, {"name": "שם מלא", "phone": "Phone_Number", "email": "E_Mail", "org": "company"})
        self.assertEqual(parse_ts("2019-03-04"), parse_ts("04/03/2019"))
        self.assertEqual(parse_ts(1546300800000), 1546300800.0)

    def test_sqlite_import_feeds_existing_subject_with_history(self):
        sid = self.svc.search("יונתן חייט")["subject_id"]       # subject exists before import -> live findings
        path = os.path.join(self.dir, "old.db")
        make_sqlite(path)
        res = import_db(self.eng, path, label="old-tool", delete_raw=True)
        self.assertEqual((res["tables"], res["records"], res["documents"], res["skipped"]), (2, 3, 1, 1))
        self.assertTrue(res["deleted"])
        self.assertFalse(os.path.exists(path))                   # raw input removed after import
        self.assertEqual(res["urls_queued"], 1)                   # original page queued for re-verification
        prof = self.svc.profile(sid)
        emails = {e["value"]: e for i in prof["identities"] for e in i["emails"]}
        self.assertIn("yonatan.hayat@alpha.co.il", emails)
        self.assertIn("jhayat@alpha.co.il", emails)             # from the stored page text, via full extraction
        self.assertLess(emails["info@alpha.co.il"]["confidence"], 0.5)   # role mailbox is weak
        first = emails["yonatan.hayat@alpha.co.il"]["first_seen"]
        self.assertAlmostEqual(first, parse_ts("2019-03-04"), delta=1)   # historical discovery date kept
        self.assertTrue(any(e["type"] == "finding" for e in prof["events"]))
        roles = [r["value"] for i in prof["identities"] for r in i["roles"]]
        self.assertTrue(any("מנכ" in r for r in roles))

    def test_history_not_overwritten_by_older_import(self):
        path = os.path.join(self.dir, "a.jsonl")
        with open(path, "w", encoding="utf-8") as f:
            f.write(json.dumps({"name": "דנה לוי", "email": "dana@gamma.co.il", "date": "2023-01-01"}) + "\n")
        import_db(self.eng, path)
        with open(path, "w", encoding="utf-8") as f:
            f.write(json.dumps({"name": "דנה לוי", "email": "dana@gamma.co.il", "date": "2018-01-01"}) + "\n")
        import_db(self.eng, path)
        e = self.store.q1("SELECT first_seen, last_seen FROM entities WHERE key='dana@gamma.co.il'")
        self.assertAlmostEqual(e["first_seen"], parse_ts("2018-01-01"), delta=1)
        self.assertAlmostEqual(e["last_seen"], parse_ts("2023-01-01"), delta=1)

    def test_csv_with_mapping(self):
        path = os.path.join(self.dir, "x.csv")
        with open(path, "w", encoding="utf-8") as f:
            f.write("who,num,em\nדנה לוי,054-6613972,dana@gamma.co.il\n")
        res = import_db(self.eng, path, mapping={"tables": {"default": {"name": "who", "phone": "num", "email": "em"}}})
        self.assertEqual(res["records"], 1)
        self.assertFalse(os.path.exists(path) is False)          # not deleted without delete_raw
        rel = self.store.q1("SELECT COUNT(*) n FROM relations")["n"]
        self.assertGreaterEqual(rel, 2)


if __name__ == "__main__":
    unittest.main()
