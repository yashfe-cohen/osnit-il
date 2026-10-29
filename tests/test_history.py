import time
import unittest

from osnit.importdb import import_db
from tests import helpers
from tests.helpers import PAGES

PAGE = '<div><h2>יונתן חייט</h2><p>מנכ"ל חברת אלפא בע"מ</p><p>טלפון: 050-8317945</p><p>yonatan.hayat@alpha.co.il</p></div>'


class History(unittest.TestCase):
    def setUp(self):
        PAGES.clear()
        PAGES["/team"] = (PAGE, "text/html; charset=utf-8")
        self.srv, self.base, self.store, self.eng, self.svc, _ = helpers.make(["/team"])

    def tearDown(self):
        self.srv.shutdown()

    def rescan(self):
        row = self.store.q1("SELECT id FROM sources WHERE url=?", (self.base + "/team",))
        self.store.update_source(row["id"], next_scan_at=0)
        time.sleep(0.01)
        self.eng.step(1)

    def test_removed_phone_is_marked_gone_with_event_and_since_summary(self):
        sid = self.svc.search("יונתן חייט")["subject_id"]
        self.eng.drain()
        mark = time.time()
        PAGES["/team"] = (PAGE.replace("050-8317945", "054-6613972"), "text/html; charset=utf-8")
        self.rescan()
        p = self.svc.profile(sid, since=mark)
        phones = {x["value"]: x for x in p["identities"][0]["phones"]}
        self.assertEqual(phones["+972508317945"]["status"], "gone")
        self.assertEqual(phones["+972546613972"]["status"], "active")
        self.assertTrue(phones["+972546613972"]["is_new"])
        self.assertFalse(phones["+972508317945"]["is_new"])
        self.assertEqual(p["since"]["new"], 1)
        self.assertEqual(p["since"]["gone"], 0)        # it disappeared, but was last seen before `mark`
        gone = [e for e in p["events"] if e["type"] == "gone"]
        self.assertEqual([g["data"]["value"] for g in gone], ["+972508317945"])
        self.assertTrue(any(t["what"] == "gone" and t["value"] == "+972508317945" for t in p["timeline"]))
        # rescanning again does not repeat the "gone" alert
        self.rescan()
        self.assertEqual(len([e for e in self.svc.profile(sid)["events"] if e["type"] == "gone"]), 1)

    def test_unchanged_page_keeps_items_active(self):
        sid = self.svc.search("יונתן חייט")["subject_id"]
        self.eng.drain()
        self.rescan()
        p = self.svc.profile(sid)
        self.assertTrue(all(x["status"] == "active" for x in p["identities"][0]["phones"]))

    def test_imported_records_are_historical(self):
        import json, os, tempfile
        path = os.path.join(tempfile.mkdtemp(), "x.jsonl")
        with open(path, "w", encoding="utf-8") as f:
            f.write(json.dumps({"name": "יונתן חייט", "phone": "052-4471893"}) + "\n")
        sid = self.svc.search("יונתן חייט")["subject_id"]
        import_db(self.eng, path)
        p = self.svc.profile(sid)
        st = {x["value"]: x["status"] for i in p["identities"] for x in i["phones"]}
        st.update({x["value"]: x["status"] for x in (p["unattributed"] or {}).get("phones", [])})
        self.assertEqual(st["+972524471893"], "historical")


if __name__ == "__main__":
    unittest.main()
