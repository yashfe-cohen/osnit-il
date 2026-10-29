import io
import unittest
import uuid
import zipfile

from tests import helpers
from tests.helpers import PAGES, H

TEAM = """<html><head><title>הצוות שלנו</title></head><body>
<div class="card"><h2>יונתן חייט</h2><p>מנכ"ל חברת אלפא בע"מ</p>
<p>טלפון: 050-831-7945</p><a href="mailto:yonatan.hayat@alpha.co.il">שלח מייל</a></div>
<div class="card"><h2>ד"ר רונית לוי</h2><p>סמנכ"לית מחקר</p><a href="mailto:ronit@alpha.co.il">ronit@alpha.co.il</a></div>
<a href="/news">חדשות</a> <a href="/private/secret">x</a> <a href="/doc.txt">מסמך</a></body></html>"""
NEWS = ('<html><head><title>News</title></head><body><p>Jonathan Hayat, CEO of Alpha Ltd, said on Monday that '
        'contact is via jhayat@alpha.co.il or +972-52-4471893.</p></body></html>')
OTHER = '<html><body><p>Yonatan Hayat, Director at Beta Ltd. Reach him at yh@beta-corp.com.</p></body></html>'
DOC = "קורות חיים\nיונתן חייט\nנייד 050-8317945\nהמייל: yonatan.hayat@alpha.co.il\n"


def docx(text):
    b = io.BytesIO()
    with zipfile.ZipFile(b, "w") as z:
        z.writestr("word/document.xml", '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body>'
                   + "".join(f"<w:p><w:r><w:t>{ln}</w:t></w:r></w:p>" for ln in text.split("\n")) + "</w:body></w:document>")
    return b.getvalue()


class Pipeline(unittest.TestCase):
    def setUp(self):
        H.hits.clear()
        PAGES.clear()
        PAGES.update({"/team": (TEAM, "text/html; charset=utf-8"), "/news": (NEWS, "text/html"),
                      "/other": (OTHER, "text/html"), "/doc.txt": (DOC, "text/plain; charset=utf-8"),
                      "/private/secret": ("<p>יונתן חייט secret@x.com</p>", "text/html"),
                      "/cv.docx": (docx(DOC), "application/octet-stream")})
        self.srv, self.base, self.store, self.eng, self.svc, self.prov = helpers.make(["/team", "/other", "/news", "/cv.docx"])

    def tearDown(self):
        self.srv.shutdown()

    def test_end_to_end(self):
        res = self.svc.search("יונתן חייט")
        sid = res["subject_id"]
        self.assertEqual(res["profile"]["identities"], [])          # empty DB: instant but empty
        self.eng.drain()
        prof = self.svc.profile(sid)
        self.assertIn("/robots.txt", H.hits)
        self.assertNotIn("/private/secret", H.hits)                  # robots respected
        self.assertGreaterEqual(len(prof["identities"]), 2)          # alpha cluster vs beta cluster
        alpha = next(i for i in prof["identities"] if any("alpha" in o["value"].lower() or "אלפא" in o["value"] for o in i["orgs"]))
        emails = {e["value"] for e in alpha["emails"]}
        self.assertIn("yonatan.hayat@alpha.co.il", emails)
        self.assertIn("jhayat@alpha.co.il", emails)                  # Latin variant merged via name variants
        phones = {p["value"] for p in alpha["phones"]}
        self.assertTrue({"+972508317945", "+972524471893"} <= phones)
        self.assertTrue(any("מנכ" in r["value"] or "CEO" in r["value"] for r in alpha["roles"]))
        em = next(e for e in alpha["emails"] if e["value"] == "yonatan.hayat@alpha.co.il")
        self.assertGreaterEqual(em["confidence"], 0.85)
        self.assertGreaterEqual(em["sources"], 2)                    # seen in page + documents
        self.assertEqual(em["confidence"], 0.85)                     # same site => not independent corroboration
        self.assertTrue(em["evidence"][0]["url"].startswith(self.base))
        self.assertTrue(any(d["kind"] in ("txt", "docx") for d in alpha["documents"]))
        beta = next(i for i in prof["identities"] if i is not alpha)
        self.assertNotIn("yonatan.hayat@alpha.co.il", {e["value"] for e in beta["emails"]})
        self.assertTrue(any(e["type"] == "finding" for e in prof["events"]))
        self.assertGreater(len(prof["subject"]["variants"]), 5)

    def test_no_rework_and_change_detection(self):
        sid = self.svc.search("יונתן חייט")["subject_id"]
        self.eng.drain()
        n_team = H.hits.count("/team")
        row = self.store.q1("SELECT * FROM sources WHERE url=?", (self.base + "/team",))
        self.assertEqual(row["state"], "scanned")
        # force due; same content => hash match, no re-extraction, last_seen refreshed
        self.store.update_source(row["id"], next_scan_at=0)
        before = self.store.q1("SELECT COUNT(*) n FROM evidence")["n"]
        self.eng.step(1)
        self.assertEqual(self.store.q1("SELECT COUNT(*) n FROM evidence")["n"], before)
        self.assertGreater(self.eng.stats["unchanged"], 0)
        self.assertEqual(self.store.q1("SELECT scan_interval FROM sources WHERE id=?", (row["id"],))["scan_interval"],
                         self.eng.cfg.rescan_min * 2)
        # change content: phone replaced -> new evidence + removed evidence recorded
        PAGES["/team"] = (TEAM.replace("050-831-7945", "054-661-3972"), "text/html")
        self.store.update_source(row["id"], next_scan_at=0)
        self.eng.step(1)
        ch = self.store.q("SELECT * FROM source_changes WHERE source_id=? ORDER BY id", (row["id"],))
        self.assertEqual([c["kind"] for c in ch], ["new", "changed"])
        self.assertGreater(ch[-1]["added"], 0)
        self.assertGreater(ch[-1]["removed"], 0)
        old = self.store.q1("SELECT e.id FROM entities e WHERE type='phone' AND key='+972508317945'")
        new = self.store.q1("SELECT e.id FROM entities e WHERE type='phone' AND key='+972546613972'")
        self.assertTrue(old and new)                                 # history kept; old no longer "seen" on this page
        ev = self.store.q1("SELECT first_seen, last_seen FROM evidence WHERE entity_id=? AND source_id=?", (old["id"], row["id"]))
        self.assertLess(ev["last_seen"], self.store.q1("SELECT last_scanned FROM sources WHERE id=?", (row["id"],))["last_scanned"])

    def test_backfill_shows_existing_data_instantly(self):
        self.svc.search("יונתן חייט")
        self.eng.drain()
        res = self.svc.search("Jonathan Hayat")                      # new subject, DB already knows him
        self.assertGreaterEqual(len(res["profile"]["identities"]), 1)

    def test_forget_erases_entity_and_links(self):
        self.svc.search("יונתן חייט")
        self.eng.drain()
        r = self.store.forget("yonatan.hayat@alpha.co.il")
        self.assertEqual(r["entities"], 1)
        self.assertGreater(r["relations"], 0)
        self.assertIsNone(self.store.q1("SELECT 1 FROM entities WHERE key='yonatan.hayat@alpha.co.il'"))
        self.assertEqual(self.store.q1("SELECT COUNT(*) n FROM rel_evidence WHERE relation_id NOT IN (SELECT id FROM relations)")["n"], 0)

    def test_raw_never_persisted_and_imports(self):
        import os, tempfile
        d = tempfile.mkdtemp()
        with open(os.path.join(d, "a.txt"), "w", encoding="utf-8") as f:
            f.write("ד\"ר דנה אברמוב, מנהלת פיתוח\ndana@gamma.co.il\n")
        from osnit.ingest import import_path
        r = import_path(self.eng, d, delete_raw=True)
        self.assertEqual(r["imported"], 1)
        self.assertEqual(os.listdir(d), [])                          # raw removed on request
        self.assertTrue(self.store.q1("SELECT 1 FROM entities WHERE type='email' AND key='dana@gamma.co.il'"))
        cols = {c["name"] for c in self.store.q("PRAGMA table_info(sources)")}
        self.assertFalse(cols & {"body", "raw", "content", "html"})  # schema has no place to keep raw content


if __name__ == "__main__":
    unittest.main()
