import unittest

from tests import helpers
from tests.helpers import PAGES, H

# A Wikipedia-style article: lots of person names in prose (incl. biblical), subject mentioned with an org.
WIKI = """<html><head><title>ההיסטוריה של העיר</title></head><body>
<p>דוד המלך ושלמה בנו בנו את המקדש. אברהם יצחק ויעקב היו האבות. משה רבנו הוציא את העם ממצרים.</p>
<p>בעת החדשה, יונתן חייט כיהן כמנכ"ל חברת אלפא בע"מ. גם רונית לוי ומשה כהן פעלו בעיר.</p>
<p>הרב שמואל הכהן כתב על כך. אסתר המלכה מוזכרת גם היא.</p>
<a href="/wiki/article2">ערך אחר</a> <a href="/files/report.pdf">דוח</a></body></html>"""


class Focus(unittest.TestCase):
    def setUp(self):
        H.hits.clear()
        PAGES.clear()
        PAGES["/wiki"] = (WIKI, "text/html; charset=utf-8")
        self.srv, self.base, self.store, self.eng, self.svc, self.prov = helpers.make(["/wiki"])

    def tearDown(self):
        self.srv.shutdown()

    def test_web_page_keeps_only_subject_and_its_links(self):
        self.svc.search("יונתן חייט")
        self.eng.drain()
        persons = {r["display"] for r in self.store.q("SELECT display FROM entities WHERE type='person'")}
        self.assertIn("יונתן חייט", persons)
        for bib in ("דוד", "שלמה", "אברהם", "משה רבנו", "אסתר", "שמואל הכהן"):
            self.assertFalse(any(bib in p for p in persons), f"biblical/prose name leaked: {bib} in {persons}")
        orgs = {r["display"] for r in self.store.q("SELECT display FROM entities WHERE type='org'")}
        self.assertTrue(any("אלפא" in o for o in orgs))   # the subject's org is kept

    def test_crawl_only_follows_documents_from_hit_page(self):
        self.svc.search("יונתן חייט")
        self.eng.drain()
        queued = {r["url"].split(self.base)[-1] for r in self.store.q("SELECT url FROM sources")}
        self.assertIn("/files/report.pdf", queued)      # document chased
        self.assertNotIn("/wiki/article2", queued)      # generic page not crawled

    def test_imported_file_keeps_all_people(self):
        # the focus rule is web-only; a user file still extracts everyone
        from osnit.ingest import import_parsed
        from osnit.parse import parse
        html = '<div><h3>ד"ר דן לוי</h3><p>050-8317945</p></div><div><h3>שרה כהן</h3><p>sara@x.co.il</p></div>'
        import_parsed(self.eng, "file://team.html", parse(html.encode(), "file://team.html", "text/html"))
        persons = {r["display"] for r in self.store.q("SELECT display FROM entities WHERE type='person'")}
        self.assertTrue({"דן לוי", "שרה כהן"} <= persons)
