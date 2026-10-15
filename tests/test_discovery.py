import json
import unittest

from osnit.providers import Wayback, build_providers
from osnit.config import Config
from tests import helpers
from tests.helpers import PAGES, H, FakeProvider
from tests.test_pipeline import TEAM, DOC


class Discovery(unittest.TestCase):
    def setUp(self):
        H.hits.clear()
        PAGES.clear()
        self.srv, self.base, self.store, self.eng, self.svc, self.prov = helpers.make(["/team"])

    def tearDown(self):
        self.srv.shutdown()

    def test_wayback_returns_documents_first_as_raw_captures(self):
        cdx = [["timestamp", "original", "mimetype"],
               ["20190101000000", "http://alpha.co.il/", "text/html"],
               ["20180505000000", "http://alpha.co.il/files/team.pdf", "application/pdf"]]
        PAGES["/cdx/search/cdx"] = (json.dumps(cdx), "application/json")
        cfg = Config(db_path=":memory:", wayback_url=self.base)
        # local stub ignores the query string
        import tests.helpers as hp
        orig = hp.H.do_GET

        def do_get(handler):
            handler.path = handler.path.split("?")[0]
            return orig(handler)
        hp.H.do_GET = do_get
        try:
            urls = Wayback(cfg).search("archive:alpha.co.il", 5)
        finally:
            hp.H.do_GET = orig
        self.assertEqual(urls[0], f"{self.base}/web/20180505000000id_/http://alpha.co.il/files/team.pdf")
        self.assertFalse(Wayback(cfg).accepts('"יונתן חייט"'))
        self.assertTrue(Wayback(cfg).accepts("archive:alpha.co.il"))

    def test_archive_queries_only_go_to_archive_provider(self):
        arch = FakeProvider([])
        arch.accepts = lambda q: q.startswith("archive:")
        self.eng.providers["archive"] = arch
        self.prov.accepts = lambda q: not q.startswith("archive:")
        sid = self.svc.search("יונתן חייט")["subject_id"]
        self.svc._round(sid, [("archive:alpha.co.il", False), ('"יונתן חייט" cv', False)])
        jobs = {(r["provider"], r["query"]) for r in self.store.q("SELECT provider, query FROM jobs")}
        self.assertIn(("archive", "archive:alpha.co.il"), jobs)
        self.assertNotIn(("fake", "archive:alpha.co.il"), jobs)
        self.assertNotIn(("archive", '"יונתן חייט" cv'), jobs)

    def test_sitemap_of_a_hit_site_is_followed_documents_first(self):
        PAGES["/team"] = (TEAM.replace('<a href="/doc.txt">מסמך</a>', ""), "text/html; charset=utf-8")
        PAGES["/sitemap.xml"] = ("<?xml version='1.0'?><urlset>" + "".join(
            f"<url><loc>{self.base}/p{i}</loc></url>" for i in range(80)) +
            f"<url><loc>{self.base}/files/cv.txt</loc></url></urlset>", "application/xml")
        PAGES["/files/cv.txt"] = (DOC, "text/plain; charset=utf-8")
        sid = self.svc.search("יונתן חייט")["subject_id"]
        self.eng.drain()
        self.assertIn("/sitemap.xml", H.hits)
        self.assertIn("/files/cv.txt", H.hits)                  # doc listed last in the sitemap, fetched anyway
        docs = [d["url"] for i in self.svc.profile(sid)["identities"] for d in i["documents"]]
        self.assertTrue(any(u.endswith("/files/cv.txt") for u in docs))

    def test_daily_budget_defers_jobs(self):
        self.eng.cfg.budgets = {"fake": 2}
        sid = self.svc.search("יונתן חייט")["subject_id"]
        self.eng.drain()
        states = [r["state"] for r in self.store.q("SELECT state FROM jobs WHERE provider='fake' ORDER BY id")]
        self.assertEqual(states.count("done"), 2)
        self.assertTrue(states.count("pending") > 0)            # rest waits for tomorrow's quota

    def test_keyed_providers_enabled_by_env(self):
        cfg = Config(db_path=":memory:", providers=["wikipedia"], google_key="k", google_cx="c", serpapi_key="s")
        self.assertEqual(set(build_providers(cfg)), {"wikipedia", "google", "serpapi"})


if __name__ == "__main__":
    unittest.main()
