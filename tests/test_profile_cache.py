"""Investigation pages on a huge database: served from a saved copy, never holding a request for minutes."""
import json
import os
import tempfile
import time
import unittest
import urllib.request

import osnit.search as search_mod
from osnit.importdb import import_db
from osnit.server import make_server, serve_in_thread
from tests import helpers


class ProfileCache(unittest.TestCase):
    def setUp(self):
        self.srv, self.base, self.store, self.eng, self.svc, _ = helpers.make([])
        p = os.path.join(tempfile.mkdtemp(), "p.csv")
        with open(p, "w", encoding="utf-8") as f:
            f.write("שם פרטי,שם משפחה,טלפון\nרונית,אברמוביץ,054-7718293\n")
        import_db(self.eng, p, label="t")
        self.api = make_server(self.svc, "127.0.0.1", 0)
        serve_in_thread(self.api)
        self.url = f"http://127.0.0.1:{self.api.server_address[1]}"

    def tearDown(self):
        self.api.shutdown()
        self.srv.shutdown()

    def _get(self, path):
        with urllib.request.urlopen(self.url + path, timeout=30) as r:
            return r.status, json.loads(r.read())

    def test_saved_copy_is_served_and_refreshed_when_stale(self):
        sid = self.svc.search("רונית אברמוביץ", wait=5)["subject_id"]
        p1 = self.svc.profile_cached(sid)
        self.assertEqual(p1["exact_match"]["person_name"], "רונית אברמוביץ")
        self.assertFalse(p1["cached"]["refreshing"])
        with self.store.tx() as c:                            # make the copy old
            c.execute("UPDATE subject_cache SET built=built-3600 WHERE subject_id=?", (sid,))
        p2 = self.svc.profile_cached(sid)
        self.assertTrue(p2["cached"]["refreshing"])            # stale copy served at once, rebuilt behind it
        for _ in range(100):
            if time.time() - self.store.q1("SELECT built FROM subject_cache WHERE subject_id=?", (sid,))["built"] < 60:
                break
            time.sleep(0.05)
        self.assertFalse(self.svc.profile_cached(sid)["cached"]["refreshing"])

    def test_slow_first_build_answers_building_then_ready(self):
        real = search_mod.build_profile

        def slow(*a, **kw):
            time.sleep(1.5)
            return real(*a, **kw)
        search_mod.build_profile = slow
        try:
            sid = self.svc.search("רונית אברמוביץ", wait=0.1)["subject_id"]
            self.svc.drop_cached_profile(sid)
            st, body = self._get(f"/api/subjects/{sid}?view=page")
            if st == 202:                                       # still building: the page polls
                self.assertTrue(body["building"])
                for _ in range(100):
                    st, body = self._get(f"/api/subjects/{sid}?view=page")
                    if st == 200:
                        break
                    time.sleep(0.1)
            self.assertEqual(st, 200)
            self.assertEqual(body["exact_match"]["person_name"], "רונית אברמוביץ")
            self.assertEqual(body["identities"], [])            # page view: the unused per-source packs are left out
        finally:
            search_mod.build_profile = real

    def test_removing_data_drops_saved_copies(self):
        sid = self.svc.search("רונית אברמוביץ", wait=5)["subject_id"]
        self.svc.profile_cached(sid)
        self.assertIsNotNone(self.store.q1("SELECT 1 FROM subject_cache WHERE subject_id=?", (sid,)))
        self.store.purge_sources("1=1")
        self.assertIsNone(self.store.q1("SELECT 1 FROM subject_cache WHERE subject_id=?", (sid,)))

    def test_api_callers_still_get_the_full_profile(self):
        sid = self.svc.search("רונית אברמוביץ")["subject_id"]
        st, body = self._get(f"/api/subjects/{sid}")
        self.assertEqual(st, 200)
        self.assertIn("identities", body)
        self.assertNotIn("cached", body)


if __name__ == "__main__":
    unittest.main()
