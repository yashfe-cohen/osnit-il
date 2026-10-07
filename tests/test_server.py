import json
import unittest
import urllib.error
import urllib.request

from osnit.server import make_server, serve_in_thread
from tests import helpers
from tests.helpers import PAGES
from tests.test_pipeline import TEAM


class Api(unittest.TestCase):
    def setUp(self):
        PAGES.clear()
        PAGES["/team"] = (TEAM, "text/html")
        self.srv, self.base, self.store, self.eng, self.svc, _ = helpers.make(["/team"])
        self.api = make_server(self.svc, "127.0.0.1", 0, token="s3cret")
        serve_in_thread(self.api)
        self.url = f"http://127.0.0.1:{self.api.server_address[1]}"

    def tearDown(self):
        self.api.shutdown()
        self.srv.shutdown()

    def call(self, path, body=None, headers=None, token=True):
        h = {"Content-Type": "application/json", **(headers or {})}
        if token:
            h["Authorization"] = "Bearer s3cret"
        req = urllib.request.Request(self.url + path, data=json.dumps(body).encode() if body is not None else None, headers=h)
        try:
            with urllib.request.urlopen(req) as r:
                return r.status, r.read()
        except urllib.error.HTTPError as e:
            return e.code, e.read()

    def test_search_flow_and_security(self):
        self.assertEqual(self.call("/api/stats", token=False)[0], 401)
        self.assertEqual(self.call("/api/search", {"query": "x"}, {"Origin": "http://evil.example"})[0], 403)
        code, body = self.call("/api/search", {"query": "יונתן חייט"})
        sid = json.loads(body)["subject_id"]
        self.assertEqual(code, 200)
        self.eng.drain()
        code, body = self.call(f"/api/subjects/{sid}")
        prof = json.loads(body)
        self.assertEqual(prof["identities"][0]["emails"][0]["value"], "yonatan.hayat@alpha.co.il")
        code, body = self.call(f"/api/subjects/{sid}/events?after=0")
        self.assertTrue(any(e["type"] == "finding" for e in json.loads(body)))
        self.assertEqual(self.call("/api/search", {"query": ""})[0], 400)
        self.assertEqual(self.call(f"/api/subjects/{sid}/stop", {})[0], 200)
        self.assertEqual(json.loads(self.call(f"/api/subjects/{sid}")[1])["subject"]["status"], "done")
        self.assertEqual(self.call("/")[0], 200)

    def test_background_threads(self):
        """Workers + job thread + ticker running concurrently converge on the same picture."""
        import time
        self.eng.start()
        try:
            sid = self.svc.search("יונתן חייט")["subject_id"]
            for _ in range(60):
                if self.svc.profile(sid)["identities"]:
                    break
                time.sleep(0.2)
        finally:
            self.eng.stop()
        self.assertTrue(self.svc.profile(sid)["identities"])


if __name__ == "__main__":
    unittest.main()
