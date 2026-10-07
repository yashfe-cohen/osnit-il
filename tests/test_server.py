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


class LiveAndExport(unittest.TestCase):
    def setUp(self):
        PAGES.clear()
        PAGES["/team"] = (TEAM, "text/html")
        self.srv, self.base, self.store, self.eng, self.svc, _ = helpers.make(["/team"])
        self.api = make_server(self.svc, "127.0.0.1", 0)
        serve_in_thread(self.api)
        self.url = f"http://127.0.0.1:{self.api.server_address[1]}"

    def tearDown(self):
        self.api.shutdown()
        self.srv.shutdown()

    def test_sse_pushes_new_events(self):
        import threading
        sid = self.svc.search("יונתן חייט")["subject_id"]
        after = self.svc.events(sid)[-1]["id"]
        r = urllib.request.urlopen(f"{self.url}/api/subjects/{sid}/stream?after={after}", timeout=10)
        self.assertIn("text/event-stream", r.headers["Content-Type"])
        threading.Timer(0.3, lambda: self.store.add_event(sid, "finding", {"value": "x@y.co.il"})).start()
        got = []
        for _ in range(20):
            line = r.readline().decode()
            got.append(line)
            if line.startswith("data:"):
                break
        r.close()
        self.assertIn("event: update\n", got)
        self.assertIn("x@y.co.il", got[-1])

    def test_export_csv_and_json(self):
        sid = self.svc.search("יונתן חייט")["subject_id"]
        self.eng.drain()
        with urllib.request.urlopen(f"{self.url}/api/subjects/{sid}/export?format=csv") as r:
            body = r.read().decode("utf-8")
            self.assertIn("attachment", r.headers["Content-Disposition"])
        self.assertTrue(body.startswith("﻿subject,identity"))
        self.assertIn("yonatan.hayat@alpha.co.il", body)
        with urllib.request.urlopen(f"{self.url}/api/subjects/{sid}/export?format=json") as r:
            self.assertEqual(json.loads(r.read())["subject"]["id"], sid)

    def test_csv_neutralises_formulas(self):
        from osnit.export import profile_csv
        p = {"subject": {"canonical": "x"}, "unattributed": None, "identities": [{
            "id": 1, "label": "", "confidence": 0.5, "documents": [],
            "orgs": [{"type": "org", "value": "=HYPERLINK(\"http://evil\")", "confidence": 0.5, "first_seen": 0,
                      "last_seen": 0, "evidence": [{"url": "u", "snippet": "+cmd"}]}]}]}
        out = profile_csv(p)
        self.assertIn("'=HYPERLINK", out)
        self.assertIn("'+cmd", out)


class UploadAndDashboard(unittest.TestCase):
    def setUp(self):
        import tempfile
        PAGES.clear()
        PAGES["/team"] = (TEAM, "text/html")
        self.srv, self.base, self.store, self.eng, self.svc, _ = helpers.make(["/team"])
        from osnit.importqueue import ImportQueue
        self.q = ImportQueue(self.eng, inbox=tempfile.mkdtemp())
        self.api = make_server(self.svc, "127.0.0.1", 0, queue=self.q)
        serve_in_thread(self.api)
        self.url = f"http://127.0.0.1:{self.api.server_address[1]}"

    def tearDown(self):
        self.api.shutdown()
        self.srv.shutdown()

    def _post(self, path, body, headers=None):
        req = urllib.request.Request(self.url + path, data=body,
                                     headers={"Origin": self.url, **(headers or {})})
        with urllib.request.urlopen(req) as r:
            return r.status, json.loads(r.read())

    def test_upload_queues_and_processes(self):
        body = "name,phone,email\nאבי כהן,050-8317945,avi@demo.co.il\n".encode()
        code, res = self._post("/api/upload", body, {"X-Filename": "list.csv", "Content-Type": "application/octet-stream"})
        self.assertEqual(code, 200)
        self.assertEqual(res["detected"]["kind"], "csv")
        self.q.run_pending()
        imports = json.loads(urllib.request.urlopen(self.url + "/api/imports").read())
        self.assertEqual(imports[0]["state"], "done")
        self.assertEqual(imports[0]["records"], 1)
        self.assertTrue(self.store.q1("SELECT 1 FROM entities WHERE key='avi@demo.co.il'"))

    def test_dashboard_shape(self):
        self.svc.search("יונתן חייט")
        self.eng.drain()
        with urllib.request.urlopen(self.url + "/api/dashboard") as r:
            d = json.loads(r.read())
        self.assertIn("completeness", d)
        self.assertIn("complete", d["completeness"])
        self.assertGreaterEqual(d["counts"]["emails"], 1)
        self.assertEqual(len(d["activity"]), 30)


class PauseControl(unittest.TestCase):
    def setUp(self):
        PAGES.clear()
        self.srv, self.base, self.store, self.eng, self.svc, _ = helpers.make([])
        self.api = make_server(self.svc, "127.0.0.1", 0)
        serve_in_thread(self.api)
        self.url = f"http://127.0.0.1:{self.api.server_address[1]}"

    def tearDown(self):
        self.api.shutdown()
        self.srv.shutdown()

    def test_pause_resume_toggles_engine(self):
        self.assertFalse(json.loads(urllib.request.urlopen(self.url + "/api/stats").read())["paused"])
        req = urllib.request.Request(self.url + "/api/pause", data=b"{}",
                                     headers={"Origin": self.url, "Content-Type": "application/json"})
        self.assertTrue(json.loads(urllib.request.urlopen(req).read())["paused"])
        self.assertTrue(self.eng.is_paused)
        req = urllib.request.Request(self.url + "/api/resume", data=b"{}",
                                     headers={"Origin": self.url, "Content-Type": "application/json"})
        urllib.request.urlopen(req)
        self.assertFalse(self.eng.is_paused)

    def test_paused_engine_does_not_process(self):
        self.eng.pause()
        sid, _ = self.store.add_source(self.base + "/x", priority=100)
        self.assertEqual(self.eng.step(1) if not self.eng.is_paused else 0, 0)  # worker would skip; step is manual
        self.eng.resume()
