import io
import json
import os
import tempfile
import unittest
import urllib.parse
import urllib.request
import zipfile
from PIL import Image, ImageDraw, ImageFont

from osnit.importqueue import ImportQueue
from osnit.server import make_server, serve_in_thread
from tests import helpers
from tests.helpers import PAGES


def _make_hebrew_ocr_png_bytes(lines):
    img = Image.new("RGB", (1400, 500), color=(255, 255, 255))
    draw = ImageDraw.Draw(img)
    font = None
    for candidate in (
        r"C:\Windows\Fonts\arial.ttf",
        r"C:\Windows\Fonts\david.ttf",
        r"C:\Windows\Fonts\tahoma.ttf",
    ):
        if os.path.exists(candidate):
            font = ImageFont.truetype(candidate, 34)
            break
    if font is None:
        font = ImageFont.load_default()
    y = 40
    for line in lines:
        draw.text((60, y), line, fill=(0, 0, 0), font=font)
        y += 65
    buf = io.BytesIO()
    img.save(buf, format="PNG", dpi=(300, 300))
    return buf.getvalue()


class Phase6FullSystemE2ETest(unittest.TestCase):
    """Real-world End-to-End (E2E) integration test verifying Phases 1-6 together."""

    def setUp(self):
        PAGES.clear()
        self.srv, self.base, self.store, self.eng, self.svc, _ = helpers.make([])
        self.inbox = tempfile.mkdtemp(prefix="osnit_phase6_inbox_")
        self.q = ImportQueue(self.eng, inbox=self.inbox)
        self.api = make_server(self.svc, "127.0.0.1", 0, queue=self.q)
        serve_in_thread(self.api)
        self.url = f"http://127.0.0.1:{self.api.server_address[1]}"

    def tearDown(self):
        self.api.shutdown()
        self.srv.shutdown()

    def _get_json(self, path):
        with urllib.request.urlopen(self.url + path) as r:
            self.assertEqual(r.status, 200)
            return json.loads(r.read().decode("utf-8"))

    def _post_bytes(self, path, body, headers=None):
        req = urllib.request.Request(
            self.url + path,
            data=body,
            headers={"Origin": self.url, **(headers or {})},
        )
        with urllib.request.urlopen(req) as r:
            return r.status, json.loads(r.read().decode("utf-8"))

    def test_full_e2e_pipeline_dossier_kinship_graph_and_ui(self):
        # 1. Verify UI HTML includes all Phase 6 upgrades (Kinship Graph, renderJob, Dossier kinship table)
        with urllib.request.urlopen(self.url + "/") as r:
            self.assertEqual(r.status, 200)
            html = r.read().decode("utf-8")
        self.assertIn("function renderJob(d)", html)
        self.assertIn("קשרי משפחה וזיקות קרובים", html)
        self.assertIn('e.kind === "kinship"', html)
        self.assertIn("national_id", html)

        # 2. Build a multi-format archive containing:
        #    a) SQL dump with family records & Israeli IDs
        #    b) English CSV with transliterated name ("Yonatan Hayat") sharing phone/email
        #    c) Hebrew text document with explicit kinship declarations (Father, Mother, Spouse)
        #    d) Scanned Hebrew PNG image processed via local Tesseract OCR
        sql_dump = """
        CREATE TABLE citizens (
            full_name TEXT,
            id_number TEXT,
            phone TEXT,
            email TEXT,
            address TEXT,
            father_name TEXT,
            mother_name TEXT,
            spouse_name TEXT
        );
        INSERT INTO citizens VALUES (
            'יונתן חייט',
            '000000018',
            '052-3344556',
            'yonatan.hayat@alpha.co.il',
            'הרצל 22 תל אביב',
            'דוד חייט',
            'שרה חייט',
            'מיכל חייט'
        );
        INSERT INTO citizens VALUES (
            'דוד חייט',
            '000000026',
            '03-5551234',
            'david.hayat@alpha.co.il',
            'הרצל 22 תל אביב',
            '',
            '',
            'שרה חייט'
        );
        INSERT INTO citizens VALUES (
            'עומר חייט',
            '000000034',
            '03-5551234',
            'omer.hayat@alpha.co.il',
            'הרצל 22 תל אביב',
            'דוד חייט',
            'שרה חייט',
            ''
        );
        """

        eng_csv = (
            "full_name,phone,email,organization,role\n"
            "Yonatan Hayat,+972-52-334-4556,yonatan.hayat@alpha.co.il,Alpha Cyber Labs,VP R&D\n"
        )

        heb_doc = (
            "תיק מודיעין מאוחד: יונתן חייט\n"
            "תעודת זהות: 000000018\n"
            "טלפון נייד: 052-3344556\n"
            "אימייל: yonatan.hayat@alpha.co.il\n"
            "כתובת מגורים: הרצל 22 תל אביב\n"
            "שם האב: דוד חייט\n"
            "שם האם: שרה חייט\n"
            "בת זוג: מיכל חייט\n"
        )

        ocr_png = _make_hebrew_ocr_png_bytes([
            "Name: Yonatan Hayat",
            "ID: 000000018 | Phone: 052-3344556",
            "Email: yonatan.hayat@alpha.co.il",
        ])

        zip_buf = io.BytesIO()
        with zipfile.ZipFile(zip_buf, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("registry_dump.sql", sql_dump.encode("utf-8"))
            zf.writestr("hr_directory.csv", eng_csv.encode("utf-8"))
            zf.writestr("family_certificate.txt", heb_doc.encode("utf-8"))
            zf.writestr("scanned_certificate.png", ocr_png)

        # 3. Upload the archive AND the standalone scanned Hebrew image via HTTP POST /api/upload and run ImportQueue
        status, upload_res = self._post_bytes(
            "/api/upload",
            zip_buf.getvalue(),
            {"X-Filename": "intelligence_bundle.zip", "Content-Type": "application/octet-stream"},
        )
        self.assertEqual(status, 200)
        self.assertEqual(upload_res["detected"]["kind"], "archive")

        status2, upload_res2 = self._post_bytes(
            "/api/upload",
            ocr_png,
            {"X-Filename": "scanned_certificate.png", "Content-Type": "application/octet-stream"},
        )
        self.assertEqual(status2, 200)

        processed = self.q.run_pending()
        self.assertGreaterEqual(processed, 2)

        imports = self._get_json("/api/imports")
        self.assertEqual(len(imports), 2)
        self.assertTrue(all(imp["state"] == "done" for imp in imports))

        # 4. Query /api/dossier for "יונתן חייט" and verify cross-language merging + kinship
        q_heb = urllib.parse.quote("יונתן חייט")
        dossier = self._get_json(f"/api/dossier?name={q_heb}")
        self.assertGreaterEqual(len(dossier["clusters"]), 1)

        cluster = dossier["clusters"][0]
        facets = cluster["facets"]
        # Verify contact unification across SQL, CSV, TXT, and OCR
        phones = {p["value"] for p in facets.get("phone", [])}
        emails = {e["value"] for e in facets.get("email", [])}
        ids = {i["value"] for i in facets.get("national_id", [])}
        self.assertIn("+972523344556", phones)
        self.assertIn("yonatan.hayat@alpha.co.il", emails)
        self.assertIn("000000018", ids)

        # Verify cross-language alias ("Yonatan Hayat" unified with "יונתן חייט")
        all_names = cluster.get("names", [])
        self.assertTrue(
            any("יונתן חייט" in n for n in all_names),
            f"Expected Hebrew name in {all_names}",
        )
        self.assertTrue(
            any("Yonatan Hayat" in n or "yonatan hayat" in n.lower() for n in all_names),
            f"Expected English name unified in {all_names}",
        )

        # Verify multiple uploaded files contributed to the unified dossier
        source_files = set(cluster.get("files", []))
        self.assertIn("intelligence_bundle.zip", source_files)
        self.assertIn("scanned_certificate.png", source_files)

        # 5. Verify Kinship & Family Ties in Dossier
        kinship = cluster.get("kinship", [])
        self.assertGreaterEqual(len(kinship), 3, f"Expected at least 3 family ties, got {kinship}")
        kin_by_name = {k["name"]: k for k in kinship}

        self.assertIn("דוד חייט", kin_by_name)
        self.assertIn("שרה חייט", kin_by_name)
        self.assertIn("מיכל חייט", kin_by_name)
        self.assertEqual(kin_by_name["דוד חייט"]["relation"], "אב")
        self.assertEqual(kin_by_name["שרה חייט"]["relation"], "אם")
        self.assertIn(kin_by_name["מיכל חייט"]["relation"], ("בן/בת זוג", "קרוב משפחה"))

        # Also check heuristic kinship with "עומר חייט" (shared surname + shared address "הרצל 22 תל אביב")
        self.assertIn("עומר חייט", kin_by_name)
        self.assertTrue(kin_by_name["עומר חייט"]["reason"])
        self.assertGreaterEqual(kin_by_name["עומר חייט"]["confidence"], 0.65)

        # 6. Verify Interactive Graph nodes and edges include kinship nodes & edges
        graph = dossier["graph"]
        kin_edges = [e for e in graph["edges"] if e.get("kind") == "kinship"]
        self.assertGreaterEqual(len(kin_edges), 3, f"Expected kinship edges in graph, got {graph['edges']}")
        for ke in kin_edges:
            self.assertTrue(ke.get("label"), f"Kinship edge missing label: {ke}")
            self.assertTrue(ke.get("reason"), f"Kinship edge missing reason: {ke}")
            self.assertGreater(ke.get("confidence", 0), 0.5)

        kin_nodes = [n for n in graph["nodes"] if n.get("kind") == "kinship"]
        self.assertGreaterEqual(len(kin_nodes), 3, f"Expected kinship nodes in graph, got {graph['nodes']}")

        # 7. Verify dedicated /api/graph, /api/entities/<id>, and /api/contacts endpoints
        person_eid = cluster["records"][0]["id"]
        self.assertIsNotNone(person_eid)

        ent_detail = self._get_json(f"/api/entities/{person_eid}")
        self.assertEqual(ent_detail["entity"]["type"], "person")
        self.assertGreaterEqual(len(ent_detail.get("kinship", [])), 3)

        graph_res = self._get_json(f"/api/graph?eid={person_eid}")
        self.assertIn("graph", graph_res)
        self.assertIn("kinship", graph_res)
        self.assertGreaterEqual(len(graph_res["kinship"]), 3)

        contacts_res = self._get_json(f"/api/contacts?q={q_heb}")
        self.assertGreaterEqual(len(contacts_res.get("rows", [])), 1)


if __name__ == "__main__":
    unittest.main()
