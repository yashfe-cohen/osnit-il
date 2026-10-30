import asyncio
import io
import tempfile
import unittest
import zipfile
from pathlib import Path

from osnit.store import Store
from osnit.web_osint import (
    DorkDocumentTreeBridge,
    InvestigationTreeBuilder,
    ReconJobManager,
    SearchTargetProfile,
    UnifiedReconEngine,
)


class TestDorkDocumentIngestBridge(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.tmp_dir.name) / "test_osint.db"
        self.store = Store(str(self.db_path))
        self.profile = SearchTargetProfile(
            entity_id=1,
            primary_name="נועם כהן",
            hebrew_names=["נועם כהן"],
            english_names=["Noam Cohen"],
            usernames=["noam_cohen"],
            emails=["noam@example.com"],
            phones=["054-1234567"],
            organizations=["סייבר טכנולוגיות בע\"מ"],
            cities=["תל אביב"],
        )

    def tearDown(self):
        self.store.close()
        self.tmp_dir.cleanup()

    def test_is_document_or_archive_url(self):
        self.assertEqual(DorkDocumentTreeBridge.is_document_or_archive_url("https://gov.il/files/roster_2026.pdf"), "pdf")
        self.assertEqual(DorkDocumentTreeBridge.is_document_or_archive_url("https://ac.il/data/staff.xlsx?ver=2"), "xlsx")
        self.assertEqual(DorkDocumentTreeBridge.is_document_or_archive_url("https://example.co.il/download?file=contacts.csv"), "csv")
        self.assertEqual(DorkDocumentTreeBridge.is_document_or_archive_url("https://example.co.il/dump.zip"), "zip")
        self.assertEqual(DorkDocumentTreeBridge.is_document_or_archive_url("https://instagram.com/noam_cohen"), "")

    def test_harvest_and_ingest_document_populates_store_and_tree_branches(self):
        tree_builder = InvestigationTreeBuilder(store=self.store, job_id="job_doc_1", profile=self.profile)
        tree_builder.init_seed_nodes()

        doc_url = "https://gov.il/reports/cyber_board_roster.txt"
        doc_content = (
            "דוח דירקטוריון סייבר טכנולוגיות בע\"מ - תל אביב\n"
            "חבר הנהלה: נועם כהן | ת.ז 000000018 | טלפון: 054-7654321 | אימייל: noam.cohen@cyber-il.co.il\n"
            "יועצת משפטית: דנה לוי | אימייל: dana.levy@cyber-il.co.il | טלפון: 052-9988776\n"
        ).encode("utf-8")

        finding = {
            "category": "legal_doc",
            "source_tool": "dork_search",
            "title": "דוח דירקטוריון סייבר טכנולוגיות בע\"מ",
            "url": doc_url,
            "confidence": 0.86,
            "extracted_data": {},
        }

        async def fake_http_fetcher(u: str, headers: dict):
            if u == doc_url:
                return 200, doc_content, {"content-type": "text/plain; charset=utf-8"}
            return 404, b"", {}

        res = asyncio.run(
            DorkDocumentTreeBridge.harvest_and_ingest_document(
                finding,
                profile=self.profile,
                store=self.store,
                tree_builder=tree_builder,
                job_id="job_doc_1",
                http_fetcher=fake_http_fetcher,
            )
        )

        self.assertTrue(res["ok"])
        self.assertTrue(res["doc_node_id"] > 0)
        self.assertIsNotNone(res["ingested_source_id"])
        self.assertTrue(res["ingested_source_id"] > 0)

        # Verify file was saved to disk under <db_dir>/recon_downloads/job_doc_1/
        local_file = Path(res["local_file_path"])
        self.assertTrue(local_file.exists())
        self.assertEqual(local_file.read_bytes(), doc_content)

        # Verify source was ingested into `sources` table in osnit.db
        src_row = self.store.q1("SELECT * FROM sources WHERE id=?", (res["ingested_source_id"],))
        self.assertIsNotNone(src_row)
        self.assertEqual(src_row["state"], "imported")

        # Verify extracted identifiers
        self.assertIn("000000018", res["id_numbers"])
        self.assertIn("noam.cohen@cyber-il.co.il", res["emails"])
        self.assertIn("dana.levy@cyber-il.co.il", res["emails"])
        self.assertTrue(any("7654321" in p for p in res["phones"]))
        self.assertTrue(any("נועם כהן" in p or "דנה לוי" in p for p in res["persons"]))

        # Verify Investigation Tree structure: `web_document` node + `extracted_from_file` children
        snap = tree_builder.snapshot()
        doc_node = next((n for n in snap["nodes"] if n["id"] == res["doc_node_id"]), None)
        self.assertIsNotNone(doc_node)
        self.assertEqual(doc_node["node_type"], "web_document")
        self.assertEqual(doc_node["status"], "verified")
        self.assertEqual(doc_node["ingested_source_id"], res["ingested_source_id"])
        self.assertEqual(doc_node["local_file_path"], str(local_file))

        children = [n for n in snap["nodes"] if n["parent_node_id"] == res["doc_node_id"]]
        child_types = {c["node_type"] for c in children}
        self.assertIn("id_number", child_types)
        self.assertIn("email", child_types)
        self.assertIn("phone", child_types)
        self.assertIn("person", child_types)

        file_edges = [
            e for e in snap["edges"]
            if e["from_node_id"] == res["doc_node_id"] and e["relation_kind"] == "extracted_from_file"
        ]
        self.assertGreaterEqual(len(file_edges), 4)

    def test_harvest_and_ingest_zip_archive(self):
        tree_builder = InvestigationTreeBuilder(store=self.store, job_id="job_zip_1", profile=self.profile)
        tree_builder.init_seed_nodes()

        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr(
                "contacts.csv",
                "name,email,phone,id_number\n"
                "נועם כהן,noam.archive@cyber-il.co.il,054-1122334,000000018\n",
            )
        zip_bytes = buf.getvalue()
        zip_url = "https://example.co.il/exports/leaked_contacts.zip"

        res = asyncio.run(
            DorkDocumentTreeBridge.harvest_and_ingest_document(
                zip_url,
                profile=self.profile,
                store=self.store,
                tree_builder=tree_builder,
                job_id="job_zip_1",
                bytes_fetcher=lambda u: (200, zip_bytes),
            )
        )
        self.assertTrue(res["ok"])
        self.assertEqual(res["file_type"], "zip")
        self.assertTrue(Path(res["local_file_path"]).exists())
        self.assertIsNotNone(res["ingested_source_id"])

        # Leaf CSV inside ZIP should have been unpacked & imported into sources/entities!
        sources_count = self.store.q1("SELECT COUNT(*) AS c FROM sources")["c"]
        self.assertGreaterEqual(sources_count, 2)

    def test_confirm_candidate_and_expand_node_via_job_manager(self):
        mgr = ReconJobManager(self.store)
        tree_builder = InvestigationTreeBuilder(store=self.store, job_id="job_interactive_1", profile=self.profile)
        root_id = tree_builder.init_seed_nodes()

        # Insert a Top-3 candidate social profile node
        cand_id = tree_builder._upsert_node(
            node_type="social_profile",
            canonical_key="https://www.instagram.com/noam_cohen_tlv",
            label="Instagram: Noam Cohen (@noam_cohen_tlv)",
            parent_node_id=root_id,
            depth=1,
            platform="Instagram",
            status="candidate_top3",
            confidence=0.72,
            candidate_rank=1,
            discovery_reason="מועמד #1 לאימות",
            source_url="https://www.instagram.com/noam_cohen_tlv/",
        )

        ig_html = """
        <html>
          <head><title>Noam Cohen (@noam_cohen_tlv)</title></head>
          <body>
            <p>ארוחת שישי עם אחי @yossi_cohen_il | צילום: @studio_art_il | פניות: noam.ig@cyber-il.co.il</p>
          </body>
        </html>
        """

        def fake_http(url: str, headers: dict):
            if "instagram.com/noam_cohen_tlv" in url:
                return 200, ig_html, {}
            return 404, "", {}

        out = mgr.confirm_or_reject_candidate(cand_id, decision="confirm", http_fetcher=fake_http)
        self.assertTrue(out["ok"])
        self.assertEqual(out["decision"], "verified")
        self.assertEqual(out["node"]["status"], "verified")

        # Confirming the social profile should have automatically mined @mentions and email children!
        tree_nodes = out["tree"]["nodes"]
        children = [n for n in tree_nodes if n["parent_node_id"] == cand_id]
        self.assertGreaterEqual(len(children), 2)
        child_labels = " ".join(c["label"] for c in children)
        self.assertIn("yossi_cohen_il", child_labels)
        self.assertIn("noam.ig@cyber-il.co.il", child_labels)


if __name__ == "__main__":
    unittest.main()
