"""Stage 3 Unit Tests: TagContextAnalyzer & DeepSocialBranchMiner (Post-Confirmation Branching)."""
from __future__ import annotations

import asyncio
import struct
import tempfile
import unittest
from pathlib import Path

from osnit.store import Store
from osnit.web_osint import (
    DeepSocialBranchMiner,
    InvestigationTreeBuilder,
    SearchTargetProfile,
    TagContextAnalyzer,
)


def _build_minimal_jpeg_with_gps_exif(lat: float = 32.0853, lon: float = 34.7818) -> bytes:
    """Build a valid minimal JPEG with an APP1 Exif IFD containing Make='Apple' and GPS coordinates (Tel Aviv)."""
    try:
        import cv2
        import numpy as np

        img = np.full((160, 160, 3), 210, dtype=np.uint8)
        ok, buf = cv2.imencode(".jpg", img)
        raw_jpg = bytes(buf) if ok else b"\xff\xd8\xff\xd9"
    except Exception:
        raw_jpg = b"\xff\xd8\xff\xd9"

    # Build a Little-Endian ('II') TIFF header + IFD0 with Make (0x010F) and GPSIFD pointer (0x8825)
    # Offset 0: 'II' (2), 42 (2), offset to IFD0 = 8 (4)
    # IFD0 at offset 8: count=2 (2 bytes)
    # Entry 0 (offset 10): tag=0x010F, type=2 (ASCII), count=6, value_offset=38 ('Apple\0')
    # Entry 1 (offset 22): tag=0x8825, type=4 (LONG), count=1, value_offset=44 (GPS IFD offset)
    # Next IFD (offset 34): 0 (4 bytes)
    # Offset 38: b'Apple\x00' (6 bytes -> ends at 44)
    # GPS IFD at offset 44: count=4 (2 bytes)
    # Entry 0 (offset 46): tag=0x0001 (LatRef), type=2, count=2, value=b'N\x00\x00\x00'
    # Entry 1 (offset 58): tag=0x0002 (Lat), type=5 (RATIONAL), count=3, offset=98
    # Entry 2 (offset 70): tag=0x0003 (LonRef), type=2, count=2, value=b'E\x00\x00\x00'
    # Entry 3 (offset 82): tag=0x0004 (Lon), type=5 (RATIONAL), count=3, offset=122
    # Next GPS IFD (offset 94): 0 (4 bytes -> ends at 98)
    # Offset 98: 3 rationals for Lat (24 bytes -> ends at 122)
    # Offset 122: 3 rationals for Lon (24 bytes -> ends at 146)
    tiff = bytearray()
    tiff += b"II" + struct.pack("<HI", 42, 8)
    tiff += struct.pack("<H", 2)
    tiff += struct.pack("<HHI4s", 0x010F, 2, 6, struct.pack("<I", 38))
    tiff += struct.pack("<HHI4s", 0x8825, 4, 1, struct.pack("<I", 44))
    tiff += struct.pack("<I", 0)
    tiff += b"Apple\x00"
    tiff += struct.pack("<H", 4)
    tiff += struct.pack("<HHI4s", 0x0001, 2, 2, b"N\x00\x00\x00")
    tiff += struct.pack("<HHI4s", 0x0002, 5, 3, struct.pack("<I", 98))
    tiff += struct.pack("<HHI4s", 0x0003, 2, 2, b"E\x00\x00\x00")
    tiff += struct.pack("<HHI4s", 0x0004, 5, 3, struct.pack("<I", 122))
    tiff += struct.pack("<I", 0)
    lat_deg = int(lat)
    lat_min = int((lat - lat_deg) * 60)
    lat_sec = int(round(((lat - lat_deg) * 60 - lat_min) * 60 * 100))
    lon_deg = int(lon)
    lon_min = int((lon - lon_deg) * 60)
    lon_sec = int(round(((lon - lon_deg) * 60 - lon_min) * 60 * 100))
    tiff += struct.pack("<IIIIII", lat_deg, 1, lat_min, 1, lat_sec, 100)
    tiff += struct.pack("<IIIIII", lon_deg, 1, lon_min, 1, lon_sec, 100)

    app1_payload = b"Exif\x00\x00" + bytes(tiff)
    app1_seg = b"\xff\xe1" + struct.pack(">H", len(app1_payload) + 2) + app1_payload
    return raw_jpg[:2] + app1_seg + raw_jpg[2:]


class TestDeepSocialBranching(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db_path = Path(self.tmp.name) / "test_social_branch.db"
        self.store = Store(str(self.db_path))

    def tearDown(self):
        self.store.close()
        self.tmp.cleanup()

    def test_tag_context_analyzer_classifies_all_four_categories_and_shared_surname(self):
        """Verify TagContextAnalyzer classifies family, colleague_business, service_credit, and social_friend."""
        profile = SearchTargetProfile.from_query("מתן שנער matanshi@gmail.com")

        # 1. Family via keyword + shared surname
        res_fam = TagContextAnalyzer.analyze_mention(
            handle="guy_shinar",
            snippet="שבת שלום עם אחי היקר @guy_shinar בארוחת שישי משפחתית",
            platform="Instagram",
            interaction_kind="post_tag",
            tagged_display_name="גיא שנער",
            profile=profile,
        )
        self.assertEqual(res_fam["context_type"], "family")
        self.assertTrue(res_fam["shared_surname"])
        self.assertIn("קשר משפחתי", res_fam["why_tagged"])
        self.assertGreaterEqual(res_fam["confidence"], 0.88)

        # 2. Colleague / Business partner
        res_work = TagContextAnalyzer.analyze_mention(
            handle="dan_cyber",
            snippet="גאה להשיק פרויקט סייבר חדש עם שותפי @dan_cyber והצוות במשרד",
            platform="Instagram",
            interaction_kind="bio_mention",
            profile=profile,
        )
        self.assertEqual(res_work["context_type"], "colleague_business")
        self.assertEqual(res_work["interaction_kind"], "bio_mention")
        self.assertIn("קולגה / שותף עסקי", res_work["why_tagged"])

        # 3. Service / Photo credit
        res_credit = TagContextAnalyzer.analyze_mention(
            handle="studio_or_photo",
            snippet="ערב בלתי נשכח! צילום: @studio_or_photo 📸",
            platform="Instagram",
            interaction_kind="post_tag",
            profile=profile,
        )
        self.assertEqual(res_credit["context_type"], "service_credit")
        self.assertIn("קרדיט צילום", res_credit["why_tagged"])

        # 4. Social friend + multi-face co-occurrence upgrade
        res_friend = TagContextAnalyzer.analyze_mention(
            handle="omer_tlv",
            snippet="חוגגים יום הולדת לחבר יקר @omer_tlv בתל אביב",
            platform="Instagram",
            interaction_kind="post_tag",
            profile=profile,
            co_faces_count=3,
        )
        self.assertEqual(res_friend["context_type"], "social_friend")
        self.assertEqual(res_friend["interaction_kind"], "photo_co_tag")
        self.assertIn("3 פנים", res_friend["why_tagged"])

    def test_deep_social_branch_miner_spawns_child_nodes_in_tree(self):
        """Verify DeepSocialBranchMiner extracts @mentions, tag reasons, EXIF GPS images, and bio links into the tree."""
        profile = SearchTargetProfile.from_query("מתן שנער matanshi@gmail.com", entity_id=1)
        tree_builder = InvestigationTreeBuilder(store=self.store, job_id="job_branch_1", profile=profile)
        root_id = tree_builder.init_seed_nodes()

        ig_node_id = tree_builder._upsert_node(
            node_type="social_profile",
            canonical_key="https://www.instagram.com/matanshi",
            label="פרופיל Instagram: מתן שנער (@matanshi)",
            parent_node_id=root_id,
            depth=2,
            platform="Instagram",
            status="candidate_top3",
            candidate_rank=1,
            confidence=0.84,
            source_url="https://www.instagram.com/matanshi",
        )

        mock_html = """
        <html>
          <head>
            <meta property="og:title" content="מתן שנער (@matanshi) • Instagram photos and videos" />
            <meta property="og:description" content="1,200 Followers, 340 Following, 45 Posts - Co-founder with @dan_cyber | Tel Aviv" />
            <meta property="og:image" content="https://cdn.example.com/matanshi_avatar.jpg" />
            <meta name="description" content="מתן שנער on Instagram: &quot;Co-founder at @dan_cyber | Contact: office@shinar-sec.co.il | 052-8889900&quot;" />
          </head>
          <body>
            <a href="https://shinar-sec.co.il/about">Website</a>
            <article>
              <img src="https://cdn.example.com/post_family.jpg" alt="שבת שלום עם אחי @guy_shinar בחוף תל אביב" />
              <p>שבת שלום עם אחי היקר @guy_shinar בחוף תל אביב! צילום: @lens_master_il 📸</p>
            </article>
            <div class="post-comment">תגובה מאת @noa_cohen_tlv: מזל טוב חברים אלופים!</div>
          </body>
        </html>
        """
        jpg_bytes = _build_minimal_jpeg_with_gps_exif(32.0853, 34.7818)

        def mock_http_fetcher(url: str, headers=None):
            if "instagram.com/matanshi" in url:
                return 200, mock_html, {}
            return 404, "", {}

        def mock_bytes_fetcher(url: str):
            return 200, jpg_bytes

        res = asyncio.run(
            DeepSocialBranchMiner.mine_confirmed_profile(
                {
                    "node_id": ig_node_id,
                    "source_url": "https://www.instagram.com/matanshi",
                    "platform": "Instagram",
                    "metadata": {"username": "matanshi", "location": "תל אביב"},
                },
                profile=profile,
                store=self.store,
                tree_builder=tree_builder,
                http_fetcher=mock_http_fetcher,
                bytes_fetcher=mock_bytes_fetcher,
            )
        )

        # 1. Parent node should now be upgraded to 'verified' and marked branch_expanded=True
        updated_parent = self.store.get_investigation_node(ig_node_id)
        self.assertEqual(updated_parent["status"], "verified")
        self.assertEqual(updated_parent["candidate_rank"], 0)
        self.assertTrue(updated_parent["metadata"].get("branch_expanded"))

        # 2. Check extracted tagged/mentioned users and their classifications
        handles_by_name = {t["handle"]: t for t in res["tagged_users"]}
        self.assertIn("guy_shinar", handles_by_name)
        self.assertEqual(handles_by_name["guy_shinar"]["context_type"], "family")
        self.assertIn("dan_cyber", handles_by_name)
        self.assertEqual(handles_by_name["dan_cyber"]["context_type"], "colleague_business")
        self.assertIn("lens_master_il", handles_by_name)
        self.assertEqual(handles_by_name["lens_master_il"]["context_type"], "service_credit")
        self.assertIn("noa_cohen_tlv", handles_by_name)
        self.assertEqual(handles_by_name["noa_cohen_tlv"]["interaction_kind"], "comment_interaction")

        # 3. Check tree snapshot has child nodes under ig_node_id (including GPS location under image)
        tree_snap = tree_builder.snapshot()
        children_of_ig = [n for n in tree_snap["nodes"] if n["parent_node_id"] == ig_node_id]
        child_types = {n["node_type"] for n in children_of_ig}
        self.assertIn("username", child_types)
        self.assertIn("image", child_types)
        self.assertIn("domain", child_types)
        self.assertIn("email", child_types)
        self.assertIn("phone", child_types)

        # Check EXIF GPS location child node was spawned under the image node
        gps_nodes = [n for n in tree_snap["nodes"] if n["node_type"] == "location" and "EXIF" in n["label"]]
        self.assertGreaterEqual(len(gps_nodes), 1)
        self.assertIn("תל אביב", gps_nodes[0]["label"])


if __name__ == "__main__":
    unittest.main()
