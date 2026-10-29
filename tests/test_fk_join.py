"""
Unit tests for Phase 7 (UPGRADE_PLAN v2.0):
Foreign Key Relational Join Resolution across SQL tables,
Cross-Language (Hebrew <-> English) Dossier Unification with Strong Anchors,
and Document Co-occurrence Linking.
"""
import os
import tempfile
import unittest

from osnit.dossier import can_unify_records, dossier, is_cross_language_match
from osnit.importdb import import_db
from osnit.parse import Parsed
from tests import helpers


class TestFKJoinAndDossier(unittest.TestCase):

    def setUp(self):
        self.srv, self.base, self.store, self.eng, self.svc, _ = helpers.make([])
        self.tmp_dir = tempfile.mkdtemp()

    def tearDown(self):
        self.srv.shutdown()

    # ------------------------------------------------------------------
    # 1. Foreign Key Join Resolution (SQL / Tables)
    # ------------------------------------------------------------------

    def test_sql_foreign_key_join_resolution(self):
        """
        A SQL dump where user details are spread across 'users', 'orders' and 'user_addresses'.
        Child tables with user_id automatically resolve to the parent 'users' record.
        """
        sql_content = """
        CREATE TABLE users (
            id INT PRIMARY KEY,
            name VARCHAR(100),
            email VARCHAR(100)
        );

        CREATE TABLE orders (
            order_id INT PRIMARY KEY,
            user_id INT,
            shipping_phone VARCHAR(50),
            delivery_city VARCHAR(50)
        );

        CREATE TABLE user_addresses (
            id INT PRIMARY KEY,
            user_id INT,
            city VARCHAR(50),
            phone VARCHAR(50)
        );

        INSERT INTO users (id, name, email) VALUES
        (504, 'יוסי כהן', 'yossi.cohen@testcorp.co.il');

        INSERT INTO orders (order_id, user_id, shipping_phone, delivery_city) VALUES
        (9001, 504, '052-8317945', 'תל אביב');

        INSERT INTO user_addresses (id, user_id, city, phone) VALUES
        (1, 504, 'חיפה', '054-6613972');
        """
        sql_path = os.path.join(self.tmp_dir, "store_dump.sql")
        with open(sql_path, "w", encoding="utf-8") as f:
            f.write(sql_content)

        stats = import_db(self.eng, sql_path, delete_raw=False)
        self.assertGreater(stats["records"], 0)

        # Check dossier for Yossi Cohen
        d = dossier(self.store, name="יוסי כהן")
        self.assertTrue(len(d["clusters"]) > 0, "Yossi Cohen must have at least one cluster")
        c = d["clusters"][0]
        self.assertIn("יוסי כהן", c["names"])

        # The shipping phone from orders and phone from user_addresses must be linked to Yossi Cohen
        phones = [p["value"] for p in c["facets"].get("phone", [])]
        self.assertIn("+972528317945", phones, "Phone from orders should be joined to user")
        self.assertIn("+972546613972", phones, "Phone from user_addresses should be joined to user")

        # Delivery cities / addresses should also appear in attributes or facets
        all_attr_vals = [v["value"] for g in c.get("attributes", []) for v in g.get("values", [])]
        self.assertTrue(any("תל אביב" in v or "חיפה" in v for v in all_attr_vals),
                        "Attributes from child tables should be attached to parent user")

    # ------------------------------------------------------------------
    # 2. Cross-Language Dossier Unification (Hebrew <-> English)
    # ------------------------------------------------------------------

    def test_cross_language_match_helper(self):
        """Cross-language name match recognizes Hebrew and Latin phonetic/consonant pairs."""
        self.assertTrue(is_cross_language_match("יונתן חייט", "Yonatan Hayat"))
        self.assertTrue(is_cross_language_match("ברקת כהן", "Bareket Cohen"))
        self.assertTrue(is_cross_language_match("דנה לוי", "Dana Levi"))
        self.assertFalse(is_cross_language_match("יוסי כהן", "Dana Levi"))

    def test_can_unify_records_helper(self):
        """can_unify_records verifies matching name + strong personal anchor."""
        # Matching names with strong national_id anchor
        self.assertTrue(can_unify_records(
            "יונתן חייט", "Yonatan Hayat",
            [{"type": "national_id", "value": "100000009", "is_strong": True}]
        ))
        # Matching names with personal mobile phone anchor
        self.assertTrue(can_unify_records(
            "ברקת כהן", "Bareket Cohen",
            [{"type": "phone", "value": "0528317945", "exclusive": True}]
        ))
        # Non-matching names even with shared anchor should fail
        self.assertFalse(can_unify_records(
            "יוסי כהן", "Dana Levi",
            [{"type": "national_id", "value": "100000009", "is_strong": True}]
        ))

    def test_cross_language_dossier_unification(self):
        """
        When two records (one in Hebrew, one in English) share a strong personal anchor
        (mobile phone / email / ID), dossier unifies them into a single cluster.
        """
        csv_he = "name,phone,email\nיונתן חייט,0528317945,yonatan@hayat-tech.co.il\n"
        csv_en = "name,phone,email\nYonatan Hayat,0528317945,yonatan@hayat-tech.co.il\n"

        p1 = os.path.join(self.tmp_dir, "he.csv")
        p2 = os.path.join(self.tmp_dir, "en.csv")
        with open(p1, "w", encoding="utf-8") as f:
            f.write(csv_he)
        with open(p2, "w", encoding="utf-8") as f:
            f.write(csv_en)

        import_db(self.eng, p1)
        import_db(self.eng, p2)

        # Query dossier by Hebrew name
        d = dossier(self.store, name="יונתן חייט")
        self.assertEqual(len(d["clusters"]), 1, "Both records must be unified into a SINGLE cluster")
        cluster = d["clusters"][0]
        self.assertIn("יונתן חייט", cluster["names"])
        self.assertIn("Yonatan Hayat", cluster["names"])
        # the English record joined the Hebrew identity through the shared mobile/email: ONE identity, two spellings
        self.assertEqual(len(cluster["records"]), 1, "Both records resolve to one identity")

    def test_cross_language_conflict_blocks_unification(self):
        """
        Different check-digit-valid national IDs strictly prevent auto-unification,
        even if names match across languages.
        """
        csv_he = "name,national_id\nיונתן חייט,100000009\n"
        csv_en = "name,national_id\nYonatan Hayat,100000017\n"

        p1 = os.path.join(self.tmp_dir, "he_conf.csv")
        p2 = os.path.join(self.tmp_dir, "en_conf.csv")
        with open(p1, "w", encoding="utf-8") as f:
            f.write(csv_he)
        with open(p2, "w", encoding="utf-8") as f:
            f.write(csv_en)

        import_db(self.eng, p1)
        import_db(self.eng, p2)

        d = dossier(self.store, name="יונתן חייט")
        # Should not merge into the same cluster because national IDs conflict
        for c in d["clusters"]:
            names = c["names"]
            self.assertFalse("יונתן חייט" in names and "Yonatan Hayat" in names,
                             "Conflicting national IDs must never merge into same cluster")

    # ------------------------------------------------------------------
    # 3. Document Co-occurrence Linking (2 to 6 persons)
    # ------------------------------------------------------------------

    def test_document_co_occurrence(self):
        """
        A focused document mentioning 3 people automatically links them with 'co_mentioned_in_doc'.
        A large directory (>= 7 people) does NOT create co-occurrence links.
        """
        from osnit.ingest import import_parsed

        # 1. Focused document with 3 people
        focused_text = "Meeting between Dr. Alice Smith, Dr. Bob Jones, and Dr. Charlie Brown to sign the contract."
        url_focused = "file://focused_doc.txt"
        import_parsed(self.eng, url_focused, Parsed("txt", focused_text, "Management Meeting"))

        # Verify co_mentioned_in_doc relations in DB
        rows = self.store.q("SELECT kind FROM relations WHERE kind='co_mentioned_in_doc'")
        self.assertGreaterEqual(len(rows), 3, "3 people should generate 3 pairwise co-occurrence relations")
        co_evidence = self.store.q(
            "SELECT re.snippet FROM rel_evidence re JOIN relations r ON r.id = re.relation_id "
            "WHERE r.kind='co_mentioned_in_doc'"
        )
        self.assertGreaterEqual(len(co_evidence), 3)
        self.assertTrue(all("Management Meeting" in r["snippet"] or "focused_doc.txt" in r["snippet"]
                            for r in co_evidence))


if __name__ == "__main__":
    unittest.main()
