# -*- coding: utf-8 -*-
import os
import tempfile
import unittest

from osnit.name_validator import is_valid_person_name, has_non_person_stop_token
from osnit.extract import Extractor, extract_name_from_filename
from osnit.store import Store


class TestNameValidatorAndArchiveCalibration(unittest.TestCase):
    def test_false_positive_non_person_rejection(self):
        """Ensure government ministries, calendar dates, cities, form headers, and OCR noise are rejected."""
        invalid_names = [
            "משרד המשפטים",
            "משרד ראש הממשלה",
            "משרד הפנים",
            "משרד הבריאות",
            "משרד הביטחון",
            "משרד התחבורה",
            "רשות האוכלוסין וההגירה",
            "ביטוח לאומי",
            "משטרת ישראל",
            "צבא הגנה לישראל",
            "בית משפט השלום",
            "חודש סיוון",
            "חודש תשרי",
            "יום ראשון",
            "שנת תשפ\"ד",
            "תל אביב",
            "ירושלים",
            "פתח תקווה",
            "ראשון לציון",
            "באר שבע",
            "רחוב הרצל",
            "בעל התעודה",
            "תעודת זהות",
            "תעודת לידה",
            "רישיון נהיגה",
            "אזרחות ישראלית",
            "בעל כושר",
            "שם פרטי",
            "שם משפחה",
            "מספר זהות",
            "תאריך לידה",
            "מצב משפחתי",
            "אלוף גל",
            "סרן דוד",
            "nny דביר",
            "בע\"מ",
            "חברה בעמ",
            "עמותה רשומה",
            "Ministry of Justice",
            "State of Israel",
            "Identity Card",
            "Driving License",
            "123456789",
            "א ב",
        ]
        for bad in invalid_names:
            with self.subTest(bad=bad):
                self.assertFalse(
                    is_valid_person_name(bad),
                    f"Expected non-person string '{bad}' to be rejected by is_valid_person_name",
                )

    def test_valid_person_names_accepted(self):
        """Ensure genuine Hebrew and English person names pass validation."""
        valid_names = [
            "עמית שלמה דיין",
            "ינון רפאל אוחיון",
            "שלמה מו",
            "אורן ערן",
            "דוד כהן",
            "שרה לוי",
            "משה אברהם",
            "יוסף חיים מזרחי",
            "נופר ביטון",
            "עודד חדד",
            "שפרה פרץ",
            "Alisah Alterthum",
            "Amit Tulian",
            "Daniel Cohen",
        ]
        for good in valid_names:
            with self.subTest(good=good):
                self.assertTrue(
                    is_valid_person_name(good),
                    f"Expected real person name '{good}' to be accepted by is_valid_person_name",
                )

    def test_has_non_person_stop_token(self):
        self.assertTrue(has_non_person_stop_token("משרד המשפטים"))
        self.assertTrue(has_non_person_stop_token("חודש סיוון"))
        self.assertTrue(has_non_person_stop_token("בעל התעודה"))
        self.assertFalse(has_non_person_stop_token("עמית שלמה דיין"))

    def test_intelligence_dossier_extraction(self):
        """Verify extraction of Arabic/Hebrew intelligence dossier records with kinship and phones."""
        ext = Extractor()
        sample_dossier = """
الرقمالوطني 204688899
الاسمالأول עמית שלמה
اسمالعائلة דיין
اسمالأب משה
اسمالأم רחל
נייד: 9936544-052
טלפון נוסף: 450-6306071
דוא"ל: amit.dayan@example.co.il
"""
        ex = ext.extract(sample_dossier, "dossier_test.docx")
        persons = [v["display"] for (t, k), v in ex.ents.items() if t == "person"]
        ids = [k for (t, k) in ex.ents if t == "national_id"]
        phones = [k for (t, k) in ex.ents if t == "phone"]
        emails = [k for (t, k) in ex.ents if t == "email"]

        self.assertTrue(any("עמית שלמה דיין" in p for p in persons), f"Persons found: {persons}")
        self.assertIn("204688899", ids)
        self.assertIn("+972529936544", phones)
        self.assertIn("+972546306071", phones)
        self.assertIn("amit.dayan@example.co.il", emails)
        self.assertTrue(
            any(str(kind).startswith("kinship:") for (_, _, kind) in ex.links),
            f"Expected kinship relations, got {list(ex.links.keys())}",
        )

    def test_ocr_spaced_id_and_bare_luhn_id_vs_phone(self):
        """Ensure OCR-spaced IDs are captured and bare 9-digit Luhn IDs are not stolen by PHONE_IL."""
        ext = Extractor()
        text = """
תעודת זהות
מספר זהות: 3 1840005 8
שם: ינון רפאל אוחיון

025685298
עודד כהן
"""
        ex = ext.extract(text, "id_card.pdf")
        ids = [k for (t, k) in ex.ents if t == "national_id"]
        phones = [k for (t, k) in ex.ents if t == "phone"]
        persons = [v["display"] for (t, k), v in ex.ents.items() if t == "person"]

        self.assertIn("318400058", ids)
        self.assertIn("025685298", ids)
        self.assertFalse(any("25685298" in p for p in phones), f"Phones: {phones}")
        self.assertTrue(any("ינון רפאל אוחיון" in p for p in persons), f"Persons: {persons}")
        self.assertTrue(any("עודד כהן" in p for p in persons), f"Persons: {persons}")

    def test_parent_directory_filename_extraction(self):
        """Verify extract_name_from_filename inspects parent folder when file basename is generic."""
        name = extract_name_from_filename("for test/AMIT TULIAN/Pic1.jpg")
        self.assertEqual(name, "Amit Tulian")

        he_name = extract_name_from_filename("for test/דוד כהן 025685298/scan_001.jpg")
        self.assertEqual(he_name, "דוד כהן")

    def test_store_blocks_and_purges_invalid_persons(self):
        """Verify Store.resolve_entity blocks invalid persons and Store.purge_invalid_persons cleans existing DB rows."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = os.path.join(tmpdir, "test_purge.db")
            st = Store(db_path)
            try:
                # 1. resolve_entity should refuse to create an invalid person entity
                bad_id = st.resolve_entity("person", "משרד המשפטים", "משרד המשפטים", 1000.0)
                self.assertEqual(bad_id, -1)

                # 2. Valid person should be created normally
                good_id = st.resolve_entity("person", "דוד כהן", "דוד כהן", 1000.0)
                self.assertGreater(good_id, 0)

                # 3. Simulate legacy invalid person inserted directly into SQLite
                with st.tx() as c:
                    cur = c.execute(
                        "INSERT INTO entities(type, key, display, first_seen, last_seen) "
                        "VALUES ('person', 'חודש סיוון', 'חודש סיוון', 0, 0)"
                    )
                    legacy_bad_id = cur.lastrowid
                    c.execute(
                        "INSERT INTO relations(a_id, b_id, kind, first_seen, last_seen) "
                        "VALUES (?, ?, 'co_mentioned', 0, 0)",
                        (legacy_bad_id, good_id),
                    )

                # Run purge_invalid_persons
                res = st.purge_invalid_persons()
                self.assertEqual(res["removed"], 1)
                self.assertIn("חודש סיוון", res["removed_names"])

                remaining = st.q("SELECT display FROM entities WHERE type='person'")
                remaining_names = [r["display"] for r in remaining]
                self.assertEqual(remaining_names, ["דוד כהן"])
            finally:
                st.close()


if __name__ == "__main__":
    unittest.main()
