import unittest
from osnit.extract import (
    Extractor,
    preprocess_caps_for_ner,
    extract_name_from_filename,
    extract_name_from_email,
)
from osnit.parse import parse_pdf


class TestResumeAndHebrewExtraction(unittest.TestCase):

    def test_preprocess_caps_for_ner_names_and_acronyms(self):
        text = "AMIT TULIAN is a Senior AI and SQL Developer with CV and PDF attached. Working at TECH LTD."
        processed = preprocess_caps_for_ner(text)
        self.assertIn("Amit Tulian", processed)
        self.assertIn("AI", processed)
        self.assertIn("SQL", processed)
        self.assertIn("CV", processed)
        self.assertIn("PDF", processed)
        self.assertIn("LTD", processed)
        self.assertIn("Senior", processed)
        self.assertIn("Developer", processed)

    def test_extract_name_from_filename(self):
        self.assertEqual(extract_name_from_filename("Amit Tulian.pdf"), "Amit Tulian")
        self.assertEqual(extract_name_from_filename("Amit_Tulian_CV.pdf"), "Amit Tulian")
        self.assertEqual(extract_name_from_filename("CV - Amit Tulian (2024).pdf"), "Amit Tulian")
        self.assertEqual(extract_name_from_filename("Resume_Amit_Tulian.docx"), "Amit Tulian")
        self.assertEqual(extract_name_from_filename("scan_001.pdf"), "")
        self.assertEqual(extract_name_from_filename("123456789.pdf"), "")
        self.assertEqual(extract_name_from_filename(""), "")

    def test_extract_name_from_email(self):
        self.assertEqual(extract_name_from_email("Amit.tuli2@gmail.com"), "Amit Tuli")
        self.assertEqual(extract_name_from_email("amit_tulian@gmail.com"), "Amit Tulian")
        self.assertEqual(extract_name_from_email("david.cohen.1985@domain.com"), "David Cohen")
        # Generic organizational email should NOT extract a person name
        self.assertEqual(extract_name_from_email("aircollege.co.il@gmail.com"), "")
        self.assertEqual(extract_name_from_email("info@domain.com"), "")
        self.assertEqual(extract_name_from_email("admin@company.com"), "")
        self.assertEqual(extract_name_from_email(""), "")

    def test_resume_all_caps_name_and_contacts(self):
        body = """AMIT TULIAN
Full Stack Developer
Phone: 052-5248353
Email: Amit.tuli2@gmail.com
"""
        extractor = Extractor()
        ex = extractor.extract(body, title="Amit Tulian.pdf")

        # Must have person entity "Amit Tulian"
        person_keys = [k for (t, k) in ex.ents if t == "person"]
        self.assertTrue(len(person_keys) >= 1)
        self.assertIn("amit tulian", person_keys)

        # Must have phone and email
        phone_displays = [v["display"] for (t, k), v in ex.ents.items() if t == "phone"]
        email_displays = [v["display"] for (t, k), v in ex.ents.items() if t == "email"]
        self.assertIn("+972525248353", phone_displays)
        self.assertIn("amit.tuli2@gmail.com", email_displays)

        # Person must be linked to contacts
        linked_to_person = []
        for (a, b, kind) in ex.links:
            if kind == "contact":
                if a == ("person", "amit tulian"):
                    linked_to_person.append(b[0])
                elif b == ("person", "amit tulian"):
                    linked_to_person.append(a[0])

        self.assertIn("phone", linked_to_person)
        self.assertIn("email", linked_to_person)

    def test_resume_fallback_from_filename(self):
        # Body has no name at all, only contacts
        body = """Phone: 052-5248353
Email: candidate.contact@gmail.com
Experience in Python and SQL.
"""
        extractor = Extractor()
        ex = extractor.extract(body, title="Amit Tulian.pdf")

        self.assertIn(("person", "amit tulian"), ex.ents)
        self.assertEqual(ex.ents[("person", "amit tulian")]["display"], "Amit Tulian")

        # Contacts linked to Amit Tulian
        linked_types = [b[0] if a == ("person", "amit tulian") else a[0] for (a, b, k) in ex.links if k == "contact"]
        self.assertIn("phone", linked_types)
        self.assertIn("email", linked_types)

    def test_resume_fallback_from_email(self):
        # Body has no name and filename is generic
        body = """Phone: 052-5248353
Email: Amit.tuli2@gmail.com
"""
        extractor = Extractor()
        ex = extractor.extract(body, title="CV.pdf")

        # Name extracted from email Amit.tuli2@gmail.com -> Amit Tuli
        self.assertIn(("person", "amit tuli"), ex.ents)
        self.assertEqual(ex.ents[("person", "amit tuli")]["display"], "Amit Tuli")

        # Contacts linked
        linked_types = [b[0] if a == ("person", "amit tuli") else a[0] for (a, b, k) in ex.links if k == "contact"]
        self.assertIn("phone", linked_types)
        self.assertIn("email", linked_types)

    def test_hebrew_ort_document_extraction(self):
        text = """אישור לימודים מכללת אורט תעופה וחלל
שם + ת"ז: כהן ישפה ת"ז 216958868
מספר טלפון: 0547681313
דוא"ל: aircollege.co.il@gmail.com"""

        extractor = Extractor()
        ex = extractor.extract(text, title="אישור לימודים.pdf")

        # 1. Person entity: כהן ישפה
        person_keys = [k for (t, k) in ex.ents if t == "person"]
        self.assertTrue(len(person_keys) >= 1)
        self.assertTrue(any("כהן ישפה" in ex.ents[("person", k)]["display"] for k in person_keys))

        # 2. National ID: 216958868
        self.assertIn(("national_id", "216958868"), ex.ents)

        # 3. Phone: 0547681313 -> +972547681313
        self.assertIn(("phone", "+972547681313"), ex.ents)

        # 4. Email: aircollege.co.il@gmail.com
        email_displays = [v["display"] for (t, k), v in ex.ents.items() if t == "email"]
        self.assertIn("aircollege.co.il@gmail.com", email_displays)

        # 5. Links: person linked to national_id, phone, and email
        p_key = next(k for k in person_keys if "כהן ישפה" in ex.ents[("person", k)]["display"])
        p_tuple = ("person", p_key)
        linked = [b if a == p_tuple else a for (a, b, k) in ex.links if k == "contact"]
        self.assertIn(("national_id", "216958868"), linked)
        self.assertIn(("phone", "+972547681313"), linked)

    def test_hebrew_id_adjacent_variations(self):
        extractor = Extractor()

        # Name before ID with comma and תעודת זהות
        ex1 = extractor.extract("כהן ישפה, תעודת זהות: 216958868")
        self.assertTrue(any(t == "person" and "כהן ישפה" in v["display"] for (t, _), v in ex1.ents.items()))
        self.assertIn(("national_id", "216958868"), ex1.ents)

        # ID before Name
        ex2 = extractor.extract("ת\"ז 216958868 כהן ישפה")
        self.assertTrue(any(t == "person" and "כהן ישפה" in v["display"] for (t, _), v in ex2.ents.items()))
        self.assertIn(("national_id", "216958868"), ex2.ents)

    def test_parse_pdf_fallback_to_url_filename(self):
        minimal_pdf = (
            b"%PDF-1.4\n"
            b"1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n"
            b"2 0 obj<</Type/Pages/Count 1/Kids[3 0 R]>>endobj\n"
            b"3 0 obj<</Type/Page/MediaBox[0 0 612 792]/Parent 2 0 R/Resources<<>>>>endobj\n"
            b"xref\n0 4\n0000000000 65535 f \n0000000009 00000 n \n0000000052 00000 n \n0000000101 00000 n \n"
            b"trailer<</Size 4/Root 1 0 R>>\nstartxref\n178\n%%EOF"
        )
        parsed = parse_pdf(minimal_pdf, url="data/inbox/Amit Tulian.pdf")
        self.assertEqual(parsed.title, "Amit Tulian.pdf")


class FileTitleOnlyTest(unittest.TestCase):
    """The file-name name heuristic applies to a document's own file name, never to a web page title or URL."""

    def test_page_title_is_not_a_person(self):
        from osnit.extract import Extractor
        ex = Extractor().extract("מחיר מציאה! טלפון 052-6631890", title="יד שנייה - רכבים")
        self.assertFalse([k for (t, k) in ex.ents if t == "person"])

    def test_url_slug_is_not_a_person(self):
        from osnit.extract import Extractor
        ex = Extractor().extract("call 052-6631890", title="https://news.example/yossi-cohen-arrested")
        self.assertFalse([k for (t, k) in ex.ents if t == "person"])

    def test_document_file_name_still_names_its_owner(self):
        from osnit.extract import Extractor
        ex = Extractor().extract("phone 052-6631890", title="Amit Tulian.pdf")
        self.assertIn("Amit Tulian", [v["display"] for (t, k), v in ex.ents.items() if t == "person"])


if __name__ == "__main__":
    unittest.main()
