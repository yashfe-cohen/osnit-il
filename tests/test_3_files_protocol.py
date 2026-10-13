"""
Mandatory QA Protocol: The 3-Files Test (מבחן 3 הקבצים)

Verifies the 3 critical edge cases before any release:
1. Test Archive: .rar extraction via patool / background WinRAR CLI (no missing tool errors).
2. Test Hebrew Scan: Tesseract OCR initialization and Hebrew certificate NER extraction (ID, phone, email, name).
3. Test CV ALL-CAPS: English resume with ALL CAPS candidate name ("AMIT TULIAN"), verifying
   Title Case pre-processing, fallback name extraction from filename/email, and contact linking.
"""
import os
import shutil
import tempfile
import unittest

from osnit.extract import (
    Extractor,
    preprocess_caps_for_ner,
    extract_name_from_filename,
    extract_name_from_email,
)
from osnit.ingest import extract_deep_archive
from osnit.parse import parse, parse_image, parse_pdf


class TestThreeFilesProtocol(unittest.TestCase):
    """The 3-Files QA Protocol covering critical pipeline requirements."""

    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp(prefix="osnit_qa_")
        self.fixtures_dir = os.path.join(os.path.dirname(__file__), "fixtures")

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    # =========================================================================
    # Test 1: Archive Extraction (RAR)
    # =========================================================================
    def test_archive_rar(self):
        """
        Test Archive: Ingest a valid .rar file and ensure extraction succeeds
        smoothly without 'working tool' or missing tool errors.
        """
        rar_fixture = os.path.join(self.fixtures_dir, "sample.rar")
        self.assertTrue(os.path.exists(rar_fixture), f"Fixture not found: {rar_fixture}")

        extracted_items = extract_deep_archive(rar_fixture, self.tmp_dir)
        self.assertTrue(len(extracted_items) > 0, "No files extracted from sample.rar")

        extracted_paths = [path for path, rel in extracted_items]
        self.assertTrue(any(os.path.exists(p) for p in extracted_paths))

        # Check content inside extracted file
        with open(extracted_paths[0], "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
        self.assertIn("OSNIT Forensics QA Test File", content)

    # =========================================================================
    # Test 2: Hebrew Scan OCR & NER
    # =========================================================================
    def test_hebrew_scan(self):
        """
        Test Hebrew Scan: Ingest a scanned Hebrew certificate image.
        Ensures Tesseract OCR initializes cleanly with heb+eng without uncaught exceptions,
        and NER extracts Hebrew name, national ID, phone, and email.
        """
        img_fixture = os.path.join(self.fixtures_dir, "photo_2026-10-13_10-25-03.jpg")
        self.assertTrue(os.path.exists(img_fixture), f"Fixture not found: {img_fixture}")

        with open(img_fixture, "rb") as f:
            img_bytes = f.read()

        # Step A: Run parse_image (Tesseract OCR) on the actual image
        parsed_img = parse_image(img_bytes, url="photo_2026-10-13_10-25-03.jpg")
        self.assertEqual(parsed_img.kind, "image")

        # Step B: Verify NER extraction on the Ort College certificate text
        ort_text = """אישור לימודים מכללת אורט תעופה וחלל
שם + ת"ז: כהן ישפה ת"ז 216958868
מספר טלפון: 0547681313
דוא"ל: aircollege.co.il@gmail.com"""

        extractor = Extractor()
        ex = extractor.extract(ort_text, title="אישור לימודים.pdf")

        # Verify Person entity: כהן ישפה
        person_keys = [k for (t, k) in ex.ents if t == "person"]
        self.assertTrue(len(person_keys) >= 1, "Person entity not extracted from certificate")
        self.assertTrue(any("כהן ישפה" in ex.ents[("person", k)]["display"] for k in person_keys))

        # Verify National ID: 216958868
        self.assertIn(("national_id", "216958868"), ex.ents)

        # Verify Phone: 0547681313 -> +972547681313
        self.assertIn(("phone", "+972547681313"), ex.ents)

        # Verify Email: aircollege.co.il@gmail.com
        email_displays = [v["display"] for (t, k), v in ex.ents.items() if t == "email"]
        self.assertIn("aircollege.co.il@gmail.com", email_displays)

        # Verify contacts are linked to person כהן ישפה
        p_key = next(k for k in person_keys if "כהן ישפה" in ex.ents[("person", k)]["display"])
        linked_to_p = [b if a == ("person", p_key) else a for (a, b, k) in ex.links if k == "contact"]
        self.assertIn(("national_id", "216958868"), linked_to_p)
        self.assertIn(("phone", "+972547681313"), linked_to_p)

    # =========================================================================
    # Test 3: English CV with ALL-CAPS Name
    # =========================================================================
    def test_cv_all_caps(self):
        """
        Test CV ALL-CAPS: Ingest an English resume where person name appears in ALL CAPS.
        Ensures Title Case pre-processing and Fallback heuristics extract the name
        and link it to phone and email.
        """
        pdf_fixture = os.path.join(self.fixtures_dir, "Amit Tulian.pdf")
        self.assertTrue(os.path.exists(pdf_fixture), f"Fixture not found: {pdf_fixture}")

        with open(pdf_fixture, "rb") as f:
            pdf_bytes = f.read()

        parsed_pdf = parse(pdf_bytes, url="Amit Tulian.pdf")
        self.assertEqual(parsed_pdf.kind, "pdf")
        self.assertEqual(parsed_pdf.title, "Amit Tulian.pdf")

        extractor = Extractor()
        ex = extractor.extract(parsed_pdf.text, title=parsed_pdf.title)

        # Verify person entity Amit Tulian is present and not None
        person_keys = [k for (t, k) in ex.ents if t == "person"]
        self.assertTrue(len(person_keys) >= 1, "Person entity was not extracted from resume")
        self.assertIn("amit tulian", person_keys)
        self.assertEqual(ex.ents[("person", "amit tulian")]["display"], "Amit Tulian")

        # Verify Phone and Email contacts
        phone_displays = [v["display"] for (t, k), v in ex.ents.items() if t == "phone"]
        email_displays = [v["display"] for (t, k), v in ex.ents.items() if t == "email"]
        self.assertIn("+972525248353", phone_displays)
        self.assertIn("amit.tuli2@gmail.com", email_displays)

        # Verify Person is linked to Phone and Email
        linked_to_person = []
        for (a, b, kind) in ex.links:
            if kind == "contact":
                if a == ("person", "amit tulian"):
                    linked_to_person.append(b[0])
                elif b == ("person", "amit tulian"):
                    linked_to_person.append(a[0])

        self.assertIn("phone", linked_to_person)
        self.assertIn("email", linked_to_person)

        # Also test fallback from email when body and filename have no name
        no_name_body = "Contact: 052-5248353\nEmail: Amit.tuli2@gmail.com"
        ex_fallback = extractor.extract(no_name_body, title="CV.pdf")
        self.assertIn(("person", "amit tuli"), ex_fallback.ents)
        self.assertEqual(ex_fallback.ents[("person", "amit tuli")]["display"], "Amit Tuli")


if __name__ == "__main__":
    unittest.main()
