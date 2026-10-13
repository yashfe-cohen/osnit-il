import unittest
from unittest.mock import patch, MagicMock

from osnit.ocr_engine import (
    is_ocr_available,
    fix_bidi_text,
    ocr_image,
    ocr_pdf_page,
    ocr_pdf_document,
)
from osnit.parse import parse_pdf, parse_image, parse, Parsed


class TestOCREngine(unittest.TestCase):
    def test_availability_check(self):
        # Must return boolean and never raise
        avail = is_ocr_available()
        self.assertIsInstance(avail, bool)

    def test_bidi_text_correction(self):
        # Pure English or digits should remain in order
        eng = "Invoice #12345"
        self.assertEqual(fix_bidi_text(eng), eng)

        # Hebrew line with words reversed visually
        # e.g. "ישראל כהן" written visually as "כהן ישראל"
        raw_visual = "כהן ישראל"
        corrected = fix_bidi_text(raw_visual)
        self.assertIn("ישראל", corrected)
        self.assertIn("כהן", corrected)

    def test_ocr_fallback_when_disabled(self):
        # When EasyOCR is not installed or available, returns empty string cleanly
        with patch("osnit.ocr_engine.is_ocr_available", return_value=False):
            self.assertEqual(ocr_image(b"fake_image_bytes"), "")
            self.assertEqual(ocr_pdf_page(b"fake_pdf_bytes", 0), "")
            self.assertEqual(ocr_pdf_document(b"fake_pdf_bytes"), "")

    def test_ocr_image_with_mocked_reader(self):
        mock_reader = MagicMock()
        mock_reader.readtext.return_value = ["מדינת ישראל", "משרד המשפטים"]

        with patch("osnit.ocr_engine.is_ocr_available", return_value=True), \
             patch("osnit.ocr_engine.get_ocr_reader", return_value=mock_reader):
            res = ocr_image(b"dummy_image_data")
            self.assertTrue(len(res) > 0)
            mock_reader.readtext.assert_called_once()

    def test_parse_image(self):
        # parse_image returns Parsed object with image kind
        with patch("osnit.ocr_engine.is_ocr_available", return_value=True), \
             patch("osnit.ocr_engine.ocr_image", return_value="טקסט מחולץ מ-OCR"):
            p = parse_image(b"\x89PNG\r\n\x1a\n", "doc.png")
            self.assertIsInstance(p, Parsed)
            self.assertEqual(p.kind, "image")
            self.assertIn("טקסט מחולץ מ-OCR", p.text)

    def test_scanned_pdf_page_fallback(self):
        # When pypdf extracts <30 characters on a page, triggers ocr_pdf_page fallback
        mock_page = MagicMock()
        mock_page.extract_text.return_value = "short"  # < 30 chars
        mock_page.get.return_value = []

        mock_reader_obj = MagicMock()
        mock_reader_obj.pages = [mock_page]
        mock_reader_obj.is_encrypted = False
        mock_reader_obj.metadata = {"/Title": "Scanned Doc"}

        with patch("pypdf.PdfReader", return_value=mock_reader_obj), \
             patch("osnit.ocr_engine.is_ocr_available", return_value=True), \
             patch("osnit.ocr_engine.ocr_pdf_page", return_value="טקסט מלא שחולץ בעזרת EasyOCR מעמוד הסריקה"):
            parsed = parse_pdf(b"%PDF-1.4 dummy")
            self.assertIn("EasyOCR", parsed.text)
            self.assertIn("סריקה", parsed.text)
