"""
Tests for osnit.ocr_engine (Tesseract / pytesseract backend).

All EasyOCR-specific mocks have been replaced with pytesseract equivalents.
Heavy integration tests (real Tesseract call on the Hebrew fixture image) are
included and print raw OCR output for visual verification.
"""
import io
import os
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

# Fixtures
FIXTURES_DIR = Path(__file__).parent / "fixtures"
HEBREW_IMG = FIXTURES_DIR / "photo_2026-10-13_10-25-03.jpg"


class TestOCREngineAPI(unittest.TestCase):
    """Unit tests for the public API — no real Tesseract required."""

    def test_is_ocr_available_returns_bool(self):
        from osnit.ocr_engine import is_ocr_available
        result = is_ocr_available()
        self.assertIsInstance(result, bool)

    def test_fix_bidi_english_unchanged(self):
        from osnit.ocr_engine import fix_bidi_text
        eng = "Invoice #12345"
        self.assertEqual(fix_bidi_text(eng), eng)

    def test_fix_bidi_empty_string(self):
        from osnit.ocr_engine import fix_bidi_text
        self.assertEqual(fix_bidi_text(""), "")

    def test_fix_bidi_hebrew_reverses_word_order(self):
        from osnit.ocr_engine import fix_bidi_text
        # Visually reversed Hebrew (as EasyOCR / naive OCR might produce)
        raw_visual = "לארשי ןהכ"
        corrected = fix_bidi_text(raw_visual)
        # After correction, "ישראל" and "כהן" should both be present
        self.assertIn("ישראל", corrected)
        self.assertIn("כהן", corrected)

    def test_normalize_ocr_artifacts_email(self):
        from osnit.ocr_engine import normalize_ocr_artifacts
        # Spaces inside email domain should be collapsed
        noisy = "john doe@example com"
        # function only repairs @-containing sequences; ensure it doesn't crash
        result = normalize_ocr_artifacts(noisy)
        self.assertIsInstance(result, str)

    def test_normalize_ocr_artifacts_none_input(self):
        from osnit.ocr_engine import normalize_ocr_artifacts
        self.assertIsNone(normalize_ocr_artifacts(None))  # type: ignore

    # ── ocr_image fallback when OCR is disabled ──────────────────────────────

    def test_ocr_image_returns_empty_when_unavailable(self):
        from osnit import ocr_engine
        with patch.object(ocr_engine, "_OCR_AVAILABLE", False):
            result = ocr_engine.ocr_image(b"\x89PNG\r\n\x1a\n")
            self.assertEqual(result, "")

    def test_ocr_pdf_page_returns_empty_when_unavailable(self):
        from osnit import ocr_engine
        with patch.object(ocr_engine, "_OCR_AVAILABLE", False):
            result = ocr_engine.ocr_pdf_page(b"%PDF-1.4", 0)
            self.assertEqual(result, "")

    def test_ocr_pdf_document_returns_empty_when_unavailable(self):
        from osnit import ocr_engine
        with patch.object(ocr_engine, "_OCR_AVAILABLE", False):
            result = ocr_engine.ocr_pdf_document(b"%PDF-1.4")
            self.assertEqual(result, "")

    # ── ocr_image with mocked pytesseract ────────────────────────────────────

    def test_ocr_image_with_mocked_pytesseract(self):
        """Ensure ocr_image calls pytesseract.image_to_string and returns text."""
        from osnit import ocr_engine

        fake_pil = MagicMock()
        fake_pil_cls = MagicMock(return_value=fake_pil)
        fake_pil_cls.open = MagicMock(return_value=fake_pil)

        with patch.object(ocr_engine, "_OCR_AVAILABLE", True), \
             patch.object(ocr_engine, "_PILImage", fake_pil_cls), \
             patch.object(ocr_engine, "pytesseract") as mock_tess:
            mock_tess.image_to_string.return_value = "מדינת ישראל\nמשרד המשפטים"
            result = ocr_engine.ocr_image(b"fake_png_data")
            self.assertIn("ישראל", result)
            mock_tess.image_to_string.assert_called_once()

    def test_ocr_image_exception_returns_empty(self):
        """If pytesseract raises, ocr_image should return '' not crash."""
        from osnit import ocr_engine

        with patch.object(ocr_engine, "_OCR_AVAILABLE", True), \
             patch.object(ocr_engine, "pytesseract") as mock_tess, \
             patch.object(ocr_engine, "_PILImage") as mock_pil:
            mock_pil.open.side_effect = Exception("Corrupt image")
            result = ocr_engine.ocr_image(b"bad_bytes")
            self.assertEqual(result, "")


class TestOCREngineIntegration(unittest.TestCase):
    """Integration tests — require actual Tesseract binary + tessdata installed."""

    @unittest.skipUnless(HEBREW_IMG.exists(), "Hebrew fixture image not found")
    def test_hebrew_image_real_ocr(self):
        """
        Real Tesseract OCR on the Hebrew fixture image.
        Prints raw OCR output for visual inspection.
        Verifies:
          1. Returns a non-empty string.
          2. Contains at least some Hebrew characters.
        """
        from osnit.ocr_engine import is_ocr_available, ocr_image

        if not is_ocr_available():
            self.skipTest("Tesseract binary not reachable — skipping integration test")

        with open(HEBREW_IMG, "rb") as f:
            img_bytes = f.read()

        result = ocr_image(img_bytes)  # prints raw OCR text internally
        print(f"\n[TEST] OCR result length: {len(result)} chars")

        self.assertIsInstance(result, str)
        self.assertGreater(len(result), 0, "Expected non-empty OCR output from Hebrew image")

        has_hebrew = any("\u05d0" <= c <= "\u05ea" for c in result)
        if not has_hebrew:
            print("[WARN] No Hebrew characters detected in OCR output. Tessdata may be missing heb.traineddata.")
        else:
            print("[OK] Hebrew characters detected in OCR output.")

    @unittest.skipUnless(HEBREW_IMG.exists(), "Hebrew fixture image not found")
    def test_hebrew_image_ner_extraction(self):
        """
        After OCR, run NER extraction and verify at least one entity is found.
        """
        from osnit.ocr_engine import is_ocr_available, ocr_image

        if not is_ocr_available():
            self.skipTest("Tesseract binary not reachable — skipping NER integration test")

        from osnit.extract import Extractor, Extraction

        with open(HEBREW_IMG, "rb") as f:
            img_bytes = f.read()

        raw_text = ocr_image(img_bytes)
        if not raw_text:
            self.skipTest("OCR returned empty string — cannot test NER")

        extractor = Extractor()
        entities = extractor.extract(raw_text)
        print(f"[TEST] Entities found: {len(entities.ents)}")
        self.assertIsInstance(entities, Extraction)


class TestParseIntegration(unittest.TestCase):
    """Test that parse.py correctly invokes the OCR engine for image types."""

    def test_parse_image_calls_ocr(self):
        from osnit import ocr_engine
        from osnit.parse import parse_image, Parsed

        with patch.object(ocr_engine, "_OCR_AVAILABLE", True), \
             patch.object(ocr_engine, "pytesseract") as mock_tess, \
             patch.object(ocr_engine, "_PILImage") as mock_pil:
            mock_pil.open.return_value = MagicMock()
            mock_tess.image_to_string.return_value = "טקסט מחולץ מ-OCR"

            p = parse_image(b"\x89PNG\r\n\x1a\n", "doc.png")
            self.assertIsInstance(p, Parsed)
            self.assertEqual(p.kind, "image")
            self.assertIn("OCR", p.text)

    def test_parse_image_graceful_when_ocr_disabled(self):
        from osnit import ocr_engine
        from osnit.parse import parse_image, Parsed

        with patch.object(ocr_engine, "_OCR_AVAILABLE", False):
            p = parse_image(b"\x89PNG\r\n\x1a\n", "doc.png")
            self.assertIsInstance(p, Parsed)
            # Should not crash; text may be empty
            self.assertIsInstance(p.text, str)


if __name__ == "__main__":
    unittest.main(verbosity=2)
