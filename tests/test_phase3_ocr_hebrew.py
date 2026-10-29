"""
Phase 3 Real-World E2E QA Test Suite:
OCR & Hebrew Text Extraction (Tesseract heb+eng, 300 DPI PDF fallback,
histogram verification, RGBA & dark-mode normalization, and entity extraction).
"""
import io
import os
import unittest
from pathlib import Path
from PIL import Image, ImageDraw, ImageFont

from osnit.ocr_engine import (
    is_ocr_available,
    get_tesseract_info,
    ocr_image,
    ocr_pdf_page,
    _prepare_grayscale_and_verify_histogram,
    DEFAULT_PDF_OCR_SCALE,
)
from osnit.parse import parse_pdf
from osnit.extract import Extractor


PROJECT_ROOT = Path(__file__).resolve().parent.parent
HEBREW_PHOTO = PROJECT_ROOT / "tests" / "fixtures" / "photo_2026-10-13_10-25-03.jpg"
AMIT_PDF = PROJECT_ROOT / "Amit Tulian.pdf"


def _load_hebrew_font(size: int = 32):
    for candidate in (
        r"C:\Windows\Fonts\arial.ttf",
        r"C:\Windows\Fonts\david.ttf",
        r"C:\Windows\Fonts\tahoma.ttf",
        r"C:\Windows\Fonts\segoeui.ttf",
    ):
        if os.path.isfile(candidate):
            return ImageFont.truetype(candidate, size)
    return ImageFont.load_default()


class TestPhase3OCRHebrew(unittest.TestCase):
    def test_01_tesseract_configuration_and_tessdata(self):
        info = get_tesseract_info()
        print("\n[Phase 3] Tesseract Diagnostic Info:", info)
        self.assertTrue(is_ocr_available(), "Tesseract OCR must be available")
        self.assertTrue(info["has_heb"], "heb.traineddata must be present in tessdata")
        self.assertTrue(info["has_eng"], "eng.traineddata must be present in tessdata")
        self.assertEqual(info["default_lang"], "heb+eng")
        self.assertTrue(os.path.isdir(info["tessdata_prefix_env"]))
        self.assertAlmostEqual(DEFAULT_PDF_OCR_SCALE, 300.0 / 72.0, places=3)

    def test_02_real_hebrew_photo_ocr_and_entities(self):
        self.assertTrue(HEBREW_PHOTO.is_file(), f"Missing fixture: {HEBREW_PHOTO}")
        raw_bytes = HEBREW_PHOTO.read_bytes()
        text = ocr_image(raw_bytes)
        print(f"\n[Phase 3] Real Hebrew Photo OCR Length: {len(text)} chars")
        self.assertGreater(len(text), 50, "Hebrew photo OCR must extract > 50 characters")

        heb_chars = [c for c in text if "\u0590" <= c <= "\u05fe"]
        self.assertGreater(len(heb_chars), 30, "Expected substantial Hebrew characters in OCR output")

        ext = Extractor().extract(text)
        print("[Phase 3] Extracted Entities from Hebrew Photo:", ext.ents)
        self.assertIn(("national_id", "216958868"), ext.ents)
        self.assertIn(("phone", "+972547681313"), ext.ents)
        self.assertIn(("person", "ישפה כהנ"), ext.ents)

    def test_03_real_pdf_digital_and_300dpi_ocr(self):
        # 1. Digital PDF with live text stream (fast-path extraction without OCR)
        content_stream = (
            b"BT /F1 12 Tf 50 750 Td "
            b"(Curriculum Vitae - Amit Tulian - Senior Cyber Intelligence Analyst) Tj "
            b"0 -20 Td (Email: amit.tulian@intel-unit.co.il | Phone: 052-8877665 | ID: 039199047) Tj ET"
        )
        digital_pdf = (
            b"%PDF-1.4\n"
            b"1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj\n"
            b"2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj\n"
            b"3 0 obj << /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
            b"/Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >> endobj\n"
            b"4 0 obj << /Length " + str(len(content_stream)).encode() + b" >>\nstream\n"
            + content_stream + b"\nendstream\nendobj\n"
            b"5 0 obj << /Type /Font /Subtype /Type1 /BaseFont /Helvetica >> endobj\n"
            b"xref\n0 6\n0000000000 65535 f \n"
            b"trailer << /Root 1 0 R /Size 6 >>\n%%EOF\n"
        )
        parsed = parse_pdf(digital_pdf, "Amit_Tulian_CV.pdf")
        self.assertGreater(len(parsed.text), 50)
        self.assertIn("Amit Tulian", parsed.text)
        self.assertIn("amit.tulian@intel-unit.co.il", parsed.text)

        # 2. Forced 300 DPI rasterized OCR on a clean PDF page via ocr_pdf_page
        font = _load_hebrew_font(36)
        page_img = Image.new("RGB", (1200, 600), (255, 255, 255))
        draw = ImageDraw.Draw(page_img)
        draw.text((50, 60), "CURRICULUM VITAE - AMIT TULIAN", fill=(0, 0, 0), font=font)
        draw.text((50, 140), "EMAIL: amit.tulian@cyber.co.il | TEL: 052-8877665", fill=(0, 0, 0), font=font)
        draw.text((50, 220), "NATIONAL ID: 039199047 | TEL AVIV ISRAEL", fill=(0, 0, 0), font=font)
        pdf_buf = io.BytesIO()
        page_img.save(pdf_buf, format="PDF", resolution=300.0)

        ocr_text = ocr_pdf_page(pdf_buf.getvalue(), 0)
        print(f"\n[Phase 3] 300-DPI PDF Page OCR Length: {len(ocr_text)} chars")
        self.assertGreater(len(ocr_text), 50, "300 DPI PDF OCR must extract > 50 characters")
        self.assertIn("AMIT TULIAN", ocr_text.upper())
        self.assertIn("039199047", ocr_text)

    def test_04_scanned_hebrew_pdf_automatic_ocr_fallback(self):
        """
        Creates a real scanned (image-only, zero digital text) PDF from the Hebrew fixture photo
        and verifies that parse_pdf automatically triggers the 300 DPI OCR fallback and extracts >50 chars.
        """
        img = Image.open(HEBREW_PHOTO).convert("RGB")
        pdf_buf = io.BytesIO()
        img.save(pdf_buf, format="PDF", resolution=300.0)
        scanned_pdf_bytes = pdf_buf.getvalue()

        parsed = parse_pdf(scanned_pdf_bytes, "scanned_hebrew_certificate.pdf")
        print(f"\n[Phase 3] Scanned Hebrew PDF Auto-OCR Length: {len(parsed.text)} chars")
        self.assertGreater(len(parsed.text), 50, "Scanned Hebrew PDF must extract > 50 chars via OCR")
        self.assertIn("216958868", parsed.text)
        heb_chars = [c for c in parsed.text if "\u0590" <= c <= "\u05fe"]
        self.assertGreater(len(heb_chars), 30)

    def test_05_rgba_transparent_and_dark_mode_hebrew_images(self):
        """
        Verifies the two root-cause 0-char fixes:
          1. RGBA image with transparent background (0,0,0,0) and black text (0,0,0,255)
          2. Dark-mode high-res screenshot (>300k px) with dark background and light Hebrew/English text
        Note: PIL ImageDraw without libraqm draws LTR character order, so we pass visual order or
        use fix_bidi_text to render visual Hebrew glyphs accurately.
        """
        font = _load_hebrew_font(34)
        # Visual order for PIL when libraqm is not compiled in:
        lines = [
            "OSNIT-IL INTELLIGENCE REPORT 2026",
            "ID: 039994256 | PHONE: 054-7681313",
            "EMAIL: daniel.cohen@intel.co.il",
        ]

        # Case A: RGBA transparent background with black text (1000x400 = 400,000 px)
        rgba_img = Image.new("RGBA", (1000, 400), (0, 0, 0, 0))
        draw_a = ImageDraw.Draw(rgba_img)
        y = 40
        for line in lines:
            draw_a.text((40, y), line, fill=(0, 0, 0, 255), font=font)
            y += 80

        g_a, stats_a = _prepare_grayscale_and_verify_histogram(rgba_img)
        self.assertTrue(stats_a["has_ink"], "RGBA transparent image must preserve ink after white compositing")
        text_a = ocr_image(rgba_img)
        print(f"\n[Phase 3] RGBA Transparent Image OCR ({len(text_a)} chars):\n{text_a}")
        self.assertGreater(len(text_a), 50, "RGBA image must extract > 50 chars (not 0)")
        self.assertIn("039994256", text_a)

        # Case B: Dark-mode screenshot (dark background, white text, 1000x400 = 400,000 px)
        dark_img = Image.new("RGB", (1000, 400), (15, 20, 28))
        draw_b = ImageDraw.Draw(dark_img)
        y = 40
        for line in lines:
            draw_b.text((40, y), line, fill=(240, 246, 252), font=font)
            y += 80

        g_b, stats_b = _prepare_grayscale_and_verify_histogram(dark_img)
        self.assertTrue(stats_b["inverted"], "Dark-mode image must be automatically inverted to dark-on-light")
        self.assertTrue(stats_b["has_ink"], "Dark-mode image must have valid ink ratio after inversion")
        text_b = ocr_image(dark_img)
        print(f"\n[Phase 3] Dark-Mode Image OCR ({len(text_b)} chars):\n{text_b}")
        self.assertGreater(len(text_b), 50, "Dark-mode image must extract > 50 chars (not 0)")
        self.assertIn("039994256", text_b)


if __name__ == "__main__":
    unittest.main(verbosity=2)
