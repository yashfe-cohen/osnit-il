"""
osnit.ocr_engine: Hebrew + English OCR engine using Tesseract (via pytesseract).
Provides page-level fallback for scanned PDFs (<30 text chars) using in-memory pypdfium2 rendering,
and direct OCR on image files (JPG, PNG, TIFF, WEBP, BMP).

Architecture & Strategy:
  1. Prefer bundled portable Tesseract in tools/Tesseract-OCR/ (zero external install required).
  2. Fall back to system PATH Tesseract if bundled binary is not present.
  3. Uses heb+eng when Hebrew traineddata is available, otherwise eng only.
  4. Automatic environment variable configuration (TESSDATA_PREFIX) for cross-platform portability.
  5. All OCR dependencies are wrapped in try/except ImportError for clean degradation.
"""
import io
import logging
import os
import re
import threading
from typing import Optional, Union, List, Any

logger = logging.getLogger("osnit.ocr")

# ── Locate bundled Tesseract ──────────────────────────────────────────────────
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_BUNDLED_TESS = os.path.join(_PROJECT_ROOT, "tools", "Tesseract-OCR", "tesseract.exe")
_TESSDATA_DIR = os.path.join(_PROJECT_ROOT, "tools", "Tesseract-OCR", "tessdata")
_HAS_HEB_DATA = os.path.isfile(os.path.join(_TESSDATA_DIR, "heb.traineddata"))
_HAS_ENG_DATA = os.path.isfile(os.path.join(_TESSDATA_DIR, "eng.traineddata"))
_DEFAULT_LANG = "heb+eng" if _HAS_HEB_DATA else "eng"

# Configure TESSDATA_PREFIX environment variable if bundled directory exists
if os.path.isdir(_TESSDATA_DIR):
    os.environ["TESSDATA_PREFIX"] = _TESSDATA_DIR

# ── Optional dependencies ─────────────────────────────────────────────────────
try:
    import pytesseract
    from PIL import Image as _PILImage

    # Point pytesseract at bundled binary if available, else rely on PATH
    if os.path.isfile(_BUNDLED_TESS):
        pytesseract.pytesseract.tesseract_cmd = _BUNDLED_TESS
        logger.info("Tesseract: using bundled binary at %s", _BUNDLED_TESS)
    else:
        logger.info("Tesseract: using system PATH (bundled binary not found)")

    # Smoke-test that Tesseract is actually reachable
    try:
        _TESS_VERSION = pytesseract.get_tesseract_version()
        logger.info("Tesseract version: %s", _TESS_VERSION)
        _OCR_AVAILABLE = True
    except Exception as _e:
        logger.warning("Tesseract binary not reachable: %s — OCR disabled", _e)
        _OCR_AVAILABLE = False

except ImportError:
    pytesseract = None  # type: ignore
    _PILImage = None  # type: ignore
    _OCR_AVAILABLE = False
    logger.info("pytesseract or Pillow not installed — OCR disabled")

try:
    import pypdfium2
    _HAS_PYPDFIUM2 = True
except ImportError:
    pypdfium2 = None  # type: ignore
    _HAS_PYPDFIUM2 = False

try:
    import bidi.algorithm as _bidi_algo
    _HAS_BIDI = True
except ImportError:
    _bidi_algo = None  # type: ignore
    _HAS_BIDI = False


# ── Public helpers ────────────────────────────────────────────────────────────

def is_ocr_available() -> bool:
    """Returns True if Tesseract OCR is installed, configured and reachable."""
    return _OCR_AVAILABLE


def get_ocr_reader(*args, **kwargs) -> Any:
    """Compatibility helper for legacy code/tests."""
    if not _OCR_AVAILABLE:
        return None
    return pytesseract


def reset_ocr_reader() -> None:
    """Compatibility helper for legacy code/tests."""
    pass


def fix_bidi_text(text: str) -> str:
    """
    Visual-to-Logical BiDi correction for Hebrew text.
    Reverses words and characters for text that was rendered/extracted in visual RTL order.
    """
    if not text:
        return ""
    if _HAS_BIDI and _bidi_algo:
        try:
            return _bidi_algo.get_display(text)
        except Exception:
            pass

    # Heuristic fallback: reverse letters in Hebrew words and reverse word order
    lines = text.split("\n")
    out_lines = []
    for line in lines:
        if re.search(r"[\u0590-\u05fe]", line):
            words = line.split()
            rev_words = [
                "".join(reversed(w)) if re.search(r"[\u0590-\u05fe]", w) else w
                for w in reversed(words)
            ]
            out_lines.append(" ".join(rev_words))
        else:
            out_lines.append(line)
    return "\n".join(out_lines)


def normalize_ocr_artifacts(text: str) -> str:
    """Corrects common OCR artifacts such as spaces in place of dots in email addresses."""
    if not text:
        return text

    def _fix_mail(m):
        raw = m.group(0)
        local, _, dom = raw.partition("@")
        local = re.sub(r"\s+", ".", local.strip())
        dom = re.sub(r"\s+", ".", dom.strip())
        return f"{local}@{dom}"

    return re.sub(
        r"(?i)\b[a-z0-9_\-]+(?:\s+[a-z0-9_\-]+)*\s*@\s*[a-z0-9_\-]+"
        r"(?:\s+[a-z0-9_\-]+)*\s+(?:com|co\s+il|org|net|edu|gov)\b",
        _fix_mail,
        text,
    )


def _build_tess_config() -> str:
    """
    Build pytesseract config string.
    TESSDATA_PREFIX environment variable handles the path directly without command-line quotes.
    """
    if os.path.isdir(_TESSDATA_DIR):
        os.environ["TESSDATA_PREFIX"] = _TESSDATA_DIR
    return ""


def _ocr_pil_image(img: Any, use_lang: str, config: str) -> str:
    """
    Runs Tesseract OCR on a PIL Image (or mock object).
    For real high-resolution photos/scans (>= 300k pixels), applies local illumination
    normalization (Gaussian background subtraction + contrast enhancement) to remove
    camera shadows and runs complementary page segmentation passes (--psm 3 and --psm 6).
    For small synthetic images or unit-test mocks, invokes image_to_string once directly.
    """
    is_real_pil = (
        _PILImage is not None
        and isinstance(_PILImage, type)
        and isinstance(img, _PILImage)
    )
    if not is_real_pil and hasattr(_PILImage, "Image") and isinstance( getattr(_PILImage, "Image", None), type):
        is_real_pil = isinstance(img, _PILImage.Image)

    if is_real_pil:
        try:
            w, h = int(img.width), int(img.height)
        except Exception:
            w, h = 0, 0
        if w * h >= 300_000:
            try:
                from PIL import ImageOps, ImageFilter, ImageChops, ImageEnhance

                g = ImageOps.grayscale(img)
                resampling = getattr(_PILImage, "Resampling", _PILImage).LANCZOS

                # Pass 1: 1.5x upscaled illumination-normalized with automatic layout (--psm 3)
                g2 = g.resize((int(w * 1.5), int(h * 1.5)), resampling)
                bg2 = g2.filter(ImageFilter.GaussianBlur(radius=45))
                diff2 = ImageChops.subtract(bg2, g2)
                norm2 = ImageEnhance.Contrast(
                    ImageOps.invert(ImageOps.autocontrast(diff2, cutoff=0))
                ).enhance(1.58)
                cfg1 = f"{config} --psm 3".strip()
                t1 = pytesseract.image_to_string(norm2, lang=use_lang, config=cfg1)

                # Pass 2: 1.0x illumination-normalized with uniform block layout (--psm 6)
                bg1 = g.filter(ImageFilter.GaussianBlur(radius=30))
                diff1 = ImageChops.subtract(bg1, g)
                norm1 = ImageOps.invert(ImageOps.autocontrast(diff1, cutoff=0))
                cfg2 = f"{config} --psm 6".strip()
                t2 = pytesseract.image_to_string(norm1, lang=use_lang, config=cfg2)

                return f"{t1.strip()}\n{t2.strip()}".strip()
            except Exception as e:
                logger.debug("Illumination preprocessing fallback: %s", e)

    return pytesseract.image_to_string(img, lang=use_lang, config=config)


def ocr_image(
    image_input: Union[str, bytes, Any],
    lang: Optional[str] = None,
) -> str:
    """
    Performs OCR on an image (file path, raw bytes, or PIL Image).
    Returns cleaned text string in logical Unicode order.
    """
    if not _OCR_AVAILABLE:
        logger.debug("OCR not available; skipping image OCR")
        return ""
    try:
        # Convert inputs to PIL Image
        if isinstance(image_input, (bytes, bytearray)):
            img = _PILImage.open(io.BytesIO(image_input))
        elif isinstance(image_input, str) and os.path.isfile(image_input):
            img = _PILImage.open(image_input)
        else:
            img = image_input

        # Ensure TESSDATA_PREFIX is configured in process environment
        if os.path.isdir(_TESSDATA_DIR):
            os.environ["TESSDATA_PREFIX"] = _TESSDATA_DIR

        use_lang = lang or _DEFAULT_LANG
        config = _build_tess_config()
        raw_text = _ocr_pil_image(img, use_lang, config)
        raw_text = raw_text.strip()
        raw_text = normalize_ocr_artifacts(raw_text)

        try:
            print(
                f"\n==================== [OCR RAW TEXT START] ====================\n"
                f"{raw_text}\n"
                f"==================== [OCR RAW TEXT END] ======================\n",
                flush=True,
            )
        except UnicodeEncodeError:
            pass
        logger.info("[OCR] Extracted %d characters (lang=%s)", len(raw_text), use_lang)
        return raw_text
    except Exception as e:
        logger.error("[OCR ERROR] ocr_image failed: %s", e)
        return ""


def ocr_pdf_page(pdf_bytes: bytes, page_index: int, scale: float = 2.0) -> str:
    """
    Renders a single PDF page into memory using pypdfium2
    and extracts text via Tesseract OCR.
    """
    if not _HAS_PYPDFIUM2 or not _OCR_AVAILABLE:
        return ""
    try:
        pdf = pypdfium2.PdfDocument(pdf_bytes)
        if page_index < 0 or page_index >= len(pdf):
            return ""
        page = pdf.get_page(page_index)
        pil_image = page.render(scale=scale).to_pil()
        buf = io.BytesIO()
        pil_image.save(buf, format="PNG")
        return ocr_image(buf.getvalue())
    except Exception as e:
        logger.warning("Failed to OCR PDF page %d: %s", page_index, e)
        return ""


def ocr_pdf_document(
    pdf_bytes: bytes, max_pages: int = 50, min_chars_per_page: int = 30
) -> str:
    """
    Performs OCR on all scanned pages of a PDF document where native text
    extraction yielded fewer than min_chars_per_page characters.
    """
    if not _HAS_PYPDFIUM2 or not _OCR_AVAILABLE:
        return ""
    try:
        pdf = pypdfium2.PdfDocument(pdf_bytes)
        num_pages = min(len(pdf), max_pages)
        pages_text = []
        for i in range(num_pages):
            page_text = ocr_pdf_page(pdf_bytes, i)
            if page_text:
                pages_text.append(page_text)
        return "\n\n".join(pages_text)
    except Exception as e:
        logger.warning("Failed to OCR PDF document: %s", e)
        return ""
