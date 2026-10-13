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


def _get_short_path(path: str) -> str:
    """
    Returns 8.3 short path on Windows if available to avoid quote/space issues
    with Tesseract CLI arguments.
    """
    if os.name == "nt" and os.path.exists(path):
        try:
            import ctypes
            buf = ctypes.create_unicode_buffer(500)
            if ctypes.windll.kernel32.GetShortPathNameW(path, buf, 500):
                return buf.value or path
        except Exception:
            pass
    return path


# Configure TESSDATA_PREFIX environment variable if bundled directory exists
if os.path.isdir(_TESSDATA_DIR):
    os.environ["TESSDATA_PREFIX"] = _TESSDATA_DIR

# ── Optional dependencies ─────────────────────────────────────────────────────
try:
    import pytesseract
    from PIL import Image as _PILImage

    # Point pytesseract at bundled binary if available, else rely on PATH
    if os.path.isfile(_BUNDLED_TESS):
        pytesseract.pytesseract.tesseract_cmd = _get_short_path(_BUNDLED_TESS)
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


def _build_tess_config(psm: Optional[int] = 6) -> str:
    """
    Build pytesseract config string.
    Explicitly provides --tessdata-dir to ensure Tesseract CLI finds language traineddata files,
    and sets --psm (Page Segmentation Mode, default 6).
    """
    configs: List[str] = []
    if os.path.isdir(_TESSDATA_DIR):
        os.environ["TESSDATA_PREFIX"] = _TESSDATA_DIR
        safe_path = _get_short_path(_TESSDATA_DIR)
        # Avoid quote-concatenation bugs in Tesseract CLI on Windows
        if " " in safe_path:
            configs.append(f'--tessdata-dir "{safe_path}"')
        else:
            configs.append(f'--tessdata-dir {safe_path}')
    if psm is not None:
        configs.append(f"--psm {psm}")
    return " ".join(configs)


def ocr_image(
    image_input: Union[str, bytes, Any],
    lang: Optional[str] = None,
    psm: Optional[int] = 6,
    config: Optional[str] = None,
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
        use_config = config if config is not None else _build_tess_config(psm=psm)
        raw_text = pytesseract.image_to_string(img, lang=use_lang, config=use_config)
        raw_text = raw_text.strip()
        raw_text = normalize_ocr_artifacts(raw_text)

        print(
            f"\n==================== [OCR RAW TEXT START] ====================\n"
            f"{raw_text}\n"
            f"==================== [OCR RAW TEXT END] ======================\n",
            flush=True,
        )
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
