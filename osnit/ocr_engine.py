"""
osnit.ocr_engine: Local GPU-accelerated OCR Engine.
Uses EasyOCR (Hebrew + English) with automatic Visual-to-Logical BiDi correction.
Provides page-level fallback for scanned PDFs (<30 text chars) using in-memory pypdfium2 rendering,
and direct OCR on image files (JPG, PNG, TIFF, WEBP, BMP).
"""
import io
import logging
import os
import re
import threading
from typing import Optional, Union, List, Any

from .gpu_runtime import is_gpu_available, get_device, get_models_dir

logger = logging.getLogger("osnit.ocr")

try:
    import easyocr
    HAS_EASYOCR = True
except ImportError:
    easyocr = None
    HAS_EASYOCR = False

try:
    import pypdfium2
    HAS_PYPDFIUM2 = True
except ImportError:
    pypdfium2 = None
    HAS_PYPDFIUM2 = False

try:
    from PIL import Image
    HAS_PIL = True
except ImportError:
    Image = None
    HAS_PIL = False

try:
    import bidi.algorithm as bidi_algo
    HAS_BIDI = True
except ImportError:
    bidi_algo = None
    HAS_BIDI = False

_OCR_READER = None
_OCR_LOCK = threading.Lock()


def is_ocr_available() -> bool:
    """Returns True if EasyOCR is installed and loadable."""
    return HAS_EASYOCR


def fix_bidi_text(text: str) -> str:
    """
    Visual-to-Logical BiDi correction for Hebrew text output by OCR engines.
    EasyOCR reads RTL text visually from left to right; this restores logical word/sentence ordering.
    """
    if not text:
        return ""
    if HAS_BIDI and bidi_algo:
        try:
            return bidi_algo.get_display(text)
        except Exception:
            pass

    # Heuristic BiDi fallback when python-bidi is not installed:
    lines = text.split("\n")
    out_lines = []
    for line in lines:
        if re.search(r"[\u0590-\u05fe]", line):
            # Line has Hebrew letters: reverse Hebrew word order if visually flipped
            words = line.split()
            out_lines.append(" ".join(reversed(words)))
        else:
            out_lines.append(line)
    return "\n".join(out_lines)


def reset_ocr_reader():
    """Resets the singleton EasyOCR reader instance (useful for tests)."""
    global _OCR_READER
    with _OCR_LOCK:
        _OCR_READER = None


def get_ocr_reader(languages: Optional[Union[List[str], Any]] = None, gpu: Optional[bool] = None):
    """
    Singleton EasyOCR Reader instance loaded into GPU memory (or CPU fallback).
    """
    global _OCR_READER
    if not HAS_EASYOCR:
        return None
    if _OCR_READER is not None:
        return _OCR_READER
    with _OCR_LOCK:
        if _OCR_READER is not None:
            return _OCR_READER

        # Ensure standard list representation with Hebrew and English
        if languages:
            langs = list(languages)
            if "he" in langs and "en" in langs:
                langs = ["he", "en"] + [l for l in langs if l not in ("he", "en")]
            elif "he" in langs and "en" not in langs:
                langs = ["he", "en"]
        else:
            langs = ["he", "en"]

        if gpu is None:
            gpu = is_gpu_available()
        models_dir = get_models_dir()
        try:
            _OCR_READER = easyocr.Reader(
                langs,
                gpu=gpu,
                model_storage_directory=models_dir,
                download_enabled=True
            )
        except ValueError as ve:
            logger.warning("EasyOCR reader init with %s raised ValueError (%s), falling back to ['en']", langs, ve)
            try:
                _OCR_READER = easyocr.Reader(
                    ["en"],
                    gpu=gpu,
                    model_storage_directory=models_dir,
                    download_enabled=True
                )
            except Exception as e2:
                logger.warning("EasyOCR fallback to ['en'] also failed: %s", e2)
                _OCR_READER = None
        except Exception as e:
            logger.warning(f"Could not initialize EasyOCR reader: {e}")
            _OCR_READER = None
        return _OCR_READER


def ocr_image(image_input: Union[str, bytes, Any], languages: Optional[List[str]] = None, paragraph: bool = True) -> str:
    """
    Performs OCR on an image (file path, raw bytes, or PIL Image).
    Returns cleaned, BiDi-corrected text.
    """
    if not is_ocr_available():
        return ""
    reader = get_ocr_reader(languages=languages)
    if not reader:
        return ""

    try:
        # Convert raw bytes to PIL / numpy if needed
        if isinstance(image_input, (bytes, bytearray)):
            if HAS_PIL and Image:
                image_input = Image.open(io.BytesIO(image_input))
            else:
                # EasyOCR can accept bytes directly in some versions or via temp file
                pass
        results = reader.readtext(image_input, detail=0, paragraph=paragraph)
        raw_text = "\n".join(results) if isinstance(results, list) else str(results)

        # Print and log Raw Text extracted by OCR before passing to NER
        print(f"\n==================== [OCR RAW TEXT START] ====================\n{raw_text}\n==================== [OCR RAW TEXT END] ======================\n", flush=True)
        logger.info("[OCR RAW TEXT] Extracted %d characters from image:\n%s", len(raw_text), raw_text)

        return fix_bidi_text(raw_text)
    except Exception as e:
        logger.warning(f"OCR failed on image: {e}")
        return ""


def ocr_pdf_page(pdf_bytes: bytes, page_index: int, scale: float = 2.0) -> str:
    """
    Renders a single PDF page into memory using pypdfium2 (zero OS Poppler dependency)
    and extracts text via EasyOCR.
    """
    if not HAS_PYPDFIUM2 or not is_ocr_available():
        return ""
    try:
        pdf = pypdfium2.PdfDocument(pdf_bytes)
        if page_index < 0 or page_index >= len(pdf):
            return ""
        page = pdf.get_page(page_index)
        pil_image = page.render(scale=scale).to_pil()
        return ocr_image(pil_image)
    except Exception as e:
        logger.warning(f"Failed to OCR PDF page {page_index}: {e}")
        return ""


def ocr_pdf_document(pdf_bytes: bytes, max_pages: int = 50, min_chars_per_page: int = 30) -> str:
    """
    Performs OCR on scanned pages of a PDF document where native text extraction yielded <30 characters.
    """
    if not HAS_PYPDFIUM2 or not is_ocr_available():
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
        logger.warning(f"Failed to OCR PDF document: {e}")
        return ""
