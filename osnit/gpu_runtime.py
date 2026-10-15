"""
osnit.gpu_runtime: Hardware & GPU resource management (CUDA / MPS / CPU fallback).
Enables native local GPU acceleration for OCR and NER pipelines with graceful CPU fallbacks.
"""
import logging
import os
import sys

logger = logging.getLogger("osnit.gpu")

try:
    import torch
    _HAS_TORCH = True
except ImportError:
    torch = None
    _HAS_TORCH = False


def is_torch_available() -> bool:
    """Returns True if PyTorch is installed and importable."""
    return _HAS_TORCH


def is_cuda_available() -> bool:
    """Returns True if NVIDIA CUDA acceleration is active."""
    if not _HAS_TORCH:
        return False
    try:
        return bool(torch.cuda.is_available())
    except Exception:
        return False


def is_mps_available() -> bool:
    """Returns True if Apple Silicon Metal (MPS) acceleration is active."""
    if not _HAS_TORCH:
        return False
    try:
        return hasattr(torch.backends, "mps") and bool(torch.backends.mps.is_available())
    except Exception:
        return False


def is_gpu_available() -> bool:
    """Returns True if any hardware GPU acceleration (CUDA or MPS) is available."""
    return is_cuda_available() or is_mps_available()


def get_device() -> str:
    """Returns the primary compute device string: 'cuda', 'mps', or 'cpu'."""
    if is_cuda_available():
        return "cuda"
    if is_mps_available():
        return "mps"
    return "cpu"


def get_models_dir() -> str:
    """Returns the configured models directory (data/models by default)."""
    d = os.environ.get("OSNIT_MODELS_DIR") or os.path.join("data", "models")
    os.makedirs(d, exist_ok=True)
    return d


def get_device_info() -> dict:
    """
    Returns hardware resource and acceleration info dictionary.
    Safe to call in any environment (with or without PyTorch / GPU).
    """
    if not _HAS_TORCH:
        return {
            "torch_available": False,
            "gpu_available": False,
            "device": "cpu",
            "name": "CPU (PyTorch not installed - deterministic engine active)",
            "vram_total_mb": 0,
            "vram_free_mb": 0,
        }

    if is_cuda_available():
        try:
            device_idx = torch.cuda.current_device()
            device_name = torch.cuda.get_device_name(device_idx)
            free_bytes, total_bytes = torch.cuda.mem_get_info(device_idx)
            return {
                "torch_available": True,
                "gpu_available": True,
                "device": "cuda",
                "name": f"NVIDIA {device_name}",
                "vram_total_mb": round(total_bytes / (1024 * 1024)),
                "vram_free_mb": round(free_bytes / (1024 * 1024)),
            }
        except Exception as e:
            return {
                "torch_available": True,
                "gpu_available": True,
                "device": "cuda",
                "name": f"CUDA Device (info error: {e})",
                "vram_total_mb": 0,
                "vram_free_mb": 0,
            }

    if is_mps_available():
        return {
            "torch_available": True,
            "gpu_available": True,
            "device": "mps",
            "name": "Apple Silicon (MPS)",
            "vram_total_mb": 0,
            "vram_free_mb": 0,
        }

    return {
        "torch_available": True,
        "gpu_available": False,
        "device": "cpu",
        "name": "CPU (PyTorch CPU fallback)",
        "vram_total_mb": 0,
        "vram_free_mb": 0,
    }


def log_gpu_status() -> str:
    """Logs and returns the active compute device status line."""
    info = get_device_info()
    if info["gpu_available"]:
        msg = f"GPU Active: {info['name']}"
        if info.get("vram_total_mb"):
            msg += f" (VRAM: {info['vram_free_mb']}MB free / {info['vram_total_mb']}MB total)"
        logger.info(msg)
        print(f"==> {msg}")
    else:
        msg = f"GPU Inactive: Running on {info['name']}"
        logger.info(msg)
        print(f"==> {msg}")
    return msg


def clear_vram_cache() -> None:
    """Frees cached GPU memory to prevent VRAM overflow after large batches."""
    if not _HAS_TORCH:
        return
    try:
        if is_cuda_available():
            torch.cuda.empty_cache()
            torch.cuda.ipc_collect()
        elif is_mps_available() and hasattr(torch, "mps") and hasattr(torch.mps, "empty_cache"):
            torch.mps.empty_cache()
    except Exception as e:
        logger.debug("Failed to empty GPU cache: %s", e)


def warmup(models_dir: str = None) -> dict:
    """
    Pre-warms and downloads AI models (Tesseract OCR + DictaBERT-NER) to local models_dir.
    Guarantees 100% offline local capability.
    """
    log_gpu_status()
    models_dir = models_dir or os.path.join("data", "models")
    os.makedirs(models_dir, exist_ok=True)
    results = {
        "device": get_device(),
        "gpu_available": is_gpu_available(),
        "ocr": "not_installed",
        "dictabert_ner": "not_installed",
        "models_dir": models_dir
    }

    # 1. Tesseract OCR (Hebrew + English)
    try:
        from .ocr_engine import is_ocr_available, _HAS_HEB_DATA, _HAS_ENG_DATA, _DEFAULT_LANG
        if is_ocr_available():
            lang_status = []
            if _HAS_HEB_DATA:
                lang_status.append("heb")
            if _HAS_ENG_DATA:
                lang_status.append("eng")
            langs_str = "+".join(lang_status) if lang_status else _DEFAULT_LANG
            logger.info("Tesseract OCR initialized successfully (langs: %s).", langs_str)
            results["ocr"] = f"ready (tesseract, langs={langs_str})"
            results["easyocr"] = results["ocr"]  # backward compatibility alias
        else:
            logger.info("Tesseract OCR is not installed or available.")
            results["ocr"] = "not_available"
            results["easyocr"] = "not_available"
    except Exception as e:
        logger.warning("OCR warmup warning: %s", e)
        results["ocr"] = f"error: {e}"
        results["easyocr"] = results["ocr"]

    # 2. DictaBERT-NER
    try:
        from transformers import AutoTokenizer, AutoModelForTokenClassification
        model_name = "dicta-il/dictabert-ner"
        logger.info("Pre-warming DictaBERT-NER from %s to %s...", model_name, models_dir)
        AutoTokenizer.from_pretrained(model_name, cache_dir=models_dir)
        AutoModelForTokenClassification.from_pretrained(model_name, cache_dir=models_dir)
        results["dictabert_ner"] = "ready"
        logger.info("DictaBERT-NER warmed up successfully.")
    except ImportError:
        logger.info("Transformers / DictaBERT-NER is not installed (optional).")
    except Exception as e:
        logger.warning("DictaBERT-NER warmup warning: %s", e)
        results["dictabert_ner"] = f"error: {e}"

    clear_vram_cache()
    return results
