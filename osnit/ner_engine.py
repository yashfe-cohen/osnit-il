"""
osnit.ner_engine: Local Statistical Named Entity Recognition (NER) Engine.
Uses `dicta-il/dictabert-ner` on GPU (CUDA) or CPU to recognize persons, organizations,
and locations in free-text documents, OCR results, and SQL/CSV unmapped/notes columns.
Combines with the deterministic regex engine (running with high threshold >= 0.85).
"""
import logging
import os
import re
import threading
from typing import Optional, List, Dict, Any

from .gpu_runtime import is_gpu_available, get_device, get_models_dir

logger = logging.getLogger("osnit.ner")

try:
    import torch
    HAS_TORCH = True
except ImportError:
    torch = None
    HAS_TORCH = False

try:
    from transformers import AutoTokenizer, AutoModelForTokenClassification, pipeline
    HAS_TRANSFORMERS = True
except ImportError:
    AutoTokenizer = None
    AutoModelForTokenClassification = None
    pipeline = None
    HAS_TRANSFORMERS = False

_NER_PIPELINE = None
_NER_LOCK = threading.Lock()

DEFAULT_NER_THRESHOLD = 0.85

ENTITY_TYPE_MAP = {
    "PER": "person",
    "ORG": "org",
    "LOC": "address",
    "GPE": "address",
    "FAC": "address",
    "EVE": "event"
}


def is_ner_available() -> bool:
    """Returns True if PyTorch and Transformers are available."""
    return HAS_TORCH and HAS_TRANSFORMERS


def get_ner_pipeline(model_path: Optional[str] = None):
    """
    Singleton HuggingFace NER pipeline loaded on GPU (if available) or CPU.
    Loads locally from data/models/dictabert-ner when present.
    """
    global _NER_PIPELINE
    if not is_ner_available():
        return None
    if _NER_PIPELINE is not None:
        return _NER_PIPELINE
    with _NER_LOCK:
        if _NER_PIPELINE is not None:
            return _NER_PIPELINE
        models_dir = get_models_dir()
        local_dir = os.path.join(models_dir, "dictabert-ner")
        model_name = local_dir if os.path.exists(local_dir) else (model_path or "dicta-il/dictabert-ner")
        device = 0 if is_gpu_available() else -1
        try:
            tokenizer = AutoTokenizer.from_pretrained(model_name, local_files_only=os.path.exists(local_dir))
            model = AutoModelForTokenClassification.from_pretrained(model_name, local_files_only=os.path.exists(local_dir))
            _NER_PIPELINE = pipeline(
                "ner",
                model=model,
                tokenizer=tokenizer,
                aggregation_strategy="simple",
                device=device
            )
        except Exception as e:
            logger.warning(f"Could not load DictaBERT-NER pipeline from {model_name}: {e}")
            _NER_PIPELINE = None
        return _NER_PIPELINE


def _split_into_chunks(text: str, max_chars: int = 400) -> List[tuple]:
    """
    Splits text into sentence/line chunks preserving character offsets (chunk_text, start_offset).
    """
    chunks = []
    lines = re.split(r"(\n+|[.!?]+(?:\s+|$))", text)
    curr = []
    curr_len = 0
    curr_start = 0
    pos = 0

    for part in lines:
        if not part:
            continue
        part_len = len(part)
        if curr_len + part_len > max_chars and curr:
            chunk_str = "".join(curr)
            chunks.append((chunk_str, curr_start))
            curr = [part]
            curr_start = pos
            curr_len = part_len
        else:
            if not curr:
                curr_start = pos
            curr.append(part)
            curr_len += part_len
        pos += part_len

    if curr:
        chunks.append(("".join(curr), curr_start))
    return chunks


def extract_entities_ner(
    text: str,
    threshold: float = DEFAULT_NER_THRESHOLD,
    batch_size: int = 16
) -> List[Dict[str, Any]]:
    """
    Extracts named entities from Hebrew/English text using DictaBERT-NER.
    Returns list of dicts: {"type": ..., "value": ..., "confidence": ..., "start": ..., "end": ...}
    Only returns entities with confidence >= threshold (default 0.85).
    """
    if not is_ner_available() or not text or not text.strip():
        return []

    pipe = get_ner_pipeline()
    if not pipe:
        return []

    chunks = _split_into_chunks(text)
    if not chunks:
        return []

    results = []
    texts = [c[0] for c in chunks]
    starts = [c[1] for c in chunks]

    try:
        raw_outputs = pipe(texts, batch_size=batch_size)
    except Exception as e:
        logger.warning(f"DictaBERT-NER inference failed: {e}")
        return []

    if isinstance(raw_outputs, dict):
        raw_outputs = [raw_outputs]

    for chunk_idx, entities in enumerate(raw_outputs):
        base_offset = starts[chunk_idx]
        if not isinstance(entities, list):
            entities = [entities]
        for ent in entities:
            score = float(ent.get("score", 0.0))
            if score < threshold:
                continue

            entity_group = ent.get("entity_group") or ent.get("entity") or ""
            # Strip B- or I- prefixes if present
            entity_group = re.sub(r"^[BI]-", "", entity_group).upper()
            mapped_type = ENTITY_TYPE_MAP.get(entity_group)
            if not mapped_type:
                continue

            word = ent.get("word", "").strip()
            # Clean DictaBERT subwords or punctuation
            word = word.replace("##", "").strip()
            if len(word) < 2:
                continue

            start = base_offset + ent.get("start", 0)
            end = base_offset + ent.get("end", len(word))

            results.append({
                "type": mapped_type,
                "raw_type": entity_group,
                "value": word,
                "confidence": score,
                "start": start,
                "end": end
            })

    return results
