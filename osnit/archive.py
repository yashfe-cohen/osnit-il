"""
osnit.archive: Managed local archive and full lineage tracking.
Prevents raw data loss, maintains SHA-256 hashes, stores lineage paths,
and allows retrieval of exact file lines or document pages.
"""
import hashlib
import json
import logging
import os
import re
import shutil
from typing import Optional, Tuple, Dict, Any

logger = logging.getLogger("osnit.archive")

DEFAULT_ARCHIVE_DIR = "data/archive"


def get_archive_dir() -> str:
    """Returns the configured archive directory, creating it if needed."""
    d = os.environ.get("OSNIT_ARCHIVE_DIR") or DEFAULT_ARCHIVE_DIR
    os.makedirs(d, exist_ok=True)
    return d


def compute_sha256(path: str, block_size: int = 65536) -> str:
    """Computes SHA-256 hex digest of a file in streaming chunks."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(block_size), b""):
            h.update(chunk)
    return h.hexdigest()


def build_lineage(archive_rel_path: str, inner_path: Optional[str] = None, location_ref: Optional[str] = None) -> str:
    """
    Constructs a full lineage path string.
    Examples:
      - archive/dump.tar.zst::inner.zip::users.sql
      - archive/toufan.tar.zst::ikea_db.sql#table=wp_users:line=145892
      - archive/contract.pdf#page=3
    """
    parts = [archive_rel_path.replace("\\", "/")]
    if inner_path:
        parts.append(inner_path.replace("\\", "/"))
    base = "::".join(parts)
    if location_ref:
        base += f"#{location_ref}"
    return base


def archive_file(src_path: str, archive_dir: Optional[str] = None, move: bool = False, lineage_hint: Optional[str] = None) -> Dict[str, Any]:
    """
    Computes SHA-256, moves/copies file to the managed archive directory,
    and returns metadata including sha256, archive_path, and lineage.
    """
    archive_dir = archive_dir or get_archive_dir()
    os.makedirs(archive_dir, exist_ok=True)

    if not os.path.exists(src_path):
        raise FileNotFoundError(f"Source file to archive does not exist: {src_path}")

    sha = compute_sha256(src_path)
    base_name = os.path.basename(src_path)
    # Strip any inbox timestamp prefix if present
    clean_name = re.sub(r"^\d+_", "", base_name)
    target_filename = f"{sha[:16]}_{clean_name}"
    target_path = os.path.join(archive_dir, target_filename)

    if not os.path.exists(target_path):
        if move:
            shutil.move(src_path, target_path)
        else:
            shutil.copy2(src_path, target_path)
    elif move:
        # File already exists in archive, remove src if move requested
        try:
            os.remove(src_path)
        except OSError:
            pass

    rel_archive = os.path.relpath(target_path).replace("\\", "/")
    lineage = lineage_hint or rel_archive

    return {
        "sha256": sha,
        "archive_path": os.path.abspath(target_path),
        "archive_rel": rel_archive,
        "lineage": lineage
    }


def view_archive_content(store, source_id: Optional[int] = None, location_ref: Optional[str] = None, archive_path: Optional[str] = None) -> Dict[str, Any]:
    """
    Retrieves original content or snippet from the archived source file.
    Supports location_ref formats:
      - table=<name>:line=<num>
      - line=<num>
      - page=<num>
    """
    path = archive_path
    lineage = None
    if source_id:
        row = store.q1("SELECT archive_path, lineage, url FROM sources WHERE id=?", (source_id,))
        if not row:
            row = store.q1("SELECT archive_path, lineage, path FROM imports WHERE id=?", (source_id,))
        if row:
            r_dict = dict(row)
            path = r_dict.get("archive_path") or r_dict.get("url") or r_dict.get("path")
            lineage = r_dict.get("lineage")

    if not path or not os.path.exists(path):
        return {"error": "Archived file not found on disk", "path": path, "source_id": source_id}

    loc = location_ref or ""
    line_no = None
    table_name = None
    page_no = None

    m_tbl_line = re.search(r"table=([^:#]+):line=(\d+)", loc)
    if m_tbl_line:
        table_name = m_tbl_line.group(1)
        line_no = int(m_tbl_line.group(2))
    else:
        m_line = re.search(r"line=(\d+)", loc)
        if m_line:
            line_no = int(m_line.group(1))
        m_page = re.search(r"page=(\d+)", loc)
        if m_page:
            page_no = int(m_page.group(1))

    # 1. Text/SQL line retrieval
    if line_no is not None:
        target_line = ""
        context_lines = []
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                for idx, line in enumerate(f, start=1):
                    if abs(idx - line_no) <= 2:
                        context_lines.append(f"{idx}: {line.rstrip()}")
                    if idx == line_no:
                        target_line = line.rstrip()
                    if idx > line_no + 2:
                        break
            return {
                "source_id": source_id,
                "path": path,
                "lineage": lineage,
                "location_ref": loc,
                "table": table_name,
                "line": line_no,
                "content": target_line,
                "context": context_lines
            }
        except Exception as e:
            return {"error": f"Failed reading line: {e}", "path": path}

    # 2. Whole file or preview
    try:
        size = os.path.getsize(path)
        with open(path, "rb") as f:
            preview_bytes = f.read(min(size, 8192))
        return {
            "source_id": source_id,
            "path": path,
            "lineage": lineage,
            "location_ref": loc,
            "size": size,
            "preview": preview_bytes.decode("utf-8", errors="replace")[:2000]
        }
    except Exception as e:
        return {"error": str(e), "path": path}
