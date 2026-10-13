import bz2
import email
import gzip
import json
import logging
import mailbox
import os
import re
import shutil
import subprocess
import tarfile
import tempfile
import time
import zipfile
from typing import List, Dict, Any, Optional, Tuple, Set

from .detect import sniff_magic_route
from .engine import Engine
from .parse import ParseError, Parsed, parse
from .urls import normalize_url

logger = logging.getLogger("osnit.ingest")

try:
    import zstandard as zstd
    HAS_ZSTD = True
except ImportError:
    zstd = None
    HAS_ZSTD = False

try:
    import py7zr
    HAS_PY7ZR = True
except ImportError:
    py7zr = None
    HAS_PY7ZR = False

try:
    import patoolib
    HAS_PATOOL = True
except ImportError:
    patoolib = None
    HAS_PATOOL = False


def find_winrar_executable(custom_path: Optional[str] = None) -> Optional[str]:
    """
    Locates WinRAR.exe or UnRAR.exe executable on the system.
    Checks custom path, environment variables, user project directory,
    relative project folder, and standard Windows paths.
    """
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    candidate_paths = [
        custom_path,
        os.environ.get("OSNIT_WINRAR_EXE"),
        os.environ.get("WINRAR_EXE"),
        os.environ.get("OSNIT_UNRAR_TOOL"),
        os.environ.get("UNRAR_TOOL"),
        r"C:\Users\yashf\Desktop\osnit-il-main\WinRAR\WinRAR.exe",
        r"C:\Users\yashf\Desktop\osnit-il-main\WinRAR\UnRAR.exe",
        os.path.join(project_root, "WinRAR", "WinRAR.exe"),
        os.path.join(project_root, "WinRAR", "UnRAR.exe"),
        os.path.join(os.getcwd(), "WinRAR", "WinRAR.exe"),
        os.path.join(os.getcwd(), "WinRAR", "UnRAR.exe"),
        r"C:\Program Files\WinRAR\WinRAR.exe",
        r"C:\Program Files\WinRAR\UnRAR.exe",
        r"C:\Program Files\WinRAR\rar.exe",
        r"C:\Program Files\WinRAR\rar.EXE",
        r"C:\Program Files (x86)\WinRAR\WinRAR.exe",
        r"C:\Program Files (x86)\WinRAR\UnRAR.exe",
        r"C:\Program Files (x86)\WinRAR\rar.exe",
        r"C:\Program Files (x86)\WinRAR\rar.EXE",
    ]

    for p in candidate_paths:
        if p and os.path.isfile(p):
            return p
    return None


def configure_unrar_tool(custom_path: Optional[str] = None) -> Optional[str]:
    """
    Legacy helper: returns custom path or located WinRAR executable.
    """
    return find_winrar_executable(custom_path)


def extract_rar_archive(
    src_path: str,
    dest_dir: str,
    max_bytes: int = 500 * 1024 * 1024,
    _state: Optional[dict] = None
) -> List[Tuple[str, str]]:
    """
    Extracts a RAR archive to dest_dir using:
    1. patoolib (standard multi-format archive extractor in Python)
    2. Direct background subprocess with WinRAR.exe (-ibck, -inul, -y) or UnRAR.exe

    Protects against Zip Slip (directory traversal) and Zip Bomb (cumulative size).
    Returns list of (extracted_file_path, relative_file_name).
    """
    if _state is None:
        _state = {"total_bytes": 0}

    os.makedirs(dest_dir, exist_ok=True)
    extracted_items: List[Tuple[str, str]] = []

    def _collect_new_files(before_set: Set[str]) -> List[Tuple[str, str]]:
        items = []
        for root, _, files in os.walk(dest_dir):
            for fn in files:
                full_p = os.path.join(root, fn)
                if full_p not in before_set:
                    rel_n = os.path.relpath(full_p, dest_dir).replace("\\", "/")
                    safe_p = _safe_dest_path(dest_dir, rel_n)
                    file_sz = os.path.getsize(safe_p)
                    _state["total_bytes"] += file_sz
                    if _state["total_bytes"] > max_bytes:
                        raise ZipBombError(
                            f"Zip bomb protection triggered: cumulative extracted size {_state['total_bytes']} bytes exceeds {max_bytes} bytes"
                        )
                    items.append((safe_p, rel_n))
        return items

    # 1. Primary method: patoolib
    if HAS_PATOOL and patoolib:
        try:
            before_files = set()
            for root, _, files in os.walk(dest_dir):
                for fn in files:
                    before_files.add(os.path.join(root, fn))

            patoolib.extract_archive(src_path, outdir=dest_dir, interactive=False, verbosity=-1)
            new_items = _collect_new_files(before_files)
            if new_items:
                return new_items
        except ZipBombError:
            raise
        except Exception as e:
            logger.debug(f"patoolib extraction failed for {src_path}: {e}")

    # 2. Fallback method: Direct subprocess using WinRAR.exe or UnRAR.exe with background CLI flags
    winrar_bin = find_winrar_executable()
    if winrar_bin and os.path.isfile(winrar_bin):
        try:
            dest_arg = dest_dir if dest_dir.endswith(os.sep) else (dest_dir + os.sep)
            is_winrar_gui = os.path.basename(winrar_bin).lower() == "winrar.exe"
            if is_winrar_gui:
                # -ibck: Run in background (prevents GUI window)
                # -inul: Disable error dialogs / popups
                # -y: Assume Yes on all queries (overwrite, etc.)
                cmd = [winrar_bin, "x", "-ibck", "-inul", "-y", src_path, dest_arg]
            else:
                cmd = [winrar_bin, "x", "-inul", "-y", src_path, dest_arg]

            kwargs: Dict[str, Any] = {"capture_output": True, "text": True, "timeout": 180}
            if os.name == "nt":
                # CREATE_NO_WINDOW = 0x08000000
                kwargs["creationflags"] = 0x08000000

            before_files = set()
            for root, _, files in os.walk(dest_dir):
                for fn in files:
                    before_files.add(os.path.join(root, fn))

            proc = subprocess.run(cmd, **kwargs)
            # In WinRAR CLI: 0 = successful operation, 1 = non-fatal warnings
            if proc.returncode in (0, 1):
                new_items = _collect_new_files(before_files)
                if new_items:
                    return new_items
        except ZipBombError:
            raise
        except Exception as e:
            logger.debug(f"Direct WinRAR/UnRAR subprocess extraction failed for {src_path}: {e}")

    if not extracted_items:
        logger.warning(f"Could not extract RAR archive {src_path}: no working extractor tool found (patool or WinRAR)")

    return extracted_items


def extract_deep_archive(
    src_path: str,
    dest_dir: str,
    max_bytes: Optional[int] = None
) -> List[Tuple[str, str]]:
    """
    Extracts an archive (.rar, .zip, .7z, .tar, etc.) returning a list of (extracted_path, relative_name) tuples.
    """
    if src_path.lower().endswith(".rar"):
        return extract_rar_archive(src_path, dest_dir, max_bytes=max_bytes or (500 * 1024 * 1024))
    res = unpack_archive_recursive(src_path, dest_dir, max_bytes=max_bytes)
    return [(item["path"], item.get("rel_path", os.path.basename(item["path"]))) for item in res]


try:
    import extract_msg
    HAS_EXTRACT_MSG = True
except ImportError:
    extract_msg = None
    HAS_EXTRACT_MSG = False

ARCHIVE_EXTS = {
    ".zip", ".7z", ".rar", ".zst", ".tar", ".gz", ".bz2", ".tgz", ".tbz2",
    ".mbox", ".eml", ".msg"
}
SUPPORTED = {
    ".html", ".htm", ".pdf", ".docx", ".xlsx", ".csv", ".json", ".txt", ".md", ".vcf", ".xml", ".eml", ".msg",
    ".jpg", ".jpeg", ".png", ".tiff", ".tif", ".webp", ".bmp"
}
TABULAR_EXTS = {
    ".sql", ".dump", ".db", ".sqlite", ".sqlite3", ".mdb", ".accdb", ".mde", ".accde",
    ".csv", ".tsv", ".json", ".jsonl", ".ndjson", ".xlsx", ".xlsm", ".xls"
}


class ZipBombError(Exception):
    """Raised when cumulative extraction exceeds maximum allowed size."""
    pass


def is_archive(path_or_head: Any, name: str = "") -> bool:
    """Returns True if the file or bytes represent an archive or mailbox format."""
    if isinstance(path_or_head, (bytes, bytearray)):
        route = sniff_magic_route(bytes(path_or_head[:4096]), name)
        return route.get("category") == "archive"
    if isinstance(path_or_head, str):
        if not name:
            name = os.path.basename(path_or_head)
        ext = os.path.splitext(name)[1].lower()
        if ext in ARCHIVE_EXTS:
            return True
        if os.path.isfile(path_or_head):
            try:
                with open(path_or_head, "rb") as f:
                    head = f.read(4096)
                route = sniff_magic_route(head, name)
                return route.get("category") == "archive"
            except OSError:
                return False
    return False


def _safe_dest_path(dest_dir: str, filename: str) -> str:
    """Prevents Zip Slip directory traversal vulnerabilities."""
    cleaned = filename.lstrip("/\\")
    cleaned = re.sub(r"^[a-zA-Z]:[/|\\]", "", cleaned)
    parts = []
    for part in re.split(r"[/|\\]", cleaned):
        if part in ("", "."):
            continue
        if part == "..":
            raise ValueError(f"Zip slip path traversal detected: {filename}")
        parts.append(part)
    safe_rel = os.path.join(*parts) if parts else "extracted_file"
    target = os.path.abspath(os.path.join(dest_dir, safe_rel))
    dest_prefix = os.path.abspath(dest_dir) + os.sep
    if not (target.startswith(dest_prefix) or target == os.path.abspath(dest_dir)):
        raise ValueError(f"Zip slip path traversal detected: {filename}")
    return target


def unpack_archive_recursive(
    src_path: str,
    dest_dir: str,
    max_depth: int = 5,
    max_bytes: Optional[int] = None,
    current_depth: int = 0,
    parent_lineage: str = "",
    _state: Optional[Dict[str, int]] = None
) -> List[Dict[str, Any]]:
    """
    Recursively unpacks leak archives (.zip, .tar, .tar.gz, .zst, .7z, .rar, .mbox, .eml, .msg).
    Includes Zip Bomb protection (capped at OSNIT_MAX_EXTRACTED_GB, default 200GB)
    and Zip Slip directory traversal defense.
    Returns list of extracted leaf file metadata with lineage.
    """
    if max_bytes is None:
        try:
            max_gb = float(os.environ.get("OSNIT_MAX_EXTRACTED_GB", "200"))
        except ValueError:
            max_gb = 200.0
        max_bytes = int(max_gb * 1024 * 1024 * 1024)

    if _state is None:
        _state = {"total_bytes": 0}

    os.makedirs(dest_dir, exist_ok=True)
    if not parent_lineage:
        parent_lineage = os.path.basename(src_path)

    if not is_archive(src_path):
        return [{
            "path": os.path.abspath(src_path),
            "rel_path": os.path.basename(src_path),
            "lineage": parent_lineage,
            "size": os.path.getsize(src_path) if os.path.exists(src_path) else 0,
            "is_leaf": True
        }]

    extracted_items = []
    ext = os.path.splitext(src_path)[1].lower()
    head = b""
    try:
        with open(src_path, "rb") as f:
            head = f.read(4096)
    except OSError:
        pass
    route = sniff_magic_route(head, os.path.basename(src_path))
    kind = route.get("kind", "")

    # 1. ZIP
    if (kind == "zip" or ext == ".zip") and zipfile.is_zipfile(src_path):
        with zipfile.ZipFile(src_path, "r") as zf:
            for info in zf.infolist():
                if info.is_dir():
                    continue
                out_path = _safe_dest_path(dest_dir, info.filename)
                os.makedirs(os.path.dirname(out_path), exist_ok=True)
                with zf.open(info) as src, open(out_path, "wb") as dst:
                    while True:
                        chunk = src.read(65536)
                        if not chunk:
                            break
                        _state["total_bytes"] += len(chunk)
                        if _state["total_bytes"] > max_bytes:
                            raise ZipBombError(
                                f"Zip bomb protection triggered: cumulative extracted size {_state['total_bytes']} bytes exceeds {max_bytes} bytes"
                            )
                        dst.write(chunk)
                extracted_items.append((out_path, info.filename))

    # 2. TAR / TAR.GZ / TAR.BZ2
    elif tarfile.is_tarfile(src_path) or kind == "tar" or ext in (".tar", ".tgz", ".tbz2"):
        try:
            with tarfile.open(src_path, "r:*") as tf:
                for member in tf.getmembers():
                    if not member.isfile():
                        continue
                    out_path = _safe_dest_path(dest_dir, member.name)
                    os.makedirs(os.path.dirname(out_path), exist_ok=True)
                    f_in = tf.extractfile(member)
                    if f_in:
                        with f_in, open(out_path, "wb") as dst:
                            while True:
                                chunk = f_in.read(65536)
                                if not chunk:
                                    break
                                _state["total_bytes"] += len(chunk)
                                if _state["total_bytes"] > max_bytes:
                                    raise ZipBombError(
                                        f"Zip bomb protection triggered: cumulative extracted size {_state['total_bytes']} bytes exceeds {max_bytes} bytes"
                                    )
                                dst.write(chunk)
                        extracted_items.append((out_path, member.name))
        except (tarfile.TarError, OSError) as e:
            logger.warning(f"Failed tar extraction on {src_path}: {e}")

    # 3. Gzip standalone
    elif kind == "gz" or ext in (".gz", ".tgz"):
        base_name = os.path.basename(src_path)
        inner_name = base_name[:-3] if base_name.lower().endswith(".gz") else base_name + ".extracted"
        out_path = _safe_dest_path(dest_dir, inner_name)
        os.makedirs(os.path.dirname(out_path), exist_ok=True)
        with gzip.open(src_path, "rb") as f_in, open(out_path, "wb") as dst:
            while True:
                chunk = f_in.read(65536)
                if not chunk:
                    break
                _state["total_bytes"] += len(chunk)
                if _state["total_bytes"] > max_bytes:
                    raise ZipBombError(
                        f"Zip bomb protection triggered: cumulative extracted size {_state['total_bytes']} bytes exceeds {max_bytes} bytes"
                    )
                dst.write(chunk)
        extracted_items.append((out_path, inner_name))

    # 4. Bzip2 standalone
    elif kind == "bz2" or ext in (".bz2", ".tbz2"):
        base_name = os.path.basename(src_path)
        inner_name = base_name[:-4] if base_name.lower().endswith(".bz2") else base_name + ".extracted"
        out_path = _safe_dest_path(dest_dir, inner_name)
        os.makedirs(os.path.dirname(out_path), exist_ok=True)
        with bz2.open(src_path, "rb") as f_in, open(out_path, "wb") as dst:
            while True:
                chunk = f_in.read(65536)
                if not chunk:
                    break
                _state["total_bytes"] += len(chunk)
                if _state["total_bytes"] > max_bytes:
                    raise ZipBombError(
                        f"Zip bomb protection triggered: cumulative extracted size {_state['total_bytes']} bytes exceeds {max_bytes} bytes"
                    )
                dst.write(chunk)
        extracted_items.append((out_path, inner_name))

    # 5. Zstandard (.zst)
    elif kind == "zst" or ext == ".zst":
        if HAS_ZSTD:
            base_name = os.path.basename(src_path)
            inner_name = base_name[:-4] if base_name.lower().endswith(".zst") else base_name + ".extracted"
            out_path = _safe_dest_path(dest_dir, inner_name)
            os.makedirs(os.path.dirname(out_path), exist_ok=True)
            dctx = zstd.ZstdDecompressor()
            with open(src_path, "rb") as f_in, open(out_path, "wb") as dst:
                reader = dctx.stream_reader(f_in)
                while True:
                    chunk = reader.read(65536)
                    if not chunk:
                        break
                    _state["total_bytes"] += len(chunk)
                    if _state["total_bytes"] > max_bytes:
                        raise ZipBombError(
                            f"Zip bomb protection triggered: cumulative extracted size {_state['total_bytes']} bytes exceeds {max_bytes} bytes"
                        )
                    dst.write(chunk)
            extracted_items.append((out_path, inner_name))
        else:
            logger.warning(f"zstandard module not installed, skipping decompression of {src_path}")

    # 6. 7-Zip (.7z)
    elif kind == "7z" or ext == ".7z":
        if HAS_PY7ZR:
            with py7zr.SevenZipFile(src_path, mode="r") as sz:
                for fname, bio in sz.readall().items():
                    out_path = _safe_dest_path(dest_dir, fname)
                    os.makedirs(os.path.dirname(out_path), exist_ok=True)
                    data = bio.read()
                    _state["total_bytes"] += len(data)
                    if _state["total_bytes"] > max_bytes:
                        raise ZipBombError(
                            f"Zip bomb protection triggered: cumulative extracted size {_state['total_bytes']} bytes exceeds {max_bytes} bytes"
                        )
                    with open(out_path, "wb") as dst:
                        dst.write(data)
                    extracted_items.append((out_path, fname))
        else:
            logger.warning(f"py7zr module not installed, skipping extraction of {src_path}")

    # 7. RAR (.rar)
    elif kind == "rar" or ext == ".rar":
        rar_items = extract_rar_archive(src_path, dest_dir, max_bytes=max_bytes, _state=_state)
        extracted_items.extend(rar_items)

    # 8. MBOX
    elif kind == "mbox" or ext == ".mbox":
        try:
            mb = mailbox.mbox(src_path)
            try:
                for idx, msg in enumerate(mb):
                    eml_name = f"message_{idx:05d}.eml"
                    eml_path = _safe_dest_path(dest_dir, eml_name)
                    os.makedirs(os.path.dirname(eml_path), exist_ok=True)
                    raw_bytes = msg.as_bytes()
                    _state["total_bytes"] += len(raw_bytes)
                    if _state["total_bytes"] > max_bytes:
                        raise ZipBombError(f"Zip bomb protection triggered: cumulative extracted size exceeds {max_bytes} bytes")
                    with open(eml_path, "wb") as dst:
                        dst.write(raw_bytes)
                    extracted_items.append((eml_path, eml_name))

                    for part_idx, part in enumerate(msg.walk()):
                        fn = part.get_filename()
                        if fn:
                            safe_fn = re.sub(r"[^\w.\-]+", "_", fn) or f"att_{part_idx}"
                            att_name = f"msg_{idx:05d}_{safe_fn}"
                            att_path = _safe_dest_path(dest_dir, att_name)
                            payload = part.get_payload(decode=True)
                            if payload:
                                _state["total_bytes"] += len(payload)
                                if _state["total_bytes"] > max_bytes:
                                    raise ZipBombError(f"Zip bomb protection triggered: cumulative extracted size exceeds {max_bytes} bytes")
                                with open(att_path, "wb") as dst:
                                    dst.write(payload)
                                extracted_items.append((att_path, att_name))
            finally:
                mb.close()
        except Exception as e:
            logger.warning(f"mbox extraction failed on {src_path}: {e}")

    # 9. EML
    elif kind == "eml" or ext == ".eml":
        try:
            with open(src_path, "rb") as f:
                msg = email.message_from_binary_file(f)
            for part_idx, part in enumerate(msg.walk()):
                fn = part.get_filename()
                if fn:
                    safe_fn = re.sub(r"[^\w.\-]+", "_", fn) or f"att_{part_idx}"
                    att_name = f"att_{part_idx}_{safe_fn}"
                    att_path = _safe_dest_path(dest_dir, att_name)
                    payload = part.get_payload(decode=True)
                    if payload:
                        _state["total_bytes"] += len(payload)
                        if _state["total_bytes"] > max_bytes:
                            raise ZipBombError(f"Zip bomb protection triggered: cumulative extracted size exceeds {max_bytes} bytes")
                        with open(att_path, "wb") as dst:
                            dst.write(payload)
                        extracted_items.append((att_path, att_name))
        except Exception as e:
            logger.warning(f"eml extraction failed on {src_path}: {e}")

    # 10. MSG
    elif kind == "msg" or ext == ".msg":
        if HAS_EXTRACT_MSG:
            try:
                msg = extract_msg.Message(src_path)
                body = msg.body
                if body:
                    b_name = os.path.splitext(os.path.basename(src_path))[0] + "_body.txt"
                    b_path = _safe_dest_path(dest_dir, b_name)
                    with open(b_path, "w", encoding="utf-8") as dst:
                        dst.write(body)
                    extracted_items.append((b_path, b_name))
                for att_idx, att in enumerate(msg.attachments):
                    fn = getattr(att, "longFilename", None) or getattr(att, "shortFilename", None) or f"att_{att_idx}.bin"
                    safe_fn = re.sub(r"[^\w.\-]+", "_", fn)
                    att_path = _safe_dest_path(dest_dir, safe_fn)
                    data = getattr(att, "data", None)
                    if data:
                        _state["total_bytes"] += len(data)
                        if _state["total_bytes"] > max_bytes:
                            raise ZipBombError(f"Zip bomb protection triggered: cumulative extracted size exceeds {max_bytes} bytes")
                        with open(att_path, "wb") as dst:
                            dst.write(data)
                        extracted_items.append((att_path, safe_fn))
            except Exception as e:
                logger.warning(f"extract_msg failed on {src_path}: {e}")
        else:
            logger.warning(f"extract_msg module not installed, skipping extraction of {src_path}")

    # Recursive descent on extracted archives
    results = []
    for out_path, rel_name in extracted_items:
        item_lineage = f"{parent_lineage}::{rel_name}"
        is_nested = False
        if current_depth + 1 < max_depth:
            if not rel_name.endswith(".eml") and is_archive(out_path, rel_name):
                is_nested = True

        if is_nested:
            sub_dest = os.path.join(dest_dir, f"sub_{len(results)}_{os.path.splitext(rel_name)[0]}")
            os.makedirs(sub_dest, exist_ok=True)
            sub_items = unpack_archive_recursive(
                out_path,
                sub_dest,
                max_depth=max_depth,
                max_bytes=max_bytes,
                current_depth=current_depth + 1,
                parent_lineage=item_lineage,
                _state=_state
            )
            results.extend(sub_items)
        else:
            results.append({
                "path": os.path.abspath(out_path),
                "rel_path": rel_name,
                "lineage": item_lineage,
                "size": os.path.getsize(out_path) if os.path.exists(out_path) else 0,
                "is_leaf": True
            })

    return results


def _source_row(engine, url, now, import_id=None, archive_path=None, lineage=None, sha256=None):
    sid, _ = engine.store.add_source(url, priority=0, origin="import", now=now, import_id=import_id,
                                    archive_path=archive_path, lineage=lineage, sha256=sha256)
    return engine.store.q1("SELECT * FROM sources WHERE id=?", (sid,))


def import_parsed(engine: Engine, url: str, parsed: Parsed, now=None, import_id=None,
                  archive_path=None, lineage=None, sha256=None):
    now = now or time.time()
    row = _source_row(engine, url, now, import_id, archive_path=archive_path, lineage=lineage, sha256=sha256)
    return engine.ingest(row, parsed, now, state="imported")


def scan_file_for_identifiers(path: str, max_bytes: int = 4_000_000) -> dict:
    """A fast local scan of a just-downloaded file: pull the contactable identifiers (emails, phones, national IDs,
    names) out of its text immediately, so an aggressive crawl can act on a find without waiting for the full
    import. Reuses the project's extractor and the sensitive engine; never raises."""
    try:
        with open(path, "rb") as f:
            body = f.read(max_bytes)
        p = parse(body, "file://" + os.path.basename(path), "")
    except Exception as e:
        return {"error": str(e)[:200], "emails": [], "phones": [], "national_ids": [], "names": []}
    from .extract import Extractor
    from .sensitive import analyze_text
    ex = Extractor([]).extract(p.text[:max_bytes], p.title)
    emails = sorted({e["display"] for (t, _), e in ex.ents.items() if t == "email"})
    phones = sorted({e["display"] for (t, _), e in ex.ents.items() if t == "phone"})
    names = sorted({e["display"] for (t, _), e in ex.ents.items() if t == "person"})
    rep = analyze_text(p.text[:max_bytes], source=os.path.basename(path))
    ids = sorted({f.value for f in rep.findings if f.kind == "national_id"})
    return {"emails": emails, "phones": phones, "national_ids": ids, "names": names,
            "sensitive": len(rep.findings)}


def import_path(engine: Engine, path: str, base_url: str = None, delete_raw: bool = False,
                import_id=None, lineage: str = None) -> dict:
    """Walk `path` or unpack archive; each file becomes a source (file:// URL, or base_url + relative path).
    Raw files are removed afterwards only when delete_raw=True (the importer never deletes by default)."""
    res = {"imported": 0, "unchanged": 0, "failed": 0, "deleted": 0}

    # If the file itself is an archive, unpack it recursively
    if os.path.isfile(path) and is_archive(path):
        staging_dir = tempfile.mkdtemp(prefix="osnit_unpack_")
        try:
            leaf_files = unpack_archive_recursive(path, staging_dir, parent_lineage=lineage or os.path.basename(path))
            for item in leaf_files:
                fp = item["path"]
                item_lineage = item["lineage"]
                ext = os.path.splitext(fp)[1].lower()
                if ext == ".jsonl":
                    r = import_jsonl(engine, fp)
                    for k in r:
                        res[k] = res.get(k, 0) + r[k]
                elif ext in TABULAR_EXTS:
                    from .importdb import import_db
                    try:
                        r = import_db(engine, fp, label=item_lineage, import_id=import_id, lineage=item_lineage)
                        res["imported"] += r.get("records", 0) + r.get("documents", 0)
                        res["failed"] += r.get("skipped", 0)
                    except Exception:
                        res["failed"] += 1
                elif ext in SUPPORTED or ext in (".txt", ".pdf", ".docx", ".xlsx", ".vcf", ".xml"):
                    url = "file://" + os.path.abspath(fp)
                    try:
                        with open(fp, "rb") as f:
                            body = f.read()
                        out = import_parsed(engine, normalize_url(url) or url, parse(body, url, ""),
                                            import_id=import_id, lineage=item_lineage)
                        res["imported" if out in ("scanned", "imported") else "unchanged"] += 1
                        del body
                    except (OSError, ParseError):
                        res["failed"] += 1
            if delete_raw:
                try:
                    os.remove(path)
                    res["deleted"] += 1
                except OSError:
                    pass
        finally:
            shutil.rmtree(staging_dir, ignore_errors=True)
        return res

    files = [path] if os.path.isfile(path) else [os.path.join(d, f) for d, _, fs in os.walk(path) for f in sorted(fs)]
    for fp in files:
        ext = os.path.splitext(fp)[1].lower()
        if ext == ".jsonl":
            r = import_jsonl(engine, fp)
            for k in r:
                res[k] = res.get(k, 0) + r[k]
        elif is_archive(fp):
            r = import_path(engine, fp, base_url=base_url, delete_raw=delete_raw, import_id=import_id,
                            lineage=f"{lineage or os.path.basename(path)}::{os.path.basename(fp)}")
            for k in r:
                res[k] = res.get(k, 0) + r[k]
        elif ext in SUPPORTED:
            rel = os.path.relpath(fp, path if os.path.isdir(path) else os.path.dirname(path))
            url = (base_url.rstrip("/") + "/" + rel.replace(os.sep, "/")) if base_url else "file://" + os.path.abspath(fp)
            try:
                with open(fp, "rb") as f:
                    body = f.read()
                out = import_parsed(engine, normalize_url(url) or url, parse(body, url, ""),
                                    import_id=import_id, lineage=lineage)
                res["imported" if out in ("scanned", "imported") else "unchanged"] += 1
                del body
                if delete_raw:
                    os.remove(fp)
                    res["deleted"] += 1
            except (OSError, ParseError):
                res["failed"] += 1
    return res


def import_text_chunks(engine: Engine, path: str, import_id=None, chunk_chars=1_000_000, progress=None) -> dict:
    """A huge free-text file, read and extracted piece by piece (~1M characters, cut at a line end) — each piece
    its own source ('file://…#part<N>'), so memory stays flat and the server stays responsive."""
    from .importdb import _detect_encoding
    from .textnorm import clean
    res = {"imported": 0, "unchanged": 0, "failed": 0, "deleted": 0}
    base = "file://" + os.path.abspath(path)
    buf, size, part = [], 0, 0

    def flush():
        nonlocal buf, size, part
        text = clean("".join(buf))
        buf, size = [], 0
        if text.strip():
            try:
                out = import_parsed(engine, f"{base}#part{part}", Parsed("txt", text), import_id=import_id)
                res["imported" if out in ("scanned", "imported") else "unchanged"] += 1
            except Exception:
                res["failed"] += 1
        part += 1
        if progress:
            progress(res)

    with open(path, encoding=_detect_encoding(path), errors="replace") as f:
        for ln in f:
            buf.append(ln)
            size += len(ln)
            if size >= chunk_chars:
                flush()
    if buf:
        flush()
    return res


def import_jsonl(engine: Engine, path: str) -> dict:
    res = {"imported": 0, "failed": 0}
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            try:
                rec = json.loads(line)
                url = normalize_url(rec["url"]) or rec["url"]
                if "html" in rec:
                    p = parse(rec["html"].encode("utf-8"), url, "text/html; charset=utf-8")
                else:
                    from .textnorm import clean
                    p = Parsed("txt", clean(rec["text"]), clean(rec.get("title", "")))
                import_parsed(engine, url, p)
                res["imported"] += 1
            except (ValueError, KeyError, TypeError):
                res["failed"] += 1
    return res
