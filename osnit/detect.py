"""Auto-detect the structure of a file a user hands us, so extraction adapts to varied layouts.

Returns a plan: kind, recognised columns (for tabular), a confidence, and whether an AI pass could
help. The heuristic is the default; `ai_hint` marks files where a model (e.g. Gemini) could map
ambiguous columns — the AI layer is opt-in and only ever *adds* a mapping, see osnit.ai.
"""
import csv
import io
import json
import os
import re

from .catalog import detect_columns
from .parse import decode, sniff_kind

RECOGNISABLE = {"name", "first", "last", "email", "phone", "org", "role", "url", "domain", "text"}

ARCHIVE_EXTS = {
    ".zip", ".7z", ".rar", ".zst", ".tar", ".gz", ".bz2", ".tgz", ".tbz2",
    ".mbox", ".eml", ".msg"
}
VISUAL_EXTS = {".jpg", ".jpeg", ".png", ".tiff", ".tif", ".webp", ".bmp"}
STRUCTURED_EXTS = {
    ".sql", ".dump", ".db", ".sqlite", ".sqlite3", ".mdb", ".accdb", ".mde", ".accde",
    ".csv", ".tsv", ".json", ".jsonl", ".ndjson", ".xlsx", ".xlsm", ".xls"
}
RICH_TEXT_EXTS = {".pdf", ".docx", ".doc", ".html", ".htm", ".vcf", ".xml", ".txt", ".md", ".rtf", ".log"}


def sniff_magic_route(head: bytes, name: str = "") -> dict:
    """
    Magic-Bytes Router (v2.0): Inspects the first 16+ bytes of content to detect
    exact file type and routes it to one of four processing tracks:
    1. 'archive': compressed leak archives and mailboxes (.zip, .7z, .rar, .zst, .tar, .gz, .bz2, .mbox, .eml, .msg)
    2. 'structured': databases and spreadsheets (.sql, .db, .sqlite, .mdb, .csv, .tsv, .jsonl, .xlsx)
    3. 'rich_text': documents (.pdf, .docx, .html, .vcf, .xml, .txt)
    4. 'visual': visual image formats (.jpg, .png, .tiff, .webp, .bmp)
    """
    ext = os.path.splitext(name)[1].lower() if name else ""
    head16 = head[:16]

    # --- 1. Archives & Mailboxes ---
    if head16.startswith(b"7z\xbc\xaf\x27\x1c") or ext == ".7z":
        return dict(category="archive", kind="7z", confidence=0.95, note="ארכיון 7-Zip")
    if head16.startswith(b"Rar!\x1a\x07") or ext == ".rar":
        return dict(category="archive", kind="rar", confidence=0.95, note="ארכיון RAR")
    if head16.startswith(b"\x28\xb5\x2f\xfd") or ext == ".zst":
        return dict(category="archive", kind="zst", confidence=0.95, note="ארכיון Zstandard (.zst)")
    if head16.startswith(b"\x1f\x8b") or ext in (".gz", ".tgz"):
        return dict(category="archive", kind="gz", confidence=0.95, note="ארכיון Gzip")
    if head16.startswith(b"BZh") or ext in (".bz2", ".tbz2"):
        return dict(category="archive", kind="bz2", confidence=0.95, note="ארכיון Bzip2")
    if head16.startswith(b"From ") or ext == ".mbox":
        return dict(category="archive", kind="mbox", confidence=0.9, note="תיבת דואר MBOX")
    if ext == ".tar" or (len(head) >= 262 and head[257:262] == b"ustar"):
        return dict(category="archive", kind="tar", confidence=0.95, note="ארכיון TAR")

    # ZIP container: can be docx, xlsx, or standard zip
    if head16.startswith(b"PK\x03\x04") or head16.startswith(b"PK\x05\x06") or ext == ".zip":
        sample = head[:4096]
        if b"word/" in sample or ext == ".docx":
            return dict(category="rich_text", kind="docx", confidence=0.9, note="מסמך Word")
        if b"xl/" in sample or ext in (".xlsx", ".xlsm"):
            return dict(category="structured", kind="xlsx", confidence=0.9, note="גיליון Excel")
        return dict(category="archive", kind="zip", confidence=0.95, note="ארכיון ZIP")

    # OLE compound file: can be .msg, .xls, .doc
    if head16.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
        sample = head[:4096]
        if ext == ".msg" or b"__substg1.0" in sample:
            return dict(category="archive", kind="msg", confidence=0.9, note="הודעת Outlook (.msg)")
        if ext == ".xls" or b"Workbook" in sample or b"Book" in sample:
            return dict(category="structured", kind="xls", confidence=0.8, note="Excel ישן (.xls)")
        return dict(category="rich_text", kind="doc", confidence=0.7, note="מסמך Word ישן (.doc)")

    if ext == ".eml":
        return dict(category="archive", kind="eml", confidence=0.85, note="הודעת דואר EML")

    # --- 2. Visual / Images ---
    if head16.startswith(b"\xff\xd8\xff") or ext in (".jpg", ".jpeg"):
        return dict(category="visual", kind="jpg", confidence=0.95, note="תמונה JPEG")
    if head16.startswith(b"\x89PNG\r\n\x1a\n") or ext == ".png":
        return dict(category="visual", kind="png", confidence=0.95, note="תמונה PNG")
    if head16.startswith(b"II*\x00") or head16.startswith(b"MM\x00*") or ext in (".tiff", ".tif"):
        return dict(category="visual", kind="tiff", confidence=0.95, note="תמונה TIFF")
    if (head[:4] == b"RIFF" and head[8:12] == b"WEBP") or ext == ".webp":
        return dict(category="visual", kind="webp", confidence=0.95, note="תמונה WebP")
    if head16.startswith(b"BM") or ext == ".bmp":
        return dict(category="visual", kind="bmp", confidence=0.9, note="תמונה BMP")

    # --- 3. Structured Data ---
    if head[4:19] in (b"Standard Jet DB", b"Standard ACE DB") or ext in (".mdb", ".accdb", ".mde", ".accde"):
        return dict(category="structured", kind="access", confidence=0.95, note="מסד Microsoft Access")
    if head16.startswith(b"SQLite format 3\x00") or ext in (".db", ".sqlite", ".sqlite3"):
        return dict(category="structured", kind="sqlite", confidence=0.95, note="מסד SQLite")
    if ext in (".sql", ".dump") or re.search(rb"\b(INSERT\s+INTO|CREATE\s+TABLE|COPY\s+.*?FROM\s+stdin)\b", head[:2048], re.I):
        return dict(category="structured", kind="sql_dump", confidence=0.9, note="SQL dump")
    if ext in (".jsonl", ".ndjson") or (head.lstrip()[:1] == b"{" and b"\n{" in head[:4096]):
        return dict(category="structured", kind="jsonl", confidence=0.85, note="JSON לפי שורות")
    if ext == ".json" or head.lstrip()[:1] in (b"{", b"["):
        return dict(category="structured", kind="json", confidence=0.7, note="JSON")
    if ext in (".csv", ".tsv") or (ext not in RICH_TEXT_EXTS and b"," in head[:2048] and b"\n" in head[:2048] and b"<" not in head[:1]):
        return dict(category="structured", kind="csv" if ext != ".tsv" else "tsv", confidence=0.85, note="טבלה מופרדת")

    # --- 4. Rich Text Documents ---
    if head16.startswith(b"%PDF-") or ext == ".pdf":
        return dict(category="rich_text", kind="pdf", confidence=0.95, note="מסמך PDF")
    if head16.startswith(b"{\\rtf") or ext == ".rtf":
        return dict(category="rich_text", kind="rtf", confidence=0.9, note="מסמך RTF")
    if b"<html" in head[:1024].lower() or b"<!doctype html" in head[:1024].lower() or ext in (".html", ".htm"):
        return dict(category="rich_text", kind="html", confidence=0.85, note="דף אינטרנט")
    if b"BEGIN:VCARD" in head[:512] or ext == ".vcf":
        return dict(category="rich_text", kind="vcf", confidence=0.9, note="כרטיסי קשר VCF")
    if b"<?xml" in head[:256] or ext == ".xml":
        return dict(category="rich_text", kind="xml", confidence=0.85, note="מסמך XML")

    return dict(category="unknown", kind=ext.lstrip(".") or "unknown", confidence=0.2, note="לא מזוהה")


def _table_plan(cols, sample_rows):
    cm = detect_columns(cols)
    recognised = {k: v for k, v in cm.items() if k in RECOGNISABLE}
    identifying = recognised.keys() & {"name", "first", "last", "email", "phone"}
    return cm, recognised, identifying


def detect(body: bytes, name: str = "") -> dict:
    ext = os.path.splitext(name)[1].lower()
    head = body[:8192]
    route = sniff_magic_route(head, name)

    # Route: Archive
    if route["category"] == "archive":
        return dict(kind="archive", archive_type=route["kind"], confidence=route["confidence"], ai_hint=False,
                    note=route["note"])

    # Route: Visual
    if route["category"] == "visual":
        return dict(kind=route["kind"], category="visual", confidence=route["confidence"], ai_hint=False,
                    note=route["note"])

    if head[4:19] in (b"Standard Jet DB", b"Standard ACE DB") or ext in (".mdb", ".accdb", ".mde", ".accde"):
        return dict(kind="access", confidence=0.95, ai_hint=False,
                    note="מסד Microsoft Access" + (" (accdb)" if head[4:19] == b"Standard ACE DB" else " (mdb)"))

    if ext in (".sql", ".dump") or re.search(rb"\b(INSERT\s+INTO|CREATE\s+TABLE)\b", head, re.I):
        from .sqldump import read_sql_dump
        text = decode(body[:1_000_000])
        tables = []
        for tname, cols, rows in read_sql_dump(text):
            cm, rec, ident = _table_plan(cols, rows[:5])
            tables.append(dict(table=tname, columns=cols, recognised=rec, identifying=sorted(ident)))
        ok = any(t["identifying"] for t in tables)
        return dict(kind="sql_dump", tables=tables, confidence=0.9 if ok else 0.4,
                    ai_hint=not ok, note="SQL dump" + (" — עמודות לא זוהו" if not ok else ""))

    if ext in (".db", ".sqlite", ".sqlite3") or head[:16] == b"SQLite format 3\x00":
        return dict(kind="sqlite", confidence=0.95, ai_hint=False, note="מסד SQLite")

    if ext in (".xlsx", ".xlsm") or (head[:2] == b"PK" and (b"xl/" in head or b"[Content_Types]" in head)):
        return dict(kind="xlsx", confidence=0.85, ai_hint=False, note="גיליון Excel — נקרא לפי שורות ועמודות")
    if ext == ".xls" or head[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
        return dict(kind="xls", confidence=0.7, ai_hint=False, note="Excel ישן (.xls) — נדרש xlrd, או שמרו כ-xlsx/CSV")

    if ext in (".jsonl", ".ndjson") or (head.lstrip()[:1] == b"{" and b"\n{" in head):
        first = {}
        for ln in decode(head).splitlines():
            try:
                o = json.loads(ln)
                if isinstance(o, dict):
                    first = o
                    break
            except ValueError:
                continue
        cm, rec, ident = _table_plan(list(first), [])
        return dict(kind="jsonl", columns=list(first), recognised=rec, identifying=sorted(ident),
                    confidence=0.85 if ident else 0.5, ai_hint=not ident, note="JSON לפי שורות")

    if ext == ".json" or head.lstrip()[:1] in (b"{", b"["):
        return dict(kind="json", confidence=0.7, ai_hint=False, note="JSON")

    if ext in (".csv", ".tsv") or (ext not in (".txt", ".md", ".log", ".vcf", ".html", ".htm", ".xml", ".pdf", ".docx")
                                   and b"," in head and b"\n" in head and b"<" not in head[:1]):
        text = decode(head)
        cut = max(text.rfind("\n"), text.rfind("\r"))
        text = text[:cut] if cut > 0 else text                # the head may end mid-row (or mid-quote)
        try:
            dialect = csv.excel_tab if ext == ".tsv" else csv.Sniffer().sniff(text[:2048], delimiters=",;\t|")
        except csv.Error:
            dialect = csv.excel
        try:
            rd = csv.reader(io.StringIO(text, newline=""), dialect)
            header = next(rd, [])
            rows = [r for _, r in zip(range(5), rd)]
        except csv.Error:                                     # odd quoting / line endings: a guess, never a crash
            lines = [ln for ln in text.splitlines() if ln.strip()]
            d = getattr(dialect, "delimiter", ",")
            header = lines[0].split(d) if lines else []
            rows = [ln.split(d) for ln in lines[1:6]]
        cm, rec, ident = _table_plan(header, rows)
        return dict(kind="csv", columns=header, recognised=rec, identifying=sorted(ident),
                    sample=rows[:3], confidence=0.85 if ident else 0.4, ai_hint=not ident,
                    note="טבלה" + (" — עמודות לא זוהו, אפשר למפות ידנית או עם AI" if not ident else ""))

    k = sniff_kind(body, "", name)
    kinds = {"pdf": "מסמך PDF", "docx": "מסמך Word", "xlsx": "גיליון Excel", "html": "דף אינטרנט",
             "vcf": "כרטיסי קשר", "xml": "XML", "txt": "טקסט חופשי"}
    return dict(kind=k, confidence=0.75 if k != "unknown" else 0.2, ai_hint=(k in ("txt", "unknown")),
                note=kinds.get(k, "לא מזוהה"))
