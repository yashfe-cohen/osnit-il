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

from .importdb import FIELDS, detect_columns
from .parse import decode, sniff_kind

RECOGNISABLE = {"name", "first", "last", "email", "phone", "org", "role", "url", "domain", "text"}


def _table_plan(cols, sample_rows):
    cm = detect_columns(cols)
    recognised = {k: v for k, v in cm.items() if k in RECOGNISABLE}
    identifying = recognised.keys() & {"name", "first", "last", "email", "phone"}
    return cm, recognised, identifying


def detect(body: bytes, name: str = "") -> dict:
    ext = os.path.splitext(name)[1].lower()
    head = body[:8192]

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

    if ext in (".csv", ".tsv") or (b"," in head and b"\n" in head and b"<" not in head[:1]):
        text = decode(head)
        try:
            dialect = csv.excel_tab if ext == ".tsv" else csv.Sniffer().sniff(text[:2048], delimiters=",;\t|")
        except csv.Error:
            dialect = csv.excel
        rd = csv.reader(io.StringIO(text), dialect)
        header = next(rd, [])
        rows = [r for _, r in zip(range(5), rd)]
        cm, rec, ident = _table_plan(header, rows)
        return dict(kind="csv", columns=header, recognised=rec, identifying=sorted(ident),
                    sample=rows[:3], confidence=0.85 if ident else 0.4, ai_hint=not ident,
                    note="טבלה" + (" — עמודות לא זוהו, אפשר למפות ידנית או עם AI" if not ident else ""))

    k = sniff_kind(body, "", name)
    kinds = {"pdf": "מסמך PDF", "docx": "מסמך Word", "xlsx": "גיליון Excel", "html": "דף אינטרנט",
             "vcf": "כרטיסי קשר", "xml": "XML", "txt": "טקסט חופשי"}
    return dict(kind=k, confidence=0.75 if k != "unknown" else 0.2, ai_hint=(k in ("txt", "unknown")),
                note=kinds.get(k, "לא מזוהה"))
