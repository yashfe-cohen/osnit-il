"""Import already-collected public data: files/dirs (any parsable type) and JSONL dumps of {url,text|html}."""
import json
import os
import time

from .engine import Engine
from .parse import ParseError, Parsed, parse
from .urls import normalize_url

SUPPORTED = {".html", ".htm", ".pdf", ".docx", ".xlsx", ".csv", ".json", ".txt", ".md", ".vcf", ".xml"}


def _source_row(engine, url, now):
    sid, _ = engine.store.add_source(url, priority=0, origin="import", now=now)
    return engine.store.q1("SELECT * FROM sources WHERE id=?", (sid,))


def import_parsed(engine: Engine, url: str, parsed: Parsed, now=None):
    now = now or time.time()
    row = _source_row(engine, url, now)
    return engine.ingest(row, parsed, now, state="imported")


def import_path(engine: Engine, path: str, base_url: str = None, delete_raw: bool = False) -> dict:
    """Walk `path`; each file becomes a source (file:// URL, or base_url + relative path when given).
    Raw files are removed afterwards only when delete_raw=True (the importer never deletes by default)."""
    res = {"imported": 0, "unchanged": 0, "failed": 0, "deleted": 0}
    files = [path] if os.path.isfile(path) else [os.path.join(d, f) for d, _, fs in os.walk(path) for f in sorted(fs)]
    for fp in files:
        ext = os.path.splitext(fp)[1].lower()
        if ext == ".jsonl":
            r = import_jsonl(engine, fp)
            for k in r:
                res[k] = res.get(k, 0) + r[k]
        elif ext in SUPPORTED:
            rel = os.path.relpath(fp, path if os.path.isdir(path) else os.path.dirname(path))
            url = (base_url.rstrip("/") + "/" + rel.replace(os.sep, "/")) if base_url else "file://" + os.path.abspath(fp)
            try:
                with open(fp, "rb") as f:
                    body = f.read()
                out = import_parsed(engine, normalize_url(url) or url, parse(body, url, ""))
                res["imported" if out == "scanned" or out == "imported" else "unchanged"] += 1
                del body
                if delete_raw:
                    os.remove(fp)
                    res["deleted"] += 1
            except (OSError, ParseError):
                res["failed"] += 1
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
