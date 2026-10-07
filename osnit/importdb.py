"""Import structured records collected by earlier tools (SQLite / CSV / TSV / JSON / JSONL).

Columns are recognised automatically (Hebrew/English synonyms) or set with a mapping file:
  {"tables": {"people": {"name": "full_name", "phone": "mobile", "seen": "found_at"}}}
Each record keeps its own historical discovery time and original URL. Rows that carry free text
(page text/html) go through the full extraction pipeline instead.
"""
import csv
import io
import json
import os
import re
import sqlite3
import time
from datetime import datetime

from .extract import Ent, Extraction, norm_phone_il, org_key, role_key
from .parse import Parsed, decode, parse
from .quality import is_role_mailbox, valid_email, valid_phone
from .textnorm import clean, fold, name_key, squash
from .urls import PUBLIC_MAIL, normalize_url, registered_domain

FIELDS = {
    "name": ["name", "full_name", "fullname", "person", "contact_name", "שם", "שם מלא", "שם_מלא"],
    "first": ["first_name", "firstname", "given_name", "שם פרטי", "שם_פרטי"],
    "last": ["last_name", "lastname", "surname", "family_name", "שם משפחה", "שם_משפחה"],
    "email": ["email", "e_mail", "mail", "email_address", "מייל", "אימייל", "דוא\"ל", "דואל"],
    "phone": ["phone", "telephone", "tel", "mobile", "cell", "phone_number", "טלפון", "נייד", "פלאפון", "מספר טלפון"],
    "org": ["org", "organization", "organisation", "company", "employer", "workplace", "חברה", "ארגון", "מקום עבודה"],
    "role": ["role", "title", "job_title", "position", "jobtitle", "תפקיד"],
    "url": ["url", "source", "source_url", "link", "page", "href", "מקור", "קישור"],
    "domain": ["domain", "website", "site", "אתר", "דומיין"],
    "seen": ["seen", "found_at", "first_seen", "date", "created", "created_at", "timestamp", "collected_at", "תאריך"],
    "text": ["text", "content", "body", "html", "page_text", "raw_text", "תוכן", "טקסט"],
}
_SYN = {fold(s).replace(" ", "_"): f for f, syns in FIELDS.items() for s in syns}


def detect_columns(cols):
    m = {}
    for c in cols:
        f = _SYN.get(fold(str(c)).strip().replace(" ", "_"))
        if f and f not in m:
            m[f] = c
    return m


def parse_ts(v):
    if v in (None, ""):
        return None
    if isinstance(v, (int, float)) or re.fullmatch(r"\d{9,13}(\.\d+)?", str(v)):
        x = float(v)
        return x / 1000 if x > 1e11 else x
    s = str(v).strip()
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp()
    except ValueError:
        pass
    for fmt in ("%d/%m/%Y %H:%M:%S", "%d/%m/%Y %H:%M", "%d/%m/%Y", "%d.%m.%Y", "%d-%m-%Y", "%Y/%m/%d", "%d/%m/%y"):
        try:
            return datetime.strptime(s, fmt).timestamp()
        except ValueError:
            continue
    return None


# ---------------------------------------------------------------- readers
def read_tables(path, mapping=None):
    """Yields (table_name, column_map, rows_iter) for any supported file."""
    ext = os.path.splitext(path)[1].lower()
    tmap = (mapping or {}).get("tables", {})
    if ext in (".db", ".sqlite", ".sqlite3"):
        con = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
        con.row_factory = sqlite3.Row
        names = [r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")]
        for t in names:
            if tmap and t not in tmap:
                continue
            cols = [r[1] for r in con.execute(f'PRAGMA table_info("{t}")')]
            cm = tmap.get(t) or detect_columns(cols)
            if cm:
                yield t, cm, (dict(r) for r in con.execute(f'SELECT * FROM "{t}"'))
        con.close()
    elif ext in (".csv", ".tsv"):
        with open(path, "rb") as f:
            text = decode(f.read())
        dialect = csv.excel_tab if ext == ".tsv" else csv.Sniffer().sniff(text[:4096], delimiters=",;\t|")
        rd = csv.DictReader(io.StringIO(text), dialect=dialect)
        cm = tmap.get("default") or detect_columns(rd.fieldnames or [])
        yield os.path.basename(path), cm, rd
    elif ext in (".jsonl", ".ndjson"):
        def rows():
            with open(path, encoding="utf-8", errors="replace") as f:
                for ln in f:
                    try:
                        o = json.loads(ln)
                        if isinstance(o, dict):
                            yield o
                    except ValueError:
                        continue
        first = next(rows(), {})
        yield os.path.basename(path), tmap.get("default") or detect_columns(first.keys()), rows()
    elif ext == ".json":
        with open(path, encoding="utf-8", errors="replace") as f:
            data = json.load(f)
        if isinstance(data, dict):
            data = next((v for v in data.values() if isinstance(v, list)), [])
        data = [d for d in data if isinstance(d, dict)]
        yield os.path.basename(path), tmap.get("default") or detect_columns(data[0].keys() if data else []), iter(data)


# ---------------------------------------------------------------- records -> evidence
def record_extraction(rec, cm, specs, trust):
    g = lambda f: squash(str(rec.get(cm[f]) or "")) if f in cm else ""
    name = g("name") or squash(f"{g('first')} {g('last')}")
    snippet = squash(" · ".join(f"{k}: {v}" for k, v in rec.items() if v not in (None, "") and k != cm.get("text")))[:300]
    ex = Extraction()
    owner = None
    if name and len(name) >= 3:
        key, disp, sub = name_key(name), clean(name), None
        for sp in specs:
            if sp.kind == "person" and sp.matcher and sp.matcher.fullmatch(fold(clean(name)).strip()):
                key, disp, sub = sp.key, sp.display, sp.id
                ex.subject_hits.add(sp.id)
        owner = Ent("person", key, disp, 0, 0, trust, surface=clean(name), subject_id=sub, sub=sub is not None)
    org = g("org")
    org_e = Ent("org", org_key(org), clean(org), 0, 0, trust) if org and org_key(org) else None
    if owner is None and org_e is not None:
        owner, org_e = org_e, None
        for sp in specs:
            if sp.kind == "org" and sp.key == owner.key:
                ex.subject_hits.add(sp.id)
    contacts = []
    for raw in re.split(r"[;,/]| \| ", g("email")) if g("email") else []:
        a = raw.strip().lower()
        if "@" in a and valid_email(a):
            contacts.append(Ent("email", a, a, 0, 0, trust))
            d = registered_domain(a.split("@", 1)[1])
            if d not in PUBLIC_MAIL:
                contacts.append(Ent("domain", d, d, 0, 0, trust * 0.9))
    for raw in re.split(r"[;,/]| \| ", g("phone")) if g("phone") else []:
        n = norm_phone_il(raw) or ("+" + re.sub(r"\D", "", raw) if raw.strip().startswith("+") else None)
        if n and valid_phone(n):
            contacts.append(Ent("phone", n, n, 0, 0, trust))
    if g("domain"):
        d = registered_domain(re.sub(r"^https?://", "", g("domain")).split("/")[0])
        contacts.append(Ent("domain", d, d, 0, 0, trust * 0.9))
    src = normalize_url(g("url")) if g("url") else None
    if src:
        contacts.append(Ent("url", src, src, 0, 0, trust * 0.6))
    for sp in specs:   # identifier subjects (email/phone/domain)
        if any(c.type == sp.kind and c.key == sp.key for c in contacts):
            ex.subject_hits.add(sp.id)
    for e in ([owner, org_e] if owner else [org_e]) + contacts:
        if e is not None:
            ex.add_ent(e, snippet)
    if owner is not None:
        for c in contacts:
            conf = trust * (0.5 if c.type == "email" and owner.type == "person" and is_role_mailbox(c.key) else 1.0)
            ex.add_link(owner, c, "contact", conf, snippet)
        if org_e is not None:
            ex.add_link(owner, org_e, "affiliated_with", trust, snippet)
        if g("role") and owner.type == "person":
            rk = role_key(g("role"))
            r = Ent("role", f"{rk}|{org_e.key}" if org_e else rk,
                    clean(g("role")) + (f", {org_e.display}" if org_e else ""), 0, 0, trust)
            ex.add_ent(r, snippet)
            ex.add_link(owner, r, "has_role", trust, snippet)
    return ex, src


def import_db(engine, path, mapping=None, label=None, trust=0.8, delete_raw=False, chunk=500, crawl_urls=True,
              progress=None) -> dict:
    """Import every table of `path`. With delete_raw the input file is removed after a fully successful import."""
    label = label or os.path.basename(path)
    specs = engine.specs(force=True)
    stats = {"tables": 0, "records": 0, "documents": 0, "skipped": 0, "urls_queued": 0, "deleted": False}
    st = engine.store
    for table, cm, rows in read_tables(path, mapping):
        stats["tables"] += 1
        buf, part = [], 0

        def flush(buf, part):
            url = f"import://{label}/{table}/{part}"
            sid, _ = st.add_source(url, origin=f"import:{label}")
            now = time.time()
            with st.tx():
                findings = []
                for ex, ts, src in buf:
                    findings.append((ex, engine.persist(ex, sid, ts or now, specs), src))
                st.update_source(sid, state="imported", kind="records", title=f"{label} / {table}", last_scanned=now,
                                 last_seen=now, last_changed=now, next_scan_at=9e15, scan_count=1,
                                 hit=1 if any(ex.subject_hits for ex, _, _ in buf) else 0)
                for ex, nf, src in findings:
                    engine.emit_findings(ex, nf, src or url, now)
            for ex, _, src in buf:
                if crawl_urls and src and src.startswith("http"):   # re-verify the original page later
                    stats["urls_queued"] += st.add_source(src, priority=5, origin=f"import:{label}")[1]

        for rec in rows:
            if "text" in cm and rec.get(cm["text"]):
                body = str(rec[cm["text"]])
                u = normalize_url(str(rec.get(cm.get("url"), "") or "")) or f"import://{label}/{table}/doc{stats['documents']}"
                try:
                    p = parse(body.encode("utf-8"), u, "text/html" if "<" in body[:200] else "text/plain")
                except Exception:
                    p = Parsed("txt", clean(body))
                from .ingest import import_parsed
                import_parsed(engine, u, p, now=parse_ts(rec.get(cm.get("seen"))) or None)
                stats["documents"] += 1
                continue
            ex, src = record_extraction(rec, cm, specs, trust)
            if not ex.ents:
                stats["skipped"] += 1
                continue
            buf.append((ex, parse_ts(rec.get(cm["seen"])) if "seen" in cm else None, src))
            stats["records"] += 1
            if len(buf) >= chunk:
                flush(buf, part)
                buf, part = [], part + 1
                if progress:
                    progress(stats)
        if buf:
            flush(buf, part)
    if delete_raw and stats["records"] + stats["documents"] > 0:
        os.remove(path)
        stats["deleted"] = True
    return stats
