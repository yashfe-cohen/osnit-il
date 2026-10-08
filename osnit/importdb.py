"""Import records from any file that holds them: databases (SQLite, SQL dumps), spreadsheets (CSV/TSV/XLSX/XLS),
JSON / JSONL (nested objects flattened), and documents whose text is a list of records (key: value blocks,
delimited or typed lines, HTML tables, XML, vCard).

Every column is catalogued (osnit.catalog): known types become linkable entities, unknown columns are kept on the
record's person/org under their original header, sensitive columns are dropped. A mapping file can still force
columns:  {"tables": {"people": {"name": "full_name", "phone": "mobile", "seen": "found_at"}}}
Each record keeps its own historical discovery time and original URL. Rows that carry page text go through the
full text extraction pipeline instead.
"""
import csv
import json
import os
import re
import sqlite3
import time
from datetime import datetime
from itertools import chain, islice

from .catalog import attr_value, blank, detect_columns, learnable, plan_columns  # noqa: F401
from .extract import Ent, Extraction, norm_phone_il, org_key, role_key
from .parse import Parsed, decode, parse
from .quality import is_role_mailbox, valid_email, valid_phone
from .semantic import Registry, address_key, email_key, has_city, profile_url, username_key, value_kind
from .structure import _flatten, json_tables, tables_from_text, xml_tables
from .textnorm import clean, fold, name_key, squash
from .urls import PUBLIC_MAIL, normalize_url, registered_domain

SAMPLE = 300
ACCESS_EXT = (".mdb", ".accdb", ".mde", ".accde")
DOC_EXT = (".html", ".htm", ".txt", ".md", ".pdf", ".docx", ".xml", ".vcf", ".rtf", ".log")
TABLE_EXT = (".db", ".sqlite", ".sqlite3", ".mdb", ".accdb", ".mde", ".accde", ".csv", ".tsv", ".json", ".jsonl", ".ndjson", ".sql", ".dump",
             ".xlsx", ".xlsm", ".xls")


class Context:
    """What planning needs from the database: learned header names, the user's own information types, and the
    marker-taught piece rules ('***…***' examples) for this file and learned from earlier files."""
    def __init__(self, store=None, overrides=None):
        self.memory = store.field_memory() if store is not None else {}
        self.registry = Registry(store.custom_types() if store is not None else ())
        # a private copy: prepare() adds the virtual columns' types and must not leak them into the caller's dict
        self.overrides = {t: dict(v) for t, v in (overrides or {}).items() if isinstance(v, dict)}
        self.learned_spans = store.span_rules() if store is not None else {}   # header_key -> [rule, ...]

    def spans(self, table, cols):
        """Piece rules that apply to this table: the file's own, plus rules learned on the same column headers."""
        from .semantic import header_key
        own_all = list((self.overrides.get(table) or {}).get("__spans__") or [])
        have = {(r["col"], r["label"]) for r in own_all}           # disabled ones block their learned twin too
        own = [r for r in own_all if not r.get("disabled") and r.get("rule")]
        for c in cols:
            for r in self.learned_spans.get(header_key(c), []):
                if (c, r["label"]) not in have:
                    own.append(dict(r, col=c, learned=True))
                    have.add((c, r["label"]))
        return own

    def prepare(self, table, cols, rows):
        """The user's row layout first (separators removed -> neighbouring fields joined into one column), then one
        virtual column per piece rule ('<column> ▸ <label>'), typed as the user said. Streaming."""
        from .spans import augment, virtual_name
        cols, rows = apply_merges(cols, rows, (self.overrides.get(table) or {}).get("__merge__"))
        rules = [r for r in self.spans(table, cols) if r["col"] in cols]
        if not rules:
            return cols, rows
        ov = self.overrides.setdefault(table, {})
        extra = []
        for r in rules:
            vn = virtual_name(r["col"], r["label"])
            ov.setdefault(vn, r["type"])
            extra.append(vn)
        return list(cols) + [e for e in extra if e not in cols], (augment(row, rules) for row in rows)

    def plan(self, table, cols, head, mapping=None):
        ov = {k: v for k, v in (self.overrides.get(table) or {}).items() if not k.startswith("__")}
        return plan_columns(cols, head, mapping, self.memory, self.registry, ov or None)


# ---------------------------------------------------------------- the user's row layout
MERGE_JOIN = " "


def merged_name(group) -> str:
    return " + ".join(str(c) for c in group)


def merge_layout(cols, groups):
    """Valid merge groups for these columns: each a run of >= 2 ADJACENT columns (the separators between them were
    removed), not overlapping. Anything that no longer fits the file's columns is ignored."""
    pos = {str(c): i for i, c in enumerate(cols)}
    out, used = [], set()
    for g in groups or []:
        if not isinstance(g, (list, tuple)) or len(g) < 2 or not all(str(c) in pos for c in g):
            continue
        idx = [pos[str(c)] for c in g]
        if idx != list(range(idx[0], idx[0] + len(idx))) or used & set(idx):
            continue
        used |= set(idx)
        out.append([str(c) for c in g])
    return out


def apply_merges(cols, rows, groups):
    """Join each run of adjacent columns into ONE new column '<a> + <b>' at the place of the first — the value is
    the fields' text joined as one continuous piece. Streaming; nothing is dropped (the joined text holds it all)."""
    groups = merge_layout(cols, groups)
    if not groups:
        return cols, rows
    first = {g[0]: g for g in groups}
    inner = {c for g in groups for c in g[1:]}
    new_cols = [merged_name(first[str(c)]) if str(c) in first else c for c in cols if str(c) not in inner]

    def join(row, g):
        parts = [str(row.get(c)).strip() for c in g if not blank(row.get(c))]
        return MERGE_JOIN.join(p for p in parts if p) or None

    def gen():
        for row in rows:
            row = dict(row)
            for g in groups:
                row[merged_name(g)] = join(row, g)
                for c in g:
                    row.pop(c, None)
            yield row
    return new_cols, gen()


def _peeked(rows, n=SAMPLE):
    """(first n rows, iterator over all rows) — the sample drives column cataloguing."""
    it = iter(rows)
    head = list(islice(it, n))
    return head, chain(head, it)


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
def count_sql_tuples(path) -> int:
    """Rows in a SQL dump, counted in 4 MB chunks (a small overlap keeps boundary matches) — never the whole file
    in memory."""
    n, tail = 0, b""
    rx_sep, rx_val = re.compile(rb"\)\s*,\s*\("), re.compile(rb"VALUES\s*\(", re.I)
    with open(path, "rb") as f:
        for buf in iter(lambda: f.read(4 << 20), b""):
            chunk = tail + buf
            cut = max(0, len(chunk) - 64)
            n += len(rx_sep.findall(chunk, 0, cut)) + len(rx_val.findall(chunk, 0, cut))
            tail = chunk[cut:]
    return n + len(rx_sep.findall(tail)) + len(rx_val.findall(tail))


def cheap_count(path):
    """Row count per table without reading every record where possible: {table: (count, exact)}.
    Big files are never capped — SQLite uses COUNT(*), text formats count lines/tuples. Returns {} when
    the format needs a full pass (JSON / XLSX / documents are already materialised and counted by the caller)."""
    ext = os.path.splitext(path)[1].lower()
    base = re.sub(r"^\d{13}_", "", os.path.basename(path))
    try:
        if ext in (".db", ".sqlite", ".sqlite3"):
            con = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
            try:
                out = {}
                for (t,) in con.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"):
                    try:
                        out[t] = (con.execute(f'SELECT COUNT(*) FROM "{t}"').fetchone()[0], True)
                    except sqlite3.Error:
                        pass
                return out
            finally:
                con.close()
        if ext in ACCESS_EXT:
            from .mdb import count_access
            return count_access(path)
        if ext in (".csv", ".tsv"):
            with open(path, "rb") as f:
                lines = sum(buf.count(b"\n") for buf in iter(lambda: f.read(1 << 20), b""))
            return {base: (max(0, lines - 1), False)}         # minus header; approximate (quoted newlines)
        if ext in (".jsonl", ".ndjson"):
            with open(path, "rb") as f:
                lines = sum(buf.count(b"\n") for buf in iter(lambda: f.read(1 << 20), b""))
            return {base: (lines, False)}
        if ext in (".sql", ".dump"):
            n = count_sql_tuples(path)
            return {base: (n, False)} if n else {}
    except OSError:
        return {}
    return {}


def _detect_encoding(path):
    """Guess a text encoding from the first bytes only (so we never read a huge file to decode it)."""
    with open(path, "rb") as f:
        head = f.read(65536)
    if head[:3] == b"\xef\xbb\xbf":
        return "utf-8-sig"
    if head[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return "utf-16"
    for enc in ("utf-8", "windows-1255", "iso-8859-8", "windows-1252"):
        try:
            head.decode(enc)
            return enc
        except UnicodeDecodeError:
            continue
    return "latin-1"


def _csv_dialect(path, ext, enc=None):
    """The CSV/TSV dialect, sniffed from the first chunk only."""
    with open(path, encoding=enc or _detect_encoding(path), errors="replace", newline="") as f:
        sample = f.read(65536)
    try:
        return csv.excel_tab if ext == ".tsv" else csv.Sniffer().sniff(sample[:8192], delimiters=",;\t|")
    except csv.Error:
        return csv.excel


TEXT_TABLE_DELIM = {"טבלת טאבים": "\t", "טבלת |": "|", "טבלת ;": ";", "טבלת פסיקים": ","}


def table_delimiter(path, table) -> str:
    """The character that separates one field from the next in this table's rows, as the file writes it — what
    the operator sees between the values of a raw row (and removes to join two fields)."""
    ext = os.path.splitext(path)[1].lower()
    if ext in (".csv", ".tsv"):
        try:
            return _csv_dialect(path, ext).delimiter
        except OSError:
            return ","
    if ext in (".sql", ".dump"):
        return ","
    return TEXT_TABLE_DELIM.get(table, "|")


def _csv_rows(path, ext):
    """Stream a CSV/TSV row by row — the whole file is never held in memory, so a multi-GB file imports fine.
    The dialect is sniffed from the first chunk only."""
    enc = _detect_encoding(path)
    dialect = _csv_dialect(path, ext, enc)

    f = open(path, encoding=enc, errors="replace", newline="")
    rd = csv.DictReader(f, dialect=dialect)
    cols = [str(c) for c in (rd.fieldnames or [])]   # reads only the header line

    def rows():
        try:
            for row in rd:
                yield row
        finally:
            f.close()
    return cols, rows()


def raw_tables(path):
    """Yields (table_name, columns, rows_iter) for every record table found in the file — no interpretation yet."""
    ext = os.path.splitext(path)[1].lower()
    base = re.sub(r"^\d{13}_", "", os.path.basename(path))     # inbox copies carry a timestamp prefix
    if ext in (".db", ".sqlite", ".sqlite3"):
        con = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
        con.row_factory = sqlite3.Row
        try:
            names = [r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")]
            for t in names:
                cols = [r[1] for r in con.execute(f'PRAGMA table_info("{t}")')]
                yield t, cols, (dict(r) for r in con.execute(f'SELECT * FROM "{t}"'))
        finally:
            con.close()
    elif ext in ACCESS_EXT:
        from .mdb import access_tables                  # pure-Python Jet/ACE reader, page by page; fact tables
        yield from access_tables(path)                  # get their parent's identity through the foreign key
    elif ext in (".csv", ".tsv"):
        cols, rd = _csv_rows(path, ext)
        yield base, cols, rd
    elif ext in (".jsonl", ".ndjson"):
        def rows():
            with open(path, encoding="utf-8", errors="replace") as f:
                for ln in f:
                    try:
                        o = json.loads(ln)
                        if isinstance(o, dict):
                            yield _flatten(o)
                    except ValueError:
                        continue
        head, it = _peeked(rows())
        yield base, list(dict.fromkeys(k for r in head for k in r)), it
    elif ext == ".json":
        with open(path, encoding="utf-8", errors="replace") as f:
            data = json.load(f)
        for name, cols, rows in json_tables(data, base):
            yield name, cols, iter(rows)
    elif ext in (".xlsx", ".xlsm", ".xls"):
        from .xlsx import read_xls, read_xlsx
        for sheet, cols, rows in (read_xls if ext == ".xls" else read_xlsx)(path):
            yield sheet, [str(c) for c in cols], iter(rows)
    elif ext in (".sql", ".dump"):
        from .sqldump import stream_sql_dump            # statement by statement: any size, flat memory
        for table, cols, rows in stream_sql_dump(path, _detect_encoding(path)):
            yield table, cols, rows
    elif ext in DOC_EXT:
        with open(path, "rb") as f:
            body = f.read()
        if ext == ".xml":
            for t in xml_tables(decode(body)):
                yield t[0], t[1], iter(t[2])
            return
        try:
            p = parse(body, "file://" + base, "")
        except Exception:
            return
        html = decode(body) if ext in (".html", ".htm") else None
        for name, cols, rows in tables_from_text(p.text, html):
            yield name, cols, iter(rows)


def read_tables(path, mapping=None, ctx=None, all_tables=False):
    """Yields (table_name, Plan, rows_iter). Tables with nothing to hang data on are skipped unless all_tables."""
    ctx = ctx or Context()
    tmap = (mapping or {}).get("tables", {})
    for table, cols, rows in raw_tables(path):
        if tmap and table not in tmap and "default" not in tmap and os.path.splitext(path)[1].lower() in (".db", ".sqlite", ".sqlite3") + ACCESS_EXT:
            continue
        head, rows = _peeked(rows)
        cols = cols or list(dict.fromkeys(k for r in head for k in r))
        cols, rows = ctx.prepare(table, cols, rows)          # marker-taught pieces become their own columns
        head, rows = _peeked(rows)
        mp = tmap.get(table) or tmap.get("default")
        plan = ctx.plan(table, cols, head, mp)
        if plan.usable or all_tables:
            yield table, plan, rows


# ---------------------------------------------------------------- records -> evidence
def _split(v):
    return [x.strip() for x in re.split(r"[;,/\n]| \| ", v) if x.strip()] if v else []


REL = {"email": "contact", "phone": "contact", "domain": "contact", "url": "profile", "address": "address",
       "username": "account", "national_id": "identifier"}
OWNER_ORDER = ("person", "org", "national_id", "email", "phone", "username")


def _row_entities(rec, plan, trust):
    """Entities a row's typed columns hold, as (Ent, column) pairs (owner not chosen yet)."""
    reg = plan.registry or Registry()
    out = []

    def vals(t):
        return [(squash(str(rec.get(c))), c) for c in plan.cols(t) if not blank(rec.get(c))]

    for v, c in vals("email"):
        for a in _split(v):
            a = a.lower().removeprefix("mailto:")
            if "@" in a and valid_email(a):
                out.append((Ent("email", email_key(a), a, 0, 0, trust), c))
                d = registered_domain(a.split("@", 1)[1])
                if d not in PUBLIC_MAIL:
                    out.append((Ent("domain", d, d, 0, 0, trust * 0.9), c))
    for v, c in vals("phone"):
        for raw in re.split(r"[;,/]| \| ", v):
            if not raw.strip():
                continue
            n = norm_phone_il(raw) or ("+" + re.sub(r"\D", "", raw) if raw.strip().startswith("+") else None)
            if n and valid_phone(n):
                out.append((Ent("phone", n, n, 0, 0, trust), c))
    for v, c in vals("website"):
        d = registered_domain(re.sub(r"^https?://", "", v).split("/")[0].lower())
        if d and "." in d:
            out.append((Ent("domain", d, d, 0, 0, trust * 0.9), c))
    for v, c in vals("profile"):
        for x in re.split(r"[\s;,|]+", v):
            if "/" in x or "." in x:
                u = profile_url(x)
                out.append((Ent("url", u, u, 0, 0, trust * 0.9), c))
    for v, c in vals("username"):
        k = username_key(v)
        if 2 <= len(k) <= 40 and " " not in k:
            out.append((Ent("username", k, v.strip(), 0, 0, trust * 0.85), c))
    # addresses: a full address column, else street + house + city composed
    city = squash(str(rec.get(plan.col("city")) or "")) if plan.col("city") and not blank(rec.get(plan.col("city"))) else ""
    addrs = [(v, c) for v, c in vals("address")]
    if not addrs and plan.col("street") and not blank(rec.get(plan.col("street"))):
        st = squash(str(rec.get(plan.col("street"))))
        hn = squash(str(rec.get(plan.col("house")) or "")) if plan.col("house") else ""
        addrs = [(f"{st} {hn}".strip(), plan.col("street"))]
    for v, c in addrs:
        disp = clean(v)
        if city and fold(city) not in fold(disp) and not has_city(disp):
            disp = f"{disp}, {city}"
        k = address_key(disp)
        if len(k) >= 4:
            out.append((Ent("address", k, disp, 0, 0, trust * 0.9), c))
    for v, c in vals("national_id"):         # national ID is a strong personal identifier -> links records
        k = re.sub(r"\D", "", v).zfill(9)
        if k.strip("0"):
            out.append((Ent("national_id", k, v.strip(), 0, 0, trust), c))
    for t, ty in reg.types.items():          # the user's own identifier types
        if ty.group == "custom" and ty.entity:
            for v, c in vals(t):
                out.append((Ent(t, v.strip(), v.strip(), 0, 0, trust), c))
    return out


def record_extraction(rec, plan, specs, trust):
    """One table row -> Extraction. Typed columns become entities linked to the row's main entity (a person
    when there is a name); unknown columns become attributes under their original header; sensitive columns
    are never read."""
    if isinstance(plan, dict):                       # plain {field: column} mapping (older callers)
        plan = plan_columns(list(rec.keys()), [rec], plan)

    def g(f):
        c = plan.col(f)
        return squash(str(rec.get(c) or "")) if c and not blank(rec.get(c)) else ""

    shown = [c for c in plan.columns if c.status in ("entity", "attribute")]
    snippet = squash(" · ".join(f"{c.name}: {rec.get(c.name)}" for c in shown if not blank(rec.get(c.name))))[:300]
    ex = Extraction()
    owner = None
    name = g("name") or squash(f"{g('first')} {g('last')}")
    if name and len(name) >= 3 and re.search(r"[^\W\d_]", name) and not re.search(r"@|\d{3}", name):
        key, disp, sub = name_key(name), clean(name), None
        for sp in specs:
            if sp.kind == "person" and sp.matcher and sp.matcher.fullmatch(fold(clean(name)).strip()):
                key, disp, sub = sp.key, sp.display, sp.id
                ex.subject_hits.add(sp.id)
        owner = Ent("person", key, disp, 0, 0, trust, surface=clean(name), subject_id=sub, sub=sub is not None)
    orgs = []
    for c in plan.cols("org"):
        o = "" if blank(rec.get(c)) else squash(str(rec.get(c)))
        if o and org_key(o) and all(org_key(o) != x.key for x in orgs):
            orgs.append(Ent("org", org_key(o), clean(o), 0, 0, trust))
    if owner is None and orgs:
        owner = orgs.pop(0)
        for sp in specs:
            if sp.kind == "org" and sp.key == owner.key:
                ex.subject_hits.add(sp.id)
    found, seen = [], set()
    for e, col in _row_entities(rec, plan, trust):
        if (e.type, e.key) not in seen:
            seen.add((e.type, e.key))
            found.append(e)
    src = normalize_url(g("url")) if g("url") else None
    if src:
        found.append(Ent("url", src, src, 0, 0, trust * 0.6))
    for sp in specs:   # identifier subjects (email/phone/domain/...)
        if any(e.type == sp.kind and e.key == sp.key for e in found):
            ex.subject_hits.add(sp.id)
    if owner is None:  # no name and no org: the strongest identifier carries the row
        rank = {t: i for i, t in enumerate(OWNER_ORDER)}
        cands = sorted((e for e in found if e.type in rank or e.type.startswith("u_")),
                       key=lambda e: rank.get(e.type, len(rank)))
        owner = cands[0] if cands else None
        if owner is not None:
            found.remove(owner)
    for e in ([owner] if owner else []) + orgs + found:
        ex.add_ent(e, snippet)
    if owner is not None:
        for e in found:
            conf = trust * (0.5 if e.type == "email" and owner.type == "person" and is_role_mailbox(e.key) else 1.0)
            ex.add_link(owner, e, REL.get(e.type, "identifier"), conf, snippet)
        for o in orgs:
            ex.add_link(owner, o, "affiliated_with", trust, snippet)
        if g("role") and owner.type == "person":
            org_e = orgs[0] if orgs else None
            rk = role_key(g("role"))
            r = Ent("role", f"{rk}|{org_e.key}" if org_e else rk,
                    clean(g("role")) + (f", {org_e.display}" if org_e else ""), 0, 0, trust)
            ex.add_ent(r, snippet)
            ex.add_link(owner, r, "has_role", trust, snippet)
        for c in plan.attrs:
            v = attr_value(rec.get(c.name), c.type)
            if v is not None:
                ex.attrs.append(((owner.type, owner.key), c.name, v, c.type))
    return ex, src


def describe(ex: Extraction, plan=None) -> dict:
    """Readable summary of one extracted record — the live 'this is what we got' sample."""
    ents = [dict(type=t, value=e["display"]) for (t, _), e in ex.ents.items()]
    main = ents[0] if ents else None
    labels = {c.name: c.label for c in plan.columns} if plan else {}
    return dict(main=main, items=ents[1:],
                attrs=[dict(name=n, label=labels.get(n, n), value=v, type=k) for _, n, v, k in ex.attrs])


def import_db(engine, path, mapping=None, label=None, trust=0.8, delete_raw=False, chunk=500, crawl_urls=True,
              progress=None, import_id=None, on_preview=None, overrides=None, learn=True) -> dict:
    """Import every record table of `path`. With delete_raw the input file is removed after a successful import.
    on_preview(dict) is called as soon as each table is catalogued and its first records extracted.
    overrides: {table: {column: type}} — the user's corrections from the analysis screen."""
    label = label or os.path.basename(path)
    tag = f"?import={import_id}" if import_id else ""
    specs = engine.specs(force=True)
    st = engine.store
    ctx = Context(st, overrides)
    stats = {"tables": 0, "records": 0, "documents": 0, "skipped": 0, "urls_queued": 0, "deleted": False,
             "attributes": 0}
    preview = {"kind": "tabular", "tables": []}
    for table, plan, rows in read_tables(path, mapping, ctx):
        stats["tables"] += 1
        buf, part, before = [], 0, stats["records"]
        tinfo = dict(table=table, **plan.summary(), samples=[])
        preview["tables"].append(tinfo)
        if on_preview:
            on_preview(preview)

        def flush(buf, part):
            url = f"import://{label}/{table}/{part}{tag}"
            sid, _ = st.add_source(url, origin=f"import:{label}", import_id=import_id)
            now = time.time()
            with st.tx():
                findings = []
                for ex, ts, src in buf:
                    findings.append((ex, engine.persist(ex, sid, ts or now, specs, bulk=True), src))
                st.update_source(sid, state="imported", kind="records", title=f"{label} / {table}", last_scanned=now,
                                 last_seen=now, last_changed=now, next_scan_at=9e15, scan_count=1,
                                 hit=1 if any(ex.subject_hits for ex, _, _ in buf) else 0)
                for ex, nf, src in findings:
                    engine.emit_findings(ex, nf, src or url, now)
            for ex, _, src in buf:
                if crawl_urls and src and src.startswith("http"):   # re-verify the original page later
                    stats["urls_queued"] += st.add_source(src, priority=5, origin=f"import:{label}")[1]

        text_col, seen_col, url_col = plan.col("doc"), plan.col("seen"), plan.col("url")
        for rec in rows:
            if text_col and not blank(rec.get(text_col)) and len(str(rec.get(text_col))) > 20:
                body = str(rec[text_col])
                u = normalize_url(str(rec.get(url_col, "") or "")) if url_col else None
                u = u or f"import://{label}/{table}/doc{stats['documents']}{tag}"
                try:
                    p = parse(body.encode("utf-8"), u, "text/html" if "<" in body[:200] else "text/plain")
                except Exception:
                    p = Parsed("txt", clean(body))
                from .ingest import import_parsed
                import_parsed(engine, u, p, now=parse_ts(rec.get(seen_col)) if seen_col else None, import_id=import_id)
                stats["documents"] += 1
                continue
            ex, src = record_extraction(rec, plan, specs, trust)
            if not ex.ents:
                stats["skipped"] += 1
                continue
            stats["attributes"] += len(ex.attrs)
            if len(tinfo["samples"]) < 3:
                tinfo["samples"].append(describe(ex, plan))
                if on_preview:
                    on_preview(preview)
            buf.append((ex, parse_ts(rec.get(seen_col)) if seen_col else None, src))
            stats["records"] += 1
            if len(buf) >= chunk:
                flush(buf, part)
                buf, part = [], part + 1
                if progress:
                    progress(stats)
        if buf:
            flush(buf, part)
        tinfo["records"] = stats["records"] - before
        if learn:
            st.learn_fields(learnable(plan))
    if on_preview:
        on_preview(preview)
    stats["preview"] = preview
    if delete_raw and stats["records"] + stats["documents"] > 0:
        os.remove(path)
        stats["deleted"] = True
    return stats
