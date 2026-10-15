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
import logging
import os
import re
import sqlite3
import time
from datetime import datetime
from itertools import chain, islice

from .catalog import attr_value, blank, detect_columns, learnable, plan_columns  # noqa: F401
from .extract import (Ent, Extraction, norm_phone_il, org_key, role_key,
                      extract_phone_from_identifier, extract_id_from_identifier, split_couple_names)
from .parse import Parsed, decode, parse
from .quality import (is_role_mailbox, valid_email, valid_phone, valid_national_id,
                      valid_corporate_id, valid_license_plate, is_dummy_value, is_dummy_name)
from .semantic import Registry, address_key, email_key, has_city, il_id_key, profile_url, username_key, value_kind
from .structure import _flatten, json_tables, tables_from_text, xml_tables
from .textnorm import clean, fold, name_key, squash
from .urls import PUBLIC_MAIL, normalize_url, registered_domain

log = logging.getLogger("osnit.importdb")

SAMPLE = 300
ACCESS_EXT = (".mdb", ".accdb", ".mde", ".accde")
TEXT_EXT = (".txt", ".log", ".md")


def big_text(path) -> bool:
    """A plain-text file too big to read whole: streamed (layout from its head) instead of parsed in memory."""
    from .structure import BIG_TEXT
    try:
        return os.path.splitext(path)[1].lower() in TEXT_EXT and os.path.getsize(path) > BIG_TEXT
    except OSError:
        return False
IMAGE_EXTS = (".jpg", ".jpeg", ".png", ".tiff", ".tif", ".webp", ".bmp")
DOC_EXT = (".html", ".htm", ".txt", ".md", ".pdf", ".docx", ".xml", ".vcf", ".rtf", ".log", ".yaml", ".yml", ".eml") + IMAGE_EXTS
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
        virtual column per piece rule ('<column> ▸ <label>'), then a reconstructed national-ID column when the user
        marked a ת"ז + Family-Tz pair ('__idjoin__'), each typed accordingly. Streaming."""
        from .spans import augment, virtual_name
        cols, rows = apply_merges(cols, rows, (self.overrides.get(table) or {}).get("__merge__"))
        rules = [r for r in self.spans(table, cols) if r["col"] in cols]
        idj = (self.overrides.get(table) or {}).get("__idjoin__") or None
        if idj and not (idj.get("tz") in cols and idj.get("family") in cols):
            idj = None
        if not rules and not idj:
            return cols, rows
        ov = self.overrides.setdefault(table, {})
        extra = []
        for r in rules:
            vn = virtual_name(r["col"], r["label"])
            ov.setdefault(vn, r["type"])
            extra.append(vn)
        idcol = None
        if idj:
            from .idrecon import assemble
            idcol = idj.get("as") or "תעודת זהות (משוחזר)"
            ov.setdefault(idcol, "national_id")
            extra.append(idcol)
            tzc, famc, pat = idj["tz"], idj["family"], idj.get("pattern", "bb+a")

        def gen():
            for row in rows:
                row = augment(row, rules) if rules else dict(row)
                if idcol:
                    row[idcol] = assemble(row.get(tzc), row.get(famc), pat) or None
                yield row
        return list(cols) + [e for e in extra if e not in cols], gen()

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
    """Rows in a SQL dump, counted in 4 MB chunks (a 64-byte overlap carries boundary matches) — never the whole
    file in memory. Each match is counted once by its GLOBAL start offset, so a tuple separator that straddles a
    chunk boundary is never missed nor double-counted (a CRLF dump used to undercount when the cut landed inside a
    match)."""
    rx = re.compile(rb"\)\s*,\s*\(|VALUES\s*\(", re.I)    # a tuple separator ')  ,  (' or the opening 'VALUES ('
    n, tail, base, seen_upto = 0, b"", 0, 0
    with open(path, "rb") as f:
        while True:
            buf = f.read(4 << 20)
            chunk = tail + buf
            for m in rx.finditer(chunk):
                gs = base + m.start()
                if gs >= seen_upto:                  # count each match once, by where it starts in the whole file
                    n += 1
                    seen_upto = gs + 1
            if not buf:
                return n
            keep = min(64, len(chunk))               # carry enough to re-see any match straddling the boundary
            base += len(chunk) - keep
            tail = chunk[len(chunk) - keep:]


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
        if big_text(path):
            from .structure import text_layout
            lay = text_layout(path, _detect_encoding(path))
            if not lay:
                return {}
            with open(path, "rb") as f:
                lf = cr = 0
                for buf in iter(lambda: f.read(1 << 20), b""):
                    lf += buf.count(b"\n")
                    cr += buf.count(b"\r")
            lines = lf or cr                                  # old-Mac files end lines with \r alone
            info = lay[3]
            return {lay[1]: (int(lines * info["head_rows"] / max(1, info["head_lines"])), False)}
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
    import codecs
    with open(path, "rb") as f:
        head = f.read(65536)
    if head[:3] == b"\xef\xbb\xbf":
        return "utf-8-sig"
    if head[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return "utf-16"
    for enc in ("utf-8", "windows-1255", "iso-8859-8", "windows-1252"):
        try:
            # decode incrementally (final=False) so a multibyte char split by the 64KB sample window is buffered,
            # not mistaken for invalid utf-8 — otherwise a valid Hebrew UTF-8 file wrongly fell back to windows-1255
            # and the whole import decoded as garbage.
            codecs.getincrementaldecoder(enc)().decode(head)
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
    The dialect is sniffed from the first chunk only. Single-quoted CSV exports (e.g. 'o','First Name',...)
    with unescaped inner apostrophes ('שבט אבו ג'ווייעד '') are parsed via sql_parser.split_fields."""
    enc = _detect_encoding(path)
    with open(path, encoding=enc, errors="replace", newline="") as probe:
        first_line = ""
        for ln in probe:
            if ln.strip():
                first_line = ln.strip()
                break

    if first_line and ext != ".tsv" and re.match(r"^'[^']*'\s*,", first_line):
        from .sql_parser import split_fields
        cols = [str(c or f"col_{i}").strip().strip("'") for i, c in enumerate(split_fields(first_line))]

        def sq_rows():
            with open(path, encoding=enc, errors="replace") as f:
                header_skipped = False
                for ln in f:
                    s = ln.strip()
                    if not s:
                        continue
                    if not header_skipped:
                        header_skipped = True
                        continue
                    vals = split_fields(s)
                    if not vals:
                        continue
                    cleaned = [("" if v is None else str(v).strip().strip("'")) for v in vals]
                    if len(cleaned) < len(cols):
                        cleaned.extend([""] * (len(cols) - len(cleaned)))
                    yield dict(zip(cols, cleaned[:len(cols)]))
        return cols, sq_rows()

    dialect = _csv_dialect(path, ext, enc)

    f = open(path, encoding=enc, errors="replace", newline="")
    rd = csv.DictReader(f, dialect=dialect)
    cols = [str(c).strip().strip("'") for c in (rd.fieldnames or [])]   # reads only the header line

    def rows():
        try:
            while True:
                try:
                    row = next(rd)
                except StopIteration:
                    return
                except csv.Error:               # one malformed line (stray quote, NUL…) never stops the file
                    continue
                yield {str(k).strip().strip("'"): (v.strip().strip("'") if isinstance(v, str) and len(v) >= 2 and v.startswith("'") and v.endswith("'") else v)
                       for k, v in row.items() if k is not None}
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
            names.sort(key=lambda t: 0 if str(t).lower() in PARENT_TABLES_ORDER else 1)
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
    elif big_text(path):                                # 1.5 GB of text: never in memory, rows streamed
        from .structure import stream_text_table, text_layout
        enc = _detect_encoding(path)
        lay = text_layout(path, enc)
        if lay:
            yield lay[1], list(lay[2]), stream_text_table(path, enc, lay)
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


PARENT_TABLES_ORDER = (
    "users", "user", "wp_users", "tbl_users", "app_users",
    "customers", "customer", "clients", "client", "members", "member",
    "accounts", "account", "people", "person", "contacts", "contact"
)


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


def _clean_address_text(s: str) -> str:
    """Clean address text from SQL/CSV dumps: fix reversed Hebrew parens ')שבט(', strip stray outer quotes and trailing standalone '0'."""
    if not s:
        return ""
    s = squash(str(s)).strip().strip("'\"")
    s = re.sub(r"\)([^()]+)\(", r"(\1)", s)
    s = re.sub(r"\s+0$", "", s).strip().strip("'\"")
    return clean(s)


def _aggregate_row_addresses(rec: dict, plan) -> list[tuple[str, str]]:
    """Aggregate address columns with adjacent fragmented overflow columns (e.g. 's', 't', 'col_N' in voter/user CSVs)."""
    all_cols = list(rec.keys())
    col_map = {col.name: col for col in getattr(plan, "columns", ())}
    out = []
    for c in plan.cols("address"):
        if blank(rec.get(c)):
            continue
        base_val = _clean_address_text(str(rec.get(c)))
        if not base_val:
            continue
        idx = all_cols.index(c) if c in all_cols else -1
        fragments = [base_val]
        if idx >= 0:
            for offset in (1, 2):
                if idx + offset < len(all_cols):
                    nc = all_cols[idx + offset]
                    nc_clean = nc.strip().strip("'\"")
                    nc_col = col_map.get(nc)
                    nc_type = nc_col.type if nc_col else "unknown"
                    if (len(nc_clean) == 1 or re.match(r"^(?:col_\d+|unnamed.*)$", nc_clean, re.I)) and nc_type in ("unknown", "text", "address", "street"):
                        if not blank(rec.get(nc)):
                            fv = _clean_address_text(str(rec.get(nc)))
                            if fv and re.search(r"[A-Za-zא-ת]", fv) and not re.match(r"^\d+$", fv):
                                fragments.append(fv)
                    else:
                        break
        if len(fragments) > 1:
            # Check if a later fragment already contains the complete clean address (e.g. 'שבט אבו ג'ווייעד')
            best = None
            for cand in reversed(fragments[1:]):
                if "(" not in cand and ")" not in cand and len(cand) >= len(base_val) and base_val[:4] in cand:
                    best = cand
                    break
            if best:
                out.append((best, c))
            else:
                joined = fragments[0]
                for frag in fragments[1:]:
                    frag_no_paren = re.sub(r"\([^)]*\)", "", frag).strip()
                    if not frag_no_paren:
                        continue
                    if joined.endswith("'") or joined.endswith("׳"):
                        joined = joined + frag_no_paren
                    elif frag_no_paren not in joined:
                        joined = f"{joined} {frag_no_paren}"
                out.append((clean(joined), c))
        else:
            out.append((base_val, c))
    return out


_NON_STANDARD_ID_COLS = {
    "discount_number", "user_number", "company_number", "external_account_code",
    "tehudat_zhut", "national_id", "tz", "id_num", "id_number", "ssn"
}


def _row_entities(rec, plan, trust):
    """Entities a row's typed columns hold, as (Ent, column) pairs (owner not chosen yet)."""
    reg = plan.registry or Registry()
    out = []

    def vals(t):
        return [(squash(str(rec.get(c))), c) for c in plan.cols(t) if not blank(rec.get(c))]

    for v, c in vals("email"):
        for a in _split(v):
            a = a.lower().removeprefix("mailto:").strip().strip("'\"")
            if "@" in a and valid_email(a) and not is_dummy_value(a):
                out.append((Ent("email", email_key(a), a, 0, 0, trust), c))
                d = registered_domain(a.split("@", 1)[1])
                if d not in PUBLIC_MAIL:
                    out.append((Ent("domain", d, d, 0, 0, trust * 0.9), c))
                emb_ph = extract_phone_from_identifier(a)
                if emb_ph:
                    out.append((Ent("phone", emb_ph, emb_ph, 0, 0, trust * 0.9), c))
                else:
                    emb_id = extract_id_from_identifier(a)
                    if emb_id:
                        out.append((Ent("national_id", emb_id, emb_id, 0, 0, trust * 0.9), c))
            else:
                # An email column might hold a bare phone number in dirty dumps
                ph_fallback = norm_phone_il(a, allow_missing_zero=False)
                if ph_fallback and valid_phone(ph_fallback) and not is_dummy_value(ph_fallback):
                    out.append((Ent("phone", ph_fallback, ph_fallback, 0, 0, trust * 0.85), c))
    from .kinship import detect_kinship_column_role, is_emergency_phone_column
    has_kinship_col = any(detect_kinship_column_role(k) for k in rec.keys())
    for v, c in vals("phone"):
        if has_kinship_col and is_emergency_phone_column(c):
            continue
        for raw in re.split(r"[;,/]| \| ", v):
            raw = raw.strip().strip("'\"")
            if not raw:
                continue
            n = norm_phone_il(raw, allow_missing_zero=True) or ("+" + re.sub(r"\D", "", raw) if raw.startswith("+") else None)
            if n and valid_phone(n) and not is_dummy_value(n):
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
        v_clean = v.strip().strip("'\"")
        if not v_clean or is_dummy_value(v_clean):
            continue
        if "@" in v_clean and valid_email(v_clean.lower()):
            em = v_clean.lower()
            out.append((Ent("email", email_key(em), em, 0, 0, trust * 0.9), c))
        emb_ph = extract_phone_from_identifier(v_clean)
        if emb_ph:
            out.append((Ent("phone", emb_ph, emb_ph, 0, 0, trust * 0.9), c))
        else:
            emb_id = extract_id_from_identifier(v_clean)
            if emb_id:
                out.append((Ent("national_id", emb_id, emb_id, 0, 0, trust * 0.9), c))
        k = username_key(v_clean)
        if 2 <= len(k) <= 40 and " " not in k:
            out.append((Ent("username", k, v_clean, 0, 0, trust * 0.85), c))
    # addresses: a full address column (with fragmented overflow aggregation), else street + house + city composed
    city = _clean_address_text(str(rec.get(plan.col("city")) or "")) if plan.col("city") and not blank(rec.get(plan.col("city"))) else ""
    if city.isdigit():
        city = ""
    addrs = _aggregate_row_addresses(rec, plan)
    if not addrs and plan.col("street") and not blank(rec.get(plan.col("street"))):
        st = _clean_address_text(str(rec.get(plan.col("street"))))
        hn = _clean_address_text(str(rec.get(plan.col("house")) or "")) if plan.col("house") else ""
        if hn == "0":
            hn = ""
        if st:
            addrs = [(f"{st} {hn}".strip(), plan.col("street"))]
    for v, c in addrs:
        disp = clean(v)
        if city and fold(city) not in fold(disp) and not has_city(disp):
            disp = f"{disp}, {city}"
        k = address_key(disp)
        if len(k) >= 4:
            out.append((Ent("address", k, disp, 0, 0, trust * 0.9), c))
    for v, c in vals("national_id"):         # national ID is a strong personal identifier -> links records
        v_clean = v.strip().strip("'\"")
        corp_digits = re.sub(r"\D", "", v_clean)
        is_corp = valid_corporate_id(v_clean) and (
            corp_digits.startswith(("51", "58"))
            or any(w in c.lower() for w in ("ח.פ", "חפ", "ח_פ", "ע.מ", "company", "corp", "discount", "user_number"))
        )
        if is_corp:
            out.append((Ent("org", f"il_company:{corp_digits}", f"ח.פ. {corp_digits}", 0, 0, trust), c))
        elif valid_national_id(v_clean) and not is_dummy_value(v_clean):
            k = il_id_key(v_clean)                     # canonical: the same ID written any way links to one entity
            if k:
                out.append((Ent("national_id", k, k, 0, 0, trust), c))
    for v, c in vals("corporate_id"):
        if valid_corporate_id(v):
            corp_num = re.sub(r"\D", "", v)
            out.append((Ent("org", f"il_company:{corp_num}", f"ח.פ. {corp_num}", 0, 0, trust), c))
    # Scan non-standard ID / discount / company number columns that may be unmapped or attribute columns
    mapped_id_cols = set(plan.cols("national_id")) | set(plan.cols("corporate_id")) | set(plan.cols("phone"))
    for col_name, col_val in rec.items():
        if col_name in mapped_id_cols or blank(col_val):
            continue
        ck = col_name.strip().strip("'\"").lower()
        if ck in _NON_STANDARD_ID_COLS:
            s_val = str(col_val).strip().strip("'\"")
            digits = re.sub(r"\D", "", s_val)
            if 7 <= len(digits) <= 9 and re.fullmatch(r"\d{7,9}", s_val) and not is_dummy_value(digits):
                if valid_corporate_id(digits):
                    out.append((Ent("org", f"il_company:{digits}", f"ח.פ. {digits}", 0, 0, trust * 0.95), col_name))
                elif not digits.startswith(("50", "52", "53", "54", "55", "58")) and valid_national_id(digits):
                    k = il_id_key(digits)
                    if k:
                        out.append((Ent("national_id", k, k, 0, 0, trust * 0.95), col_name))
    for v, c in vals("license_plate"):
        if valid_license_plate(v):
            plate_num = re.sub(r"\D", "", v)
            out.append((Ent("vehicle", plate_num, v.strip(), 0, 0, trust), c))
    for t, ty in reg.types.items():          # the user's own identifier types
        if ty.group == "custom" and ty.entity:
            for v, c in vals(t):
                out.append((Ent(t, v.strip(), v.strip(), 0, 0, trust), c))
    return out


def _valid_person_candidate(n: str) -> bool:
    return bool(n and not is_dummy_name(n) and len(n) >= 3 and re.search(r"[^\W\d_]", n) and not re.search(r"@|\d{3}", n))


def _collect_row_person_names(rec: dict, plan) -> tuple[list[str], list[tuple[str, str]]]:
    """Gather all candidate person names and couple pairs from a row across first+last, name, and billing/shipping columns."""
    candidates = []
    couples = []

    def add_cand(raw_first: str, raw_last: str = ""):
        f = squash(raw_first).strip().strip("'\"")
        l = squash(raw_last).strip().strip("'\"")
        if f and is_dummy_name(f):
            f = ""
        if l and is_dummy_name(l):
            l = ""
        if not f and not l:
            return
        cp = split_couple_names(f, l)
        if cp:
            p1, p2 = cp
            if _valid_person_candidate(p1) and _valid_person_candidate(p2):
                if (p1, p2) not in couples:
                    couples.append((p1, p2))
                if p1 not in candidates:
                    candidates.append(p1)
                return
        full = squash(f"{f} {l}") if l else f
        if _valid_person_candidate(full) and full not in candidates:
            candidates.append(full)

    # 1. Pair up first & last columns (e.g. first_name+last_name, billing_first_name+billing_last_name, shipping_first_name+shipping_last_name)
    first_cols = plan.cols("first")
    last_cols = plan.cols("last")
    for i, fc in enumerate(first_cols):
        lc = last_cols[i] if i < len(last_cols) else (last_cols[0] if last_cols else None)
        fv = str(rec.get(fc) or "") if not blank(rec.get(fc)) else ""
        lv = str(rec.get(lc) or "") if lc and not blank(rec.get(lc)) else ""
        add_cand(fv, lv)

    # 2. All full-name columns (e.g. name, full_name, user_contact)
    for nc in plan.cols("name"):
        if not blank(rec.get(nc)):
            add_cand(str(rec.get(nc) or ""), "")

    # Sort so multi-token names (first + surname) take priority over single-token names
    candidates.sort(key=lambda x: (len(x.split()) >= 2, len(x)), reverse=True)
    return candidates, couples


def record_extraction(rec, plan, specs=(), trust=0.8, table_pk_map=None, table_name=None):
    """One table row -> Extraction. Typed columns become entities linked to the row's main entity (a person
    when there is a name); unknown columns become attributes under their original header; sensitive columns
    are never read.
    With table_pk_map (v2.0), relational joins across tables are automatically resolved (e.g. orders.user_id -> users.id).
    """
    if isinstance(plan, dict):                       # plain {field: column} mapping (older callers)
        plan = plan_columns(list(rec.keys()), [rec], plan)

    # 1. Resolve parent owner via foreign key in table_pk_map (v2.0)
    parent_owner = None
    if table_pk_map:
        from .sql_parser import find_row_foreign_keys
        fk_list = find_row_foreign_keys(rec, table_name or "")
        for fk_col, fk_val, parent_candidates in fk_list:
            for pt in parent_candidates:
                if (pt.lower(), str(fk_val)) in table_pk_map:
                    parent_owner = table_pk_map[(pt.lower(), str(fk_val))]
                    break
            if parent_owner is not None:
                break

    def g(f):
        c = plan.col(f)
        return squash(str(rec.get(c) or "")) if c and not blank(rec.get(c)) else ""

    shown = [c for c in plan.columns if c.status in ("entity", "attribute")]
    snippet = squash(" · ".join(f"{c.name}: {rec.get(c.name)}" for c in shown if not blank(rec.get(c.name))))[:300]
    ex = Extraction()
    owner = None
    extra_persons = []     # (Ent, relation_to_owner) e.g. spouse or cross-script alias

    candidates, couples = _collect_row_person_names(rec, plan)
    name = candidates[0] if candidates else ""
    if name:
        key, disp, sub = name_key(name), clean(name), None
        for sp in specs:
            if sp.kind == "person" and sp.matcher and sp.matcher.fullmatch(fold(clean(name)).strip()):
                key, disp, sub = sp.key, sp.display, sp.id
                ex.subject_hits.add(sp.id)
        owner = Ent("person", key, disp, 0, 0, trust, surface=clean(name), subject_id=sub, sub=sub is not None)

        # Couple splitting: create second spouse person entity and link both
        for p1, p2 in couples:
            for sp_name in (p1, p2):
                sk = name_key(sp_name)
                if sk and sk != owner.key and all(sk != ep.key for ep, _ in extra_persons):
                    sp_ent = Ent("person", sk, clean(sp_name), 0, 0, trust, surface=clean(sp_name), via="kinship")
                    extra_persons.append((sp_ent, "kinship:spouse"))

        # Secondary names in the row (e.g. English user_contact 'Ariel Adar' alongside Hebrew 'אריאל אדר')
        for alt in candidates[1:]:
            ak = name_key(alt)
            if ak and ak != owner.key and all(ak != ep.key for ep, _ in extra_persons) and len(alt.split()) >= 2:
                alt_ent = Ent("person", ak, clean(alt), 0, 0, trust * 0.95, surface=clean(alt))
                extra_persons.append((alt_ent, "alias"))

    orgs = []
    for c in plan.cols("org"):
        o = "" if blank(rec.get(c)) else squash(str(rec.get(c))).strip().strip("'\"")
        if o and not is_dummy_value(o) and not is_dummy_name(o) and org_key(o) and all(org_key(o) != x.key for x in orgs):
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
            if e.type == "org":
                if all(e.key != x.key for x in orgs) and (owner is None or owner.key != e.key):
                    orgs.append(e)
            else:
                found.append(e)
    src = normalize_url(g("url")) if g("url") else None
    if src:
        found.append(Ent("url", src, src, 0, 0, trust * 0.6))
    for sp in specs:   # identifier subjects (email/phone/domain/...)
        if any(e.type == sp.kind and e.key == sp.key for e in found):
            ex.subject_hits.add(sp.id)
    if owner is None and parent_owner is not None:
        owner = parent_owner
    elif owner is None:  # no name and no org: the strongest identifier carries the row
        rank = {t: i for i, t in enumerate(OWNER_ORDER)}
        cands = sorted((e for e in found if e.type in rank or e.type.startswith("u_")),
                       key=lambda e: rank.get(e.type, len(rank)))
        owner = cands[0] if cands else None
        if owner is not None:
            found.remove(owner)
    for e in ([owner] if owner else []) + [ep for ep, _ in extra_persons] + orgs + found:
        ex.add_ent(e, snippet)
    if parent_owner is not None and owner is not None and owner.key != parent_owner.key:
        ex.add_ent(parent_owner, snippet)
        ex.add_link(parent_owner, owner, "related_to", trust, snippet)
        for e in found:
            ex.add_link(parent_owner, e, REL.get(e.type, "identifier"), trust, snippet)
    if owner is not None:
        for ep, rel_kind in extra_persons:
            if rel_kind == "kinship:spouse":
                ex.add_link(owner, ep, "kinship:spouse", trust, snippet)
            else:
                ex.attrs.append(((owner.type, owner.key), "alias", ep.display, "text"))
            for e in found:
                conf = trust * (0.5 if e.type == "email" and is_role_mailbox(e.key) else 1.0)
                ex.add_link(ep, e, REL.get(e.type, "identifier"), conf, snippet)
            for o in orgs:
                ex.add_link(ep, o, "affiliated_with", trust, snippet)
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
        if parent_owner is not None and owner is not parent_owner:
            tbl_pfx = f"{table_name}_" if table_name else ""
            for c in plan.attrs:
                v = attr_value(rec.get(c.name), c.type)
                if v is not None:
                    ex.attrs.append(((parent_owner.type, parent_owner.key), f"{tbl_pfx}{c.name}", v, c.type))

        # Phase 4: Explicit Kinship columns in tabular / DB records (e.g. father_name, mother_name, spouse, emergency_contact)
        if owner.type == "person":
            try:
                from .kinship import detect_kinship_column_role, is_emergency_phone_column, extract_explicit_kinship_from_text
                em_phones = []
                for col_name, col_val in rec.items():
                    if is_emergency_phone_column(col_name) and not blank(col_val):
                        ph_norm = norm_phone_il(str(col_val))
                        if ph_norm and valid_phone(ph_norm):
                            em_phones.append(ph_norm)
                owner_toks = [t for t in owner.display.split() if len(t) >= 2]
                owner_surname = owner_toks[-1] if len(owner_toks) >= 2 else ""
                last_em_ent = None
                for col_name, col_val in rec.items():
                    role = detect_kinship_column_role(col_name)
                    if not role or blank(col_val):
                        continue
                    raw_str = squash(str(col_val))
                    # Check if cell contains inline phone or role in parens, e.g. "שרה כהן (אחות) - 052-3334455"
                    inline_ph = None
                    ph_m = re.search(r"((?:\+?972|0)[2348957]\d?[-\s.]?\d{3}[-\s.]?\d{4})", raw_str)
                    if ph_m:
                        inline_ph = norm_phone_il(ph_m.group(1))
                        raw_str = raw_str[:ph_m.start()].strip(" -,:;|()")
                    paren_m = re.search(r"\(([^)]+)\)", raw_str)
                    if paren_m:
                        sub_role = detect_kinship_column_role(paren_m.group(1))
                        if sub_role:
                            role = sub_role
                        raw_str = (raw_str[:paren_m.start()] + " " + raw_str[paren_m.end():]).strip(" -,:;|")
                    rel_name = clean(raw_str)
                    if not rel_name or is_dummy_name(rel_name) or len(rel_name) < 2:
                        continue
                    if len(rel_name.split()) == 1 and owner_surname and role in ("father", "mother", "brother", "sister", "child"):
                        rel_name = f"{rel_name} {owner_surname}"
                    rel_key = name_key(rel_name)
                    if not rel_key or rel_key == owner.key:
                        continue
                    rel_ent = Ent("person", rel_key, rel_name, 0, 0, trust * 0.95, surface=rel_name, via="kinship")
                    kin_snip = f"{col_name}: {col_val}"[:240]
                    ex.add_ent(rel_ent, kin_snip)
                    ex.add_link(owner, rel_ent, f"kinship:{role}", trust * 0.95, kin_snip)
                    if role == "emergency_contact" or last_em_ent is None:
                        last_em_ent = rel_ent
                    if inline_ph and valid_phone(inline_ph):
                        ph_ent = Ent("phone", inline_ph, inline_ph, 0, 0, trust * 0.9)
                        ex.add_ent(ph_ent, kin_snip)
                        ex.add_link(rel_ent, ph_ent, "contact", trust * 0.9, kin_snip)
                if last_em_ent is not None and em_phones:
                    for ep in em_phones:
                        ph_ent = Ent("phone", ep, ep, 0, 0, trust * 0.9)
                        ex.add_ent(ph_ent, snippet)
                        ex.add_link(last_em_ent, ph_ent, "contact", trust * 0.9, snippet)
            except Exception:
                pass

        # Free-Text and Notes Sweep (v2.0): scan notes, comments, delivery_instructions and unmapped columns for entities
        sweep_headers = ("note", "comment", "remark", "desc", "bio", "instruction", "detail", "הער", "משלוח", "תוכן", "פירוט", "notes", "comments")
        for c in plan.attrs:
            c_name_lower = c.name.lower()
            if any(sh in c_name_lower for sh in sweep_headers) or c.type in ("unknown", "text", "doc"):
                val_str = str(rec.get(c.name) or "").strip()
                if len(val_str) >= 8 and not is_dummy_value(val_str):
                    from .extract import Extractor
                    sub_ex = Extractor(specs).extract(val_str)
                    for (etype, ekey), edata in sub_ex.ents.items():
                        if etype in ("phone", "email", "national_id", "person", "org", "vehicle"):
                            sub_e = Ent(etype, ekey, edata["display"], 0, 0, trust * 0.9)
                            sub_snip = f"{c.name}: {val_str}"[:300]
                            ex.add_ent(sub_e, sub_snip)
                            if owner is not None:
                                ex.add_link(owner, sub_e, REL.get(etype, "related_to"), trust * 0.9, sub_snip)
                            if parent_owner is not None and parent_owner is not owner:
                                ex.add_link(parent_owner, sub_e, REL.get(etype, "related_to"), trust * 0.9, sub_snip)
                    if owner.type == "person":
                        try:
                            from .kinship import extract_explicit_kinship_from_text
                            for km in extract_explicit_kinship_from_text(val_str, primary_person_name=owner.display):
                                rname = km.get("name") or km.get("relative_name") or ""
                                rk = km.get("key") or name_key(rname)
                                conf = km.get("confidence", 0.9)
                                if rk and rk != owner.key:
                                    re_ent = Ent("person", rk, rname, 0, 0, conf, surface=rname, via="kinship")
                                    ex.add_ent(re_ent, km["snippet"])
                                    ex.add_link(owner, re_ent, f"kinship:{km['role']}", conf, km["snippet"])
                        except Exception:
                            pass

    # Register this record in table_pk_map for downstream child tables (v2.0)
    if table_pk_map is not None and table_name and owner is not None:
        from .sql_parser import find_table_pk
        pk_col = find_table_pk(table_name, list(rec.keys()))
        if pk_col and not blank(rec.get(pk_col)):
            pk_val = str(rec[pk_col]).strip()
            if pk_val and pk_val not in ("0", "NULL", r"\N", "None", "-1"):
                t_lower = table_name.lower()
                table_pk_map[(t_lower, pk_val)] = owner
                tbl_clean = t_lower.rstrip("s")
                table_pk_map[(tbl_clean, pk_val)] = owner
                table_pk_map[(tbl_clean + "s", pk_val)] = owner
                if tbl_clean in ("user", "wp_user", "tbl_user", "app_user", "customer", "client", "member", "account", "person", "contact"):
                    for alias in ("users", "user", "customers", "customer", "clients", "client", "members", "member", "accounts", "account", "people", "person", "contacts", "contact"):
                        table_pk_map[(alias, pk_val)] = owner
    return ex, src


def describe(ex: Extraction, plan=None) -> dict:
    """Readable summary of one extracted record — the live 'this is what we got' sample."""
    ents = [dict(type=t, value=e["display"]) for (t, _), e in ex.ents.items()]
    main = ents[0] if ents else None
    labels = {c.name: c.label for c in plan.columns} if plan else {}
    return dict(main=main, items=ents[1:],
                attrs=[dict(name=n, label=labels.get(n, n), value=v, type=k) for _, n, v, k in ex.attrs])


def import_db(engine, path, mapping=None, label=None, trust=0.8, delete_raw=False, chunk=500, crawl_urls=True,
              progress=None, import_id=None, on_preview=None, overrides=None, learn=True, lineage=None) -> dict:
    """Import every record table of `path`. With delete_raw the input file is removed after a successful import.
    on_preview(dict) is called as soon as each table is catalogued and its first records extracted.
    overrides: {table: {column: type}} — the user's corrections from the analysis screen."""
    label = label or os.path.basename(path)
    tag = f"?import={import_id}" if import_id else ""
    specs = engine.specs(force=True)
    st = engine.store
    ctx = Context(st, overrides)
    stats = {"tables": 0, "records": 0, "documents": 0, "skipped": 0, "urls_queued": 0, "deleted": False,
             "attributes": 0, "persons": 0, "national_ids": 0, "phones": 0, "emails": 0, "links": 0}
    preview = {"kind": "tabular", "tables": []}
    table_pk_map = {}
    for table, plan, rows in read_tables(path, mapping, ctx):
        stats["tables"] += 1
        buf, part, before = [], 0, stats["records"]
        tinfo = dict(table=table, **plan.summary(), samples=[])
        preview["tables"].append(tinfo)
        if on_preview:
            on_preview(preview)

        fts_rows = []
        row_idx = 0

        def flush(buf, part):
            url = f"import://{label}/{table}/{part}{tag}"
            sid, _ = st.add_source(url, origin=f"import:{label}", import_id=import_id, lineage=lineage or label)
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
            if fts_rows:
                st.index_documents_fts_batch([(sid, path, f"table={table}:line={idx}", text) for idx, text in fts_rows])
                fts_rows.clear()
            for ex, _, src in buf:
                if crawl_urls and src and src.startswith("http"):   # re-verify the original page later
                    stats["urls_queued"] += st.add_source(src, priority=5, origin=f"import:{label}")[1]

        text_col, seen_col, url_col = plan.col("doc"), plan.col("seen"), plan.col("url")
        for rec in rows:
            row_idx += 1
            row_str = " | ".join(f"{k}: {v}" for k, v in rec.items() if v is not None and str(v).strip())
            if row_str:
                fts_rows.append((row_idx, row_str))
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
                if not any(c.status == "entity" for c in plan.columns):
                    continue
            ex, src = record_extraction(rec, plan, specs, trust, table_pk_map=table_pk_map, table_name=table)
            if not ex.ents:
                stats["skipped"] += 1
                if len(fts_rows) >= chunk:
                    flush(buf, part)
                    buf, part = [], part + 1
                continue
            stats["attributes"] += len(ex.attrs)
            stats["links"] += len(ex.links)
            for (etype, _) in ex.ents:
                if etype == "person":
                    stats["persons"] += 1
                elif etype == "national_id":
                    stats["national_ids"] += 1
                elif etype == "phone":
                    stats["phones"] += 1
                elif etype == "email":
                    stats["emails"] += 1
            if len(tinfo["samples"]) < 3:
                tinfo["samples"].append(describe(ex, plan))
                if on_preview:
                    on_preview(preview)
            buf.append((ex, parse_ts(rec.get(seen_col)) if seen_col else None, src))
            stats["records"] += 1
            if len(buf) >= chunk or len(fts_rows) >= chunk:
                flush(buf, part)
                buf, part = [], part + 1
                if progress:
                    progress(stats)
        if buf or fts_rows:
            flush(buf, part)
        tinfo["records"] = stats["records"] - before
        if learn:
            st.learn_fields(learnable(plan))
    log.info(
        "[Import Summary] file=%s tables=%d records=%d skipped=%d persons=%d national_ids=%d phones=%d emails=%d links=%d attrs=%d",
        label, stats["tables"], stats["records"], stats["skipped"],
        stats["persons"], stats["national_ids"], stats["phones"], stats["emails"], stats["links"], stats["attributes"]
    )
    if on_preview:
        on_preview(preview)
    stats["preview"] = preview
    if delete_raw and stats["records"] + stats["documents"] > 0:
        os.remove(path)
        stats["deleted"] = True
    return stats
