"""Find records inside files that are not tables: where one person's details end and the next one's begin.

Recognised layouts (each yields (table_name, columns, rows) like a spreadsheet would):
  key: value blocks   "שם: יונתן חייט / טלפון: 050-… / (blank line) / שם: דנה לוי / …"   (also vCard)
  delimited lines     "יונתן חייט | 050-8317945 | yon@x.co.il" with or without a header line
  typed lines         "יונתן חייט 050-8317945 yon@x.co.il" — split by what each piece is (phone, email, ...)
  HTML tables         <table> with <th> or a first header row
  nested JSON         any list of objects at any depth, nested keys flattened ("address.city")
  XML                 repeated elements with child fields
"""
import json
import re
from collections import Counter
from html.parser import HTMLParser
from xml.etree import ElementTree as ET

from .semantic import value_kind

MIN_RECORDS = 2

# ---------------------------------------------------------------- key: value blocks
_KV = re.compile(r"^\s*(?:[-*•▪◦]\s*)?(?P<k>[^\s:：=|][^:：=|\n]{0,38}?)\s*(?:[:：=]|\s[-–]\s)\s*(?P<v>\S.{0,500}?)\s*$")
_VC = re.compile(r"^([A-Z][A-Z0-9\-]*)(?:;[^:]*)?:(.*)$")
_SEP = re.compile(r"^\s*(?:[-=_*~#.]{3,}|BEGIN:VCARD|END:VCARD)\s*$", re.I)


def _kv_key(k: str) -> str:
    k = k.strip().strip("*_#").strip()
    return re.sub(r";.*$", "", k) if re.match(r"^[A-Z\-]+;", k) else k     # vCard "TEL;TYPE=CELL" -> "TEL"


def kv_blocks(text: str):
    lines = text.splitlines()
    nonblank = [l for l in lines if l.strip()]
    if len(nonblank) < 4:
        return None
    recs, cur, kv_lines, order = [], {}, 0, []
    vcard = "BEGIN:VCARD" in text.upper()
    dashed = set()
    for ln in lines + [""]:
        if not ln.strip() or _SEP.match(ln):
            if len(cur) >= 2:
                recs.append(cur)
                cur = {}
            elif ln.strip() == "" and cur:
                pass                                   # a single field then a blank line: keep collecting
            continue
        vm = _VC.match(ln) if vcard else None
        if vm:
            k, v = vm.group(1).upper(), vm.group(2).strip().replace(";", " ").strip()
            if k in ("N", "VERSION", "PRODID", "REV", "UID"):
                continue
            k = {"FN": "שם", "TEL": "טלפון", "EMAIL": "מייל", "ORG": "ארגון", "TITLE": "תפקיד", "ADR": "כתובת",
                 "URL": "קישור", "NOTE": "הערה", "BDAY": "תאריך לידה"}.get(k, k)
            kv_lines += 1
            if k in cur:
                k = next(f"{k} {i}" for i in range(2, 20) if f"{k} {i}" not in cur)
            cur[k] = v
            if k not in order:
                order.append(k)
            continue
        m = _KV.match(ln)
        if not m or m.group("v").startswith("//") or re.match(r"https?$", m.group("k"), re.I):
            continue
        k, v = _kv_key(m.group("k")), m.group("v").strip()
        if ":" not in ln and "=" not in ln and "：" not in ln:
            dashed.add(k)                              # "title - subtitle" lines count only if the key repeats
        if len(k.split()) > 4 or not re.search(r"[^\W\d_]", k):
            continue
        kv_lines += 1
        if k in cur:                                   # the same field again: a new record started
            if len(cur) >= 2:
                recs.append(cur)
            cur = {}
        cur[k] = v
        if k not in order:
            order.append(k)
    if len(recs) < MIN_RECORDS or kv_lines < 0.4 * len(nonblank):
        return None
    freq = Counter(k for r in recs for k in r)
    if max(freq.values()) < MIN_RECORDS:           # no field repeats: one form, not a list of records
        return None
    drop = {k for k in dashed if freq[k] < 2}
    recs = [{k: v for k, v in r.items() if k not in drop} for r in recs]
    cols = [k for k in order if freq[k] >= 1 and k not in drop]
    return "רשומות שדה:ערך", cols, recs


# ---------------------------------------------------------------- delimited lines
def _looks_header(fields, rows_kinds):
    if not all(f.strip() and len(f) <= 40 for f in fields):
        return False
    kinds = [value_kind(f) for f in fields]
    if any(k in ("email", "phone", "date", "number", "url", "money") for k in kinds):
        return False
    return sum(1 for i, k in enumerate(kinds) if i < len(rows_kinds) and k != rows_kinds[i]) >= max(1, len(fields) // 2)


def delimited_layout(text: str):
    """(delimiter, field count, columns, has_header) of a delimited-lines table, or None."""
    t = delimited(text)
    if not t:
        return None
    name, cols, rows = t
    d = {"טבלת טאבים": "\t", "טבלת |": "|", "טבלת ;": ";", "טבלת פסיקים": ","}[name]
    return d, len(cols), cols, not cols[0].startswith("עמודה 1")


def delimited(text: str):
    lines = [l for l in text.splitlines() if l.strip()]
    if len(lines) < 3:
        return None
    best = None
    for d in ("\t", "|", ";", ","):
        counts = [len(l.split(d)) for l in lines]
        n, hits = Counter(counts).most_common(1)[0]
        if n < 2 or hits < 3 or hits < 0.7 * len(lines):
            continue
        if d == "," and (hits < 5 or n > 12):
            continue
        rows = [[x.strip() for x in l.split(d)] for l in lines if len(l.split(d)) == n]
        avg = sum(len(x) for r in rows for x in r) / max(1, n * len(rows))
        if avg > 45:
            continue                                   # prose with commas, not a table
        if best is None or hits * n > best[0]:
            best = (hits * n, d, rows)
    if not best:
        return None
    _, d, rows = best
    body_kinds = [Counter(value_kind(r[i]) for r in rows[1:6]).most_common(1)[0][0] for i in range(len(rows[0]))]
    if _looks_header(rows[0], body_kinds):
        cols, rows = rows[0], rows[1:]
        cols = [c or f"עמודה {i+1}" for i, c in enumerate(cols)]
    else:
        cols = [f"עמודה {i+1}" for i in range(len(rows[0]))]
    if len(set(cols)) != len(cols):
        cols = [f"{c} ({i+1})" for i, c in enumerate(cols)]
    name = {"\t": "טבלת טאבים", "|": "טבלת |", ";": "טבלת ;", ",": "טבלת פסיקים"}[d]
    return name, cols, [dict(zip(cols, r)) for r in rows]


# ---------------------------------------------------------------- typed lines
_TOKENS = [
    ("מייל", re.compile(r"[\w.+\-]+@[\w\-]+(?:\.[\w\-]+)+")),
    ("קישור", re.compile(r"https?://\S+|www\.\S+")),
    ("טלפון", re.compile(r"(?<![\d\w])(?:\+972[\s\-]?|0)(?:[23489]|5\d|7\d)[\s\-]?\d{3}[\s\-]?\d{4}(?!\d)")),
    ("תאריך", re.compile(r"(?<!\d)(?:\d{1,2}[./]\d{1,2}[./]\d{2,4}|\d{4}-\d{2}-\d{2})(?!\d)")),
]


def typed_lines(text: str):
    """Lines that each carry several typed items, e.g. a pasted contact list without separators."""
    lines = [l.strip() for l in text.splitlines() if l.strip()]
    recs, sigs = [], Counter()
    for ln in lines:
        if len(ln) > 300:
            continue
        rec, rest = {}, ln
        for label, rx in _TOKENS:
            found = rx.findall(rest)
            for i, f in enumerate(found):
                rec[label if i == 0 else f"{label} {i+1}"] = f.strip(".,;")
            rest = rx.sub(" | ", rest)
        if not rec:
            continue
        chunks = [c.strip(" ,;:-–|()") for c in re.split(r"\s*(?:\||,|;|\s[-–]\s|\t|\s{2,})\s*", rest)]
        chunks = [c for c in chunks if c and re.search(r"[^\W\d_]", c)]
        for i, c in enumerate(chunks[:3]):
            rec["טקסט" if i == 0 else f"טקסט {i+1}"] = c
        if len(rec) >= 2:
            recs.append(rec)
            sigs[tuple(sorted(k for k in rec if not k.startswith("טקסט ")))] += 1
    if len(recs) < 3 or not sigs or sigs.most_common(1)[0][1] < 0.5 * len(recs) or len(recs) < 0.3 * len(lines):
        return None
    cols = list(dict.fromkeys(k for r in recs for k in r))
    return "שורות עם פרטים", cols, recs


# ---------------------------------------------------------------- HTML tables
class _Tables(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.tables, self.stack = [], []

    def handle_starttag(self, tag, attrs):
        if tag == "table":
            self.stack.append({"rows": [], "row": None, "cell": None, "th": []})
        elif not self.stack:
            return
        t = self.stack[-1]
        if tag == "tr":
            t["row"] = []
        elif tag in ("td", "th") and t["row"] is not None:
            t["cell"] = [tag, ""]
        elif tag == "br" and t["cell"] is not None:
            t["cell"][1] += " "

    def handle_endtag(self, tag):
        if not self.stack:
            return
        t = self.stack[-1]
        if tag in ("td", "th") and t["cell"] is not None and t["row"] is not None:
            t["row"].append((t["cell"][0], " ".join(t["cell"][1].split())))
            t["cell"] = None
        elif tag == "tr" and t["row"] is not None:
            if t["row"]:
                t["rows"].append(t["row"])
            t["row"] = None
        elif tag == "table":
            self.tables.append(self.stack.pop()["rows"])

    def handle_data(self, data):
        if self.stack and self.stack[-1]["cell"] is not None:
            self.stack[-1]["cell"][1] += data


def html_tables(html: str):
    p = _Tables()
    try:
        p.feed(html)
    except Exception:
        return []
    out = []
    for n, rows in enumerate(p.tables, 1):
        rows = [r for r in rows if any(v for _, v in r)]
        if len(rows) < 2:
            continue
        width = Counter(len(r) for r in rows).most_common(1)[0][0]
        if width < 2:
            continue
        head = rows[0]
        if all(t == "th" for t, _ in head) or _looks_header([v for _, v in head], [value_kind(v) for _, v in rows[1]]):
            cols, body = [v or f"עמודה {i+1}" for i, (_, v) in enumerate(head)], rows[1:]
        else:
            cols, body = [f"עמודה {i+1}" for i in range(width)], rows
        if len(set(cols)) != len(cols):
            cols = [f"{c} ({i+1})" for i, c in enumerate(cols)]
        recs = [dict(zip(cols, [v for _, v in r])) for r in body if len(r) >= 2]
        if len(recs) >= MIN_RECORDS:
            out.append((f"טבלה {n} בדף", cols, recs))
    return out


# ---------------------------------------------------------------- JSON / XML
def _flatten(o, prefix="", out=None, depth=0):
    out = {} if out is None else out
    for k, v in o.items():
        key = f"{prefix}{k}"
        if isinstance(v, dict) and depth < 4:
            _flatten(v, key + ".", out, depth + 1)
        elif isinstance(v, list):
            if all(not isinstance(x, (dict, list)) for x in v):
                out[key] = "; ".join(str(x) for x in v if x not in (None, ""))
            elif v and all(isinstance(x, dict) for x in v) and len(v) <= 5 and depth < 4:
                for i, x in enumerate(v):                       # small nested lists: phones[0].number …
                    _flatten(x, f"{key}.{i+1}.", out, depth + 1)
        else:
            out[key] = v
    return out


def json_tables(data, name="json"):
    """Every list of objects in the document, at any depth, as a table with flattened columns."""
    found = []

    def walk(o, path, depth):
        if depth > 6:
            return
        if isinstance(o, list):
            objs = [x for x in o if isinstance(x, dict)]
            if len(objs) >= MIN_RECORDS and len(objs) >= 0.6 * len(o):
                rows = [_flatten(x) for x in objs]
                cols = list(dict.fromkeys(k for r in rows[:500] for k in r))
                found.append((path or name, cols, rows))
                return
            for i, x in enumerate(o[:50]):
                walk(x, path, depth + 1)
        elif isinstance(o, dict):
            for k, v in o.items():
                walk(v, f"{path}.{k}" if path else str(k), depth + 1)
    walk(data, "", 0)
    if not found and isinstance(data, dict):
        flat = _flatten(data)
        if len(flat) >= 2:
            found.append((name, list(flat), [flat]))
    return found


def xml_tables(text: str):
    try:
        root = ET.fromstring(text.encode("utf-8") if isinstance(text, str) else text)
    except ET.ParseError:
        return []
    out = []

    def tag(e):
        return e.tag.split("}", 1)[-1]

    def rec(e):
        r = {f"@{k}": v for k, v in e.attrib.items()}
        for ch in e:
            if len(ch):
                for g in ch:
                    if g.text and g.text.strip():
                        r[f"{tag(ch)}.{tag(g)}"] = g.text.strip()
            elif ch.text and ch.text.strip():
                r[tag(ch)] = ch.text.strip()
        return r

    for parent in root.iter():
        groups = Counter(tag(ch) for ch in parent if len(ch) or ch.attrib)
        for t, n in groups.items():
            if n >= MIN_RECORDS:
                rows = [rec(ch) for ch in parent if tag(ch) == t]
                rows = [r for r in rows if len(r) >= 2]
                if len(rows) >= MIN_RECORDS:
                    out.append((t, list(dict.fromkeys(k for r in rows for k in r)), rows))
        if len(out) >= 10:
            break
    return out


# ---------------------------------------------------------------- huge text files, streamed
BIG_TEXT = 16 * 1024 * 1024        # above this a text file is never read whole: layout from its head, rows streamed
HEAD_TEXT = 2 * 1024 * 1024
CHUNK_LINES = 20000


def _lines(path, enc):
    from .textnorm import clean
    with open(path, encoding=enc, errors="replace") as f:     # universal newlines: \n, \r\n and lone \r
        for ln in f:
            yield clean(ln.rstrip("\r\n"))


def text_layout(path, enc):
    """Which record layout a big text file has, decided on its first ~2 MB: (kind, table name, columns, info)."""
    head, size = [], 0
    for ln in _lines(path, enc):
        head.append(ln)
        size += len(ln) + 1
        if size >= HEAD_TEXT:
            break
    text = "\n".join(head)
    t = kv_blocks(text)                                # same order as tables_from_text
    if t:
        return "kv", t[0], t[1], dict(head_lines=len(head), head_rows=len(t[2]))
    lay = delimited_layout(text)
    if lay:
        d, n, cols, has_header = lay
        name = {"\t": "טבלת טאבים", "|": "טבלת |", ";": "טבלת ;", ",": "טבלת פסיקים"}[d]
        return "delimited", name, cols, dict(delim=d, n=n, header=has_header, head_lines=len(head),
                                             head_rows=len(head) - (1 if has_header else 0))
    t = typed_lines(text)
    if t:
        return "typed", t[0], t[1], dict(head_lines=len(head), head_rows=len(t[2]))
    return None


def stream_text_table(path, enc, layout):
    """Rows of a big text file, streamed in the layout found on its head. Delimited lines are split one by one
    (a line with extra separators keeps them in its last field, a short line is padded — nothing is lost);
    key:value blocks and typed lines are parsed in chunks of ~20k lines cut at a record boundary."""
    kind, _, cols, info = layout
    if kind == "delimited":
        d, n, skip = info["delim"], info["n"], info["header"]
        for ln in _lines(path, enc):
            if d not in ln:
                continue
            parts = [x.strip() for x in ln.split(d)]
            if skip:                                   # the header line itself
                skip = False
                continue
            if len(parts) > n:
                parts = parts[:n - 1] + [d.join(parts[n - 1:])]
            parts += [None] * (n - len(parts))
            yield dict(zip(cols, parts))
        return
    finder = kv_blocks if kind == "kv" else typed_lines

    def parse(lines):
        t = finder("\n".join(lines)) if lines else None
        return t[2] if t else []

    # each chunk is parsed one step late, so a short last chunk (a record or two — too few to look like a
    # table on its own) is parsed together with the chunk before it
    pending, buf = None, []
    for ln in _lines(path, enc):
        buf.append(ln)
        if len(buf) >= CHUNK_LINES and (kind == "typed" or not ln.strip() or _SEP.match(ln)):
            if pending is not None:
                yield from parse(pending)
            pending, buf = buf, []
    if pending is not None and len(buf) < CHUNK_LINES // 2:
        yield from parse(pending + buf)
    else:
        yield from parse(pending)
        yield from parse(buf)


# ---------------------------------------------------------------- entry point
def tables_from_text(text: str, html: str = None):
    """All record tables a document holds. HTML tables first, then the first text layout that fits."""
    out = html_tables(html) if html else []
    if len(text) > 3_000_000:
        text = text[:3_000_000]
    for finder in (kv_blocks, delimited, typed_lines):
        t = finder(text)
        if t:
            out.append(t)
            break
    return out


def tables_from_json_text(text: str, name="json"):
    try:
        return json_tables(json.loads(text), name)
    except ValueError:
        return []
