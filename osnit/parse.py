"""Turn raw bytes into plain text + outbound links. Everything is in-memory; nothing is written to disk."""
import csv
import io
import json
import re
import zipfile
from dataclasses import dataclass, field
from html.parser import HTMLParser
from xml.etree import ElementTree as ET

from .textnorm import clean, squash
from .urls import ext_of, normalize_url

MAX_TEXT = 4_000_000
MAX_ZIP_PART = 40 * 1024 * 1024
URL_IN_TEXT = re.compile(r"https?://[^\s<>\"')\]]+")


class ParseError(Exception):
    pass


@dataclass
class Parsed:
    kind: str
    text: str
    title: str = ""
    links: list = field(default_factory=list)   # (absolute_url, anchor_text)
    meta: dict = field(default_factory=dict)


def decode(body: bytes, hint: str = None) -> str:
    if body[:3] == b"\xef\xbb\xbf":
        return body[3:].decode("utf-8", "replace")
    if body[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return body.decode("utf-16", "replace")
    encs = ([hint] if hint else []) + ["utf-8", "windows-1255", "iso-8859-8", "windows-1252"]
    for enc in encs:
        try:
            return body.decode(enc)
        except (UnicodeDecodeError, LookupError):
            continue
    return body.decode("latin-1", "replace")


def sniff_kind(body: bytes, content_type: str, url: str) -> str:
    ct = (content_type or "").split(";")[0].strip().lower()
    ext = ext_of(url)
    head = body[:2048].lstrip().lower()
    if body[:5] == b"%PDF-" or ct == "application/pdf" or ext == ".pdf":
        return "pdf"
    if body[:2] == b"PK":
        if ext == ".docx" or "wordprocessingml" in ct:
            return "docx"
        if ext == ".xlsx" or "spreadsheetml" in ct:
            return "xlsx"
        return "docx" if b"word/" in body[:4096] else "xlsx" if b"xl/" in body[:4096] else "unknown"
    if ct in ("text/html", "application/xhtml+xml") or head.startswith((b"<!doctype html", b"<html")):
        return "html"
    if ct == "text/csv" or ext == ".csv":
        return "csv"
    if ct in ("application/json", "text/json") or ext == ".json" or ct.endswith("+json"):
        return "json"
    if ct in ("text/vcard", "text/x-vcard") or ext == ".vcf":
        return "vcf"
    if ct.endswith("xml") or ext == ".xml" or head.startswith(b"<?xml"):
        return "xml"
    if ct.startswith("text/") or ext in (".txt", ".md", ".log"):
        return "txt"
    return "txt" if ct in ("", "application/octet-stream") and b"\x00" not in body[:1024] else "unknown"


# ---------------------------------------------------------------- HTML
class _H(HTMLParser):
    # structural containers separate blocks (blank line); inline-ish blocks only break the line, so a
    # contact "card" (name / title / phone / mail in sibling p/div/h*) stays one extraction block
    BLOCK2 = {"section", "article", "header", "footer", "main", "aside", "ul", "ol", "table", "blockquote",
              "form", "pre", "figure", "address", "dl", "hr"}
    BLOCK1 = {"br", "li", "tr", "dt", "dd", "p", "div", "h1", "h2", "h3", "h4", "h5", "h6"}
    SKIP = {"script", "style", "noscript", "template", "svg", "iframe"}

    def __init__(self, base):
        super().__init__(convert_charrefs=True)
        self.base, self.out, self.title, self.links, self.meta = base, [], "", [], {}
        self.skip = 0
        self.in_title = False
        self.ld = None
        self.a_stack = []
        self.ld_lines = []
        self.nl = 2        # trailing newlines already emitted
        self.pre = 0

    def _brk(self, n):
        if n > self.nl:
            self.out.append("\n" * (n - self.nl))
            self.nl = n

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "title":
            self.in_title = True
        elif tag == "meta":
            k = (a.get("name") or a.get("property") or "").lower()
            if k in ("description", "og:title", "og:description", "author", "og:site_name") and a.get("content"):
                self.meta[k] = a["content"]
        elif tag == "script" and (a.get("type") or "").lower() == "application/ld+json":
            self.ld = []
        elif tag in self.SKIP:
            self.skip += 1
        elif tag == "a":
            self.a_stack.append([a.get("href") or "", []])
        if tag == "pre":
            self.pre += 1
        if tag in self.BLOCK2:
            self._brk(2)
        elif tag in self.BLOCK1:
            self._brk(1)
        elif tag in ("td", "th"):
            self.out.append(" | ")
            self.nl = 0

    def handle_endtag(self, tag):
        if tag == "title":
            self.in_title = False
        elif tag == "script" and self.ld is not None:
            self._ld_done()
        elif tag in self.SKIP and self.skip:
            self.skip -= 1
        elif tag == "a" and self.a_stack:
            href, parts = self.a_stack.pop()
            anchor = squash("".join(parts))
            u = normalize_url(href, self.base) if href else None
            if u:
                self.links.append((u, anchor))
            low = href.lower()
            if low.startswith("mailto:"):
                self.out.append(" " + href[7:].split("?")[0] + " ")
                self.nl = 0
            elif low.startswith("tel:"):
                self.out.append(" " + href[4:] + " ")
                self.nl = 0
        if tag == "pre" and self.pre:
            self.pre -= 1
        if tag in self.BLOCK2:
            self._brk(2)
        elif tag in self.BLOCK1:
            self._brk(1)

    def handle_data(self, data):
        if self.ld is not None:
            self.ld.append(data)
        elif self.in_title:
            self.title += data
        elif not self.skip:
            if not self.pre:
                data = re.sub(r"\s+", " ", data)
            if data.strip():
                self.nl = 0
            elif not self.nl:
                pass
            else:
                return                  # whitespace between tags at a line start
            self.out.append(data)
            if self.a_stack:
                self.a_stack[-1][1].append(data)

    def _ld_done(self):
        raw, self.ld = "".join(self.ld), None
        try:
            self._walk_ld(json.loads(raw))
        except ValueError:
            pass

    def _walk_ld(self, o):
        if isinstance(o, list):
            for x in o:
                self._walk_ld(x)
        elif isinstance(o, dict):
            t = o.get("@type")
            t = t if isinstance(t, list) else [t]
            if any(x in ("Person", "Organization", "Corporation", "LocalBusiness", "NGO") for x in t if x):
                def s(v):
                    if isinstance(v, dict):
                        return str(v.get("name", ""))
                    return ", ".join(map(str, v)) if isinstance(v, list) else str(v or "")
                self.ld_lines.append(", ".join(x for x in (
                    s(o.get("name")), s(o.get("jobTitle")), s(o.get("worksFor")),
                    s(o.get("email")), s(o.get("telephone")), s(o.get("url"))) if x))
            for v in o.values():
                if isinstance(v, (dict, list)):
                    self._walk_ld(v)


def _tidy(text: str) -> str:
    text = re.sub(r"[ \t\r\f\v]+", " ", text)
    text = re.sub(r" ?\n ?", "\n", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    text = re.sub(r"( \| )+(?=\n|$)", "", text)
    return text.strip()


def parse_html(body: bytes, base: str, hint: str = None) -> Parsed:
    m = re.search(rb"charset=[\"']?([\w-]+)", body[:3000], re.I)
    s = decode(body, hint or (m.group(1).decode() if m else None))
    h = _H(base)
    h.feed(s)
    h.close()
    text = "\n\n".join(x for x in (
        squash(h.meta.get("description", "")), "\n".join(h.ld_lines), _tidy("".join(h.out))) if x)
    title = squash(h.title) or squash(h.meta.get("og:title", ""))
    return Parsed("html", clean(text)[:MAX_TEXT], clean(title), h.links, h.meta)


# ---------------------------------------------------------------- binary documents
_HE_FN = ("של", "את", "על", "עם", "או", "כי")
_HE_FN_REV = ("לש", "תא", "לע", "םע", "וא", "יכ")


def fix_reversed_hebrew(text: str) -> str:
    """Some PDFs extract Hebrew in visual (reversed) order; detect by function words and flip runs."""
    words = re.findall(r"[א-ת]+", text)
    fwd = sum(1 for w in words if w in _HE_FN)
    rev = sum(1 for w in words if w in _HE_FN_REV)
    if rev < 3 or rev <= 2 * fwd:
        return text
    run = re.compile(r"[א-ת][א-ת\s\"'.,\-:]*[א-ת]|[א-ת]")
    return "\n".join(run.sub(lambda m: m.group()[::-1], ln) for ln in text.split("\n"))


def parse_pdf(body: bytes) -> Parsed:
    try:
        from pypdf import PdfReader
    except ImportError as e:
        raise ParseError("pypdf not installed") from e
    try:
        r = PdfReader(io.BytesIO(body))
        if r.is_encrypted and not r.decrypt(""):
            raise ParseError("encrypted pdf")
        pages, links = [], []
        for page in r.pages[:400]:
            pages.append(page.extract_text() or "")
            for an in (page.get("/Annots") or []):
                try:
                    uri = (an.get_object().get("/A") or {}).get("/URI")
                except Exception:
                    uri = None
                u = normalize_url(str(uri)) if uri else None
                if u:
                    links.append((u, ""))
        title = str((r.metadata or {}).get("/Title") or "")
    except ParseError:
        raise
    except Exception as e:
        raise ParseError(f"pdf: {e}") from e
    text = fix_reversed_hebrew("\n\n".join(pages))
    return Parsed("pdf", clean(text)[:MAX_TEXT], clean(title), links)


def _zip_part(z: zipfile.ZipFile, name: str) -> bytes:
    with z.open(name) as f:
        data = f.read(MAX_ZIP_PART + 1)
    if len(data) > MAX_ZIP_PART:
        raise ParseError("zip part too large")
    return data


def parse_docx(body: bytes) -> Parsed:
    try:
        z = zipfile.ZipFile(io.BytesIO(body))
        root = ET.fromstring(_zip_part(z, "word/document.xml"))
    except (zipfile.BadZipFile, KeyError, ET.ParseError) as e:
        raise ParseError(f"docx: {e}") from e
    ns = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}"
    paras = ["".join((t.text or "") if t.tag == ns + "t" else "\t" if t.tag == ns + "tab" else ""
                     for t in p.iter()) for p in root.iter(ns + "p")]
    return Parsed("docx", clean("\n".join(x for x in paras if x.strip()))[:MAX_TEXT])


def parse_xlsx(body: bytes) -> Parsed:
    try:
        z = zipfile.ZipFile(io.BytesIO(body))
        ns = "{http://schemas.openxmlformats.org/spreadsheetml/2006/main}"
        shared = []
        if "xl/sharedStrings.xml" in z.namelist():
            for si in ET.fromstring(_zip_part(z, "xl/sharedStrings.xml")).iter(ns + "si"):
                shared.append("".join(t.text or "" for t in si.iter(ns + "t")))
        lines = []
        for name in sorted(n for n in z.namelist() if n.startswith("xl/worksheets/sheet")):
            for row in ET.fromstring(_zip_part(z, name)).iter(ns + "row"):
                cells = []
                for c in row.iter(ns + "c"):
                    v = c.find(ns + "v")
                    if c.get("t") == "inlineStr":
                        cells.append("".join(t.text or "" for t in c.iter(ns + "t")))
                    elif v is not None and v.text:
                        cells.append(shared[int(v.text)] if c.get("t") == "s" and int(v.text) < len(shared)
                                     else v.text)
                if cells:
                    lines.append(" | ".join(cells))
    except (zipfile.BadZipFile, KeyError, ET.ParseError, ValueError) as e:
        raise ParseError(f"xlsx: {e}") from e
    return Parsed("xlsx", clean("\n".join(lines))[:MAX_TEXT])


# ---------------------------------------------------------------- plain/structured
def _urls(text):
    out = []
    for m in URL_IN_TEXT.findall(text):
        u = normalize_url(m.rstrip(".,;:!?"))
        if u:
            out.append((u, ""))
    return out


def parse_csv(body: bytes) -> Parsed:
    s = decode(body)
    try:
        dialect = csv.Sniffer().sniff(s[:4096], delimiters=",;\t|")
    except csv.Error:
        dialect = csv.excel
    csv.field_size_limit(1 << 20)
    rows = csv.reader(io.StringIO(s), dialect)
    lines = [" | ".join(c.strip() for c in row if c.strip()) for _, row in zip(range(300_000), rows)]
    text = clean("\n".join(x for x in lines if x))
    return Parsed("csv", text[:MAX_TEXT], links=_urls(text))


def parse_json(body: bytes) -> Parsed:
    try:
        data = json.loads(decode(body))
    except ValueError as e:
        raise ParseError(f"json: {e}") from e
    lines = []

    def walk(o, depth=0):
        if len(lines) > 200_000:
            return
        if isinstance(o, dict):
            scalars = [f"{k}: {v}" for k, v in o.items() if isinstance(v, (str, int, float)) and v != ""]
            if scalars:
                lines.append(", ".join(scalars))
            for v in o.values():
                if isinstance(v, (dict, list)) and depth < 12:
                    walk(v, depth + 1)
        elif isinstance(o, list):
            for v in o:
                if isinstance(v, str):
                    lines.append(v)
                else:
                    walk(v, depth + 1)
        elif isinstance(o, str):
            lines.append(o)

    walk(data)
    text = clean("\n".join(lines))
    return Parsed("json", text[:MAX_TEXT], links=_urls(text))


def parse_vcf(body: bytes) -> Parsed:
    cards, cur = [], {}
    for ln in decode(body).splitlines():
        k, _, v = ln.partition(":")
        k = k.split(";")[0].upper()
        if k == "BEGIN":
            cur = {}
        elif k == "END":
            cards.append(", ".join(x for x in (cur.get("FN"), cur.get("TITLE"), cur.get("ORG", "").replace(";", " "),
                                               cur.get("EMAIL"), cur.get("TEL"), cur.get("URL")) if x))
        elif k in ("FN", "TITLE", "ORG", "EMAIL", "TEL", "URL"):
            cur.setdefault(k, v.strip())
    text = clean("\n\n".join(c for c in cards if c))
    return Parsed("vcf", text, links=_urls(text))


def parse_xml(body: bytes) -> Parsed:
    s = decode(body)
    links = [(u, "") for loc in re.findall(r"<(?:loc|link)>\s*([^<\s]+)\s*</(?:loc|link)>", s)
             if (u := normalize_url(loc))]
    text = re.sub(r"<[^>]+>", "\n", re.sub(r"<!\[CDATA\[|\]\]>", "", s))
    return Parsed("xml", clean(_tidy(text))[:MAX_TEXT], links=links)


def parse_txt(body: bytes) -> Parsed:
    text = clean(decode(body))[:MAX_TEXT]
    return Parsed("txt", text, links=_urls(text))


def parse(body: bytes, url: str = "", content_type: str = "") -> Parsed:
    kind = sniff_kind(body, content_type, url)
    m = re.search(r"charset=([\w-]+)", content_type or "", re.I)
    hint = m.group(1) if m else None
    if kind == "html":
        return parse_html(body, url, hint)
    fn = {"pdf": parse_pdf, "docx": parse_docx, "xlsx": parse_xlsx, "csv": parse_csv, "json": parse_json,
          "vcf": parse_vcf, "xml": parse_xml, "txt": parse_txt}.get(kind)
    if not fn:
        raise ParseError(f"unsupported content ({content_type or 'unknown'})")
    return fn(body)
