"""Turn raw bytes into plain text + outbound links. Everything is in-memory; nothing is written to disk."""
import collections
import csv
import email
import email.header
import hashlib
import io
import json
import logging
import os
import re
import zipfile
from dataclasses import dataclass, field
from html.parser import HTMLParser
from xml.etree import ElementTree as ET

from .textnorm import clean, squash
from .urls import ext_of, normalize_url

logger = logging.getLogger(__name__)

MAX_TEXT = 4_000_000
MAX_ZIP_PART = 40 * 1024 * 1024
URL_IN_TEXT = re.compile(r"https?://[^\s<>\"')\]]+")

try:
    import yaml as _yaml
    HAS_YAML = True
except ImportError:
    _yaml = None
    HAS_YAML = False


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
    if not body:
        return ""
    if body[:3] == b"\xef\xbb\xbf":
        return body[3:].decode("utf-8", "replace")
    if body[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return body.decode("utf-16", "replace")
    if hint:
        try:
            s = body.decode(hint)
            return fix_reversed_hebrew(s) if hint.lower() in ("iso-8859-8", "iso8859-8") else s
        except (UnicodeDecodeError, LookupError):
            pass
    try:
        return body.decode("utf-8")
    except UnicodeDecodeError:
        pass
    sample = body[:65536]
    heb_win_iso = sum(1 for b in sample if 0xE0 <= b <= 0xFA)
    heb_cp862 = sum(1 for b in sample if 0x80 <= b <= 0x9A)
    if heb_cp862 > 4 and heb_win_iso == 0:
        try:
            return body.decode("cp862")
        except UnicodeDecodeError:
            pass
    for enc in ("windows-1255", "iso-8859-8", "cp862", "windows-1252"):
        try:
            s = body.decode(enc)
            return fix_reversed_hebrew(s) if enc == "iso-8859-8" else s
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
        if ext in (".xlsx", ".xlsm") or "spreadsheetml" in ct:
            return "xlsx"
        return "docx" if b"word/" in body[:4096] else "xlsx" if b"xl/" in body[:4096] else "unknown"
    if ext == ".eml" or ct == "message/rfc822" or re.match(rb"^(?:from|return-path|delivered-to|received|mime-version|subject|date):\s", body[:512].lstrip(), re.I | re.M):
        return "eml"
    if ct in ("text/html", "application/xhtml+xml") or head.startswith((b"<!doctype html", b"<html")):
        return "html"
    if ct in ("text/csv", "text/tab-separated-values") or ext in (".csv", ".tsv"):
        return "csv"
    if ct in ("application/json", "text/json") or ext == ".json" or ct.endswith("+json"):
        return "json"
    if ct in ("application/x-yaml", "text/yaml", "text/x-yaml") or ext in (".yaml", ".yml"):
        return "yaml"
    if ct in ("text/vcard", "text/x-vcard") or ext == ".vcf":
        return "vcf"
    if ct.endswith("xml") or ext == ".xml" or head.startswith(b"<?xml"):
        return "xml"
    if ct.startswith("text/") or ext in (".txt", ".md", ".log"):
        return "txt"
    if ext in (".jpg", ".jpeg", ".png", ".tiff", ".tif", ".webp", ".bmp") or ct.startswith("image/"):
        return "image"
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


def _is_garbled_pdf_text(txt: str) -> bool:
    s = (txt or "").strip()
    if len(s) < 30:
        return True
    readable = len(re.findall(r"[א-תA-Za-z0-9]", s))
    if readable < 15:
        return True
    non_ws = len(re.sub(r"\s+", "", s))
    bad = s.count("\ufffd") + len(re.findall(r"\(cid:\d+\)", s))
    if non_ws > 0 and (bad / non_ws > 0.25 or readable / non_ws < 0.25):
        return True
    return False


def parse_pdf(body: bytes, url: str = "") -> Parsed:
    try:
        from pypdf import PdfReader
    except ImportError as e:
        raise ParseError("pypdf not installed") from e
    try:
        r = PdfReader(io.BytesIO(body))
        if r.is_encrypted and not r.decrypt(""):
            raise ParseError("encrypted pdf")

        fitz_doc = None
        try:
            import fitz as _fitz
            fitz_doc = _fitz.open(stream=body, filetype="pdf")
        except Exception:
            fitz_doc = None

        pages, links = [], []
        for page_idx, page in enumerate(r.pages[:400]):
            txt = ""
            if fitz_doc is not None and page_idx < len(fitz_doc):
                try:
                    txt = fitz_doc[page_idx].get_text("text") or ""
                except Exception:
                    txt = ""
            if not txt.strip():
                txt = page.extract_text() or ""

            if _is_garbled_pdf_text(txt):
                try:
                    from .ocr_engine import is_ocr_available, ocr_pdf_page
                    if is_ocr_available():
                        ocr_txt = ocr_pdf_page(body, page_idx)
                        if len(re.findall(r"[א-תA-Za-z0-9]", ocr_txt)) > len(re.findall(r"[א-תA-Za-z0-9]", txt)):
                            txt = ocr_txt
                except Exception as ocr_err:
                    logger.warning("PDF page %d OCR failed: %s", page_idx, ocr_err)
            pages.append(txt)
            for an in (page.get("/Annots") or []):
                try:
                    uri = (an.get_object().get("/A") or {}).get("/URI")
                except Exception:
                    uri = None
                u = normalize_url(str(uri)) if uri else None
                if u:
                    links.append((u, ""))
        if fitz_doc is not None:
            try:
                fitz_doc.close()
            except Exception:
                pass
        title = str((r.metadata or {}).get("/Title") or "").strip()
        if not title and url:
            title = os.path.basename(url)
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
    xml_roots = [root]
    for name in sorted(z.namelist()):
        if re.match(r"^word/(?:header|footer)\d*\.xml$", name):
            try:
                xml_roots.append(ET.fromstring(_zip_part(z, name)))
            except Exception:
                pass
    paras = []
    for xr in xml_roots:
        for p in xr.iter(ns + "p"):
            line = "".join((t.text or "") if t.tag == ns + "t" else "\t" if t.tag == ns + "tab" else ""
                           for t in p.iter())
            if line.strip():
                paras.append(line)
    text = clean("\n".join(paras))[:MAX_TEXT]
    return Parsed("docx", text, links=_urls(text))


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


def _walk_structured(data, lines: list, depth: int = 0):
    if len(lines) > 200_000:
        return
    if isinstance(data, dict):
        scalars = [f"{k}: {v}" for k, v in data.items() if isinstance(v, (str, int, float, bool)) and v != "" and v is not None]
        if scalars:
            lines.append(", ".join(scalars))
        for v in data.values():
            if isinstance(v, (dict, list)) and depth < 12:
                _walk_structured(v, lines, depth + 1)
    elif isinstance(data, list):
        for v in data:
            if isinstance(v, str):
                lines.append(v)
            else:
                _walk_structured(v, lines, depth + 1)
    elif isinstance(data, (str, int, float)):
        lines.append(str(data))


def parse_json(body: bytes) -> Parsed:
    try:
        data = json.loads(decode(body))
    except ValueError as e:
        raise ParseError(f"json: {e}") from e
    lines = []
    _walk_structured(data, lines)
    text = clean("\n".join(lines))
    return Parsed("json", text[:MAX_TEXT], links=_urls(text))


def parse_yaml(body: bytes) -> Parsed:
    s = decode(body)
    lines = []
    if HAS_YAML and _yaml is not None:
        try:
            for doc in _yaml.safe_load_all(s):
                if doc is not None:
                    _walk_structured(doc, lines)
        except Exception:
            lines = []
    if not lines:
        for ln in s.splitlines():
            stripped = ln.strip()
            if stripped and not stripped.startswith("#") and stripped not in ("---", "..."):
                lines.append(stripped.lstrip("- ").strip())
    text = clean("\n".join(lines))
    return Parsed("yaml", text[:MAX_TEXT], links=_urls(text))


def _decode_mime_header(val: str) -> str:
    if not val:
        return ""
    parts = []
    for chunk, enc in email.header.decode_header(val):
        if isinstance(chunk, bytes):
            parts.append(decode(chunk, enc))
        else:
            parts.append(str(chunk))
    return squash("".join(parts))


def parse_eml(body: bytes) -> Parsed:
    try:
        msg = email.message_from_bytes(body)
    except Exception as e:
        raise ParseError(f"eml: {e}") from e
    headers = []
    subj = _decode_mime_header(msg.get("Subject", ""))
    for hdr_key, label in (("From", "מאת / From"), ("To", "אל / To"), ("Cc", "העתק / Cc"),
                           ("Date", "תאריך / Date"), ("Subject", "נושא / Subject")):
        val = _decode_mime_header(msg.get(hdr_key, ""))
        if val:
            headers.append(f"{label}: {val}")
    body_parts = []
    links = []
    attachments = []
    for part in msg.walk():
        if part.is_multipart():
            continue
        fn = part.get_filename()
        if fn:
            attachments.append(_decode_mime_header(fn))
            continue
        ctype = (part.get_content_type() or "text/plain").lower()
        payload = part.get_payload(decode=True)
        if not payload:
            continue
        charset = part.get_content_charset()
        if ctype == "text/html":
            hp = parse_html(payload, "", charset)
            if hp.text:
                body_parts.append(hp.text)
            links.extend(hp.links)
        elif ctype.startswith("text/"):
            body_parts.append(clean(decode(payload, charset)))
    if attachments:
        headers.append("קבצים מצורפים / Attachments: " + ", ".join(attachments))
    full_text = clean("\n\n".join(["\n".join(headers)] + body_parts if headers else body_parts))[:MAX_TEXT]
    links.extend(_urls(full_text))
    return Parsed("eml", full_text, clean(subj), links, {"attachments": attachments})


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


def parse_image(body: bytes, url: str = "") -> Parsed:
    text = ""
    try:
        from .ocr_engine import is_ocr_available, ocr_image
        if is_ocr_available():
            text = ocr_image(body)
    except Exception as e:
        logger.warning("parse_image failed on %s: %s", url, e)
        text = ""
    title = os.path.basename(url) if url else ""
    print(f"[parse_image] Extracted {len(text)} characters from {url or 'image'}", flush=True)
    return Parsed("image", clean(text)[:MAX_TEXT], clean(title))


_PARSE_CACHE: "collections.OrderedDict[tuple, Parsed]" = collections.OrderedDict()
_PARSE_CACHE_MAX = 64


def parse(body: bytes, url: str = "", content_type: str = "") -> Parsed:
    cache_key = None
    if body and len(body) <= 25 * 1024 * 1024:
        cache_key = (hashlib.sha256(body).hexdigest(), url or "", content_type or "")
        cached = _PARSE_CACHE.get(cache_key)
        if cached is not None and len(cached.text) > 0:
            _PARSE_CACHE.move_to_end(cache_key)
            return cached

    kind = sniff_kind(body, content_type, url)
    m = re.search(r"charset=([\w-]+)", content_type or "", re.I)
    hint = m.group(1) if m else None
    if kind == "html":
        res = parse_html(body, url, hint)
    elif kind == "image":
        res = parse_image(body, url)
    elif kind == "pdf":
        res = parse_pdf(body, url)
    else:
        fn = {"docx": parse_docx, "xlsx": parse_xlsx, "csv": parse_csv, "json": parse_json,
              "yaml": parse_yaml, "eml": parse_eml, "vcf": parse_vcf, "xml": parse_xml, "txt": parse_txt}.get(kind)
        if not fn:
            raise ParseError(f"unsupported content ({content_type or 'unknown'})")
        res = fn(body)

    if cache_key is not None and len(res.text) > 0:
        _PARSE_CACHE[cache_key] = res
        if len(_PARSE_CACHE) > _PARSE_CACHE_MAX:
            _PARSE_CACHE.popitem(last=False)
    return res
