"""Column cataloguing for any table: decide, for every column, what information type it holds and what
happens to it. Decisions use (in order of trust): the user's explicit choice, the user's taught header names,
an exact header synonym, the values themselves, what was learned from earlier files, and header fragments.

Every column ends up as one of:
  entity     a linkable type (person name, email, phone, address, org, username, profile, website, custom ID…):
             becomes an entity, so the same value in another file connects the records
  attribute  kept on the row's main person/org under the column's ORIGINAL header, with a detected type
             (city, date, gender, IP, ...) or "unknown" when nothing fits
  doc        free page text: goes through full text extraction
  sensitive  passwords, hashes, tokens, card / ID numbers: never stored
  internal   row ids and bookkeeping columns
  empty      no values in the sample
"""
import re
from collections import Counter
from dataclasses import dataclass, field

from .semantic import (EXACT, SENSITIVE_KINDS, TYPES, Registry, blank_value, header_key, header_label,
                       value_kind)  # noqa: F401
from .textnorm import fold

LEGACY = {"text": "doc", "domain": "website"}              # field names of older mapping files
SINGLE = {"name", "first", "last", "role", "url", "seen", "doc", "street", "house", "city", "zip", "country",
          "birthdate", "gender", "age"}                   # one column per row makes sense; extras become attributes
STRUCTURAL = {"name", "first", "last", "role", "url", "seen", "doc", "street", "house", "city", "zip"}
HARD = {"email", "phone", "profile", "url", "ip", "date", "coords", "money"}   # content that overrules a header
NOT_ENTITY_STATUS = {"sensitive", "internal", "empty"}
blank = blank_value


@dataclass
class Column:
    name: str
    type: str = "unknown"
    status: str = "attribute"
    how: str = ""
    confidence: float = 0.0
    kind: str = "text"
    kind_share: float = 0.0
    filled: float = 0.0
    distinct: int = 0
    samples: list = field(default_factory=list)
    reason: str = ""
    label: str = ""

    @property
    def field(self):                     # older name
        return self.type

    def as_dict(self):
        return dict(name=self.name, type=self.type, label=self.label, status=self.status, how=self.how,
                    confidence=round(self.confidence, 2), kind=self.kind, kind_share=round(self.kind_share, 2),
                    filled=round(self.filled, 2), distinct=self.distinct, samples=self.samples, reason=self.reason)


@dataclass
class Plan:
    columns: list
    fields: dict                          # type -> [column names] (entity + structural columns)
    registry: Registry = None

    def col(self, t):
        t = LEGACY.get(t, t)
        return (self.fields.get(t) or [None])[0]

    def cols(self, t):
        return self.fields.get(LEGACY.get(t, t), [])

    @property
    def attrs(self):
        return [c for c in self.columns if c.status == "attribute"]

    @property
    def entity_cols(self):
        return [c for c in self.columns if c.status == "entity"]

    @property
    def usable(self) -> bool:
        """Something to hang the data on: a person, an org, a contact point, an identifier, or page text."""
        return any(c.status in ("entity", "doc") for c in self.columns) or bool(self.fields.keys() & {"first", "last"})

    def summary(self):
        return dict(columns=[c.as_dict() for c in self.columns], fields=dict(self.fields), usable=self.usable)


def _support(kinds, reg, t):
    """Share of values whose kind is compatible with type t."""
    if not kinds:
        return 0.0
    return sum(1 for k in kinds if t in reg.kind_types(k)) / len(kinds)


def plan_columns(cols, sample_rows=(), mapping=None, memory=None, registry=None, overrides=None) -> Plan:
    """Catalogue every column of a table from its header and a sample of rows ({col: value} dicts).
    mapping: {type: column | [columns]} (mapping file); overrides: {column: type} (user's choice in the UI);
    memory: {header_key: {"type", "source"}} learned from earlier files and from the user."""
    reg = registry or Registry()
    memory = memory or {}
    sample_rows = [r for r in sample_rows if isinstance(r, dict)][:300]
    forced = {}
    for t, v in (mapping or {}).items():
        for cname in ([v] if isinstance(v, str) else v):
            forced[str(cname)] = (LEGACY.get(t, t), "mapping")
    for cname, t in (overrides or {}).items():
        forced[str(cname)] = (LEGACY.get(t, t), "user")
    out = []
    for name in cols:
        name = str(name)
        vals = [r.get(name) for r in sample_rows]
        present = [v for v in vals if not blank(v)]
        c = Column(name)
        c.filled = len(present) / len(vals) if vals else 0.0
        c.distinct = len({str(v) for v in present})
        kinds = [reg.kind(v) for v in present]
        if kinds:
            c.kind, n = Counter(kinds).most_common(1)[0]
            c.kind_share = n / len(kinds)
        c.samples = [str(v)[:80] for v in list(dict.fromkeys(str(x).strip() for x in present))[:4]]
        _decide(c, name, kinds, present, reg, memory, forced, bool(sample_rows))
        out.append(c)

    # one column per single-valued type; the rest are kept as attributes of the same type
    fields, used = {}, set()
    for c in sorted(out, key=lambda c: -c.confidence):
        if c.status not in ("entity", "doc") and not (c.status == "attribute" and c.type in STRUCTURAL):
            continue
        if c.type in SINGLE and c.type in used:
            if c.status == "doc":
                c.status = "attribute"
            elif c.type in ("name", "first", "last", "role"):
                c.status, c.reason = "attribute", "עמודה נוספת מאותו סוג — נשמרת כשדה"
            continue
        used.add(c.type)
    for c in out:                                   # keep the table's own column order
        if c.status in ("entity", "doc") or (c.status == "attribute" and c.type in STRUCTURAL and c.type in used
                                              and c.reason == ""):
            fields.setdefault(c.type, []).append(c.name)
    for c in out:
        if not c.label:
            c.label = _label(c, reg)
    return Plan(out, fields, reg)


def _label(c, reg):
    if c.status == "sensitive":
        return "רגיש — לא נשמר"
    if c.status == "internal":
        return "שדה טכני"
    if c.status == "empty":
        return header_label(c.name) or "ריקה"
    if c.type == "unknown":
        hl = header_label(c.name)
        return f"{hl}" if hl else "לא מזוהה"
    return reg.label(c.type)


def _status_for(t, reg):
    if t == "doc":
        return "doc"
    if reg.entity(t) or t in ("name", "first", "last"):
        return "entity"
    return "attribute"


def _decide(c, name, kinds, present, reg, memory, forced, sampled):
    hk = header_key(name)
    htype, hhow = reg.header_type(name)
    sens_share = sum(1 for k in kinds if k in SENSITIVE_KINDS or reg.sensitive(k)) / len(kinds) if kinds else 0
    mem = memory.get(hk) or {}

    def set_(t, how, conf, reason=""):
        c.type, c.how, c.confidence = t, how, conf
        c.status = _status_for(t, reg) if t not in ("sensitive", "internal") else t
        c.reason = reason or c.reason
        if c.status == "sensitive":
            c.samples = []

    if name in forced:
        t, how = forced[name]
        if t in ("sensitive", "internal", "skip"):
            return set_("sensitive" if t != "internal" else "internal", how, 1.0, "סומן ידנית — לא נשמר")
        return set_(t if t in reg.types else "unknown", how, 1.0)
    if htype == "sensitive" or sens_share >= 0.5 or reg.sensitive(htype or "") or reg.sensitive(c.kind):
        return set_("sensitive", "header" if htype == "sensitive" else "content", 0.95,
                    'מידע רגיש (סיסמה / גיבוב / אשראי / ת"ז) — לא נשמר')
    if sampled and not present:
        if hhow == "exact" or mem.get("source") == "user":
            set_(mem.get("type") or htype, "header", 0.5)
        else:
            c.status, c.reason, c.how = "empty", "ריקה בדגימה", ""
        return
    if mem.get("source") == "user" and mem.get("type") == "skip":
        return set_("sensitive", "learned", 1.0, "סימנת בעבר: לא לשמור")
    if mem.get("source") == "user" and mem.get("type") in reg.types:
        return set_(mem["type"], "learned", 0.98, "לפי הגדרה שלך")
    dk, share = c.kind, c.kind_share
    decisive_t = None
    th = reg.decisive(dk)
    if th is not None and share >= th and reg.kind_types(dk):
        decisive_t = reg.kind_types(dk)[0]
    if hhow == "exact" and htype not in ("internal", "username", "sensitive"):
        sup = _support(kinds, reg, htype)
        # an exact header loses only to clear, different content ("phone" column full of emails)
        if decisive_t in HARD and decisive_t != htype and htype != "doc" and sup < 0.3 and share >= 0.8:
            return set_(_refine(decisive_t, htype), "content", share, f"הכותרת אומרת '{reg.label(htype)}' אבל התוכן הוא {reg.label(decisive_t)}")
        return set_(htype, "header", 0.95 if not kinds else 0.7 + 0.3 * max(sup, 0.5))
    if decisive_t:
        return set_(_refine(decisive_t, htype), "content", min(0.99, share))
    if mem.get("type") in reg.types and (not kinds or _support(kinds, reg, mem["type"]) >= 0.3
                                         or dk in ("text", "longtext", "name?", "code")):
        return set_(mem["type"], "learned", 0.75, "נלמד מקבצים קודמים")
    if htype == "internal" or hhow == "exact" and htype == "internal":
        c.status, c.type, c.how, c.reason, c.confidence = "internal", "internal", "header", "מזהה / שדה טכני של הטבלה", 0.8
        return
    if htype and htype not in ("sensitive", "internal"):
        sup = _support(kinds, reg, htype)
        if not kinds or sup >= 0.5:
            return set_(htype, "fuzzy" if hhow == "fuzzy" else "header", 0.55 + 0.4 * sup)
    # nothing certain: an attribute, typed by what the values look like
    t = {"date": "date", "number": "number", "money": "money", "bool": "bool", "gender": "gender", "ip": "ip",
         "coords": "coords", "city": "city", "country": "country", "code": "code", "url": "url",
         "longtext": "text", "username": "username" if share >= 0.5 else "code"}.get(dk, "unknown")
    if dk == "name?" and htype == "name":
        t = "name"
    if t == "username" and share < 0.7:
        t = "code"
    set_(t, "guess", 0.4 * share if t != "unknown" else 0.0)
    if c.status == "entity" and c.confidence < 0.5 and t != "name":
        c.status = "attribute"


def _refine(t, htype):
    """Content says 'date' / 'number' / 'name'; the header narrows it."""
    if t == "date" and htype in ("birthdate", "seen"):
        return htype
    if t == "number" and htype in ("zip", "age", "house", "money"):
        return htype
    if t == "name" and htype in ("first", "last"):
        return htype
    if t == "first" and htype == "name":
        return "first"
    if t == "url" and htype in ("profile", "website"):
        return htype
    if t == "address" and htype == "street":
        return "street"
    return t


def detect_columns(cols):
    """Header-only mapping {field: column} (first match per field), with the original field names."""
    back = {v: k for k, v in LEGACY.items()}
    m = {}
    for c in cols:
        f = EXACT.get(header_key(c))
        if f and f in ("name", "first", "last", "email", "phone", "org", "role", "url", "website", "seen", "doc"):
            f = back.get(f, f)
            if f not in m:
                m[f] = c
    return m


def attr_value(v, kind=None):
    """Normalised text of an attribute value, or None when it carries nothing."""
    if blank(v):
        return None
    if isinstance(v, float) and v.is_integer():
        v = int(v)
    s = re.sub(r"\s+", " ", str(v)).strip()
    if not s:
        return None
    return s[:500] + ("…" if len(s) > 500 else "")


def learnable(plan: Plan):
    """(header_key, header, type) pairs worth remembering: decided by content on a header that is not a synonym."""
    for c in plan.columns:
        if c.how == "content" and c.confidence >= 0.6 and c.type in plan.registry.types and \
                header_key(c.name) not in plan.registry.exact and not re.fullmatch(r"(col|column|field|עמודה)_?\d*", header_key(c.name)):
            yield header_key(c.name), c.name, c.type


def fold_key(s):
    return fold(s)
