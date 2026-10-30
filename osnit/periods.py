"""When was a link true? Time periods on links, and whether two people's links overlap in time.

"Lived at the same address" is a strong tie when it was in the same years and a weak one when one moved out in 2003
and the other moved in in 2019. This module gives a link its period and compares two periods.

Where time comes from (strongest first), all recorded at import in rel_period (relation, lo, hi, basis):
  * dates in the SAME row as the link: a start column (מתאריך / תחילת / כניסה / from / since ...), an end column
    (עד / סיום / עזיבה / to / until ...) or a point-in-time column (תאריך / תאריך עדכון / שנה / updated / year ...).
    A birth date is never a period of a link.
  * a year in the file's own name or label ("פנקס בוחרים 2015") — a weak point in time.
  * nothing -> no row in rel_period: the period is UNKNOWN, which neither weakens nor strengthens a tie
    (missing information is never a penalty).

Periods are month-granular strings 'YYYY-MM'; an open end (since 2012, still there) is hi=None.
overlap(a, b) -> ('overlap' | 'near' | 'apart' | 'unknown', factor, Hebrew text): the factor multiplies a tie's
strength (network.py) and divides a step's cost (connect.py)."""
import re
import time


_START = re.compile(r"^(?:מ|מתאריך|מ ?תאריך|תאריך ?(?:התחלה|כניסה|הצטרפות|תחילה)|תחילת|התחלה|כניסה|הצטרפות|נכנס|"
                    r"from|start|started|since|joined|begin|valid ?from|move ?in|moved ?in)\b", re.I)
_END = re.compile(r"^(?:עד|עד ?תאריך|תאריך ?(?:סיום|עזיבה|יציאה)|סיום|עזיבה|יציאה|עזב|to|end|ended|until|left|"
                  r"valid ?to|move ?out|moved ?out)\b", re.I)
_POINT = re.compile(r"(?:תאריך|עדכון|מועד|שנה|שנת|date|updated|update|as ?of|year|timestamp|נכון ל)", re.I)
_BIRTH = re.compile(r"לידה|נולד|birth|dob|born", re.I)
_YEAR = re.compile(r"(?<!\d)(19[5-9]\d|20\d\d)(?!\d)")
_RANGE = re.compile(r"^\s*(19\d\d|20\d\d)\s*[-–—]\s*(19\d\d|20\d\d)\s*$")
_MONTH = (re.compile(r"^(\d{4})-(\d{1,2})(?:-(\d{1,2}))?"), re.compile(r"^(?:(\d{1,2})[/.])?(\d{1,2})[/.](\d{4})"))
# links whose time matters (a person's address / employer / phone / role); kinship and identity do not expire
TIMED_KINDS = ("address", "affiliated_with", "contact", "has_role")


def header_role(name):
    """'start' | 'end' | 'point' | None for a column header."""
    # lower() and not fold(): fold() turns a final ך into כ, and 'מתאריך' would no longer read as a header
    h = " ".join(str(name or "").lower().replace("_", " ").replace("-", " ").split())
    if not h or _BIRTH.search(h):
        return None
    if _START.match(h):
        return "start"
    if _END.match(h):
        return "end"
    if _POINT.search(h):
        return "point"
    return None


def parse_when(v):
    """A cell -> (lo, hi) as 'YYYY-MM' strings, or None. '2014' -> 2014-01..2014-12; '03/2012', '2012-03',
    '01/03/2012' -> that month; '2012-2016' -> 2012-01..2016-12."""
    s = str(v or "").strip()
    if not s:
        return None
    m = _RANGE.match(s)
    if m:
        a, b = sorted((int(m.group(1)), int(m.group(2))))
        return f"{a:04d}-01", f"{b:04d}-12"
    m = _MONTH[0].match(s)
    if m:
        y, mo = int(m.group(1)), int(m.group(2))
        return (f"{y:04d}-{mo:02d}",) * 2 if 1950 <= y <= 2100 and 1 <= mo <= 12 else None
    m = _MONTH[1].match(s)
    if m:
        y, mo = int(m.group(3)), int(m.group(2))
        return (f"{y:04d}-{mo:02d}",) * 2 if 1950 <= y <= 2100 and 1 <= mo <= 12 else None
    if re.fullmatch(r"(19[5-9]\d|20\d\d)(\.0)?", s):
        y = int(s[:4])
        return f"{y:04d}-01", f"{y:04d}-12"
    return None


def row_period(attrs):
    """The period a row's links were true, from its own date cells. attrs: [(header, value)]. -> (lo, hi, basis) or
    None. A start and an end make a range; a start alone is open-ended; points widen to cover each other."""
    start = end = None
    points = []
    for name, value in attrs:
        role = header_role(name)
        if not role:
            continue
        w = parse_when(value)
        if not w:
            continue
        if role == "start":
            start = w[0] if start is None else min(start, w[0])
        elif role == "end":
            end = w[1] if end is None else max(end, w[1])
        else:
            points.append(w)
    if start or end:
        lo = start or (min(p[0] for p in points) if points else end)
        hi = end if end else None
        if hi and lo > hi:
            lo, hi = hi, lo
        return lo, hi, "row"
    if points:
        return min(p[0] for p in points), max(p[1] for p in points), "row"
    return None


def file_year(label):
    """A year in a file's name or label ('פנקס בוחרים 2015.csv') as a weak point in time, or None."""
    now = time.gmtime().tm_year
    ys = [int(y) for y in _YEAR.findall(str(label or "")) if int(y) <= now]
    if len(set(ys)) != 1:
        return None                     # no year, or two different years: not a dependable date
    y = ys[0]
    return f"{y:04d}-01", f"{y:04d}-12", "file"


def merge(periods):
    """Several (lo, hi, basis) of one link -> one (lo, hi, basis); the row's own dates win over the file's year."""
    ps = [p for p in periods if p and p[0]]
    if not ps:
        return None
    own = [p for p in ps if p[2] == "row"] or ps
    lo = min(p[0] for p in own)
    hi = None if any(p[1] is None for p in own) else max(p[1] for p in own)
    return lo, hi, own[0][2]


def _months(ym):
    y, m = ym.split("-")
    return int(y) * 12 + int(m) - 1


def _now_ym():
    t = time.gmtime()
    return f"{t.tm_year:04d}-{t.tm_mon:02d}"


def show(p):
    """'2014–2016', '2015', 'מ-2012', '' for unknown."""
    if not p:
        return ""
    lo, hi = p[0][:4], (p[1] or "")[:4]
    if not p[1]:
        return f"מ-{lo}"
    return lo if lo == hi else f"{lo}–{hi}"


def overlap(a, b):
    """Two periods on one shared value -> (state, factor, text)."""
    if not a or not b:
        return "unknown", 1.0, "זמן לא ידוע"
    alo, ahi = _months(a[0]), _months(a[1] or _now_ym())
    blo, bhi = _months(b[0]), _months(b[1] or _now_ym())
    gap = max(blo - ahi, alo - bhi)
    if gap <= 0:
        lo, hi = max(a[0], b[0]), min(a[1] or _now_ym(), b[1] or _now_ym())
        both = show((lo, hi if (a[1] and b[1]) or hi < _now_ym() else None))
        return "overlap", 1.0, f"באותה תקופה ({both})"
    if gap <= 12:
        return "near", 0.6, f"כמעט באותה תקופה ({show(a)} / {show(b)})"
    return "apart", 0.15, f"לא באותה תקופה ({show(a)} מול {show(b)})"


def contains(p, year):
    """Was a link true in `year`? None when its period is unknown."""
    if not p:
        return None
    y = f"{int(year):04d}"
    return p[0][:4] <= y <= (p[1] or _now_ym())[:4]


def pair_period(store, person, value, cache=None):
    """The period of every link between one person and one value, merged (None when unknown)."""
    key = (person, value)
    if cache is not None and key in cache:
        return cache[key]
    rows = store.q("SELECT p.lo, p.hi, p.basis FROM relations r CROSS JOIN rel_period p ON p.relation_id=r.id "
                   "WHERE (r.a_id=? AND r.b_id=?) OR (r.a_id=? AND r.b_id=?)", (person, value, value, person))
    res = merge([(r["lo"], r["hi"], r["basis"]) for r in rows])
    if cache is not None:
        cache[key] = res
    return res
