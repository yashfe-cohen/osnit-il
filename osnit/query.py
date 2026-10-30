"""Free-text query understanding: 'יונתן חייט pdf', 'יונתן חייט מספר טלפון', 'Jane Doe filetype:docx email'."""
import re
from dataclasses import asdict, dataclass, field

FILETYPES = {"pdf": "pdf", "doc": "docx", "docx": "docx", "xls": "xlsx", "xlsx": "xlsx", "csv": "csv", "txt": "txt",
             "json": "json", "vcf": "vcf", "ppt": "ppt", "pptx": "ppt"}
WANT = {
    "phone": ["מספר טלפון", "מספר נייד", "מס' טלפון", "טלפון", "נייד", "פלאפון", "טל'", "phone number", "phone", "mobile", "cell", "tel"],
    "email": ["כתובת מייל", "כתובת אימייל", "דואר אלקטרוני", "דוא\"ל", "אימייל", "מייל", "email", "e-mail", "mail"],
    "cv": ["קורות חיים", "קו\"ח", "resume", "cv"],
    "org": ["מקום עבודה", "חברה", "עובד ב", "employer", "company", "works at"],
    "address": ["כתובת מגורים", "מקום מגורים", "איפה גר", "איפה גרה", "היכן גר", "היכן גרה", "כתובת", "home address",
                "address", "where does"],
}
_PHRASES = sorted(((p, k) for k, ps in WANT.items() for p in ps), key=lambda x: -len(x[0]))


@dataclass
class Intent:
    raw: str
    subject: str
    filetypes: list = field(default_factory=list)
    want: list = field(default_factory=list)
    clues: dict = field(default_factory=dict)   # {"phone": [...], "email": [...], "national_id": [...], "city": [...], "address": [...]}

    def to_json(self):
        return asdict(self)


def parse_query(raw: str) -> Intent:
    s = " " + raw.strip() + " "
    filetypes, want = [], []

    def ft(m):
        t = FILETYPES.get(m.group(1).lower())
        if t and t not in filetypes:
            filetypes.append(t)
        return " "

    s = re.sub(r"(?i)\b(?:filetype|ext|type):\s*(\w+)", lambda m: ft(m) if m.group(1).lower() in FILETYPES else m.group(), s)
    s = re.sub(r"(?i)(?:\bנקודה\s+|(?<=\s)\.)(" + "|".join(FILETYPES) + r")(?=\s)", ft, s)
    s = re.sub(r"(?i)(?<=\s)(" + "|".join(FILETYPES) + r")(?=\s)", ft, s)
    for phrase, kind in _PHRASES:
        he = bool(re.match(r"[א-ת]", phrase))       # Hebrew phrases also in the definite form: "הטלפון של ..."
        pat = re.compile(r"(?<![\wא-ת])" + ("ה?" if he else "") + re.escape(phrase) + r"(?![\wא-ת])", re.I)
        if pat.search(s):
            s = pat.sub(" ", s)
            if kind not in want:
                want.append(kind)
    subject = re.sub(r"\s+", " ", re.sub(r'(^|\s)"|"(?=\s|$)', " ", s)).strip()
    rest, clues = extract_clues(subject, strip_filler=bool(want))
    if not rest and clues:                       # no name: the strongest clue is the subject ("054… חיפה")
        for k in ("national_id", "email", "phone", "address", "city"):
            if clues.get(k):
                rest = clues[k][0]
                break
    subject = rest or subject
    return Intent(raw=raw.strip(), subject=subject or raw.strip(), filetypes=filetypes, want=want, clues=clues)


# ---------------------------------------------------------------- several clues in one free-text query
# "דנה לוי 054-1234567", "דנה לוי חיפה", "דנה לוי רחוב הרצל 5 חיפה", "מה הטלפון של דנה לוי"
_EMAIL = re.compile(r"(?<![\w.%+\-])[A-Za-z0-9][A-Za-z0-9._%+\-]*@[A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)+")
_PHONE = re.compile(r"(?<![\d+])(?:(?:\+|00)?972[-\s.]?\(?0?\)?|0)(?:[23489]|[57]\d)[-\s.]?\d{3}[-\s.]?\d{4}(?!\d)")
_DIGITS = re.compile(r"(?<!\d)\d{5,9}(?!\d)")
_HOUSE = re.compile(r"(?<![\d\w])(\d{1,4}[א-ת]?)(?=\s|,|$)")
_STREET = re.compile(r"(?:(?<=\s)|^)(?:ברחוב|רחוב|רח'|רח׳|שדרות|שד'|שד׳|דרך|סמטת|כיכר)\s+[א-ת\"'׳״\- ]{2,30}?\s+\d{1,4}[א-ת]?(?=\s|,|$)")
# who the person is beyond the name: a birth year ("יליד 1979", or a bare plausible year next to a name), an age
# ("בן 45", "בת 52", "גיל 45") and a father's name ("שם האב משה", "son of Moshe", or "בן משה" after a full name)
_BORN = re.compile(r"(?<![\wא-ת])(?:יליד|ילידת|ילידי|נולד|נולדה|born|b\.)\s*(?:ב[-־]?|בשנת\s+|in\s+)?((?:19|20)\d\d)(?!\d)",
                   re.I)
_YEAR = re.compile(r"(?<![\d\w])((?:19|20)\d\d)(?![\d\w])")
_AGE = re.compile(r"(?<![\wא-ת])(?:בן|בת|בגיל|גיל|age|aged)\s+(\d{1,3})(?!\d)", re.I)
_FATHER_EXPLICIT = re.compile(r"(?<![\wא-ת])(?:שם\s+ה?אב|אביו|אביה|father|son\s+of|daughter\s+of)\s*[:\-]?\s*"
                              r"([א-תA-Za-z][א-תA-Za-z'׳\-]+)", re.I)
_SON_OF = re.compile(r"(?<![\wא-ת])(?:בן|בת)\s+([א-ת][א-ת'׳\-]+)(?![\wא-ת])")
# question words that wrap a lookup ("מה הטלפון של ...", "איפה גר ...") but are never part of the name itself
_FILLER = {"מה", "מי", "איפה", "היכן", "של", "את", "עם", "גר", "גרה", "מתגורר", "מתגוררת", "כתובת", "הכתובת", "הטלפון",
           "המייל", "האימייל", "הנייד", "ב", "מ", "ו", "and", "with", "at", "in", "of", "who", "what", "where", "is"}


def _known_first_name(word):
    from .names import AMBIGUOUS_HE, FIRST_EN, FIRST_HE
    from .textnorm import fold
    w = fold(word)
    return (w in {fold(x) for x in FIRST_HE} or w.lower() in {x.lower() for x in FIRST_EN}) and w not in AMBIGUOUS_HE


def _who_clues(s, put):
    """Birth year / age / father's name out of a query (see the regexes above). -> the text without them.
    Precision-first: a bare 4-digit number is a year only in 1920..this year and only next to at least two words;
    "בן/בת" + a number is an age; "בן/בת" + a known first name is a father only AFTER a full name (first + last),
    so "יוסי בן דוד" stays a surname."""
    import time as _time
    now = _time.localtime().tm_year
    for m in _BORN.finditer(s):
        if 1900 <= int(m.group(1)) <= now:
            put("birth_year", m.group(1))
    s = _BORN.sub(lambda m: " " if 1900 <= int(m.group(1)) <= now else m.group(0), s)

    def age(m):
        a = int(m.group(1))
        if 1 <= a <= 120:
            put("age", str(a))
            return " "
        return m.group(0)
    s = _AGE.sub(age, s)
    if len(re.findall(r"[A-Za-zא-ת]{2,}", s)) >= 2:
        def year(m):
            if 1920 <= int(m.group(1)) <= now:
                put("birth_year", m.group(1))
                return " "
            return m.group(0)
        s = _YEAR.sub(year, s)
    for m in _FATHER_EXPLICIT.finditer(s):
        put("father", m.group(1))
    s = _FATHER_EXPLICIT.sub(" ", s)

    def son_of(m):
        before = re.findall(r"[A-Za-zא-ת][A-Za-zא-ת'׳\-]*", s[:m.start()])
        if len(before) >= 2 and _known_first_name(m.group(1)):
            put("father", m.group(1))
            return " "
        return m.group(0)
    return _SON_OF.sub(son_of, s)


def extract_clues(text: str, strip_filler: bool = False):
    """-> (the remaining name text, {clue_type: [values]}). Precision-first: only unambiguous clue shapes are taken —
    a phone needs a 0 / 972 trunk (a bare 8-9 digit number is never a phone), a national ID needs a valid check
    digit, a city must be a known city, a street needs a street word and a house number."""
    from .semantic import il_id_ok, is_city

    clues = {}

    def put(kind, value):
        lst = clues.setdefault(kind, [])
        if value not in lst:
            lst.append(value)

    s = " " + (text or "") + " "
    for m in _EMAIL.finditer(s):
        put("email", m.group(0))
    s = _EMAIL.sub(" ", s)
    for m in _PHONE.finditer(s):
        put("phone", m.group(0).strip())
    s = _PHONE.sub(" ", s)
    for m in _STREET.finditer(s):
        put("address", m.group(0).strip())
    s = _STREET.sub(" ", s)
    s = _who_clues(s, put)

    def digits(m):
        d = m.group(0)
        if len(d) in (8, 9) and il_id_ok(d.zfill(9)):
            put("national_id", d.zfill(9))
            return " "
        return d
    s = _DIGITS.sub(digits, s)

    # "דנה לוי הרצל 12": a short house number with the word before it is a street address (a number is never part
    # of a name). Only when at least two other words remain for the name; the search may move one more word from
    # the name to the street when the shorter name matches nobody ("יהודה הלוי 12").
    m = _HOUSE.search(s)
    if m and not clues.get("address"):
        before = s[:m.start()].split()
        if len(before) >= 3:
            put("address", f"{before[-1]} {m.group(1)}")
            s = " ".join(before[:-1]) + " " + s[m.end():]

    toks = s.split()
    out, i = [], 0
    while i < len(toks):
        hit = 0
        for n in (3, 2, 1):                           # longest known city first: "תל אביב יפו", "באר שבע"
            if i + n <= len(toks) and is_city(" ".join(toks[i:i + n]).strip(",")):
                hit = n
                break
        # a lone city word that is also a common first/last name stays part of the name when it is the whole query
        if hit and (len(toks) > hit or clues):
            put("city", " ".join(toks[i:i + hit]).strip(","))
            i += hit
            continue
        out.append(toks[i])
        i += 1
    if clues or strip_filler:
        out = [t for t in out if t.strip(",.?!").lower() not in _FILLER]
    rest = re.sub(r"\s+", " ", " ".join(out)).strip(" ,.?!")
    return rest, clues
