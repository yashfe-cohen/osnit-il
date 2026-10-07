"""Entity + relation extraction. Precision-first: names only via subject match, titles, or role adjacency."""
import re
from dataclasses import dataclass, field

from .textnorm import fold, is_hebrew, name_key, squash, tokens
from .urls import PUBLIC_MAIL, normalize_url, registered_domain
from .names import AMBIGUOUS_HE, GAZ_EN, GAZ_HE
from .quality import classify, prune_shared, valid_email, valid_phone
from .variants import latin_forms

HW = r"[א-ת]{2,}"
NAME_HE = rf"{HW}[ ]+(?:(?:בן|בר|אבו)[ -])?{HW}(?:-{HW})?"
NAME_EN = r"[A-Z][a-z]{1,20}(?:[ ]+[A-Z]\.)?(?:[ ]+(?:van|von|de|der|bin|ben|al|el))?[ ]+[A-Z][A-Za-z'\-]{1,25}"
TITLE_HE = r"ד\"ר|פרופ'|פרופסור|עו\"ד|רו\"ח|אינג'|מר|גב'|גברת|הרב|הרבנית|תא\"ל|אל\"מ|רס\"ן|סא\"ל|ח\"כ|השופט|השופטת"
TITLE_EN = r"Dr|Prof|Professor|Mr|Mrs|Ms|Adv|Judge|Rabbi|Hon|Sir"
# titles that also state a profession/office
TITLE_ROLE = {"עו\"ד": "עורך דין", "רו\"ח": "רואה חשבון", "פרופ'": "פרופסור", "פרופסור": "פרופסור", "השופט": "שופט",
              "השופטת": "שופטת", "ח\"כ": "חבר כנסת", "הרב": "רב", "אינג'": "מהנדס", "Prof": "Professor",
              "Professor": "Professor", "Judge": "Judge", "Adv": "Attorney", "Rabbi": "Rabbi"}
# "label: name" lines in CVs, forms, court documents
LABELS_HE = ("שם מלא", "שם", "התובע", "התובעת", "הנתבע", "הנתבעת", "המבקש", "המבקשת", "המשיב", "המשיבה", "העותר",
             "העותרת", "המערער", "המערערת", "הנאשם", "הנאשמת", "המצהיר", "המצהירה", "איש קשר", "מגיש הבקשה")
LABELS_EN = ("Name", "Full Name", "Contact", "Contact Person", "Plaintiff", "Defendant", "Applicant", "Author")
CV_CUES = re.compile(r"קורות חיים|קו\"ח|curriculum vitae|\bresume\b|\bCV\b|ניסיון תעסוקתי|work experience", re.I)

ROLES_HE = ["מנכ\"ל", "מנכ\"לית", "סמנכ\"ל", "סמנכ\"לית", "יו\"ר", "יושב ראש", "יושבת ראש", "מנהל כללי", "מנהלת כללית",
            "מנהל", "מנהלת", "מייסד", "מייסדת", "שותף מייסד", "שותף", "שותפה", "בעלים", "עורך דין", "עורכת דין",
            "רופא", "רופאה", "מרצה", "חוקר", "חוקרת", "כתב", "כתבת", "עורך", "עורכת", "עיתונאי", "עיתונאית", "מהנדס",
            "מהנדסת", "מפתח", "מפתחת", "יועץ", "יועצת", "דובר", "דוברת", "נשיא", "נשיאה", "סגן נשיא", "דירקטור",
            "דירקטורית", "ראש עיר", "ראש מועצה", "ראש מחלקה", "ראש צוות", "מזכ\"ל", "גזבר", "גזברית", "פרופסור",
            "שופט", "שופטת", "רשם", "רשמת", "רואה חשבון", "רואת חשבון", "מורה", "אחות", "פסיכולוג", "פסיכולוגית",
            "אדריכל", "אדריכלית", "מעצב", "מעצבת", "מנהל מוצר", "מנהלת מוצר", "אנליסט", "אנליסטית", "רכז", "רכזת",
            "ראש המועצה", "ראש העיר", "ראש העירייה", "סגן ראש העיר", "סגנית ראש העיר", "סגן ראש המועצה",
            "סגנית ראש המועצה", "חבר מועצה", "חברת מועצה", "חבר מועצת העיר", "חברת מועצת העיר", "חבר כנסת",
            "חברת כנסת", "מזכיר", "מזכירה", "מזכיר המועצה", "מנהל המחלקה", "מנהלת המחלקה"]
ROLES_EN = ["Chief Executive Officer", "Chief Technology Officer", "Chief Financial Officer", "Chief Operating Officer",
            "CEO", "CTO", "CFO", "COO", "CISO", "CMO", "Co-Founder", "Cofounder", "Founder", "Chairman", "Chairwoman",
            "Chair", "Managing Director", "General Manager", "Director", "Manager", "Professor", "Lecturer", "Researcher",
            "Engineer", "Partner", "Attorney", "Lawyer", "Consultant", "Spokesperson", "President", "Vice President",
            "VP", "Editor-in-Chief", "Editor", "Journalist", "Reporter", "Treasurer", "Principal", "Owner"]
_ROLE_SYN = {"מנכ\"לית": "מנכ\"ל", "סמנכ\"לית": "סמנכ\"ל", "מנהלת": "מנהל", "מייסדת": "מייסד", "שותפה": "שותף",
             "עורכת דין": "עורך דין", "רופאה": "רופא", "חוקרת": "חוקר", "כתבת": "כתב", "עורכת": "עורך",
             "עיתונאית": "עיתונאי", "מהנדסת": "מהנדס", "מפתחת": "מפתח", "יועצת": "יועץ", "דוברת": "דובר",
             "נשיאה": "נשיא", "דירקטורית": "דירקטור", "גזברית": "גזבר", "מנהלת כללית": "מנהל כללי",
             "יושבת ראש": "יושב ראש", "פרופ'": "פרופסור", "ראש המועצה": "ראש מועצה", "ראש העיר": "ראש עיר",
             "ראש העירייה": "ראש עיר", "סגנית ראש העיר": "סגן ראש העיר", "סגנית ראש המועצה": "סגן ראש המועצה",
             "חברת מועצה": "חבר מועצה", "חבר מועצת העיר": "חבר מועצה", "חברת מועצת העיר": "חבר מועצה",
             "חברת כנסת": "חבר כנסת", "מזכירה": "מזכיר", "מנהלת המחלקה": "מנהל מחלקה", "מנהל המחלקה": "מנהל מחלקה",
             "שופטת": "שופט", "רשמת": "רשם", "רואת חשבון": "רואה חשבון", "chief executive officer": "ceo", "chief technology officer": "cto",
             "chief financial officer": "cfo", "chief operating officer": "coo", "cofounder": "co-founder",
             "chairwoman": "chairman", "chair": "chairman"}
_ROLE_HE_RE = "|".join(sorted(map(re.escape, ROLES_HE), key=len, reverse=True))
_ROLE_EN_RE = (r"(?:(?:Head|VP|Director|Vice President) of [A-Z][A-Za-z&]+|(?:"
               + "|".join(sorted(map(re.escape, ROLES_EN), key=len, reverse=True)) + r"))")

STOP_HE = set(map(fold, """של את על עם או כי לא גם הוא היא הם אני זה זו אבל מאת אל מן כל יש אין היה הייתה שלו שלה בין לפני אחרי
כמו אם מה מי איך למה חברת עמותת קרן בנק אוניברסיטת משרד מכללת עיריית ארגון הארגון החברה הקבוצה בעמ מנכל סמנכל מנהל
מנהלת יור שותף מייסד עורך כתב אמר אמרה הודיע הודיעה לדברי לפי ידי יום שנת חודש טלפון נייד פקס מייל דואר כתובת צור קשר
מחקר פיתוח מכירות שיווק כספים תפעול הנדסה משאבי אנוש חדשנות תוכנה טכנולוגיות בכיר בכירה אחראי אחראית מחלקת צוות
ראש ראשת מרכז המרכז הפקולטה פקולטה מכון המכון פרטים נוספים להרשמה הרשמה לפניות פניות שאלות מידע הודעה
דברי פתיחה הרצאה פאנל הפסקה הפסקת צהריים כנס תוכנית""".split()))
STOP_EN = set(map(str.lower, """The And For With From This That Inc Ltd LLC Corp University Company Group Chief Director Manager
President Contact Email Phone Tel Fax Address Home About News Mobile Office Page Read More Click Here Our Team
Privacy Policy Terms Service Services Copyright Rights Reserved All Please Dear Hello""".split()))

PFX1 = r"חברת|עמותת|קרן|ארגון|בנק|קבוצת|רשת|חברה"
PFX2 = r"אוניברסיטת|מכללת|עיריית|מועצת|משרד|מכון|בית החולים|בית ספר|בית הספר|קופת חולים|המרכז ל|הפקולטה ל"
KNOWN_ORGS = ["הטכניון", "צה\"ל", "משטרת ישראל", "הכנסת", "בנק ישראל", "רשות המסים", "מכבי שירותי בריאות", "כללית"]
ORG_HE = [
    re.compile(rf"(?<![א-ת])((?:{HW}[ ]+){{1,2}}בע\"מ)"),
    re.compile(rf"(?<![א-ת])((?:{PFX1})[ ]+{HW})"),
    re.compile(rf"(?<![א-ת])((?:{PFX2})[ ]*{HW}(?:[ ]+{HW})?)"),
    re.compile(r"(?<![א-ת])(" + "|".join(map(re.escape, KNOWN_ORGS)) + r")(?![א-ת])"),
]
_CAP = r"[A-Z][\w&'.\-]*"
ORG_EN = [
    re.compile(rf"\b((?:{_CAP}[ ]+){{0,4}}{_CAP}[ ]+(?:Ltd|Inc|LLC|Corp|Corporation|GmbH|PLC)\b\.?)"),
    re.compile(rf"\b((?:University|Institute|College|Ministry|Bank|Hospital|Foundation|Association) of {_CAP}(?:[ ]+{_CAP}){{0,2}})"),
    re.compile(rf"\b((?:{_CAP}[ ]+){{1,3}}(?:University|Institute|College|Foundation|Association|Hospital)\b)"),
]
ORG_LEAD_STOP = {"contact", "the", "at", "for", "email", "from", "by", "our", "and", "with", "visit", "about", "of", "to"}
ORG_SUFFIX = {"ltd", "inc", "llc", "corp", "corporation", "gmbh", "plc", "בעמ", "co"}

EMAIL_RE = re.compile(r"(?<![\w.%+\-])[A-Za-z0-9][A-Za-z0-9._%+\-]*@[A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)+")
OBF_AT = re.compile(r"\s*[\[(]\s*at\s*[\])]\s*|\s+\bat\b\s+(?=[\w\-]+\s*[\[(]\s*dot)", re.I)
OBF_DOT = re.compile(r"\s*[\[(]\s*dot\s*[\])]\s*", re.I)
URL_RE = re.compile(r"(?:https?://|www\.)[^\s<>\"')\]|]+", re.I)
TLDS = set("com org net edu gov io co il us uk de fr ru info biz me ai app dev tech xyz online site shop club "
           "news nl it es ca au in br cn jp eu ch se no dk fi pl cz at be ie nz za tv fm".split())
BAD_TLD = {"png", "jpg", "jpeg", "gif", "svg", "webp", "css", "js", "pdf", "html", "php"}
DOMAIN_RE = re.compile(r"(?<![\w@.\-/])(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}(?![\w@\-]|\.[a-z0-9])", re.I)
PHONE_IL = re.compile(r"(?<![\d+])(?:(?:\+|00)?972[-\s.]?\(?0?\)?|0)(?:[23489]|[57]\d)[-\s.]?\d{3}[-\s.]?\d{4}(?!\d)")
PHONE_IL_SPECIAL = re.compile(r"(?<![\d*])(?:1[-\s]?(?:700|800|599|801)[-\s]?\d{3}[-\s]?\d{3}|\*\d{3,4})(?!\d)")
PHONE_INTL = re.compile(r"(?<![\w+])\+(?!972)\d{1,3}[-\s.(]*\d[\d\-\s.()]{6,14}\d(?!\d)")


@dataclass(eq=False)
class Ent:
    type: str
    key: str
    display: str
    start: int
    end: int
    conf: float
    line: int = 0
    surface: str = ""
    subject_id: int = None
    sub: bool = False        # matched via a subject query
    via: str = ""            # how a person was recognised: title|role|label|subject


@dataclass
class SubjectSpec:
    id: int
    kind: str                # person|org|email|phone|domain
    display: str
    key: str
    matcher: object = None   # compiled regex over folded text (person/org)


@dataclass
class Extraction:
    ents: dict = field(default_factory=dict)      # (type,key) -> {"display","hits":[(snip,conf)],"aliases":{}}
    links: dict = field(default_factory=dict)     # ((t,k),(t,k),kind) -> [(snip, conf)]
    subject_hits: set = field(default_factory=set)
    page_type: str = "normal"

    def add_ent(self, e: Ent, snip: str):
        d = self.ents.setdefault((e.type, e.key), {"display": e.display, "hits": [], "aliases": {}})
        if len(e.display) > len(d["display"]) and e.type != "person":
            d["display"] = e.display
        d["hits"].append((snip, e.conf))
        if e.surface and fold(e.surface) != fold(d["display"]):
            d["aliases"][e.surface] = snip

    def add_link(self, a: Ent, b: Ent, kind: str, conf: float, snip: str):
        ka, kb = (a.type, a.key), (b.type, b.key)
        if ka == kb:
            return
        if ka > kb:
            ka, kb = kb, ka
        self.links.setdefault((ka, kb, kind), []).append((snip, conf))


def org_key(s: str) -> str:
    toks = [t for t in tokens(s.replace('"', "")) if t not in ORG_SUFFIX and t != "the"]
    return " ".join(toks)


def role_key(s: str) -> str:
    k = squash(fold(s))
    return _ROLE_SYN.get(k, k)


def norm_phone_il(raw: str):
    d = re.sub(r"\D", "", raw)
    if d.startswith("00"):
        d = d[2:]
    if d.startswith("972"):
        d = d[3:]
    d = d.lstrip("0") if d.startswith("0") else d
    if d and d[0] in "23489" and len(d) == 8 or d and d[0] in "57" and len(d) == 9:
        return "+972" + d
    return None


def snippet(block: str, s: int, e: int, width: int = 260) -> str:
    one = block.replace("\n", " ⏎ ") if len(block) <= width else None
    if one is not None:
        return squash(block.replace("\n", " · "))
    a = max(0, s - width // 2)
    return squash(block[a:a + width].replace("\n", " · "))


def blocks_of(text: str, limit: int = 700):
    for b in re.split(r"\n\s*\n", text):
        b = b.strip()
        if not b:
            continue
        if len(b) <= limit:
            yield b
            continue
        buf = ""
        for ln in re.split(r"(?<=[A-Za-zא-ת]{3}[.!?])\s+|\n", b):
            if buf and len(buf) + len(ln) > limit:
                yield buf
                buf = ""
            buf += ln + "\n"
        if buf.strip():
            yield buf.strip()


def _name_ok(name: str) -> bool:
    toks = tokens(name)
    if len(toks) < 2:
        return False
    if is_hebrew(name):
        return not any(t in STOP_HE or (len(t) > 3 and t[0] in "והבכלמש" and t[1:] in STOP_HE)
                       or t in ("באוניברסיטת", "במכללת") for t in toks)
    return not any(t in STOP_EN for t in toks) and len({t for t in toks}) == len(toks)


class Extractor:
    def __init__(self, subjects=(), strict=False):
        self.strict = strict     # directory pages: only same-line (row) associations, capped confidence
        self._doc_text = ""
        self.subjects = [s for s in subjects]
        # Hebrew glues ו/ה/ל/ש/ב/מ/כ onto words ("וד\"ר", "לעו\"ד"); bare "מר" is excluded there ("שמר" = kept)
        prefixed = "|".join(t for t in TITLE_HE.split("|") if t != "מר")
        self.titled_he = re.compile(rf"(?<![א-ת])(?:(?P<t>{TITLE_HE})|(?:[והלשבמכ]{{1,2}}(?P<tp>{prefixed})))[ ]+(?P<n>{NAME_HE})")
        self.titled_en = re.compile(rf"\b(?P<t>{TITLE_EN})\.?[ ]+(?P<n>{NAME_EN})")
        labels_he = "|".join(sorted(map(re.escape, LABELS_HE), key=len, reverse=True))
        labels_en = "|".join(sorted(map(re.escape, LABELS_EN), key=len, reverse=True))
        self.labeled = re.compile(rf"(?:^|\n)[ ]*(?:{labels_he}|{labels_en})[ ]*:[ ]*(?:(?:{TITLE_HE}|{TITLE_EN})\.?[ ]+)?"
                                  rf"(?P<n>{NAME_HE}|{NAME_EN})[ ]*(?=$|\n|,)")
        self.after_mixed = re.compile(rf"(?<![א-ת])({NAME_HE})[ ]*[,\-|(][ ]*({_ROLE_EN_RE})\b")
        self.after_he = re.compile(rf"(?<![א-ת])({NAME_HE})(?:[ ]*[,\-|:(][ ]*|[ ]*\n[ ]*)ה?({_ROLE_HE_RE})(?![א-ת])")
        # "דוברת החברה, נועה פרץ": one ה-word may sit between the role and the comma
        self.before_he = re.compile(rf"(?<![א-ת])ה?({_ROLE_HE_RE})(?![א-ת])(?:[ ]+ה[א-ת]{{2,}}(?=[ ]*[:,\-]))?"
                                    rf"(?:[ ]*[:,\-]?[ ]+|[ ]*\n[ ]*)(?:(?:{TITLE_HE})[ ]+)?({NAME_HE})")
        self.after_en = re.compile(rf"\b({NAME_EN})(?:[ ]*[,\-|:(][ ]*|[ ]*\n[ ]*)({_ROLE_EN_RE})\b")
        self.before_en = re.compile(rf"\b({_ROLE_EN_RE})(?:[ ]*[:,\-]?[ ]+|[ ]*\n[ ]*)(?:(?:{TITLE_EN})\.?[ ]+)?({NAME_EN})")

    # ---------------------------------------------------------------- per-block detection
    def _contacts(self, seg: str):
        out, taken = [], []

        def free(s, e):
            return not any(s < b and a < e for a, b in taken)

        for m in EMAIL_RE.finditer(seg):
            addr = m.group().rstrip(".").lower()
            tld = addr.rsplit(".", 1)[-1]
            if tld in BAD_TLD or not tld.isalpha() or not valid_email(addr):
                continue
            taken.append(m.span())
            out.append(Ent("email", addr, addr, m.start(), m.end(), 0.9))
            dom = registered_domain(addr.split("@", 1)[1])
            if dom not in PUBLIC_MAIL:
                out.append(Ent("domain", dom, dom, m.start(), m.end(), 0.85))
        for m in URL_RE.finditer(seg):
            if not free(*m.span()):
                continue
            raw = m.group().rstrip(".,;:!?")
            u = normalize_url(raw if raw.lower().startswith("http") else "http://" + raw)
            if not u:
                continue
            taken.append(m.span())
            host = re.sub(r"^https?://([^/:?#]+).*$", r"\1", u)
            out.append(Ent("url", u, u, m.start(), m.end(), 0.8))
            out.append(Ent("domain", registered_domain(host), registered_domain(host), m.start(), m.end(), 0.8))
        for rx, norm in ((PHONE_IL, norm_phone_il), (PHONE_IL_SPECIAL, lambda r: re.sub(r"[^\d*]", "", r))):
            for m in rx.finditer(seg):
                if not free(*m.span()):
                    continue
                n = norm(m.group())
                if n and valid_phone(n):
                    taken.append(m.span())
                    out.append(Ent("phone", n, n, m.start(), m.end(), 0.9))
        for m in PHONE_INTL.finditer(seg):
            d = re.sub(r"\D", "", m.group())
            if free(*m.span()) and 8 <= len(d) <= 15 and valid_phone("+" + d):
                taken.append(m.span())
                out.append(Ent("phone", "+" + d, "+" + d, m.start(), m.end(), 0.75))
        for m in DOMAIN_RE.finditer(seg):
            if not free(*m.span()):
                continue
            host = m.group().lower()
            if host.rsplit(".", 1)[-1] in TLDS and "." in host and not host[0].isdigit():
                d = registered_domain(host)
                out.append(Ent("domain", d, d, m.start(), m.end(), 0.6))
        return out

    def _orgs(self, seg: str):
        out = []
        for rx in ORG_HE:
            for m in rx.finditer(seg):
                name = squash(m.group(1))
                toks = name.split()
                if rx is ORG_HE[0]:
                    toks = [t for t in toks if fold(t) not in STOP_HE or t == 'בע"מ']
                    name = " ".join(toks)
                    if len(toks) < 2:
                        continue
                k = org_key(name)
                if k and len(k) > 2:
                    out.append(Ent("org", k, name, m.start(1), m.end(1), 0.7 if "בע\"מ" in name else 0.55))
        for rx in ORG_EN:
            for m in rx.finditer(seg):
                words = m.group(1).split()
                while words and words[0].lower().strip(".,:") in ORG_LEAD_STOP:
                    words.pop(0)
                name = " ".join(words)
                k = org_key(name)
                if len(words) >= 2 and len(k) > 2:
                    out.append(Ent("org", k, name, m.start(1), m.end(1), 0.7 if re.search(r"Ltd|Inc|LLC|Corp|GmbH|PLC", name) else 0.55))
        # drop orgs fully contained in a longer one
        out.sort(key=lambda e: (e.start, -(e.end - e.start)))
        res = []
        for e in out:
            if not any(r.start <= e.start and e.end <= r.end for r in res):
                res.append(e)
        return res

    def _persons(self, seg: str):
        """Returns persons and (person, role_text, role_span) pairs."""
        persons, pairs = [], []

        def mk(name, s, e, conf, via):
            name = squash(name)
            if _name_ok(name):
                p = Ent("person", name_key(name), name, s, e, conf, surface=name, via=via)
                persons.append(p)
                return p

        for rx in (self.titled_he, self.titled_en):
            for m in rx.finditer(seg):
                p = mk(m.group("n"), m.start("n"), m.end("n"), 0.6, "title")
                title = m.group("t") or m.groupdict().get("tp")
                if p and title in TITLE_ROLE:
                    t = "t" if m.group("t") else "tp"
                    pairs.append((p, TITLE_ROLE[title], m.span(t)))
        for m in self.labeled.finditer(seg):
            mk(m.group("n"), m.start("n"), m.end("n"), 0.7, "label")
        taken = [(p.start, p.end) for p in persons]
        for rx in (GAZ_HE, GAZ_EN):
            for m in rx.finditer(seg):
                s, e = m.start("f"), m.end("l")
                if any(a < e and s < b for a, b in taken):
                    continue
                name = f"{m.group('f')} {m.group('l')}"
                if m.group("f") in AMBIGUOUS_HE and self._doc_text.count(name) < 2:
                    continue          # "גל לוי" vs "גל" = wave: trust only a repeated full name
                mk(name, s, e, 0.5, "gazetteer")
        for rx, name_g, role_g in ((self.after_he, 1, 2), (self.after_en, 1, 2), (self.before_he, 2, 1), (self.before_en, 2, 1),
                                   (self.after_mixed, 1, 2)):
            for m in rx.finditer(seg):
                p = mk(m.group(name_g), m.start(name_g), m.end(name_g), 0.65, "role")
                if p:
                    pairs.append((p, m.group(role_g), m.span(role_g)))
        return persons, pairs

    def _subject_ents(self, seg: str):
        out, folded = [], fold(seg)
        for sp in self.subjects:
            if sp.matcher is None:
                continue
            for m in sp.matcher.finditer(folded):
                etype = "org" if sp.kind == "org" else "person"
                out.append(Ent(etype, sp.key, sp.display, m.start(), m.end(), 0.7,
                               surface=squash(seg[m.start():m.end()]), subject_id=sp.id, sub=True))
        return out

    # ---------------------------------------------------------------- main
    def extract(self, text: str, title: str = "") -> Extraction:
        ex = self._extract(text, title)
        if self.strict:
            # phone-book pages: keep only rows about a searched subject; everyone else on it is left alone
            linked = {k for (a, b, _kind) in ex.links for k in (a, b)}
            subj_keys = {(("person" if s.kind == "person" else s.kind), s.key) for s in self.subjects}
            keep = {k for k in linked if any(k in (a, b) for (a, b, _kd) in ex.links if a in subj_keys or b in subj_keys)}
            ex.ents = {k: v for k, v in ex.ents.items() if k in subj_keys or k in keep}
            ex.links = {k: v for k, v in ex.links.items() if k[0] in subj_keys or k[1] in subj_keys}
            ex.page_type = "directory"
            return ex
        kind = classify(text, ex)
        if kind == "spam":
            return Extraction(page_type="spam")        # nothing from such a page is believable
        if kind == "directory":
            return Extractor(self.subjects, strict=True).extract(text, title)
        prune_shared(ex)
        return ex

    def _extract(self, text: str, title: str = "") -> Extraction:
        ex = Extraction()
        self._doc_text = text
        title_f = fold(title)
        title_hit = {sp.id for sp in self.subjects if sp.matcher and sp.matcher.search(title_f)}
        all_blocks = ([("T:" + title)] if title else []) + list(blocks_of(text))
        doc_persons, orphan_contacts = {}, []
        for bi, block in enumerate(all_blocks):
            is_title = block.startswith("T:") and bi == 0 and title
            seg = block[2:] if is_title else block
            seg = OBF_DOT.sub(".", OBF_AT.sub("@", seg))
            for e in self._finalize(seg, ex, is_title, title_hit, doc_persons, orphan_contacts):
                pass
        self._personal_document(text, title, ex, doc_persons, orphan_contacts)
        # doc-level fallback: subject present, contacts with no owner in their own block
        for sid in ex.subject_hits:
            sp = next((s for s in self.subjects if s.id == sid), None)
            if self.strict or not sp or sp.kind not in ("person", "org") or len(doc_persons) > 5:
                continue
            subj = doc_persons.get((("person" if sp.kind == "person" else "org"), sp.key))
            if not subj or len(orphan_contacts) > 10:
                continue
            for c, snip in orphan_contacts:
                ex.add_link(subj, c, "contact", 0.3, snip)
        return ex

    def _personal_document(self, text, title, ex, doc_persons, orphan_contacts):
        """A CV / personal form names one person; its experience lines, orgs and contacts are that person's."""
        people = [e for e in doc_persons.values() if e.type == "person"]
        if self.strict or len({p.key for p in people}) != 1:
            return
        p = people[0]
        if not (CV_CUES.search(title + "\n" + text[:400]) or p.via == "label"):
            return
        snip_of = lambda ln: squash(ln)[:260]
        for c, snip in orphan_contacts:
            ex.add_link(p, c, "contact", 0.6, snip)
        for ln in text.split("\n"):
            orgs = self._orgs(ln)
            for o in orgs:
                ex.add_ent(o, snip_of(ln))
                ex.add_link(p, o, "affiliated_with", 0.55, snip_of(ln))
            for m in re.finditer(rf"(?<![א-ת])({_ROLE_HE_RE})(?![א-ת])|\b({_ROLE_EN_RE})\b", ln):
                rtext = m.group(1) or m.group(2)
                org = min(orgs, key=lambda o: abs(o.start - m.end()), default=None)
                rk = role_key(rtext)
                r = Ent("role", f"{rk}|{org.key}" if org else rk, rtext + (f", {org.display}" if org else ""),
                        m.start(), m.end(), 0.55)
                ex.add_ent(r, snip_of(ln))
                ex.add_link(p, r, "has_role", 0.55, snip_of(ln))

    def _finalize(self, seg, ex, is_title, title_hit, doc_persons, orphan_contacts):
        contacts = self._contacts(seg)
        orgs = self._orgs(seg)
        subj = self._subject_ents(seg)
        persons, pairs = self._persons(seg)
        for p in persons:  # a generic person overlapping a subject match is the same mention
            if any(s.start < p.end and p.start < s.end for s in subj):
                p.conf = -1
            if any(o.start < p.end and p.start < o.end for o in orgs):   # "Zeta Security Ltd" is not a person
                p.conf = -1
        persons = [p for p in persons if p.conf > 0]
        pairs = [x for x in pairs if x[0].conf > 0]
        for s in subj:
            if s.subject_id in {sp.id for sp in self.subjects} and s.sub:
                ex.subject_hits.add(s.subject_id)
        owners = subj + persons + orgs
        # subject kinds that are identifiers
        for sp in self.subjects:
            if sp.kind in ("email", "phone", "domain"):
                for c in contacts:
                    if c.type == sp.kind and c.key == sp.key:
                        c.sub, c.subject_id = True, sp.id
                        ex.subject_hits.add(sp.id)
        if is_title:
            for e in subj:
                e.conf = min(0.9, e.conf + 0.15)
            for e in owners + contacts:
                ex.add_ent(e, snippet(seg, e.start, e.end))
            return owners
        # dedupe owner list by identity key, keep positions of all occurrences for proximity
        for e in owners + contacts:
            e.line = seg.count("\n", 0, e.start)
        # boost subject mentions that co-occur with a role/title or sit in a hit title
        for s in subj:
            if s.subject_id in title_hit:
                s.conf = min(0.9, s.conf + 0.1)
        roles = []
        for p, rtext, (rs, re_) in pairs:
            nearest = min(orgs, key=lambda o: abs(o.start - re_), default=None)
            if nearest is not None and abs(nearest.start - re_) > 120:
                nearest = None
            rk = role_key(rtext)
            key = f"{rk}|{nearest.key}" if nearest else rk
            disp = squash(rtext) + (f", {nearest.display}" if nearest else "")
            r = Ent("role", key, disp, rs, re_, 0.6, line=seg.count("\n", 0, rs))
            roles.append((p, r, nearest))
        for sp_ent in subj:  # roles adjacent to a subject mention
            for rx, ng, rg in ((self.after_he, 1, 2), (self.after_en, 1, 2), (self.before_he, 2, 1), (self.before_en, 2, 1)):
                for m in rx.finditer(seg):
                    if m.start(ng) < sp_ent.end and sp_ent.start < m.end(ng):
                        nearest = min(orgs, key=lambda o: abs(o.start - m.end(rg)), default=None)
                        if nearest is not None and abs(nearest.start - m.end(rg)) > 120:
                            nearest = None
                        rk = role_key(m.group(rg))
                        r = Ent("role", f"{rk}|{nearest.key}" if nearest else rk,
                                squash(m.group(rg)) + (f", {nearest.display}" if nearest else ""),
                                m.start(rg), m.end(rg), 0.6, line=seg.count("\n", 0, m.start(rg)))
                        roles.append((sp_ent, r, nearest))
        for e in owners + contacts + [r for _, r, _ in roles]:
            ex.add_ent(e, snippet(seg, e.start, e.end))
        for e in owners:
            doc_persons.setdefault((e.type, e.key), e)
        persons_all = [e for e in owners if e.type == "person"]
        orgs_all = [e for e in owners if e.type == "org"]
        # ---- role links
        for p, r, org in roles:
            ex.add_link(p, r, "has_role", 0.75, snippet(seg, p.start, r.end))
            if org:
                ex.add_link(p, org, "affiliated_with", 0.7, snippet(seg, min(p.start, org.start), max(p.end, org.end)))
        # ---- person/org affiliation (weaker, co-occurrence)
        for p in persons_all:
            if self.strict:
                break
            if len(orgs_all) == 1:
                ex.add_link(p, orgs_all[0], "affiliated_with", 0.4, snippet(seg, p.start, p.end))
            elif orgs_all:
                o = min(orgs_all, key=lambda o: self._dist(p, o))
                if self._dist(p, o) <= 120:
                    ex.add_link(p, o, "affiliated_with", 0.35, snippet(seg, p.start, p.end))
        # ---- contacts -> owners
        who = [o for o in owners if o.type == "person"] or owners   # contacts belong to people first
        for c in contacts:
            if not owners:
                if c.type in ("email", "phone"):
                    orphan_contacts.append((c, snippet(seg, c.start, c.end)))
                continue
            for o in orgs_all:   # an org whose name matches the email/domain owns it too
                probe = c.key if c.type == "email" else "x@" + c.key
                if c.type in ("email", "domain") and self._org_matches_domain(o.display, probe):
                    ex.add_link(o, c, "contact", 0.75, snippet(seg, min(o.start, c.start), max(o.end, c.end)))
            lines = seg.split("\n")
            card = len(lines[c.line]) <= 70 if c.line < len(lines) else True
            best = self._pick_owner(who, c, same_line_only=self.strict or not card)
            if best is None:
                continue
            conf = 0.65 if len({(o.type, o.key) for o in who}) == 1 else (0.55 if best.line == c.line else 0.5)
            if best.line == c.line and len(lines[c.line]) > 140 and abs(best.start - c.start) > 120:
                conf = min(conf, 0.4)    # same long paragraph, far apart: weak
            if c.type == "email" and best.type == "person" and self._name_matches_email(best.display, c.key):
                conf = 0.85
            if c.type == "domain":
                conf *= 0.9
            if self.strict:
                conf = min(conf, 0.5)
            ex.add_link(best, c, "contact", conf, snippet(seg, min(best.start, c.start), max(best.end, c.end)))
        # ---- person co-mentions
        subj_p = [p for p in persons_all if p.sub]
        if self.strict:
            pass
        elif subj_p and len(persons_all) <= 8:
            for s in subj_p:
                for p in persons_all:
                    if p is not s:
                        ex.add_link(s, p, "co_mentioned", 0.25, snippet(seg, s.start, s.end))
        elif 2 <= len(persons_all) <= 3:
            for i, a in enumerate(persons_all):
                for b in persons_all[i + 1:]:
                    ex.add_link(a, b, "co_mentioned", 0.25, snippet(seg, a.start, a.end))
        return owners

    @staticmethod
    def _pick_owner(who, c, same_line_only=False):
        """Card layouts put contacts after the name; rows put name and contact on one line."""
        same = [o for o in who if o.line == c.line]
        if same:
            return min(same, key=lambda o: abs(o.start - c.start))
        if same_line_only:
            return None
        prev = [o for o in who if o.line < c.line]
        if prev:
            best = max(prev, key=lambda o: (o.line, o.start))
            if c.line - best.line <= 5:
                return best
        nxt = [o for o in who if o.line > c.line and o.line - c.line <= 1]
        return min(nxt, key=lambda o: (o.line, o.start)) if nxt else None

    @staticmethod
    def _dist(o, c):
        if o.line == c.line:
            return abs(o.start - c.start)
        return (abs(o.line - c.line) * 100 + abs(o.start - c.start) * 0.2) * (1 if o.line < c.line else 1.6)

    @staticmethod
    def _name_matches_email(name: str, email: str) -> bool:
        local = re.split(r"[._\-+0-9]+", email.split("@")[0])
        local = [x for x in local if x]
        if not local:
            return False
        forms = latin_forms(name)
        if len(local) >= 2:
            return sum(1 for x in local if x in forms or any(f.startswith(x) and len(x) >= 1 and len(local) >= 2 and len(x) == 1 for f in forms)) >= 2
        return len(local[0]) >= 4 and local[0] in forms

    @staticmethod
    def _org_matches_domain(org: str, email: str) -> bool:
        label = registered_domain(email.split("@", 1)[1]).split(".")[0]
        return len(label) >= 4 and any(len(t) >= 4 and (t in label or label in t) for t in latin_forms(org) | set(tokens(org)))
