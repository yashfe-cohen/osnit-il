import os
import re
from dataclasses import dataclass, field

from .textnorm import clean, fold, is_hebrew, name_key, squash, tokens
from .urls import PUBLIC_MAIL, normalize_url, registered_domain
from .names import AMBIGUOUS_HE, FIRST_EN, FIRST_HE, GAZ_EN, GAZ_HE

_FIRST_SET = {fold(n) for n in FIRST_HE} | {n.lower() for n in FIRST_EN}
from .quality import (classify, is_reference_text, prune_shared, valid_email, valid_phone,
                      valid_national_id, valid_corporate_id, valid_license_plate, is_dummy_value, is_dummy_name)
from .semantic import address_key, cities_in, email_key, il_id_key, social_profile
from .variants import latin_forms

HW = r"[א-ת]{2,}"
NAME_HE = rf"{HW}[ ]+(?:(?:בן|בר|אבו)[ -])?{HW}(?:-{HW})?"
NAME_HE_LABELED = rf"{HW}(?:[ ]+{HW})?[ ]+(?:(?:בן|בר|אבו)[ -])?{HW}(?:-{HW})?"
NAME_EN = r"[A-Z][a-z]{1,20}(?:[ ]+[A-Z]\.)?(?:[ ]+(?:van|von|de|der|bin|ben|al|el))?[ ]+[A-Z][A-Za-z'\-]{1,25}"
NAME_EN_LABELED = r"[A-Z][a-z]{1,20}(?:[ ]+[A-Z](?:\.|[a-z]{1,18}))?(?:[ ]+(?:van|von|de|der|bin|ben|al|el))?[ ]+[A-Z][A-Za-z'\-]{1,25}"
TITLE_HE = r"ד\"ר|פרופ'|פרופסור|עו\"ד|רו\"ח|אינג'|מר|גב'|גברת|הרב|הרבנית|תא\"ל|אל\"מ|רס\"ן|סא\"ל|ח\"כ|השופט|השופטת"
TITLE_EN = r"Dr|Prof|Professor|Mr|Mrs|Ms|Adv|Judge|Rabbi|Hon|Sir"
# titles that also state a profession/office
TITLE_ROLE = {"עו\"ד": "עורך דין", "רו\"ח": "רואה חשבון", "פרופ'": "פרופסור", "פרופסור": "פרופסור", "השופט": "שופט",
              "השופטת": "שופטת", "ח\"כ": "חבר כנסת", "הרב": "רב", "אינג'": "מהנדס", "Prof": "Professor",
              "Professor": "Professor", "Judge": "Judge", "Adv": "Attorney", "Rabbi": "Rabbi"}
# "label: name" lines in CVs, forms, court documents
LABELS_HE = ("שם מלא", "שם", "שם + ת\"ז", "שם + ת״ז", "שם + תעודת זהות", "שם הסטודנט", "שם התלמיד", "שם העובד", "שם הלקוח", "שם הפונה",
             "התובע", "התובעת", "הנתבע", "הנתבעת", "המבקש", "המבקשת", "המשיב", "המשיבה", "העותר",
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
כמו אם מה מי איך למה חברת עמותת קרן בנק אוניברסיטת משרד מכללת מכללה ביהס ביהייס עיריית ארגון הארגון החברה הקבוצה בעמ מנכל סמנכל מנהל
מנהלת יור שותף מייסד עורך כתב אמר אמרה הודיע הודיעה לדברי לפי ידי יום שנת חודש טלפון נייד פקס מייל דואר כתובת צור קשר
מחקר פיתוח מכירות שיווק כספים תפעול הנדסה משאבי אנוש חדשנות תוכנה טכנולוגיות בכיר בכירה אחראי אחראית מחלקת צוות
ראש ראשת מרכז המרכז הפקולטה פקולטה מכון המכון פרטים נוספים להרשמה הרשמה לפניות פניות שאלות מידע הודעה
דברי פתיחה הרצאה פאנל הפסקה הפסקת צהריים כנס תוכנית לימודים נרשם נרשמה כיתה בכיתה סטודנט הסטודנט תלמיד התלמיד אישור
חדש חדשה חדשים במקום מקום לשעבר הקודם הקודמת היוצא היוצאת הנכנס הנכנסת
תאריך לידה מלא מספר זהות תעודת מגורים מוסד שירות צבאי יחידה יחידת אב אם אח אחות זוג חירום""".split()))
STOP_EN = set(map(str.lower, """The And For With From This That Inc Ltd LLC Corp University Company Group Chief Director Manager
President Contact Email Phone Tel Fax Address Home About News Mobile Office Page Read More Click Here Our Team
Privacy Policy Terms Service Services Copyright Rights Reserved All Please Dear Hello""".split()))

PFX1 = r"חברת|עמותת|קרן|ארגון|בנק|קבוצת|רשת|חברה"
PFX2 = r"אוניברסיטת|מכללת|עיריית|מועצת|משרד|מכון|בית החולים|בית ספר|בית הספר|קופת חולים|המרכז ל|הפקולטה ל"
KNOWN_ORGS = ["הטכניון", "צה\"ל", "משטרת ישראל", "הכנסת", "בנק ישראל", "רשות המסים", "מכבי שירותי בריאות", "כללית"]
ORG_HE = [
    re.compile(rf"(?<![א-ת])((?:{HW}[ ]+){{1,2}}בע\"מ)"),
    re.compile(rf"(?<![א-ת])((?:{PFX1})[ ]+{HW})"),
    re.compile(rf"(?<![א-ת])((?:{PFX2})[ ]*{HW}(?:[ ]+{HW}){{0,2}})"),
    re.compile(r"(?<![א-ת])(" + "|".join(map(re.escape, KNOWN_ORGS)) + r")(?![א-ת])"),
    re.compile(r"(?<![א-ת])(יחידה[ ]+\d{3,4}|יחידת[ ]+[א-ת]{2,}(?:[ ]+\d{3,4})?)(?![א-ת\d])"),
]
_CAP = r"[A-Z][\w&'.\-]*"
ORG_EN = [
    re.compile(rf"\b((?:{_CAP}[ ]+){{0,4}}{_CAP}[ ]+(?:Ltd|Inc|LLC|Corp|Corporation|GmbH|PLC)\b\.?)"),
    re.compile(rf"\b((?:University|Institute|College|Ministry|Bank|Hospital|Foundation|Association) of {_CAP}(?:[ ]+{_CAP}){{0,2}})"),
    re.compile(rf"\b((?:{_CAP}[ ]+){{1,3}}(?:University|Institute|College|Foundation|Association|Hospital)\b)"),
    re.compile(r"\b(Unit[ ]+\d{3,4}|IDF[ ]+Unit[ ]+\d{3,4})\b", re.I),
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
IL_ID_RE = re.compile(r"(?<!\d)(?:(?:ת[\".״']?ז\.?|תעודת\s+זהות|מספר\s+זהות|מס['.]?\s*זהות|id)[:\s\-]*)?(\d{8,9})(?!\d)", re.I)
IL_CORP_RE = re.compile(r"(?<!\d)(?:(?:ח\.?פ\.?|ע\.?מ\.?|עמותה|חברה)[:\s\-]*)?(5[12578]\d{7})(?!\d)", re.I)
IL_PLATE_RE = re.compile(r"(?<!\d)(?:(?:רכב|לוחית|רישוי|plate|car)[:\s\-]*)?(\d{2,3}[-\s]\d{2}[-\s]\d{3}|\d{3}[-\s]\d{2}[-\s]\d{2,3})(?!\d)", re.I)
ADDR_LABELED_RE = re.compile(r"(?:^|\n)[ ]*(?:כתובת(?:[ ]+מגורים)?|מען|רחוב|Address|Residential[ ]+Address)[ ]*[:\-][ ]*([^\n;|]{4,70})", re.I)
ADDR_INLINE_HE_RE = re.compile(r"(?<![א-ת])((?:רחוב|רח['׳]|שדרות|שד['׳]|דרך)[ ]+[א-ת][א-ת\"'׳\- ]{1,25}[ ]+\d{1,4}(?:[ ]*[,/\-][ ]*[א-ת][א-ת\"'׳\- ]{2,20})?)")
BIRTHDATE_RE = re.compile(r"(?:תאריך[ ]+לידה|ת\.?[ ]*לידה|נולד(?:ה)?[ ]+ביום|Date[ ]+of[ ]+Birth|Birth[ ]*Date|DOB)[ ]*[:\-]?[ ]*(\d{1,2}[./\-]\d{1,2}[./\-]\d{2,4}|\d{4}[./\-]\d{1,2}[./\-]\d{1,2})", re.I)
_KINSHIP_LINE_START = re.compile(
    r"^[ ]*(?:שם\s+ה?(?:אב|אם)|בן\s+זוג|בת\s+זוג|נשוי\s+ל|נשואה\s+ל|אח(?:ות)?|"
    r"איש\s+קשר\s+לחירום|קרוב\s+משפחה|father(?:'s\s+name)?|mother(?:'s\s+name)?|"
    r"spouse|husband|wife|brother|sister|emergency\s+contact|next\s+of\s+kin)[ ]*[:\-]",
    re.I,
)
_KINSHIP_LINE_PFX = re.compile(
    r"(?:שם\s+ה?(?:אב|אם)|אב|אם|בן\s+זוג|בת\s+זוג|נשוי\s+ל|נשואה\s+ל|בעל|אישה|אשתו|בעלה|"
    r"אח|אחות|בן|בת|ילד|ילדה|איש\s+קשר\s+לחירום|קרוב\s+משפחה|"
    r"father(?:'s\s+name)?|mother(?:'s\s+name)?|spouse|husband|wife|partner|"
    r"brother|sister|sibling|son|daughter|child|emergency\s+contact|next\s+of\s+kin)\s*[:\-]?\s*$",
    re.I,
)


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
    attrs: list = field(default_factory=list)     # [((t,k), column name, value, kind)] from tabular imports

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
        if not str(kind).startswith("kinship:") and ka > kb:
            ka, kb = kb, ka
        self.links.setdefault((ka, kb, kind), []).append((snip, conf))


ORG_LEAD_HE = {"חברת", "עמותת", "תאגיד", "קונצרן", "מיזם"}   # generic leading word: "חברת אלפא" == "אלפא"


def org_key(s: str) -> str:
    toks = [t for t in tokens(s.replace('"', "")) if t not in ORG_SUFFIX and t != "the"]
    while len(toks) > 1 and toks[0] in ORG_LEAD_HE:
        toks = toks[1:]
    return " ".join(toks)


def role_key(s: str) -> str:
    k = squash(fold(s))
    return _ROLE_SYN.get(k, k)


def phone_variants(key: str, cap: int = 8) -> list:
    """Written forms of a normalized +972 number, for searching it however it appears on a page:
    0XX-XXX-XXXX, 0XXXXXXXXX, +972XXXXXXXXX, 972-XX-XXX-XXXX, +972-XX-XXXXXXX, 05X XXX XXXX."""
    d = re.sub(r"\D", "", key)
    if not d.startswith("972"):
        return [key]
    nat = d[3:]                      # national part without leading 0
    local = "0" + nat                # 0541234567
    out = [key]                      # +972541234567
    if len(nat) == 9:                # mobile 05X / 07X: 0XX-XXX-XXXX
        a, b, c = local[:3], local[3:6], local[6:]
        pre = nat[:2]                # 54, 52, 73, ...
        out += [f"{a}-{b}-{c}", f"{a}{b}{c}", f"{a} {b} {c}", f"+972-{pre}-{nat[2:5]}-{nat[5:]}",
                f"+972 {pre}-{nat[2:]}", f"972-{pre}-{nat[2:]}"]
    elif len(nat) == 8:              # landline 0X-XXXXXXX (area is one digit after 0)
        area, rest = "0" + nat[0], nat[1:]
        out += [f"{area}-{rest}", f"{area}{rest}", f"+972-{nat[0]}-{rest}", f"972{nat}"]
    seen, res = set(), []
    for v in out:
        if v not in seen:
            seen.add(v)
            res.append(v)
    return res[:cap]


def norm_phone_il(raw: str, allow_missing_zero: bool = False):
    """E.164 for an Israeli number, or None. A real number carries a trunk 0 (0545566123) or a 972 / +972
    country code (+972545566123); a BARE 8- or 9-digit number is rejected unless allow_missing_zero=True
    (used when a column is explicitly identified as a phone column)."""
    d = re.sub(r"\D", "", str(raw))
    if d.startswith("00"):
        d = d[2:]
    if d.startswith("972"):
        nat = d[3:]
        nat = nat[1:] if nat.startswith("0") else nat      # 972-0-54… (rare)
    elif d.startswith("0"):
        nat = d[1:]
    elif allow_missing_zero and ((d[:1] in "23489" and len(d) == 8) or (d[:1] in "57" and len(d) == 9)):
        nat = d
    else:
        return None                                        # no trunk 0 and no country code -> not a phone
    if (nat[:1] in "23489" and len(nat) == 8) or (nat[:1] in "57" and len(nat) == 9):
        return "+972" + nat
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


# words that follow or precede a first name in prose and scripture but are not surnames
NOT_SURNAME_HE = set(map(fold, """אבינו אמנו רבנו רבינו המלך המלכה הנביא הנביאה הכהן הצדיק הצדקת הקדוש זצ"ל זצל ע"ה ז"ל
שליט"א זיע"א אלהים אלוהים יהוה ויאמר ויבא וילך וידבר ויהי ויעש וישב ויקח ויקרא ותאמר ותלד ויולד ויצא ויען אמר אמרה
דיבר ענה הלך יצא לקח ראה שמע ידע נתן ישב קם היה היו יהיה תהיה היתה הייתה אשר כאשר לאמר עד מאד מאוד אלה אלו לכן אך עוד פרק פסוק
בנה בנו בנתה הקים הקימה האבות האמהות המלך המלכה הגיבור הקדושים
פרשת פרשה מסכת ספר בני בנות ארץ שמים יום לילה עמו ביתו אביו אמו אחיו אחיה בנו בתו אשתו בעלה עבדו מלכי שרי אומר אומרת
כתב כתבה הוסיף הוסיפה סיפר סיפרה טען טענה ציין ציינה הודה מסר מסרה שאל שאלה השיב השיבה נולד נולדה נפטר נפטרה גר גרה
עבר עברה החליט החליטה אותו אותה אליו אליה עליו עליה ממנו ממנה שלו שלה לו לה בו בה וכן כך זהו הזה הזאת היום אתמול מחר
""".split()))


def _name_ok(name: str) -> bool:
    toks = tokens(name)
    if len(toks) < 2:
        return False
    if is_hebrew(name):
        return not any(t in STOP_HE or t in NOT_SURNAME_HE or (len(t) > 3 and t[0] in "והבכלמש" and t[1:] in STOP_HE)
                       or t in ("באוניברסיטת", "במכללת") for t in toks)
    return not any(t in STOP_EN for t in toks) and len({t for t in toks}) == len(toks)


COMMON_ACRONYMS = {
    "CV", "ID", "AI", "PDF", "API", "SQL", "URL", "URI", "HTTP", "HTTPS", "HTML", "CSS", "JS",
    "JSON", "XML", "CSV", "REST", "SDK", "CLI", "GUI", "OS", "DB", "RDBMS", "NOSQL",
    "AWS", "GCP", "IT", "HR", "PR", "CEO", "CTO", "CFO", "COO", "CISO", "CMO", "VP", "PM", "QA", "RD", "R&D",
    "LTD", "LLC", "INC", "CORP", "PLC", "GMBH", "CO", "USA", "UK", "IL", "EU", "MBA", "BSC", "BA", "MA", "PHD"
}

GENERIC_EMAIL_WORDS = {
    "info", "admin", "administrator", "contact", "support", "help", "sales", "office", "team",
    "mail", "email", "gmail", "yahoo", "hotmail", "outlook", "service", "billing", "jobs", "hr",
    "career", "careers", "press", "media", "dev", "test", "demo", "co", "org", "gov", "ac", "muni",
    "il", "com", "net", "edu", "mil"
}


def preprocess_caps_for_ner(text: str) -> str:
    """Converts ALL CAPS words (e.g. AMIT TULIAN) to Title Case (Amit Tulian), preserving acronyms."""
    if not text:
        return text

    def _replace_cap(m: re.Match) -> str:
        w = m.group(0)
        if w.upper() in COMMON_ACRONYMS:
            return w
        return w.capitalize()

    return re.sub(r"\b[A-Z]{2,}\b", _replace_cap, text)


def extract_name_from_filename(filename: str) -> str:
    """Extract candidate person name from filename (e.g. 'Amit Tulian.pdf' -> 'Amit Tulian')."""
    if not filename:
        return ""
    base = os.path.splitext(os.path.basename(filename))[0]
    base = re.sub(r"[\-_+.,;:!@#$%^&*()\[\]{}|/\\]+", " ", base)
    base = re.sub(r"(?i)\b(cv|resume|קורות[ ]*חיים|קוח|doc|document|scan|scanned|final|draft|v\d+)\b", " ", base)
    base = re.sub(r"\b\d+\b", " ", base)
    words = [w.strip() for w in base.split() if w.strip()]
    if len(words) >= 2:
        if all(re.match(r"^[A-Za-zא-ת'\-]+$", w) for w in words):
            name = " ".join(w.capitalize() if not is_hebrew(w) else w for w in words)
            if _name_ok(name) and not is_dummy_name(name):
                return name
    return ""


def extract_name_from_email(email: str) -> str:
    """Extract candidate person name from email local part (e.g. 'Amit.tuli2@gmail.com' -> 'Amit Tuli')."""
    if not email or "@" not in email:
        return ""
    local = email.split("@", 1)[0]
    parts = re.split(r"[._\-+]+", local)
    if len(parts) == 1 and re.search(r"[a-z][A-Z]", parts[0]):
        parts = re.findall(r"[A-Z]?[a-z]+|[A-Z]+(?=[A-Z][a-z]|\b)", parts[0])
    cleaned = []
    for p in parts:
        letters = re.sub(r"\d+", "", p).strip()
        if len(letters) >= 2 and letters.isalpha() and letters.lower() not in GENERIC_EMAIL_WORDS:
            cleaned.append(letters.capitalize())
    if len(cleaned) >= 2:
        cand = " ".join(cleaned)
        if _name_ok(cand) and not is_dummy_name(cand):
            return cand
    return ""


_EMBEDDED_IL_PHONE_RE = re.compile(r"(?:^|(?<!\d))(05[012345689]\d{7}|07[234679]\d{7}|0[23489]\d{7})(?!\d)")
_EMBEDDED_IL_ID_RE = re.compile(r"(?:^|(?<!\d))(\d{9})(?!\d)")

_SURNAMES_STARTING_WITH_VAV = {
    "וולף", "וייס", "ויס", "וינברג", "ויינברג", "וינשטיין", "ויינשטיין", "וקנין", "ורדי",
    "ורשבסקי", "ולנסי", "ווגמן", "ויינר", "וינר", "וילנאי", "ויצמן", "וייצמן", "ורטהיים", "וורטהיים"
}


def extract_phone_from_identifier(text: str) -> str | None:
    """Extract an Israeli phone number embedded in an email local-part or username
    (e.g. '0526201912sarit@gmail.com' -> '+972526201912', 'a0548016629@gmail.com' -> '+972548016629')."""
    if not text:
        return None
    local = str(text).split("@", 1)[0]
    m = _EMBEDDED_IL_PHONE_RE.search(local)
    if m:
        ph = norm_phone_il(m.group(1))
        if ph and valid_phone(ph) and not is_dummy_value(ph):
            return ph
    return None


def extract_id_from_identifier(text: str) -> str | None:
    """Extract a 9-digit Luhn-valid Israeli National ID embedded in an email local-part or username
    (e.g. '013279476@bezeqint.net' -> '013279476')."""
    if not text:
        return None
    local = str(text).split("@", 1)[0]
    m = _EMBEDDED_IL_ID_RE.search(local)
    if m:
        cand = m.group(1)
        if not cand.startswith(("05", "07", "50", "52", "53", "54", "55", "58")) and valid_national_id(cand) and not is_dummy_value(cand):
            return il_id_key(cand)
    return None


def split_couple_names(first_or_full: str, last_name: str = "") -> tuple[str, str] | None:
    """Detect and split Hebrew/English couple names sharing a surname into two full names:
    - ('דבורה וישראל', 'לבין') -> ('דבורה לבין', 'ישראל לבין')
    - ('אלון וענבל', 'אלקובי') -> ('אלון אלקובי', 'ענבל אלקובי')
    - ('עידית ואורי טייב', '') -> ('עידית טייב', 'אורי טייב')
    """
    f = clean(first_or_full or "").strip()
    l = clean(last_name or "").strip()
    if not f:
        return None
    f_toks = f.split()
    if l:
        # Case 1: first_name has 'דבורה וישראל' or 'דבורה ו ישראל' or 'David & Ruth'
        if len(f_toks) == 2 and f_toks[1].startswith("ו") and len(f_toks[1]) >= 3:
            p1, p2 = f_toks[0].strip("'\""), f_toks[1][1:].strip("'\"")
            if len(p1) >= 2 and len(p2) >= 2 and is_hebrew(p1) and is_hebrew(p2):
                return f"{p1} {l}", f"{p2} {l}"
        elif len(f_toks) == 3 and f_toks[1].lower() in ("ו", "ו-", "&", "and"):
            p1, p2 = f_toks[0].strip("'\""), f_toks[2].strip("'\"")
            if len(p1) >= 2 and len(p2) >= 2:
                return f"{p1} {l}", f"{p2} {l}"
    else:
        # Case 2: single full name string 'דבורה וישראל לבין' or 'דבורה ו ישראל לבין'
        if len(f_toks) == 3 and f_toks[1].startswith("ו") and len(f_toks[1]) >= 3 and f_toks[1] not in _SURNAMES_STARTING_WITH_VAV:
            p1, p2, sur = f_toks[0].strip("'\""), f_toks[1][1:].strip("'\""), f_toks[2].strip("'\"")
            if len(p1) >= 2 and len(p2) >= 2 and len(sur) >= 2 and is_hebrew(p1) and is_hebrew(p2) and is_hebrew(sur):
                if p1 not in STOP_HE and p2 not in STOP_HE and sur not in STOP_HE:
                    return f"{p1} {sur}", f"{p2} {sur}"
        elif len(f_toks) == 4 and f_toks[1].lower() in ("ו", "ו-", "&", "and"):
            p1, p2, sur = f_toks[0].strip("'\""), f_toks[2].strip("'\""), f_toks[3].strip("'\"")
            if len(p1) >= 2 and len(p2) >= 2 and len(sur) >= 2:
                return f"{p1} {sur}", f"{p2} {sur}"
    return None


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
                                  rf"(?P<n>{NAME_HE_LABELED}|{NAME_EN_LABELED})[ ]*(?=$|\n|,|[ ]+ת[\".״']?ז|[ ]+\d)")
        self.after_mixed = re.compile(rf"(?<![א-ת])({NAME_HE})[ ]*[,\-|(][ ]*({_ROLE_EN_RE})\b")
        self.after_he = re.compile(rf"(?<![א-ת])({NAME_HE})(?:[ ]*[,\-|:(][ ]*|[ ]*\n[ ]*)ה?({_ROLE_HE_RE})(?![א-ת])")
        # "דוברת החברה, נועה פרץ": one ה-word may sit between the role and the comma
        self.before_he = re.compile(rf"(?<![א-ת])ה?({_ROLE_HE_RE})(?![א-ת])(?:[ ]+ה[א-ת]{{2,}}(?=[ ]*[:,\-]))?"
                                    rf"(?:[ ]*[:,\-]?[ ]+|[ ]*\n[ ]*)(?:(?:{TITLE_HE})[ ]+)?({NAME_HE})")
        self.after_en = re.compile(rf"\b({NAME_EN})(?:[ ]*[,\-|:(][ ]*|[ ]*\n[ ]*)({_ROLE_EN_RE})\b")
        self.before_en = re.compile(rf"\b({_ROLE_EN_RE})(?:[ ]*[:,\-]?[ ]+|[ ]*\n[ ]*)(?:(?:{TITLE_EN})\.?[ ]+)?({NAME_EN})")
        # appositive clause: "Eran Dahan, who will remain Chairman" / "נועה פרץ, שתמשיך לכהן כיו\"ר"
        self.who_en = re.compile(rf"\b({NAME_EN}),[ ]+who[ ]+(?:will[ ]+|has[ ]+been[ ]+|is[ ]+now[ ]+)?"
                                 rf"(?:remain|remains|serve|serves|served|continue|continues|become|becomes|is|was)"
                                 rf"(?:[ ]+(?:as|on))?(?:[ ]+(?:the|its|our))?[ ]+({_ROLE_EN_RE})\b")
        self.who_he = re.compile(rf"(?<![א-ת])({NAME_HE}),[ ]+(?:ש|אשר[ ]+)(?:ימשיך|תמשיך|מכהן|מכהנת|כיהן|כיהנה|יכהן|תכהן|ישמש|תשמש|שימש|שימשה)"
                                 rf"(?:[ ]+(?:לכהן|לשמש))?[ ]+(?:כ[\"'־\-]?ה?|ב?תפקיד[ ]+)({_ROLE_HE_RE})(?![א-ת])")
        # Israeli forms name adjacent to ID (e.g. "כהן ישפה ת\"ז 216958868" or "הסטודנט כהן ישפה ת\"ז : 216958868")
        self.id_adjacent_he = re.compile(
            rf"(?<![א-ת])(?:(?:ה?סטודנט(?:ית)?|ה?תלמיד(?:ה)?|ה?עובד(?:ת)?|ה?מבקש(?:ת)?)[ ]+)?(?:(?P<n1>{HW}[ ]+{HW}(?:[ ]+{HW})?)[ ]*[,;\-]?[ ]*(?:ת[\".״']?ז\.?|תעודת\s+זהות|מספר\s+זהות|מס['.]?\s*זהות|id)(?:[:\s\-;.]*\d{{6,9}})?"
            rf"|(?:ת[\".״']?ז\.?|תעודת\s+זהות|מספר\s+זהות|מס['.]?\s*זהות|id)[ ]*[:\-]?[ ]*\d{{8,9}}[ ]*[,;\-:]?[ ]*(?P<n2>{HW}[ ]+{HW}(?:[ ]+{HW})?))",
            re.I
        )

    # ---------------------------------------------------------------- per-block detection
    def _contacts(self, seg: str):
        out, taken = [], []

        def free(s, e):
            return not any(s < b and a < e for a, b in taken)

        def on_kinship_line(pos: int) -> bool:
            ls = seg.rfind("\n", 0, pos) + 1
            le = seg.find("\n", pos)
            line = seg[ls:] if le == -1 else seg[ls:le]
            return bool(_KINSHIP_LINE_START.search(line))

        for m in EMAIL_RE.finditer(seg):
            addr = m.group().rstrip(".").lower()
            tld = addr.rsplit(".", 1)[-1]
            if tld in BAD_TLD or not tld.isalpha() or not valid_email(addr):
                continue
            taken.append(m.span())
            out.append(Ent("email", email_key(addr), addr, m.start(), m.end(), 0.9))
            emb_ph = extract_phone_from_identifier(addr)
            if emb_ph:
                out.append(Ent("phone", emb_ph, emb_ph, m.start(), m.end(), 0.85))
            else:
                emb_id = extract_id_from_identifier(addr)
                if emb_id:
                    out.append(Ent("national_id", emb_id, emb_id, m.start(), m.end(), 0.85))
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
            prof = social_profile(u)
            if prof:                     # a social-profile link: canonical profile + the handle, so the same
                out.append(Ent("url", prof[0], prof[0], m.start(), m.end(), 0.85))   # person links across sites
                if prof[1]:
                    out.append(Ent("username", prof[1], prof[1], m.start(), m.end(), 0.75))
            else:
                out.append(Ent("url", u, u, m.start(), m.end(), 0.8))
                out.append(Ent("domain", registered_domain(host), registered_domain(host), m.start(), m.end(), 0.8))
        for rx, norm in ((PHONE_IL, norm_phone_il), (PHONE_IL_SPECIAL, lambda r: re.sub(r"[^\d*]", "", r))):
            for m in rx.finditer(seg):
                if not free(*m.span()) or on_kinship_line(m.start()):
                    continue
                n = norm(m.group())
                if n and valid_phone(n):
                    taken.append(m.span())
                    out.append(Ent("phone", n, n, m.start(), m.end(), 0.9))
        for m in PHONE_INTL.finditer(seg):
            d = re.sub(r"\D", "", m.group())
            if free(*m.span()) and not on_kinship_line(m.start()) and 8 <= len(d) <= 15 and valid_phone("+" + d):
                taken.append(m.span())
                out.append(Ent("phone", "+" + d, "+" + d, m.start(), m.end(), 0.75))
        for m in DOMAIN_RE.finditer(seg):
            if not free(*m.span()):
                continue
            host = m.group().lower()
            if host.rsplit(".", 1)[-1] in TLDS and "." in host and not host[0].isdigit():
                d = registered_domain(host)
                out.append(Ent("domain", d, d, m.start(), m.end(), 0.6))
        for m in IL_ID_RE.finditer(seg):
            cand = m.group(1)
            span = m.span(1)
            if free(*span) and not on_kinship_line(span[0]) and valid_national_id(cand):
                taken.append(span)
                k = il_id_key(cand)
                out.append(Ent("national_id", k, cand, span[0], span[1], 0.9))
        for m in IL_CORP_RE.finditer(seg):
            cand = m.group(1)
            span = m.span(1)
            if free(*span) and valid_corporate_id(cand):
                taken.append(span)
                out.append(Ent("org", f"il_company:{cand}", f"ח.פ. {cand}", span[0], span[1], 0.85))
        for m in IL_PLATE_RE.finditer(seg):
            cand = m.group(1)
            span = m.span(1)
            if free(*span) and valid_license_plate(cand):
                taken.append(span)
                digits = re.sub(r"\D", "", cand)
                out.append(Ent("vehicle", digits, cand, span[0], span[1], 0.85))
        for rx in (ADDR_LABELED_RE, ADDR_INLINE_HE_RE):
            for m in rx.finditer(seg):
                span = m.span(1)
                if not free(*span):
                    continue
                disp = squash(m.group(1).strip(" .,;:-"))
                k = address_key(disp)
                if len(k) >= 4 and re.search(r"\d", disp):
                    taken.append(span)
                    out.append(Ent("address", k, disp, span[0], span[1], 0.85))
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
            line_start = seg.rfind("\n", 0, s) + 1
            line_end = seg.find("\n", s)
            full_line = seg[line_start:] if line_end == -1 else seg[line_start:line_end]
            before_on_line = seg[line_start:s]
            if _KINSHIP_LINE_PFX.search(before_on_line) or _KINSHIP_LINE_START.search(full_line):
                return None
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
        for m in self.id_adjacent_he.finditer(seg):
            cand = m.group("n1") or m.group("n2")
            if cand:
                start = m.start("n1") if m.group("n1") else m.start("n2")
                end = m.end("n1") if m.group("n1") else m.end("n2")
                mk(cand, start, end, 0.8, "id_adjacent")
        taken = [(p.start, p.end) for p in persons]
        for rx in (GAZ_HE, GAZ_EN):
            for m in rx.finditer(seg):
                s, e = m.start("f"), m.end("l")
                if any(a < e and s < b for a, b in taken):
                    continue
                name = f"{m.group('f')} {m.group('l')}"
                if m.group("f") in AMBIGUOUS_HE and self._doc_text.count(name) < 2:
                    continue          # "גל לוי" vs "גל" = wave: trust only a repeated full name
                # two known first names ("אברהם יצחק", "David Solomon") = a list of people in prose, not one person;
                # trust it only if the exact pair repeats (then it is likely a real first+surname).
                last = fold(m.group("l")) if rx is GAZ_HE else m.group("l").lower()
                if last in _FIRST_SET and self._doc_text.count(name) < 2:
                    continue
                mk(name, s, e, 0.5, "gazetteer")
        for rx, name_g, role_g in ((self.after_he, 1, 2), (self.after_en, 1, 2), (self.before_he, 2, 1), (self.before_en, 2, 1),
                                   (self.after_mixed, 1, 2), (self.who_en, 1, 2), (self.who_he, 1, 2)):
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
        norm_text = preprocess_caps_for_ner(text)
        ex = self._extract(norm_text, title)
        if self.strict:
            # phone-book pages: keep only rows about a searched subject; everyone else on it is left alone
            linked = {k for (a, b, _kind) in ex.links for k in (a, b)}
            subj_keys = {(("person" if s.kind == "person" else s.kind), s.key) for s in self.subjects}
            keep = {k for k in linked if any(k in (a, b) for (a, b, _kd) in ex.links if a in subj_keys or b in subj_keys)}
            ex.ents = {k: v for k, v in ex.ents.items() if k in subj_keys or k in keep}
            ex.links = {k: v for k, v in ex.links.items() if k[0] in subj_keys or k[1] in subj_keys}
            ex.page_type = "directory"
            return ex
        if is_reference_text(norm_text):
            # scripture / commentary: its names are biblical figures. Only a searched subject is kept.
            subj_keys = {(("person" if s.kind == "person" else s.kind), s.key) for s in self.subjects}
            ex.links = {k: v for k, v in ex.links.items() if (k[0] in subj_keys or k[1] in subj_keys) and k[2] != "co_mentioned"}
            keep = subj_keys | {k for (a, b, _kd) in ex.links for k in (a, b)}
            ex.ents = {k: v for k, v in ex.ents.items() if k in keep}
            ex.page_type = "reference"
            return ex
        kind = classify(norm_text, ex)
        if kind == "spam":
            return Extraction(page_type="spam")        # nothing from such a page is believable
        if kind == "directory":
            return Extractor(self.subjects, strict=True).extract(norm_text, title)
        prune_shared(ex)

        # DictaBERT-NER Integration (v2.0):
        # Runs statistical NER on free-text documents with threshold >= 0.85
        try:
            from .ner_engine import is_ner_available, extract_entities_ner
            if is_ner_available() and norm_text and not self.strict and len(norm_text.strip()) > 10:
                ner_ents = extract_entities_ner(norm_text, threshold=0.85)
                for n in ner_ents:
                    ntype = n["type"]
                    val = n["value"].strip()
                    if len(val) < 2:
                        continue
                    if ntype == "person":
                        key = name_key(val)
                        if not is_dummy_name(val) and ("person", key) not in ex.ents:
                            ent = Ent("person", key, val, n.get("start", 0), n.get("end", 0), n.get("confidence", 0.85), via="ner")
                            snip = norm_text[max(0, n.get("start", 0) - 40):min(len(norm_text), n.get("end", 0) + 40)].replace("\n", " ")
                            ex.add_ent(ent, snip)
                    elif ntype == "org":
                        key = org_key(val)
                        if ("org", key) not in ex.ents:
                            ent = Ent("org", key, val, n.get("start", 0), n.get("end", 0), n.get("confidence", 0.85), via="ner")
                            snip = norm_text[max(0, n.get("start", 0) - 40):min(len(norm_text), n.get("end", 0) + 40)].replace("\n", " ")
                            ex.add_ent(ent, snip)
                    elif ntype in ("address", "location"):
                        key = squash(fold(val))
                        if ("address", key) not in ex.ents:
                            ent = Ent("address", key, val, n.get("start", 0), n.get("end", 0), n.get("confidence", 0.85), via="ner")
                            snip = norm_text[max(0, n.get("start", 0) - 40):min(len(norm_text), n.get("end", 0) + 40)].replace("\n", " ")
                            ex.add_ent(ent, snip)
        except Exception:
            pass

        # Heuristics / Fallback: If contacts found but no Person entity,
        # fallback to candidate name from filename (title) or email
        has_person = any(t == "person" for (t, k) in ex.ents)
        if not has_person and not self.strict:
            has_contacts = any(t in ("phone", "email", "national_id") for (t, k) in ex.ents)
            if has_contacts:
                cand_name = extract_name_from_filename(title)
                via = "fallback_filename"
                if not cand_name:
                    for (t, k), v in ex.ents.items():
                        if t == "email":
                            email_str = v.get("display") or k
                            cand_name = extract_name_from_email(email_str)
                            if cand_name:
                                via = "fallback_email"
                                break
                if cand_name:
                    p_key = name_key(cand_name)
                    p_ent = Ent("person", p_key, cand_name, 0, len(cand_name), 0.75, surface=cand_name, via=via)
                    ex.add_ent(p_ent, cand_name)

        # Ensure single person (or primary id_adjacent/label subject in a certificate) is linked to contact entities
        people_keys = [k for (t, k) in ex.ents if t == "person"]
        primary_keys = []
        if len(people_keys) == 1 and not self.strict:
            primary_keys = [people_keys[0]]
        elif len(people_keys) > 1 and not self.strict:
            last_dp = getattr(self, "_last_doc_persons", {})
            id_labeled = [
                k for k in people_keys
                if getattr(last_dp.get(("person", k)), "via", "") in ("id_adjacent", "label")
            ]
            if len(id_labeled) >= 1:
                primary_keys = [id_labeled[0]]

        for p_key in primary_keys:
            if ("person", p_key) not in ex.ents:
                continue
            p_disp = ex.ents[("person", p_key)]["display"]
            p_ent = Ent("person", p_key, p_disp, 0, len(p_disp), 0.75)
            for (t, k), v in list(ex.ents.items()):
                if t in ("phone", "email", "national_id", "address"):
                    c_ent = Ent(t, k, v["display"], 0, 0, 0.75)
                    ka, kb = (p_ent.type, p_ent.key), (c_ent.type, c_ent.key)
                    if ka > kb:
                        ka, kb = kb, ka
                    if not any((ka, kb, kd) in ex.links for kd in ("contact", "identified_as", "address")):
                        snip = v["hits"][0][0] if v["hits"] else p_disp
                        ex.add_link(p_ent, c_ent, "address" if t == "address" else "contact", 0.7, snip)
                if t == "address":
                    for city_val in cities_in(v["display"]):
                        ex.attrs.append((("person", p_key), "יישוב", city_val, "city"))
            for bm in BIRTHDATE_RE.finditer(norm_text):
                ex.attrs.append((("person", p_key), "תאריך לידה", bm.group(1), "birthdate"))

            # Phase 4: Explicit Kinship & Relationship Extraction from free text
            try:
                from .kinship import extract_explicit_kinship_from_text
                kin_items = extract_explicit_kinship_from_text(norm_text, primary_person_name=p_disp)
                for km in kin_items:
                    rel_name = km.get("name") or km.get("relative_name") or ""
                    rel_key = km.get("key") or name_key(rel_name)
                    if not rel_key or rel_key == p_key:
                        continue
                    conf = km.get("confidence", 0.9)
                    rel_ent = Ent("person", rel_key, rel_name, 0, len(rel_name), conf, surface=rel_name, via="kinship")
                    ex.add_ent(rel_ent, km["snippet"])
                    ex.add_link(p_ent, rel_ent, f"kinship:{km['role']}", conf, km["snippet"])
                    for ph_raw in (km.get("phones") or ([km["phone"]] if km.get("phone") else [])):
                        ph_norm = norm_phone_il(ph_raw) or ph_raw
                        if ph_norm and valid_phone(ph_norm):
                            ph_ent = Ent("phone", ph_norm, ph_norm, 0, 0, 0.85)
                            ex.add_ent(ph_ent, km["snippet"])
                            ex.add_link(rel_ent, ph_ent, "contact", 0.85, km["snippet"])
                    for nid_raw in (km.get("national_ids") or ([km["national_id"]] if km.get("national_id") else [])):
                        if valid_national_id(nid_raw):
                            id_k = il_id_key(nid_raw)
                            id_ent = Ent("national_id", id_k, nid_raw, 0, 0, 0.9)
                            ex.add_ent(id_ent, km["snippet"])
                            ex.add_link(rel_ent, id_ent, "contact", 0.9, km["snippet"])
            except Exception:
                pass

        return ex

    def _extract(self, text: str, title: str = "") -> Extraction:
        ex = Extraction()
        self._doc_text = text
        title_f = fold(title)
        title_hit = {sp.id for sp in self.subjects if sp.matcher and sp.matcher.search(title_f)}
        all_blocks = ([("T:" + title)] if title else []) + list(blocks_of(text))
        doc_persons, orphan_contacts = {}, []
        self._last_doc_persons = doc_persons
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
            for e in owners:
                doc_persons.setdefault((e.type, e.key), e)
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
