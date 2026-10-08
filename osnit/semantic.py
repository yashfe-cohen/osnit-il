"""Semantic types: what a value *is* (email, phone, address, city, person name, IP, ...), judged from the value
itself, plus what a column header *says*. Used to catalogue columns of any table, including headers nobody
has seen before ("JJDBD" full of street addresses is an address column).
"""
import re
from dataclasses import dataclass

from .names import AMBIGUOUS_HE, FIRST_EN, FIRST_HE
from .quality import valid_email
from .textnorm import fold

# ---------------------------------------------------------------- the catalogue of types
@dataclass(frozen=True)
class SType:
    key: str
    label: str            # Hebrew display name
    entity: str = ""      # entity type it becomes (linkable across files); "" = stored as an attribute
    group: str = "other"  # identity | contact | location | online | time | numeric | text | meta


TYPES = {t.key: t for t in [
    SType("name", "שם מלא", "person", "identity"),
    SType("first", "שם פרטי", "", "identity"),
    SType("last", "שם משפחה", "", "identity"),
    SType("org", "ארגון / חברה", "org", "identity"),
    SType("role", "תפקיד", "role", "identity"),
    SType("email", "מייל", "email", "contact"),
    SType("phone", "טלפון", "phone", "contact"),
    SType("address", "כתובת", "address", "location"),
    SType("street", "רחוב", "", "location"),
    SType("house", "מספר בית", "", "location"),
    SType("city", "עיר / יישוב", "", "location"),
    SType("zip", "מיקוד", "", "location"),
    SType("country", "מדינה", "", "location"),
    SType("coords", "קואורדינטות", "", "location"),
    SType("url", "קישור מקור", "", "online"),
    SType("profile", "פרופיל ברשת", "url", "online"),
    SType("website", "אתר / דומיין", "domain", "online"),
    SType("username", "שם משתמש", "username", "online"),
    SType("ip", "כתובת IP", "", "online"),
    SType("seen", "תאריך גילוי", "", "time"),
    SType("date", "תאריך", "", "time"),
    SType("birthdate", "תאריך לידה", "", "time"),
    SType("gender", "מגדר", "", "identity"),
    SType("age", "גיל", "", "numeric"),
    SType("money", "סכום", "", "numeric"),
    SType("number", "מספר", "", "numeric"),
    SType("bool", "כן / לא", "", "numeric"),
    SType("code", "קוד / מזהה", "", "text"),
    SType("national_id", "ת\"ז / מספר זהות", "national_id", "identity"),
    SType("password", "סיסמה", "", "security"),
    SType("hash", "גיבוב סיסמה", "", "security"),
    SType("card", "כרטיס אשראי", "card", "security"),
    SType("secret", "טוקן / סוד", "", "security"),
    SType("text", "טקסט", "", "text"),
    SType("doc", "תוכן מסמך (חילוץ מלא)", "", "text"),
    SType("unknown", "לא מזוהה", "", "text"),
]}
# Nothing is dropped automatically: the operator imports their own records knowingly. This set stays empty so
# no code path discards a column; SECURITY_KINDS only groups credential-type values for a visible label.
SENSITIVE_KINDS = set()
SECURITY_KINDS = {"hash", "card", "il_id", "secret"}
LINKABLE = {k for k, t in TYPES.items() if t.entity in ("email", "phone", "address", "username", "url", "domain")}

# ---------------------------------------------------------------- header vocabulary
# exact synonyms (folded, spaces -> _). Old mapping-file field names stay valid.
HEADER_EXACT = {
    "name": "name full_name fullname person contact_name display_name שם שם_מלא fn".split(),
    "first": "first_name firstname given_name fname forename שם_פרטי".split(),
    "last": "last_name lastname surname family_name lname שם_משפחה".split(),
    "email": "email e_mail mail email_address emailaddress מייל אימייל דואל דוא\"ל דואר_אלקטרוני".split(),
    "phone": "phone telephone tel mobile cell phone_number phonenumber mobile_phone טלפון נייד פלאפון מספר_טלפון סלולרי".split(),
    "org": "org organization organisation company company_name employer workplace חברה ארגון מקום_עבודה שם_חברה".split(),
    "role": "role title job_title position jobtitle תפקיד".split(),
    "url": "url source source_url link page href מקור קישור".split(),
    "website": "domain website site web אתר דומיין אתר_אינטרנט".split(),
    "seen": "seen found_at first_seen date created created_at timestamp collected_at תאריך".split(),
    "doc": "text content body html page_text raw_text תוכן טקסט".split(),
    "address": "address addr street_address full_address home_address כתובת כתובת_מגורים מען".split(),
    "street": "street street_name רחוב".split(),
    "house": "house house_number house_no building מספר_בית בית".split(),
    "city": "city town locality settlement עיר יישוב ישוב".split(),
    "zip": "zip zipcode zip_code postal postal_code postcode מיקוד".split(),
    "country": "country nation מדינה ארץ".split(),
    "username": "username user_name login nickname nick handle screen_name שם_משתמש כינוי".split(),
    "ip": "ip ip_address ipaddress last_ip registration_ip כתובת_ip".split(),
    "birthdate": "birthdate birth_date dob date_of_birth birthday תאריך_לידה יום_הולדת".split(),
    "gender": "gender sex מגדר מין".split(),
    "age": "age גיל".split(),
    "profile": "linkedin facebook instagram twitter tiktok telegram github profile profile_url לינקדאין פייסבוק".split(),
}
EXACT = {fold(s).replace(" ", "_"): k for k, syns in HEADER_EXACT.items() for s in syns}

# header fragments, checked in order ("company_name" is an org, "username" is not a person's name)
HEADER_FUZZY = [(k, re.compile(rx)) for k, rx in [
    ("sensitive", r"pass(word|wd)?|pwd|hash|salt|secret|token|api_?key|otp|pin_?code|cvv|cvc|credit|card_?num|iban"
                  r"|ssn|passport|national_?id|id_?number|id_?no$|teudat|סיסמ|אשראי|כרטיס|ת_?ז|תעודת_?זהות|מספר_?זהות|דרכון"),
    ("username", r"user_?name|login|nick|handle|screen_?name|שם_?משתמש|כינוי"),
    ("internal", r"^(id|_id|rowid|row_id|uuid|guid|pk|oid|idx|index|version|rev|updated(_at)?|modified(_at)?|"
                 r"deleted(_at)?|is_deleted|sort|ordering|begin|end)$|_id$|^id_"),
    ("birthdate", r"birth|dob|לידה"),
    ("email", r"e?_?mail|מייל|דוא\"?ל|דואל|אימייל"),
    ("phone", r"phone|tel|mobile|cell|whats_?app|fax|נייד|טלפון|פלאפון|סלולר|פקס"),
    ("profile", r"linkedin|facebook|instagram|twitter|tiktok|telegram|github|youtube|לינקדאין|פייסבוק|אינסטגרם"),
    ("org", r"company|organi[sz]ation|employer|workplace|firm|business|^org|חברה|ארגון|מעסיק|מקום_?עבודה"),
    ("first", r"first|given|פרטי"),
    ("last", r"last_?name|surname|family|משפחה"),
    ("role", r"job|title|role|position|occupation|תפקיד|משרה|עיסוק"),
    ("zip", r"zip|postal|post_?code|מיקוד"),
    ("street", r"street|רחוב"),
    ("city", r"city|town|עיר|יישוב|ישוב"),
    ("country", r"country|מדינה"),
    ("address", r"addr|כתובת|מען|location|מיקום"),
    ("ip", r"(^|_)ip($|_)|ip_?addr"),
    ("website", r"website|domain|^site|אתר|דומיין"),
    ("url", r"^(url|link|href|source_?url|page_?url)$|קישור"),
    ("seen", r"collected|scraped|found|נאסף|נמצא"),
    ("date", r"date|time|_at$|_on$|תאריך|מועד"),
    ("gender", r"gender|^sex$|מגדר"),
    ("age", r"^age$|גיל"),
    ("money", r"price|amount|salary|cost|total|sum|balance|מחיר|סכום|שכר|יתרה"),
    ("name", r"name|^שם|contact|person|customer|client|לקוח|איש_?קשר|owner|בעלים"),
]]

# readable Hebrew names for common unknown headers (the column is still stored under its original header)
HEADER_WORDS = {
    "note": "הערה", "notes": "הערות", "comment": "הערה", "comments": "הערות", "remark": "הערה", "description": "תיאור",
    "desc": "תיאור", "status": "סטטוס", "state": "מצב", "type": "סוג", "category": "קטגוריה", "group": "קבוצה",
    "department": "מחלקה", "dept": "מחלקה", "division": "חטיבה", "team": "צוות", "branch": "סניף", "region": "אזור",
    "area": "אזור", "district": "מחוז", "neighborhood": "שכונה", "school": "מוסד לימודים", "education": "השכלה",
    "degree": "תואר", "university": "אוניברסיטה", "language": "שפה", "languages": "שפות", "skills": "כישורים",
    "interests": "תחומי עניין", "hobby": "תחביב", "bio": "ביוגרפיה", "about": "אודות", "summary": "תקציר",
    "source": "מקור", "tags": "תגיות", "tag": "תגית", "level": "רמה", "rank": "דרגה", "score": "ציון", "rating": "דירוג",
    "salary": "שכר", "income": "הכנסה", "price": "מחיר", "amount": "סכום", "vehicle": "רכב", "car": "רכב",
    "plate": "מספר רכב", "license": "רישיון", "nationality": "אזרחות", "religion": "דת", "marital": "מצב משפחתי",
    "spouse": "בן/בת זוג", "children": "ילדים", "father": "אב", "mother": "אם", "fax": "פקס", "extension": "שלוחה",
    "ext": "שלוחה", "floor": "קומה", "apartment": "דירה", "apt": "דירה", "room": "חדר", "start": "התחלה",
    "end": "סיום", "joined": "הצטרפות", "registered": "הרשמה", "last_login": "כניסה אחרונה", "lastlogin": "כניסה אחרונה",
    "website": "אתר", "company": "חברה", "position": "תפקיד", "industry": "תעשייה", "sector": "מגזר", "size": "גודל",
    "employees": "עובדים", "revenue": "הכנסות", "founded": "שנת הקמה", "manager": "מנהל", "supervisor": "ממונה",
    "unit": "יחידה", "course": "קורס", "class": "כיתה", "year": "שנה", "month": "חודש", "id_card": "תעודה",
}

# ---------------------------------------------------------------- gazetteers
CITIES_HE = """ירושלים תל אביב תל אביב-יפו תל-אביב יפו חיפה ראשון לציון פתח תקווה פתח תקוה אשדוד נתניה באר שבע בני ברק חולון
רמת גן אשקלון רחובות בת ים בית שמש כפר סבא הרצליה חדרה מודיעין מודיעין-מכבים-רעות נצרת לוד רמלה רעננה רהט הוד השרון
גבעתיים קריית אתא קרית אתא נהריה קריית גת קרית גת עפולה יבנה אילת אום אל-פחם ראש העין עכו אלעד כרמיאל טבריה נס ציונה
קריית מוצקין קרית מוצקין קריית ביאליק קרית ביאליק קריית ים קרית ים קריית אונו קרית אונו קריית שמונה קרית שמונה
אור יהודה צפת דימונה טירת כרמל נתיבות אופקים שדרות מעלות-תרשיחא מעלות יקנעם יהוד גבעת שמואל מגדל העמק
בית שאן ערד אריאל מעלה אדומים ביתר עילית זכרון יעקב קדימה צורן כפר יונה גדרה גן יבנה באר יעקב אור עקיבא
פרדס חנה כרכור קיסריה רמת השרון שוהם כוכב יאיר צור יגאל טייבה טמרה סח'נין שפרעם באקה אל-גרביה קלנסווה
ירוחם מצפה רמון קצרין עתלית חריש מבשרת ציון אפרת קריית ארבע קרית ארבע אלפי מנשה גבעת זאב קריית טבעון קרית טבעון
נשר רמת ישי כפר קאסם מגאר עראבה דאלית אל-כרמל עספיא ראש פינה מטולה""".split("\n")
CITIES_EN = """Jerusalem|Tel Aviv|Tel Aviv-Yafo|Tel-Aviv|Jaffa|Haifa|Rishon LeZion|Rishon Lezion|Petah Tikva|Petach Tikva|Ashdod|
Netanya|Beersheba|Beer Sheva|Be'er Sheva|Bnei Brak|Holon|Ramat Gan|Ashkelon|Rehovot|Bat Yam|Beit Shemesh|Kfar Saba|
Herzliya|Hadera|Modiin|Modi'in|Nazareth|Lod|Ramla|Raanana|Ra'anana|Rahat|Hod Hasharon|Givatayim|Kiryat Ata|Nahariya|
Kiryat Gat|Afula|Yavne|Eilat|Rosh HaAyin|Rosh Haayin|Acre|Akko|Elad|Karmiel|Tiberias|Ness Ziona|Nes Ziona|Kiryat Motzkin|
Kiryat Bialik|Kiryat Yam|Kiryat Ono|Kiryat Shmona|Or Yehuda|Safed|Tzfat|Dimona|Sderot|Netivot|Ofakim|Yokneam|Yehud|
Caesarea|Ramat Hasharon|Shoham|Zichron Yaakov|Arad|Ariel|Maale Adumim|Ma'ale Adumim|Nesher|Mevaseret Zion|
New York|London|Paris|Berlin|Los Angeles|San Francisco|Chicago|Boston|Toronto|Moscow|Kyiv|Kiev|Madrid|Rome|
Amsterdam|Dubai|Istanbul|Athens|Vienna|Prague|Warsaw|Budapest|Miami|Washington|Seattle|Sydney|Singapore""".replace("\n", "").split("|")
CITY_KEYS = {fold(c.strip()).replace("-", " ") for line in CITIES_HE for c in [line] if c.strip()}
CITY_KEYS |= {fold(c.strip()).replace("-", " ") for c in CITIES_EN if c.strip()}
# the Hebrew list is space-separated with multi-word names; index every 1-3 word window that is a known city
_HE_CITY_TEXT = " " + " ".join(CITIES_HE) + " "
COUNTRIES = {fold(c) for c in """ישראל ארצות הברית ארה"ב בריטניה צרפת גרמניה רוסיה אוקראינה קנדה ספרד איטליה הולנד
Israel USA United States US UK United Kingdom England France Germany Russia Ukraine Canada Spain Italy Netherlands
Poland Romania Brazil Argentina Mexico India China Japan Australia Turkey Greece Cyprus Egypt Jordan""".replace("\n", " ").split(" ") if c}
_FIRST = {fold(n) for n in FIRST_HE} | {n.lower() for n in FIRST_EN}
_ORG_MARK = re.compile(r"(בע\"?מ|\bltd\b|\binc\b|\bllc\b|\bcorp\b|\bgmbh\b|\bplc\b|עמותת|עמותה|חברת|\bgroup\b|"
                       r"קבוצת|אוניברסיט|university|college|מכללת|משרד ה|ministry|בנק |bank\b|עיריית|municipality)", re.I)

# ---------------------------------------------------------------- value detectors
_HASH = re.compile(r"^(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{56}|[a-f0-9]{64}|[a-f0-9]{96}|[a-f0-9]{128}"
                   r"|\$2[aby]?\$\d\d\$.{53}|\$argon2.+|\$[156]\$.+|pbkdf2.+|sha\d*\$.+)$", re.I)
_PHONE = re.compile(r"^\+?[\d\s\-().]{7,20}$")
_URL = re.compile(r"^(https?://|www\.)\S+$", re.I)
_DOMAIN = re.compile(r"^(?:[a-z0-9-]+\.)+[a-z]{2,}$", re.I)
_DATE = re.compile(r"^(?:\d{4}[-/.]\d{1,2}[-/.]\d{1,2}|\d{1,2}[-/.]\d{1,2}[-/.]\d{2,4})(?:[ T]\d{1,2}:\d{2}(?::\d{2})?.*)?$")
_NUM = re.compile(r"^-?\d+(?:[.,]\d+)?$")
_MONEY = re.compile(r"^(?:[₪$€£]\s?-?[\d,]+(?:\.\d+)?|-?[\d,]+(?:\.\d+)?\s?(?:₪|\$|€|£|ש\"?ח|nis|ils|usd|eur))$", re.I)
_IP = re.compile(r"^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$|^[0-9a-f]{1,4}(?::[0-9a-f]{0,4}){2,7}$", re.I)
_COORDS = re.compile(r"^-?\d{1,3}\.\d{3,}\s*[,; ]\s*-?\d{1,3}\.\d{3,}$")
_CODE = re.compile(r"^(?=.*\d)(?=.*[A-Za-zא-ת])[A-Za-zא-ת0-9]{1,6}(?:[-/_.][A-Za-zא-ת0-9]{1,10}){0,3}$")
_USERNAME = re.compile(r"^@?(?=.*[a-z])[a-z0-9_.]{3,30}$", re.I)
_SOCIAL = re.compile(r"^(?:https?://)?(?:www\.|[a-z]{2}\.|m\.)?(linkedin\.com/(?:in|company)/|facebook\.com/|fb\.com/|"
                     r"instagram\.com/|twitter\.com/|x\.com/|t\.me/|github\.com/|tiktok\.com/@|youtube\.com/(?:@|c/|channel/))"
                     r"[^/?#\s]+", re.I)
_ADDR_HE = re.compile(r"^(?P<pre>(?:רח(?:וב|')?|שד(?:רות|')?|דרך|סמטת|כיכר|ככר|שכונת|מושב|קיבוץ)\s+)?"
                      r"(?P<st>[א-ת\"'\- ]{2,30}?)\s+(?P<no>\d{1,4}[א-ת]?(?:\s*[/\-]\s*\d{1,4})?)"
                      r"(?:\s*(?:דירה|ד')\s*\d{1,4})?(?:(?:\s*[,\-]\s*|\s+)(?P<city>[א-ת\"'\- ]{2,30}?))?(?:\s*,?\s*\d{5,7})?$")
_ADDR_HE_POBOX = re.compile(r"^(?:ת\.?ד\.?|תא דואר)\s*\d{1,6}")
_ADDR_EN = re.compile(r"^(?:\d{1,5}\s+[A-Za-z0-9 .'\-]{2,40}?\s(?:st|street|ave|avenue|rd|road|blvd|boulevard|lane|ln|dr|drive|"
                      r"way|ct|court|pl|place|sq|square|hwy|highway)\.?\b.*|[A-Za-z .'\-]{2,40}?\s(?:st|street|ave|avenue|rd|road|blvd|"
                      r"boulevard)\.?\s+\d{1,5}\b.*|p\.?o\.?\s*box\s*\d+.*)$", re.I)
_GENDER = {"זכר", "נקבה", "ז", "נ", "male", "female", "m", "f", "man", "woman", "גבר", "אישה", "אשה"}
_BOOL = {"true", "false", "yes", "no", "כן", "לא", "y", "n", "t", "0", "1"}
_ALPHA_TOKS = re.compile(r"^[A-Za-zא-ת][A-Za-zא-ת'\-\"]*(?:\s+[A-Za-zא-ת][A-Za-zא-ת'\-\"]*){0,3}$")


_NULLS = {"", "null", "none", "nil", "nan", "n/a", "na", "-", "--", "?", "undefined", "0000-00-00", "0000-00-00 00:00:00",
          "[]", "{}"}


def blank_value(v) -> bool:
    return v is None or str(v).strip().lower() in _NULLS


def _luhn(d: str) -> bool:
    s, alt = 0, False
    for ch in reversed(d):
        x = int(ch)
        if alt:
            x = x * 2 - 9 if x > 4 else x * 2
        s, alt = s + x, not alt
    return s % 10 == 0


def il_id_ok(d: str) -> bool:
    """Israeli ID number check digit (9 digits, zero-padded)."""
    if len(d) != 9 or not d.isdigit():
        return False
    return sum(sum(divmod(int(c) * (1 + i % 2), 10)) for i, c in enumerate(d)) % 10 == 0


def is_city(s: str) -> bool:
    k = fold(s).replace("-", " ").strip()
    return k in CITY_KEYS or f" {s.strip()} " in _HE_CITY_TEXT and len(s.strip()) >= 3


def _he_address(s: str) -> bool:
    """Street + number, with a street word before it or a known city after it ("הרצל 5, תל אביב")."""
    m = _ADDR_HE.match(s)
    if not m:
        return False
    if m.group("pre"):
        return True
    city = (m.group("city") or "").strip(" ,-")
    return bool(city) and is_city(city)


def has_city(addr: str) -> bool:
    """An address that already ends with a town ('הרצל 5, תל אביב', 'Herzl St 5, Tel Aviv')."""
    toks = re.split(r"[\s,]+", addr.strip(" ,"))
    return any(is_city(" ".join(toks[-n:])) for n in (1, 2, 3) if len(toks) > n)


def name_like(s: str):
    """'name' when the value looks like a person's full name, 'first' for a lone known first name, else None."""
    if not _ALPHA_TOKS.match(s) or len(s) > 60 or _ORG_MARK.search(s) or is_city(s):
        return None
    toks = s.split()
    known = [t for t in toks if fold(t) in _FIRST or t.lower() in _FIRST]
    if len(toks) == 1:
        return "first" if known and fold(toks[0]) not in {fold(a) for a in AMBIGUOUS_HE} else None
    if not 2 <= len(toks) <= 4:
        return None
    latin = all(re.match(r"[A-Za-z]", t) for t in toks)
    if latin and not all(t[0].isupper() for t in toks):
        return None
    return "name" if known else "name?"      # 'name?' = shaped like a name, no dictionary support


def value_kind(v) -> str:
    """The most specific thing one cell value looks like."""
    if isinstance(v, bool):
        return "bool"
    if isinstance(v, (int, float)):
        s = str(int(v)) if isinstance(v, float) and v.is_integer() else str(v)
        if isinstance(v, int) and len(s) == 9 and il_id_ok(s):
            return "il_id"
        return "number"
    s = str(v).strip()
    if not s:
        return "empty"
    low = s.lower()
    if "@" in s and " " not in s and re.match(r"^[^@\s]+@[^@\s]+\.[a-z]{2,}$", low):
        return "email" if valid_email(low) else "email?"
    if _HASH.match(s):
        return "hash"
    digits = re.sub(r"\D", "", s)
    if re.fullmatch(r"[\d \-]{13,23}", s) and 13 <= len(digits) <= 19 and _luhn(digits) and not s.startswith("0"):
        return "card"
    if re.fullmatch(r"\d{8,9}", s) and il_id_ok(s.zfill(9)) and not s.startswith(("05", "07")) and len(s) == 9:
        return "il_id"
    if _SOCIAL.match(s):
        return "profile"
    if _URL.match(s):
        return "url"
    if _IP.match(s):
        return "ip"
    if _COORDS.match(s):
        return "coords"
    if _DATE.match(s):
        return "date"
    if _MONEY.match(s):
        return "money"
    if _PHONE.match(s) and 9 <= len(digits) <= 13 and (s.startswith(("0", "+", "(0")) or digits.startswith("972")):
        return "phone"
    if low in _GENDER and len(low) > 1:
        return "gender"
    if low in _BOOL and len(low) > 1:
        return "bool"
    if _NUM.match(s.replace(",", "")):
        return "number"
    if _DOMAIN.match(s) and len(s) < 80:
        return "domain"
    if _ADDR_HE_POBOX.match(s) or _ADDR_EN.match(s) or _he_address(s):
        return "address"
    if is_city(s):
        return "city"
    if fold(s) in COUNTRIES:
        return "country"
    nl = name_like(s)
    if nl:
        return nl
    if _ORG_MARK.search(s) and len(s) < 120:
        return "org"
    if _USERNAME.match(s) and (s.startswith("@") or re.search(r"[\d_.]", s)) and not re.fullmatch(r"[\d.]+", s):
        return "username"
    if _CODE.match(s) and len(s) <= 24:
        return "code"
    return "longtext" if len(s) > 200 else "text"


# which column types a value kind supports (first = the type it proves on its own)
KIND_TO_TYPES = {
    "email": ["email"], "email?": ["email"], "phone": ["phone"], "profile": ["profile", "url"], "url": ["url", "profile", "website"],
    "domain": ["website"], "ip": ["ip"], "coords": ["coords"], "date": ["date", "seen", "birthdate"], "money": ["money"],
    "gender": ["gender"], "bool": ["bool"], "number": ["number", "age", "zip", "house", "money", "phone"],
    "address": ["address", "street"], "city": ["city", "address"], "country": ["country"], "name": ["name", "last"],
    "name?": ["name", "org", "role", "last", "street", "text", "city"], "first": ["first", "name", "last"],
    "org": ["org"], "username": ["username"], "code": ["code", "username", "zip", "house"],
    "il_id": ["national_id"], "hash": ["hash"], "card": ["card"], "secret": ["secret"],
    "text": ["text", "role", "org", "name", "last", "street", "unknown", "doc"], "longtext": ["text", "doc"],
}
# value kinds strong enough to name a column by content alone (with this share of the sampled values)
DECISIVE = {"email": .6, "phone": .6, "profile": .6, "url": .7, "ip": .7, "coords": .7, "date": .7, "money": .7,
            "address": .5, "city": .6, "country": .7, "name": .5, "first": .6, "gender": .8, "username": .7,
            "domain": .7, "org": .6, "il_id": .6, "hash": .8, "card": .7}


def header_key(h) -> str:
    return re.sub(r"[\s\-./]+", "_", fold(str(h)).strip()).strip("_")


def header_type(h):
    """(type, how) from the header alone: exact synonym, else a fragment rule. how: exact|fuzzy|''"""
    k = header_key(h)
    if k in EXACT:
        return EXACT[k], "exact"
    for t, rx in HEADER_FUZZY:
        if rx.search(k):
            return t, "fuzzy"
    return None, ""


def header_label(h) -> str:
    """A readable Hebrew name for an unknown header when one of its words is familiar."""
    k = header_key(h)
    if k in HEADER_WORDS:
        return HEADER_WORDS[k]
    parts = [HEADER_WORDS.get(p) for p in re.split(r"_+", k) if p]
    parts = [p for p in parts if p]
    return " ".join(dict.fromkeys(parts)) if parts else ""


# ---------------------------------------------------------------- normalisation of linkable values
_STREET_WORDS = re.compile(r"\b(?:רחוב|רח'|רח|שדרות|שד'|street|st|ave|avenue|road|rd|blvd)\b\.?", re.I)


def address_key(s: str) -> str:
    """'רח' הרצל 5, תל-אביב יפו' and 'הרצל 5 תל אביב' share a key."""
    k = fold(s).replace("-", " ").replace("יפו", "")
    k = _STREET_WORDS.sub(" ", k)
    k = re.sub(r"[^\w\s]", " ", k)
    return " ".join(k.split())


def username_key(s: str) -> str:
    return s.strip().lstrip("@").lower()


def profile_url(s: str) -> str:
    """Canonical form of a social profile link: https://<site>/<path> without query, 'www.' or trailing slash."""
    s = s.strip()
    s = re.sub(r"^https?://", "", s, flags=re.I)
    s = re.sub(r"^(?:www\.|m\.|[a-z]{2}\.)(?=[a-z0-9-]+\.[a-z]+/)", "", s, flags=re.I)
    s = re.split(r"[?#]", s, maxsplit=1)[0].rstrip("/")
    host, _, path = s.partition("/")
    return f"https://{host.lower()}/{path}" if path else f"https://{host.lower()}"


# ---------------------------------------------------------------- user-defined information types
def pattern_from_examples(examples) -> str:
    """'AB-12345', 'XY-9981' -> '[A-Z]{2}-\\d{4,5}': a regex that describes how the examples look."""
    def shape(ex):
        out = []
        for ch in ex.strip():
            cls = (r"\d" if ch.isdigit() else "[A-Z]" if "A" <= ch <= "Z" else "[a-z]" if "a" <= ch <= "z"
                   else "[א-ת]" if "א" <= ch <= "ת" else r"\s" if ch.isspace() else re.escape(ch))
            if out and out[-1][0] == cls:
                out[-1][1] += 1
            else:
                out.append([cls, 1])
        return out
    shapes = [shape(e) for e in examples if str(e).strip()]
    if not shapes:
        return ""
    groups = {}
    for sh in shapes:                       # same token classes in the same order -> merge run lengths
        groups.setdefault(tuple(c for c, _ in sh), []).append([n for _, n in sh])
    alts = []
    for classes, lens in groups.items():
        parts = []
        for i, c in enumerate(classes):
            lo, hi = min(l[i] for l in lens), max(l[i] for l in lens)
            q = "" if lo == hi == 1 else f"{{{lo}}}" if lo == hi else f"{{{lo},{hi}}}"
            parts.append(c + q)
        alts.append("".join(parts))
    return alts[0] if len(alts) == 1 else "(?:" + "|".join(alts) + ")"


@dataclass
class CustomType:
    key: str                       # e.g. "u_employee_id"
    label: str                     # what the user called it
    headers: tuple = ()            # header names it appears under
    pattern: str = ""              # regex for one value (full match)
    identifier: bool = True        # links records across files (becomes an entity)
    sensitive: bool = False        # recognised but never stored

    def __post_init__(self):
        try:
            self._rx = re.compile(self.pattern, re.I) if self.pattern else None
        except re.error:
            self._rx = None

    def matches(self, v) -> bool:
        return bool(self._rx and self._rx.fullmatch(str(v).strip()))

    @property
    def stype(self):
        return SType(self.key, self.label, self.key if self.identifier and not self.sensitive else "", "custom")


def custom_key(label: str) -> str:
    k = re.sub(r"[^\w]+", "_", fold(label)).strip("_")[:40] or "type"
    return "u_" + k


class Registry:
    """Built-in types plus the user's own. One per planning run; cheap to build."""
    def __init__(self, custom=()):
        self.custom = list(custom)
        self.types = dict(TYPES)
        self.exact = dict(EXACT)
        for c in self.custom:
            self.types[c.key] = c.stype
            for h in c.headers:
                self.exact[header_key(h)] = c.key

    def kind(self, v) -> str:
        if not isinstance(v, (bool,)) and str(v).strip():
            for c in self.custom:
                if c.matches(v):
                    return c.key
        return value_kind(v)

    def kind_types(self, kind):
        if kind in self.types and kind.startswith("u_"):
            return [kind]
        return KIND_TO_TYPES.get(kind, [])

    def decisive(self, kind):
        return 0.6 if kind.startswith("u_") else DECISIVE.get(kind)

    def header_type(self, h):
        k = header_key(h)
        if k in self.exact:
            return self.exact[k], "exact"
        return header_type(h)

    def sensitive(self, key) -> bool:
        return any(c.key == key and c.sensitive for c in self.custom)

    def label(self, key) -> str:
        t = self.types.get(key)
        return t.label if t else key

    def entity(self, key) -> str:
        t = self.types.get(key)
        return t.entity if t else ""

    def group(self, key) -> str:
        t = self.types.get(key)
        return t.group if t else ""
