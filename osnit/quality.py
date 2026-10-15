"""Plausibility gate: what is a believable contact, and what kind of page are we looking at."""
import re

ROLE_MAILBOX = {"info", "office", "support", "sales", "contact", "admin", "hello", "noreply", "no-reply", "mail",
                "webmaster", "service", "team", "hr", "marketing", "billing", "postmaster", "press", "jobs", "careers",
                "enquiries", "inquiries", "help", "general", "reception", "secretary"}
PLACEHOLDER_DOMAINS = {"example.com", "example.org", "example.net", "test.com", "domain.com", "email.com",
                       "yourdomain.com", "yourcompany.com", "company.com", "site.com", "website.com", "mydomain.com",
                       "sharklasers.com", "guerrillamail.com", "guerrillamailblock.com", "grr.la", "pokemail.net",
                       "spam4.me", "mailinator.com", "yopmail.com", "tempmail.com", "10minutemail.com", "trashmail.com"}
PLACEHOLDER_LOCALS = {"name", "your", "yourname", "user", "username", "email", "example", "test", "someone", "firstname",
                      "lastname", "first.last", "john.doe", "you", "demo", "asdf", "xcv"}


DUMMY_VALUES = {
    "", "null", "none", "nil", "nan", "n/a", "na", "אין", "0", "000000000", "123456789", "123456",
    "test", "test@test.com", "admin", "unknown", "user", "0500000000", "-", "--", "undefined",
    "כלום", "ללא", "לא ידוע", "לא צוין", "blank", "dummy", "xxx", "yyy", "zzz",
    "0000-00-00", "0000-00-00 00:00:00", "1900-01-01", "0001-01-01", "1970-01-01", "00/00/0000",
    "system", "signature engine", "demo", "asdf", "xcv", "jola", "strata", "פרטי משפחה",
}

_DUMMY_NAMES = {
    "admin", "administrator", "user", "username", "test", "tester", "testing", "guest",
    "customer", "client", "לקוח", "אורח", "משתמש", "מנהל", "אנונימי", "anonymous",
    "john doe", "jane doe", "israel israeli", "ישראל ישראלי", "פלוני אלמוני",
    "system", "signature engine", "signature", "engine", "demo", "פרטי משפחה",
    "שם פרטי", "שם משפחה", "שם פרטי שם משפחה", "פרטי", "משפחה",
    "asdf", "asdfg", "asdfgh", "xcv", "zxcv", "jola", "strata", "qwer", "qwerty",
    "בדיקה", "דמו", "זמני", "משתמש זמני", "משתמש בדיקה",
}

_STRICT_JUNK_NAME_TOKENS = {
    "system", "demo", "asdf", "asdfg", "asdfgh", "xcv", "zxcv", "jola", "strata",
    "test", "tester", "testing", "dummy", "admin", "administrator", "qwer", "qwerty",
    "sharklasers",
}

_DUMMY_NAME_WORDS = _STRICT_JUNK_NAME_TOKENS | {
    "signature", "engine", "user", "username", "guest", "customer", "client",
    "פרטי", "משפחה", "משתמש", "בדיקה", "דמו", "זמני", "אנונימי", "לקוח", "אורח",
}


def is_empty_date(v) -> bool:
    if v is None:
        return True
    s = str(v).strip()
    return not s or s.startswith(("0000-00-00", "1900-01-01", "0001-01-01", "00/00/0000")) or s in ("0", "-", "null", "None")


def is_dummy_value(v) -> bool:
    if v is None:
        return True
    s = str(v).strip().lower()
    if s in DUMMY_VALUES or is_empty_date(s):
        return True
    if len(s) >= 3 and len(set(s)) == 1:
        return True
    if not re.search(r"[a-zA-Z0-9א-ת\u0400-\u04ff]", s):
        return True
    return False


def is_dummy_name(name: str) -> bool:
    if is_dummy_value(name):
        return True
    s = re.sub(r"\s+", " ", str(name).strip()).lower()
    if s in _DUMMY_NAMES:
        return True
    # Must contain at least 2 letters and no digits or code/junk symbols
    if len(re.findall(r"[a-zA-Zא-ת\u0400-\u04ff]", s)) < 2:
        return True
    if re.search(r"[\d@#$%^&*+=<>~`|\\]", s):
        return True
    toks = [t for t in re.split(r"[\s\-_'\".,/()]+", s) if t]
    if not toks:
        return True
    if any(t in _STRICT_JUNK_NAME_TOKENS for t in toks):
        return True
    if all(t in _DUMMY_NAME_WORDS for t in toks):
        return True
    if all(len(set(t)) == 1 and len(t) >= 2 for t in toks):
        return True
    return False


def is_dummy_email(addr: str) -> bool:
    if is_dummy_value(addr):
        return True
    local, _, domain = addr.lower().strip().partition("@")
    if domain in PLACEHOLDER_DOMAINS:
        return True
    if local in PLACEHOLDER_LOCALS:
        return True
    if re.fullmatch(r"(\w)\1+", local):
        return True
    return False


def valid_email(addr: str) -> bool:
    if is_dummy_email(addr):
        return False
    local, _, domain = addr.partition("@")
    return "." in domain and len(local) >= 2 and len(domain) >= 3


def is_dummy_phone(key: str) -> bool:
    d = re.sub(r"\D", "", str(key or ""))
    if not d:
        return True
    if len(d) < 7 or len(d) > 15:
        return True
    if re.search(r"(\d)\1{5,}", d):
        return True
    if len(d) >= 7 and len(set(d[-7:])) <= 1:
        return True
    tail = d[-7:]
    if tail in ("1234567", "7654321", "0123456", "9876543", "2345678", "3456789"):
        return True
    if d in ("123456", "1234567", "12345678", "123456789", "0500000000", "0520000000", "0540000000", "0530000000", "0550000000"):
        return True
    return False


def valid_phone(key: str) -> bool:
    s = str(key or "").strip()
    d = re.sub(r"\D", "", s)
    if s.startswith("*") and 3 <= len(d) <= 6:
        return True
    if d.startswith(("1700", "1800", "1599", "1801")) and 8 <= len(d) <= 10 and not re.search(r"(\d)\1{5,}", d):
        return True
    if is_dummy_phone(s):
        return False
    tail = d[-7:]
    if len(set(tail)) <= 2 or tail in ("1234567", "7654321", "0123456", "9876543", "2345678"):
        return False
    return 8 <= len(d) <= 15


def il_id_ok(d: str) -> bool:
    if len(d) != 9 or not d.isdigit():
        return False
    return sum(sum(divmod(int(c) * (1 + i % 2), 10)) for i, c in enumerate(d)) % 10 == 0


def valid_national_id(val: str, autoincrement_seq: bool = False) -> bool:
    """Strict Luhn + sequential/autoincrement guard for Israeli national IDs (7-9 digits, zero-padded to 9)."""
    if autoincrement_seq:
        return False
    if is_dummy_value(val):
        return False
    d = re.sub(r"\D", "", str(val))
    if not (7 <= len(d) <= 9):
        return False
    d9 = d.zfill(9)
    if len(set(d9)) <= 1 or d9 in ("000000000", "123456789", "987654321"):
        return False
    return il_id_ok(d9)


def valid_corporate_id(val: str) -> bool:
    """Israeli corporate ID (ח.פ. / ע.מ. / עמותה): 9 digits starting with 51, 52, 55, 57, 58 + Luhn."""
    if is_dummy_value(val):
        return False
    d = re.sub(r"\D", "", str(val))
    if len(d) != 9:
        return False
    if not d.startswith(("51", "52", "55", "57", "58")):
        return False
    return il_id_ok(d)


def valid_license_plate(val: str) -> bool:
    """Israeli vehicle license plate (7 digits: XX-XXX-XX or 8 digits: XXX-XX-XXX)."""
    if is_dummy_value(val):
        return False
    d = re.sub(r"\D", "", str(val))
    if len(d) not in (7, 8):
        return False
    if len(set(d)) <= 1 or d in ("1234567", "12345678", "0000000", "00000000"):
        return False
    return True


def is_role_mailbox(addr: str) -> bool:
    return addr.split("@")[0].lower() in ROLE_MAILBOX


def classify(text: str, ex) -> str:
    """normal | directory | spam, from contact density/repetition on the page."""
    words = max(1, len(text.split()))
    phones = [k for (t, k) in ex.ents if t == "phone"]
    emails = [k for (t, k) in ex.ents if t == "email"]
    distinct = len(phones) + len(emails)
    hits = sum(len(v["hits"]) for (t, _), v in ex.ents.items() if t in ("phone", "email"))
    if distinct and hits >= 12 and distinct <= 3:
        return "spam"                                  # same few numbers hammered over and over
    owners = sum(1 for (t, _) in ex.ents if t in ("person", "org"))
    if distinct >= 6 and words < 80 and not owners:
        return "spam"                                  # stub page that is nothing but contact data, nobody named
    persons_hits = sum(len(v["hits"]) for (t, _), v in ex.ents.items() if t == "person")
    if persons_hits >= 15 and words / persons_hits < 12 and distinct <= 2:
        return "spam"                                  # keyword stuffing of names
    # many contacts that cannot be tied to named people/orgs: a phone book, not a team page with cards
    unowned = distinct / max(1, owners) > 3
    if distinct >= 12 or (unowned and distinct >= 6 and distinct / (words / 100) >= 4):
        return "directory"
    return "normal"


def prune_shared(ex):
    """A number/mailbox tied to 3+ different owners is a switchboard, not a personal contact."""
    owners = {}
    for (ka, kb, kind), hits in ex.links.items():
        if kind != "contact":
            continue
        for c, o in ((ka, kb), (kb, ka)):
            if c[0] in ("phone", "email") and o[0] in ("person", "org"):
                owners.setdefault(c, set()).add(o)
    shared = {c for c, os_ in owners.items() if len(os_) > 2}
    for key in list(ex.links):
        ka, kb, kind = key
        if kind != "contact":
            continue
        c, o = (ka, kb) if ka[0] in ("phone", "email") else (kb, ka)
        if c in shared and o[0] in ("person", "org"):
            del ex.links[key]
        elif c[0] == "email" and o[0] == "person" and is_role_mailbox(c[1]):
            ex.links[key] = [(s, round(conf * 0.5, 3)) for s, conf in ex.links[key]]
    return len(shared)


# ---------------------------------------------------------------- scripture / reference text
_BOOKS_HE = ("בראשית שמות ויקרא במדבר דברים יהושע שופטים שמואל מלכים ישעיהו ישעיה ירמיהו ירמיה יחזקאל הושע יואל עמוס "
             "עובדיה יונה מיכה נחום חבקוק צפניה חגי זכריה מלאכי תהלים משלי איוב רות איכה קהלת אסתר דניאל עזרא נחמיה").split()
_MARK_HE = set(_BOOKS_HE) | set("""ויאמר ויאמרו ותאמר וידבר ויהי ויעש ויבא וילך וישב ויקח ויקרא ויולד ותלד ויצו ויען אלהים
אלוהים יהוה לאמר פסוק פסוקים פרק פרשת פרשה רש"י רשי גמרא משנה מסכת תלמוד הקב"ה הקבה אבינו רבנו מדרש תורה התורה
נביא הנביא זצ"ל זיע"א""".split())
_MARK_EN = set("""genesis exodus leviticus numbers deuteronomy joshua judges psalms proverbs isaiah jeremiah ezekiel
chapter verse verses lord thee thou thy hath unto begat saith shalt ye torah talmud mishnah midrash scripture""".split())
_VERSE_REF = re.compile(r"\(\s*[א-ת\"']{2,10}\s+[א-ת\"']{1,4}\s*[,:]\s*[א-ת\"']{1,4}\s*\)|\b\d{1,3}:\d{1,3}\b")


def is_reference_text(text: str) -> bool:
    """Scripture, commentary and similar texts: full of biblical and historical names that are nobody's contact."""
    words = re.findall(r"[^\W\d_]+(?:\"[^\W\d_]+)?", text[:200_000])
    if len(words) < 40:
        return False
    hits = sum(1 for w in words if w in _MARK_HE or w.lower() in _MARK_EN)
    refs = len(_VERSE_REF.findall(text[:200_000]))
    score = (hits + 2 * refs) * 1000 / len(words)
    return hits + refs >= 6 and score >= 12
