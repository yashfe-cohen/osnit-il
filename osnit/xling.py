"""Cross-language matching (Hebrew <-> Latin) by consonant skeletons, plus role synonyms."""
import itertools
import re

from .textnorm import fold, is_hebrew, tokens
from .variants import token_forms

_HE = {"א": "", "ב": "b", "ג": "g", "ד": "d", "ה": "", "ו": "", "ז": "z", "ח": "h", "ט": "t", "י": "", "כ": "k",
       "ל": "l", "מ": "m", "נ": "n", "ס": "s", "ע": "", "פ": "p", "צ": "ts", "ק": "k", "ר": "r", "ש": "s", "ת": "t"}
_LAT_DIGRAPHS = [("sch", "s"), ("sh", "s"), ("kh", "h"), ("ph", "p"), ("th", "t"), ("tz", "ts"), ("ck", "k"),
                 ("qu", "k"), ("x", "ks")]
_LAT = {**{v: "" for v in "aeiouyw"}, "v": "b", "f": "p", "c": "k", "q": "k", "j": "g"}
ORG_NOISE = {"ltd", "inc", "llc", "corp", "corporation", "gmbh", "plc", "co", "the", "group", "בעמ", "חברת", "חברה",
             "קבוצת", "עמותת", "company", "limited"}

ROLE_CANON = {
    "ceo": ["ceo", "chief executive officer", "מנכ\"ל", "מנכ\"לית", "מנהל כללי", "מנהלת כללית", "managing director"],
    "cto": ["cto", "chief technology officer"], "cfo": ["cfo", "chief financial officer"],
    "coo": ["coo", "chief operating officer"], "vp": ["vp", "vice president", "סמנכ\"ל", "סמנכ\"לית", "סגן נשיא"],
    "chair": ["chairman", "chairwoman", "chair", "יו\"ר", "יושב ראש", "יושבת ראש"],
    "founder": ["founder", "co-founder", "cofounder", "מייסד", "מייסדת", "שותף מייסד"],
    "director": ["director", "board member", "דירקטור", "דירקטורית"], "partner": ["partner", "שותף", "שותפה"],
    "lawyer": ["lawyer", "attorney", "advocate", "עורך דין", "עורכת דין", "עו\"ד"],
    "professor": ["professor", "prof", "פרופסור", "פרופ'"], "lecturer": ["lecturer", "מרצה"],
    "researcher": ["researcher", "חוקר", "חוקרת"], "engineer": ["engineer", "מהנדס", "מהנדסת"],
    "developer": ["developer", "מפתח", "מפתחת"], "manager": ["manager", "מנהל", "מנהלת"],
    "president": ["president", "נשיא", "נשיאה"], "spokesperson": ["spokesperson", "דובר", "דוברת"],
    "journalist": ["journalist", "reporter", "עיתונאי", "עיתונאית", "כתב", "כתבת"], "editor": ["editor", "עורך", "עורכת"],
    "consultant": ["consultant", "יועץ", "יועצת"], "owner": ["owner", "בעלים"], "treasurer": ["treasurer", "גזבר", "גזברית"],
}
_ROLE_LOOKUP = {fold(s): k for k, syns in ROLE_CANON.items() for s in syns}


def _collapse(s):
    return re.sub(r"(.)\1+", r"\1", s)


def skeletons(token: str) -> set:
    """Consonant skeletons of one token; Latin spellings yield a few variants for ambiguous digraphs."""
    t = fold(token).replace('"', "").replace("'", "")
    if is_hebrew(t):
        base = {_collapse("".join(_HE.get(c, "") for c in t))}
    else:
        outs = set()
        # 'ch' is kh in Hebrew names but k in loanwords; 'kh' may also be k+h across a word joint (bank-hapoalim)
        for ch, kh in itertools.product(("h", "k"), ("h", "k\1")):
            s = t.replace("ch", "\0").replace("kh", "\1")
            for a, b in _LAT_DIGRAPHS:
                s = s.replace(a, b)
            s = s.replace("\0", ch).replace("\1", "h") if kh == "h" else s.replace("\0", ch).replace("\1", "kh")
            outs.add(_collapse("".join(_LAT.get(c, c) if c.isalpha() else "" for c in s)))
        base = outs
    return base | {s.replace("h", "") for s in base}   # a lone Latin 'h' is often a silent ה


def _match_tokens(ta, tb):
    if len(ta) != len(tb) or not ta:
        return False
    rest = list(tb)
    for a in ta:
        m = next((b for b in rest if a & b), None)
        if m is None:
            return False
        rest.remove(m)
    return True


def org_signature(name: str):
    toks = [t for t in tokens(name.replace('"', "")) if t not in ORG_NOISE]
    return [skeletons(t) for t in toks]


def same_org_name(a: str, b: str) -> bool:
    if is_hebrew(a) == is_hebrew(b):
        return False           # same-script orgs are handled by exact keys
    sa, sb = org_signature(a), org_signature(b)
    if not _match_tokens(sa, sb):
        return False
    return sum(max(len(x) for x in s) for s in sa) >= 3   # 2-consonant names are too ambiguous alone


def same_person_name(a: str, b: str) -> bool:
    """Hebrew vs Latin spelling of one name. Dictionary spellings are trusted; skeleton-only tokens
    (names outside the dictionary) must carry enough consonants to be meaningful."""
    ta, tb = tokens(a), tokens(b)
    if len(ta) != len(tb) or is_hebrew(a) == is_hebrew(b):
        return False
    he, la = (ta, tb) if is_hebrew(a) else (tb, ta)
    rest, weak = list(la), 0
    for h in he:
        forms = {fold(f) for f in token_forms(h)} - {h}
        known = bool(forms)
        m = next((l for l in rest if (l in forms if known else skeletons(h) & skeletons(l))), None)
        if m is None:
            return False
        if not known:
            weak += max(len(x) for x in skeletons(h))
        rest.remove(m)
    return weak == 0 or weak >= 3


def name_matches_label(name: str, label: str) -> bool:
    """'אלפא בע"מ' ~ alpha.co.il, 'בנק הפועלים' ~ bankhapoalim.co.il (consonant skeletons, any script)."""
    sig = org_signature(name)
    if not sig or len(sig) > 4:
        return False
    joined = {"".join(p) for p in itertools.islice(itertools.product(*sig), 64)}
    joined = {_collapse(j) for j in joined} | {_collapse(j.replace("h", "")) for j in joined}
    lab = skeletons(re.sub(r"[^a-z]", "", label.lower()))
    return any(len(j) >= 2 for j in joined & lab)


def role_canon(role_display: str) -> str:
    """'CEO, Alpha Ltd' -> 'ceo'; unknown roles keep their folded text."""
    from .extract import role_key
    r = role_display.split(",")[0].strip()
    k = role_key(r)
    if k.startswith("head of") or k.startswith("ראש "):
        return k
    return _ROLE_LOOKUP.get(k, k)


def role_org(role_display: str) -> str:
    parts = role_display.split(",", 1)
    return parts[1].strip() if len(parts) > 1 else ""
