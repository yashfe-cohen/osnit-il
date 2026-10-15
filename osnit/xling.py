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


def name_skeleton_keys(name: str) -> set:
    """Cross-script lookup keys for a person name: the sorted consonant skeletons of its tokens, so Hebrew and Latin
    spellings of the same name collide ('ברקת כהן', 'Bareket Cohen', 'Barkat Cohen' all share the key 'brkt kn').
    A Latin token yields a few skeletons (ambiguous digraphs / silent h), so a name produces several keys; they are
    only a candidate index — the caller still confirms a real match with same_person_name/name_key."""
    toks = [t for t in tokens(name) if t]
    if not toks or len(toks) > 6:
        return set()
    per = []
    for t in toks:
        sk = {s for s in skeletons(t) if len(s) >= 2}
        if not sk:
            return set()                       # an all-vowel token (e.g. a lone initial) is too weak to index on
        per.append(sk)
    keys = set()
    for combo in itertools.islice(itertools.product(*per), 48):
        keys.add(" ".join(sorted(combo)))
    if len(per) >= 3:
        for combo in itertools.islice(itertools.product(per[0], per[-1]), 24):
            keys.add(" ".join(sorted(combo)))
    return keys


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
    (names outside the dictionary) must carry enough consonants to be meaningful.
    Supports middle-name omission (e.g. 'דניאל יוסף כהן' <-> 'Daniel Cohen')."""
    ta, tb = tokens(a), tokens(b)
    if not ta or not tb or is_hebrew(a) == is_hebrew(b):
        return False
    if len(ta) != len(tb):
        if min(len(ta), len(tb)) == 2 and max(len(ta), len(tb)) in (3, 4):
            return (
                same_person_name(f"{ta[0]} {ta[-1]}", f"{tb[0]} {tb[-1]}")
                or same_person_name(f"{ta[0]} {ta[-1]}", f"{tb[-1]} {tb[0]}")
            )
        return False
    he, la = (ta, tb) if is_hebrew(a) else (tb, ta)
    rest, weak, matched_known = list(la), 0, 0
    for h in he:
        forms = {fold(f) for f in token_forms(h)} - {h}
        known = bool(forms)
        m = next((l for l in rest if (l in forms if known else skeletons(h) & skeletons(l))), None)
        if m is None:
            if len(he) == 3 and len(la) == 3 and len(la[1]) == 1:
                return same_person_name(f"{he[0]} {he[2]}", f"{la[0]} {la[2]}")
            return False
        if known:
            matched_known += 1
        else:
            weak += max((len(x) for x in skeletons(h)), default=0)
        rest.remove(m)
    return weak == 0 or weak >= 3 or (matched_known >= 1 and weak >= 2)


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
