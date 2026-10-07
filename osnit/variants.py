"""Name variants (order, Hebrew<->Latin spellings) and a fold-aware matcher."""
import itertools
import json
import os
import re

from .textnorm import clean, fold, is_hebrew, tokens

_HE_EN = {
    "יונתן": ["yonatan", "jonathan", "yonathan", "jonatan"], "יהונתן": ["yehonatan", "jehonatan"],
    "דוד": ["david", "dudi"], "משה": ["moshe", "moses"], "יוסי": ["yossi", "yosi", "yosef"],
    "יוסף": ["yosef", "joseph", "yoseph"], "אברהם": ["avraham", "abraham"], "יצחק": ["yitzhak", "isaac", "itzhak"],
    "יעקב": ["yaakov", "jacob", "yakov"], "שמואל": ["shmuel", "samuel"], "דניאל": ["daniel"],
    "דן": ["dan"], "אלון": ["alon"], "אורי": ["uri", "ori"], "אורן": ["oren"], "עמית": ["amit"],
    "גיל": ["gil"], "רון": ["ron"], "רונן": ["ronen"], "עידו": ["ido"], "נועם": ["noam"], "איתי": ["itay", "itai"],
    "איתן": ["eitan", "etan"], "אביב": ["aviv"], "אבי": ["avi"], "אריאל": ["ariel"], "בועז": ["boaz"],
    "גדעון": ["gideon"], "זיו": ["ziv"], "חיים": ["haim", "chaim", "hayim"], "טל": ["tal"], "יובל": ["yuval"],
    "יואב": ["yoav"], "ירון": ["yaron"], "ישראל": ["israel", "yisrael"], "מיכאל": ["michael"], "מיכה": ["micha"],
    "מנחם": ["menachem", "menahem"], "נדב": ["nadav"], "נתן": ["natan", "nathan"], "עומר": ["omer"],
    "עוזי": ["uzi"], "עמוס": ["amos"], "פנחס": ["pinchas", "pinhas"], "צחי": ["tzachi", "zachi"],
    "קובי": ["kobi", "kobe"], "רונית": ["ronit"], "רן": ["ran"], "שי": ["shai", "shay"], "שלמה": ["shlomo", "solomon"],
    "שמעון": ["shimon", "simon"], "תמיר": ["tamir"], "אילן": ["ilan"], "אלי": ["eli"], "אלעד": ["elad"],
    "אמיר": ["amir"], "אסף": ["assaf", "asaf"], "ארז": ["erez", "arez"], "בני": ["benny", "beni"],
    "בנימין": ["binyamin", "benjamin"], "גל": ["gal"], "דורון": ["doron"], "הדר": ["hadar"], "מאיר": ["meir"],
    "מורן": ["moran"], "מתן": ["matan"], "ניר": ["nir"], "עדי": ["adi"], "עופר": ["ofer"], "רועי": ["roi", "roy"],
    "רפאל": ["raphael", "rafael"], "שגיא": ["sagi"], "שרון": ["sharon"],
    "שרה": ["sara", "sarah"], "רחל": ["rachel"], "לאה": ["leah", "lea"], "דנה": ["dana"], "נועה": ["noa", "noah"],
    "מיכל": ["michal"], "יעל": ["yael"], "תמר": ["tamar"], "הילה": ["hila"], "ענת": ["anat"], "רונה": ["rona"],
    "אורית": ["orit"], "נטע": ["neta"], "שירה": ["shira"], "מירב": ["merav"], "טליה": ["talia"],
    "כהן": ["cohen", "kohen", "kohn"], "לוי": ["levi", "levy"], "מזרחי": ["mizrahi", "mizrachi"],
    "פרידמן": ["friedman"], "ביטון": ["biton", "bitton"], "דהן": ["dahan"], "אברהם": ["avraham", "abraham"],
    "חייט": ["hayat", "chayat", "khayat", "hayyat", "chait", "hait"], "שפירא": ["shapira", "shapiro"],
    "גולדברג": ["goldberg"], "רוזן": ["rosen"], "אזולאי": ["azoulay", "azulay"], "פרץ": ["peretz", "perez"],
    "בן דוד": ["ben david"], "אדלר": ["adler"], "קפלן": ["kaplan"], "שטרן": ["stern"], "ברק": ["barak", "barack"],
    "גולן": ["golan"], "אשכנזי": ["ashkenazi"], "סעדה": ["saada"], "חזן": ["hazan", "chazan"], "וייס": ["weiss", "weis"],
    "קליין": ["klein"], "שוורץ": ["schwartz", "shvartz"], "אורבך": ["urbach", "orbach"],
}
_LAT_START = [("j", "y"), ("y", "j"), ("ch", "h"), ("h", "ch"), ("kh", "ch"), ("ch", "kh"), ("h", "kh"),
              ("c", "k"), ("k", "c")]
_LAT_ANY = [("tz", "ts"), ("ts", "tz"), ("ph", "f"), ("th", "t"), ("yy", "y"), ("tt", "t"),
            ("ou", "u"), ("oo", "u"), ("ei", "ey"), ("ey", "ei"), ("ay", "ai"), ("ai", "ay")]

_FOLDED = {fold(k): v for k, v in _HE_EN.items()}
_REVERSE = {}
for _he, _ens in _FOLDED.items():
    for _en in _ens:
        _REVERSE.setdefault(_en, []).append(_he)


def _load_extra():
    path = os.environ.get("OSNIT_NAME_VARIANTS", "data/name_variants.json")
    try:
        with open(path, encoding="utf-8") as f:
            for he, ens in json.load(f).items():
                _FOLDED.setdefault(fold(he), []).extend(ens)
                for en in ens:
                    _REVERSE.setdefault(en.lower(), []).append(fold(he))
    except (OSError, ValueError):
        pass


_load_extra()


def latin_variants(tok: str, cap: int = 8) -> list:
    tok = tok.lower()
    out = []
    for a, b in _LAT_START:
        if tok.startswith(a):
            out.append(b + tok[len(a):])
    for a, b in _LAT_ANY:
        if a in tok[1:]:
            i = tok.index(a, 1)
            out.append(tok[:i] + b + tok[i + len(a):])
    seen, res = {tok}, []
    for v in out:
        if v not in seen:
            seen.add(v)
            res.append(v)
    return res[:cap]


def token_forms(tok: str) -> list:
    """All plausible spellings of one name token (Hebrew <-> Latin)."""
    f = fold(tok)
    forms = [tok]
    if is_hebrew(tok):
        for en in _FOLDED.get(f, []):
            forms.append(en)
            forms.extend(latin_variants(en, 3))
    else:
        for he in _REVERSE.get(f, []):
            forms.append(he)
        forms.extend(latin_variants(f))
        for v in [f] + latin_variants(f):
            for he in _REVERSE.get(v, []):
                forms.append(he)
    seen, out = set(), []
    for x in forms:
        if fold(x) not in seen:
            seen.add(fold(x))
            out.append(x)
    return out


def latin_forms(name: str) -> set:
    """Lowercase Latin spellings per token of a name (used for email-local-part matching)."""
    res = set()
    for t in tokens(name):
        for f in token_forms(t):
            if not is_hebrew(f):
                res.add(fold(f))
    return res


def name_variants(query: str, cap: int = 60) -> list:
    """Token-lists: the query, reordered, and spelling variants. First item is the canonical form."""
    base = [t for t in clean(query).split() if t]
    if not base:
        return []
    per_token = [token_forms(t)[:6] for t in base]
    seen, out = set(), []
    for combo in itertools.islice(itertools.product(*per_token), 400):
        scripts = {is_hebrew(c) for c in combo}
        if len(scripts) > 1:  # keep scripts consistent within one variant
            continue
        for order in (combo, tuple(reversed(combo))) if len(combo) > 1 else (combo,):
            key = tuple(fold(x) for x in order)
            if key not in seen:
                seen.add(key)
                out.append(list(order))
    return out[:cap]


def build_matcher(variants: list):
    """Regex over *folded* text matching any variant, tolerant to separators and Hebrew one-letter prefixes."""
    alts = []
    sep = r"(?:\s*,\s*|\s*-\s*|\s+)"
    for toks in variants:
        parts = [re.escape(fold(t)) for t in toks]
        pre = r"[והבכלמש]?" if is_hebrew(toks[0]) else ""
        alts.append(pre + sep.join(parts))
    if not alts:
        return None
    alts.sort(key=len, reverse=True)
    return re.compile(r"(?<!\w)(?:" + "|".join(alts) + r")(?!\w)", re.IGNORECASE)
