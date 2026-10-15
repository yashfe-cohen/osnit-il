"""Rule-based Latin -> Hebrew name transliteration, for SEARCH query expansion: given an English spelling of a
person's name ("Barkat Cohen"), produce a few plausible Hebrew spellings ("ברקת כהן", "ברקת כוהן"...) so the web
search also looks for the Hebrew form even when the name is not in the gazetteer. It is deliberately a GENERATOR of
a small, capped candidate set (Hebrew is an abjad, so dropping vowels is natural and keeps the set small); results
are only extra search queries — real matches are still confirmed downstream, so a loose variant costs nothing."""
import itertools

from .textnorm import fold, is_hebrew

_FINAL = {"כ": "ך", "מ": "ם", "נ": "ן", "פ": "ף", "צ": "ץ"}
# multi-letter Latin sequences -> Hebrew (checked before single letters)
_DIG3 = {"sch": ["ש"], "tsch": ["צ'"]}
_DIG2 = {"sh": ["ש"], "tz": ["צ"], "ts": ["צ"], "ch": ["צ'", "ח", "כ"], "ph": ["פ"], "th": ["ת"],
         "kh": ["ח", "כ"], "ck": ["ק"], "qu": ["קו"], "ou": ["ו"], "oo": ["ו"], "ee": ["י"]}
# single Latin letter -> Hebrew options (a vowel also offers "" so a vowel-less Hebrew spelling is produced)
_MAP = {"a": [""], "e": [""], "i": ["", "י"], "o": ["", "ו"], "u": ["", "ו"], "y": ["י", ""],
        "b": ["ב"], "c": ["ק", "כ", "ס"], "d": ["ד"], "f": ["פ"], "g": ["ג"], "h": ["ה", ""], "j": ["ג'", "ג"],
        "k": ["ק", "כ"], "l": ["ל"], "m": ["מ"], "n": ["נ"], "p": ["פ"], "q": ["ק"], "r": ["ר"],
        "s": ["ס", "ש"], "t": ["ת", "ט"], "v": ["ו", "ב"], "w": ["ו", "וו"], "x": ["קס"], "z": ["ז"]}


def _slots(s):
    out, i = [], 0
    while i < len(s):
        if s[i:i + 3] in _DIG3:
            out.append(_DIG3[s[i:i + 3]]); i += 3
        elif s[i:i + 2] in _DIG2:
            out.append(_DIG2[s[i:i + 2]]); i += 2
        elif s[i] in _MAP:
            out.append(_MAP[s[i]]); i += 1
        else:
            i += 1                                  # drop anything else (apostrophes, digits)
    return out


def latin_to_hebrew(token, cap=6):
    """A few plausible Hebrew spellings of one Latin name token. [] for an empty/Hebrew token."""
    s = fold(token).lower()
    if not s or is_hebrew(s):
        return []
    slots = _slots(s)
    if not slots:
        return []
    initial_vowel = s[0] in "aeiou"
    out, seen = [], set()
    for combo in itertools.islice(itertools.product(*slots), 600):
        w = "".join(combo).replace("וו" * 2, "וו")
        if initial_vowel and not w.startswith(("א", "ע", "ו", "י")):
            w = "א" + w                              # an initial vowel is usually written with an aleph
        if len(w) < 2:
            continue
        if w[-1] in _FINAL:
            w = w[:-1] + _FINAL[w[-1]]
        if w not in seen:
            seen.add(w)
            out.append(w)
            if len(out) >= cap:
                break
    return out


_HE_TO_LAT = {
    "א": ["a", "e"], "ב": ["b", "v"], "ג": ["g"], "ד": ["d"], "ה": ["h", "a"],
    "ו": ["o", "u", "v"], "ז": ["z"], "ח": ["h", "ch"], "ט": ["t"], "י": ["i", "y"],
    "כ": ["k", "ch"], "ך": ["ch", "k"], "ל": ["l"], "מ": ["m"], "ם": ["m"],
    "נ": ["n"], "ן": ["n"], "ס": ["s"], "ע": ["a", "e"], "פ": ["p", "f"], "ף": ["f", "p"],
    "צ": ["tz", "ts"], "ץ": ["tz", "ts"], "ק": ["k"], "ר": ["r"], "ש": ["sh", "s"], "ת": ["t"],
}
_HE_VOWELS = {"א", "ה", "ו", "י", "ע"}


def hebrew_to_latin(token: str, cap: int = 4) -> list:
    """Rule-based Hebrew -> Latin transliteration for search query expansion."""
    s = fold(token)
    if not s or not is_hebrew(s):
        return []
    try:
        from .variants import _FOLDED
        if s in _FOLDED and _FOLDED[s]:
            return list(_FOLDED[s])[:cap]
    except Exception:
        pass
    slots = []
    for idx, ch in enumerate(s):
        opts = _HE_TO_LAT.get(ch)
        if not opts:
            continue
        if idx == len(s) - 1 and ch == "ה":
            slots.append(["a", "ah"])
        elif ch not in _HE_VOWELS and idx < len(s) - 1 and s[idx + 1] not in _HE_VOWELS:
            slots.append([o + "a" for o in opts[:1]] + [o + "e" for o in opts[:1]] + [o + "i" for o in opts[:1]] + opts[:1])
        else:
            slots.append(opts)
    if not slots:
        return []
    out, seen = [], set()
    for combo in itertools.islice(itertools.product(*slots), 200):
        w = "".join(combo)
        if len(w) < 2:
            continue
        if w not in seen:
            seen.add(w)
            out.append(w)
            if len(out) >= cap:
                break
    return out

