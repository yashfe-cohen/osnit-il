"""Fuzzy name search: find the person a name was MEANT to be, however it was typed.

The strict search (identity.find_people) finds a name in any of its known spellings and scripts. This layer is the
searcher's safety net for what people actually type: a keyboard slip, a spelling by ear (ט/ת, כ/ק, ס/ש, a vowel
letter added or dropped), the wrong keyboard layout ('hmje fvi' = 'יצחק כהן'), no space between the words, a prefix
letter or a title, Russian (Cyrillic) letters, and a name written half in Hebrew and half in English.

How: every distinct name WORD in the data is kept once in a small vocabulary (store.name_vocab) with two kinds of
lookup keys — its cross-script consonant skeleton ("s:", xling.skeletons: Hebrew and Latin spellings of one name
share it) and its one-letter deletions ("d:", SymSpell: two words one edit apart share a deletion). A query word
that is IN the vocabulary is taken as typed (plus the same word in the other script); only a word that is NOT in the
data is corrected, to the nearest vocabulary words by a weighted edit distance (a neighbouring key or a confusable
letter costs less than an arbitrary one). The corrected names are then looked up through the per-word index, so a
result is always a real person carrying every corrected word.

Precision-first: this is SEARCH only — it never merges, links or asserts anything. A name whose words are all in the
data but that names nobody (a first name with another person's surname) finds nobody; each fuzzy hit carries the
corrected spelling ("did you mean") and its cost so the UI can say what it searched for."""
import itertools
import re
from functools import lru_cache

from .textnorm import fold, is_hebrew

# ---- keyboards ---------------------------------------------------------------------------------------------------
HE_KEYS = {"q": "/", "w": "'", "e": "ק", "r": "ר", "t": "א", "y": "ט", "u": "ו", "i": "ן", "o": "ם", "p": "פ",
           "a": "ש", "s": "ד", "d": "ג", "f": "כ", "g": "ע", "h": "י", "j": "ח", "k": "ל", "l": "ך", ";": "ף",
           "z": "ז", "x": "ס", "c": "ב", "v": "ה", "b": "נ", "n": "מ", "m": "צ", ",": "ת", ".": "ץ"}
LAT_FOR_HE = {v: k for k, v in HE_KEYS.items()}
_ROWS = ["qwertyuiop", "asdfghjkl;", "zxcvbnm,."]
_POS = {c: (r, i) for r, row in enumerate(_ROWS) for i, c in enumerate(row)}
_FIN = str.maketrans("ךםןףץ", "כמנפצ")


def _near(a, b):
    """Two characters on neighbouring keys (Latin keys directly, Hebrew letters through their key)."""
    a, b = LAT_FOR_HE.get(a, a), LAT_FOR_HE.get(b, b)
    pa, pb = _POS.get(a), _POS.get(b)
    return bool(pa and pb) and abs(pa[0] - pb[0]) + abs(pa[1] - pb[1]) == 1


# letters people confuse when spelling by ear, and letters that come and go (vowel letters / vowels)
_CONFUSE = {frozenset(p) for p in [("ט", "ת"), ("כ", "ק"), ("ח", "כ"), ("ס", "ש"), ("א", "ע"), ("ב", "ו"), ("ה", "א"),
                                   ("c", "k"), ("k", "q"), ("s", "z"), ("v", "w"), ("i", "y"), ("j", "y"), ("f", "p"),
                                   ("a", "e"), ("e", "i"), ("o", "u"), ("c", "s"), ("x", "h")]}
_SOFT = set("ויאהע") | set("aeiouyh")


def _sub_cost(a, b):
    if a == b:
        return 0.0
    if frozenset((a, b)) in _CONFUSE:
        return 0.35
    if _near(a, b):
        return 0.5
    return 1.0


def _indel_cost(c):
    return 0.4 if c in _SOFT else 0.9


def distance(a, b):
    """Weighted Damerau-Levenshtein: a confusable letter 0.35, a neighbouring key 0.5, a vowel letter in/out 0.4, a
    swap of two letters 0.5, anything else 1."""
    a, b = a.translate(_FIN), b.translate(_FIN)
    n, m = len(a), len(b)
    if abs(n - m) > 3:
        return 9.0
    prev2 = None
    prev = [0.0] * (m + 1)
    for j in range(1, m + 1):
        prev[j] = prev[j - 1] + _indel_cost(b[j - 1])
    for i in range(1, n + 1):
        cur = [prev[0] + _indel_cost(a[i - 1])] + [0.0] * m
        for j in range(1, m + 1):
            v = min(prev[j] + _indel_cost(a[i - 1]), cur[j - 1] + _indel_cost(b[j - 1]),
                    prev[j - 1] + _sub_cost(a[i - 1], b[j - 1]))
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1] and a[i - 1] != a[i - 2]:
                v = min(v, prev2[j - 2] + 0.5)
            cur[j] = v
        prev2, prev = prev, cur
    return prev[m]


def max_cost(word):
    n = len(word)
    return 0.9 if n <= 2 else 1.1 if n <= 3 else 1.2 if n <= 5 else 1.6


# ---- vocabulary keys ---------------------------------------------------------------------------------------------
def _skels(word):
    from .xling import skeletons
    return {s for s in skeletons(word) if len(s) >= 2}


def _deletes(word):
    w = word.translate(_FIN)
    return {w} | ({w[:i] + w[i + 1:] for i in range(len(w))} if len(w) >= 3 else set())


# ---- a phonetic form shared by both scripts ----------------------------------------------------------------------
# consonants as heard, plus the two "soft" letters w (ו / o,u,v,w) and y (י / i,e-ish,y) that come and go between
# spellings; vowels a/e and silent א/ע/ה vanish. 'Moshe' -> 'mws', 'משה' -> 'ms'; 'Abramovich' -> 'brmwwyc',
# 'אברמוביץ' -> 'brmwbyc' — close under a weighted distance where w/y/h are cheap and b~w, k~h, c~s, c~z are near.
_PHON_HE = {"א": "", "ב": "b", "ג": "g", "ד": "d", "ה": "h", "ו": "w", "ז": "z", "ח": "h", "ט": "t", "י": "y",
            "כ": "k", "ל": "l", "מ": "m", "נ": "n", "ס": "s", "ע": "", "פ": "p", "צ": "c", "ק": "k", "ר": "r",
            "ש": "s", "ת": "t"}
_PHON_LAT = [("sch", "s"), ("tch", "C"), ("ich$", "yC"), ("itz$", "yC"), ("sh", "s"), ("kh", "h"), ("ch", "h"),
             ("tz", "C"), ("ts", "C"), ("ph", "p"), ("th", "t"), ("ck", "k"), ("qu", "k"), ("ou", "w"), ("oo", "w"),
             ("ee", "y"), ("x", "ks")]
_PHON_LAT1 = {"a": "", "e": "", "i": "y", "o": "w", "u": "w", "y": "y", "v": "w", "w": "w", "f": "p", "c": "k",
              "q": "k", "j": "y"}
_PSOFT = set("wyh")
_PNEAR = {frozenset(p) for p in [("b", "w"), ("k", "h"), ("c", "s"), ("c", "z"), ("s", "z"), ("t", "d"),
                                 ("p", "b"), ("g", "k"), ("c", "t")]}


def phon(word):
    w = fold(word).translate(_FIN)
    if is_hebrew(w):
        s = "".join(_PHON_HE.get(c, "") for c in w)
        if w.endswith("ה") and s.endswith("h"):
            s = s[:-1]                                     # a final ה is a vowel
    else:
        w = re.sub(r"[^a-z]", "", w)
        if w.endswith("h") and len(w) > 2 and w[-2] in "aeiou":
            w = w[:-1]                                     # Sarah, Leah, Noah
        for a, b in _PHON_LAT:
            w = re.sub(a, b, w) if a.endswith("$") else w.replace(a, b)
        s = "".join(_PHON_LAT1.get(c, c) for c in w).replace("C", "c")     # C: a ts sound (צ) from a digraph
    return re.sub(r"(.)\1+", r"\1", s)


_LAT_ALTS = [("g", "h"), ("ff$", "v"), ("ski$", "sky"), ("sky$", "ski"), ("w", "v")]


def lat_alts(word):
    """Conventional respellings of a Latin name word: Russian writes Hebrew ה as G (Gershkovich = הרשקוביץ, Kogan =
    כהן), -off for -ov, -ski / -sky, German w for v."""
    w = fold(word)
    out = set()
    for a, b in _LAT_ALTS:
        alt = re.sub(a, b, w) if a.endswith("$") else w.replace(a, b)
        if alt != w:
            out.add(alt)
    return out


def _hard(p):
    return "".join(c for c in p if c not in _PSOFT)


@lru_cache(maxsize=200_000)
def pdistance(a, b):
    """Distance between two phonetic forms: soft letters in/out 0.35, a near sound 0.35, otherwise 1."""
    n, m = len(a), len(b)
    if abs(n - m) > 4:
        return 9.0
    ind = lambda c: 0.35 if c in _PSOFT else 1.0
    prev = [0.0] * (m + 1)
    for j in range(1, m + 1):
        prev[j] = prev[j - 1] + ind(b[j - 1])
    for i in range(1, n + 1):
        cur = [prev[0] + ind(a[i - 1])] + [0.0] * m
        for j in range(1, m + 1):
            x, y = a[i - 1], b[j - 1]
            sub = 0.0 if x == y else 0.35 if frozenset((x, y)) in _PNEAR or (x in _PSOFT and y in _PSOFT) else 1.0
            cur[j] = min(prev[j] + ind(x), cur[j - 1] + ind(y), prev[j - 1] + sub)
        prev = cur
    return prev[m]


def _hard_keys(word):
    forms = {_hard(phon(word))}
    if not is_hebrew(word):
        forms.add(_hard(phon(re.sub(r"[vw]", "b", fold(word)))))     # English v/w is often a ב (Yaakov, Abramovich)
        forms |= {_hard(phon(a)) for a in lat_alts(word)}
    out = set()
    for h in forms:
        if h:
            out.add(h)
            if len(h) >= 2:
                out |= {h[:i] + h[i + 1:] for i in range(len(h))} - {""}
    return out


def vocab_keys(word):
    """The lookup keys one vocabulary word is stored under."""
    return ({"s:" + s for s in _skels(word)} | {"d:" + d for d in _deletes(word)}
            | {"h:" + h for h in _hard_keys(word)})


# ---- transliterations learned from the data ------------------------------------------------------------------------
def _align(he_words, lat_words):
    """Pair the words of one person's Hebrew and English names (same count): the pairing that sounds closest."""
    if len(he_words) != len(lat_words) or not 2 <= len(he_words) <= 4:
        return []
    from .nicknames import nick_equiv
    best, best_cost = None, 9e9
    for perm in itertools.permutations(lat_words):
        costs = [0.0 if nick_equiv(h, l) else pdistance(phon(h), phon(l)) for h, l in zip(he_words, perm)]
        if sum(costs) < best_cost:
            best, best_cost = list(zip(he_words, perm, costs)), sum(costs)
    # at least one word must already sound right — then the other is learned, however unlike it sounds (Kogan/כהן)
    if not best or min(c for _h, _l, c in best) > 0.5:
        return []
    return [(h, l) for h, l, _c in best]


_XLIT_HWM = "xlit_rel_hwm"


def _identifier_pairs(store, batch=200000):
    """Two people — one written in Hebrew, one in English — who are the only two holders of one personal identifier
    (email / national ID / phone): almost always one person in two files. Reads the relations added since the last
    call (a high-water mark), so a big database is walked once, in slices, in the background."""
    try:
        hwm = int(store.meta_get(_XLIT_HWM) or 0)
    except (TypeError, ValueError):
        hwm = 0
    rels = store.q("SELECT r.id, r.a_id, r.b_id, ea.type ta, eb.type tb FROM relations r "
                   "CROSS JOIN entities ea ON ea.id=r.a_id CROSS JOIN entities eb ON eb.id=r.b_id "
                   "WHERE r.id > ? ORDER BY r.id LIMIT ?", (hwm, batch))
    if not rels:
        return []
    ids = set()
    for r in rels:
        if r["ta"] == "person" and r["tb"] in ("email", "national_id", "phone"):
            ids.add(r["b_id"])
        elif r["tb"] == "person" and r["ta"] in ("email", "national_id", "phone"):
            ids.add(r["a_id"])
    out = []
    ids = list(ids)
    for i in range(0, len(ids), 400):
        part = tuple(ids[i:i + 400])
        ph = ",".join("?" * len(part))
        holders = {}
        for r in store.q(
                f"SELECT x.iid, e.display FROM (SELECT b_id iid, a_id pid FROM relations WHERE b_id IN ({ph}) "
                f"UNION SELECT a_id iid, b_id pid FROM relations WHERE a_id IN ({ph})) x "
                f"CROSS JOIN entities e ON e.id=x.pid WHERE e.type='person'", part + part):
            holders.setdefault(r["iid"], []).append(r["display"] or "")
        for names in holders.values():
            if len(names) == 2 and is_hebrew(names[0]) != is_hebrew(names[1]):
                out.append({"a": names[0], "b": names[1]})
    store.meta_set(_XLIT_HWM, str(rels[-1]["id"]))
    return out


def learn_transliterations(store, limit=50000):
    """Learn how THIS data writes names across scripts, from people it already knows are one person: a Hebrew name
    with an English alias (merged through a shared identifier) and the operator's 'same person' decisions. Each
    aligned word pair is stored as x:<word> -> <other word> in the vocabulary keys. -> pairs stored."""
    from .textnorm import tokens
    rows = store.q("SELECT e.display a, al.alias b FROM aliases al CROSS JOIN entities e ON e.id=al.entity_id "
                   "WHERE e.type='person' AND al.alias IS NOT NULL LIMIT ?", (limit,))
    rows = list(rows) + list(store.q(
        "SELECT ea.display a, eb.display b FROM identity_links l CROSS JOIN entities ea ON ea.id=l.a "
        "CROSS JOIN entities eb ON eb.id=l.b WHERE l.decision='same' LIMIT ?", (limit,)))
    rows += _identifier_pairs(store, limit)
    pairs = set()
    for r in rows:
        a, b = r["a"] or "", r["b"] or ""
        if is_hebrew(a) == is_hebrew(b):
            continue
        he, lat = (a, b) if is_hebrew(a) else (b, a)
        for h, l in _align([fold(t) for t in tokens(he)], [fold(t) for t in tokens(lat)]):
            if h != l:
                pairs.add((h, l))
    if pairs:
        with store.tx(silent=True) as c:
            c.executemany("INSERT OR IGNORE INTO name_vocab_key(k, token) VALUES(?,?)",
                          [("x:" + l, h) for h, l in pairs] + [("x:" + h, l) for h, l in pairs])
    return len(pairs)


# ---- query rewriting ---------------------------------------------------------------------------------------------
_TITLES = re.compile(r"^(?:ד\"ר|ד״ר|דר'|עו\"ד|עו״ד|פרופ'|פרופסור|הרב|הרבנית|מר|גב'|גברת|רו\"ח|dr|mr|mrs|ms|miss|prof|"
                     r"adv|rabbi|sir)\.?$", re.I)
_CYR = {"а": "a", "б": "b", "в": "v", "г": "g", "д": "d", "е": "e", "ё": "yo", "ж": "zh", "з": "z", "и": "i",
        "й": "y", "к": "k", "л": "l", "м": "m", "н": "n", "о": "o", "п": "p", "р": "r", "с": "s", "т": "t", "у": "u",
        "ф": "f", "х": "kh", "ц": "ts", "ч": "ch", "ш": "sh", "щ": "shch", "ъ": "", "ы": "y", "ь": "", "э": "e",
        "ю": "yu", "я": "ya", "і": "i", "ї": "yi", "є": "ye", "ґ": "g"}
_HE_PREFIX = "והבלמשכ"
_CYR_RE = re.compile(r"[Ѐ-ӿ]")


def cyrillic_to_latin(s):
    return "".join(_CYR.get(c, _CYR.get(c.lower(), c)) for c in s)


def _clean(q):
    q = q.replace("-", " ").replace("_", " ").replace(",", " ")
    q = re.sub(r"(?<=[a-z])(?=[A-Z])", " ", q)            # 'YitzhakCohen' -> 'Yitzhak Cohen'
    ws = [w for w in q.split() if not _TITLES.match(w)]
    return [fold(w).strip(".'\"") for w in ws if fold(w).strip(".'\"")]


def _layout_variants(raw):
    """The same keystrokes read on the other keyboard layout (from the raw query: ',' and '.' are letters there)."""
    joined = " ".join(raw.lower().split())          # not fold(): a final letter is its own key (ם = o, מ = n)
    if is_hebrew(joined):
        lat = "".join(LAT_FOR_HE.get(c, c) for c in joined)
        return [lat.split()] if lat != joined and re.fullmatch(r"[a-z;,. ]+", lat) else []
    if re.fullmatch(r"[a-z;,. ]+", joined):
        he = "".join(HE_KEYS.get(c, c) for c in joined)
        he = " ".join(w.translate(_FIN) for w in he.split())
        return [he.split()] if is_hebrew(he) and not re.search(r"[/']", he) else []
    return []


class Vocab:
    """Lookups against store.name_vocab, cached for one query."""

    def __init__(self, store):
        self.store = store
        self._has = {}
        self.opts = {}

    def has(self, w):
        if w not in self._has:
            self._has[w] = bool(self.store.q1("SELECT 1 x FROM name_vocab WHERE token=?", (w,)))
        return self._has[w]

    def by_keys(self, keys, per_key=300):
        """Vocabulary words under any of these keys — each key read on its own (a primary-key range), so a broad key
        can never crowd the exact ones out."""
        out = set()
        for k in dict.fromkeys(keys):
            out |= {r["token"] for r in self.store.q("SELECT token FROM name_vocab_key WHERE k=? LIMIT ?", (k, per_key))}
        return out

    def known(self, w):
        """In the data as typed, or the same word in the other script."""
        return self.has(w) or bool(self.cross(w))

    def cross(self, w):
        """Vocabulary words in the OTHER script with the same consonant skeleton (the same name, transliterated)."""
        he = is_hebrew(w)
        sk = _skels(w)
        if not sk:
            return set()
        from .xling import same_person_name
        return {t for t in self.by_keys("s:" + s for s in sk) if is_hebrew(t) != he and same_person_name(t, w)}


# why a query word was read as a vocabulary word (shown to the operator)
WHY_HE = {"exact": "כפי שנכתב", "script": "אותו שם בכתב השני", "learned": "כתיב שנלמד מהמאגר",
          "nickname": "כינוי", "prefix": "אות שימוש", "sound": "כתיב לפי שמיעה", "typo": "טעות הקלדה",
          "convention": "כתיב רוסי/לועזי מקובל", "layout": "מקלדת בשפה הלא נכונה", "joined": "מילים מחוברות",
          "cyrillic": "קירילית"}


def _word_options(v, w):
    """[(vocabulary word, cost, why)] a query word may stand for, cheapest first (cached for the query)."""
    if w not in v.opts:
        v.opts[w] = _word_options_uncached(v, w)
    return v.opts[w]


def _word_options_uncached(v, w):
    from .nicknames import nick_forms
    learned = v.by_keys(["x:" + w])                  # a spelling this data itself showed to be the same name
    if v.has(w):
        return ([(w, 0.0, "exact")]
                + [(t, 0.1, "learned" if t in learned else "script") for t in sorted(v.cross(w) | learned) if t != w][:4])
    opts = {}

    def put(t, c, why):
        if t not in opts or c < opts[t][0]:
            opts[t] = (c, why)

    for t in learned:
        put(t, 0.1, "learned")
    for t in v.cross(w):
        put(t, 0.2, "script")
    for f in nick_forms(w):                          # Avi -> אברהם, Sasha -> אלכסנדר, אתי -> אסתר
        f = fold(f)
        if v.has(f):
            put(f, 0.3, "nickname")
    if is_hebrew(w) and len(w) >= 4 and w[0] in _HE_PREFIX and v.has(w[1:]):
        put(w[1:], 0.3, "prefix")
    lim = max_cost(w)
    pw = phon(w)
    slips = {}
    if not is_hebrew(w):
        # an English keyboard slip changes how the word sounds: also try each letter's neighbouring keys
        for i, ch in enumerate(w):
            for nb in "qwertyuiopasdfghjklzxcvbnm":
                if nb != ch and _near(ch, nb):
                    alt = w[:i] + nb + w[i + 1:]
                    slips.setdefault(phon(alt), alt)
    keys = ["d:" + d for d in _deletes(w)] + ["s:" + s for s in _skels(w)] + ["h:" + h for h in _hard_keys(w)]
    # a slip is one wrong key and otherwise the word as spelled, so it can only be a word with the slip's own
    # skeleton: look those up per skeleton, and compare each slip only with the words found under it
    by_hard = {}
    for ps in slips:
        by_hard.setdefault(_hard(ps), []).append(ps)
    slip_for = {}
    for h, group in by_hard.items():
        if h:
            hk = {h} | ({h[:i] + h[i + 1:] for i in range(len(h))} if len(h) >= 4 else set())   # long = specific
            for t in v.by_keys("h:" + k for k in hk):
                slip_for.setdefault(t, []).extend(group)
    alts = [phon(a) for a in lat_alts(w)] if not is_hebrew(w) else []
    for t in v.by_keys(keys) | set(slip_for):
        if is_hebrew(t) == is_hebrew(w):
            d_typo, d_sound = distance(w, t), 0.2 + pdistance(pw, phon(t))
            c, why = (d_typo, "typo") if d_typo <= d_sound else (d_sound, "sound")
        else:
            pt = phon(t)
            c, why = 0.2 + pdistance(pw, pt), "sound"   # the other script: compare how the two words sound
            for pa in alts:
                if 0.3 + pdistance(pa, pt) < c:
                    c, why = 0.3 + pdistance(pa, pt), "convention"
            for ps in slip_for.get(t, ()):
                d = pdistance(ps, pt)
                if d <= 0.35 and 0.6 + d < c:          # one slipped key, otherwise as spelled
                    c, why = 0.6 + d, "typo"
        if c <= lim:
            put(t, 0.2 + c, why)
    return sorted(((t, c, why) for t, (c, why) in opts.items()), key=lambda x: (x[1], x[0]))[:4]


def _splits(v, word, parts=3):
    """A run-together name split into known words: 'שרהלוי' -> ['שרה', 'לוי'] (up to three words)."""
    out = []
    if parts < 2 or len(word) < 4:
        return out
    for i in range(2, len(word) - 1):
        left, right = word[:i], word[i:]
        left_f = left.translate(_FIN)
        if not v.known(left_f):
            continue
        right_f = right.translate(_FIN)
        if v.known(right_f) and len(right_f) >= 2:
            out.append([left_f, right_f])
        for rest in _splits(v, right, parts - 1):
            out.append([left_f] + rest)
    return out[:6]


def readings(store, query):
    """[(words, base cost, how)] — the ways a typed query can be read, cheapest first."""
    v = Vocab(store)
    q = cyrillic_to_latin(query) if _CYR_RE.search(query) else query
    words = _clean(q)
    if not words:
        return v, []
    out = [(words, 0.0 if q == query else 0.2, "cyrillic" if q != query else "")]
    if any(not v.known(w) for w in words):
        for lw in _layout_variants(q):
            if sum(bool(_word_options(v, w)) for w in lw) * 2 >= len(lw) and lw != words:
                out.append((lw, 0.3, "layout"))
    for words_, base, how in list(out):
        if len(words_) == 1 and not v.known(words_[0]):
            for sp in _splits(v, words_[0]):
                out.append((sp, base + 0.3, (how + "+" if how else "") + "joined"))
    return v, out


MAX_TOTAL = 2.0


def fuzzy_find(store, query, limit=20, exclude=()):
    """People a messy query most likely means: [{id, key, display, cost, corrected, how}], cheapest first.
    Each hit carries every corrected word; `corrected` is the spelling actually searched."""
    from .store import name_tokens
    v, reads = readings(store, query)
    seen, out = set(int(i) for i in exclude), []
    for words, base, how in reads:
        if len(words) > 5:
            continue
        opts = [_word_options(v, w) for w in words]
        if not all(opts):
            # a word nothing in the data resembles: search on the rest only when the rest is still a full name
            keep = [o for o in opts if o]
            if len(keep) < 2:
                continue
            opts = keep
        combos = sorted(itertools.product(*opts), key=lambda c: sum(x[1] for x in c))[:24]
        for combo in combos:
            toks = [t for t, _c, _w in combo]
            cost = base + sum(c for _t, c, _w in combo)
            # a typed name is a few slips away from the meant one, not a different name: at most one word may be
            # heavily corrected, and the whole reading stays within a budget
            if len(set(toks)) < len(toks) or cost > MAX_TOTAL or sum(c > 0.8 for _t, c, _w in combo) > 1:
                continue
            ids = store.persons_by_token([t for w in toks for t in name_tokens(w)], limit=limit)
            if not ids:
                continue
            fresh = [i for i in ids if i not in seen]
            if not fresh:
                continue
            ph = ",".join("?" * len(fresh))
            for r in store.q(f"SELECT id, key, display FROM entities WHERE id IN ({ph}) AND type='person'",
                             tuple(fresh)):
                seen.add(r["id"])
                whys = [x for x in (how.split("+") if how else [])]
                whys += [w_ for _t, _c, w_ in combo if w_ != "exact"]
                whys = list(dict.fromkeys(whys)) or ["exact"]
                out.append(dict(id=r["id"], key=r["key"], display=r["display"], cost=round(cost, 2),
                                corrected=" ".join(toks), how="+".join(whys),
                                why=" · ".join(WHY_HE.get(x, x) for x in whys)))
    out.sort(key=lambda r: (r["cost"], r["id"]))
    return out[:limit]


def ai_readings(cfg, store, query, limit=20):
    """The last resort, OPT-IN only (osnit.env, ai.names_enabled): ask the configured model how else this name may be
    written and search each spelling strictly. Off, failing or empty -> []. Every hit says it came from the model."""
    from . import ai
    if cfg is None or not ai.names_enabled(cfg):
        return []
    from .identity import find_people
    out, seen = [], set()
    for alt in ai.name_expansions(cfg, store, query, cap=12):
        for p in find_people(store, alt, limit=limit):
            if p["id"] not in seen:
                seen.add(p["id"])
                out.append(dict(p, cost=1.0, corrected=alt, how="ai", why="הצעת AI (לאישור המפעיל)"))
        if len(out) >= limit:
            break
    return out[:limit]


def find_people_any(store, query, limit=20, cfg=None):
    """The strict search first (every spelling of the name as typed), then the fuzzy reading of what was meant, then
    — only when both found nobody and the operator enabled it — the AI's spellings."""
    from .identity import find_people
    strict = [dict(p, cost=0.0, corrected="", how="exact") for p in find_people(store, query, limit=limit)]
    if len(strict) >= limit:
        return strict
    out = strict + fuzzy_find(store, query, limit=limit - len(strict), exclude=[p["id"] for p in strict])
    return out or ai_readings(cfg, store, query, limit=limit)
