"""Messy-query benchmark: does a name typed the way people really type it find the right person?

The identity benchmark (erbench) asks "are these two records one person?"; this one asks the searcher's question:
the operator types a name — in Hebrew or English, misspelled, transliterated by ear, on the wrong keyboard layout,
without a space, in Cyrillic — and the right person must come up. And a name that is NOT in the data must not bring
up somebody else (fuzzy search must not buy recall with false hits).

A roster of people of different origins (Ashkenazi, Mizrahi, Arab, Russian-speaking, English) is imported through
the real pipeline (some also in Latin script), and every query is generated from a person's name by one kind of
mistake, deterministically:

  he_typo       a keyboard slip in Hebrew (adjacent key / dropped / doubled / swapped letter)
  he_phonetic   a spelling by ear (ט/ת, כ/ק, ח/כ, ס/ש, א/ע, a vowel letter added or dropped)
  en_translit   the Hebrew name written in English by ear (Itzhak Koen, Yitshak Kohen)
  en_typo       a keyboard slip in the English spelling
  layout        typed on the wrong keyboard layout (hmje fvi = יצחק כהן)
  joined        no space between the words
  extras        a Hebrew prefix letter, a title, a hyphen, mixed scripts
  cyrillic      the name in Russian

Scored: found@5 per kind (the person among the first five results) and the false-hit rate over absent names.
`python -m osnit qeval` prints the summary; tools/gate.py holds the thresholds."""
import os
import random
import tempfile
import time
from collections import defaultdict

# (Hebrew, English, Cyrillic or None, also imported in Latin script?)
ROSTER = [
    ("יצחק כהן", "Yitzhak Cohen", "Ицхак Коэн", True), ("שרה לוי", "Sarah Levi", None, False),
    ("משה אברמוביץ", "Moshe Abramovich", "Моше Абрамович", False), ("דנה רבינוביץ", "Dana Rabinovich", None, False),
    ("מיכאל בן דוד", "Michael Ben David", None, False), ("אליהו חדד", "Eliyahu Hadad", None, False),
    ("יעקב שטרנברג", "Yaakov Sternberg", "Яков Штернберг", False), ("אורית טביב", "Orit Tabib", None, False),
    ("שמואל קרויטורו", "Shmuel Croitoru", None, False), ("מוחמד חליל", "Mohammed Khalil", None, True),
    ("רחל אזולאי", "Rachel Azoulay", None, False), ("אברהם אוחיון", "Avraham Ohayon", None, False),
    ("יוסף מזרחי", "Yosef Mizrahi", None, False), ("דוד ביטון", "David Biton", None, False),
    ("אסתר פרץ", "Esther Peretz", None, False), ("נועה גולדשטיין", "Noa Goldstein", "Ноа Гольдштейн", False),
    ("איתי שפירא", "Itai Shapira", None, False), ("תמר רוזנברג", "Tamar Rosenberg", None, False),
    ("חיים דהן", "Haim Dahan", None, False), ("מרים קצב", "Miriam Katzav", None, False),
    ("עומר חסון", "Omer Hasson", None, False), ("יהודית ליברמן", "Yehudit Liberman", None, False),
    ("עלי נסאר", "Ali Nassar", None, True), ("פאטמה אבו רביע", "Fatma Abu Rabia", None, False),
    ("סבטלנה איבנובה", "Svetlana Ivanova", "Светлана Иванова", True),
    ("דמיטרי קוזלוב", "Dmitry Kozlov", "Дмитрий Козлов", False),
    ("אלכסנדר פרידמן", "Alexander Friedman", "Александр Фридман", False),
    ("אולגה קוגן", "Olga Kogan", "Ольга Коган", False), ("ג'ון סמית", "John Smith", None, True),
    ("צבי הרשקוביץ", "Tzvi Hershkovitz", None, False), ("שושנה גבאי", "Shoshana Gabay", None, False),
    ("עמית בן חיים", "Amit Ben Haim", None, False), ("גילה עמר", "Gila Amar", None, False),
    ("רונן צור", "Ronen Tzur", None, False), ("ליאור אלמוג", "Lior Almog", None, False),
    ("נתן שרנסקי", "Natan Sharansky", "Натан Щаранский", False), ("מאיר וקנין", "Meir Vaknin", None, False),
    ("זהבה בוזגלו", "Zehava Buzaglo", None, False), ("שלום אלמליח", "Shalom Elmaliach", None, False),
    ("חנה זילברמן", "Hana Silberman", None, False),
]
# look-alikes that ARE in the data but are never the person searched for: the right one must still rank first
CONFUSERS = ["שרה לוין", "יצחק כהנא", "משה אברמוב", "דנה רבין", "אליהו חדאד", "יעקב שטרן", "רחל אזולאי-לוי",
             "דוד ביטן", "נועה גולדשטיין-כץ", "חיים דהאן", "מאיר וקנון", "אסתר פרצ'יק", "Dana Rabin", "Moshe Abram",
             "תמר רוזנבלום", "חנה זילבר", "ליאור אלמגור", "רונן צורי", "עומר חסין", "יוסף מזרחי-טל"]
# names NOT in the data: a real person's first name with another person's surname, etc.
ABSENT = ["יצחק לוי", "שרה כהן", "משה רבינוביץ", "דנה אברמוביץ", "אליהו בן דוד", "יעקב חדד", "אורית שטרנברג",
          "יוסף ביטון", "דוד מזרחי", "אסתר אזולאי", "נועה שפירא", "תמר גולדשטיין", "חיים קצב", "מרים דהן",
          "Yitzhak Levi", "Sarah Cohen", "Moshe Rabinovich", "David Mizrahi", "Esther Azoulay", "Noa Shapira",
          "עומר ליברמן", "יהודית חסון", "רונן אלמוג", "ליאור צור", "מאיר בוזגלו", "זהבה וקנין", "שלום זילברמן",
          "חנה אלמליח", "גילה בן חיים", "עמית עמר"]

# the standard Hebrew keyboard (SI-1452) on the Latin keys
HE_KEYS = {"q": "/", "w": "'", "e": "ק", "r": "ר", "t": "א", "y": "ט", "u": "ו", "i": "ן", "o": "ם", "p": "פ",
           "a": "ש", "s": "ד", "d": "ג", "f": "כ", "g": "ע", "h": "י", "j": "ח", "k": "ל", "l": "ך", ";": "ף",
           "z": "ז", "x": "ס", "c": "ב", "v": "ה", "b": "נ", "n": "מ", "m": "צ", ",": "ת", ".": "ץ"}
LAT_FOR_HE = {v: k for k, v in HE_KEYS.items()}
_ROWS = ["qwertyuiop", "asdfghjkl;", "zxcvbnm,."]
_POS = {c: (r, i) for r, row in enumerate(_ROWS) for i, c in enumerate(row)}
_FINAL = str.maketrans("ךםןףץ", "כמנפצ")
_TO_FINAL = {"כ": "ך", "מ": "ם", "נ": "ן", "פ": "ף", "צ": "ץ"}
PHONETIC_HE = [("ט", "ת"), ("ת", "ט"), ("כ", "ק"), ("ק", "כ"), ("ח", "כ"), ("כ", "ח"), ("ס", "ש"), ("ש", "ס"),
               ("א", "ע"), ("ע", "א"), ("ב", "ו"), ("ו", "וו")]


def _adjacent(c):
    if c not in _POS:
        return []
    r, i = _POS[c]
    out = []
    for dr, di in ((0, -1), (0, 1), (-1, 0), (1, 0)):
        rr, ii = r + dr, i + di
        if 0 <= rr < 3 and 0 <= ii < len(_ROWS[rr]):
            out.append(_ROWS[rr][ii])
    return out


def _finals(word):
    w = word.translate(_FINAL)
    return w[:-1] + _TO_FINAL.get(w[-1], w[-1]) if w else w


def typed_on_latin(he):
    """The keys you hit typing a Hebrew name with the keyboard left on English: 'יצחק כהן' -> 'hmje fvi'."""
    return "".join(LAT_FOR_HE.get(c, c) for c in he)


def typed_on_hebrew(en):
    """The characters you get typing an English name with the keyboard left on Hebrew: 'cohen' -> 'בםיקמ'."""
    return "".join(HE_KEYS.get(c, c) for c in en.lower())


def _pick_word(rng, name):
    ws = name.split()
    return rng.randrange(len(ws)), ws


def he_typo(rng, he):
    i, ws = _pick_word(rng, he)
    w = ws[i].translate(_FINAL)
    if len(w) < 3:
        return None
    j = rng.randrange(1, len(w))
    kind = rng.choice(["adjacent", "drop", "double", "swap"])
    if kind == "adjacent":
        lat = LAT_FOR_HE.get(w[j])
        near = [HE_KEYS[a] for a in _adjacent(lat) if a in HE_KEYS and HE_KEYS[a] not in "/',.;"] if lat else []
        if not near:
            return None
        w = w[:j] + rng.choice(near) + w[j + 1:]
    elif kind == "drop":
        w = w[:j] + w[j + 1:]
    elif kind == "double":
        w = w[:j] + w[j] + w[j:]
    else:
        if j >= len(w) - 1:
            return None
        w = w[:j] + w[j + 1] + w[j] + w[j + 2:]
    ws[i] = _finals(w)
    return " ".join(ws)


def he_phonetic(rng, he):
    i, ws = _pick_word(rng, he)
    w = ws[i].translate(_FINAL)
    opts = [(a, b) for a, b in PHONETIC_HE if a in w]
    if rng.random() < 0.35 or not opts:
        # a vowel letter added or dropped (מטרנברג -> שטערנברג style: a mater lectionis)
        if "ו" in w[1:-1] and rng.random() < 0.5:
            k = w.index("ו", 1)
            w = w[:k] + w[k + 1:]
        else:
            k = rng.randrange(1, max(2, len(w)))
            w = w[:k] + rng.choice("וי") + w[k:]
    else:
        a, b = rng.choice(opts)
        k = w.index(a)
        w = w[:k] + b + w[k + 1:]
    ws[i] = _finals(w)
    out = " ".join(ws)
    return out if out != he else None


EN_SWAPS = [("tz", "ts"), ("tz", "z"), ("ch", "h"), ("kh", "h"), ("h", ""), ("c", "k"), ("k", "c"), ("ck", "k"),
            ("v", "w"), ("y", "j"), ("y", "i"), ("i", "y"), ("ph", "f"), ("ou", "u"), ("a", "e"), ("e", "a"),
            ("i", "e"), ("ss", "s"), ("s", "ss"), ("ch", "tch"), ("ich", "itch"), ("vich", "vitz"), ("ey", "ay"),
            ("oh", "o"), ("ee", "i"), ("aa", "a")]


def en_translit(rng, en):
    """The English spelling, re-spelled by ear: a couple of Hebrew-speaker transliteration slips."""
    s = en
    for _ in range(rng.choice([1, 2])):
        opts = [(a, b) for a, b in EN_SWAPS if a in s.lower()]
        if not opts:
            break
        a, b = rng.choice(opts)
        low = s.lower()
        k = low.index(a)
        s = s[:k] + b + s[k + len(a):]
    s = " ".join(w[:1].upper() + w[1:] for w in s.split())
    return s if s.lower() != en.lower() else None


def en_typo(rng, en):
    i, ws = _pick_word(rng, en)
    w = ws[i].lower()
    if len(w) < 3:
        return None
    j = rng.randrange(1, len(w))
    kind = rng.choice(["adjacent", "drop", "double", "swap"])
    if kind == "adjacent":
        near = [c for c in _adjacent(w[j]) if c.isalpha()]
        if not near:
            return None
        w = w[:j] + rng.choice(near) + w[j + 1:]
    elif kind == "drop":
        w = w[:j] + w[j + 1:]
    elif kind == "double":
        w = w[:j] + w[j] + w[j:]
    elif j < len(w) - 1:
        w = w[:j] + w[j + 1] + w[j] + w[j + 2:]
    ws[i] = w.capitalize()
    return " ".join(ws)


def extras(rng, he, en):
    kind = rng.choice(["prefix", "title", "title_en", "mixed", "hyphen", "spaces"])
    ws = he.split()
    if kind == "prefix":
        return rng.choice(["ל", "ו", "מ", "ה"]) + he if len(ws) == 2 else None
    if kind == "title":
        return rng.choice(['ד"ר ', 'עו"ד ', "הרב ", "מר "]) + he
    if kind == "title_en":
        return rng.choice(["Dr. ", "Mr. ", "Mrs. "]) + en
    if kind == "mixed":
        return ws[0] + " " + en.split()[-1]
    if kind == "hyphen":
        return "-".join(ws) if len(ws) >= 3 else None
    return "  " + "   ".join(ws).lower() + " "


KINDS = ("he_typo", "he_phonetic", "en_translit", "en_typo", "layout", "joined", "extras", "cyrillic")


def generate(seed=11):
    """-> [(kind, query, roster index)] — deterministic."""
    rng = random.Random(seed)
    out = []
    for idx, (he, en, cy, _lat) in enumerate(ROSTER):
        made = [("he_typo", he_typo(rng, he)), ("he_typo", he_typo(rng, he)),
                ("he_phonetic", he_phonetic(rng, he)), ("he_phonetic", he_phonetic(rng, he)),
                ("en_translit", en_translit(rng, en)), ("en_translit", en_translit(rng, en)),
                ("en_typo", en_typo(rng, en)),
                ("layout", typed_on_latin(he) if rng.random() < 0.7 else typed_on_hebrew(en)),
                ("joined", (he if rng.random() < 0.6 else en).replace(" ", "")),
                ("extras", extras(rng, he, en)),
                ("cyrillic", cy)]
        seen = set()
        for kind, q in made:
            if q and q not in seen and q not in (he, en):
                seen.add(q)
                out.append((kind, q, idx))
    return out


def _db(folder):
    from .config import Config
    from .engine import Engine
    from .importdb import import_db
    from .store import Store
    cfg = Config(db_path=os.path.join(folder, "q.db"), request_delay=0, workers=1)
    cfg.providers = []
    store = Store(cfg.db_path)
    eng = Engine(store, cfg, providers={})
    he = os.path.join(folder, "people.csv")
    with open(he, "w", encoding="utf-8") as f:
        f.write("שם מלא,טלפון נייד\n")
        for i, (h, _e, _c, _l) in enumerate(ROSTER):
            f.write(f"{h},05{2 + i % 7}{1000000 + i * 7919:07d}\n")
    import_db(eng, he, label="people", crawl_urls=False)
    lat = os.path.join(folder, "people_en.csv")
    with open(lat, "w", encoding="utf-8") as f:
        f.write("full name,mobile\n")
        for i, (_h, e, _c, also) in enumerate(ROSTER):
            if also:
                f.write(f"{e},05{2 + i % 7}{2000000 + i * 7919:07d}\n")
    import_db(eng, lat, label="people_en", crawl_urls=False)
    conf = os.path.join(folder, "lookalikes.csv")
    with open(conf, "w", encoding="utf-8") as f:
        f.write("שם מלא,טלפון נייד\n")
        for i, n in enumerate(CONFUSERS):
            f.write(f"{n},05{2 + i % 7}{3000000 + i * 7919:07d}\n")
    import_db(eng, conf, label="lookalikes", crawl_urls=False)
    store.reindex_names(100000)
    return store


def _targets(store):
    """roster index -> the identities that are this person (any script)."""
    from .xling import same_person_name
    from .textnorm import name_key
    rows = store.q("SELECT id, display FROM entities WHERE type='person'")
    out = defaultdict(set)
    for idx, (he, en, _c, _l) in enumerate(ROSTER):
        for r in rows:
            d = r["display"] or ""
            if name_key(d) in (name_key(he), name_key(en)) or same_person_name(d, he):
                out[idx].add(r["id"])
    return out


def search(store, query, k=20):
    """The search under test: the ranked people a typed name brings up (the same entry point the UI's name search
    and the dossier use)."""
    from .fuzzyname import find_people_any
    return [p["id"] for p in find_people_any(store, query, limit=k)]


def run(seed=11, keep=None):
    t0 = time.time()
    folder = keep or tempfile.mkdtemp(prefix="osnit_q_")
    store = _db(folder)
    targets = _targets(store)
    queries = generate(seed)
    per = defaultdict(lambda: [0, 0])
    misses = []
    top1 = 0
    for kind, q, idx in queries:
        got = search(store, q)[:5]
        ok = bool(targets[idx] & set(got))
        top1 += bool(got) and got[0] in targets[idx]
        per[kind][0] += 1
        per[kind][1] += ok
        if not ok:
            misses.append((kind, q, ROSTER[idx][0]))
    # a name that is not in the data — as typed and with a slip — must bring up nobody
    rng = random.Random(seed + 1)
    absent = list(ABSENT)
    for q in ABSENT:
        slip = he_typo(rng, q) if any("\u0590" <= c <= "\u05ff" for c in q) else en_typo(rng, q)
        if slip and slip not in absent:
            absent.append(slip)
    false_hits, false_list = 0, []
    for q in absent:
        got = search(store, q)[:5]
        if got:
            false_hits += 1
            false_list.append(q)
    total = sum(v[0] for v in per.values())
    found = sum(v[1] for v in per.values())
    return dict(queries=total, found_at_5=round(found / total, 4) if total else 0.0,
                found_at_1=round(top1 / total, 4) if total else 0.0,
                by_kind={k: round(per[k][1] / per[k][0], 3) for k in KINDS if per[k][0]},
                counts={k: per[k][0] for k in KINDS if per[k][0]},
                absent=len(absent), false_hit_rate=round(false_hits / len(absent), 4), false_hits=false_list,
                misses=misses[:40], took=round(time.time() - t0, 2))
