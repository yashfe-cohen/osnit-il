"""Identity-resolution benchmark: a synthetic Israeli population with KNOWN ground truth, run through the REAL import
pipeline, and scored on whether the records of one person end up together and the records of different people stay
apart — the identity counterpart of the extraction corpus eval.

Why synthetic: the operator's data is private and unlabelled. A seeded generator with realistic name frequencies (so
namesakes collide the way they do in Israel — several "יצחק כהן" in one small town), towns of different sizes,
households (including a grandfather and grandson with the SAME name at the same address and landline), moves,
nicknames, English transliterations, typos, both date formats and missing fields gives a reproducible, labelled
stress test.

Two levels are scored:
  auto     what the importer merged on its own (person entities). Rule 5: this must never join two different people,
           so `false_merges` must stay 0. Recall here is how much the personal identifiers already join.
  suggest  the possible-match layer (possible.py): every candidate it proposes for every identity, as a directional
           claim "c is the same person as e with probability p", scored against the truth — Brier score, how many of
           the true-but-unmerged pairs it surfaces at p >= 0.5, the precision of those, and INCOHERENCE: one identity
           claimed by two provably different people (different national IDs) with probabilities summing above 1.

`python -m osnit ereval` prints the summary as JSON; tools/gate.py holds the thresholds."""
import csv
import itertools
import os
import random
import tempfile
import time
from collections import defaultdict

from .extract import norm_phone_il
from .nicknames import nick_forms
from .quality import valid_email, valid_phone
from .semantic import email_key, il_id_ok
from .textnorm import is_hebrew
from .variants import token_forms

# relative weights for sampling only (approximate, so common names collide the way they do in Israel)
MALE = [("יצחק", 30), ("דוד", 30), ("משה", 28), ("יוסף", 26), ("אברהם", 22), ("יעקב", 20), ("מיכאל", 16),
        ("דניאל", 16), ("אליהו", 12), ("שמואל", 12), ("חיים", 12), ("מאיר", 10), ("אורי", 10), ("נועם", 9),
        ("איתי", 9), ("עומר", 8), ("יונתן", 8), ("אריאל", 8), ("רון", 7), ("גיל", 6)]
FEMALE = [("שרה", 24), ("רחל", 22), ("אסתר", 20), ("מיכל", 18), ("נועה", 16), ("תמר", 16), ("יעל", 14),
          ("רבקה", 14), ("מרים", 12), ("חנה", 12), ("שירה", 10), ("הילה", 8), ("מאיה", 8), ("דנה", 8), ("טל", 6)]
SURNAMES = [("כהן", 60), ("לוי", 40), ("מזרחי", 20), ("פרץ", 16), ("ביטון", 14), ("דהן", 12), ("אברהם", 12),
            ("פרידמן", 10), ("אזולאי", 10), ("מלכה", 9), ("כץ", 9), ("יוסף", 9), ("דוד", 8), ("עמר", 8),
            ("אוחיון", 7), ("חדד", 7), ("גבאי", 7), ("שפירא", 6), ("רוזן", 6), ("גולן", 6), ("ברק", 5), ("אלון", 5)]
TOWNS = [("ירושלים", 950), ("תל אביב", 470), ("חיפה", 285), ("ראשון לציון", 260), ("אשדוד", 225), ("נתניה", 220),
         ("באר שבע", 210), ("כפר סבא", 100), ("רעננה", 80), ("יבנה", 50), ("נתיבות", 40), ("שדרות", 35),
         ("אופקים", 35), ("גן יבנה", 26)]
STREETS = ["הרצל", "ויצמן", "רוטשילד", "ז'בוטינסקי", "הנשיא", "הגפן", "האלון", "החרוב", "בן גוריון", "ביאליק",
           "סוקולוב", "הרימון"]
_HEB = "אבגדהוזחטיכלמנסעפצקרשת"
_FEMALE_NAMES = {n for n, _ in FEMALE}

CONTACTS_H = ["שם מלא", "טלפון נייד", "עיר", "דואר אלקטרוני"]
REGISTRY_H = ["שם", "מספר זהות", "כתובת", "תאריך לידה", "טלפון בבית"]
MISC_H = ["name", "mobile", "city", "email"]

# the operator's own example, plus two more: several different people sharing one name in one town
NAMESAKES = (("יצחק", "כהן", "גן יבנה", 3), ("משה", "לוי", "נתיבות", 2), ("שרה", "כהן", "ירושלים", 3))


def _weighted(rng, items):
    tot = sum(w for _, w in items)
    x = rng.uniform(0, tot)
    for v, w in items:
        x -= w
        if x <= 0:
            return v
    return items[-1][0]


def _latin(he):
    for f in token_forms(he):
        if not is_hebrew(f) and f.isascii() and f.replace("'", "").isalpha():
            return f
    return None


class _Gen:
    def __init__(self, seed):
        self.rng = random.Random(seed)
        self.used = defaultdict(set)

    def mobile(self):
        r = self.rng
        while True:
            n = "05" + r.choice("02348") + "".join(r.choice("0123456789") for _ in range(7))
            k = norm_phone_il(n)
            if k and valid_phone(k) and k not in self.used["m"]:
                self.used["m"].add(k)
                return n[:3] + "-" + n[3:]

    def landline(self):
        r = self.rng
        while True:
            n = "0" + r.choice("23489") + "".join(r.choice("0123456789") for _ in range(7))
            k = norm_phone_il(n)
            if k and valid_phone(k) and k not in self.used["l"]:
                self.used["l"].add(k)
                return n[:2] + "-" + n[2:]

    def nid(self):
        r = self.rng
        while True:
            body = r.choice("123456789") + "".join(r.choice("0123456789") for _ in range(7))
            for d in "0123456789":
                v = body + d
                if il_id_ok(v):
                    if v not in self.used["n"]:
                        self.used["n"].add(v)
                        return v
                    break

    def email(self, fl, ll):
        r = self.rng
        dom = r.choice(["gmail.com", "walla.co.il", "hotmail.com", "yahoo.com"])
        for _ in range(60):
            e = f"{fl}.{ll}{r.randint(1, 999)}@{dom}"
            if valid_email(e) and email_key(e) not in self.used["e"]:
                self.used["e"].add(email_key(e))
                return e
        return None


def generate(seed=7, people=300):
    """-> (persons, files). files: {label: {"header": [...], "rows": [[...]], "gold": [person id per row]}}."""
    g = _Gen(seed)
    rng = g.rng
    persons = []

    def new(first=None, last=None, gender=None, town=None, birth_year=None, household=None):
        if gender is None:
            gender = ("F" if first in _FEMALE_NAMES else "M") if first else rng.choice("MF")
        fn = first or _weighted(rng, MALE if gender == "M" else FEMALE)
        ln = last or _weighted(rng, SURNAMES)
        t = town or _weighted(rng, TOWNS)
        by = birth_year or rng.randint(1940, 2004)
        p = dict(pid=len(persons), gender=gender, first=fn, last=ln, town=t, street=rng.choice(STREETS),
                 house=rng.randint(1, 120), mobile=g.mobile(), nid=g.nid(),
                 birth=(by, rng.randint(1, 12), rng.randint(1, 28)), landline=None, household=household,
                 prev_town=None, email=None)
        fl, ll = _latin(fn), _latin(ln)
        if fl and ll and rng.random() < 0.55:
            p["email"] = g.email(fl, ll)
        if rng.random() < 0.12:
            p["prev_town"] = _weighted(rng, [tw for tw in TOWNS if tw[0] != t])
        persons.append(p)
        return p

    for fn, ln, town, k in NAMESAKES:
        for _ in range(k):
            new(fn, ln, "F" if fn in _FEMALE_NAMES else "M", town)
    while len(persons) < people:
        if rng.random() < 0.25:
            head = new()
            head["household"], head["landline"] = head["pid"], g.landline()
            for _ in range(rng.randint(1, 3)):
                same = head["gender"] == "M" and rng.random() < 0.3      # a grandson named after his grandfather
                by = None
                if same:
                    y = head["birth"][0]
                    by = min(2006, y + rng.randint(45, 58)) if y < 1975 else max(1925, y - rng.randint(45, 58))
                m = new(first=head["first"] if same else None, last=head["last"], gender="M" if same else None,
                        town=head["town"], birth_year=by, household=head["pid"])
                m.update(street=head["street"], house=head["house"], landline=head["landline"],
                         prev_town=None if same else m["prev_town"])
        else:
            new()
    return persons, _files(rng, persons)


def _name(rng, p, kind):
    fn, ln = p["first"], p["last"]
    if kind == "reversed":
        return f"{ln} {fn}"
    if kind == "nickname":
        nk = [n for n in nick_forms(fn) if is_hebrew(n)]
        return f"{rng.choice(nk)} {ln}" if nk else f"{fn} {ln}"
    if kind == "latin":
        fl, ll = _latin(fn), _latin(ln)
        return f"{fl.title()} {ll.title()}" if fl and ll else f"{fn} {ln}"
    if kind == "typo":
        toks = [fn, ln]
        idx = [i for i, t in enumerate(toks) if len(t) >= 5]
        if idx:
            i = rng.choice(idx)
            t = toks[i]
            j = rng.randint(1, len(t) - 2)
            toks[i] = t[:j] + rng.choice([h for h in _HEB if h != t[j]]) + t[j + 1:]
            return " ".join(toks)
    return f"{fn} {ln}"


def _date(rng, b):
    y, m, d = b
    return f"{d:02d}/{m:02d}/{y}" if rng.random() < 0.6 else f"{y}-{m:02d}-{d:02d}"   # Israeli format and ISO


def _files(rng, persons):
    files = {"contacts": dict(header=CONTACTS_H, rows=[], gold=[]),
             "registry": dict(header=REGISTRY_H, rows=[], gold=[]),
             "misc": dict(header=MISC_H, rows=[], gold=[])}
    seen = defaultdict(dict)

    def add(label, row, p):
        key = tuple(row)
        other = seen[label].get(key)
        if other is not None and other != p["pid"]:
            return False                      # never two different people with a byte-identical row in one file
        seen[label][key] = p["pid"]
        files[label]["rows"].append(row)
        files[label]["gold"].append(p["pid"])
        return True

    for p in persons:
        made = 0
        if rng.random() < 0.7:
            kind = rng.choices(["formal", "reversed", "nickname", "typo"], [70, 10, 12, 8])[0]
            made += add("contacts", [_name(rng, p, kind), p["mobile"] if rng.random() < 0.85 else "",
                                     p["town"] if rng.random() < 0.9 else "",
                                     (p["email"] or "") if rng.random() < 0.7 else ""], p)
        if rng.random() < 0.6:
            made += add("registry", [_name(rng, p, rng.choices(["formal", "reversed"], [80, 20])[0]),
                                     p["nid"] if rng.random() < 0.9 else "",
                                     f"{p['street']} {p['house']}, {p['town']}" if rng.random() < 0.8 else "",
                                     _date(rng, p["birth"]) if rng.random() < 0.6 else "",
                                     (p["landline"] or "") if rng.random() < 0.8 else ""], p)
        if rng.random() < 0.5 or not made:
            kind = rng.choices(["latin", "nickname", "formal"], [55, 25, 20])[0]
            c = rng.random()
            made += add("misc", [_name(rng, p, kind), p["mobile"] if c < 0.6 else "",
                                 (p["prev_town"] or p["town"]) if rng.random() < 0.7 else "",
                                 (p["email"] or "") if c >= 0.4 else ""], p)
        if not made:
            add("contacts", [_name(rng, p, "formal"), p["mobile"], p["town"], ""], p)
    return files


# ------------------------------------------------------------------------------------------------------- evaluation
def _import(files, folder, chunk=500):
    from .config import Config
    from .engine import Engine
    from .importdb import import_db
    from .store import Store
    db = os.path.join(folder, "er.db")
    cfg = Config(db_path=db, request_delay=0, workers=1)
    cfg.providers = []
    store = Store(db)
    eng = Engine(store, cfg, providers={})
    for label, f in files.items():
        p = os.path.join(folder, f"{label}.csv")
        with open(p, "w", encoding="utf-8", newline="") as fh:
            w = csv.writer(fh)
            w.writerow(f["header"])
            w.writerows(f["rows"])
        import_db(eng, p, label=label, crawl_urls=False, chunk=chunk)
    return store


def _row_entities(store, files):
    """[(label, line, gold person, person entity or None)] — each generated row mapped to the identity it became."""
    out = []
    for label, f in files.items():
        # the importer writes every `chunk` (500) rows under a source of their own, with the line numbers running on
        # across the file: read every source of this file, not only the last (a big file lost all but its tail)
        srcs = [r["id"] for r in store.q("SELECT id FROM sources WHERE origin=?", (f"import:{label}",))]
        ents = {}
        for sid in srcs:
            for r in store.q("SELECT r.line, v.entity_id FROM records r CROSS JOIN evidence v ON v.record_id=r.id "
                             "CROSS JOIN entities e ON e.id=v.entity_id WHERE r.source_id=? AND e.type='person'",
                             (sid,)):
                ents.setdefault(r["line"], r["entity_id"])
        for i, pid in enumerate(f["gold"], 1):
            out.append((label, i, pid, ents.get(i)))
    return out


def _auto_scores(recs, persons):
    by_ent, by_gold = defaultdict(list), defaultdict(list)
    for i, (_, _, g, e) in enumerate(recs):
        if e is not None:
            by_ent[e].append(i)
            by_gold[g].append(i)
    tp = fp = namesake_fp = 0
    examples = []
    for items in by_ent.values():
        for a, b in itertools.combinations(items, 2):
            ga, gb = recs[a][2], recs[b][2]
            if ga == gb:
                tp += 1
                continue
            fp += 1
            pa, pb = persons[ga], persons[gb]
            if (pa["first"], pa["last"]) == (pb["first"], pb["last"]):
                namesake_fp += 1
            if len(examples) < 5:
                examples.append([f"{recs[a][0]}:{recs[a][1]}", f"{recs[b][0]}:{recs[b][1]}"])
    true_pairs = sum(len(v) * (len(v) - 1) // 2 for v in by_gold.values())
    bp = br = 0.0
    n = 0
    for e, items in by_ent.items():
        for i in items:
            gold = set(by_gold[recs[i][2]])
            inter = len(set(items) & gold)
            bp += inter / len(items)
            br += inter / len(gold)
            n += 1
    prec = tp / (tp + fp) if tp + fp else 1.0
    rec = tp / true_pairs if true_pairs else 1.0
    return dict(precision=round(prec, 4), recall=round(rec, 4),
                f1=round(2 * prec * rec / (prec + rec), 4) if prec + rec else 0.0,
                bcubed_precision=round(bp / n, 4) if n else 1.0, bcubed_recall=round(br / n, 4) if n else 1.0,
                false_merges=fp, namesake_false_merges=namesake_fp, false_merge_examples=examples,
                identities=len(by_ent), people=len(by_gold))


def _national_ids(store, eids):
    out = defaultdict(set)
    ids = list(eids)
    for i in range(0, len(ids), 900):
        part = ids[i:i + 900]
        ph = ",".join("?" * len(part))
        for r in store.q(f"SELECT r.a_id, r.b_id, o.key FROM relations r CROSS JOIN entities o "
                         f"ON o.id = CASE WHEN r.a_id IN ({ph}) THEN r.b_id ELSE r.a_id END "
                         f"WHERE (r.a_id IN ({ph}) OR r.b_id IN ({ph})) AND o.type IN ('national_id','id_number')",
                         (*part, *part, *part)):
            out[r["a_id"] if r["a_id"] in eids else r["b_id"]].add(r["key"])
    return out


def _suggest_scores(store, recs):
    from .possible import possible_matches
    gold_of = defaultdict(set)
    for _, _, g, e in recs:
        if e is not None:
            gold_of[e].add(g)
    claims = []                                           # (claimer e, candidate c, probability, truth)
    for e in sorted(gold_of):
        res = possible_matches(store, e) or {}
        for c in res.get("candidates", []):
            cid = c["id"]
            if cid in gold_of and c.get("decision") is None:
                claims.append((e, cid, float(c.get("probability", 0.0)), bool(gold_of[e] & gold_of[cid])))
    brier = sum((p - t) ** 2 for _, _, p, t in claims) / len(claims) if claims else 0.0
    best = {}
    for e, c, p, t in claims:
        k = (min(e, c), max(e, c))
        best[k] = max(best.get(k, 0.0), p)
    ents = sorted(gold_of)
    true_pairs = set()
    owners = defaultdict(set)
    for e in ents:
        for g in gold_of[e]:
            owners[g].add(e)
    for es in owners.values():
        for a, b in itertools.combinations(sorted(es), 2):
            true_pairs.add((a, b))
    found = sum(1 for k in true_pairs if best.get(k, 0.0) >= 0.5)
    # the operator's rule: two records are offered as one person only with a concrete detail in common (a town, a
    # phone, an email, an ID, ...), never on a name alone — recall is also measured over those ELIGIBLE pairs
    from . import matchmodel
    from .possible import _features
    fe = _features(store, sorted({x for k in true_pairs for x in k}))
    eligible = {(a, b) for a, b in true_pairs if matchmodel.in_common(matchmodel.compare(fe[a], fe[b], "exact"))}
    found_el = sum(1 for k in eligible if best.get(k, 0.0) >= 0.5)
    hi = [(e, c, p, t) for e, c, p, t in claims if p >= 0.5]
    nids = _national_ids(store, set(ents))
    by_cand = defaultdict(list)
    for e, c, p, _t in claims:
        by_cand[c].append((e, p))
    incoherent, worst = 0, 0.0
    for c, lst in by_cand.items():
        bad = False
        for (a, pa), (b, pb) in itertools.combinations(lst, 2):
            if nids.get(a) and nids.get(b) and not (nids[a] & nids[b]):      # provably different people
                worst = max(worst, pa + pb)
                bad = bad or pa + pb > 1.05
        incoherent += bad
    return dict(claims=len(claims), brier=round(brier, 4), true_unmerged_pairs=len(true_pairs),
                eligible_pairs=len(eligible),
                recall_eligible_at_05=round(found_el / len(eligible), 4) if eligible else 1.0,
                recall_at_05=round(found / len(true_pairs), 4) if true_pairs else 1.0,
                precision_at_05=round(sum(1 for *_, t in hi if t) / len(hi), 4) if hi else 1.0,
                incoherent=incoherent, worst_claim_sum=round(worst, 3))


def run(seed=7, people=300, suggest=True, keep=None, chunk=500):
    """Generate, import through the real pipeline, and score. -> summary dict (JSON-serialisable)."""
    t0 = time.time()
    persons, files = generate(seed, people)
    folder = keep or tempfile.mkdtemp(prefix="osnit_er_")
    store = _import(files, folder, chunk)
    recs = _row_entities(store, files)
    out = dict(seed=seed, people=len(persons), rows=len(recs), unlinked_rows=sum(1 for r in recs if r[3] is None),
               auto=_auto_scores(recs, persons))
    if suggest:
        out["suggest"] = _suggest_scores(store, recs)
    out["took"] = round(time.time() - t0, 2)
    return out
