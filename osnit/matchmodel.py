"""Is this the same person? A probabilistic identity model that reasons about NAMESAKES, with its parameters measured
on the operator's own data. Nothing here merges anything: it scores possibilities (possible.py) for the operator.

The question behind every candidate is: given that B is called the same as A, is B another record of A, or one of
the OTHER people who carry this name? So the starting odds of a same-name pair are

        expected other records of A's person (duplicates, delta)
        ----------------------------------------------------------------------------
        expected records of OTHER people with this name (namesakes, mu) x where B is

where "where B is" separates two very different situations: B in another file than A (the usual way one person
splits into several identities: each file knew a different identifier) and B in the SAME file (one file rarely lists
one person twice without a shared identifier, while namesakes share a file as often as the file's size says).
Every further detail multiplies the odds by how much more often it happens for the same person than for a namesake
(a likelihood ratio, in bits = log2):

    name      exact | spelling | nickname | different (different = reached only through a shared identifier)
    nid       same | different          national ID ("different" never reaches the operator: rule 5 excludes it)
    mobile    same | different          a mobile belongs to one person
    landline  same | different          a landline belongs to a HOUSEHOLD: weak evidence for one person
    email     same | local | different  local = the same mailbox name at another provider
    town      same | different          a namesake lives in town t as often as the data's people do (x clustering)
    address   same | different
    birth     same | year | different | far   full dates (DD/MM/YYYY, DD.MM.YYYY, YYYY-MM-DD) or a year; "far" = a
              generation or more apart (a typo moves a day or a digit, never 50 years: a same-name grandfather and
              grandson are two people)
    org       same | different

What is measured on the data (fit), and why it is robust:
  delta, mu   for each sampled identity, its block (the identities carrying its name in any spelling) is split into
              same-file and other-file candidates. Under n_same ~ Poisson(delta_same + beta * x * pi) and
              n_other ~ Poisson(delta_other + beta * x * (1 - pi)) — x: how many identities the name's words predict
              (the data's own word frequencies, smoothed toward osnit/data/population_il.json), pi: the share of the
              data in the identity's own files — a Poisson EM separates the duplicates (constant) from the namesakes
              (growing with the name's commonness, and landing in each file by its size). Same-file collisions pin the
              namesake rate, so the duplicate rate across files is not guessed. mu for a name blends the prediction
              with what its block actually shows.
  towns       each town's share of the data's people (smoothed toward its population share), times omega: how much
              more often KNOWN namesakes (two different national IDs, same name) share a town than chance — families
              and communities cluster.
  u (not-same) agreement rates measured on known namesakes (pairs of two different national IDs) and the operator's
              "not the same" decisions; m (same) on the operator's "same" decisions. Both smoothed toward defaults.
A field missing on either side is no evidence either way. The fit is cached in meta and refreshed when the data or
the operator's decisions change materially."""
import hashlib
import json
import math
import os
import re
import threading
import time
from functools import lru_cache

from .textnorm import fold, is_hebrew, name_key

FIELDS = ("nid", "mobile", "landline", "email", "address", "birth", "org")   # + name, town and file: below
LEVELS = {"nid": ("same", "different"), "mobile": ("same", "different"), "landline": ("same", "different"),
          "email": ("same", "local", "different"), "address": ("same", "different"),
          "birth": ("same", "year", "different", "far"), "org": ("same", "different")}
# P(level | same person), P(level | a namesake) — only their ratio matters
DEFAULT_M = {"nid": {"same": 0.999, "different": 0.001}, "mobile": {"same": 0.6, "different": 0.4},
             "landline": {"same": 0.5, "different": 0.5}, "email": {"same": 0.5, "local": 0.1, "different": 0.4},
             "address": {"same": 0.6, "different": 0.4}, "birth": {"same": 0.9, "year": 0.06, "different": 0.0395, "far": 0.0005},
             "org": {"same": 0.4, "different": 0.6}}
DEFAULT_U = {"nid": {"same": 0.0001, "different": 0.9999}, "mobile": {"same": 0.001, "different": 0.999},
             "landline": {"same": 0.02, "different": 0.98},
             "email": {"same": 0.0005, "local": 0.003, "different": 0.9965},
             "address": {"same": 0.01, "different": 0.99}, "birth": {"same": 0.0005, "year": 0.0013, "different": 0.15, "far": 0.85},
             "org": {"same": 0.05, "different": 0.95}}
AGREE = {("nid", "same"), ("mobile", "same"), ("landline", "same"), ("email", "same"), ("email", "local"),
         ("address", "same"), ("birth", "same"), ("birth", "year"), ("org", "same")}
HOUSEHOLD = {("town", "same"), ("address", "same"), ("landline", "same")}   # one fact: they live together
TOWN_M_SAME = 0.9                         # one person's two records name the same town (moves and errors aside)
NAME_ADJ = {"exact": 0.0, "spelling": -0.3, "nickname": -1.0}   # bits, relative to an exact name
NAME_DIFFERENT_BITS = -7.0                 # a different name, met only through a shared identifier
DEFAULT_DELTA_SAME, DEFAULT_DELTA_OTHER, DEFAULT_BETA = 0.1, 0.6, 1.0
DEFAULT_FILE_SHARE = 0.5                   # an unmeasured file's share of the data
TOKEN_PSEUDO, TOWN_PSEUDO = 200, 20        # smoothing toward the population tables, in pseudo-identities
NAMESAKE_SHRINK = 1.0                      # weight of the predicted namesakes vs. the block's own count
ALPHA_M, ALPHA_U = 10.0, 30.0              # Dirichlet pseudo-counts toward the defaults for labelled pairs
PRIOR_CLIP = 10.0
MIN_FIT_IDS_FOR_DUP = 40                   # below this, keep the default delta / beta
MAX_FIT_IDS = 1500                         # identities sampled to fit (deterministic), whatever the DB size
MIN_FIT_IDS, FIT_BUDGET = 400, 8.0         # past MIN_FIT_IDS, stop sampling after FIT_BUDGET seconds
RECHECK_SECONDS = 60                       # how often a changing DB is re-checked for a refit
META_KEY = "matchmodel_v3"            # v3: birth "far" level, household counted once

_LOCK = threading.Lock()
_POP_FILE = os.path.join(os.path.dirname(__file__), "data", "population_il.json")


# ------------------------------------------------------------------------------------------- population priors
def _norm(s):
    return re.sub(r"\s+", " ", fold(s or "").replace("-", " ")).strip()


@lru_cache(maxsize=1)
def _pop():
    with open(_POP_FILE, encoding="utf-8") as f:
        d = json.load(f)
    norm = lambda m: {_norm(k): float(v) for k, v in m.items()}
    return dict(total=float(d["population_total"]), towns=norm(d["towns"]), first=norm(d["first_names"]),
                last=norm(d["surnames"]), **{k: float(v) for k, v in d["defaults"].items()})


@lru_cache(maxsize=8192)
def token_family(tok):
    """The folded spellings of one name word in both scripts, with its nicknames / formal name, from the dictionaries
    only ('יצחק' -> יצחק, yitzhak, איציק, itzik…). Rule-based guesses are left out: they would count unrelated
    words."""
    from .nicknames import nick_forms
    from .variants import _FOLDED, _REVERSE
    f = fold(tok).lower()
    heb = [f] if is_hebrew(f) else [fold(h) for h in _REVERSE.get(f, [])[:2]]
    try:
        heb += [fold(n) for n in nick_forms(tok) if is_hebrew(n)]
    except Exception:
        pass
    fam = {f}
    for h in heb:
        fam.add(h)
        fam.update(fold(e).lower() for e in _FOLDED.get(h, []))
    return tuple(sorted(fam))


def token_population_share(tok):
    """Share of the population whose name contains this word (as a first name or a surname; nicknames map to the
    full name). Unknown words get the conservative default."""
    p = _pop()
    best = 0.0
    for h in token_family(tok):
        best = max(best, p["first"].get(h, 0.0), p["last"].get(h, 0.0))
    if not best:
        try:
            from .nicknames import nick_forms
            for n in nick_forms(tok):
                best = max(best, p["first"].get(fold(n), 0.0))
        except Exception:
            pass
    return best or max(p["first_name_share"], p["surname_share"])


def town_population_share(town):
    p = _pop()
    return p["towns"].get(_norm(town), p["town_population"]) / p["total"]


def _name_words(name):
    return [t for t in dict.fromkeys((name_key(name) or "").split()) if len(t) >= 2]


# -------------------------------------------------------------------------------------------------- comparisons
_DATE_PATTERNS = (re.compile(r"^(\d{4})-(\d{1,2})-(\d{1,2})"), re.compile(r"^(\d{1,2})[/.](\d{1,2})[/.](\d{4})"),
                  re.compile(r"^(\d{4})$"))


def iso_date(v):
    """'15/03/1979' | '15.03.1979' | '1979-03-15' | '1979' -> '1979-03-15' | '1979'; None when not a date."""
    s = str(v or "").strip()
    for i, rx in enumerate(_DATE_PATTERNS):
        m = rx.match(s)
        if not m:
            continue
        if i == 2:
            return m.group(1) if 1900 <= int(m.group(1)) <= 2100 else None
        y, mo, d = (m.group(1), m.group(2), m.group(3)) if i == 0 else (m.group(3), m.group(2), m.group(1))
        if 1 <= int(mo) <= 12 and 1 <= int(d) <= 31:
            return f"{int(y):04d}-{int(mo):02d}-{int(d):02d}"
    return None


def _mobiles(f):
    from .store import is_personal_identifier
    return {k for t, k in f["ids"] if t == "phone" and is_personal_identifier(t, k)}


def _landlines(f):
    from .store import is_personal_identifier
    return {k for t, k in f["ids"] if t == "phone" and not is_personal_identifier(t, k)}


def name_level(name_a, name_b, key_a=None, key_b=None):
    """exact | spelling | nickname | different."""
    from .identity import _name_matches
    from .nicknames import names_nick_match
    ka = key_a or name_key(name_a)
    kb = key_b or name_key(name_b)
    if ka and ka == kb:
        return "exact"
    if _name_matches(name_a or ka, name_b or kb):
        return "spelling"
    if names_nick_match(name_a or ka, name_b or kb):
        return "nickname"
    ta, tb = set(ka.split()), set(kb.split())
    short, long_ = (ta, tb) if len(ta) <= len(tb) else (tb, ta)
    if len(short) >= 2 and short < long_:
        return "nickname"                                  # an extra / missing middle name
    return "different"


FAR_BIRTH_YEARS = 12          # beyond a slipped decade digit: no typo, another generation


def _birth_level(ba, bb):
    full_a, full_b = {d for d in ba if len(d) == 10}, {d for d in bb if len(d) == 10}
    ya, yb = {int(d[:4]) for d in ba}, {int(d[:4]) for d in bb}
    if ya & yb:
        if full_a and full_b:
            return "same" if full_a & full_b else "different"   # same year, another day: a typo is in m(different)
        return "year"
    gap = min(abs(x - y) for x in ya for y in yb)
    return "far" if gap >= FAR_BIRTH_YEARS else "different"


def compare(fa, fb, level_name):
    """{field: level} for the fields present on both sides (features from possible._features)."""
    g = {"name": level_name}
    if fa["nids"] and fb["nids"]:
        g["nid"] = "same" if fa["nids"] & fb["nids"] else "different"
    ma, mb = _mobiles(fa), _mobiles(fb)
    if ma and mb:
        g["mobile"] = "same" if ma & mb else "different"
    la, lb = _landlines(fa), _landlines(fb)
    if la and lb:
        g["landline"] = "same" if la & lb else "different"
    if fa["emails"] and fb["emails"]:
        if fa["emails"] & fb["emails"]:
            g["email"] = "same"
        else:
            loc = lambda es: {e.split("@")[0].replace(".", "") for e in es}
            g["email"] = "local" if loc(fa["emails"]) & loc(fb["emails"]) else "different"
    if fa["cities"] and fb["cities"]:
        g["town"] = "same" if fa["cities"] & fb["cities"] else "different"
    if fa["addresses"] and fb["addresses"]:
        g["address"] = "same" if fa["addresses"] & fb["addresses"] else "different"
    ba = {d for d in (iso_date(x) for x in fa["birth"]) if d}
    bb = {d for d in (iso_date(x) for x in fb["birth"]) if d}
    if ba and bb:
        g["birth"] = _birth_level(ba, bb)
    if fa["orgs"] and fb["orgs"]:
        g["org"] = "same" if fa["orgs"] & fb["orgs"] else "different"
    if fa.get("srcs") and fb.get("srcs"):
        g["file"] = "same" if fa["srcs"] & fb["srcs"] else "different"   # part of the starting odds, not a field
    return g


# ---------------------------------------------------------------------------------------------------- the model
class Model:
    def __init__(self, delta_same=DEFAULT_DELTA_SAME, delta_other=DEFAULT_DELTA_OTHER, beta=DEFAULT_BETA, m=None,
                 u=None, towns=None, town_n=0, omega=1.0, files=None, fitted=False, pairs=0, sig=None, ids=0):
        self.delta_same, self.delta_other, self.beta = delta_same, delta_other, beta
        self.m = {f: dict(v) for f, v in (m or DEFAULT_M).items()}
        self.u = {f: dict(v) for f, v in (u or DEFAULT_U).items()}
        self.towns, self.town_n, self.omega = dict(towns or {}), town_n, omega
        self.files = {str(k): v for k, v in (files or {}).items()}
        self.fitted, self.pairs, self.sig, self.ids = fitted, pairs, sig, ids

    @property
    def delta(self):
        return self.delta_same + self.delta_other

    def to_json(self):
        return dict(delta_same=self.delta_same, delta_other=self.delta_other, beta=self.beta, m=self.m, u=self.u,
                    towns=self.towns, town_n=self.town_n, omega=self.omega, files=self.files, fitted=self.fitted,
                    pairs=self.pairs, sig=self.sig, ids=self.ids)

    @classmethod
    def from_json(cls, d):
        return cls(d["delta_same"], d["delta_other"], d["beta"], d["m"], d["u"], d.get("towns"), d.get("town_n", 0),
                   d.get("omega", 1.0), d.get("files"), d.get("fitted", False), d.get("pairs", 0), d.get("sig"),
                   d.get("ids", 0))

    def summary(self):
        return dict(fitted=self.fitted, identities=self.ids, pairs=self.pairs,
                    duplicates_other_files=round(self.delta_other, 3), duplicates_same_file=round(self.delta_same, 3),
                    namesake_scale=round(self.beta, 3), town_clustering=round(self.omega, 2))

    def file_share(self, srcs):
        """pi: the share of the data's identities that sit in these files (where a namesake of A lands with A)."""
        if not srcs:
            return 0.0
        tiny = 1.0 / max((self.sig or [1])[0], 1)
        default = DEFAULT_FILE_SHARE if not self.fitted else tiny
        return min(0.95, sum(self.files.get(str(x), default) for x in srcs))

    def town_share(self, town):
        """P(a namesake lives in this town): the town's share of the data's people (smoothed toward its population
        share) times the clustering of namesakes."""
        d = (self.towns.get(town, 0) + TOWN_PSEUDO * town_population_share(town)) / (self.town_n + TOWN_PSEUDO)
        return min(0.9, self.omega * d)

    def field_bits(self, f, lv):
        return math.log2(self.m[f][lv] / self.u[f][lv])

    def name_prior_bits(self, mu, same_file, pi):
        """log2 of the starting odds of a same-name pair: duplicates vs. namesakes, where B is."""
        if same_file:
            odds = self.delta_same / max(mu * max(pi, 1e-3), 1e-6)
        else:
            odds = self.delta_other / max(mu * max(1.0 - pi, 0.05), 1e-6)
        return max(-PRIOR_CLIP, min(PRIOR_CLIP, math.log2(odds)))


def prob(log_odds):
    return 1.0 / (1.0 + 2.0 ** (-max(-60.0, min(60.0, log_odds))))


def _clip(x):
    return min(max(x, 1e-6), 1 - 1e-6)


# ------------------------------------------------------------------------------------------- one identity's view
_LABEL_FOR = {("landline", "same"): "טלפון קווי משותף (אותו בית?)", ("email", "local"): "אותו שם משתמש במייל",
              ("address", "same"): "אותה כתובת", ("birth", "same"): "אותו תאריך לידה",
              ("birth", "year"): "אותה שנת לידה", ("org", "same"): "אותו ארגון"}
_LABEL_AGAINST = {("mobile", "different"): "ניידים שונים", ("address", "different"): "כתובות שונות",
                  ("birth", "different"): "תאריכי לידה שונים", ("birth", "far"): "שנות לידה רחוקות (דור אחר)",
                  ("email", "different"): "מיילים שונים",
                  ("landline", "different"): "טלפונים קוויים שונים", ("org", "different"): "ארגונים שונים"}


def _town_display(folded):
    if not folded:
        return ""
    from .semantic import CITIES_EN, CITIES_HE
    for c in list(CITIES_HE) + list(CITIES_EN):
        if _norm(c) == _norm(folded):
            return c.strip()
    return folded


class Scorer:
    """Scores the candidates of ONE identity: how many namesakes to expect for its name (the data's word frequencies
    and its own block), then every candidate's evidence on top."""

    def __init__(self, store, mod, me, fa, token_counts=None):
        from .store import person_base_key
        self.store, self.mod, self.fa = store, mod, fa
        self.na = me.get("display") or person_base_key(me.get("key") or "")
        self.ka = person_base_key(me.get("key") or "") or name_key(self.na)
        self._tc = token_counts if token_counts is not None else {}
        self.pi = mod.file_share(fa.get("srcs"))

    # -- how common is this name in the data
    def _token_count(self, tok):
        if tok not in self._tc:
            n = 0
            for f in token_family(tok):
                n += self.store.q1("SELECT COUNT(*) n FROM (SELECT 1 FROM name_index WHERE skel=? LIMIT 50001)",
                                   ("t:" + f,))["n"]
            self._tc[tok] = n
        return self._tc[tok]

    def predicted_namesakes(self, name=None):
        """x: how many identities a name's words predict, from the data's own word frequencies (smoothed toward the
        population's), under independence of the words."""
        total = max((self.mod.sig or [0])[0], 1)
        cover = _index_coverage(self.store)
        share = 1.0
        words = _name_words(name or self.na or self.ka)
        if len(words) < 2:
            return float(total)                          # a single word is no full name: anyone could carry it
        for t in words:
            c = self._token_count(t) / cover
            share *= (c + TOKEN_PSEUDO * token_population_share(t)) / (total + TOKEN_PSEUDO)
        return total * share

    def namesakes(self, block_count):
        """mu: the expected identities of OTHER people with this name — the prediction, blended with what the block
        actually holds beyond the expected duplicates."""
        pred = self.mod.beta * self.predicted_namesakes()
        seen = max(block_count - self.mod.delta, 0.0)  # what the block holds beyond the expected duplicates
        return max((NAMESAKE_SHRINK * pred + seen) / (NAMESAKE_SHRINK + 1.0), 1e-3)

    # -- levels and scores
    def levels(self, cands, feats):
        """-> (namesake count in the block, [(cid, levels, shared towns)])."""
        from .store import person_base_key
        rows = []
        for cid, c in cands.items():
            fb = feats.get(cid)
            if fb is None:
                continue
            nb = c.get("display") or person_base_key(c.get("key") or "")
            kb = person_base_key(c.get("key") or "") or name_key(nb)
            g = compare(self.fa, fb, name_level(self.na, nb, self.ka, kb))
            rows.append((cid, g, self.fa["cities"] & fb["cities"]))
        return sum(1 for _c, g, _t in rows if g["name"] != "different"), rows

    def evidence(self, g, common, mu):
        """[(bits, field, level, label)] for one pair, the name's starting odds first."""
        mod, out = self.mod, []
        lv = g["name"]
        if lv == "different":
            out.append((NAME_DIFFERENT_BITS, "name", lv, "שם שונה"))
        else:
            same_file = g.get("file") == "same"
            b = mod.name_prior_bits(mu, same_file, self.pi) + NAME_ADJ[lv]
            word = {"exact": "שם זהה", "spelling": "אותו שם בכתיב אחר", "nickname": "כינוי / שם אמצעי נוסף"}[lv]
            if mu <= mod.delta / 3:
                word += " (שם נדיר)"
            out.append((max(b, 0.01), "name", lv, word))
            if b < 0:
                out.append((b - 0.01, "name", "common",
                            "שתי רשומות באותו קובץ" if same_file and mod.name_prior_bits(mu, False, self.pi) >= 0
                            else "שם נפוץ: צפויים עוד אנשים בשם זה"))
        if "town" in g:
            towns = sorted(common) or sorted(self.fa["cities"])
            if g["town"] == "same":
                t = max(towns, key=mod.town_share)
                u = mod.town_share(t)
                out.append((math.log2(TOWN_M_SAME / u), "town", "same", f"אותה עיר: {_town_display(t)}"))
            else:
                u = max(mod.town_share(t) for t in self.fa["cities"])
                out.append((math.log2((1 - TOWN_M_SAME) / (1 - u)), "town", "different", "ערים שונות"))
        for f in FIELDS:
            lv = g.get(f)
            if lv is None:
                continue
            out.append((mod.field_bits(f, lv), f, lv, _LABEL_FOR.get((f, lv)) or _LABEL_AGAINST.get((f, lv)) or ""))
        # the same town, the same address and the same home landline are ONE fact — they live together — not three
        # independent ones (an address contains its town; a landline rings at an address). Counted once, by the
        # strongest: otherwise a household (a grandfather and his same-name grandson) looks like one person.
        home = [i for i, (b, f, lv, _l) in enumerate(out) if (f, lv) in HOUSEHOLD and b > 0]
        if len(home) > 1:
            keep = max(home, key=lambda i: out[i][0])
            out = [(0.0, f, lv, lab) if i in home and i != keep else (b, f, lv, lab)
                   for i, (b, f, lv, lab) in enumerate(out)]
        return out

    def score_all(self, cands, feats):
        """-> {cid: dict(log_odds, probability, levels, reasons, against, namesakes)}, reasons strongest first."""
        from .store import person_base_key
        n, rows = self.levels(cands, feats)
        mu_me = self.namesakes(n)
        out = {}
        for cid, g, common in rows:
            fb = feats[cid]
            mu = mu_me
            if g["name"] in ("spelling", "nickname"):          # Sara Levi / Avrimi Amar: the formal name's pool
                c = cands[cid]
                mu = max(mu, self.mod.beta * self.predicted_namesakes(
                    c.get("display") or person_base_key(c.get("key") or "")))
            ev = self.evidence(g, common, mu)
            in_town = (mu * self.mod.town_share(max(sorted(common), key=self.mod.town_share))
                       if g.get("town") == "same" else None)
            lo = sum(b for b, *_ in ev)
            pro, con = [], []
            shared = sorted((self.fa["nids"] & fb["nids"]) | (_mobiles(self.fa) & _mobiles(fb))
                            | (self.fa["emails"] & fb["emails"]))
            if shared:
                pro.append((99.0, "מזהה אישי משותף: " + ", ".join(shared)[:80]))   # the UI and dossier key on this
            for b, f, lv, label in ev:
                if not label or (f in ("nid", "mobile", "email") and lv == "same"):
                    continue
                (pro if b > 0 or (f, lv) in HOUSEHOLD else con).append((abs(b), label))
            pro.sort(key=lambda x: -x[0])
            con.sort(key=lambda x: -x[0])
            out[cid] = dict(log_odds=round(lo, 2), probability=round(prob(lo), 3), levels=g, namesakes=round(mu, 2),
                            namesakes_in_town=None if in_town is None else round(in_town, 2),
                            reasons=[t for _, t in pro], against=[t for _, t in con])
        return out


def _index_coverage(store):
    """The share of people already in the per-word name index (it is built in the background after an import), so
    word counts are not mistaken for rare while it catches up."""
    try:
        hwm = int(store.meta_get(store._NAME_HWM) or 0)
        top = store.q1("SELECT MAX(id) m FROM entities WHERE type='person'")["m"] or 0
        return 1.0 if not top or hwm >= top else max(hwm / top, 0.05)
    except Exception:
        return 1.0


# ------------------------------------------------------------------------------------------ fitting and caching
def fit_duplicates(obs, iters=400):
    """obs: [(n_same_file, n_other_files, x, pi)] per identity, with
         n_same  ~ Poisson(delta_same  + beta * x * pi)
         n_other ~ Poisson(delta_other + beta * x * (1 - pi))
    A Poisson EM (each count split into duplicates and namesakes). -> (delta_same, delta_other, beta)."""
    if len(obs) < MIN_FIT_IDS_FOR_DUP or not any(a or b for a, b, _x, _p in obs):
        return DEFAULT_DELTA_SAME, DEFAULT_DELTA_OTHER, DEFAULT_BETA
    ds, do, b = 0.1, 0.5, 1.0
    sx = sum(x for _a, _b, x, _p in obs) or 1e-9
    n = len(obs)
    for _ in range(iters):
        dsum_s = dsum_o = esum = 0.0
        for ns, no, x, pi in obs:
            if ns:
                lam = ds + b * x * pi
                dsum_s += ns * ds / lam
                esum += ns * b * x * pi / lam
            if no:
                lam = do + b * x * (1.0 - pi)
                dsum_o += no * do / lam
                esum += no * b * x * (1.0 - pi) / lam
        nds, ndo, nb = max(dsum_s / n, 0.005), max(dsum_o / n, 0.02), max(esum / sx, 1e-3)
        done = abs(nds - ds) + abs(ndo - do) + abs(nb - b) < 1e-7
        ds, do, b = nds, ndo, nb
        if done:
            break
    return ds, do, b


def _signature(store):
    r = store.q1("SELECT COUNT(*) n FROM entities WHERE type='person'")
    d = store.q1("SELECT COUNT(*) n FROM identity_links")
    return [r["n"] or 0, d["n"] or 0]


def _stale(sig, cur):
    if not sig or len(sig) < 2:
        return True
    n0, n1 = sig[0], cur[0]
    return abs(n1 - n0) >= max(50, 0.1 * n0) or abs(cur[1] - sig[1]) >= 20


def _sample(store, total):
    """A deterministic sample of identities spread over the whole id range, in a hash order (so a time budget that
    stops early still covers old and new data alike)."""
    if total <= MAX_FIT_IDS:
        rows = [dict(r) for r in store.q("SELECT id, key, display FROM entities WHERE type='person'")]
    else:
        hi = store.q1("SELECT MAX(id) m FROM entities")["m"] or 0
        rows, seen = [], set()
        for i in range(MAX_FIT_IDS):
            r = store.q1("SELECT id, key, display FROM entities WHERE id >= ? AND type='person' ORDER BY id LIMIT 1",
                         (1 + hi * i // MAX_FIT_IDS,))
            if r and r["id"] not in seen:
                seen.add(r["id"])
                rows.append(dict(r))
    return sorted(rows, key=lambda r: hashlib.md5(str(r["id"]).encode()).digest())


def _all_features(store, ids):
    from .possible import _features
    out, ids = {}, list(ids)
    for i in range(0, len(ids), 400):
        out.update(_features(store, ids[i:i + 400]))
    return out


def _dirichlet(default, counts, alpha, agree_field):
    out = {}
    tot = sum(counts.values())
    for lv, p in default.items():
        out[lv] = _clip((counts.get(lv, 0.0) + alpha * p) / (tot + alpha))
    return out


def fit(store, sig=None, budget=FIT_BUDGET):
    """Measure the model on a sample of identities, through the same blocking the possible-match view uses."""
    from .possible import block
    sig = sig or _signature(store)
    if sig[0] < 3:
        return Model(sig=sig)
    try:
        store.reindex_names(5000, blocking=False)
    except Exception:
        pass
    t0 = time.time()
    ents, blocks = {}, []
    for i, me in enumerate(_sample(store, sig[0])):
        if i >= MIN_FIT_IDS and time.time() - t0 > budget:
            break
        ents[me["id"]] = me
        cand, _via = block(store, me)
        blocks.append((me["id"], cand))
        for cid, c in cand.items():
            ents.setdefault(cid, c)
    decisions = [dict(r) for r in store.q("SELECT a, b, decision FROM identity_links LIMIT 5000")]
    missing = {x for r in decisions for x in (r["a"], r["b"]) if x not in ents}
    if missing:
        for r in store.q("SELECT id, key, display FROM entities WHERE id IN (%s)" %
                         ",".join(str(int(x)) for x in missing)):
            ents[r["id"]] = dict(r)
    feats = _all_features(store, ents)
    file_counts, sampled = {}, 0
    for a, _cand in blocks:
        if a in feats:
            sampled += 1
            for x in feats[a]["srcs"]:
                file_counts[x] = file_counts.get(x, 0) + 1
    files = {str(k): v / max(sampled, 1) for k, v in sorted(file_counts.items(), key=lambda kv: -kv[1])[:2000]}
    base = Model(sig=sig, files=files, fitted=True)
    tc = {}
    obs, pairs, seen = [], [], set()
    town_counts, town_n = {}, 0
    for a, cand in blocks:
        fa = feats.get(a)
        if fa is None:
            continue
        if fa["cities"]:
            town_n += 1
            for t in fa["cities"]:
                town_counts[t] = town_counts.get(t, 0) + 1
        sc = Scorer(store, base, ents[a], fa, tc)
        _n, rows = sc.levels(cand, feats)
        named = [g for _c, g, _t in rows if g["name"] != "different"]
        obs.append((sum(1 for g in named if g.get("file") == "same"), sum(1 for g in named if g.get("file") != "same"),
                    sc.predicted_namesakes(), sc.pi))
        for cid, g, common in rows:
            k = (min(a, cid), max(a, cid))
            if k not in seen:
                seen.add(k)
                pairs.append((k, g, common))
    delta_same, delta_other, beta = fit_duplicates(obs)
    mod = Model(delta_same, delta_other, beta, towns=town_counts, town_n=town_n, files=files, sig=sig, fitted=True,
                pairs=len(pairs), ids=len(obs))
    # namesake clustering in towns, from the KNOWN namesakes (two different national IDs)
    obs = exp = 0.0
    for (a, b), g, common in pairs:
        if g.get("nid") == "different" and g.get("town") and feats[a]["cities"]:
            obs += g["town"] == "same"
            exp += min(1.0, sum(mod.town_share(t) for t in feats[a]["cities"]))
    mod.omega = max(0.5, min(30.0, (obs + 2.0) / (exp + 2.0)))
    # u from known namesakes and "not the same" decisions, m from "same" decisions
    dec = {(min(r["a"], r["b"]), max(r["a"], r["b"])): r["decision"] for r in decisions}
    by_pair = {k: g for k, g, _c in pairs}
    for k in dec:
        if k not in by_pair and k[0] in feats and k[1] in feats:
            nm = Scorer(store, base, ents[k[0]], feats[k[0]], tc)
            _n, rows = nm.levels({k[1]: ents[k[1]]}, feats)
            if rows:
                by_pair[k] = rows[0][1]
    mc = {f: {} for f in FIELDS}
    uc = {f: {} for f in FIELDS}
    for k, g in by_pair.items():
        d = dec.get(k)
        target = mc if d == "same" else uc if (d == "different" or g.get("nid") == "different") else None
        if target is None:
            continue
        for f in FIELDS:
            lv = g.get(f)
            if lv is not None and f != "nid":
                target[f][lv] = target[f].get(lv, 0.0) + 1.0
    for f in FIELDS:
        mod.m[f] = _dirichlet(DEFAULT_M[f], mc[f], ALPHA_M, f)
        mod.u[f] = _dirichlet(DEFAULT_U[f], uc[f], ALPHA_U, f)
        for lv in LEVELS[f]:                      # an agreement never counts against, a conflict never for
            if ((f, lv) in AGREE) == (mod.m[f][lv] < mod.u[f][lv]):
                mod.m[f][lv] = mod.u[f][lv]
    return mod


def get_model(store):
    """The fitted model for this data: cached in memory and in meta, refitted when the data or the operator's
    decisions changed materially (checked at most every RECHECK_SECONDS while the data keeps changing)."""
    now = time.time()
    with _LOCK:
        c = getattr(store, "_matchmodel", None)
        if c is not None and (c[1] == store.data_version or now - c[2] < RECHECK_SECONDS):
            return c[0]
        cur = _signature(store)
        if c is not None and not _stale(c[0].sig, cur):
            store._matchmodel = (c[0], store.data_version, now)
            return c[0]
        mod = None
        try:
            raw = store.meta_get(META_KEY)
            mod = Model.from_json(json.loads(raw)) if raw else None
        except Exception:
            mod = None
        if mod is None or _stale(mod.sig, cur):
            mod = fit(store, cur)
            try:
                store.meta_set(META_KEY, json.dumps(mod.to_json(), ensure_ascii=False))
            except Exception:
                pass
        store._matchmodel = (mod, store.data_version, now)
        return mod


def invalidate(store):
    """Forget the fit, so the next call refits (e.g. after a bulk change of decisions)."""
    with _LOCK:
        store._matchmodel = None
        try:
            store.meta_set(META_KEY, "")
        except Exception:
            pass
