"""Relations between two people stated in free text: "דנה גל עבדה עם רון כהן", "יוסי לוי, שותפו של משה כהן",
"עו"ד שרה לוי ייצגה את דוד ביטון", "Michael Levin worked with Daniel Cohen".

Precision-first, no statistical NER — a relation is taken only when ALL of this holds:
  * both sides are people the system already accepts: a person the extractor recognised in this text, a name that
    already exists as a person in the database (`known`), or the record's owner (`owner`, for a note column);
  * the two are in ONE sentence, and what stands between them is exactly one relation phrase from a closed list
    (plus commas / spaces) — "X לא עבדה עם Y", "X said he never worked with Y" do not match;
  * a plural form ("X ו-Y עבדו יחד", "X and Y are partners") needs both names joined by ו / and, right before it.

Kinds (stored as relations "text:<kind>", the sentence as evidence):
  symmetric  colleague · partner · spouse · adversary
  directed   represents (X represents Y) · manages (X manages Y) · deputy (X is Y's deputy)
"X כפוף ל-Y" is stored as Y manages X, "X יוצג על ידי Y" as Y represents X.

This runs AFTER extraction as its own pass (like sensitive.py), so the labelled extraction evals are untouched; it
has its own labelled corpus (tests/relcorpus) and gate (`python -m osnit releval`)."""
import json
import os
import re

from .textnorm import name_key

DIRECTED = ("text:represents", "text:manages", "text:deputy")

_HE = "א-ת"
# (kind, swap, phrase) — the phrase must be the WHOLE gap between the two names (commas/spaces around it allowed)
_CUES = [
    ("colleague", False, r"עבד(?:ה)?\s+(?:יחד\s+)?עם|עובד(?:ת)?\s+(?:יחד\s+)?עם|עבד(?:ה)?\s+לצד|"
                         r"עמית(?:ו|ה|תו|תה)?\s+(?:ל?עבודה\s+)?של|"
                         r"(?:has\s+)?work(?:ed|s)\s+(?:closely\s+)?(?:alongside|with)|(?:a\s+)?colleague\s+of"),
    ("partner", False, r"שות(?:פו|פה|פתו|פתה)\s+(?:העסקי(?:ת)?\s+)?של|שות(?:ף|פה)\s+(?:עסקי(?:ת)?\s+)?(?:של|עם)|"
                       r"(?:הקים|הקימה|ייסד|ייסדה)\s+(?:את\s+\S+\s+)?(?:יחד\s+)?עם|"
                       r"(?:a\s+)?(?:business\s+)?partner\s+of|co-?founded\s+(?:\S+\s+)?with|founded\s+(?:\S+\s+)?with"),
    ("represents", False, r"ייצג(?:ה)?\s+את|מייצג(?:ת)?\s+את|ב(?:א|את)\s+כוח(?:ו|ה)\s+של|"
                          r"represent(?:ed|s)|(?:the\s+)?(?:counsel|attorney|lawyer)\s+(?:for|of)"),
    ("represents", True, r"יוצג(?:ה)?\s+(?:על\s+ידי|ע\"י)|מיוצג(?:ת)?\s+(?:על\s+ידי|ע\"י)|(?:was\s+|is\s+)?represented\s+by"),
    ("manages", False, r"מנהל(?:ו|ה|ת|תו|תה)?\s+של|הממונה\s+על|(?:the\s+)?manager\s+of|manages|supervis(?:es|ed)"),
    ("manages", True, r"כפו(?:ף|פה)\s+ל|עובד(?:ת)?\s+תחת|report(?:s|ed)\s+to|work(?:s|ed)\s+under"),
    ("deputy", False, r"סגנ(?:ו|ה|ית|יתו|יתה)\s+של|(?:the\s+)?deputy\s+(?:of|to)"),
    ("spouse", False, r"נשו(?:י|אה)\s+ל|ב(?:ן|ת)\s+זוג(?:ו|ה)?\s+של|(?:אשתו|בעלה)\s+של|"
                      r"(?:is\s+|was\s+)?married\s+to|(?:the\s+)?(?:husband|wife|spouse)\s+of"),
    ("adversary", False, r"נגד|v\.|vs\.?"),
]
_COPULA = r"(?:(?:הוא|היא|היה|הייתה|is|was)\s+)?"
_CUE_RE = [(k, sw, re.compile(r"^[\s,–—-]*" + _COPULA + r"(?:" + p + r")[\s,–—-]*$", re.I), p) for k, sw, p in _CUES]
# "X ו-Y עבדו יחד" / "X and Y worked together": the phrase right AFTER the second name
_PLURAL = [("colleague", r"(?:עבדו|עובדים|עובדות)\s+(?:יחד|ביחד)|(?:worked|work)\s+together|(?:are|were)\s+colleagues"),
           ("partner", r"(?:הם|היו)?\s*שותפים|(?:הקימו|ייסדו)|(?:are|were)\s+(?:business\s+)?partners|co-?founded"),
           ("spouse", r"(?:נשואים|התחתנו)|(?:are|were)\s+married|got\s+married")]
_PLURAL_RE = [(k, re.compile(r"^\s*(?:" + p + r")", re.I)) for k, p in _PLURAL]
_AND = re.compile(r"^\s*(?:ו-?|and\s+|&\s*)$", re.I)
_NEG = re.compile(r"(?:^|\s)(?:לא|אינו|אינה|הכחיש|הכחישה|never|not|denied|no)(?:\s|$)", re.I)
_ABBR = re.compile(r"\b(?:v|vs|dr|mr|mrs|ms|prof|adv|st|no|inc|ltd|jr|sr)\.$|(?:^|\s)[A-Za-zא-ת]\.$", re.I)
_PREFIX = "ובלמהשכ"
_WORD = re.compile(rf"[{_HE}A-Za-z][{_HE}A-Za-z'\"״׳\-]*")
TEXT_HE = {"colleague": "עמיתים", "partner": "שותפים", "represents": "ייצוג", "manages": "ניהול", "deputy": "סגנות",
           "spouse": "בני זוג", "adversary": "צדדים שכנגד"}
MAX_SENTENCE = 400


def sentences(text):
    """Split into sentences, keeping 'v.' / 'Dr.' / an initial inside."""
    out, start = [], 0
    for m in re.finditer(r"[.!?;\n]+", text):
        piece = text[start:m.end()]
        if m.group(0).startswith(".") and "\n" not in m.group(0) and _ABBR.search(text[start:m.start() + 1]):
            continue
        out.append((start, piece))
        start = m.end()
    if start < len(text):
        out.append((start, text[start:]))
    return [(s, p) for s, p in out if p.strip()]


def _name_rx(display):
    toks = [re.escape(t) for t in display.split() if t]
    if not toks:
        return None
    body = r"[\s\-־]+".join(toks)
    return re.compile(rf"(?<![{_HE}A-Za-z])(?:[{_PREFIX}]-?)?({body})(?![{_HE}A-Za-z])", re.I)


def _mentions(sent, compiled):
    """[(start, end, display)] of every known person in one sentence (longest wins on overlap).
    compiled: [(display, regex)] built once per text."""
    found = []
    for disp, rx in compiled:
        if disp.split()[-1] in sent or disp.split()[0] in sent:   # cheap pre-check before the regex
            for m in rx.finditer(sent):
                found.append((m.start(1), m.end(1), disp))
    found.sort(key=lambda x: (x[0], -(x[1] - x[0])))
    out, last = [], -1
    for s, e, d in found:
        if s >= last:
            out.append((s, e, d))
            last = e
    return out


def _known_ngram(words, known):
    """The longest 2–3 word name among `words` (already in order, nearest first) that the database knows."""
    if not known:
        return None
    for n in (3, 2):
        if len(words) >= n:
            cand = words[:n]
            name = " ".join(w for w, _s, _e in cand)
            if known(name):
                return cand
    return None


def _party_after(sent, pos, mentions, known):
    for s, e, d in mentions:
        if s >= pos and re.fullmatch(rf"[\s,]*(?:[{_PREFIX}]-?)?", sent[pos:s]):
            return s, e, d
    words = [(m.group(0), m.start() + pos, m.end() + pos) for m in _WORD.finditer(sent[pos:pos + 80])]
    if words and words[0][1] - pos <= 2:
        hit = _known_ngram(words, known)
        if hit:
            return hit[0][1], hit[-1][2], " ".join(w for w, _s, _e in hit)
    return None


def _party_before(sent, pos, mentions, known, owner=None):
    for s, e, d in reversed(mentions):
        if e <= pos and re.fullmatch(r"[\s,]*", sent[e:pos]):
            return s, e, d
    head = sent[:pos]
    words = [(m.group(0), m.start(), m.end()) for m in _WORD.finditer(head)][::-1]
    if words and pos - words[0][2] <= 2:
        hit = _known_ngram(words, known)
        if hit:
            hit = hit[::-1]
            return hit[0][1], hit[-1][2], " ".join(w for w, _s, _e in hit)
    if owner and not head.strip(" ,-–—"):
        return 0, 0, owner                   # a note that starts with the relation: "עבד עם רון כהן" = the owner
    return None


def find_relations(text, persons, known=None, owner=None):
    """-> [(a_display, b_display, kind, confidence, sentence)] — kind 'text:<kind>'; directed kinds read a -> b."""
    persons = [p for p in dict.fromkeys(persons) if p and len(p.split()) >= 2]
    if owner and len(owner.split()) >= 2:
        persons.append(owner)
    compiled = [(d, rx) for d in persons for rx in (_name_rx(d),) if rx]
    out, seen = [], set()
    for _off, sent in sentences(text or ""):
        if len(sent) > MAX_SENTENCE:
            continue
        ms = _mentions(sent, compiled)
        found = []
        # 1. "X <phrase> Y": try every gap between two consecutive parties, and phrase-led gaps after a party
        cands = []
        for i, (s1, e1, d1) in enumerate(ms):
            for s2, e2, d2 in ms[i + 1:i + 3]:
                cands.append(((s1, e1, d1), (s2, e2, d2), sent[e1:s2]))
        for kind, swap, rx, _inner in _CUE_RE:
            for a, b, gap in cands:
                if rx.match(gap) and not _NEG.search(gap):
                    found.append((a[2], b[2], kind, swap, gap))
        # 2. one side recognised, the other a name the database knows (or the note's owner)
        if known or owner:
            for kind, swap, _rx, inner in _CUE_RE:
                for m in re.finditer(r"(?<![" + _HE + r"A-Za-z])(?:" + inner + r")(?![" + _HE + r"A-Za-z])", sent, re.I):
                    lpos = m.start()
                    cop = re.search(r"(?:^|\s)(?:הוא|היא|היה|הייתה|is|was)\s+$", sent[:lpos], re.I)
                    if cop:
                        lpos = cop.start() + (1 if sent[cop.start()].isspace() else 0)   # "X הוא שותפו של Y"
                    left = _party_before(sent, lpos, ms, known, owner)
                    right = _party_after(sent, m.end(), ms, known)
                    if left and right and not _NEG.search(sent[max(0, left[1]):m.start()] + " " + m.group(0)):
                        if re.fullmatch(r"[\s,–—-]*", sent[left[1]:lpos]) or left[1] == 0:
                            found.append((left[2], right[2], kind, swap, m.group(0)))
        # 3. "X ו-Y עבדו יחד"
        for i, (s1, e1, d1) in enumerate(ms[:-1]):
            s2, e2, d2 = ms[i + 1]
            if _AND.match(sent[e1:s2]):
                for kind, rx in _PLURAL_RE:
                    if rx.match(sent[e2:]) and not _NEG.search(sent[e2:e2 + 12]):
                        found.append((d1, d2, kind, False, ""))
        for a, b, kind, swap, _gap in found:
            if swap:
                a, b = b, a
            if name_key(a) == name_key(b):
                continue
            k = "text:" + kind
            key = (name_key(a), name_key(b), k) if k in DIRECTED else (*sorted((name_key(a), name_key(b))), k)
            if key in seen:
                continue
            seen.add(key)
            conf = 0.8 if len(sent.split()) <= 30 else 0.6
            out.append((a, b, k, conf, " ".join(sent.split())[:300]))
    return out


def store_known(store):
    """known(name) -> True when the database already holds a person by exactly this name (any anchor)."""
    cache = {}

    def known(name):
        nk = name_key(name)
        if len(nk.split()) < 2:
            return False
        if nk not in cache:
            cache[nk] = bool(store.q1("SELECT 1 x FROM entities WHERE type='person' AND (key=? OR (key>=? AND key<?)) "
                                      "LIMIT 1", (nk, nk + "|", nk + "|￿")))
        return cache[nk]
    return known


def add_to_extraction(ex, text, known=None, owner_ent=None):
    """Run the pass over one extraction: every relation found becomes a 'text:<kind>' link on `ex`. -> count."""
    from .extract import Ent
    by_disp = {}
    for (t, k), e in ex.ents.items():
        if t == "person":
            by_disp[e["display"]] = k
    owner = owner_ent.display if owner_ent is not None else None
    n = 0
    for a, b, kind, conf, snip in find_relations(text, list(by_disp), known=known, owner=owner):
        ents = []
        for d in (a, b):
            if owner_ent is not None and d == owner:
                ents.append(owner_ent)
            else:
                k = by_disp.get(d) or name_key(d)
                ents.append(Ent("person", k, d, 0, 0, conf, surface=d, via="text"))
                if k not in by_disp.values():
                    ex.add_ent(ents[-1], snip)
        ex.add_link(ents[0], ents[1], kind, conf, snip)
        n += 1
    return n


# ------------------------------------------------------------------------------------------- labelled evaluation
def evaluate(folder):
    """tests/relcorpus/*.json: {"text", "persons", "known"?, "owner"?, "relations": [[a, b, kind]]}.
    -> {precision, recall, tp, fp, fn, errors}"""
    tp = fp = fn = 0
    errors = []
    for fn_ in sorted(os.listdir(folder)):
        if not fn_.endswith(".json"):
            continue
        with open(os.path.join(folder, fn_), encoding="utf-8") as f:
            cases = json.load(f)
        for c in cases:
            known_set = {name_key(n) for n in c.get("known", [])}
            got = find_relations(c["text"], c.get("persons", []),
                                 known=(lambda n: name_key(n) in known_set) if known_set else None,
                                 owner=c.get("owner"))

            def norm(a, b, k):
                k = k if k.startswith("text:") else "text:" + k
                return (name_key(a), name_key(b), k) if k in DIRECTED else (*sorted((name_key(a), name_key(b))), k)
            g = {norm(a, b, k) for a, b, k, _c, _s in got}
            w = {norm(a, b, k) for a, b, k in c.get("relations", [])}
            tp += len(g & w)
            fp += len(g - w)
            fn += len(w - g)
            if g != w:
                errors.append({"file": fn_, "text": c["text"][:120], "extra": sorted(g - w), "missing": sorted(w - g)})
    return {"precision": round(tp / (tp + fp), 4) if tp + fp else 1.0,
            "recall": round(tp / (tp + fn), 4) if tp + fn else 1.0, "tp": tp, "fp": fp, "fn": fn, "errors": errors}
