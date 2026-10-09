"""Context-aware sensitive-information engine (a DLP-style, entity-centric pipeline), in the spirit of enterprise
systems like Microsoft Presidio: a deterministic pattern layer, a context/anchor layer that boosts or dampens
confidence by the words around a match, lightweight person coreference so a finding is attributed to the right
individual, a hierarchical sensitivity taxonomy, and an explanation for every decision.

Stdlib-only, Hebrew + English, precision-first. It REUSES the project's name gazetteers, checksums and validators
rather than re-deriving them, and it is a separate read-only analysis over free text — it does not change the
entity extractor or the import cataloguing, so the test/eval gate is unaffected.

The four stages the pipeline runs (each a pure function; detection is separated from association):

  1. Ingestion & normalization  -> split text into sentences with exact character offsets, build overlapping
                                   context windows so a value at a paragraph start still sees the previous one.
  2. Entity & coreference        -> find PERSON mentions with offsets; resolve third-person pronouns ("הוא",
                                   "שלו", "הנ\\"ל") to the nearest preceding named person.
  3. Contextual sensitivity      -> detect candidate sensitive values (national ID, card, phone, email, IBAN,
                                   credential, health/financial facts) and score each by pattern + checksum, then
                                   boost by a nearby category anchor and dampen on a hypothetical/instructional
                                   anchor ("אין למסור סיסמה").
  4. Association & dossier        -> attach each finding to the individual it concerns (possessor > subject >
                                   nearest > coref), with a confidence and a human-readable reasoning string.
"""
import re
from dataclasses import dataclass, field

from .names import AMBIGUOUS_HE, GAZ_EN, GAZ_HE
from .quality import valid_email, valid_phone
from .semantic import _luhn, il_id_ok
from .textnorm import fold, name_key, tokens

# ---------------------------------------------------------------- hierarchical sensitivity taxonomy
# leaf type -> (family, severity). Severity: low | medium | high | critical.
TAXONOMY = {
    "national_id": ("PII", "high"),
    "passport": ("PII", "high"),
    "credit_card": ("FINANCIAL", "critical"),
    "iban": ("FINANCIAL", "high"),
    "phone": ("CONTACT", "low"),
    "email": ("CONTACT", "low"),
    "password": ("CREDENTIAL", "critical"),
    "health": ("HEALTH", "high"),
    "finance_fact": ("FINANCIAL", "medium"),
}

# category anchors (lemma-free literal cues, Hebrew + English) — nearby, they raise confidence; for the
# anchor-required categories (password / health / finance_fact) they are the trigger.
ANCHORS = {
    "national_id": ["תעודת זהות", "מספר זהות", "מס' זהות", "ת\"ז", "ת.ז", "ת,ז", "תז", "teudat", "national id",
                    "id number", "id no"],
    "passport": ["דרכון", "מספר דרכון", "passport"],
    "credit_card": ["כרטיס אשראי", "אשראי", "כרטיס", "visa", "mastercard", "credit card", "card number", "cvv", "cvc"],
    "iban": ["iban", "חשבון בנק", "מספר חשבון", "bank account", "swift", "אייבן"],
    "password": ["סיסמה", "סיסמא", "ססמה", "password", "passwd", "pwd", "קוד סודי", "קוד גישה", "secret", "token", "מפתח"],
    "health": ["אבחנה", "מחלה", "תרופה", "תרופות", "אשפוז", "נכות", "פסיכיאטר", "בריאות", "מטופל", "חולה", "סרטן",
               "דיכאון", "חרדה", "diagnosis", "disease", "medication", "hospital", "patient", "psychiatric", "hiv"],
    "finance_fact": ["חוב", "חובות", "משכורת", "שכר", "הלוואה", "משכנתא", "פשיטת רגל", "עיקול", "salary", "debt",
                     "loan", "mortgage", "bankrupt", "overdraft"],
}

# hypothetical / instructional context: the value is not a real datum about a real person -> dampen hard.
NEGATIVE_ANCHORS = ["אין למסור", "לא למסור", "אסור למסור", "לעולם אל", "אל תמסור", "לדוגמה", "לדוגמא", "למשל", "כגון",
                    "דוגמה", "placeholder", "do not share", "don't share", "never share", "for example", "e.g",
                    "example", "sample", "xxxx", "dummy"]

PRONOUNS_M = ["הוא", "שלו", "אותו", "עליו", "אליו", "ממנו"]
PRONOUNS_F = ["היא", "שלה", "אותה", "עליה", "אליה", "ממנה"]
PRONOUNS_REF = ["הנ\"ל", "הלה", "הנ'ל", "הנזכר", "הנזכרת", "המדובר"]
PRONOUNS = set(PRONOUNS_M + PRONOUNS_F + PRONOUNS_REF)

def _anchor_pat(kw):
    """A matcher for a Hebrew/English cue that tolerates an attached prefix (מ/ב/ה/ו/ל/ש/כ/ד) and a definite
    article on inner words — so 'דיכאון' matches 'מדיכאון' and 'תעודת זהות' matches 'תעודת הזהות'."""
    words = kw.split()
    body = r"\s+ה?".join(re.escape(w) for w in words)
    return re.compile(r"(?<![\wא-ת])[והלבשמכד]{0,2}" + body + r"(?![\wא-ת])", re.I)


ANCHOR_PATS = {cat: [(kw, _anchor_pat(kw)) for kw in kws] for cat, kws in ANCHORS.items()}
ANCHOR_WINDOW = 60          # characters: how far a cue may sit from a value and still count
SUBJECT_WINDOW = 160        # characters: how far back a person mention may be and still own a value
ANCHOR_BOOST = 0.4          # Presidio-style: a nearby cue lifts a heuristic base score toward 1.0
MAX_CHARS = 2_000_000       # analyse a bounded slice (the ingest path caps text anyway)


# ---------------------------------------------------------------- immutable data contracts
@dataclass(frozen=True)
class Span:
    start: int
    end: int
    text: str


@dataclass(frozen=True)
class Sentence:
    index: int
    start: int
    end: int
    text: str


@dataclass(frozen=True)
class PersonMention:
    name: str
    key: str
    span: Span
    sentence: int
    is_pronoun: bool = False
    resolves_to: str = ""     # for a pronoun, the named person it was linked to


@dataclass(frozen=True)
class Anchor:
    keyword: str
    category: str
    span: Span
    distance: int


@dataclass(frozen=True)
class Finding:
    value: str
    kind: str                 # a TAXONOMY leaf
    family: str               # PII | CONTACT | FINANCIAL | HEALTH | CREDENTIAL
    severity: str
    span: Span
    confidence: float
    subject: str = ""         # the individual it concerns (a named person), "" if unattributed
    subject_key: str = ""
    link: str = "none"        # possessive | subject | nearest | coref | none
    link_confidence: float = 0.0
    anchor: Anchor = None
    reasoning: str = ""       # why it was flagged and attributed — the explainability string


@dataclass(frozen=True)
class Report:
    findings: tuple = ()
    people: tuple = ()
    source: str = ""

    def by_person(self):
        out = {}
        for f in self.findings:
            out.setdefault(f.subject or "(לא משויך)", []).append(f)
        return out

    def by_family(self):
        out = {}
        for f in self.findings:
            out.setdefault(f.family, []).append(f)
        return out


# ---------------------------------------------------------------- stage 1: ingestion & context windows
_SENT_END = re.compile(r"[.!?؟־]\s+|\n{1,}|[;׃]\s+")


def sentences(text: str):
    """Split into sentences keeping exact offsets into the original text."""
    out, start, idx = [], 0, 0
    for m in _SENT_END.finditer(text):
        seg = text[start:m.start()].strip()
        if seg:
            s0 = start + (len(text[start:m.start()]) - len(text[start:m.start()].lstrip()))
            out.append(Sentence(idx, s0, m.start(), text[s0:m.start()]))
            idx += 1
        start = m.end()
    tail = text[start:].strip()
    if tail:
        s0 = start + (len(text[start:]) - len(text[start:].lstrip()))
        out.append(Sentence(idx, s0, len(text.rstrip()), text[s0:len(text.rstrip())]))
    return out


def _sentence_at(sents, pos):
    for s in sents:
        if s.start <= pos < s.end:
            return s.index
    return sents[-1].index if sents else 0


def _negative_near(pos, sents, text):
    """A hypothetical/instructional cue counts only within the value's own sentence — a negative three sentences
    away must not suppress a real datum."""
    for s in sents:
        if s.start <= pos < s.end:
            seg = s.text.lower()
            return any(neg in seg for neg in NEGATIVE_ANCHORS)
    return False


VERB_SURNAMES = ["העביר", "העבירה", "מסר", "מסרה", "שלח", "שלחה", "קיבל", "קיבלה", "נתן", "נתנה", "לקח", "לקחה",
                 "ביקש", "ביקשה", "סיפר", "סיפרה", "הודיע", "הודיעה", "דיווח", "דיווחה", "רשם", "רשמה", "חתם",
                 "חתמה", "הציג", "הציגה", "אישר", "אישרה", "בדק", "בדקה", "ציין", "ציינה", "טען", "טענה"]


# ---------------------------------------------------------------- stage 2: person mentions & coreference
def _gaz_person_spans(text):
    """Precision-first person mentions with offsets, from the first-name gazetteers — the same rule the extractor
    uses (an ambiguous Hebrew first name counts only if the full name repeats in the text)."""
    from .extract import _name_ok
    amb = {fold(a) for a in AMBIGUOUS_HE}
    verb = {fold(v) for v in VERB_SURNAMES}
    out = []
    for m in GAZ_HE.finditer(text):
        name = f"{m.group('f')} {m.group('l')}".strip()
        if fold(m.group("f")) in amb and text.count(name) < 2:
            continue
        if not _name_ok(name) or fold(name.split()[-1]) in verb:   # drop verb-as-surname (precision-first)
            continue
        out.append((name, Span(m.start(), m.end(), m.group(0))))
    for m in GAZ_EN.finditer(text):
        name = f"{m.group('f')} {m.group('l')}".strip()
        if _name_ok(name):
            out.append((name, Span(m.start(), m.end(), m.group(0))))
    return out


STOP = set(map(fold, ["של", "את", "על", "עם", "או", "כי", "לא", "גם", "הוא", "היא", "זה", "זו", "אני", "יש", "אין"]))


def mentions(text, sents):
    """Named-person mentions plus third-person pronouns, each with an offset and sentence index. Each pronoun is
    resolved to the nearest preceding named person (coreference), so a sensitive attribute stated with 'שלו'
    still lands on the right individual."""
    named = []
    for name, span in _gaz_person_spans(text):
        named.append(PersonMention(name, name_key(name), span, _sentence_at(sents, span.start)))
    named.sort(key=lambda p: p.span.start)
    out = list(named)
    for m in re.finditer(r"(?<![\wא-ת])(" + "|".join(re.escape(p) for p in sorted(PRONOUNS, key=len, reverse=True))
                         + r")(?![\wא-ת])", text):
        pos = m.start()
        prior = [p for p in named if not p.is_pronoun and p.span.start < pos]
        if not prior:
            continue
        ref = prior[-1]                                   # nearest preceding named person
        if pos - ref.span.end > 400:                      # too far back to be a safe antecedent
            continue
        out.append(PersonMention(m.group(0), ref.key, Span(pos, m.end(), m.group(0)),
                                 _sentence_at(sents, pos), is_pronoun=True, resolves_to=ref.name))
    out.sort(key=lambda p: p.span.start)
    return out


# ---------------------------------------------------------------- stage 3: detectors (deterministic layer)
_ID_RE = re.compile(r"(?<!\d)\d{8,9}(?!\d)")
_CARD_RE = re.compile(r"(?<!\d)(?:\d[ \-]?){13,19}(?!\d)")
_EMAIL_RE = re.compile(r"[\w.+\-]+@[\w\-]+(?:\.[\w\-]+)+")
_IBAN_RE = re.compile(r"\bIL\d{2}[\s\-]?(?:\d[\s\-]?){11,27}\b", re.I)
_PHONE_RE = re.compile(r"(?<![\w])(?:\+?972[\s\-]?|0)(?:[23489]|5\d|7\d)[\s\-]?\d{3}[\s\-]?\d{4}(?![\d])")


def _detect(text):
    """Candidate sensitive values with a heuristic base score (the deterministic layer, before context)."""
    cands = []
    for m in _EMAIL_RE.finditer(text):
        if valid_email(m.group(0).lower()):
            cands.append(("email", m.group(0), m.start(), m.end(), 0.8))
    for m in _PHONE_RE.finditer(text):
        from .extract import norm_phone_il
        n = norm_phone_il(m.group(0))
        if n and valid_phone(n):
            cands.append(("phone", m.group(0).strip(), m.start(), m.end(), 0.8))
    for m in _IBAN_RE.finditer(text):
        cands.append(("iban", m.group(0).strip(), m.start(), m.end(), 0.85))
    for m in _CARD_RE.finditer(text):
        digits = re.sub(r"\D", "", m.group(0))
        if 13 <= len(digits) <= 19 and _luhn(digits) and not digits.startswith("0"):
            cands.append(("credit_card", m.group(0).strip(), m.start(), m.end(), 0.7))
    occupied = [(s, e) for _, _, s, e, _ in cands]        # a 9-digit run already claimed by a card/phone is not an ID
    for m in _ID_RE.finditer(text):
        s, e = m.start(), m.end()
        if any(s < oe and os < e for os, oe in occupied):
            continue
        if il_id_ok(m.group(0).zfill(9)):
            cands.append(("national_id", m.group(0), s, e, 0.55))
    return cands


def _anchor_detect(text, sents, people):
    """Anchor-required findings: a credential value right after 'סיסמה:'/'password:', and a sentence that states a
    health or financial fact about a person. These have no standalone pattern — the cue IS the signal."""
    cands = []
    # a credential value after a cue + separator, OR a natural-language 'הסיסמה … היא X' / '… is X'
    for kw, pat in ANCHOR_PATS["password"]:
        for am in pat.finditer(text):
            tail = text[am.end():am.end() + 60]
            vm = re.match(r"\s*(?:של\s+[א-ת][\wא-ת'\-]+(?:\s+[א-ת][\wא-ת'\-]+)?\s+)?"
                          r"(?:[:=\-]|היא|הינה|הוא|is)\s*[\"']?(\S{3,80})", tail, re.I)
            if not vm:
                continue
            val = vm.group(1).strip().strip('",;.')
            vs = am.end() + vm.start(1)
            cands.append(("password", val, vs, vs + len(val), 0.75,
                          Anchor(kw, "password", Span(am.start(), am.end(), am.group(0)), 0)))
    # sentence-level health / financial facts, tied to a person present in that sentence (one per sentence+family)
    seen = set()
    for cat in ("health", "finance_fact"):
        for kw, pat in ANCHOR_PATS[cat]:
            for m in pat.finditer(text):
                si = _sentence_at(sents, m.start())
                if (si, cat) in seen or not any(p.sentence == si for p in people):
                    continue                              # a sensitive topic with nobody attached is not a dossier fact
                seen.add((si, cat))
                sent = next((s for s in sents if s.index == si), None)
                snippet = (sent.text[:120] if sent else kw).strip()
                cands.append((cat, snippet, m.start(), m.end(), 0.5,
                              Anchor(kw, cat, Span(m.start(), m.end(), m.group(0)), 0)))
    return cands


def _nearest_anchor(kind, value_start, value_end, text):
    """The closest category cue to a value within ANCHOR_WINDOW, and the nearest hypothetical/instructional cue."""
    lo, hi = max(0, value_start - ANCHOR_WINDOW), min(len(text), value_end + ANCHOR_WINDOW)
    window = text[lo:hi]
    best = None
    for kw, pat in ANCHOR_PATS.get(kind, []):
        m = pat.search(window)
        if not m:
            continue
        apos, aend = lo + m.start(), lo + m.end()
        dist = max(0, value_start - aend if apos < value_start else apos - value_end)
        if best is None or dist < best.distance:
            best = Anchor(kw, kind, Span(apos, aend, m.group(0)), dist)
    negative = any(neg in window.lower() for neg in NEGATIVE_ANCHORS)
    return best, negative


# ---------------------------------------------------------------- stage 4: association
_POSSESS = re.compile(r"\bשל\s+$")


def _attribute(value_start, value_end, text, people, sents):
    """Attach a value to the individual it concerns, most defensible rule first:
      possessive  — '… של <name>' right beside the value (handles 'כרטיס האשראי של אבי')
      subject     — a named person earlier in the same sentence
      nearest     — the nearest preceding named person within SUBJECT_WINDOW
      coref       — the value sits by a pronoun that resolves to a named person
    Returns (name, key, link_kind, link_confidence)."""
    si = _sentence_at(sents, value_start)
    before = [p for p in people if p.span.start <= value_start]
    after = [p for p in people if p.span.start >= value_end]

    # possessive directly after the value: '… <value> של <name>'
    tail = text[value_end:value_end + SUBJECT_WINDOW]
    mt = re.match(r"\s*(?:ה[\wא-ת]+\s+)?של\s+", tail)
    if mt:
        for p in after:
            if not p.is_pronoun and p.span.start - value_end <= len(mt.group(0)) + len(p.name) + 4:
                return p.name, p.key, "possessive", 0.9
    # possessive just before the value: 'של <name> … <value>'  /  '<name> שלו … <value>'
    head = text[max(0, value_start - SUBJECT_WINDOW):value_start]
    mh = re.search(r"של\s+([א-ת][\wא-ת'\-]+(?:\s+[א-ת][\wא-ת'\-]+)?)\s*[^א-ת]*$", head)
    if mh:
        cand = mh.group(1).strip()
        for p in before[::-1]:
            if not p.is_pronoun and (p.name == cand or p.name.endswith(cand) or cand.endswith(p.name.split()[-1])):
                return p.name, p.key, "possessive", 0.88

    same_sentence = [p for p in before if p.sentence == si]
    if same_sentence:
        p = same_sentence[-1]
        if p.is_pronoun:
            return p.resolves_to, p.key, "coref", 0.6
        return p.name, p.key, "subject", 0.75

    near = [p for p in before if 0 <= value_start - p.span.end <= SUBJECT_WINDOW]
    if near:
        p = near[-1]
        if p.is_pronoun:
            return p.resolves_to, p.key, "coref", 0.55
        return p.name, p.key, "nearest", 0.55
    return "", "", "none", 0.0


def _severity(kind):
    return TAXONOMY.get(kind, ("PII", "medium"))[1]


def _reason(kind, base, anchor, negative, subject, link, dist_subject):
    parts = []
    ev = {"national_id": "תשע ספרות עם ספרת ביקורת תקינה", "credit_card": "מספר כרטיס שעובר בדיקת Luhn",
          "phone": "מספר טלפון ישראלי תקין", "email": "כתובת דוא\"ל תקינה", "iban": "מספר IBAN ישראלי",
          "password": "ערך שהופיע מיד אחרי עוגן סיסמה", "health": "אזכור בריאותי רגיש", "finance_fact": "אזכור כספי רגיש"}
    parts.append(ev.get(kind, kind))
    if anchor:
        parts.append(f"במרחק {anchor.distance} תווים מהעוגן «{anchor.keyword}»")
    if negative:
        parts.append("בהקשר היפותטי/הנחיה — הביטחון הונמך")
    if subject:
        label = {"possessive": "שייכות מפורשת", "subject": "נושא המשפט", "nearest": "האדם הקרוב ביותר",
                 "coref": "פתרון כינוי גוף"}.get(link, link)
        parts.append(f"משויך ל«{subject}» ({label})")
    else:
        parts.append("ללא אדם משויך")
    return "; ".join(parts)


# ---------------------------------------------------------------- orchestrator
def analyze_text(text: str, source: str = "", min_score: float = 0.4) -> Report:
    """Run the full context-aware pipeline over one text and return an explainable, entity-centric report."""
    if not text:
        return Report(source=source)
    text = text[:MAX_CHARS]
    sents = sentences(text)
    people = mentions(text, sents)

    raw = [(k, v, s, e, b, None) for (k, v, s, e, b) in _detect(text)]
    raw += [(k, v, s, e, b, a) for (k, v, s, e, b, a) in _anchor_detect(text, sents, people)]

    findings = []
    for kind, value, s, e, base, preset_anchor in raw:
        family, _ = TAXONOMY.get(kind, ("PII", ""))
        if preset_anchor is not None:
            anchor = preset_anchor
        else:
            anchor, _ = _nearest_anchor(kind, s, e, text)
        negative = _negative_near(s, sents, text)
        conf = base
        if anchor is not None:
            conf = min(1.0, base + ANCHOR_BOOST * (1 - min(anchor.distance, ANCHOR_WINDOW) / ANCHOR_WINDOW))
        if negative:
            conf *= 0.25
        if kind == "national_id" and anchor is None:
            conf = min(conf, 0.5)                          # a lone 9-digit ID stays a weak signal without a cue
        if conf < min_score:
            continue
        subject, key, link, lconf = _attribute(s, e, text, people, sents)
        findings.append(Finding(
            value=value, kind=kind, family=family, severity=_severity(kind), span=Span(s, e, text[s:e]),
            confidence=round(conf, 3), subject=subject, subject_key=key, link=link, link_confidence=lconf,
            anchor=anchor, reasoning=_reason(kind, base, anchor, negative, subject, link, 0)))
    findings.sort(key=lambda f: (-f.confidence, f.span.start))
    named = tuple(dict.fromkeys(p.name for p in people if not p.is_pronoun))
    return Report(findings=tuple(findings), people=named, source=source)


def redact(text: str, report: Report) -> str:
    """Mask every found value with its type tag, highest-offset first so earlier spans keep their positions."""
    out = text
    for f in sorted(report.findings, key=lambda f: -f.span.start):
        out = out[:f.span.start] + f"⟨{f.kind}⟩" + out[f.span.end:]
    return out
