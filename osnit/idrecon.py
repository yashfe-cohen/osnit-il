"""Reconstruct a full Israeli ID (ת"ז) that was split across two columns — e.g. a 7-digit 'tz' column plus a
2-digit 'Family Tz' column — by trying each way of assembling the 9 digits and keeping the one whose result passes
the official check-digit test on the most rows. Because the 9th digit is a Luhn check digit, a WRONG assembly
validates on only ~10% of rows while the RIGHT one validates on ~all of them, so the correct layout stands out and
is verifiable — never guessed. Reconstruction is proposed to the operator (shown with its validation rate); it is
not applied silently."""
from .semantic import il_id_ok


def _digits(x):
    return "".join(ch for ch in (str(x) if x is not None else "") if ch.isdigit())


# each pattern says where the 2 'family' digits (b) sit around the 7 id digits (a) to make the 9-digit number
PATTERNS = ["bb+a", "a+bb", "b.a.b", "b.a.b_rev", "brev+a", "a+brev"]
PATTERN_LABEL = {
    "bb+a": "שתי ספרות ה-Family בהתחלה",
    "a+bb": "שתי ספרות ה-Family בסוף",
    "b.a.b": "ספרה אחת בהתחלה ואחת בסוף",
    "b.a.b_rev": "ספרה אחת בסוף ואחת בהתחלה (הפוך)",
    "brev+a": "Family (הפוך) בהתחלה",
    "a+brev": "Family (הפוך) בסוף",
}


def assemble(tz, fam, pattern):
    """Build the candidate 9-digit ID from the tz digits and the family digits per `pattern` ('' if it can't)."""
    a, b = _digits(tz), _digits(fam)
    if len(b) == 1:
        b = "0" + b                       # 'Family Tz' is 2 digits; restore a leading zero lost by number storage
    if len(b) != 2 or not a:
        return ""
    return {"bb+a": b + a, "a+bb": a + b, "b.a.b": b[:1] + a + b[1:2], "b.a.b_rev": b[1:2] + a + b[:1],
            "brev+a": b[::-1] + a, "a+brev": a + b[::-1]}.get(pattern, "")


def detect_id_join(pairs, min_rows=10, min_rate=0.9):
    """pairs: [(tz_value, family_value)]. Return the assembly whose reconstructed IDs pass the Israeli check digit on
    the most rows, as dict(pattern, label, valid_rate, valid, tested, examples) — but only when it is CONVINCING
    (≥min_rows rows at ≥min_rate valid, or a perfectly-valid small sample). Otherwise None, so a mere coincidence is
    never applied."""
    cand = [(a, b) for a, b in pairs if _digits(a) and _digits(b)]
    best = None
    for p in PATTERNS:
        ok = tested = 0
        ex = []
        for a, b in cand:
            v = assemble(a, b, p)
            if len(v) == 9:
                tested += 1
                if il_id_ok(v):
                    ok += 1
                    if len(ex) < 6:
                        ex.append(dict(tz=_digits(a), family=_digits(b), id=v))
        rate = ok / tested if tested else 0.0
        c = dict(pattern=p, label=PATTERN_LABEL[p], valid_rate=round(rate, 3), valid=ok, tested=tested, examples=ex)
        if best is None or (rate, tested) > (best["valid_rate"], best["tested"]):
            best = c
    if best and ((best["tested"] >= min_rows and best["valid_rate"] >= min_rate)
                 or (best["tested"] >= 3 and best["valid_rate"] == 1.0)):
        return best
    return None
