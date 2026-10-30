"""Who is the father in the 'שם האב' column? A relative known only by name, matched to a person the data already has.

A kinship column ("שם האב: משה" on Dana Friedman's row) creates the relative as a person known by name only
("משה פרידמן", no phone, no ID, no address of his own). The real Moshe Friedman may already be in the data — at
Dana's address, born 29 years before her — but nothing joins the two: the relative has no detail of his own, so the
"possible same person" rule (a detail in common) can never fire for him.

Here the relative borrows the CHILD's details. A candidate is a person who
  * carries the same name (any spelling that name_key folds together),
  * shares at least one concrete detail with the child: an address, a landline (a household), a town, a surname
    at the same address — the operator's "something in common" rule, through the family,
  * and, when both birth years are known, is of the right generation for the role (a parent 15–60 years older,
    a child 15–60 younger, a sibling within 15, a grandparent 35+ older). A wrong generation rules a candidate out.
It is a SUGGESTION: shown on the network map with its reasons; the operator's "✓ זה הוא" records an identity
decision (possible.decide 'same'), after which the map treats the two as one person. Nothing is merged here."""
from .textnorm import name_key

ROLE_GAP = {"father": (15, 60), "mother": (15, 60), "parent": (15, 60), "son": (-60, -15), "daughter": (-60, -15),
            "child": (-60, -15), "sibling": (-15, 15), "brother": (-15, 15), "sister": (-15, 15),
            "grandparent": (35, 90), "grandchild": (-90, -35)}
ROLE_HE = {"father": "האב", "mother": "האם", "parent": "ההורה", "son": "הבן", "daughter": "הבת", "child": "הילד/ה",
           "sibling": "האח/ות", "brother": "האח", "sister": "האחות", "grandparent": "הסב/תא", "grandchild": "הנכד/ה",
           "spouse": "בן/בת הזוג", "relative": "קרוב/ת המשפחה"}


def name_only(store, pid):
    """A person with nothing of their own but family links (created from a kinship column or sentence)."""
    other = store.q1("SELECT 1 x FROM relations r CROSS JOIN entities o ON o.id = CASE WHEN r.a_id=? THEN r.b_id "
                     "ELSE r.a_id END WHERE (r.a_id=? OR r.b_id=?) AND r.kind NOT LIKE 'kinship%' LIMIT 1",
                     (pid, pid, pid))
    return other is None and store.q1("SELECT 1 x FROM attributes WHERE entity_id=? LIMIT 1", (pid,)) is None


def _birth(feat):
    from .kinship import _birth_years
    ys = _birth_years(feat.get("birth") or ())
    return min(ys) if ys else None


def candidates(store, child, relative, role):
    """[{id, name, reasons:[...], score}] — who the name-only `relative` (role as seen from `child`, e.g. 'father')
    may be, best first. Empty when nothing shares a detail with the child."""
    from .possible import _features
    rel = store.q1("SELECT display, key FROM entities WHERE id=?", (relative,))
    if not rel:
        return []
    nk = name_key(rel["display"] or "")
    if len(nk.split()) < 2:
        return []
    pool = [r["id"] for r in store.q("SELECT id FROM entities WHERE type='person' AND (key=? OR (key>=? AND key<?)) "
                                     "LIMIT 200", (nk, nk + "|", nk + "|￿")) if r["id"] not in (child, relative)]
    if not pool:
        return []
    feats = _features(store, [child] + pool)
    me = feats[child]
    my_landlines = {k for t, k in me["ids"] if t == "phone"}
    my_birth = _birth(me)
    lo, hi = ROLE_GAP.get(role, (-90, 90))
    out = []
    for c in pool:
        f = feats[c]
        reasons, score = [], 0.0
        shared_addr = me["addresses"] & f["addresses"]
        if shared_addr:
            reasons.append("כתובת משותפת")
            score += 0.5
        shared_phone = my_landlines & {k for t, k in f["ids"] if t == "phone"}
        if shared_phone:
            reasons.append("טלפון משותף")
            score += 0.4
        if me["cities"] & f["cities"] and not shared_addr:
            reasons.append("אותה עיר")
            score += 0.15
        if not reasons:
            continue                                 # nothing in common with the family: never offered
        b = _birth(f)
        if my_birth and b:
            gap = my_birth - b                       # > 0: the candidate is older
            if not lo <= gap <= hi:
                continue                             # the wrong generation for this role
            reasons.append(f"הפרש גילים מתאים ({abs(gap)} שנים)")
            score += 0.3
        out.append({"id": c, "name": store.q1("SELECT display FROM entities WHERE id=?", (c,))["display"],
                    "reasons": reasons, "score": round(min(score, 0.95), 2)})
    out.sort(key=lambda x: -x["score"])
    return out[:5]


def suggestions_for(store, child, kin_links):
    """{relative id: {role, role_he, candidates}} for the name-only relatives among kin_links [(relative id, kind)]
    of one person; relatives the operator already resolved (an identity decision) are skipped."""
    out = {}
    for rid, kind in kin_links:
        if not str(kind).startswith("kinship:") or not name_only(store, rid):
            continue
        if store.q1("SELECT 1 x FROM identity_links WHERE (a=? OR b=?) AND decision='same' LIMIT 1", (rid, rid)):
            continue
        role = kind.split(":", 1)[1]
        cands = candidates(store, child, rid, role)
        if cands:
            out[rid] = {"role": role, "role_he": ROLE_HE.get(role, "קרוב/ת המשפחה"), "candidates": cands}
    return out
