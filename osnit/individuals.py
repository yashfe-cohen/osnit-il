"""Distinct individuals behind a search: "יצחק כהן גן יבנה" answers with PEOPLE, not with a pile of records.

A search finds identities (records joined by the importer). Several of them can be one person (each file knew a
different identifier) and several people can share the name. This module turns the found identities into
individuals, the way an analyst would lay them out:

  individual   a core: identities that are provably one person (a shared personal identifier, or the operator
               said "same"). A core with a national ID is always its own individual.
  qualifiers   every detail the query gave beyond the name (town / street, birth year or age, father's name, and the
               strong clues) is checked per individual: match, conflict (the individual is known to have another
               value — e.g. born 1985 when 1980 was asked), or unknown (nothing on file). Individuals that match come
               first; conflicting ones are "others with this name".
  attached     an identity that is probably one of the individuals (coherent probability from resolve.py >= 0.5) is
               shown UNDER that individual with its probability and what would decide it ("a birth date would
               settle it") — never merged: the operator confirms (rule 5).
  distinct     what sets each individual apart from the others found: an ID, a birth year, a town, a father, a
               mobile — the details no other individual in the result shares.

Nothing here decides identity on its own; it organises what the model and the operator's decisions already say."""
import time

from . import matchmodel, resolve
from .possible import _block_resolution, _features, decisions_for
from .store import person_base_key

ATTACH_P = 0.5           # shown under an individual from this coherent probability
MAYBE_P = 0.2            # below ATTACH_P: a "maybe the same as" note between two individuals
MAX_IDS = 80             # resolving is quadratic: the most relevant identities only
LABEL = {"name": "שם", "city": "עיר", "address": "כתובת", "birth_year": "שנת לידה", "father": "שם האב", "phone": "טלפון",
         "email": "מייל", "national_id": 'ת"ז'}
_DECIDE = (("nids", 'ת"ז'), ("birth", "תאריך לידה"), ("mobiles", "טלפון נייד"), ("emails", "מייל"),
           ("addresses", "כתובת"))


def fathers_of(store, ids):
    """{identity: {father display}} from imported kinship ("שם האב") links."""
    out = {i: set() for i in ids}
    if ids:
        ph = ",".join(str(int(i)) for i in ids)
        for r in store.q(f"SELECT r.a_id, o.display FROM relations r CROSS JOIN entities o ON o.id = r.b_id "
                         f"WHERE r.a_id IN ({ph}) AND r.kind = 'kinship:father'"):
            if r["display"]:
                out[r["a_id"]].add(r["display"])
    return out


def _years(f):
    return {int(d[:4]) for d in f["birth"] if d[:4].isdigit()}


def _merge(fs):
    out = {k: set() for k in ("ids", "nids", "addresses", "cities", "orgs", "birth", "emails", "files", "srcs")}
    for f in fs:
        for k in out:
            out[k] |= f.get(k, set())
    out["recycled"] = frozenset().union(*(f.get("recycled", frozenset()) for f in fs)) if fs else frozenset()
    out["mobiles"] = matchmodel._mobiles(out)
    out["landlines"] = matchmodel._landlines(out)
    return out


def _father_matches(display, want):
    from .nicknames import _tok_same
    toks = display.split()
    given = toks[:-1] if len(toks) >= 2 else toks          # the importer adds the child's surname to a lone name
    return any(_tok_same(t, want)[0] for t in given)


def birth_range(clues, now=None):
    """(lo, hi) of the birth year a query asks for: an explicit year, or an age (as of this year)."""
    now = now or time.localtime().tm_year
    if clues.get("birth_year"):
        y = int(str(clues["birth_year"]).strip()[:4])
        return y, y
    if clues.get("age"):
        a = int(str(clues["age"]).strip())
        return now - a - 1, now - a
    return None


def build(store, ids, qualifiers=None, matched=None, limit=MAX_IDS):
    """ids: the identities a search found, most relevant first. qualifiers: {city, address, birth_year: (lo, hi),
    father, phone, email, national_id} — what the query said beyond the name. matched: {identity: {field: value}}
    (the clues each identity matched in the search). -> dict(individuals=[...], counts={...}, considered, took)."""
    t0 = time.time()
    qualifiers = {k: v for k, v in (qualifiers or {}).items() if v}
    matched = matched or {}
    ids = list(dict.fromkeys(int(i) for i in ids))[:limit]
    empty = dict(individuals=[], counts=dict(match=0, possible=0, conflict=0, attached=0), considered=0, took=0.0)
    if not ids:
        return empty
    ents = {r["id"]: dict(r) for r in store.q(
        f"SELECT id, key, display FROM entities WHERE id IN ({','.join(str(i) for i in ids)}) AND type='person'")}
    ids = [i for i in ids if i in ents]
    if not ids:
        return empty
    feats = _features(store, ids)
    mod = matchmodel.get_model(store)
    _lo, coh, _scored = _block_resolution(store, mod, ids, ents, feats)
    decisions = {}
    for i in ids:
        for j, d in decisions_for(store, i).items():
            if j in ents:
                decisions[(i, j)] = d
    names = {i: (ents[i].get("display") or "") for i in ids if i in ents}
    cores, core_of, core_nids = resolve._cores(ids, feats, decisions, names)

    place_hits = {}
    if qualifiers.get("city") or qualifiers.get("address"):
        from .multisearch import _place_hits
        for k in ("city", "address"):
            if qualifiers.get(k):
                place_hits[k] = _place_hits(store, ids, qualifiers[k])
    fathers = fathers_of(store, ids)

    info = {}
    for k, members in cores.items():
        f = _merge([feats[m] for m in members])
        names = sorted({ents[m]["display"] or person_base_key(ents[m]["key"]) for m in members}, key=len)
        fath = set().union(*(fathers.get(m, set()) for m in members))
        facts = dict(names=names, national_ids=sorted(f["nids"]), mobiles=sorted(f["mobiles"]),
                     landlines=sorted(f["landlines"]), emails=sorted(f["emails"]),
                     towns=sorted({matchmodel._town_display(t) for t in f["cities"]}), birth_years=sorted(_years(f)),
                     birth_dates=sorted(d for d in f["birth"] if len(d) == 10), addresses=sorted(f["addresses"])[:3],
                     fathers=sorted(fath), files=len(f["srcs"]))
        quals = []
        for field, want in qualifiers.items():
            st, found, shown = "unknown", None, want
            if field in ("city", "address"):
                if any(m in place_hits.get(field, ()) for m in members):
                    st = "match"
                elif f["cities"] or f["addresses"]:
                    st, found = "conflict", ", ".join(facts["towns"] or facts["addresses"])
            elif field == "birth_year":
                lo, hi = want
                shown = str(lo) if lo == hi else f"{lo}–{hi}"
                ys = _years(f)
                if any(lo <= y <= hi for y in ys):
                    st = "match"
                elif ys:
                    st, found = "conflict", ", ".join(str(y) for y in sorted(ys))
            elif field == "father":
                if any(_father_matches(x, want) for x in fath):
                    st = "match"
                elif fath:
                    st, found = "conflict", ", ".join(sorted(fath))
            elif field == "name":
                if not any("name" in matched.get(m, {}) for m in members):
                    st = "other"                                               # found through a detail, other name
                else:
                    continue                                                   # every name hit: nothing to say
            elif field in ("phone", "email", "national_id"):
                if any(field in matched.get(m, {}) for m in members):
                    st = "match"
                elif field == "national_id" and f["nids"]:
                    st, found = "conflict", ", ".join(sorted(f["nids"]))      # one ID per person: a different one
                elif field != "national_id" and (f["mobiles"] or f["landlines"] if field == "phone" else f["emails"]):
                    st = "other"                                               # people hold several phones/mails
            else:
                continue
            quals.append(dict(field=field, label=LABEL.get(field, field), value=str(shown), status=st, found=found))
        status = ("conflict" if any(q["status"] == "conflict" for q in quals)
                  else "possible" if any(q["status"] in ("unknown", "other") for q in quals) else "match")
        strength = (bool(f["nids"]), len(f["mobiles"]) + len(f["emails"]), len(members), len(f["srcs"]),
                    -min(members))
        info[k] = dict(members=sorted(members), feat=f, facts=facts, quals=quals, status=status, strength=strength)

    # how likely two cores are one person: the best coherent probability between their members
    pcore = {}
    for a in ids:
        for b in ids:
            ka, kb = core_of[a], core_of[b]
            if a < b and ka != kb:
                key = (ka, kb) if ka < kb else (kb, ka)
                pcore[key] = max(pcore.get(key, 0.0), coh.get(frozenset((a, b)), 0.0))
    pc = lambda x, y: pcore.get((x, y) if x < y else (y, x), 0.0)

    attached = {}
    by_strength = sorted(cores, key=lambda k: info[k]["strength"], reverse=True)
    for x in sorted(cores, key=lambda k: info[k]["strength"]):          # weakest first
        if core_nids[x]:
            continue                                                     # an ID-anchored core is its own person
        best, bp = None, 0.0
        for y in by_strength:
            if y == x or y in attached or info[y]["strength"] <= info[x]["strength"]:
                continue
            p = pc(x, y)
            if p > bp:
                best, bp = y, p
        if best is not None and bp >= ATTACH_P and _share_something(info[x]["feat"], info[best]["feat"]):
            attached[x] = (best, bp)

    tops = [k for k in cores if k not in attached]
    rank = {"match": 0, "possible": 1, "conflict": 2}
    tops.sort(key=lambda k: (rank[info[k]["status"]], -sum(q["status"] == "match" for q in info[k]["quals"]),
                             tuple(-int(x) for x in info[k]["strength"][:4]), min(cores[k])))
    index = {k: n + 1 for n, k in enumerate(tops)}
    out = []
    for k in tops:
        me = info[k]
        others = [info[o] for o in tops if o != k]
        out.append(dict(index=index[k], ids=me["members"], name=me["facts"]["names"][0], status=me["status"],
                        qualifiers=me["quals"], facts=me["facts"], distinct=_distinct(me, others),
                        identities=len(me["members"]), anchored=bool(me["facts"]["national_ids"]),
                        possible=[], maybe=[], family=[]))
    pos = {k: n for n, k in enumerate(tops)}
    for x, (y, p) in sorted(attached.items(), key=lambda kv: -kv[1][1]):
        ix, iy = info[x], info[y]
        decide = [label for key, label in _DECIDE if iy["feat"][key] and not ix["feat"][key]]
        out[pos[y]]["possible"].append(dict(ids=ix["members"], name=ix["facts"]["names"][0], probability=round(p, 3),
                                            qualifiers=ix["quals"], facts=ix["facts"], decide=decide[:3]))
    for k in tops:
        for o in tops:
            if o != k:
                p = pc(k, o)
                if MAYBE_P <= p < ATTACH_P and _share_something(info[k]["feat"], info[o]["feat"]):
                    out[pos[k]]["maybe"].append(dict(index=index[o], probability=round(p, 3)))
    # family among the people found: one household (a home landline or an address) and one surname; the birth years
    # name the tie — a same-name grandfather and grandson are two people of one family, said plainly
    from .kinship import KINSHIP_ROLE_LABELS, kin_from_birth_gap, surname_of
    for k in tops:
        for o in tops:
            if o == k:
                continue
            fk, fo = info[k]["feat"], info[o]["feat"]
            home = (fk["landlines"] & fo["landlines"]) or (fk["addresses"] & fo["addresses"])
            sk = {surname_of(n) for n in info[k]["facts"]["names"]} - {""}
            so = {surname_of(n) for n in info[o]["facts"]["names"]} - {""}
            if not home or not (sk & so):
                continue
            kin = kin_from_birth_gap(set(info[k]["facts"]["birth_years"]), set(info[o]["facts"]["birth_years"]))
            role = kin[0] if kin else "household"
            out[pos[k]]["family"].append(dict(index=index[o], role=role,
                                              relation=KINSHIP_ROLE_LABELS.get(role, "בן בית"),
                                              why=kin[1] if kin else "אותו משק בית"))
    counts = dict(match=sum(1 for i in out if i["status"] == "match"),
                  possible=sum(1 for i in out if i["status"] == "possible"),
                  conflict=sum(1 for i in out if i["status"] == "conflict"), attached=len(attached))
    return dict(individuals=out, counts=counts, considered=len(ids), took=round(time.time() - t0, 3))


def _share_something(fa, fb):
    """The operator's rule: two people are linked as "maybe the same" only through a concrete shared detail (a town,
    an address, a phone, an email, an ID, a birth date, an org) — never through the name alone."""
    return bool(matchmodel.in_common(matchmodel.compare(fa, fb, "exact")))


def _distinct(me, others):
    """Up to three details that set this individual apart from the others found."""
    f, out = me["facts"], []
    if f["national_ids"]:
        out.append('ת"ז ' + f["national_ids"][0])
    ys, oys = set(f["birth_years"]), set().union(*(set(o["facts"]["birth_years"]) for o in others)) if others else set()
    if ys and not ys & oys:
        out.append("שנת לידה " + ", ".join(str(y) for y in sorted(ys)))
    ts, ots = set(f["towns"]), set().union(*(set(o["facts"]["towns"]) for o in others)) if others else set()
    if ts and not ts & ots:
        out.append("עיר: " + ", ".join(sorted(ts)))
    fa, ofa = set(f["fathers"]), set().union(*(set(o["facts"]["fathers"]) for o in others)) if others else set()
    if fa and not fa & ofa:
        out.append("שם האב: " + sorted(fa)[0].split()[0])
    ms, oms = set(f["mobiles"]), set().union(*(set(o["facts"]["mobiles"]) for o in others)) if others else set()
    if ms - oms:
        out.append("נייד " + sorted(ms - oms)[0])
    es, oes = set(f["emails"]), set().union(*(set(o["facts"]["emails"]) for o in others)) if others else set()
    if es - oes:
        out.append(sorted(es - oes)[0])
    return out[:3]
