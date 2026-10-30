"""Possible same person: who else in the database may be this identity, with a score and the reasons.

Identity resolution at import (Store.resolve_person_record) only joins records on a shared personal identifier.
Everything weaker — the same name and the same town, a nickname and the same employer, the same birth date — is a
POSSIBILITY the operator decides on. This module finds and ranks those possibilities, the way entity-resolution
systems do it at scale:

1. Blocking (never a full scan): candidates are the people reachable through an index from this identity —
   its name in any spelling/script (key prefix, name_index skeletons and words), its nicknames / a missing or
   extra middle name, and the holders of its personal identifiers.
2. Scoring (matchmodel.py): a Fellegi-Sunter model compares the pair field by field; each agreement or conflict
   counts by how often it happens for the same person vs. for different people IN THIS DATA (learned by EM, with
   the operator's decisions as labels), a rare name or a small town counts more than "דוד כהן" in Jerusalem, and
   two different national IDs rule a candidate out entirely.
3. Decisions: the operator's "same" / "not the same" is stored (identity_links) and always wins over the score;
   dossiers honour it.

Precision-first: nothing here merges anything on its own."""
import json
import time
from collections import defaultdict

from . import matchmodel
from .matchmodel import iso_date
from .store import is_personal_identifier, person_base_key
from .textnorm import fold

MAX_CANDIDATES = 600
RESOLVE_MAX = 60          # the coherent resolution (quadratic) runs on this many strongest candidates of a block
BLOCK_CACHE = 8           # resolved blocks kept in memory (per store, per data version)


def _city_display(folded):
    from .semantic import CITIES_EN, CITIES_HE
    for c in list(CITIES_HE) + list(CITIES_EN):
        if fold(c.strip()).replace("-", " ") == folded:
            return c.strip()
    return folded


def _in(ids):
    return ",".join(str(int(i)) for i in ids) or "NULL"


def _features(store, pids):
    """{pid: {"ids": {(type,key)}, "emails", "nids", "addresses", "cities", "orgs", "birth", "files", "srcs"}}
    for a batch of people, in a few indexed queries."""
    f = {p: dict(ids=set(), nids=set(), addresses=set(), cities=set(), orgs=set(), birth=set(), emails=set(),
                 files=set(), srcs=set()) for p in pids}
    if not pids:
        return f
    from .semantic import address_key
    ph = _in(pids)
    for r in store.q(
            f"SELECT r.pid, o.type, o.key, o.display FROM ("
            f"  SELECT a_id pid, b_id oid FROM relations WHERE a_id IN ({ph}) "
            f"  UNION ALL SELECT b_id, a_id FROM relations WHERE b_id IN ({ph})) r "
            f"CROSS JOIN entities o ON o.id = r.oid "
            f"WHERE o.type IN ('phone','email','national_id','id_number','address','org','city')"):
        d = f.get(r["pid"])
        if d is None:
            continue
        t, k = r["type"], r["key"]
        if t in ("phone", "email", "national_id", "id_number"):
            d["ids"].add((t, k))
            if t in ("national_id", "id_number"):
                d["nids"].add(k)
            if t == "email":
                d["emails"].add(k)
        elif t == "address":
            d["addresses"].add(address_key(r["display"] or k))
        elif t == "org":
            d["orgs"].add(k)
        elif t == "city":
            from .semantic import canonical_city
            d["cities"].add(canonical_city(r["display"] or k))
    from .kinship import _extract_cities_from_strings
    for r in store.q(f"SELECT a.entity_id, a.kind, a.value, s.import_id FROM attributes a "
                     f"CROSS JOIN sources s ON s.id = a.source_id WHERE a.entity_id IN ({ph}) LIMIT 20000"):
        d = f.get(r["entity_id"])
        if d is None:
            continue
        v, kind = str(r["value"] or "").strip(), (r["kind"] or "")
        if r["import_id"]:
            d["files"].add(r["import_id"])
        if not v:
            continue
        if kind == "city":
            from .semantic import canonical_city
            d["cities"] |= _extract_cities_from_strings([v]) or {canonical_city(v)}
        elif kind == "address":
            d["addresses"].add(address_key(v))
            d["cities"] |= _extract_cities_from_strings([v])
        elif kind == "birthdate":
            b = iso_date(v)                              # 15/03/1979 and 1979-03-15 are the same date
            if b:
                d["birth"].add(b)
    for r in store.q(f"SELECT DISTINCT entity_id, source_id FROM evidence WHERE entity_id IN ({ph})"):
        if r["entity_id"] in f:
            f[r["entity_id"]]["srcs"].add(r["source_id"])     # the files / pages this identity was seen in
    for d in f.values():
        d["cities"] |= {c for a in d["addresses"] for c in _extract_cities_from_strings([a])}
    rec = recycled_identifiers(store, {k for d in f.values() for t, k in d["ids"] if t in ("phone", "email")})
    for d in f.values():
        d["recycled"] = rec
    return f


def recycled_identifiers(store, keys):
    """The phone / email keys (of `keys`) held by people with two or more DIFFERENT national IDs: a number recycled by
    the carrier to a new owner, or a family line. Such a value proves nothing about which of its holders a record is,
    so it is never a must-link and never "the same identifier" evidence (temporal reasoning, rule 5)."""
    keys = sorted(keys)
    out = set()
    for i in range(0, len(keys), 400):
        part = keys[i:i + 400]
        ph = ",".join("?" * len(part))
        idents = {r["id"]: r["key"] for r in store.q(
            f"SELECT id, key FROM entities WHERE type IN ('phone','email') AND key IN ({ph})", tuple(part))}
        if not idents:
            continue
        ip = _in(idents)
        holders = defaultdict(set)                       # identifier entity -> holder persons
        for r in store.q(f"SELECT r.oid, r.pid FROM (SELECT b_id oid, a_id pid FROM relations WHERE b_id IN ({ip}) "
                         f"UNION ALL SELECT a_id, b_id FROM relations WHERE a_id IN ({ip})) r "
                         f"CROSS JOIN entities e ON e.id = r.pid WHERE e.type = 'person'"):
            holders[r["oid"]].add(r["pid"])
        many = {o: ps for o, ps in holders.items() if len(ps) >= 2}
        if not many:
            continue
        pids = {p for ps in many.values() for p in ps}
        pp = _in(pids)
        nid_of = defaultdict(set)
        for r in store.q(f"SELECT r.pid, o.key FROM (SELECT a_id pid, b_id oid FROM relations WHERE a_id IN ({pp}) "
                         f"UNION ALL SELECT b_id, a_id FROM relations WHERE b_id IN ({pp})) r "
                         f"CROSS JOIN entities o ON o.id = r.oid WHERE o.type IN ('national_id','id_number')"):
            nid_of[r["pid"]].add(r["key"])
        for o, ps in many.items():
            if len({n for p in ps for n in nid_of[p]}) >= 2:
                out.add(idents[o])
    return frozenset(out)



def decisions_for(store, eid):
    out = {}
    for r in store.q("SELECT a, b, decision FROM identity_links WHERE a=? OR b=?", (eid, eid)):
        out[r["b"] if r["a"] == eid else r["a"]] = r["decision"]
    return out


def decide(store, a, b, decision, reasons=None, score=None):
    """Record the operator's decision on two identities: same | different | clear (forget)."""
    a, b = sorted((int(a), int(b)))
    if a == b:
        raise ValueError("same identity")
    with store.tx() as c:
        if decision == "clear":
            c.execute("DELETE FROM identity_links WHERE a=? AND b=?", (a, b))
        elif decision in ("same", "different"):
            c.execute("INSERT INTO identity_links(a, b, decision, score, reasons, at) VALUES(?,?,?,?,?,?) "
                      "ON CONFLICT(a, b) DO UPDATE SET decision=excluded.decision, score=excluded.score, "
                      "reasons=excluded.reasons, at=excluded.at",
                      (a, b, decision, score, json.dumps(reasons or [], ensure_ascii=False), time.time()))
        else:
            raise ValueError("decision must be same, different or clear")
        c.execute("DELETE FROM subject_cache")          # saved investigation pages must reflect the decision
    return {"a": a, "b": b, "decision": decision}


def decision_log(store, limit=100):
    """The operator's identity decisions, newest first, with both names — the audit trail of who was said to be
    whom (and the score and reasons shown when it was decided)."""
    out = []
    for r in store.q("SELECT l.a, l.b, l.decision, l.score, l.reasons, l.at, ea.display na, eb.display nb "
                     "FROM identity_links l LEFT JOIN entities ea ON ea.id = l.a LEFT JOIN entities eb ON eb.id = l.b "
                     "ORDER BY l.at DESC LIMIT ?", (int(limit),)):
        try:
            reasons = json.loads(r["reasons"] or "[]")
        except ValueError:
            reasons = []
        out.append(dict(a=r["a"], b=r["b"], a_name=r["na"], b_name=r["nb"], decision=r["decision"],
                        score=r["score"], reasons=reasons, at=r["at"]))
    return out


def same_as(store, eids):
    """Identities the operator confirmed are the same as any of `eids` (transitively)."""
    out, todo = set(eids), list(eids)
    while todo and len(out) < 500:
        e = todo.pop()
        for r in store.q("SELECT a, b FROM identity_links WHERE (a=? OR b=?) AND decision='same'", (e, e)):
            o = r["b"] if r["a"] == e else r["a"]
            if o not in out:
                out.add(o)
                todo.append(o)
    return out


def block(store, me, mine=None, limit=MAX_CANDIDATES):
    """Candidate identities for one identity, through indexes only (never a full scan): its name in any spelling or
    script, its nicknames / a missing or extra middle name, and the holders of its personal identifiers (an
    identifier held by more than GENERIC_IDENTIFIER_LIMIT people is generic and skipped).
    -> ({id: {id, key, display}}, {id: {"name" | "variant" | "identifier"}})"""
    from .identity import find_people, suggest_same_person
    eid = me["id"]
    name = me["display"] or person_base_key(me["key"])
    cand, via = {}, defaultdict(set)
    for p in find_people(store, name, limit=limit):
        cand[p["id"]] = p
        via[p["id"]].add("name")
    for p in suggest_same_person(store, name, exclude_ids=list(cand)):
        cand.setdefault(p["id"], dict(id=p["id"], display=p["name"], key=""))
        via[p["id"]].add("variant")
    if mine is None:
        mine = _features(store, [eid])[eid]
    for t, k in sorted(mine["ids"]):
        if not is_personal_identifier(t, k):
            continue
        iid = store.q1("SELECT id FROM entities WHERE type=? AND key=?", (t, k))
        if not iid:
            continue
        hold = store.q(
            "SELECT e.id, e.key, e.display FROM (SELECT a_id pid FROM relations WHERE b_id=? UNION "
            "SELECT b_id FROM relations WHERE a_id=?) r CROSS JOIN entities e ON e.id=r.pid WHERE e.type='person' "
            "LIMIT 26", (iid["id"], iid["id"]))
        if len(hold) > 25:
            continue
        for h in hold:
            cand.setdefault(h["id"], dict(h))
            via[h["id"]].add("identifier")
    cand.pop(eid, None)
    ids = list(cand)[:limit]
    if any(not cand[i].get("key") for i in ids):            # a variant hit carries only its display name
        for r in store.q(f"SELECT id, key, display FROM entities WHERE id IN ({_in(ids)})"):
            cand[r["id"]] = dict(r)
    return {i: cand[i] for i in ids}, via


def _name_count(store, nk):
    return store.q1("SELECT COUNT(*) n FROM (SELECT 1 FROM entities WHERE type='person' AND (key=? OR (key>=? AND "
                    "key<?)) LIMIT 501)", (nk, nk + "|", nk + "|\uffff"))["n"]


def _block_resolution(store, mod, ids, ents, feats):
    """Score every pair of the block, then resolve it coherently (resolve.py). Cached per block + data version, so
    the per-identity calls of one block (and the dossier) share the work and report the same numbers.
    -> ({(i,j): log_odds}, {frozenset({i,j}): coherent probability}, {i: scored dict from i's own view})."""
    from . import resolve
    key = (frozenset(ids), store.data_version)
    cache = getattr(store, "_block_cache", None)
    if not isinstance(cache, dict):
        cache = store._block_cache = {}
    if key in cache:
        cache[key] = cache.pop(key)                       # most recently used last
        return cache[key]
    scored_by = {}
    pair_lo = {}
    for i in ids:
        others = {j: ents[j] for j in ids if j != i}
        scored_by[i] = matchmodel.Scorer(store, mod, ents[i], feats[i]).score_all(others, feats)
        for j, s in scored_by[i].items():
            k = (min(i, j), max(i, j))
            lo = pair_lo.get(k)
            pair_lo[k] = s["log_odds"] if lo is None else max(lo, s["log_odds"])
    decisions = {}
    for i in ids:
        for j, d in decisions_for(store, i).items():
            if j in ids:
                decisions[(i, j)] = d
    coh = resolve.resolve_block(list(ids), feats, pair_lo, decisions)
    res = (pair_lo, coh, scored_by)
    for k in [k for k in cache if k[1] != store.data_version]:
        cache.pop(k, None)                                # an older data version is stale
    cache[key] = res
    while len(cache) > BLOCK_CACHE:
        cache.pop(next(iter(cache)))
    return res


def possible_matches(store, eid, limit=30):
    """Ranked candidates for one identity, resolved coherently. matchmodel.py scores each pair — every detail weighed
    by how often it agrees for the same person vs. a namesake in THIS data, a rare name or small town counting more —
    and resolve.py turns the whole name block's pairwise scores into one coherent picture, so the probabilities of
    several different-ID namesakes can no longer all be high at once. Two different national IDs rule a candidate out;
    a shared identifier and the operator's decisions are certainties that always win."""
    t0 = time.time()
    me = store.q1("SELECT id, type, key, display FROM entities WHERE id=?", (eid,))
    if not me or me["type"] != "person":
        return None
    me = dict(me)
    name = me["display"] or person_base_key(me["key"])
    confirmed = same_as(store, [eid])
    mine = _features(store, [eid])[eid]
    cand, via = block(store, me, mine)
    ids = sorted(set(cand) | {eid})
    ents = {eid: me}
    ents.update(cand)
    feats = _features(store, ids)
    decided = decisions_for(store, eid)
    # a "not the same" decision on anyone confirmed to be this person holds for this person too (A is B, B is not C)
    for x in confirmed - {eid}:
        for o, d in decisions_for(store, x).items():
            if d == "different" and o not in decided:
                decided[o] = "different"
    mod = matchmodel.get_model(store)
    # scale: score this identity against the whole block (linear), then resolve coherently only the strongest
    # RESOLVE_MAX candidates (+ the decided ones) — the joint resolution is quadratic in the block
    mine_scored = matchmodel.Scorer(store, mod, me, mine).score_all(cand, feats)
    top = sorted(cand, key=lambda c: -mine_scored[c]["log_odds"] if c in mine_scored else 99)[:RESOLVE_MAX]
    rids = sorted(set(top) | {eid} | (set(decided) & set(cand)) | (confirmed & set(cand)))
    _pair_lo, coh, scored_by = _block_resolution(store, mod, rids, ents, feats)
    scored = dict(mine_scored)
    scored.update(scored_by.get(eid, {}))
    out = []
    for pid in cand:
        fc = feats[pid]
        if mine["nids"] and fc["nids"] and not (mine["nids"] & fc["nids"]):
            continue                                       # two different national IDs: never the same person
        s = scored.get(pid)
        if s is None:
            continue
        decision = "same" if pid in confirmed else decided.get(pid)
        shared_id = bool((mine["nids"] & fc["nids"]) or (matchmodel._mobiles(mine) & matchmodel._mobiles(fc))
                         or (matchmodel._emails(mine) & matchmodel._emails(fc)))
        if decision == "same" or shared_id:
            prob = max(s["probability"], 0.95)
        elif decision == "different":
            prob = coh.get(frozenset((eid, pid)), 0.0)
        else:
            # resolved: the coherent value (0 when the resolution gave it nothing); beyond the RESOLVE_MAX strongest
            # (only for a huge block): below the list's threshold, never an unchecked high value
            prob = coh.get(frozenset((eid, pid)), 0.0) if pid in rids else min(s["probability"], 0.19)
        common = matchmodel.in_common(s.get("levels") or {})
        if decision is None and not (common or shared_id):
            continue                                       # a name alone is never offered (the operator's rule)
        if decision is None and prob < 0.2:
            continue
        out.append(dict(id=pid, name=cand[pid].get("display") or person_base_key(cand[pid].get("key") or ""),
                        score=s["log_odds"], namesakes=s.get("namesakes"),
                        namesakes_in_town=s.get("namesakes_in_town"), probability=round(prob, 3),
                        reasons=s["reasons"], against=s["against"], ask=[] if decision else s.get("ask", []),
                        in_common=common,
                        decision=decision, via=sorted(via[pid])))
    out.sort(key=lambda x: (x["decision"] != "same", x["decision"] == "different", -x["probability"], x["id"]))
    return dict(person=dict(id=eid, name=name), name_count=_name_count(store, person_base_key(me["key"])),
                candidates=out[:limit], considered=len(ids) - 1, took=round(time.time() - t0, 3),
                model=mod.summary())
