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
            d["cities"].add(fold(r["display"] or k))
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
            d["cities"] |= _extract_cities_from_strings([v]) or {fold(v)}
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
    return f



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
    if cache is not None and cache[0] == key:
        return cache[1]
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
    store._block_cache = (key, res)
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
    mod = matchmodel.get_model(store)
    _pair_lo, coh, scored_by = _block_resolution(store, mod, ids, ents, feats)
    scored = scored_by.get(eid, {})
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
                         or (mine["emails"] & fc["emails"]))
        if decision == "same" or shared_id:
            prob = max(s["probability"], 0.95)
        elif decision == "different":
            prob = coh.get(frozenset((eid, pid)), 0.0)
        else:
            prob = coh.get(frozenset((eid, pid)), min(s["probability"], 0.5))
        if decision is None and prob < 0.2:
            continue
        out.append(dict(id=pid, name=cand[pid].get("display") or person_base_key(cand[pid].get("key") or ""),
                        score=s["log_odds"], namesakes=s.get("namesakes"),
                        namesakes_in_town=s.get("namesakes_in_town"), probability=round(prob, 3),
                        reasons=s["reasons"], against=s["against"], decision=decision, via=sorted(via[pid])))
    out.sort(key=lambda x: (x["decision"] != "same", x["decision"] == "different", -x["probability"], x["id"]))
    return dict(person=dict(id=eid, name=name), name_count=_name_count(store, person_base_key(me["key"])),
                candidates=out[:limit], considered=len(ids) - 1, took=round(time.time() - t0, 3),
                model=mod.summary())
