"""Possible same person: who else in the database may be this identity, with a score and the reasons.

Identity resolution at import (Store.resolve_person_record) only joins records on a shared personal identifier.
Everything weaker — the same name and the same town, a nickname and the same employer, the same birth date — is a
POSSIBILITY the operator decides on. This module finds and ranks those possibilities, the way entity-resolution
systems do it at scale:

1. Blocking (never a full scan): candidates are the people reachable through an index from this identity —
   its name in any spelling/script (key prefix, name_index skeletons and words), its nicknames / a missing or
   extra middle name, and the holders of its personal identifiers.
2. Scoring: each shared detail adds evidence weighted by how rare it is (a rare name or a small town says more
   than "דוד כהן" in Jerusalem; a phone shared by many says nothing), a conflicting detail subtracts, and two
   different national IDs rule a candidate out entirely.
3. Decisions: the operator's "same" / "not the same" is stored (identity_links) and always wins over the score;
   dossiers honour it.

Precision-first: nothing here merges anything on its own."""
import json
import math
import time
from collections import defaultdict

from .store import is_personal_identifier, person_base_key
from .textnorm import fold

BIG_CITIES = {fold(c) for c in ("ירושלים", "תל אביב", "תל אביב יפו", "חיפה", "ראשון לציון", "פתח תקווה", "אשדוד",
                                "נתניה", "באר שבע", "בני ברק", "חולון", "רמת גן")}
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
    """{pid: {"ids": {(type,key)}, "phones", "emails", "nids", "addresses", "cities", "orgs", "birth", "files"}}
    for a batch of people, in a few indexed queries."""
    f = {p: dict(ids=set(), nids=set(), addresses=set(), cities=set(), orgs=set(), birth=set(), emails=set(),
                 files=set()) for p in pids}
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
            d["birth"].add(v[:10])
    for d in f.values():
        d["cities"] |= {c for a in d["addresses"] for c in _extract_cities_from_strings([a])}
    return f


def _name_weight(store, name_key_):
    """Rarer names are stronger evidence: how many identities carry exactly this name (capped count)."""
    n = store.q1("SELECT COUNT(*) n FROM (SELECT 1 FROM entities WHERE type='person' AND (key=? OR (key>=? AND key<?)) "
                 "LIMIT 501)", (name_key_, name_key_ + "|", name_key_ + "|￿"))["n"]
    return max(0.4, 4.0 - math.log10(max(1, n)) * 1.3), n


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


def possible_matches(store, eid, limit=30):
    t0 = time.time()
    me = store.q1("SELECT id, type, key, display FROM entities WHERE id=?", (eid,))
    if not me or me["type"] != "person":
        return None
    from .identity import _name_matches, find_people, suggest_same_person
    from .xling import same_person_name
    name = me["display"] or person_base_key(me["key"])
    nk = person_base_key(me["key"])
    confirmed = same_as(store, [eid])
    # ---- 1. blocking
    cand, via = {}, defaultdict(set)
    for p in find_people(store, name, limit=MAX_CANDIDATES):
        cand[p["id"]] = p
        via[p["id"]].add("name")
    for p in suggest_same_person(store, name, exclude_ids=list(cand)):
        cand.setdefault(p["id"], dict(id=p["id"], display=p["name"], key=""))
        via[p["id"]].add("variant")
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
    ids = list(cand)[:MAX_CANDIDATES]
    feats = _features(store, ids)
    decided = decisions_for(store, eid)
    w_name, name_count = _name_weight(store, nk)
    # ---- 2. scoring
    out = []
    for pid in ids:
        c, fc = cand[pid], feats[pid]
        cname = c.get("display") or person_base_key(c.get("key") or "")
        if mine["nids"] and fc["nids"] and not (mine["nids"] & fc["nids"]):
            continue                                       # two different national IDs: never the same person
        score, reasons = 0.0, []
        ck = person_base_key(c.get("key") or "")
        if ck and ck == nk:
            score += w_name
            reasons.append("שם זהה" + (f" (שם נפוץ: {name_count if name_count <= 500 else '500+'} רשומות)"
                                        if name_count > 20 else ""))
        elif same_person_name(name, cname) or _name_matches(name, cname):
            score += w_name * 0.8
            reasons.append("אותו שם בכתיב אחר")
        elif "variant" in via[pid]:
            score += w_name * 0.55
            reasons.append("כינוי / שם אמצעי נוסף")
        else:
            score += 0.3
            reasons.append("שם שונה")
        shared_ids = {(t, k) for t, k in (mine["ids"] & fc["ids"]) if is_personal_identifier(t, k)}
        if shared_ids:
            score += 6.0
            reasons.append("מזהה אישי משותף: " + ", ".join(sorted(k for _, k in shared_ids))[:80])
        if mine["addresses"] & fc["addresses"]:
            score += 3.0
            reasons.append("אותה כתובת")
        common_city = mine["cities"] & fc["cities"]
        if common_city:
            small = [x for x in common_city if x not in BIG_CITIES]
            score += 1.8 if small else 0.8
            reasons.append("אותה עיר: " + _city_display(sorted(common_city)[0]))
        elif mine["cities"] and fc["cities"]:
            score -= 1.0
            reasons.append("ערים שונות")
        if mine["birth"] and fc["birth"]:
            if mine["birth"] & fc["birth"]:
                score += 4.0
                reasons.append("אותו תאריך לידה")
            elif {b[:4] for b in mine["birth"]} & {b[:4] for b in fc["birth"]}:
                score += 1.0
                reasons.append("אותה שנת לידה")
            else:
                score -= 4.0
                reasons.append("תאריכי לידה שונים")
        if mine["orgs"] & fc["orgs"]:
            score += 1.5
            reasons.append("אותו ארגון")
        loc_me = {e.split("@")[0].replace(".", "") for e in mine["emails"]}
        loc_c = {e.split("@")[0].replace(".", "") for e in fc["emails"]}
        if loc_me & loc_c and not shared_ids:
            score += 1.5
            reasons.append("אותו שם משתמש במייל")
        decision = decided.get(pid)
        if pid in confirmed:
            decision = "same"
        prob = 1 / (1 + 2 ** -(score - 4.0))
        if decision is None and prob < 0.2:
            continue
        out.append(dict(id=pid, name=cname, score=round(score, 2), probability=round(prob, 3), reasons=reasons,
                        decision=decision, via=sorted(via[pid])))
    out.sort(key=lambda x: (x["decision"] != "same", x["decision"] == "different", -x["probability"], x["id"]))
    return dict(person=dict(id=eid, name=name), name_count=name_count, candidates=out[:limit],
                considered=len(ids), took=round(time.time() - t0, 3))
