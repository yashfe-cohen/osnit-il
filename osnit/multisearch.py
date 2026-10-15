"""Multi-field lookup: find the person who matches several known clues at once — name + phone, address + name,
id + email, and so on. Each clue is normalised exactly the way the importer stored it, so '054-55-66-123'
matches '+972545566123', a name matches its spellings/nicknames/transliterations, and gmail dots or +tags
collapse. Candidates are scored by how many clues they match and how strong each clue is (a shared national id /
email / mobile points hard at one individual; a shared address or organisation is a weak, shared signal), then
ranked — the person who matches the most, strongest clues first. This is a suggestion for the operator to
confirm, never an automatic identity assertion (the precision-first rule)."""
from .extract import norm_phone_il, org_key
from .identity import find_people
from .semantic import address_key, email_key, il_id_key, username_key

# weight = how strongly a shared value points to the SAME person (mirrors the dossier's personal-vs-shared rule)
_WEIGHT = {"national_id": 1.0, "email": 1.0, "phone": 0.9, "username": 0.9, "name": 0.75, "address": 0.5, "org": 0.45}
_LABEL = {"name": "שם", "phone": "טלפון", "email": "מייל", "national_id": 'ת"ז', "address": "כתובת",
          "org": "ארגון", "username": "שם משתמש"}
_NORM = {"phone": norm_phone_il, "email": email_key, "national_id": il_id_key,
         "address": address_key, "org": org_key, "username": username_key}
FIELDS = ("name", "phone", "email", "national_id", "address", "org", "username")


def _persons_on(store, etype, key):
    """Person entity ids linked to the identifier entity (etype, key) — [] if that value is not in the data."""
    e = store.q1("SELECT id FROM entities WHERE type=? AND key=?", (etype, key))
    if not e:
        return []
    eid = e["id"]
    return [r["pid"] for r in store.q(
        "SELECT DISTINCT CASE WHEN r.a_id=? THEN r.b_id ELSE r.a_id END pid FROM relations r "
        "JOIN entities o ON o.id = CASE WHEN r.a_id=? THEN r.b_id ELSE r.a_id END "
        "WHERE (r.a_id=? OR r.b_id=?) AND o.type='person'", (eid, eid, eid, eid))]


def multi_find(store, fields, limit=50):
    """fields: {name,phone,email,national_id,address,org,username}. -> {fields:{used}, results:[ranked people]}."""
    fields = {k: str(v).strip() for k, v in (fields or {}).items() if k in FIELDS and v and str(v).strip()}
    cand, used = {}, {}

    def bump(pid, field, value, w):
        c = cand.setdefault(pid, {"score": 0.0, "matched": {}})
        if field not in c["matched"]:
            c["score"] += w
            c["matched"][field] = value

    for field, raw in fields.items():
        if field == "name":
            people = find_people(store, raw)
            if people:
                used["name"] = raw
            for p in people:
                bump(p["id"], "name", raw, _WEIGHT["name"])
            continue
        key = _NORM[field](raw)
        if not key:
            continue
        pids = _persons_on(store, field, key)
        if pids:
            used[field] = raw
        for pid in pids:
            bump(pid, field, raw, _WEIGHT[field])

    if not cand:
        return {"fields": used, "results": []}
    names = {}
    ids = list(cand)
    for i in range(0, len(ids), 900):                       # stay under SQLite's 999-variable bound
        part = ids[i:i + 900]
        for r in store.q(f"SELECT id, display FROM entities WHERE id IN ({','.join('?' * len(part))})", tuple(part)):
            names[r["id"]] = r["display"]
    out = []
    for pid, c in cand.items():
        out.append(dict(id=pid, name=names.get(pid, "?"), score=round(c["score"], 3), match_count=len(c["matched"]),
                        matched=[{"field": f, "label": _LABEL.get(f, f), "value": v} for f, v in c["matched"].items()]))
    out.sort(key=lambda x: (-x["match_count"], -x["score"], x["name"]))
    return {"fields": used, "results": out[:limit]}
