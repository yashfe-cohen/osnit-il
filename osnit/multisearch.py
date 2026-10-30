"""Multi-field lookup: find the person who matches several known clues at once — name + phone, address + name,
id + email, and so on. Each clue is normalised exactly the way the importer stored it, so '054-55-66-123'
matches '+972545566123', a name matches its spellings/nicknames/transliterations, and gmail dots or +tags
collapse. Candidates are scored by how many clues they match and how strong each clue is (a shared national id /
email / mobile points hard at one individual; a shared address or organisation is a weak, shared signal), then
ranked — the person who matches the most, strongest clues first. This is a suggestion for the operator to
confirm, never an automatic identity assertion (the precision-first rule)."""
from .extract import norm_phone_il, org_key
from .identity import find_people, suggest_same_person
from .semantic import address_key, email_key, il_id_key, username_key

# weight = how strongly a shared value points to the SAME person (mirrors the dossier's personal-vs-shared rule)
_WEIGHT = {"national_id": 1.0, "email": 1.0, "phone": 0.9, "username": 0.9, "name": 0.75, "address": 0.5, "org": 0.45}
_LABEL = {"name": "שם", "phone": "טלפון", "email": "מייל", "national_id": 'ת"ז', "address": "כתובת", "city": "עיר",
          "org": "ארגון", "username": "שם משתמש", "birth_year": "שנת לידה", "age": "גיל", "father": "שם האב"}
_NORM = {"phone": norm_phone_il, "email": email_key, "national_id": il_id_key,
         "address": address_key, "org": org_key, "username": username_key}
FIELDS = ("name", "phone", "email", "national_id", "address", "org", "username")


def _persons_on(store, etype, key):
    """Person entity ids linked to the identifier entity (etype, key) — [] if that value is not in the data."""
    eids = []
    eid = store.resolve_entity(etype, key)
    if eid:
        eids.append(eid)
    if etype in ("address", "org") and len(key) >= 2:
        for r in store.q(
            "SELECT id FROM entities WHERE type=? AND key >= ? AND key < ? LIMIT 50",
            (etype, key, key + "\uffff"),
        ):
            if r["id"] not in eids:
                eids.append(r["id"])
    if not eids:
        return []
    ph = ",".join("?" * len(eids))
    t = tuple(eids)
    return [r["pid"] for r in store.q(
        f"SELECT DISTINCT rel_pids.pid AS pid FROM ("
        f"  SELECT r.b_id AS pid FROM relations r WHERE r.a_id IN ({ph}) "
        f"  UNION "
        f"  SELECT r.a_id AS pid FROM relations r WHERE r.b_id IN ({ph})"
        f") rel_pids CROSS JOIN entities o ON o.id = rel_pids.pid WHERE o.type='person'",
        t + t,
    )]


def _place_hits(store, pids, place):
    """Which of these person ids are tied to `place` (a city or a street address): through a linked address/city
    entity or an attribute value (an imported "עיר"/"כתובת" column). Matching is on folded text containment, so
    'חיפה' matches 'הרצל 5, חיפה'. Only checks the given candidates (never scans the database)."""
    from .textnorm import fold
    want = fold(place).replace("-", " ").replace(",", " ").split()
    if not want or not pids:
        return set()
    want_s = " ".join(want)

    from .kinship import _extract_cities_from_strings
    want_towns = _extract_cities_from_strings([place])      # "Gan Yavne" finds "גן יבנה" and back

    def ok(v):
        f = " ".join(fold(str(v or "")).replace("-", " ").replace(",", " ").split())
        if bool(f) and (f" {want_s} " in f" {f} "):
            return True
        return bool(want_towns) and bool(want_towns & _extract_cities_from_strings([str(v or "")]))

    hits = set()
    ids = list(pids)
    for i in range(0, len(ids), 900):
        part = ids[i:i + 900]
        ph = ",".join("?" * len(part))
        for r in store.q(f"SELECT entity_id, value FROM attributes WHERE entity_id IN ({ph})", tuple(part)):
            if r["entity_id"] not in hits and ok(r["value"]):
                hits.add(r["entity_id"])
        t = tuple(part)
        for r in store.q(
            f"SELECT r.pid, o.display, o.key FROM ("
            f"  SELECT a_id AS pid, b_id AS oid FROM relations WHERE a_id IN ({ph}) "
            f"  UNION ALL SELECT b_id AS pid, a_id AS oid FROM relations WHERE b_id IN ({ph})"
            f") r CROSS JOIN entities o ON o.id = r.oid WHERE o.type IN ('address','city')", t + t):
            if r["pid"] not in hits and (ok(r["display"]) or ok(r["key"])):
                hits.add(r["pid"])
    return hits


def _who_hits(store, pids, birth, father):
    """Which candidates' OWN records satisfy a birth-year range / a father's name (identity-level; the individual
    view also looks across the identities of one person). -> ({pid: matched birth year}, {pid: father})."""
    from .individuals import _father_matches, fathers_of
    from .possible import _features
    by, bf = {}, {}
    ids = list(pids)
    if birth:
        lo, hi = birth
        for i in range(0, len(ids), 400):
            for pid, f in _features(store, ids[i:i + 400]).items():
                ys = sorted(int(d[:4]) for d in f["birth"] if d[:4].isdigit() and lo <= int(d[:4]) <= hi)
                if ys:
                    by[pid] = str(ys[0])
    if father:
        for pid, names in fathers_of(store, ids).items():
            hit = next((n for n in sorted(names) if _father_matches(n, father)), None)
            if hit:
                bf[pid] = hit
    return by, bf


def multi_find(store, fields, limit=50):
    """fields: {name,phone,email,national_id,address,city,org,username,birth_year,age,father}.
    -> {fields:{used}, results:[ranked identities], individuals:[distinct people], counts}.
    A city / street address, a birth year or age and a father's name narrow the candidates found by the other clues
    (each is shared by many people, so on its own it never lists everyone). `individuals` groups the found
    identities into people (individuals.py): who matches every detail asked, who conflicts, and which records may
    belong to whom."""
    raw_fields = dict(fields or {})
    if raw_fields.get("id_number") and not raw_fields.get("national_id"):
        raw_fields["national_id"] = raw_fields["id_number"]
    places = [(k, str(raw_fields.get(k)).strip()) for k in ("address", "city")
              if raw_fields.get(k) and str(raw_fields.get(k)).strip()]
    from .individuals import birth_range
    try:
        birth = birth_range({k: raw_fields.get(k) for k in ("birth_year", "age") if raw_fields.get(k)})
    except (TypeError, ValueError):
        birth = None
    father = str(raw_fields.get("father") or "").strip() or None
    fields = {k: str(v).strip() for k, v in raw_fields.items() if k in FIELDS and v and str(v).strip()}
    cand, used = {}, {}

    def bump(pid, field, value, w):
        c = cand.setdefault(pid, {"score": 0.0, "matched": {}})
        if field not in c["matched"]:
            c["score"] += w
            c["matched"][field] = value

    for field, raw in fields.items():
        if field == "name":
            people = find_people(store, raw, limit=max(limit * 4, 200))
            sub_people = suggest_same_person(store, raw, exclude_ids=[p["id"] for p in people])
            if people or sub_people:
                used["name"] = raw
            for p in people:
                bump(p["id"], "name", raw, _WEIGHT["name"])
            for sp in sub_people:
                bump(sp["id"], "name", raw, round(_WEIGHT["name"] * 0.9, 3))
            continue
        key = _NORM[field](raw)
        if not key:
            continue
        pids = _persons_on(store, field, key)
        if pids:
            used[field] = raw
        for pid in pids:
            bump(pid, field, raw, _WEIGHT[field])

    # place clues: an address entity can still find its owners directly (above); both an address and a city also
    # confirm candidates through their linked addresses / imported address-or-city attributes
    for fname, place in places:
        for pid in _place_hits(store, list(cand), place):
            used[fname] = place
            c = cand[pid]
            if "address" not in c["matched"] and "city" not in c["matched"]:
                c["score"] += _WEIGHT["address"]
            c["matched"][fname] = place

    # who-clues: a birth year / age and a father's name confirm candidates (never find them on their own)
    if cand and (birth or father):
        by, bf = _who_hits(store, list(cand), birth, father)
        bfield = "birth_year" if raw_fields.get("birth_year") else "age"
        for pid, y in by.items():
            used[bfield] = str(raw_fields.get(bfield))
            c = cand[pid]
            if bfield not in c["matched"]:
                c["score"] += 0.6
                c["matched"][bfield] = y
        for pid, fname in bf.items():
            used["father"] = father
            c = cand[pid]
            if "father" not in c["matched"]:
                c["score"] += 0.5
                c["matched"]["father"] = fname

    if not cand:
        return {"fields": used, "results": [], "individuals": [],
                "counts": dict(match=0, possible=0, conflict=0, attached=0)}
    names = {}
    ids = list(cand)
    for i in range(0, len(ids), 900):                       # stay under SQLite's 999-variable bound
        part = ids[i:i + 900]
        for r in store.q(f"SELECT id, display FROM entities WHERE id IN ({','.join('?' * len(part))})", tuple(part)):
            names[r["id"]] = r["display"]
    from .contacts import _aggregate, _dedupe
    det = _aggregate(store, ids) if ids else {}
    out = []
    for pid, c in cand.items():
        d = det.get(pid, {})
        out.append(dict(id=pid, name=names.get(pid, "?"), score=round(c["score"], 3), match_count=len(c["matched"]),
                        emails=_dedupe(d.get("emails", [])), phones=_dedupe(d.get("phones", [])),
                        orgs=_dedupe(d.get("orgs", [])), sources=d.get("sources", 0),
                        osint_count=d.get("osint_count", 0), avatar=d.get("avatar", ""),
                        matched=[{"field": f, "label": _LABEL.get(f, f), "value": v} for f, v in c["matched"].items()]))
    out.sort(key=lambda x: (-x["match_count"], -x["score"], -x.get("osint_count", 0), -x.get("sources", 0), x["name"]))
    from .individuals import build
    quals = {k: v for k, v in places}
    if birth:
        quals["birth_year"] = birth
    if father:
        quals["father"] = father
    for k in ("name", "phone", "email", "national_id"):
        if fields.get(k):
            quals[k] = fields[k]
    ind = build(store, [r["id"] for r in out], quals, matched={pid: c["matched"] for pid, c in cand.items()})
    return {"fields": used, "results": out[:limit], "individuals": ind["individuals"], "counts": ind["counts"]}

