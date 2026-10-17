"""Connections across files and the web: the same email / phone / address / username / profile / custom ID in
two places ties the records together. Used by the entity page and by the subject picture.
"""
from collections import defaultdict

from .analyze import origin_of, source_label
from .semantic import Registry, header_label
from .urls import PUBLIC_MAIL

ANCHOR_TYPES = ("email", "phone", "address", "username", "url", "domain", "national_id")
OWNER_TYPES = ("person", "org")


def _in(ids):
    return ",".join(str(int(i)) for i in ids) or "NULL"


def is_anchor(etype, key=""):
    if etype.startswith("u_"):
        return True
    if etype == "domain":
        return key not in PUBLIC_MAIL
    return etype in ANCHOR_TYPES


def attributes_of(store, eids, source_ids=None, registry=None):
    """Fields kept from files for these entities, grouped by original header."""
    if not eids:
        return []
    reg = registry or Registry(store.custom_types())
    cond = f" AND a.source_id IN ({_in(source_ids)})" if source_ids is not None else ""
    rows = store.q(f"SELECT a.name, a.value, a.kind, a.first_seen, a.last_seen, s.id sid, s.url, s.domain, s.title, "
                   f"s.state, s.import_id FROM attributes a JOIN sources s ON s.id=a.source_id "
                   f"WHERE a.entity_id IN ({_in(eids)}){cond} ORDER BY a.name, a.last_seen DESC")
    return _group_attribute_rows(store, rows, reg)


def _group_attribute_rows(store, rows, reg):
    groups = {}
    for r in rows:
        g = groups.setdefault(r["name"], dict(name=r["name"], type=r["kind"], values={}))
        if r["kind"] and r["kind"] != "unknown":
            g["label"] = reg.label(r["kind"])
        v = g["values"].setdefault(r["value"], dict(value=r["value"], files=set(), first_seen=r["first_seen"],
                                                     last_seen=r["last_seen"]))
        v["files"].add(source_label(store, r))
        v["first_seen"] = min(v["first_seen"], r["first_seen"])
        v["last_seen"] = max(v["last_seen"], r["last_seen"])
    out = []
    for g in groups.values():
        g.setdefault("label", header_label(g["name"]) or "לא מזוהה")
        g["values"] = [dict(v, files=sorted(v["files"])) for v in g["values"].values()]
        out.append(g)
    return out


def attributes_for_clusters(store, clusters):
    """Batch-load attributes for all clusters in a single SQL query instead of one query per cluster."""
    all_eids = {int(m) for c in clusters for m in c.get("members", ()) if m}
    if not all_eids:
        return [ [] for _ in clusters ]
    reg = Registry(store.custom_types())
    by_eid = defaultdict(list)
    eid_list = sorted(all_eids)
    for idx in range(0, len(eid_list), 800):
        chunk = eid_list[idx:idx + 800]
        rows = store.q(
            f"SELECT a.entity_id, a.name, a.value, a.kind, a.first_seen, a.last_seen, s.id sid, s.url, s.domain, s.title, "
            f"s.state, s.import_id FROM attributes a JOIN sources s ON s.id=a.source_id "
            f"WHERE a.entity_id IN ({_in(chunk)}) ORDER BY a.name, a.last_seen DESC"
        )
        for r in rows:
            by_eid[r["entity_id"]].append(r)
    result = []
    for c in clusters:
        c_rows = [r for m in c.get("members", ()) for r in by_eid.get(m, ())]
        result.append(_group_attribute_rows(store, c_rows, reg) if c_rows else [])
    return result


def origins_of(store, eid):
    """Where an entity was seen, grouped by file / site."""
    rows = store.q("SELECT s.id, s.url, s.domain, s.title, s.state, s.import_id, COUNT(*) n, MAX(v.last_seen) last_seen "
                   "FROM evidence v JOIN sources s ON s.id=v.source_id WHERE v.entity_id=? GROUP BY s.id", (eid,))
    groups = {}
    for r in rows:
        lab, org = source_label(store, r), origin_of(r)
        g = groups.setdefault((org, lab), dict(origin=org, label=lab, import_id=r["import_id"], mentions=0,
                                                url=r["url"] if org == "web" else None, last_seen=r["last_seen"]))
        g["mentions"] += r["n"]
        g["last_seen"] = max(g["last_seen"], r["last_seen"])
    return sorted(groups.values(), key=lambda g: (g["origin"], -g["mentions"]))


def _anchor_degree_exceeds(store, eid, max_deg=60):
    na = store.q1(f"SELECT COUNT(*) n FROM (SELECT 1 FROM relations WHERE a_id=? LIMIT {int(max_deg) + 1})", (eid,))["n"]
    if na > max_deg:
        return True
    nb = store.q1(f"SELECT COUNT(*) n FROM (SELECT 1 FROM relations WHERE b_id=? LIMIT {int(max_deg) + 1})", (eid,))["n"]
    return (na + nb) > max_deg


def _filter_low_degree_anchors(store, candidate_ids, max_deg=60) -> set:
    if not candidate_ids:
        return set()
    cands = sorted({int(i) for i in candidate_ids if i})
    if not cands:
        return set()
    lim = int(max_deg) + 1
    deg = int(max_deg)
    low = set()
    for idx in range(0, len(cands), 400):
        chunk = cands[idx:idx + 400]
        ph = ",".join(str(x) for x in chunk)
        rows = store.q(
            f"SELECT id FROM entities WHERE id IN ({ph}) "
            f"AND (SELECT COUNT(*) FROM (SELECT 1 FROM relations WHERE a_id=entities.id LIMIT {lim})) "
            f"+ (SELECT COUNT(*) FROM (SELECT 1 FROM relations WHERE b_id=entities.id LIMIT {lim})) <= {deg}"
        )
        for r in rows:
            low.add(r["id"])
    return low


def _neighbours(store, eids, types=None, limit=200):
    if not eids:
        return []
    ids = _in(eids)
    lim = int(limit)
    rows = store.q(
        f"SELECT r.a_id, r.b_id, r.kind, o.id oid, o.type, o.key, o.display FROM ("
        f"  SELECT * FROM (SELECT a_id, b_id, kind, b_id AS other_id FROM relations WHERE a_id IN ({ids}) AND kind != 'co_mentioned' LIMIT {lim}) "
        f"  UNION ALL "
        f"  SELECT * FROM (SELECT a_id, b_id, kind, a_id AS other_id FROM relations WHERE b_id IN ({ids}) AND a_id NOT IN ({ids}) AND kind != 'co_mentioned' LIMIT {lim})"
        f") r CROSS JOIN entities o ON o.id = r.other_id"
    )
    return [r for r in rows if types is None or r["type"] in types or (types == "anchor" and is_anchor(r["type"], r["key"]))]


def _files_for_relation(store, a, b):
    rows = store.q("SELECT DISTINCT s.id, s.url, s.domain, s.title, s.state, s.import_id FROM relations r "
                   "JOIN rel_evidence re ON re.relation_id=r.id JOIN sources s ON s.id=re.source_id "
                   "WHERE (r.a_id=? AND r.b_id=?) OR (r.a_id=? AND r.b_id=?) LIMIT 6", (a, b, b, a))
    return sorted({source_label(store, s) for s in rows})


def connections(store, eid, limit=40):
    """Other people/orgs that share an identifier with this entity, with what they share and where it came from.
    For an identifier entity (an email, a phone…): everyone it belongs to, each with their other details."""
    e = store.q1("SELECT * FROM entities WHERE id=?", (eid,))
    if not e:
        return dict(shared=[], owners=[])
    if e["type"] in OWNER_TYPES:
        anchors = [r for r in _neighbours(store, [eid], "anchor", limit=150)]
        valid_a_oids = _filter_low_degree_anchors(store, [a["oid"] for a in anchors], max_deg=60)
        shared = {}
        for a in anchors:
            if a["oid"] not in valid_a_oids:
                continue
            for o in _neighbours(store, [a["oid"]], OWNER_TYPES, limit=60):
                if o["oid"] == eid:
                    continue
                s = shared.setdefault(o["oid"], dict(id=o["oid"], type=o["type"], name=o["display"], display=o["display"], via=[]))
                s["via"].append(dict(type=a["type"], value=a["display"], display=a["display"], _a_oid=a["oid"]))
        out = sorted(shared.values(), key=lambda s: -len(s["via"]))[:limit]
        for s in out:
            for v in s["via"]:
                a_oid = v.pop("_a_oid", None)
                v["files"] = _files_for_relation(store, a_oid, s["id"]) if a_oid else []
        return dict(shared=out, owners=[])
    owners = []
    for o in _neighbours(store, [eid], OWNER_TYPES, limit=limit)[:limit]:
        details = defaultdict(list)
        for n in _neighbours(store, [o["oid"]], limit=60):
            if n["oid"] != eid and n["type"] not in ("role",) and len(details[n["type"]]) < 6:
                details[n["type"]].append(dict(id=n["oid"], value=n["display"]))
        owners.append(dict(id=o["oid"], type=o["type"], name=o["display"], details=dict(details),
                           files=_files_for_relation(store, eid, o["oid"]),
                           attributes=attributes_of(store, [o["oid"]])[:12]))
    return dict(shared=[], owners=owners)


def link_stats(store):
    """How connected the database is: identifiers that tie together 2+ people/orgs, and those seen in 2+ origins."""
    max_row = store.q1("SELECT COALESCE(MAX(id), 0) m FROM entities")
    max_id = int(max_row["m"] or 0) if max_row else 0
    if max_id > 50000:
        min_id = max(1, max_id - 10000)
        multi_owner = store.q1(
            "SELECT COUNT(*) n FROM ("
            "  SELECT x.id FROM entities x "
            "  JOIN relations r ON r.a_id=x.id "
            "  WHERE x.id >= ? AND x.type IN ('email','phone','address','username') AND r.kind!='co_mentioned' "
            "  GROUP BY x.id HAVING COUNT(DISTINCT r.b_id) >= 2"
            ")",
            (min_id,),
        )["n"]
        cross = store.q1(
            "SELECT COUNT(*) n FROM ("
            "  SELECT v.entity_id FROM evidence v "
            "  JOIN sources s ON s.id=v.source_id "
            "  WHERE v.entity_id >= ? "
            "  GROUP BY v.entity_id HAVING COUNT(DISTINCT COALESCE(s.import_id, -s.id)) >= 2"
            ")",
            (min_id,),
        )["n"]
        return dict(shared_identifiers=multi_owner, cross_source_entities=cross)
    multi_owner = store.q1(
        "SELECT COUNT(*) n FROM (SELECT x.id FROM entities x JOIN relations r ON (r.a_id=x.id OR r.b_id=x.id) "
        "JOIN entities o ON o.id = CASE WHEN r.a_id=x.id THEN r.b_id ELSE r.a_id END "
        "WHERE x.type IN ('email','phone','address','username') AND o.type IN ('person','org') AND r.kind!='co_mentioned' "
        "GROUP BY x.id HAVING COUNT(DISTINCT o.id) >= 2)")["n"]
    cross = store.q1(
        "SELECT COUNT(*) n FROM (SELECT v.entity_id FROM evidence v JOIN sources s ON s.id=v.source_id "
        "JOIN entities e ON e.id=v.entity_id WHERE e.type IN ('person','email','phone','address','username') "
        "GROUP BY v.entity_id HAVING COUNT(DISTINCT COALESCE(s.import_id, -s.id)) >= 2)")["n"]
    return dict(shared_identifiers=multi_owner, cross_source_entities=cross)
