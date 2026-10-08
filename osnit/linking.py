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
    reg = registry or Registry(store.custom_types())
    cond = f" AND a.source_id IN ({_in(source_ids)})" if source_ids is not None else ""
    rows = store.q(f"SELECT a.name, a.value, a.kind, a.first_seen, a.last_seen, s.id sid, s.url, s.domain, s.title, "
                   f"s.state, s.import_id FROM attributes a JOIN sources s ON s.id=a.source_id "
                   f"WHERE a.entity_id IN ({_in(eids)}){cond} ORDER BY a.name, a.last_seen DESC")
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


def _neighbours(store, eids, types=None):
    rows = store.q(f"SELECT r.a_id, r.b_id, r.kind, o.id oid, o.type, o.key, o.display FROM relations r JOIN entities o "
                   f"ON o.id = CASE WHEN r.a_id IN ({_in(eids)}) THEN r.b_id ELSE r.a_id END "
                   f"WHERE (r.a_id IN ({_in(eids)}) OR r.b_id IN ({_in(eids)})) AND r.kind != 'co_mentioned'")
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
        anchors = [r for r in _neighbours(store, [eid], "anchor")]
        shared = {}
        for a in anchors:
            for o in _neighbours(store, [a["oid"]], OWNER_TYPES):
                if o["oid"] == eid:
                    continue
                s = shared.setdefault(o["oid"], dict(id=o["oid"], type=o["type"], name=o["display"], via=[]))
                s["via"].append(dict(type=a["type"], value=a["display"],
                                     files=_files_for_relation(store, a["oid"], o["oid"])))
        out = sorted(shared.values(), key=lambda s: -len(s["via"]))[:limit]
        return dict(shared=out, owners=[])
    owners = []
    for o in _neighbours(store, [eid], OWNER_TYPES)[:limit]:
        details = defaultdict(list)
        for n in _neighbours(store, [o["oid"]]):
            if n["oid"] != eid and n["type"] not in ("role",) and len(details[n["type"]]) < 6:
                details[n["type"]].append(dict(id=n["oid"], value=n["display"]))
        owners.append(dict(id=o["oid"], type=o["type"], name=o["display"], details=dict(details),
                           files=_files_for_relation(store, eid, o["oid"]),
                           attributes=attributes_of(store, [o["oid"]])[:12]))
    return dict(shared=[], owners=owners)


def link_stats(store):
    """How connected the database is: identifiers that tie together 2+ people/orgs, and those seen in 2+ origins."""
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
