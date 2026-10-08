"""Identity dossier: everything the database holds about one person, as threads between details.

Start from a name (or any entity): collect every person record with that name in any spelling (Hebrew/Latin,
typos, word order), then follow the threads — emails, phones, addresses, usernames, profiles, the user's own
IDs, organisations — to see which records are the same individual and what belongs to whom.

  * records that share a *personal* identifier (email, username, profile, custom ID, a phone few people use)
    are the same individual  -> one cluster ("יצחק כהן #1")
  * an address, organisation or a shared phone links people but does not merge them (family, colleagues)
  * every detail is ranked per cluster: independent sources, confidence, how many records confirm it, and how
    exclusive it is (a phone used by 3 different people is a weak fact about any one of them)
  * people with other names that share an identifier are shown as threads to other people, not merged
"""
import math
from collections import defaultdict

from .analyze import origin_of, source_label
from .linking import attributes_of
from .profile import combine
from .store import similar_person_keys
from .textnorm import fold, name_key
from .urls import PUBLIC_MAIL
from .variants import name_variants
from .xling import same_person_name

STRONG = {"email", "username", "url", "national_id"}   # + custom IDs (u_*) and lightly-shared phones
WEAK = {"address", "org", "domain", "role"}
FACET_ORDER = ["national_id", "phone", "email", "username", "url", "address", "org", "role", "domain"]
MAX_NODES = 220


def _in(ids):
    return ",".join(str(int(i)) for i in ids) or "NULL"


def _name_matches(a: str, b: str) -> bool:
    ka, kb = name_key(a), name_key(b)
    return ka == kb or similar_person_keys(ka, kb) or same_person_name(a, b)


def find_people(store, name: str, limit=200):
    """Person records whose name is this name in any spelling."""
    keys = {name_key(" ".join(v)) for v in name_variants(name)[:24]} | {name_key(name)}
    probes = {t[:3] for k in keys for t in k.split() if len(t) >= 3}
    seen, out = set(), []
    for p in probes:
        for r in store.q("SELECT id, key, display FROM entities WHERE type='person' AND key LIKE ? LIMIT 400", (f"%{p}%",)):
            if r["id"] in seen:
                continue
            seen.add(r["id"])
            if r["key"] in keys or _name_matches(name, r["display"]):
                out.append(dict(r))
                if len(out) >= limit:
                    return out
    return out


def _links(store, eids):
    """(entity, neighbour, relation kind, best confidence, [(source id, domain/import, origin, label)])"""
    if not eids:
        return []
    rows = store.q(
        f"SELECT r.id rid, r.a_id, r.b_id, r.kind, re.confidence, s.id sid, s.url, s.domain, s.title, s.state, s.import_id "
        f"FROM relations r JOIN rel_evidence re ON re.relation_id=r.id JOIN sources s ON s.id=re.source_id "
        f"WHERE (r.a_id IN ({_in(eids)}) OR r.b_id IN ({_in(eids)})) AND r.kind != 'co_mentioned'")
    eids = set(eids)
    agg = {}
    for r in rows:
        me, other = (r["a_id"], r["b_id"]) if r["a_id"] in eids else (r["b_id"], r["a_id"])
        g = agg.setdefault((me, other, r["kind"]), dict(me=me, other=other, kind=r["kind"], conf=0.0, src={}))
        g["conf"] = max(g["conf"], r["confidence"])
        g["src"][r["sid"]] = (f"imp{r['import_id']}" if r["import_id"] else (r["domain"] or r["url"]), r["confidence"],
                              origin_of(r), source_label(store, r))
    return list(agg.values())


def _entities(store, ids):
    return {r["id"]: dict(r) for r in store.q(f"SELECT id, type, key, display FROM entities WHERE id IN ({_in(ids)})")}


class _UF:
    def __init__(self, items):
        self.p = {i: i for i in items}

    def find(self, x):
        while self.p[x] != x:
            self.p[x] = self.p[self.p[x]]
            x = self.p[x]
        return x

    def union(self, a, b):
        self.p[self.find(a)] = self.find(b)


def _is_strong(etype, n_owners):
    return etype in STRONG or etype.startswith("u_") or (etype == "phone" and n_owners <= 2)


def dossier(store, eid=None, name=None) -> dict:
    """The full picture around a person name (or around any entity: an email, a phone, an ID…)."""
    focus = store.q1("SELECT * FROM entities WHERE id=?", (eid,)) if eid else None
    if focus is not None and focus["type"] != "person":
        owners = [l for l in _links(store, [focus["id"]]) if True]
        ents = _entities(store, [l["other"] for l in owners])
        seeds = [ents[l["other"]] for l in owners if ents.get(l["other"], {}).get("type") == "person"]
        title = focus["display"]
    else:
        name = name or (focus["display"] if focus else "")
        seeds = find_people(store, name) if name else []
        if focus is not None and all(s["id"] != focus["id"] for s in seeds):
            seeds.append(dict(focus))
        title = name
    seed_ids = {s["id"] for s in seeds}

    def gather(seed_ids):
        links = _links(store, seed_ids)
        ents = _entities(store, {l["other"] for l in links} | seed_ids)
        # who else uses each detail (other people / orgs): exclusivity and threads to other people
        detail_ids = {l["other"] for l in links if ents.get(l["other"], {}).get("type") != "person"}
        back = _links(store, detail_ids)
        ents.update(_entities(store, {l["other"] for l in back} - set(ents)))
        users = defaultdict(set)
        for l in back:
            if ents.get(l["other"], {}).get("type") in ("person", "org"):
                users[l["me"]].add(l["other"])
        return links, ents, users

    links, ents, users = gather(seed_ids)

    # absorb records written another way that share a personal identifier and a name token
    def name_tokens(n):
        return {fold(t) for t in n.split() if len(t) >= 2}
    seed_names = set().union(*(name_tokens(s["display"]) for s in seeds)) if seeds else set()
    absorbed = False
    for d, us in list(users.items()):
        de = ents.get(d)
        if not de or not (de["type"] in STRONG or de["type"].startswith("u_")):
            continue
        for u in us:
            ue = ents.get(u)
            if u in seed_ids or not ue or ue["type"] != "person":
                continue
            if any(same_person_name(ue["display"], s["display"]) for s in seeds) or (name_tokens(ue["display"]) & seed_names):
                seeds.append(ue)
                seed_ids.add(u)
                absorbed = True
    if absorbed:
        links, ents, users = gather(seed_ids)

    # ---- clusters: records sharing a personal identifier are one individual
    uf = _UF(seed_ids)
    by_detail = defaultdict(set)
    for l in links:
        by_detail[l["other"]].add(l["me"])
    for d, ps in by_detail.items():
        de = ents.get(d)
        if de and len(ps) > 1 and _is_strong(de["type"], len(users.get(d, ps))) and \
                not (de["type"] == "email" and de["key"].split("@")[0] in ("info", "office", "contact")):
            ps = list(ps)
            for p in ps[1:]:
                uf.union(ps[0], p)
    groups = defaultdict(list)
    for s in seed_ids:
        groups[uf.find(s)].append(s)

    clusters = []
    for root, members in groups.items():
        facets = defaultdict(dict)
        files = set()
        for l in links:
            if l["me"] not in members:
                continue
            o = ents.get(l["other"])
            if not o or o["type"] == "person":
                continue
            if o["type"] == "domain" and o["key"] in PUBLIC_MAIL:
                continue
            it = facets[o["type"]].setdefault(o["id"], dict(id=o["id"], type=o["type"], value=o["display"], kind=l["kind"],
                                                            records=set(), src={}))
            it["records"].add(l["me"])
            it["src"].update(l["src"])
            for s in l["src"].values():
                if s[2] == "file":
                    files.add(s[3])
        clusters.append(dict(root=root, members=members, facets=facets, files=files))

    # exclusivity: how many separate individuals (clusters + outside people/orgs) hold each detail
    holders = defaultdict(set)
    for i, c in enumerate(clusters):
        for t, items in c["facets"].items():
            for did in items:
                holders[did].add(("c", i))
    for d, us in users.items():
        for u in us:
            if u not in seed_ids:
                holders[d].add(("e", u))

    out = []
    for i, c in enumerate(clusters):
        fac = {}
        for t, items in c["facets"].items():
            lst = []
            for it in items.values():
                base = combine([(dom, conf) for dom, conf, _o, _l in it["src"].values()])
                n_hold = max(1, len(holders[it["id"]]))
                corro = min(1.0, 0.85 + 0.15 * len(it["records"]))
                score = round(min(0.99, base * corro / math.sqrt(n_hold)), 3)
                others = []
                for kind, x in holders[it["id"]]:
                    if kind == "e" and ents.get(x):
                        others.append(dict(id=x, name=ents[x]["display"], type=ents[x]["type"]))
                    elif kind == "c" and x != i:
                        others.append(dict(cluster=x + 1))
                lst.append(dict(id=it["id"], value=it["value"], type=t, score=score, kind=it["kind"],
                                records=len(it["records"]), sources=len(it["src"]),
                                origins=sorted({s[2] for s in it["src"].values()}),
                                where=sorted({s[3] for s in it["src"].values()})[:6], shared_with=others[:8]))
            fac[t] = sorted(lst, key=lambda x: -x["score"])
        names = sorted({ents[m]["display"] for m in c["members"] if m in ents})
        strength = combine([("x%d" % n, x["score"]) for n, x in enumerate(v for vs in fac.values() for v in vs[:3])])
        out.append(dict(names=names, records=[dict(id=m, name=ents[m]["display"]) for m in c["members"] if m in ents],
                        facets={t: fac[t] for t in sorted(fac, key=lambda t: FACET_ORDER.index(t) if t in FACET_ORDER else 99)},
                        attributes=attributes_of(store, c["members"]), files=sorted(c["files"]),
                        detail_count=sum(len(v) for v in fac.values()), strength=round(strength, 3)))
    out.sort(key=lambda c: (-c["detail_count"], -c["strength"]))
    for n, c in enumerate(out, 1):
        c["n"] = n

    return dict(title=title, focus=dict(focus) if focus is not None else None, clusters=out,
                people_connected=_connected(clusters, users, ents, seed_ids),
                graph=_graph(out, users, ents, seed_ids))


def _connected(clusters, users, ents, seed_ids):
    """Other people who share a detail with one of the clusters (threads to other people)."""
    res = {}
    for i, c in enumerate(clusters):
        for t, items in c["facets"].items():
            for did, it in items.items():
                for u in users.get(did, ()):
                    e = ents.get(u)
                    if u in seed_ids or not e or e["type"] != "person":
                        continue
                    r = res.setdefault(u, dict(id=u, name=e["display"], via=[]))
                    r["via"].append(dict(type=t, value=it["value"], cluster=i + 1))
    return sorted(res.values(), key=lambda r: -len(r["via"]))[:40]


def _graph(clusters, users, ents, seed_ids):
    """Nodes and threads for drawing: individual hubs, their records, their details, and other people on them."""
    nodes, edges, seen = [], [], set()

    def node(key, **kw):
        if key not in seen and len(nodes) < MAX_NODES:
            seen.add(key)
            nodes.append(dict(key=key, **kw))
        return key in seen

    for c in clusters:
        hub = f"c{c['n']}"
        node(hub, kind="cluster", label=f"{c['names'][0]} #{c['n']}" if c["names"] else f"#{c['n']}", cluster=c["n"])
        if len(c["records"]) > 1:
            for r in c["records"]:
                if node(f"e{r['id']}", kind="person", id=r["id"], label=r["name"], cluster=c["n"]):
                    edges.append(dict(a=hub, b=f"e{r['id']}", w=1.0, kind="record"))
        for t, items in c["facets"].items():
            for it in items[:12]:
                if node(f"e{it['id']}", kind=t, id=it["id"], label=it["value"], cluster=c["n"]):
                    edges.append(dict(a=hub, b=f"e{it['id']}", w=it["score"], kind=t))
                for u in users.get(it["id"], ()):
                    e = ents.get(u)
                    if u in seed_ids or not e:
                        continue
                    if node(f"e{u}", kind="other_" + e["type"], id=u, label=e["display"]):
                        edges.append(dict(a=f"e{it['id']}", b=f"e{u}", w=0.4, kind="shared"))
    return dict(nodes=nodes, edges=edges)
