"""Builds the 'intelligence picture' for a subject from stored evidence. Always computed from the live DB."""
import json
import time
from collections import defaultdict
from difflib import SequenceMatcher

from .store import Store
from .urls import DOC_EXT, PUBLIC_MAIL, ext_of
from .xling import name_matches_label, role_canon, role_org, same_org_name, same_person_name

DOC_KINDS = {"pdf", "docx", "xlsx", "csv", "json", "txt", "vcf"}
ANCHORS = {"email", "phone", "org", "domain", "address", "username", "national_id"}
FACETS = {"org": "orgs", "role": "roles", "email": "emails", "phone": "phones", "domain": "domains",
          "url": "links", "person": "people", "address": "addresses", "username": "usernames",
          "national_id": "identifiers"}


def combine(items):
    """items: [(source_domain, confidence)] -> noisy-or over independent domains, rank-discounted."""
    best = {}
    for d, c in items:
        best[d] = max(best.get(d, 0.0), c)
    p, out = 1.0, sorted(best.values(), reverse=True)
    for i, c in enumerate(out):
        p *= 1 - c * (0.85 ** i)
    return round(min(0.99, 1 - p), 3) if out else 0.0


class _UF:
    def __init__(self):
        self.p = {}

    def find(self, x):
        self.p.setdefault(x, x)
        while self.p[x] != x:
            self.p[x] = self.p[self.p[x]]
            x = self.p[x]
        return x

    def union(self, a, b):
        self.p[self.find(a)] = self.find(b)


def _in(ids):
    return ",".join(str(int(i)) for i in ids) or "NULL"


def org_groups(store: Store, orgs: dict, nearby_domains=()) -> dict:
    """Org entity id -> group id. Same org across languages: transliterated name, or a shared own domain
    (linked to the org, or a domain of this picture whose name spells the org)."""
    if not orgs:
        return {}
    ids = _in(orgs)
    doms = defaultdict(set)
    for r in store.q(f"SELECT r.a_id, r.b_id, e.key, MAX(re.confidence) c FROM relations r "
                     f"JOIN rel_evidence re ON re.relation_id=r.id "
                     f"JOIN entities e ON e.id = CASE WHEN r.a_id IN ({ids}) THEN r.b_id ELSE r.a_id END "
                     f"WHERE (r.a_id IN ({ids}) OR r.b_id IN ({ids})) AND e.type='domain' GROUP BY r.id"):
        if r["c"] >= 0.5 and r["key"] not in PUBLIC_MAIL:
            doms[r["a_id"] if r["a_id"] in orgs else r["b_id"]].add(r["key"])
    for oid, o in orgs.items():
        for d in nearby_domains:
            if d not in PUBLIC_MAIL and name_matches_label(o["display"], d.split(".")[0]):
                doms[oid].add(d)
    uf = _UF()
    lst = list(orgs.values())
    for i, a in enumerate(lst):
        uf.find(a["id"])
        for b in lst[i + 1:]:
            if doms[a["id"]] & doms[b["id"]] or same_org_name(a["display"], b["display"]):
                uf.union(a["id"], b["id"])
    return {i: uf.find(i) for i in orgs}


def _merge(items: dict, keyf) -> dict:
    """Fold facet items that are the same thing written differently; keeps every spelling as an alias."""
    out = {}
    for iid, it in items.items():
        k = keyf(iid, it)
        g = out.get(k)
        if g is None:
            out[k] = dict(it, aliases=[])
            continue
        best = max(c for _, c in it["_c"]) > max(c for _, c in g["_c"])
        g["aliases"].append(g["value"] if best else it["value"])
        if best:
            g["value"] = it["value"]
        g["evidence"] = g["evidence"] + it["evidence"]
        g["_c"] = g["_c"] + it["_c"]
        g["first_seen"] = min(g["first_seen"], it["first_seen"])
        g["last_seen"] = max(g["last_seen"], it["last_seen"])
    return out


def subject_entity_ids(store: Store, subj) -> set:
    ids = {r["entity_id"] for r in store.q("SELECT entity_id FROM subject_entities WHERE subject_id=?", (subj["id"],))}
    e = store.q1("SELECT id FROM entities WHERE type=? AND key=?", (subj["entity_type"], subj["entity_key"]))
    if e:
        ids.add(e["id"])
    return ids


def _ev_status(r):
    """active: still on the page at its last scan; gone: was removed since; historical: imported, not re-checkable."""
    if r["sstate"] == "imported":
        return "historical"
    return "active" if r["last_seen"] >= (r["slast"] or 0) - 1e-6 else "gone"   # same scan writes the same timestamp


def build_profile(store: Store, subject_id: int, since: float = None) -> dict:
    subj = store.q1("SELECT * FROM subjects WHERE id=?", (subject_id,))
    if not subj:
        return None
    E = subject_entity_ids(store, subj)
    kind = subj["kind"]
    ents = {r["id"]: r for r in store.q(f"SELECT * FROM entities WHERE id IN ({_in(E)})")}
    # mentions of the subject itself
    mentions = store.q(
        f"SELECT ev.entity_id, ev.source_id, ev.snippet, ev.confidence, ev.first_seen, ev.last_seen, "
        f"s.url, s.domain, s.kind skind, s.title, s.first_seen sfirst, s.last_scanned, s.last_changed, "
        f"s.state sstate, s.import_id "
        f"FROM evidence ev JOIN sources s ON s.id=ev.source_id WHERE ev.entity_id IN ({_in(E)})")
    rels = store.q(
        f"SELECT r.id rid, r.a_id, r.b_id, r.kind, re.source_id, re.snippet, re.confidence, re.first_seen, re.last_seen, "
        f"s.url, s.domain, s.kind skind, s.title, s.last_scanned slast, s.state sstate, s.import_id "
        f"FROM relations r JOIN rel_evidence re ON re.relation_id=r.id "
        f"JOIN sources s ON s.id=re.source_id WHERE r.a_id IN ({_in(E)}) OR r.b_id IN ({_in(E)})")
    other_ids = {(r["b_id"] if r["a_id"] in E else r["a_id"]) for r in rels} - E
    others = {r["id"]: r for r in store.q(f"SELECT * FROM entities WHERE id IN ({_in(other_ids)})")}

    file_names = {r["id"]: r["name"] for r in store.q("SELECT id, name FROM imports")}

    def origin(r):
        url = r["url"] or ""
        return "file" if (r["import_id"] or r["sstate"] == "imported" or url.startswith(("import://", "file://"))) else "web"

    def where(r):
        if r["import_id"] and r["import_id"] in file_names:
            return file_names[r["import_id"]]
        url = r["url"] or ""
        return (r["domain"] or url) if url.startswith("http") else (r["title"] or url).split(" / ")[0]

    src = {}
    for m in mentions:
        src[m["source_id"]] = dict(id=m["source_id"], url=m["url"], domain=m["domain"], title=m["title"], kind=m["skind"],
                                   first_seen=m["sfirst"], last_scanned=m["last_scanned"], last_changed=m["last_changed"],
                                   origin=origin(m), where=where(m))
    for r in rels:
        src.setdefault(r["source_id"], dict(id=r["source_id"], url=r["url"], domain=r["domain"], title=r["title"],
                                            kind=r["skind"], origin=origin(r), where=where(r)))

    org_group = org_groups(store, {i: o for i, o in others.items() if o["type"] == "org"},
                           [o["key"] for o in others.values() if o["type"] == "domain"])
    org_by_key = {o["key"]: i for i, o in others.items() if o["type"] == "org"}

    # ---- identity clustering (people only; other kinds are a single picture)
    uf = _UF()
    for sid in src:
        uf.find(("s", sid))
    anchored = set()
    link_rows = []
    for r in rels:
        oid = r["b_id"] if r["a_id"] in E else r["a_id"]
        o = others.get(oid)
        if not o or r["kind"] == "co_mentioned":
            continue
        link_rows.append((r, o))
        if kind == "person" and (o["type"] in ANCHORS or o["type"].startswith("u_")) and not (o["type"] == "domain" and o["key"] in PUBLIC_MAIL) \
                and r["confidence"] >= 0.4:
            uf.union(("s", r["source_id"]), ("a", org_group.get(o["id"], o["id"])))
            anchored.add(r["source_id"])
    clusters = defaultdict(set)
    for sid in src:
        if kind != "person":
            clusters["all"].add(sid)
        elif sid in anchored:
            clusters[uf.find(("s", sid))].add(sid)
        else:
            clusters["unattributed"].add(sid)

    aliases = defaultdict(set)
    for a in store.q(f"SELECT alias, source_id FROM aliases WHERE entity_id IN ({_in(E)})"):
        aliases[a["source_id"]].add(a["alias"])

    def pack(cluster_sources, label_hint=None):
        facets = defaultdict(dict)
        for r, o in link_rows:
            if r["source_id"] not in cluster_sources:
                continue
            fk = FACETS.get(o["type"])
            if not fk and o["type"].startswith("u_"):
                fk = "identifiers"
            if not fk:
                continue
            if o["type"] == "url" and ext_of(o["key"]) in DOC_EXT:
                fk = "documents_linked"
            it = facets[fk].setdefault(o["id"], dict(type=o["type"], value=o["display"], relation=r["kind"], evidence=[],
                                                     first_seen=r["first_seen"], last_seen=r["last_seen"], _c=[]))
            it["evidence"].append(dict(url=r["url"], snippet=r["snippet"], confidence=round(r["confidence"], 2),
                                       first_seen=r["first_seen"], last_seen=r["last_seen"], status=_ev_status(r),
                                       origin=origin(r), where=where(r)))
            it["_c"].append((r["domain"], r["confidence"]))
            it["first_seen"] = min(it["first_seen"], r["first_seen"])
            it["last_seen"] = max(it["last_seen"], r["last_seen"])
        if "orgs" in facets:
            facets["orgs"] = _merge(facets["orgs"], lambda iid, it: org_group.get(iid, iid))

        def role_key(iid, it):
            okey = others[iid]["key"].split("|", 1)[1] if "|" in others[iid]["key"] else ""
            oid = org_by_key.get(okey)
            return role_canon(it["value"]), org_group.get(oid, oid) if oid else role_org(it["value"]).lower()
        if "roles" in facets:
            facets["roles"] = _merge(facets["roles"], role_key)
        out = {}
        for fk, items in facets.items():
            lst = []
            for it in items.values():
                it.setdefault("aliases", [])
                it["confidence"] = combine(it.pop("_c"))
                it["sources"] = len({e["url"] for e in it["evidence"]})
                live = {e["url"] for e in it["evidence"] if e["status"] != "gone"}
                # an older wording of a fact that is still on the same page is not a disappearance
                it["evidence"] = [e for e in it["evidence"] if e["status"] != "gone" or e["url"] not in live]
                sts = {e["status"] for e in it["evidence"]}
                it["status"] = "active" if "active" in sts else "historical" if "historical" in sts else "gone"
                it["is_new"] = bool(since) and it["first_seen"] > since
                it["origins"] = sorted({e["origin"] for e in it["evidence"]})
                it["where"] = sorted({e["where"] for e in it["evidence"]})[:6]
                it["evidence"] = sorted(it["evidence"], key=lambda e: (e["status"] != "active", -e["confidence"]))[:5]
                lst.append(it)
            out[fk] = sorted(lst, key=lambda x: (-x["confidence"], x["value"]))
        mc = [(m["domain"], m["confidence"]) for m in mentions if m["source_id"] in cluster_sources]
        srcs = sorted((src[s] for s in cluster_sources), key=lambda s: s["url"])
        names = {ents[e]["display"] for e in E if e in ents}
        for s in cluster_sources:
            names |= aliases.get(s, set())
        docs = [s for s in srcs if s["kind"] in DOC_KINDS]
        has_anchor = any(x in out for x in ("emails", "phones", "orgs", "domains"))
        conf = combine(mc) * (1.0 if has_anchor or kind != "person" else 0.85)
        seen = [m["first_seen"] for m in mentions if m["source_id"] in cluster_sources]
        last = [m["last_seen"] for m in mentions if m["source_id"] in cluster_sources]
        from .linking import attributes_of
        return dict(
            attributes=attributes_of(store, E, cluster_sources),
            origins=dict(file=sum(1 for x in srcs if x["origin"] == "file"), web=sum(1 for x in srcs if x["origin"] == "web")),
            confidence=round(conf, 3), names=sorted(names), sources=srcs, documents=docs, source_count=len(srcs),
            first_seen=min(seen) if seen else None, last_seen=max(last) if last else None,
            mentions=[dict(url=m["url"], snippet=m["snippet"], confidence=round(m["confidence"], 2),
                           first_seen=m["first_seen"], last_seen=m["last_seen"])
                      for m in sorted((m for m in mentions if m["source_id"] in cluster_sources),
                                      key=lambda m: -m["confidence"])[:6]],
            **{k: out.get(k, []) for k in ("orgs", "roles", "emails", "phones", "addresses", "usernames", "identifiers", "domains",
                                            "links", "documents_linked", "people")})

    identities, unattributed = [], None
    for key, cs in clusters.items():
        pk = pack(cs)
        if key == "unattributed":
            unattributed = pk
            continue
        top = (pk["roles"] or pk["orgs"] or pk["domains"] or pk["emails"] or [{"value": ""}])[0]["value"]
        pk["label"] = top
        identities.append(pk)
    identities.sort(key=lambda i: (-i["confidence"], -i["source_count"]))
    for n, i in enumerate(identities, 1):
        i["id"] = n

    # ---- related people (co-mentions), similar names (not auto-merged), timeline
    related = {}
    for r in rels:
        oid = r["b_id"] if r["a_id"] in E else r["a_id"]
        o = others.get(oid)
        if o and r["kind"] == "co_mentioned" and o["type"] == "person":
            it = related.setdefault(oid, dict(type="person", value=o["display"], relation="co_mentioned", _c=[], evidence=[]))
            it["_c"].append((r["domain"], r["confidence"]))
            it["evidence"].append(dict(url=r["url"], snippet=r["snippet"], confidence=round(r["confidence"], 2)))
    groups = []                        # same person written in Hebrew and in Latin letters
    for oid, it in related.items():
        g = next((g for g in groups if same_person_name(g[0]["value"], it["value"])), None)
        if g:
            g.append(it)
        else:
            groups.append([it])
    related = {}
    for n, g in enumerate(groups):
        head = max(g, key=lambda x: max(c for _, c in x["_c"]))
        related[n] = dict(head, aliases=[x["value"] for x in g if x is not head],
                          _c=[c for x in g for c in x["_c"]], evidence=[e for x in g for e in x["evidence"]])
    rel_list = []
    for it in related.values():
        it["confidence"] = combine(it.pop("_c"))
        it["evidence"] = it["evidence"][:3]
        rel_list.append(it)
    rel_list.sort(key=lambda x: -x["confidence"])

    similar = []
    if kind == "person":
        from .textnorm import name_key
        ck = name_key(subj["canonical"])
        toks = [t[:3] for t in ck.split() if len(t) >= 3]
        if toks:
            cond = " OR ".join("key LIKE ?" for _ in toks)
            for c in store.q(f"SELECT id,display,key FROM entities WHERE type='person' AND ({cond}) LIMIT 300",
                             tuple(f"%{t}%" for t in toks)):
                if c["id"] in E:
                    continue
                ratio = SequenceMatcher(None, ck, c["key"]).ratio()
                if ratio >= 0.8:
                    n = store.q1("SELECT COUNT(DISTINCT source_id) n FROM evidence WHERE entity_id=?", (c["id"],))["n"]
                    similar.append(dict(value=c["display"], similarity=round(ratio, 2), sources=n))
        similar.sort(key=lambda x: -x["similarity"])

    timeline = []          # appeared / disappeared, oldest first
    for i in identities + ([unattributed] if unattributed else []):
        for fk in ("orgs", "roles", "emails", "phones", "domains", "documents_linked"):
            for it in i.get(fk, []):
                timeline.append(dict(at=it["first_seen"], what="first_seen", type=it["type"], value=it["value"]))
                if it["status"] == "gone":
                    timeline.append(dict(at=it["last_seen"], what="gone", type=it["type"], value=it["value"]))
    timeline.sort(key=lambda x: x["at"])
    since_summary = None
    if since:
        items = [it for i in identities + ([unattributed] if unattributed else [])
                 for fk in ("orgs", "roles", "emails", "phones", "domains", "documents_linked") for it in i.get(fk, [])]
        since_summary = dict(since=since, new=sum(1 for it in items if it["is_new"]),
                             gone=sum(1 for it in items if it["status"] == "gone" and it["last_seen"] > since))
    events = [dict(id=e["id"], at=e["at"], type=e["kind"], data=json.loads(e["payload"]))
              for e in store.q("SELECT * FROM events WHERE subject_id=? ORDER BY id DESC LIMIT 60", (subject_id,))]
    jobs = {r["state"]: r["n"] for r in store.q("SELECT state, COUNT(*) n FROM jobs WHERE subject_id=? GROUP BY state", (subject_id,))}
    sstate = {r["state"]: r["n"] for r in store.q("SELECT state, COUNT(*) n FROM sources WHERE subject_id=? GROUP BY state", (subject_id,))}
    intent = json.loads(subj["intent"]) if subj["intent"] else {}
    answer = {}
    allid = identities + ([unattributed] if unattributed else [])
    for w, facet in (("phone", "phones"), ("email", "emails"), ("org", "orgs")):
        if w in intent.get("want", []):
            rows = [dict(it, identity=i.get("id") or "?", identity_label=i.get("label", ""))
                    for i in allid for it in i[facet]]
            answer[facet] = sorted(rows, key=lambda x: -x["confidence"])[:10]
    if intent.get("filetypes") or "cv" in intent.get("want", []):
        fts = set(intent.get("filetypes", []))
        docs = [dict(d, identity=i.get("id") or "?") for i in allid for d in i["documents"]
                if not fts or d["kind"] in fts or (d["url"].lower().rsplit(".", 1)[-1] in fts)]
        answer["documents"] = docs[:20]
    from .linking import connections
    main = store.q1("SELECT id FROM entities WHERE type=? AND key=?", (subj["entity_type"], subj["entity_key"]))
    conn = connections(store, main["id"]) if main else dict(shared=[], owners=[])
    return dict(
        connections=conn,
        intent=intent, answer=answer,
        subject=dict(id=subj["id"], query=subj["query"], kind=kind, canonical=subj["canonical"], status=subj["status"],
                     created=subj["created"], deadline=subj["deadline"], rounds=subj["rounds"],
                     variants=[" ".join(v) for v in json.loads(subj["variants"])][:40], now=time.time()),
        progress=dict(jobs=jobs, sources=sstate, hits=len(src)),
        summary=dict(identities=len(identities), sources=len(src), people_related=len(rel_list),
                     origins=dict(file=sum(1 for x in src.values() if x["origin"] == "file"),
                                  web=sum(1 for x in src.values() if x["origin"] == "web")),
                     files=sorted({x["where"] for x in src.values() if x["origin"] == "file"})),
        identities=identities, unattributed=unattributed, related=rel_list[:30], similar_names=similar[:10],
        timeline=timeline[-100:], events=events, since=since_summary)
