"""Builds the 'intelligence picture' for a subject from stored evidence. Always computed from the live DB."""
import json
import time
from collections import defaultdict
from difflib import SequenceMatcher

from .store import Store
from .urls import DOC_EXT, PUBLIC_MAIL, ext_of

DOC_KINDS = {"pdf", "docx", "xlsx", "csv", "json", "txt", "vcf"}
ANCHORS = {"email", "phone", "org", "domain"}
FACETS = {"org": "orgs", "role": "roles", "email": "emails", "phone": "phones", "domain": "domains",
          "url": "links", "person": "people"}


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


def subject_entity_ids(store: Store, subj) -> set:
    ids = {r["entity_id"] for r in store.q("SELECT entity_id FROM subject_entities WHERE subject_id=?", (subj["id"],))}
    e = store.q1("SELECT id FROM entities WHERE type=? AND key=?", (subj["entity_type"], subj["entity_key"]))
    if e:
        ids.add(e["id"])
    return ids


def build_profile(store: Store, subject_id: int) -> dict:
    subj = store.q1("SELECT * FROM subjects WHERE id=?", (subject_id,))
    if not subj:
        return None
    E = subject_entity_ids(store, subj)
    kind = subj["kind"]
    ents = {r["id"]: r for r in store.q(f"SELECT * FROM entities WHERE id IN ({_in(E)})")}
    # mentions of the subject itself
    mentions = store.q(
        f"SELECT ev.entity_id, ev.source_id, ev.snippet, ev.confidence, ev.first_seen, ev.last_seen, "
        f"s.url, s.domain, s.kind skind, s.title, s.first_seen sfirst, s.last_scanned, s.last_changed "
        f"FROM evidence ev JOIN sources s ON s.id=ev.source_id WHERE ev.entity_id IN ({_in(E)})")
    rels = store.q(
        f"SELECT r.id rid, r.a_id, r.b_id, r.kind, re.source_id, re.snippet, re.confidence, re.first_seen, re.last_seen, "
        f"s.url, s.domain, s.kind skind, s.title FROM relations r JOIN rel_evidence re ON re.relation_id=r.id "
        f"JOIN sources s ON s.id=re.source_id WHERE r.a_id IN ({_in(E)}) OR r.b_id IN ({_in(E)})")
    other_ids = {(r["b_id"] if r["a_id"] in E else r["a_id"]) for r in rels} - E
    others = {r["id"]: r for r in store.q(f"SELECT * FROM entities WHERE id IN ({_in(other_ids)})")}

    src = {}
    for m in mentions:
        src[m["source_id"]] = dict(id=m["source_id"], url=m["url"], domain=m["domain"], title=m["title"], kind=m["skind"],
                                   first_seen=m["sfirst"], last_scanned=m["last_scanned"], last_changed=m["last_changed"])
    for r in rels:
        src.setdefault(r["source_id"], dict(id=r["source_id"], url=r["url"], domain=r["domain"], title=r["title"],
                                            kind=r["skind"]))

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
        if kind == "person" and o["type"] in ANCHORS and not (o["type"] == "domain" and o["key"] in PUBLIC_MAIL) \
                and r["confidence"] >= 0.4:
            uf.union(("s", r["source_id"]), ("a", o["id"]))
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
            if not fk:
                continue
            if o["type"] == "url" and ext_of(o["key"]) in DOC_EXT:
                fk = "documents_linked"
            it = facets[fk].setdefault(o["id"], dict(type=o["type"], value=o["display"], relation=r["kind"], evidence=[],
                                                     first_seen=r["first_seen"], last_seen=r["last_seen"], _c=[]))
            it["evidence"].append(dict(url=r["url"], snippet=r["snippet"], confidence=round(r["confidence"], 2),
                                       first_seen=r["first_seen"], last_seen=r["last_seen"]))
            it["_c"].append((r["domain"], r["confidence"]))
            it["first_seen"] = min(it["first_seen"], r["first_seen"])
            it["last_seen"] = max(it["last_seen"], r["last_seen"])
        out = {}
        for fk, items in facets.items():
            lst = []
            for it in items.values():
                it["confidence"] = combine(it.pop("_c"))
                it["sources"] = len({e["url"] for e in it["evidence"]})
                it["evidence"] = sorted(it["evidence"], key=lambda e: -e["confidence"])[:5]
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
        return dict(
            confidence=round(conf, 3), names=sorted(names), sources=srcs, documents=docs, source_count=len(srcs),
            first_seen=min(seen) if seen else None, last_seen=max(last) if last else None,
            mentions=[dict(url=m["url"], snippet=m["snippet"], confidence=round(m["confidence"], 2),
                           first_seen=m["first_seen"], last_seen=m["last_seen"])
                      for m in sorted((m for m in mentions if m["source_id"] in cluster_sources),
                                      key=lambda m: -m["confidence"])[:6]],
            **{k: out.get(k, []) for k in ("orgs", "roles", "emails", "phones", "domains", "links", "documents_linked")})

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

    timeline = []
    for i in identities + ([unattributed] if unattributed else []):
        for fk in ("orgs", "roles", "emails", "phones", "domains", "documents_linked"):
            for it in i.get(fk, []):
                timeline.append(dict(at=it["first_seen"], what="first_seen", type=it["type"], value=it["value"]))
    timeline.sort(key=lambda x: x["at"])
    events = [dict(id=e["id"], at=e["at"], type=e["kind"], data=json.loads(e["payload"]))
              for e in store.q("SELECT * FROM events WHERE subject_id=? ORDER BY id DESC LIMIT 60", (subject_id,))]
    jobs = {r["state"]: r["n"] for r in store.q("SELECT state, COUNT(*) n FROM jobs WHERE subject_id=? GROUP BY state", (subject_id,))}
    sstate = {r["state"]: r["n"] for r in store.q("SELECT state, COUNT(*) n FROM sources WHERE subject_id=? GROUP BY state", (subject_id,))}
    return dict(
        subject=dict(id=subj["id"], query=subj["query"], kind=kind, canonical=subj["canonical"], status=subj["status"],
                     created=subj["created"], deadline=subj["deadline"], rounds=subj["rounds"],
                     variants=[" ".join(v) for v in json.loads(subj["variants"])][:40], now=time.time()),
        progress=dict(jobs=jobs, sources=sstate, hits=len(src)),
        summary=dict(identities=len(identities), sources=len(src), people_related=len(rel_list)),
        identities=identities, unattributed=unattributed, related=rel_list[:30], similar_names=similar[:10],
        timeline=timeline[-100:], events=events)
