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
from .kinship import infer_kinship_for_dossier
from .linking import attributes_of
from .nicknames import names_nick_match
from .profile import combine
from .semantic import il_id_ok
from .store import similar_person_keys
from .textnorm import fold, name_key
from .urls import PUBLIC_MAIL
from .variants import name_variants
from .xling import same_person_name

STRONG = {"email", "username", "url", "national_id"}   # + custom IDs (u_*) and lightly-shared phones
WEAK = {"address", "org", "domain", "role"}
WEAK_MERGE = {"address", "org", "domain"}              # anchors that merge records of the SAME name (not role)
FACET_ORDER = ["national_id", "phone", "email", "username", "url", "address", "org", "role", "domain"]
MAX_NODES = 220


def _in(ids):
    return ",".join(str(int(i)) for i in ids) or "NULL"


def _name_matches(a: str, b: str) -> bool:
    ka, kb = name_key(a), name_key(b)
    return ka == kb or similar_person_keys(ka, kb) or same_person_name(a, b)


def find_people(store, name: str, limit=200):
    """Person records whose name is this name in any spelling."""
    try:
        store.reindex_names(1000)
    except Exception:
        pass
    keys = {name_key(" ".join(v)) for v in name_variants(name)[:24]} | {name_key(name)}
    probes = {t[:3] for k in keys for t in k.split() if len(t) >= 3}
    seen, out = set(), []
    klist = [k for k in keys if k]
    if klist:                                      # exact-key match: works for short Hebrew names with no 3-char probe
        ph = ",".join("?" * len(klist))
        for r in store.q(f"SELECT id, key, display FROM entities WHERE type='person' AND key IN ({ph})", tuple(klist)):
            if r["id"] not in seen:
                seen.add(r["id"])
                out.append(dict(r))
    for p in probes:
        for r in store.q("SELECT id, key, display FROM entities WHERE type='person' AND key LIKE ? LIMIT 400", (f"%{p}%",)):
            if r["id"] in seen:
                continue
            seen.add(r["id"])
            if r["key"] in keys or _name_matches(name, r["display"]):
                out.append(dict(r))
                if len(out) >= limit:
                    return out
    for r in store.persons_by_skeleton(name):      # cross-script: 'bareket cohen' finds 'ברקת כהן' and vice versa
        if r["id"] in seen:
            continue
        seen.add(r["id"])
        if _name_matches(name, r["display"]):
            out.append(dict(r))
            if len(out) >= limit:
                return out
    return out


def _subset_name(short, long):
    """Every token of the shorter name is present in the longer one, which carries extra (e.g. middle) tokens —
    e.g. 'ברקת כהן' inside 'ברקת צביה כהן'. name_key sorts and folds tokens, so this is a set-subset test, not
    positional. A single shared token is never enough."""
    s, l = set(short), set(long)
    return len(s) >= 2 and s < l


def suggest_same_person(store, name, exclude_ids=()):
    """Person records that look like the SAME person written with an extra (or missing) middle name — e.g.
    'ברקת כהן' next to 'ברקת צביה כהן'. Returned as a POSSIBILITY for the operator to confirm, never merged
    automatically: a shared first+last name is not proof of identity, and auto-merging would risk a false identity
    against the precision-first rule. (Same-spelling and Hebrew<->English variants are already clustered as one
    person elsewhere; this only covers the differing-token-count case those miss.)"""
    toks = name_key(name).split()
    if len(toks) < 2:
        return []
    tset = set(toks)
    seen, out = {int(i) for i in exclude_ids}, []
    for probe in tset:                                        # share any name token, then the set-subset test decides
        if len(probe) < 2:
            continue
        for r in store.q("SELECT id, display, key FROM entities WHERE type='person' AND key LIKE ? LIMIT 400",
                         (f"%{probe}%",)):
            if r["id"] in seen:
                continue
            ct = (r["key"] or "").split()
            short, long = (toks, ct) if len(toks) <= len(ct) else (ct, toks)
            if _subset_name(short, long):
                seen.add(r["id"])
                extra = " ".join(t for t in long if t not in (tset if long is ct else set(ct)))
                out.append(dict(id=r["id"], name=r["display"],
                                reason=("שם נוסף: " + extra) if len(ct) > len(toks) else "גרסה מקוצרת של השם"))
            elif names_nick_match(name, r["display"]):   # same name via a nickname (אסתר↔אתי, Esther↔Etti)
                seen.add(r["id"])
                out.append(dict(id=r["id"], name=r["display"], reason="כינוי אפשרי של אותו שם"))
    return out[:12]


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


_SAME_LABEL = {"national_id": "ת.ז.", "phone": "טלפון", "email": "מייל", "username": "שם משתמש",
               "url": "קישור/פרופיל", "address": "כתובת", "org": "ארגון", "role": "תפקיד", "domain": "דומיין"}


def _is_mobile(phone_value):
    """An Israeli mobile number (05x / +9725x) belongs to a person; a landline (02/03/04/08/09) is a shared place."""
    d = "".join(ch for ch in (phone_value or "") if ch.isdigit())
    return d.startswith("9725") or d.startswith("05")


def _personal(t, value):
    """A detail that identifies the PERSON (shared -> same individual), vs a shared-space anchor (address, org,
    domain, landline) that several different people can share (-> related, e.g. same household or workplace)."""
    return t in STRONG or t.startswith("u_") or (t == "phone" and _is_mobile(value))


def _attach_cross_source(store, out, ents):
    """For each identified person (cluster), rank OTHER people who may be the SAME individual across sources —
    'identity one, two sources'. The signal is the details they share, each weighted by how EXCLUSIVE it is (a
    phone only the two of them share is strong; a city a thousand share is weak — that weighting is already in each
    detail's score), combined with noisy-or, plus a boost when the names also match. Two people with DIFFERENT
    national IDs never pass (the hard rule). Every candidate carries its reasons. These are possibilities for the
    operator to confirm, never an automatic merge."""
    cand_ids, per = set(), []
    for c in out:
        cand = {}
        for t, items in c["facets"].items():
            for it in items:
                shared = it.get("shared_with", [])
                exclusive = len(shared) <= 1                 # this detail is shared by only these two people
                for sw in shared:
                    if "id" not in sw or sw.get("type") != "person":
                        continue
                    e = cand.setdefault(sw["id"], dict(id=sw["id"], name=sw["name"], sigs=[], reasons=[],
                                                       personal=False))
                    sig = it["score"]
                    personal = _personal(t, it["value"])
                    e["personal"] = e["personal"] or personal
                    if exclusive and personal:
                        sig = max(sig, 0.75)                 # an exclusive personal identifier (a mobile/email only
                        #                                      the two of them share) is strong same-person evidence
                    e["sigs"].append(("%s:%d" % (t, len(e["sigs"])), sig))
                    e["reasons"].append("%s: %s%s" % (_SAME_LABEL.get(t, t), it["value"],
                                                      " · ורק הם" if exclusive else ""))
                    cand_ids.add(sw["id"])
        per.append((c, cand))
    cand_nat = defaultdict(set)                         # each candidate's own national IDs (to block a conflict)
    if cand_ids:
        ph = _in(cand_ids)
        for r in store.q(f"SELECT r.a_id, r.b_id, ne.id nid FROM relations r "
                         f"JOIN entities ne ON ne.id = CASE WHEN r.a_id IN ({ph}) THEN r.b_id ELSE r.a_id END "
                         f"WHERE (r.a_id IN ({ph}) OR r.b_id IN ({ph})) AND ne.type='national_id'"):
            cand_nat[r["a_id"] if r["a_id"] in cand_ids else r["b_id"]].add(r["nid"])
    for c, cand in per:
        cnat = {it["id"] for it in c["facets"].get("national_id", [])}
        names = [r["name"] for r in c["records"]] + c["names"]
        res = []
        for e in cand.values():
            if cnat and cand_nat.get(e["id"]) and not (cand_nat[e["id"]] & cnat):
                continue                                # different national IDs -> not the same person, ever
            sigs = list(e["sigs"])
            reasons = list(e["reasons"])
            name_match = any(nm and _name_matches(nm, e["name"]) for nm in names)
            nick_match = not name_match and any(nm and names_nick_match(nm, e["name"]) for nm in names)
            if name_match:
                sigs.append(("name", 0.8))
                reasons.insert(0, "שם תואם")
            elif nick_match:                            # same name reached via a nickname (אסתר↔אתי, Esther↔Etti)
                sigs.append(("nick", 0.6))              # a suggestion signal — weaker than an exact name match
                reasons.insert(0, "שם תואם (כינוי)")
            score = combine(sigs)
            if score < 0.45:
                continue
            # same person only when a PERSONAL identifier is shared or the name matches; otherwise they merely share
            # a place (address / landline / org / domain) -> a relationship, not the same individual
            relation = "same_person" if (e["personal"] or name_match or nick_match) else "related"
            tier = "ודאי" if score >= 0.9 else "סביר מאוד" if score >= 0.7 else "אפשרי"
            res.append(dict(id=e["id"], name=e["name"], score=round(score, 3), tier=tier, relation=relation,
                            relation_label=("אותו אדם" if relation == "same_person" else "קשור — אותו בית/ארגון"),
                            reasons=reasons[:6]))
        res.sort(key=lambda x: (x["relation"] != "same_person", -x["score"]))   # same-person first, then by score
        c["same_identity"] = res[:12]


def dossier(store, eid=None, name=None, entity_id=None) -> dict:
    """The full picture around a person name (or around any entity: an email, a phone, an ID…)."""
    if eid is None and entity_id is not None:
        eid = entity_id
    try:
        store.reindex_names(1000)
    except Exception:
        pass
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

    seen_seed_ids = {s["id"] for s in seeds}
    for s in list(seeds):
        for r in store.persons_by_skeleton(s["display"]):
            if r["id"] not in seen_seed_ids and _name_matches(s["display"], r["display"]):
                seen_seed_ids.add(r["id"])
                seeds.append(dict(r))
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

    # Absorb person entities directly linked via Deep OSINT Recursive Pivot ('pivot_match')
    pivot_pairs = []
    for l in list(links):
        if l.get("kind") == "pivot_match":
            oe = ents.get(l["other"])
            if oe and oe.get("type") == "person":
                pivot_pairs.append((l["me"], l["other"]))
                if l["other"] not in seed_ids:
                    seeds.append(oe)
                    seed_ids.add(l["other"])

    # absorb records written another way that share a personal identifier and a name token
    def name_tokens(n):
        return {fold(t) for t in n.split() if len(t) >= 2}
    seed_names = set().union(*(name_tokens(s["display"]) for s in seeds)) if seeds else set()
    absorbed = bool(pivot_pairs)
    for d, us in list(users.items()):
        de = ents.get(d)
        if not de:
            continue
        is_strong_detail = de["type"] in STRONG or de["type"].startswith("u_")
        is_mobile_detail = de["type"] == "phone" and _is_mobile(de["display"])
        if not (is_strong_detail or is_mobile_detail):
            continue
        # a personal mailbox / username / id tying 2 people together is the same person even when the names
        # look different (nickname, a transliteration the dictionary misses). A detail shared by many is not.
        personal = de["type"] != "email" or de["key"].split("@")[0] not in ("info", "office", "contact", "support")
        strong_link = is_strong_detail and personal and len([x for x in us if ents.get(x, {}).get("type") in ("person", "org")]) <= 2
        for u in us:
            ue = ents.get(u)
            if u in seed_ids or not ue or ue["type"] != "person":
                continue
            cross_lang = any(same_person_name(ue["display"], s["display"]) or _name_matches(ue["display"], s["display"]) for s in seeds)
            has_shared_token = bool(name_tokens(ue["display"]) & seed_names)
            if strong_link or cross_lang or has_shared_token:
                seeds.append(ue)
                seed_ids.add(u)
                absorbed = True
    if absorbed:
        links, ents, users = gather(seed_ids)

    # ---- clusters: records that are the same individual
    # strong = a personal identifier (merges even across spellings); weak = a shared org / address / city
    # (merges only records whose names match); conflicting national IDs never merge.
    uf = _UF(seed_ids)
    by_detail = defaultdict(set)
    for l in links:
        by_detail[l["other"]].add(l["me"])
    natid = defaultdict(set)                       # record -> CHECK-DIGIT-VALID national IDs it carries (a hard
    for d, ps in by_detail.items():               # discriminator; a typo'd/invalid ID must never force a split)
        de = ents.get(d)
        if de and de["type"] == "national_id" and il_id_ok(de["key"]):
            for p in ps:
                natid[p].add(de["key"])
    city_of = defaultdict(set)
    for r in store.q(f"SELECT entity_id, value FROM attributes WHERE entity_id IN ({_in(seed_ids)}) AND kind='city'"):
        city_of[r["entity_id"]].add(fold(r["value"]))
    name_of = {s["id"]: s["display"] for s in seeds}
    strong_joined, weak_joined = set(), set()

    def _cluster_natids(x):                        # every valid ID anywhere in x's current cluster
        root = uf.find(x)
        out = set()
        for m in list(uf.p):
            if uf.find(m) == root:
                out |= natid[m]
        return out

    def conflict(a, b):                            # block the union iff the two CLUSTERS hold disjoint valid IDs —
        na, nb = _cluster_natids(a), _cluster_natids(b)   # so two different IDs never merge, in any join order,
        return bool(na and nb and na.isdisjoint(nb))      # even through an ID-less bridge record

    def join(a, b, weak=False):
        if uf.find(a) == uf.find(b) or conflict(a, b):
            return
        if weak and not (name_key(name_of.get(a, "")) == name_key(name_of.get(b, "")) or
                         same_person_name(name_of.get(a, ""), name_of.get(b, ""))):
            return
        uf.union(a, b)
        (weak_joined if weak else strong_joined).update((a, b))

    for pa, pb in pivot_pairs:
        if pa in seed_ids and pb in seed_ids:
            join(pa, pb, weak=False)

    for d, ps in by_detail.items():                # strong identifiers
        de = ents.get(d)
        if de and len(ps) > 1 and _is_strong(de["type"], len(users.get(d, ps))) and \
                not (de["type"] == "email" and de["key"].split("@")[0] in ("info", "office", "contact")):
            ps = list(ps)
            for p in ps[1:]:
                join(ps[0], p)

    for d, ps in by_detail.items():                # weak anchors: same-name records sharing an org / address
        de = ents.get(d)
        if de and len(ps) > 1 and de["type"] in WEAK_MERGE and not (de["type"] == "domain" and de["key"] in PUBLIC_MAIL):
            ps = list(ps)
            for p in ps[1:]:
                join(ps[0], p, weak=True)
    by_city = defaultdict(set)
    for p, cs in city_of.items():
        for c in cs:
            by_city[c].add(p)
    for c, ps in by_city.items():
        ps = list(ps)
        for p in ps[1:]:
            join(ps[0], p, weak=True)

    # 4.2 Cross-language & variant automatic unification (UPGRADE_PLAN v2.0):
    # If two seed members match cross-language (Hebrew <-> English via same_person_name or consonant skeleton)
    # or share a personal anchor without conflicting national IDs, unify them into the same cluster.
    seed_list = list(seed_ids)
    for i in range(len(seed_list)):
        for j in range(i + 1, len(seed_list)):
            p1, p2 = seed_list[i], seed_list[j]
            n1, n2 = name_of.get(p1, ""), name_of.get(p2, "")
            if n1 and n2 and (same_person_name(n1, n2) or _name_matches(n1, n2)):
                shared_personal = any(
                    (p1 in ps and p2 in ps and ents.get(d) and _personal(ents[d]["type"], ents[d]["display"]))
                    for d, ps in by_detail.items()
                )
                if shared_personal or same_person_name(n1, n2):
                    join(p1, p2, weak=not shared_personal)
    groups = defaultdict(list)
    for s in seed_ids:
        groups[uf.find(s)].append(s)

    member_files = defaultdict(set)
    if seed_ids:
        for r in store.q(
            f"SELECT v.entity_id, s.id sid, s.url, s.domain, s.title, s.state, s.import_id "
            f"FROM evidence v JOIN sources s ON s.id=v.source_id WHERE v.entity_id IN ({_in(seed_ids)})"
        ):
            if origin_of(r) == "file":
                lbl = source_label(store, r)
                if lbl:
                    member_files[r["entity_id"]].add(lbl)

    clusters = []
    for root, members in groups.items():
        facets = defaultdict(dict)
        files = set()
        for m in members:
            files.update(member_files.get(m, ()))
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
    all_identifiers = defaultdict(list)
    all_spellings = []
    seen_spellings = set()
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
                entry = dict(id=it["id"], value=it["value"], type=t, score=score, kind=it["kind"],
                             records=len(it["records"]), sources=len(it["src"]),
                             origins=sorted({s[2] for s in it["src"].values()}),
                             where=sorted({s[3] for s in it["src"].values()})[:6], shared_with=others[:8])
                lst.append(entry)
                all_identifiers[t].append(entry)
            fac[t] = sorted(lst, key=lambda x: -x["score"])
        names = sorted({ents[m]["display"] for m in c["members"] if m in ents})
        for nm in names:
            if nm not in seen_spellings:
                seen_spellings.add(nm)
                all_spellings.append({"name": nm})
        strength = combine([("x%d" % n, x["score"]) for n, x in enumerate(v for vs in fac.values() for v in vs[:3])])
        mem = set(c["members"])
        merge = ("single" if len(mem) < 2 else "strong" if mem & strong_joined else "weak" if mem & weak_joined else "strong")
        out.append(dict(names=names, records=[dict(id=m, name=ents[m]["display"]) for m in c["members"] if m in ents],
                        facets={t: fac[t] for t in sorted(fac, key=lambda t: FACET_ORDER.index(t) if t in FACET_ORDER else 99)},
                        attributes=attributes_of(store, c["members"]), files=sorted(c["files"]), merge=merge,
                        sensitive=[dict(kind=r["kind"], family=r["family"], severity=r["severity"], value=r["value"],
                                        confidence=r["confidence"], reasoning=r["reasoning"])
                                   for r in store.sensitive_for(c["members"])][:40],
                        osint_findings=store.osint_findings_for(c["members"])[:80],
                        detail_count=sum(len(v) for v in fac.values()), strength=round(strength, 3)))
    out.sort(key=lambda c: (-c["detail_count"], -c["strength"]))
    for n, c in enumerate(out, 1):
        c["n"] = n
    _attach_cross_source(store, out, ents)         # rank other people who may be the same identity across sources

    kinship = infer_kinship_for_dossier(store, out, ents, links)
    for c in out:
        c["kinship"] = [k for k in kinship if k.get("cluster") == c["n"]]

    subject_name = title if (focus is None or focus["type"] == "person") else ""
    suggested = suggest_same_person(store, subject_name, seed_ids) if subject_name else []
    target_eids = list(seed_ids) or ([int(eid)] if eid else [])
    osint_findings = store.osint_findings_for(target_eids)[:100]
    entity_images = store.entity_images_for(target_eids)[:30]
    primary_avatar = store.primary_avatar_for(target_eids)
    return dict(title=title, focus=dict(focus) if focus is not None else None, clusters=out,
                identifiers=dict(all_identifiers),
                spellings=all_spellings,
                osint_findings=osint_findings,
                images=entity_images,
                primary_avatar=primary_avatar,
                people_connected=_connected(clusters, users, ents, seed_ids),
                kinship=kinship,
                suggested=suggested,
                graph=_graph(out, users, ents, seed_ids, kinship=kinship))


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


def _graph(clusters, users, ents, seed_ids, kinship=()):
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

    for idx, k in enumerate(kinship):
        hub = f"c{k.get('cluster', 1)}"
        if hub not in seen:
            continue
        pid = k.get("person_id")
        tkey = f"e{pid}" if pid else f"kin_{idx}_{name_key(k.get('name', ''))}"
        if node(tkey, kind="kinship", id=pid, label=k.get("name", ""), relation=k.get("relation", ""), reason=k.get("reason", "")):
            for existing in nodes:
                if existing["key"] == tkey and existing.get("kind") != "cluster":
                    existing["kind"] = "kinship"
                    existing["relation"] = k.get("relation", "")
                    existing["reason"] = k.get("reason", "")
            edges.append(dict(
                a=hub,
                b=tkey,
                w=k.get("confidence", 0.7),
                confidence=k.get("confidence", 0.7),
                kind="kinship",
                label=k.get("relation", "קשר משפחתי"),
                reason=k.get("reason", ""),
                evidence_type=k.get("evidence_type", "heuristic"),
            ))
    return dict(nodes=nodes, edges=edges)

