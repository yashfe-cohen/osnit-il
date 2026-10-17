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


def _is_large_db(store, threshold: int = 50000) -> bool:
    try:
        r = store.q1("SELECT MAX(id) m FROM entities")
        return bool(r and (r["m"] or 0) > threshold)
    except Exception:
        return False


def find_people(store, name: str, limit=200):
    """Person records whose name is this name in any spelling.
    Optimized for 10M–20M entity scale using B-tree exact, prefix-range, alias, and skeleton indexes."""
    try:
        store.reindex_names(250, blocking=False)
    except Exception:
        pass
    keys = {name_key(" ".join(v)) for v in name_variants(name)[:24]} | {name_key(name)}
    raw_toks = [t for t in fold(name).split() if len(t) >= 2]
    if raw_toks:
        keys.add(" ".join(raw_toks))
        if len(raw_toks) >= 2:
            keys.add(" ".join(reversed(raw_toks)))
    probes = {t[:3] for k in keys for t in k.split() if len(t) >= 3}
    seen, out = set(), []
    klist = [k for k in keys if k]

    # 1. Exact B-tree index lookup on entities(type, key)
    if klist:
        ph = ",".join("?" * len(klist))
        for r in store.q(f"SELECT id, key, display FROM entities WHERE type='person' AND key IN ({ph}) LIMIT ?", (*klist, limit)):
            if r["id"] not in seen:
                seen.add(r["id"])
                out.append(dict(r))

    # 2. Cross-script consonant skeleton B-tree index lookup on name_index(skel)
    for r in store.persons_by_skeleton(name, limit=limit):
        if r["id"] in seen:
            continue
        if r["key"] in keys or _name_matches(name, r["display"]):
            seen.add(r["id"])
            out.append(dict(r))
            if len(out) >= limit:
                return out

    # 3. Indexed B-tree prefix range scan on aliases(alias_key)
    for k in klist[:12]:
        for r in store.q(
            "SELECT e.id, e.key, e.display FROM aliases a JOIN entities e ON e.id=a.entity_id "
            "WHERE a.alias_key >= ? AND a.alias_key < ? AND e.type='person' LIMIT 100",
            (k, k + "\uffff"),
        ):
            if r["id"] not in seen and (r["key"] in keys or _name_matches(name, r["display"])):
                seen.add(r["id"])
                out.append(dict(r))
                if len(out) >= limit:
                    return out

    # 4. Indexed B-tree prefix range scan on entities(type, key) for each key and 3-char token probe
    prefix_probes = sorted({k[:4] for k in klist if len(k) >= 2} | probes)
    for p in prefix_probes:
        for r in store.q(
            "SELECT id, key, display FROM entities WHERE type='person' AND key >= ? AND key < ? LIMIT 400",
            (p, p + "\uffff"),
        ):
            if r["id"] in seen:
                continue
            if r["key"] in keys or _name_matches(name, r["display"]) or (len(raw_toks) == 1 and raw_toks[0] in (r["key"] or "").split()):
                seen.add(r["id"])
                out.append(dict(r))
                if len(out) >= limit:
                    return out

    # 5. Substring LIKE fallback ONLY on small databases (<50k rows), never on 10M–20M scale
    if len(out) < limit and not _is_large_db(store):
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
    cands = list(store.persons_by_skeleton(name, limit=250))
    for probe in tset:
        if len(probe) < 2:
            continue
        cands.extend(store.q(
            "SELECT id, display, key FROM entities WHERE type='person' AND key >= ? AND key < ? LIMIT 250",
            (probe, probe + "\uffff"),
        ))
    if not _is_large_db(store):
        for probe in tset:
            if len(probe) >= 2:
                cands.extend(store.q(
                    "SELECT id, display, key FROM entities WHERE type='person' AND key LIKE ? LIMIT 250",
                    (f"%{probe}%",),
                ))
    for r in cands:
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
        if len(out) >= 12:
            break
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
        store.reindex_names(250, blocking=False)
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


_FACET_TITLE_HE = {
    "national_id": "תעודת זהות",
    "phone": "מספר טלפון",
    "email": "כתובת אימייל",
    "username": "שם משתמש / כינוי",
    "url": "פרופיל / קישור ישיר",
    "address": "כתובת מגורים / עיר",
    "location": "עיר / מיקום",
    "org": "ארגון / חברה",
    "role": "תפקיד / עיסוק",
    "domain": "דומיין משויך",
}

_OSINT_CAT_TITLE_HE = {
    "target_image": "📸 תמונות יעד מאומתות וזיהוי פנים (שכבה 6)",
    "open_web_article": "📰 כתבות, ראיונות וציטוטי הקשר מהרשת הפתוחה (שכבה 5)",
    "social_comment": "💬 ציד תגובות, פוסטים ולוחות לפי טלפון/מייל (שכבה 5)",
    "breach": "🔓 דליפות מידע, סיסמאות ונוזקות Infostealers (שכבה 2)",
    "email_intel": "✉️ מודיעין כתובות אימייל ורישום שירותים (שכבה 2)",
    "code_intel": "💻 מודיעין קוד, קומיטים ופרויקטים ב-GitHub (שכבה 2)",
    "social_profile": "👤 פרופילים ברשתות חברתיות ו-Chained Deep Enrichers (שכבה 3)",
    "phone_intel": "📱 מודיעין טלפוני, ספק תקשורת, WhatsApp ו-Telegram (שכבה 4)",
    "legal_doc": "⚖️ פסקי דין, תיקים משפטיים ורישומים ציבוריים (שכבה 5)",
    "gov_registry": "🏛️ מאגרי ממשלה, רשויות ורישומים רשמיים (שכבה 5)",
    "business": "🏢 חברות, עמותות, דירקטוריונים וגיידסטאר (שכבה 5)",
    "document": "📄 מסמכים וקבצים ברשת (PDF / Word / Excel) (שכבה 5)",
    "academic": "🎓 מחקרים ופרסומים אקדמיים (שכבה 5)",
    "web_mention": "🌐 אזכורים כלליים ברשת (שכבה 5)",
    "pivot_link": "🔗 הצלבות אוטומטיות חזרה למאגר המקומי (שכבה 7 — Recursive Pivot)",
}

_OSINT_CAT_ALIASES = {
    "social": "social_profile",
    "legal": "legal_doc",
    "breach_intel": "breach",
    "email_breach": "breach",
    "avatar_intel": "target_image",
    "general_mention": "web_mention",
}


def _norm_osint_cat(cat: str) -> str:
    c = (cat or "web_mention").strip().lower()
    return _OSINT_CAT_ALIASES.get(c, c)


def export_dossier_json(store, eid=None, name=None, entity_id=None) -> str:
    """Export the complete unified dossier (local DB + 7-layer Web OSINT) as formatted JSON."""
    import json
    import datetime
    d = dossier(store, eid=eid, name=name, entity_id=entity_id)
    d["exported_at"] = datetime.datetime.now().isoformat(timespec="seconds")
    return json.dumps(d, ensure_ascii=False, indent=2)


def export_dossier_markdown(store, eid=None, name=None, entity_id=None) -> str:
    """Generate a structured, publication-grade Hebrew Markdown intelligence report combining local DB records
    and all 7 layers of Web OSINT findings for a target person."""
    import datetime
    d = dossier(store, eid=eid, name=name, entity_id=entity_id)
    now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    title = d.get("title") or name or f"Entity #{eid or entity_id}"
    clusters = d.get("clusters") or []
    osint_findings = d.get("osint_findings") or []
    images = d.get("images") or []
    primary_av = d.get("primary_avatar")
    kinship = d.get("kinship") or []
    spellings = [s.get("name") for s in (d.get("spellings") or []) if s.get("name")]

    total_records = sum(len(c.get("records") or []) for c in clusters)
    total_details = sum(int(c.get("detail_count") or 0) for c in clusters)

    lines = [
        f"# 🕵️‍♂️ דו\"ח מחקר מודיעיני מאוחד (Dossier & 7-Layer Deep OSINT): {title}",
        "",
        f"> **מועד הפקת הדו\"ח:** `{now_str}`  ",
        f"> **מערכת:** `OSNIT-IL v2.0 — Unified Deep Web OSINT & Recursive Recon Engine`  ",
        f"> **כתיבים ושמות מאוחדים (עברית / אנגלית):** {', '.join(f'`{s}`' for s in spellings) if spellings else f'`{title}`'}  ",
        f"> **סיכום כמותי:** `{total_records}` רשומות מאגר מאוחדות · `{total_details}` מזהים ופרטי קשר · `{len(kinship)}` קשרי משפחה · `{len(osint_findings)}` ממצאי רשת (OSINT) · `{len(images)}` תמונות יעד",
        "",
        "---",
        "",
        "## 1. פרופיל זהות ומזהים ממסד הנתונים והקבצים המקומיים (Local DB & File Extraction)",
        "",
    ]

    if not clusters:
        lines.append("_לא נמצאו רשומות מקומיות עבור יעד זה._\n")
    else:
        for c in clusters:
            c_names = ", ".join(c.get("names") or [title])
            strength_pct = int(round(float(c.get("strength") or 0.0) * 100))
            merge_lbl = "איחוד זהות מובהק (מזהה קשיח / דו-לשוני)" if c.get("merge") == "strong" else (
                "איחוד לפי הקשר" if c.get("merge") == "weak" else "רשומה יחידה"
            )
            lines.append(f"### אשכול זהות #{c.get('n', 1)}: {c_names} (עוצמת איחוד: `{strength_pct}%` — {merge_lbl})")
            lines.append("")
            recs = c.get("records") or []
            if recs:
                rec_str = ", ".join(f"{r['name']} (`#{r['id']}`)" for r in recs)
                lines.append(f"- **רשומות מקור מאוחדות בתיק:** {rec_str}")
            files = c.get("files") or []
            if files:
                lines.append(f"- **קבצי ומסמכי מקור שנסרקו:** {', '.join(f'`{f}`' for f in files)}")
            lines.append("")

            # Facets table
            facets = c.get("facets") or {}
            if facets:
                lines.append("#### טבלת מזהים ופרטי קשר מאומתים")
                lines.append("")
                lines.append("| סוג מזהה | ערך | רמת ודאות | מקורות מאמתים | הערות / שיתוף |")
                lines.append("| :--- | :--- | :---: | :--- | :--- |")
                for ftype, items in facets.items():
                    flabel = _FACET_TITLE_HE.get(ftype, ftype)
                    for it in items:
                        val = str(it.get("value") or "").replace("|", "\\|")
                        sc = f"{int(round(float(it.get('score') or 0) * 100))}%"
                        where_list = ", ".join(it.get("where") or []) or f"{it.get('sources', 1)} מקורות"
                        shared = it.get("shared_with") or []
                        shared_str = ("משותף עם: " + ", ".join(str(s.get("name") or f"#{s.get('cluster')}") for s in shared)) if shared else "ייחודי ליעד"
                        lines.append(f"| **{flabel}** | `{val}` | {sc} | {where_list} | {shared_str} |")
                lines.append("")

            # Biographical attributes (filter out empty or internal 'observed')
            attrs = [
                a for a in (c.get("attributes") or [])
                if str(a.get("value") or "").strip() and str(a.get("label") or a.get("name") or "").lower() != "observed"
            ]
            if attrs:
                lines.append("#### פרטים ביוגרפיים ושדות שחולצו מהקבצים")
                lines.append("")
                lines.append("| שדה | ערך | מקור |")
                lines.append("| :--- | :--- | :--- |")
                for a in attrs:
                    albl = str(a.get("label") or a.get("name") or "").replace("|", "\\|")
                    aval = str(a.get("value") or "").replace("|", "\\|")
                    asrc = ", ".join(a.get("where") or a.get("sources") or []) if isinstance(a.get("where") or a.get("sources"), list) else str(a.get("source") or "מאגר מקומי")
                    lines.append(f"| **{albl}** | `{aval}` | {asrc} |")
                lines.append("")

    # Section 2: Kinship & Connected People
    lines.append("---")
    lines.append("")
    lines.append("## 2. קשרי משפחה וזיקות לאנשים קשורים (Kinship & Relationship Graph)")
    lines.append("")
    if kinship:
        lines.append("| שם קרוב משפחה | סוג קשר | סיווג ראיה | רמת ודאות | נימוק מודיעיני |")
        lines.append("| :--- | :--- | :--- | :---: | :--- |")
        for k in kinship:
            kname = str(k.get("name") or "").replace("|", "\\|")
            krel = str(k.get("relation") or "קרוב משפחה").replace("|", "\\|")
            kev = "מפורש במסמך" if k.get("evidence_type") == "explicit" else "היוריסטיקה מוצלבת"
            kconf = f"{int(round(float(k.get('confidence') or 0.75) * 100))}%"
            kreason = str(k.get("reason") or "").replace("|", "\\|")
            lines.append(f"| **{kname}** | {krel} | {kev} | {kconf} | {kreason} |")
        lines.append("")
    else:
        lines.append("_לא אותרו קשרי משפחה ישירים במאגר המקומי._\n")

    same_all = []
    for c in clusters:
        for s in c.get("same_identity") or []:
            same_all.append(s)
    if same_all:
        lines.append("### זיקות לאנשים נוספים החולקים מזהים או כתובת/ארגון")
        lines.append("")
        lines.append("| שם | סיווג זיקה | ציון התאמה | נימוקים מצליבים |")
        lines.append("| :--- | :--- | :---: | :--- |")
        for s in same_all:
            sname = str(s.get("name") or "").replace("|", "\\|")
            slbl = str(s.get("relation_label") or "")
            ssc = f"{int(round(float(s.get('score') or 0) * 100))}%"
            sreas = " · ".join(s.get("reasons") or [])
            lines.append(f"| **{sname}** | {slbl} | {ssc} | {sreas} |")
        lines.append("")

    # Section 3: Target Images & Visual Recon (Layer 6)
    lines.append("---")
    lines.append("")
    lines.append("## 3. ממצאי תמונות יעד ואימות פנים (Layer 6 — Visual & Face Recon)")
    lines.append("")
    if primary_av and isinstance(primary_av, dict):
        lines.append(
            f"- **תמונת פרופיל ראשית נבחרת:** `{primary_av.get('image_url') or primary_av.get('local_path')}` "
            f"(אימות פנים: `{'כן ✓' if primary_av.get('face_detected') or primary_av.get('face_verified') else 'לא'}` · "
            f"מקור: `{primary_av.get('source_type')}`)"
        )
        lines.append("")
    if images:
        lines.append("| # | סוג מקור | אימות פנים | ודאות | נתיב מקומי / URL | דף מקור |")
        lines.append("| :---: | :--- | :---: | :---: | :--- | :--- |")
        for idx, img in enumerate(images, 1):
            stype = img.get("source_type") or "image"
            face_ok = "✓ פנים אומתו" if (img.get("face_detected") or img.get("face_verified")) else "ללא פנים"
            conf_s = f"{int(round(float(img.get('confidence') or 0.8) * 100))}%"
            u_img = img.get("local_path") or img.get("image_url") or ""
            p_url = img.get("source_page_url") or img.get("source_url") or ""
            lines.append(f"| {idx} | `{stype}` | {face_ok} | {conf_s} | `{u_img}` | {p_url} |")
        lines.append("")
    else:
        lines.append("_לא נשמרו תמונות פנים מאומתות עבור יעד זה._\n")

    # Section 4: Open-Web Articles & Comments Context Quotes (Layer 5)
    article_findings = [
        f for f in osint_findings
        if _norm_osint_cat(f.get("category")) in ("open_web_article", "social_comment") or f.get("source_tool") == "open_web_scraper"
    ]
    lines.append("---")
    lines.append("")
    lines.append("## 4. כתבות, תגובות וציטוטי הקשר מהרשת הפתוחה (Layer 5 — Open-Web Context & Article Scraper)")
    lines.append("")
    if article_findings:
        for idx, f in enumerate(article_findings, 1):
            ed = f.get("extracted_data") or f.get("raw") or {}
            kind_lbl = "💬 תגובה / פוסט ברשת" if _norm_osint_cat(f.get("category")) == "social_comment" else "📰 כתבה / אזכור ברשת הפתוחה"
            conf_s = f"{int(round(float(f.get('confidence') or 0.78) * 100))}%"
            lines.append(f"### {idx}. {f.get('title') or ed.get('article_title') or 'ממצא מהרשת הפתוחה'} ({kind_lbl} · ודאות `{conf_s}`)")
            if f.get("url"):
                lines.append(f"- **קישור למקור:** {f.get('url')}")
            quote_txt = ed.get("quoted_context") or f.get("summary") or ""
            if quote_txt:
                lines.append("- **חלון הקשר שחולץ (פסקה לפני + פסקת היעד + פסקה אחרי):**")
                for qline in quote_txt.splitlines():
                    if qline.strip():
                        lines.append(f"  > {qline.strip()}")
            ext_bits = []
            if ed.get("phones"):
                ext_bits.append("טלפונים: " + ", ".join(f"`{p}`" for p in ed["phones"]))
            if ed.get("emails"):
                ext_bits.append("מיילים: " + ", ".join(f"`{em}`" for em in ed["emails"]))
            if ed.get("orgs"):
                ext_bits.append("ארגונים: " + ", ".join(f"`{o}`" for o in ed["orgs"]))
            if ed.get("attributes"):
                ext_bits.append("תכונות: " + ", ".join(f"{a.get('name')}: `{a.get('value')}`" for a in ed["attributes"] if isinstance(a, dict)))
            if ext_bits:
                lines.append(f"- **ישויות שחולצו מתוך הכתבה ל-Pivot:** {' · '.join(ext_bits)}")
            lines.append("")
    else:
        lines.append("_לא אותרו כתבות עומק או תגובות ציבוריות עם ציטוט ישיר בסריקה זו._\n")

    # Section 5: All 7-Layer Deep Web OSINT Findings by Category
    lines.append("---")
    lines.append("")
    lines.append(f"## 5. פירוט מלא של ממצאי חקירת רשת עמוקה (7-Layer Deep Web OSINT — סה\"כ {len(osint_findings)} ממצאים)")
    lines.append("")
    if not osint_findings:
        lines.append("_טרם הופעלה חקירת רשת עמוקה (Deep Recon) או שלא אותרו ממצאים חיצוניים._\n")
    else:
        by_cat = defaultdict(list)
        for f in osint_findings:
            by_cat[_norm_osint_cat(f.get("category"))].append(f)

        cat_order = list(_OSINT_CAT_TITLE_HE.keys()) + [k for k in by_cat if k not in _OSINT_CAT_TITLE_HE]
        for cat in cat_order:
            items = by_cat.get(cat)
            if not items:
                continue
            cat_title = _OSINT_CAT_TITLE_HE.get(cat, f"🌐 {cat}")
            lines.append(f"### {cat_title} ({len(items)})")
            lines.append("")
            for f in items:
                tool = f.get("source_tool") or f.get("tool") or "osint"
                conf_s = f"{int(round(float(f.get('confidence') or 0.75) * 100))}%"
                ftitle = f.get("title") or ""
                fsum = f.get("summary") or ""
                furl = f.get("url") or ""
                lines.append(f"- **[{tool} | ודאות {conf_s}] {ftitle}**")
                if fsum:
                    lines.append(f"  - תקציר ממצא: {fsum}")
                if furl:
                    lines.append(f"  - מקור: {furl}")
            lines.append("")

    return "\n".join(lines)


def export_dossier_html(store, eid=None, name=None, entity_id=None) -> str:
    """Generate a standalone, print-ready RTL HTML intelligence report combining local DB records
    and all 7 layers of Web OSINT findings for a target person."""
    import datetime
    import html as _html

    def _e(v) -> str:
        return _html.escape(str(v if v is not None else ""))

    d = dossier(store, eid=eid, name=name, entity_id=entity_id)
    now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    title = d.get("title") or name or f"Entity #{eid or entity_id}"
    clusters = d.get("clusters") or []
    osint_findings = d.get("osint_findings") or []
    images = d.get("images") or []
    kinship = d.get("kinship") or []
    spellings = [s.get("name") for s in (d.get("spellings") or []) if s.get("name")]

    total_records = sum(len(c.get("records") or []) for c in clusters)
    total_details = sum(int(c.get("detail_count") or 0) for c in clusters)

    # Clusters HTML
    clusters_html = []
    for c in clusters:
        c_names = " · ".join(_e(n) for n in (c.get("names") or [title]))
        strength_pct = int(round(float(c.get("strength") or 0.0) * 100))
        facets = c.get("facets") or {}
        facet_rows = []
        for ftype, items in facets.items():
            flabel = _FACET_TITLE_HE.get(ftype, ftype)
            for it in items:
                sc = f"{int(round(float(it.get('score') or 0) * 100))}%"
                where_str = ", ".join(_e(w) for w in (it.get("where") or [])) or f"{it.get('sources', 1)} מקורות"
                shared = it.get("shared_with") or []
                shared_str = ("משותף עם: " + ", ".join(_e(s.get("name") or f"#{s.get('cluster')}") for s in shared)) if shared else "ייחודי ליעד"
                facet_rows.append(
                    f"<tr><td><b>{_e(flabel)}</b></td><td class='ltr mono'><b>{_e(it.get('value'))}</b></td>"
                    f"<td><span class='badge ok'>{sc}</span></td><td>{where_str}</td><td>{shared_str}</td></tr>"
                )
        attrs = [
            a for a in (c.get("attributes") or [])
            if str(a.get("value") or "").strip() and str(a.get("label") or a.get("name") or "").lower() != "observed"
        ]
        attr_chips = "".join(
            f"<span class='chip'><span class='sub'>{_e(a.get('label') or a.get('name'))}:</span> <b>{_e(a.get('value'))}</b></span>"
            for a in attrs
        )
        files = c.get("files") or []
        file_chips = "".join(f"<span class='chip mono ltr'>📄 {_e(f)}</span>" for f in files)
        clusters_html.append(f"""
        <div class="card">
          <h3>אשכול זהות #{c.get('n', 1)}: {c_names} <span class="badge ok">עוצמת איחוד {strength_pct}%</span></h3>
          <table>
            <thead><tr><th>סוג מזהה</th><th>ערך</th><th>ודאות</th><th>מקורות</th><th>שיוך</th></tr></thead>
            <tbody>{''.join(facet_rows) or '<tr><td colspan="5">אין מזהים</td></tr>'}</tbody>
          </table>
          {f'<h4>פרטים ביוגרפיים ושדות שחולצו מהקבצים ({len(attrs)})</h4><div class="chips">{attr_chips}</div>' if attr_chips else ''}
          {f'<h4>קבצי ומסמכי מקור במאגר ({len(files)})</h4><div class="chips">{file_chips}</div>' if file_chips else ''}
        </div>
        """)

    # Kinship HTML
    kin_rows = "".join(
        f"<tr><td><b>{_e(k.get('name'))}</b></td><td><span class='badge ok'>{_e(k.get('relation'))}</span></td>"
        f"<td>{'מפורש במסמך' if k.get('evidence_type') == 'explicit' else 'היוריסטיקה מוצלבת'}</td>"
        f"<td>{int(round(float(k.get('confidence') or 0.75) * 100))}%</td><td>{_e(k.get('reason'))}</td></tr>"
        for k in kinship
    )

    # Article & Comment Quotes HTML
    article_findings = [
        f for f in osint_findings
        if _norm_osint_cat(f.get("category")) in ("open_web_article", "social_comment") or f.get("source_tool") == "open_web_scraper"
    ]
    articles_html = []
    for f in article_findings:
        ed = f.get("extracted_data") or f.get("raw") or {}
        hl = ed.get("highlighted_html") or _e(ed.get("quoted_context") or f.get("summary") or "")
        furl = f.get("url") or ""
        articles_html.append(f"""
        <div class="quote-card">
          <div class="row-between">
            <b>{_e(f.get('title') or ed.get('article_title') or 'כתבה / אזכור ברשת')}</b>
            <span class="badge acc">{int(round(float(f.get('confidence') or 0.78) * 100))}% ודאות</span>
          </div>
          <div class="quote-body">{hl}</div>
          {f'<div class="ltr mono" style="font-size:12px;margin-top:6px"><a href="{_e(furl)}" target="_blank">{_e(furl)}</a></div>' if furl else ''}
        </div>
        """)

    # All OSINT Findings HTML
    by_cat = defaultdict(list)
    for f in osint_findings:
        by_cat[_norm_osint_cat(f.get("category"))].append(f)
    cat_order = list(_OSINT_CAT_TITLE_HE.keys()) + [k for k in by_cat if k not in _OSINT_CAT_TITLE_HE]
    osint_sections = []
    for cat in cat_order:
        items = by_cat.get(cat)
        if not items:
            continue
        ctitle = _OSINT_CAT_TITLE_HE.get(cat, cat)
        rows_html = []
        for f in items:
            tool = _e(f.get("source_tool") or f.get("tool") or "OSINT")
            conf_s = f"{int(round(float(f.get('confidence') or 0.75) * 100))}%"
            furl = f.get("url") or ""
            url_link = f'<a href="{_e(furl)}" target="_blank" class="ltr mono">{_e(furl[:85])}</a>' if furl else "—"
            rows_html.append(
                f"<tr><td><span class='badge acc'>{tool}</span></td><td><b>{_e(f.get('title'))}</b>"
                f"<div class='sub'>{_e(f.get('summary'))}</div></td><td>{conf_s}</td><td>{url_link}</td></tr>"
            )
        osint_sections.append(f"""
        <div class="card">
          <h3>{_e(ctitle)} ({len(items)})</h3>
          <table>
            <thead><tr><th style="width:110px">כלי / מקור</th><th>ממצא ותקציר</th><th style="width:75px">ודאות</th><th>קישור מאומת</th></tr></thead>
            <tbody>{''.join(rows_html)}</tbody>
          </table>
        </div>
        """)

    return f"""<!DOCTYPE html>
<html lang="he" dir="rtl">
<head>
<meta charset="utf-8">
<title>דו"ח מחקר מודיעיני מאוחד — {_e(title)}</title>
<style>
  body {{ font-family: system-ui, -apple-system, 'Segoe UI', Arial, sans-serif; background: #0b101b; color: #e6edf7; margin: 0; padding: 28px; line-height: 1.55; }}
  .container {{ max-width: 1120px; margin: 0 auto; }}
  .hero {{ background: linear-gradient(135deg, #111a2e, #0d1524); border: 1px solid #1e3252; border-right: 5px solid #00f0ff; border-radius: 14px; padding: 22px 26px; margin-bottom: 22px; }}
  h1 {{ margin: 0 0 8px 0; font-size: 24px; color: #00f0ff; }}
  h2 {{ font-size: 18px; color: #00f0ff; border-bottom: 1px solid #1e2d47; padding-bottom: 6px; margin-top: 26px; }}
  h3 {{ font-size: 15px; color: #7cc4ff; margin-top: 0; }}
  h4 {{ font-size: 13.5px; color: #a8c5e8; margin: 14px 0 8px; }}
  .sub {{ color: #94a8c4; font-size: 12.5px; }}
  .card {{ background: #11192a; border: 1px solid #1e2d47; border-radius: 12px; padding: 16px 20px; margin-bottom: 16px; }}
  table {{ width: 100%; border-collapse: collapse; margin-top: 8px; font-size: 13px; }}
  th, td {{ border-bottom: 1px solid #1b2840; padding: 8px 10px; text-align: right; vertical-align: top; }}
  th {{ color: #8ab4f8; background: rgba(255,255,255,0.03); font-weight: 600; }}
  .ltr {{ direction: ltr; unicode-bidi: embed; }}
  .mono {{ font-family: Consolas, Monaco, monospace; }}
  .badge {{ display: inline-block; padding: 2px 8px; border-radius: 99px; font-size: 11.5px; font-weight: 600; background: #1b2a44; color: #d0e2ff; }}
  .badge.ok {{ background: rgba(0, 255, 136, 0.14); color: #00ff88; border: 1px solid rgba(0, 255, 136, 0.35); }}
  .badge.acc {{ background: rgba(0, 240, 255, 0.14); color: #00f0ff; border: 1px solid rgba(0, 240, 255, 0.35); }}
  .chips {{ display: flex; flex-wrap: wrap; gap: 6px; }}
  .chip {{ background: #17233b; border: 1px solid #25385c; padding: 4px 10px; border-radius: 8px; font-size: 12.5px; }}
  .quote-card {{ background: #101c30; border: 1px solid #22385e; border-right: 4px solid #a855f7; border-radius: 10px; padding: 14px 16px; margin-bottom: 12px; }}
  .quote-body {{ margin-top: 8px; white-space: pre-line; font-size: 13.5px; color: #e2e8f0; background: rgba(0,0,0,0.25); padding: 10px 14px; border-radius: 8px; }}
  mark, .osint-hl {{ background: rgba(0, 240, 255, 0.25); color: #00f0ff; padding: 0 4px; border-radius: 4px; font-weight: 700; }}
  a {{ color: #38bdf8; text-decoration: none; }}
  a:hover {{ text-decoration: underline; }}
  .row-between {{ display: flex; justify-content: space-between; align-items: center; gap: 10px; }}
  @media print {{
    body {{ background: #fff; color: #111; padding: 10px; }}
    .hero, .card, .quote-card {{ background: #fff; border-color: #ccc; color: #111; }}
    h1, h2, h3, h4 {{ color: #0f172a; }}
    .sub {{ color: #475569; }}
  }}
</style>
</head>
<body>
<div class="container">
  <div class="hero">
    <h1>🕵️‍♂️ דו"ח מחקר מודיעיני מאוחד (Dossier & 7-Layer Deep OSINT): {_e(title)}</h1>
    <div class="sub">מועד הפקת הדו"ח: <span class="mono">{_e(now_str)}</span> · מערכת: <b>OSNIT-IL v2.0</b></div>
    <div style="margin-top:8px">
      כתיבים ושמות מאוחדים: <b>{', '.join(_e(s) for s in spellings) if spellings else _e(title)}</b>
    </div>
    <div style="margin-top:8px" class="chips">
      <span class="badge ok">{total_records} רשומות מאגר מאוחדות</span>
      <span class="badge acc">{total_details} מזהים ופרטי קשר</span>
      <span class="badge ok">{len(kinship)} קשרי משפחה</span>
      <span class="badge acc">{len(osint_findings)} ממצאי רשת (7-Layer OSINT)</span>
      <span class="badge ok">{len(images)} תמונות יעד</span>
    </div>
  </div>

  <h2>1. מזהים, פרטי קשר ונתונים ביוגרפיים מהמאגר והקבצים המקומיים</h2>
  {''.join(clusters_html) or '<div class="card">לא נמצאו רשומות מקומיות.</div>'}

  <h2>2. קשרי משפחה וזיקות קרובים ({len(kinship)})</h2>
  <div class="card">
    {f'<table><thead><tr><th>שם קרוב</th><th>סוג קשר</th><th>סיווג ראיה</th><th>ודאות</th><th>נימוק מודיעיני</th></tr></thead><tbody>{kin_rows}</tbody></table>' if kin_rows else '<div class="sub">לא אותרו קשרי משפחה ישירים במאגר המקומי.</div>'}
  </div>

  {f'<h2>3. כתבות, תגובות וציטוטי הקשר מהרשת הפתוחה ({len(articles_html)})</h2>' + ''.join(articles_html) if articles_html else ''}

  <h2>4. פירוט מלא של ממצאי חקירת רשת עמוקה (7-Layer Deep Web OSINT — {len(osint_findings)} ממצאים)</h2>
  {''.join(osint_sections) or '<div class="card"><div class="sub">לא אותרו ממצאי רשת חיצוניים.</div></div>'}
</div>
</body>
</html>"""


