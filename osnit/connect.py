"""How are X and Y connected? The strongest chains of links between two people in the data.

The graph is what the imports and the web engine already recorded: a person linked to a phone, an email, an ID, an
address, an organisation, a relative (relations), plus the operator's "same person" decisions (identity_links). A
chain is only as convincing as its links, and a link is as convincing as it is EXCLUSIVE: a mobile that exactly two
people carry joins them tightly; an employer with three thousand employees barely joins anyone. So the cost of
passing through a shared value is ln(how many hold it): a phone held by 2 costs 0.7, an org held by 400 costs 6.
Values held by more than HUB people are not walked at all (they connect everyone to everyone).

Dijkstra from X towards Y (bounded hops and expansion), then a few alternative chains that avoid the best chain's
intermediate steps. Each chain comes with a strength and a Hebrew sentence per hop ("טלפון ‎+972… — משותף ל-2
אנשים"). Read-only: it explains links the data already has; it never creates one."""
import heapq
import math

HUB = 2000
DIRECTED_TEXT = ("text:represents", "text:manages", "text:deputy")
# a relation read from free text (textrel.py), as the OTHER person is to the one we stand on; '<' = they point at us
TEXT_REL_HE = {"text:colleague": "עמית/ה", "text:partner": "שותף/ה", "text:spouse": "בן/בת זוג",
               "text:adversary": "צד שכנגד בהליך", "text:represents": "מיוצג/ת", "text:represents<": "מייצג/ת (עו\"ד)",
               "text:manages": "כפוף/ה", "text:manages<": "מנהל/ת", "text:deputy": "ממונה", "text:deputy<": "סגן/ית"}
MAX_HOPS = 6
MAX_EXPAND = 20000
TYPE_HE = {"phone": "טלפון", "email": "מייל", "national_id": 'ת"ז', "id_number": "מספר מזהה", "address": "כתובת",
           "org": "ארגון", "person": "אדם", "city": "עיר", "username": "שם משתמש", "website": "אתר",
           "domain": "דומיין", "social": "פרופיל רשת"}
KIN_HE = {"father": "אב", "mother": "אם", "son": "בן", "daughter": "בת", "child": "ילד", "parent": "הורה",
          "spouse": "בן/בת זוג", "sibling": "אח/אחות", "brother": "אח", "sister": "אחות", "grandparent": "סב/סבתא",
          "grandchild": "נכד/נכדה", "relative": "קרוב משפחה"}


class _Graph:
    def __init__(self, store):
        self.store = store
        self._n, self._deg, self._ent = {}, {}, {}

    def ent(self, eid):
        if eid not in self._ent:
            r = self.store.q1("SELECT id, type, display FROM entities WHERE id=?", (eid,))
            self._ent[eid] = dict(r) if r else {"id": eid, "type": "?", "display": "?"}
        return self._ent[eid]

    def degree(self, eid):
        """How many people hold this value (capped at HUB + 1)."""
        if eid not in self._deg:
            r = self.store.q1(
                "SELECT COUNT(*) n FROM (SELECT x.pid FROM (SELECT b_id pid FROM relations WHERE a_id=? "
                "UNION SELECT a_id pid FROM relations WHERE b_id=?) x CROSS JOIN entities e ON e.id=x.pid "
                "WHERE e.type='person' LIMIT ?)", (eid, eid, HUB + 1))
            self._deg[eid] = r["n"] if r else 0
        return self._deg[eid]

    def period(self, person, value):
        """When the link between one person and one value was true (periods.py), None if unknown."""
        from .periods import pair_period
        return pair_period(self.store, person, value, self.__dict__.setdefault("_periods", {}))

    def time_factor(self, a, value, b):
        """How two people's links to one shared value line up in time -> (state, factor, text)."""
        from .periods import overlap
        return overlap(self.period(a, value), self.period(b, value))

    def neighbours(self, eid):
        if eid not in self._n:
            out = []
            for r in self.store.q(
                    "SELECT x.oid, x.kind, x.inc, e.type, e.display FROM (SELECT b_id oid, kind, 0 inc FROM relations "
                    "WHERE a_id=? UNION ALL SELECT a_id oid, kind, 1 inc FROM relations WHERE b_id=?) x "
                    "CROSS JOIN entities e ON e.id=x.oid LIMIT 5000", (eid, eid)):
                self._ent.setdefault(r["oid"], {"id": r["oid"], "type": r["type"], "display": r["display"]})
                kind = r["kind"]
                if r["inc"] and kind in DIRECTED_TEXT:
                    kind += "<"              # read from this side: the other one manages / represents / is deputy of us
                out.append((r["oid"], kind))
            for r in self.store.q("SELECT b oid FROM identity_links WHERE a=? AND decision='same' "
                                  "UNION SELECT a oid FROM identity_links WHERE b=? AND decision='same'", (eid, eid)):
                out.append((r["oid"], "same_person"))
            for r in self.store.q("SELECT b oid FROM link_decisions WHERE a=? AND decision='related' "
                                  "UNION SELECT a oid FROM link_decisions WHERE b=? AND decision='related'", (eid, eid)):
                out.append((r["oid"], "operator"))
            self._n[eid] = out
        return self._n[eid]

    def unrelated(self, x, y):
        """The operator said these two people are not related (linkdecide.py)."""
        cache = self.__dict__.setdefault("_unrel", {})
        k = (min(x, y), max(x, y))
        if k not in cache:
            cache[k] = bool(self.store.q1("SELECT 1 x FROM link_decisions WHERE a=? AND b=? AND decision='unrelated'", k))
        return cache[k]

    def step_cost(self, to, kind):
        """The cost of reaching `to` along a link of `kind` — None when the step is not walked."""
        if kind == "same_person":
            return 0.1
        if kind == "operator":
            return 0.15
        t = self.ent(to)["type"]
        if t == "person":
            k = kind or ""
            if k.startswith("kinship") or k in ("relative", "family"):
                return 0.5
            if k.startswith("text:"):
                return 0.6           # a relation stated in a text: a direct, named tie
            if k in ("co_mentioned_in_doc", "co_mentioned"):
                return 1.6           # only named in the same document: weak (0.2 - ln 0.25, as in network.py)
            return 1.0
        d = self.degree(to)
        if d > HUB:
            return None
        return 0.2 + math.log(max(d, 1))


def _shortest(g, a, b, banned=frozenset()):
    dist = {a: 0.0}
    prev = {}
    hops = {a: 0}
    pq = [(0.0, a)]
    expanded = 0
    while pq:
        d, u = heapq.heappop(pq)
        if u == b:
            break
        if d > dist.get(u, 9e9):
            continue
        expanded += 1
        if expanded > MAX_EXPAND or hops[u] >= MAX_HOPS:
            continue
        # a shared value is a waypoint, never a destination; from a value only people (or other values) are next
        for v, kind in g.neighbours(u):
            if v in banned or v == u:
                continue
            c = g.step_cost(v, kind)
            if c is None:
                continue
            # the operator said these two are unrelated: no step straight from one to the other (also via a value)
            if g.ent(v)["type"] == "person":
                frm = u if g.ent(u)["type"] == "person" else (prev[u][0] if u in prev else None)
                if frm is not None and frm != v and g.unrelated(frm, v):
                    continue
            # value -> person: the two people's links to this value must line up in time to tie them closely
            if g.ent(u)["type"] != "person" and g.ent(v)["type"] == "person" and u in prev:
                _st, f, _t = g.time_factor(prev[u][0], u, v)
                c += -math.log(f)
            nd = d + c
            if nd < dist.get(v, 9e9):
                dist[v], prev[v], hops[v] = nd, (u, kind), hops[u] + 1
                heapq.heappush(pq, (nd, v))
    if b not in dist:
        return None
    path, kinds, cur = [b], [], b
    while cur != a:
        p, k = prev[cur]
        path.append(p)
        kinds.append(k)
        cur = p
    return dist[b], path[::-1], kinds[::-1]


def _kind_he(kind):
    if not kind:
        return ""
    if kind == "same_person":
        return "אותו אדם (החלטת מפעיל)"
    if kind == "operator":
        return "קשר שאושר על ידי המפעיל"
    if kind.startswith("kinship:"):
        return KIN_HE.get(kind.split(":", 1)[1], "קרוב משפחה")
    if kind.startswith("text:"):
        return TEXT_REL_HE.get(kind, "קשר מטקסט")
    return {"relative": "קרוב משפחה", "family": "משפחה"}.get(kind, "")


def _describe(g, cost, path, kinds):
    nodes, hops, parts = [], [], []
    for i, eid in enumerate(path):
        e = g.ent(eid)
        nodes.append({"id": eid, "type": e["type"], "display": e["display"]})
        if e["type"] == "person":
            parts.append(e["display"])
        else:
            n = g.degree(eid)
            when = ""
            if 0 < i < len(path) - 1 and g.ent(path[i - 1])["type"] == "person" and g.ent(path[i + 1])["type"] == "person":
                state, _f, txt = g.time_factor(path[i - 1], eid, path[i + 1])
                when = "" if state == "unknown" else f", {txt}"
                nodes[-1]["when"] = txt if state != "unknown" else ""
            parts.append(f"{TYPE_HE.get(e['type'], e['type'])} {e['display']} (משותף ל-{n}{when})")
        if i:
            hops.append({"from": path[i - 1], "to": eid, "kind": kinds[i - 1], "label": _kind_he(kinds[i - 1])})
    strength = "חזק" if cost < 2.5 else "בינוני" if cost < 5 else "חלש"
    text = ""
    for i, p in enumerate(parts):
        lab = hops[i - 1]["label"] if i else ""
        text += ("" if not i else f" —{lab}→ " if lab else " → ") + p
    return {"cost": round(cost, 2), "strength": strength, "nodes": nodes, "hops": hops, "text": text,
            "steps": len(path) - 1}


def how_connected(store, a, b, k=3):
    """-> {a, b, paths:[{cost, strength, nodes, hops, text, steps}]} — up to k chains, strongest first."""
    g = _Graph(store)
    out = {"a": g.ent(a), "b": g.ent(b), "paths": []}
    if a == b:
        return out
    best = _shortest(g, a, b)
    if not best:
        return out
    found = [best]
    seen = {tuple(best[1])}
    # alternatives: the best chain with one of its waypoints taken out (Yen-style, bounded)
    for w in best[1][1:-1]:
        if len(found) >= k:
            break
        alt = _shortest(g, a, b, banned=frozenset([w]))
        if alt and tuple(alt[1]) not in seen:
            seen.add(tuple(alt[1]))
            found.append(alt)
    found.sort(key=lambda x: x[0])
    out["paths"] = [_describe(g, *f) for f in found[:k]]
    return out


def resolve_person(store, text, cfg=None):
    """An entity id, or the person a typed name most likely means (strict then fuzzy). -> (id or None, reading)."""
    s = str(text or "").strip()
    if s.isdigit():
        return int(s), ""
    from .fuzzyname import find_people_any
    hits = find_people_any(store, s, limit=1, cfg=cfg)
    if not hits:
        return None, ""
    return hits[0]["id"], hits[0].get("corrected", "")
