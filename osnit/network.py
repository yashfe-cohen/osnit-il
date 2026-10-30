"""The network around one person: who is near them in the data, how strongly, through what, and in which groups.

connect.py answers "how are X and Y connected"; this answers "who is around X". The ego graph is built from what the
imports and the web engine already recorded (relations), the operator's "same person" decisions (identity_links)
and, when present, time periods on links (periods.py) and relations read from free text (textrel.py).

Strength — the same exclusivity rule as connect.py, in one place:
  * one shared value  w = TYPE_W[type] / (1 + ln(holders - 1))      a mobile of 2 people 0.9, an org of 400 0.07
  * a direct person-person link  DIRECT_W (relative 0.9, a relation stated in text 0.75, co-mentioned 0.25)
  * a person's tie to the centre = noisy-or over its independent links: 1 - prod(1 - w)
  * ring 2 (depth=2): strength = tie(centre, middle) * tie(middle, person), best middle wins
Values held by more than connect.HUB people are never walked; in ring 2 not above EXPAND2_MAX.

Groups: every ring-1 person is grouped by the link that binds them to the centre most strongly (the same address,
the same employer, family, ...), so each group is explainable in one phrase. Read-only: nothing is created."""
import math

from .connect import HUB, KIN_HE, TEXT_REL_HE, TYPE_HE, _Graph
from .periods import contains, overlap

TYPE_W = {"national_id": 1.0, "id_number": 0.9, "phone": 0.9, "email": 0.9, "username": 0.8, "social": 0.8,
          "profile": 0.8, "address": 0.7, "website": 0.5, "domain": 0.4, "org": 0.45}
DIRECT_W = {"same_person": 1.0, "kinship": 0.9, "text": 0.75, "co_mentioned_in_doc": 0.25}
LIST_MAX = 300          # a value with more holders is too weak to list them all (w < 0.08 for an org)
EXPAND2_MAX = 200
MAX_PEOPLE = 60
MIN_STRENGTH = 0.05


def value_weight(etype, holders):
    """How strongly one shared value ties two of its holders (0 when it does not)."""
    if holders < 2 or holders > HUB:
        return 0.0
    return TYPE_W.get(etype, 0.3) / (1.0 + math.log(holders - 1))


def direct_weight(kind):
    k = kind or ""
    if k == "same_person":
        return DIRECT_W["same_person"]
    if k == "operator":
        return 0.95                      # the operator said they are related (linkdecide.CONFIRMED_W)
    if k.startswith("kinship") or k in ("relative", "family"):
        return DIRECT_W["kinship"]
    if k.startswith("text:"):
        return DIRECT_W["text"]
    if k in ("co_mentioned_in_doc", "co_mentioned"):
        return DIRECT_W["co_mentioned_in_doc"]
    return 0.3


def direct_label(kind):
    k = kind or ""
    if k == "same_person":
        return "אותו אדם (החלטת מפעיל)"
    if k == "operator":
        return "אושר על ידי המפעיל"
    if k.startswith("kinship:"):
        return KIN_HE.get(k.split(":", 1)[1], "קרוב משפחה")
    if k in ("relative", "family"):
        return "קרוב משפחה"
    if k.startswith("text:"):
        return TEXT_REL_HE.get(k, "קשר מטקסט") + " (מטקסט)"
    if k in ("co_mentioned_in_doc", "co_mentioned"):
        return "הוזכרו יחד במסמך"
    return k


def noisy_or(ws):
    p = 1.0
    for w in ws:
        p *= 1.0 - max(0.0, min(1.0, w))
    return 1.0 - p


class _Net(_Graph):
    def holders(self, eid):
        """The people holding one value (only when there are at most LIST_MAX of them)."""
        if self.degree(eid) > LIST_MAX:
            return []
        return [r["pid"] for r in self.store.q(
            "SELECT DISTINCT x.pid FROM (SELECT b_id pid FROM relations WHERE a_id=? "
            "UNION SELECT a_id pid FROM relations WHERE b_id=?) x CROSS JOIN entities e ON e.id=x.pid "
            "WHERE e.type='person' LIMIT ?", (eid, eid, LIST_MAX))]

    def ties(self, group, cap_values=None, at=None):
        """{person id: {link key: link}} for everyone tied to any identity in `group` (a set of ids that are one person).
        A link is one shared value or one direct person-person relation; the same value counts once per person."""
        out = {}
        for p in group:
            for o, kind in self.neighbours(p):
                if o in group:
                    continue
                e = self.ent(o)
                if e["type"] == "person":
                    w = direct_weight(kind)
                    key = ("direct", kind if not kind.startswith("kinship") else "kinship:" + kind.split(":")[-1])
                    link = {"kind": kind, "type": "person", "label": direct_label(kind), "w": round(w, 3)}
                    cur = out.setdefault(o, {})
                    if key not in cur or cur[key]["w"] < w:
                        cur[key] = link
                    continue
                n = self.degree(o)
                if cap_values is not None and n > cap_values:
                    continue
                w = value_weight(e["type"], n)
                if w <= 0:
                    continue
                base = f"{TYPE_HE.get(e['type'], e['type'])} {e['display']} (משותף ל-{n})"
                p_when = self.period(p, o)
                if at is not None and contains(p_when, at) is False:
                    continue                 # the centre was not linked to this value in that year
                for q in self.holders(o):
                    if q in group:
                        continue
                    q_when = self.period(q, o)
                    if at is not None and contains(q_when, at) is False:
                        continue
                    state, f, txt = overlap(p_when, q_when)
                    link = {"kind": kind, "type": e["type"], "value_id": o, "value": e["display"], "holders": n,
                            "w": round(w * f, 3), "time": state, "when": "" if state == "unknown" else txt,
                            "label": base if state == "unknown" else f"{base} — {txt}"}
                    cur = out.setdefault(q, {})
                    if ("value", o) not in cur or cur[("value", o)]["w"] < link["w"]:
                        cur[("value", o)] = link
        return out


def _same_group(store, pid, cap=50):
    """The person and every identity the operator confirmed is them (transitively)."""
    group, todo = {pid}, [pid]
    while todo and len(group) < cap:
        x = todo.pop()
        for r in store.q("SELECT b o FROM identity_links WHERE a=? AND decision='same' "
                         "UNION SELECT a o FROM identity_links WHERE b=? AND decision='same'", (x, x)):
            if r["o"] not in group:
                group.add(r["o"])
                todo.append(r["o"])
    return group


def ego_network(store, pid, depth=1, max_people=MAX_PEOPLE, min_strength=MIN_STRENGTH, at=None):
    """-> {center, people:[{id, name, strength, depth, via, group}], groups:[{key, label, people}], graph:{nodes, edges}}
    at=YYYY: only links that were (or may have been — time unknown) true in that year."""
    from .linkdecide import decisions_for
    g = _Net(store)
    center = _same_group(store, pid)
    c_ent = g.ent(pid)
    ring1 = {q: list(links.values()) for q, links in g.ties(center, at=at).items()}
    # the operator's word (linkdecide.py): "unrelated" removes a person, "related" adds or raises them
    dec = decisions_for(store, center)
    said = {}
    for (a, b), (d, note) in dec.items():
        other = b if a in center else a
        if other not in center:
            said[other] = (d, note)
    people = {}
    for q, (d, note) in said.items():
        for l in ring1.get(q, ()):
            if l["kind"] == "operator" and note:
                l["label"] = f"אושר על ידי המפעיל: {note}"
    for q, links in ring1.items():
        if said.get(q, (None,))[0] == "unrelated":
            continue
        s = noisy_or(l["w"] for l in links)
        if s >= min_strength:
            people[q] = {"id": q, "strength": s, "depth": 1, "via": sorted(links, key=lambda l: -l["w"]),
                         "decision": said.get(q, (None,))[0]}
    keep1 = sorted(people, key=lambda q: -people[q]["strength"])[:max_people]
    people = {q: people[q] for q in keep1}

    # ties among ring-1 people (for the drawing, and as the bridges ring 2 grows from)
    between = {}
    dec2 = decisions_for(store, list(people)[:40])
    for q in list(people)[:40]:
        for r, links in g.ties({q}, cap_values=EXPAND2_MAX, at=at).items():
            if r in center or dec2.get((min(q, r), max(q, r)), (None,))[0] == "unrelated" \
                    or said.get(r, (None,))[0] == "unrelated":
                continue
            between[(q, r)] = noisy_or(l["w"] for l in links.values()), list(links.values())

    if depth >= 2:
        for (q, r), (t, links) in between.items():
            if r in people and people[r]["depth"] == 1:
                continue
            s = people[q]["strength"] * t
            if s < min_strength:
                continue
            cur = people.get(r)
            if cur is None or (cur["depth"] == 2 and s > cur["strength"]):
                people[r] = {"id": r, "strength": s, "depth": 2, "through": q,
                             "via": sorted(links, key=lambda l: -l["w"])}
        ranked = sorted(people.values(), key=lambda p: (p["depth"], -p["strength"]))
        people = {p["id"]: p for p in ranked[:max_people]}

    for p in people.values():
        p["name"] = g.ent(p["id"])["display"]
        p["strength"] = round(p["strength"], 3)

    # groups: by the strongest link to the centre (ring 2 joins its bridge's group)
    groups = {}
    for p in sorted(people.values(), key=lambda p: p["depth"]):
        if p["depth"] == 1:
            top = p["via"][0]
            if top["type"] == "person":
                key = "family" if top["kind"].startswith("kinship") or top["kind"] in ("relative", "family") \
                    else "direct:" + top["kind"]
                label = "משפחה" if key == "family" else "אושרו על ידי המפעיל" if top["kind"] == "operator" \
                    else top["label"]
            else:
                key, label = f"value:{top['value_id']}", top["label"].split(" (")[0].split(" — ")[0]
        else:
            key = people[p["through"]]["group"] if p.get("through") in people else "ring2"
            label = groups.get(key, {}).get("label", "מעגל שני")
        p["group"] = key
        gr = groups.setdefault(key, {"key": key, "label": label, "people": []})
        gr["people"].append(p["id"])
    group_list = sorted(groups.values(), key=lambda gr: -max(people[i]["strength"] for i in gr["people"]))

    unrelated = [{"id": q, "name": g.ent(q)["display"], "note": n} for q, (d, n) in said.items() if d == "unrelated"]
    return {"center": {"id": pid, "name": c_ent["display"], "identities": sorted(center)}, "at": at,
            "unrelated": unrelated,
            "people": sorted(people.values(), key=lambda p: (p["depth"], -p["strength"])),
            "groups": group_list, "graph": _drawing(g, pid, people, between)}


def _drawing(g, pid, people, between):
    """The {nodes, edges} the UI's forceGraph draws: the centre, the people, and the shared values that tie two or
    more of them to the centre (a value tying only one person is folded into that person's edge)."""
    nodes, edges = [{"key": "c", "kind": "cluster", "id": pid, "label": g.ent(pid)["display"]}], []
    value_users = {}
    for p in people.values():
        if p["depth"] == 1:
            for l in p["via"]:
                if l["type"] != "person":
                    value_users.setdefault(l["value_id"], []).append((p["id"], l))
    for p in people.values():
        nodes.append({"key": f"e{p['id']}", "kind": "person" if p["depth"] == 1 else "other_person", "id": p["id"],
                      "label": p["name"]})
    for vid, users in value_users.items():
        if len(users) >= 2:
            l = users[0][1]
            nodes.append({"key": f"v{vid}", "kind": l["type"], "id": vid, "label": l["value"]})
            edges.append({"a": "c", "b": f"v{vid}", "w": l["w"], "kind": l["type"], "label": "", "reason": l["label"]})
            for q, _l in users:
                edges.append({"a": f"v{vid}", "b": f"e{q}", "w": l["w"], "kind": l["type"]})
    for p in people.values():
        if p["depth"] != 1:
            continue
        direct = [l for l in p["via"] if l["type"] == "person"]
        lone = [l for l in p["via"] if l["type"] != "person" and len(value_users.get(l["value_id"], ())) < 2]
        if direct:
            l = direct[0]
            edges.append({"a": "c", "b": f"e{p['id']}", "w": p["strength"],
                          "kind": "kinship" if l["kind"].startswith("kinship") else "rel", "label": l["label"],
                          "reason": l["label"]})
        elif lone:
            edges.append({"a": "c", "b": f"e{p['id']}", "w": p["strength"], "kind": "record",
                          "reason": " · ".join(x["label"] for x in lone[:3])})
    for (q, r), (t, links) in between.items():
        if q in people and r in people and q < r and t >= 0.3:
            edges.append({"a": f"e{q}", "b": f"e{r}", "w": t, "kind": "shared",
                          "reason": links[0]["label"] if links else ""})
    return {"nodes": nodes, "edges": edges}
