"""Coherent resolution of one name block: who-is-who among the identities that share a name.

possible.py scores each candidate pair on its own. That is enough to rank, but a pile of independent pairwise
probabilities is not a coherent picture: three records of "יצחק כהן" in one town can each look 90% like the other
two, which would say there is one person when their national IDs prove there are three. A real resolution assigns
each record to a PERSON, under two hard constraints:

  must-link   records sharing a personal identifier (or the operator said "same") are the same person.
  cannot-link records with two different national IDs (or the operator said "different") are different people.

This module groups a block into cores (the must-linked components) and gives, for each identity, a distribution over
"which core is my person" plus "someone else not in this block", under two budgets:

  per identity   an identity belongs to at most one person, so its probabilities over cores sum to at most 1.
  per core       a core is one person, so among identities that are pairwise different people (cannot-link) at most
                 one is that person: their probabilities of being this core sum to at most 1.

Enforcing both (a couple of Sinkhorn-style passes) makes the reported pair probabilities coherent: three different-ID
namesakes can no longer each be 90% the same as the others. The pairwise affinities come from matchmodel.py; a shared
identifier or an operator decision stays an exact certainty, not a budget share. Nothing is merged — the operator
still decides. Cached per name block, so possible_matches and the dossier read the same coherent numbers."""
from . import matchmodel


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


def _cores(ids, feats, decisions, names=None):
    """-> {core: [ids]}, {id: core}, {core: national IDs it carries}. A union that would put two different national
    IDs in one core is refused, whatever the join order (rule 5) — e.g. a mobile recycled to a new owner.
    names: {id: display} — when given, a shared identifier joins only compatible names (two different names on one
    mobile are a couple / a household, not one person)."""
    uf = _UF()
    nids_of = {}

    def union(a, b):
        ra, rb = uf.find(a), uf.find(b)
        if ra == rb:
            return
        na, nb = nids_of.get(ra, set()), nids_of.get(rb, set())
        if na and nb and na.isdisjoint(nb):
            return
        uf.union(ra, rb)
        nids_of[uf.find(ra)] = na | nb

    holders = {}
    for i in ids:
        uf.find(i)
        f = feats[i]
        nids_of[i] = set(f["nids"])
        for key in (f["nids"] | matchmodel._mobiles(f) | matchmodel._emails(f)):
            holders.setdefault(key, []).append(i)
    def compatible(a, b):
        if not names or a not in names or b not in names:
            return True
        return matchmodel.name_level(names[a] or "", names[b] or "") != "different"

    for grp in holders.values():
        for x, a in enumerate(grp):
            for b in grp[x + 1:]:
                if compatible(a, b):
                    union(a, b)
    for (a, b), dec in decisions.items():
        if dec == "same" and a in uf.p and b in uf.p:
            union(a, b)
    core_of = {i: uf.find(i) for i in ids}
    cores, core_nids = {}, {}
    for i in ids:
        cores.setdefault(core_of[i], []).append(i)
        core_nids.setdefault(core_of[i], set()).update(feats[i]["nids"])
    return cores, core_of, core_nids


def _cannot_link(i, j, feats, forbidden):
    ni, nj = feats[i]["nids"], feats[j]["nids"]
    return (ni and nj and not (ni & nj)) or (min(i, j), max(i, j)) in forbidden


def resolve_block(ids, feats, pair_log_odds, decisions, passes=4, names=None):
    """-> {frozenset({i, j}): coherent same-person probability}."""
    cores, core_of, core_nids = _cores(ids, feats, decisions, names)
    # a "not the same" decision separates the two PEOPLE, not just the two records: it propagates through every
    # must-link (A is B, B is not C -> A is not C)
    forbidden = set()
    for (a, b), d in decisions.items():
        if d == "different" and a in core_of and b in core_of:
            for x in cores[core_of[a]]:
                for y in cores[core_of[b]]:
                    forbidden.add((min(x, y), max(x, y)))
    # q[i][K]: identity i's current mass on core K (K != i's own core)
    q = {i: {} for i in ids}
    for i in ids:
        for j in ids:
            if j == i or core_of[j] == core_of[i]:
                continue
            k = core_of[j]
            if core_nids[k] and feats[i]["nids"] and not (feats[i]["nids"] & core_nids[k]):
                continue
            if _cannot_link(i, j, feats, forbidden):
                continue
            lo = pair_log_odds.get((min(i, j), max(i, j)))
            if lo is None:
                continue
            q[i][k] = max(q[i].get(k, 0.0), 2.0 ** max(-60.0, min(60.0, lo)))
    # turn the affinities into pairwise probabilities, then bring ONLY the incoherent sums down to 1 — a pair with no
    # conflict keeps its pairwise value, so a real duplicate is not diluted just because namesakes are nearby.
    prob = {i: {k: o / (1.0 + o) for k, o in q[i].items()} for i in ids}
    for _ in range(passes):
        # per core: among identities that are pairwise different people, at most one is this core's person
        col = {}
        for i in ids:
            for k, v in prob[i].items():
                col.setdefault(k, []).append((i, v))
        for k, claims in col.items():
            claims.sort(key=lambda x: -x[1])
            chosen = []
            for i, v in claims:
                excl = [c for c, _ in chosen if _cannot_link(i, c, feats, forbidden)]
                s = v + sum(dict(chosen)[c] for c in excl)
                if s > 1.0:
                    prob[i][k] = max(v / s, 0.0)
                chosen.append((i, prob[i][k]))
        # per identity: an identity belongs to at most one core
        for i in ids:
            tot = sum(prob[i].values())
            if tot > 1.0:
                prob[i] = {k: v / tot for k, v in prob[i].items()}
    q = prob
    out = {}
    for i in ids:
        for j in ids:
            if j <= i:
                continue
            pij = q[i].get(core_of[j], 0.0) if core_of[j] != core_of[i] else 1.0
            pji = q[j].get(core_of[i], 0.0) if core_of[j] != core_of[i] else 1.0
            p = 1.0 if core_of[i] == core_of[j] else min(pij, pji)
            if p > 0:
                out[frozenset((i, j))] = round(p, 3)
    return out
