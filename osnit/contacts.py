"""Flat contacts table: one row per person with all their emails, phones and orgs — the full
database, not a summary. Used by the 'אנשים' view and its CSV export.

Scales to millions of people: the page of people is chosen first with an indexed ORDER BY (so LIMIT
short-circuits instead of ranking the whole table), then the emails/phones/orgs/source-count are gathered
only for that page. The old query ordered by a correlated COUNT() subquery, which forced SQLite to evaluate
four subqueries for every person in the database before it could return even one row."""
import csv
import io

from .store import Store

_CHUNK = 900   # stay under SQLite's default 999 bound-variable limit per statement


def _split(s):
    return [x for x in (s or "").split(",") if x]


def _dedupe(seq):
    seen, out = set(), []
    for x in seq:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out


def _chunks(items, n=_CHUNK):
    for i in range(0, len(items), n):
        yield items[i:i + n]


def _aggregate(store, ids):
    """emails/phones/orgs and the independent-source count for exactly these person ids (page-sized)."""
    det = {i: dict(id=i, emails=[], phones=[], orgs=[], sources=0) for i in ids}
    bucket = {"email": "emails", "phone": "phones", "org": "orgs"}
    for part in _chunks(ids):
        ph = ",".join("?" * len(part))
        for r in store.q(
            f"SELECT p.id pid, o.type t, o.display d FROM entities p "
            f"JOIN relations r ON (r.a_id=p.id OR r.b_id=p.id) "
            f"JOIN entities o ON o.id = CASE WHEN r.a_id=p.id THEN r.b_id ELSE r.a_id END "
            f"WHERE p.id IN ({ph}) AND o.type IN ('email','phone','org')", tuple(part)):
            det[r["pid"]][bucket[r["t"]]].append(r["d"])
        for r in store.q(
            f"SELECT entity_id eid, COUNT(DISTINCT source_id) n FROM evidence "
            f"WHERE entity_id IN ({ph}) GROUP BY entity_id", tuple(part)):
            det[r["eid"]]["sources"] = r["n"]
    return det


def contacts(store: Store, q="", only_contactable=False, limit=500, offset=0):
    where, args = ["p.type='person'"], []
    if q:
        where.append("(p.display LIKE ? OR p.key LIKE ?)")
        args += [f"%{q}%", f"%{q.lower()}%"]
    if only_contactable:
        where.append("EXISTS(SELECT 1 FROM relations r JOIN entities o ON o.id = "
                     "CASE WHEN r.a_id=p.id THEN r.b_id ELSE r.a_id END "
                     "WHERE (r.a_id=p.id OR r.b_id=p.id) AND o.type IN ('email','phone'))")
    w = " AND ".join(where)
    page = store.q(f"SELECT p.id, p.display, p.first_seen, p.last_seen FROM entities p WHERE {w} "
                   f"ORDER BY p.last_seen DESC, p.id DESC LIMIT ? OFFSET ?", (*args, limit, offset))
    ids = [r["id"] for r in page]
    det = _aggregate(store, ids) if ids else {}
    rows = []
    for r in page:
        d = det.get(r["id"], {})
        rows.append(dict(id=r["id"], name=r["display"],
                         emails=_dedupe(d.get("emails", [])), phones=_dedupe(d.get("phones", [])),
                         orgs=_dedupe(d.get("orgs", [])), sources=d.get("sources", 0),
                         first_seen=r["first_seen"], last_seen=r["last_seen"]))
    total = store.q1("SELECT COUNT(*) n FROM entities WHERE type='person'")["n"]
    return dict(rows=rows, total=total)


def contacts_csv(store: Store, q="", only_contactable=False):
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["name", "emails", "phones", "orgs", "sources"])
    for r in contacts(store, q, only_contactable, limit=100000)["rows"]:
        cells = [r["name"], " | ".join(r["emails"]), " | ".join(r["phones"]), " | ".join(r["orgs"]), r["sources"]]
        w.writerow(["'" + str(c) if isinstance(c, str) and c[:1] in "=+-@" else c for c in cells])
    return "﻿" + buf.getvalue()
