"""Flat contacts table: one row per person with all their emails, phones and orgs — the full
database, not a summary. Used by the 'אנשים' view and its CSV export."""
import csv
import io

from .store import Store

AGG = """
SELECT p.id, p.display, p.first_seen, p.last_seen,
  (SELECT COUNT(DISTINCT source_id) FROM evidence v WHERE v.entity_id=p.id) sources,
  (SELECT GROUP_CONCAT(DISTINCT o.display) FROM relations r JOIN entities o ON o.id=
     CASE WHEN r.a_id=p.id THEN r.b_id ELSE r.a_id END
   WHERE (r.a_id=p.id OR r.b_id=p.id) AND o.type='email') emails,
  (SELECT GROUP_CONCAT(DISTINCT o.display) FROM relations r JOIN entities o ON o.id=
     CASE WHEN r.a_id=p.id THEN r.b_id ELSE r.a_id END
   WHERE (r.a_id=p.id OR r.b_id=p.id) AND o.type='phone') phones,
  (SELECT GROUP_CONCAT(DISTINCT o.display) FROM relations r JOIN entities o ON o.id=
     CASE WHEN r.a_id=p.id THEN r.b_id ELSE r.a_id END
   WHERE (r.a_id=p.id OR r.b_id=p.id) AND o.type='org') orgs
FROM entities p WHERE p.type='person'
"""


def _split(s):
    return [x for x in (s or "").split(",") if x]


def contacts(store: Store, q="", only_contactable=False, limit=500, offset=0):
    where, args = "", []
    if q:
        where = " AND (p.display LIKE ? OR p.key LIKE ?)"
        args += [f"%{q}%", f"%{q.lower()}%"]
    sql = AGG + where + " ORDER BY sources DESC, p.last_seen DESC LIMIT ? OFFSET ?"
    rows = []
    for r in store.q(sql, (*args, limit, offset)):
        emails, phones = _split(r["emails"]), _split(r["phones"])
        if only_contactable and not (emails or phones):
            continue
        rows.append(dict(id=r["id"], name=r["display"], emails=emails, phones=phones,
                         orgs=_split(r["orgs"]), sources=r["sources"],
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
