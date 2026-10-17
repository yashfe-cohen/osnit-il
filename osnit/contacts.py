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


def linked_exists(col, cond):
    """SQL: the entity in `col` is linked (either direction) to an entity `o` satisfying `cond`.

    CROSS JOIN pins the join order: walk this entity's relations first (indexed by a_id / b_id), then look up each
    neighbour by primary key. With a plain JOIN SQLite may instead start from every entity matching `cond` (e.g.
    all phones in the database, via the type index) and probe relations for each one, which turns a page-sized
    lookup into a scan of millions of rows. `cond` is used twice, so bind its parameters twice."""
    return (f"(EXISTS(SELECT 1 FROM relations r CROSS JOIN entities o ON o.id = r.b_id WHERE r.a_id = {col} AND {cond}) "
            f"OR EXISTS(SELECT 1 FROM relations r CROSS JOIN entities o ON o.id = r.a_id WHERE r.b_id = {col} AND {cond}))")


def _aggregate(store, ids):
    """emails/phones/orgs and the independent-source count for exactly these person ids (page-sized)."""
    det = {i: dict(id=i, emails=[], phones=[], orgs=[], sources=0, osint_count=0, avatar="") for i in ids}
    bucket = {"email": "emails", "phone": "phones", "org": "orgs"}
    for part in _chunks(ids):
        ph = ",".join("?" * len(part))
        p_tup = tuple(part)
        for r in store.q(
            f"SELECT r.pid, o.type t, o.display d FROM ("
            f"  SELECT a_id AS pid, b_id AS oid FROM relations WHERE a_id IN ({ph}) "
            f"  UNION ALL "
            f"  SELECT b_id AS pid, a_id AS oid FROM relations WHERE b_id IN ({ph})"
            f") r CROSS JOIN entities o ON o.id = r.oid WHERE o.type IN ('email','phone','org')",
            p_tup + p_tup,
        ):
            det[r["pid"]][bucket[r["t"]]].append(r["d"])
        for r in store.q(
            f"SELECT entity_id eid, COUNT(DISTINCT source_id) n FROM evidence "
            f"WHERE entity_id IN ({ph}) GROUP BY entity_id", p_tup):
            det[r["eid"]]["sources"] = r["n"]
        try:
            for r in store.q(
                f"SELECT entity_id eid, COUNT(*) n FROM osint_findings "
                f"WHERE entity_id IN ({ph}) GROUP BY entity_id", p_tup):
                det[r["eid"]]["osint_count"] = r["n"]
            for r in store.q(
                f"SELECT entity_id eid, COALESCE(NULLIF(local_path,''), image_url) av FROM entity_images "
                f"WHERE entity_id IN ({ph}) ORDER BY is_primary DESC, confidence DESC", p_tup):
                if r["eid"] in det and not det[r["eid"]]["avatar"] and r["av"]:
                    det[r["eid"]]["avatar"] = r["av"]
        except Exception:
            pass
    return det


def _fast_match_person_ids(store: Store, q: str, limit: int = 200) -> list[int]:
    """Fast B-tree indexed lookup of person IDs matching query `q` (by name, alias, skeleton, or linked identifier)."""
    from .textnorm import name_key, fold
    pids = []
    seen = set()

    def _add(pid):
        if pid and pid not in seen:
            seen.add(pid)
            pids.append(int(pid))

    has_letters = any(ch.isalpha() for ch in q)
    digits = "".join(ch for ch in q if ch.isdigit())
    nk = name_key(q)
    ql = fold(q).strip()

    if has_letters:
        try:
            from .identity import find_people
            for m in find_people(store, q, limit=min(limit, 80)):
                _add(m["id"])
        except Exception:
            pass

        for pfx in {nk, ql}:
            if pfx:
                for r in store.q(
                    "SELECT id FROM entities WHERE type='person' AND key >= ? AND key < ? LIMIT ?",
                    (pfx, pfx + "\uffff", limit)
                ):
                    _add(r["id"])
                for r in store.q(
                    "SELECT entity_id FROM aliases WHERE alias_key >= ? AND alias_key < ? AND entity_id IS NOT NULL LIMIT ?",
                    (pfx, pfx + "\uffff", limit)
                ):
                    _add(r["entity_id"])

    # Check linked identifiers (phone, email, national_id, org, username) using indexed key prefix
    id_keys = {ql}
    if nk:
        id_keys.add(nk)
    try:
        from .extract import norm_phone_il
        np = norm_phone_il(q)
        if np:
            id_keys.add(np)
    except Exception:
        pass
    if len(digits) >= 5:
        id_keys.add(digits)
        if len(digits) >= 7:
            tail = digits[3:] if (digits.startswith("972") and len(digits) >= 11) else (digits[1:] if digits.startswith("0") else digits)
            if len(tail) >= 8:
                id_keys.update({"+972" + tail, "972" + tail, "0" + tail, tail})
                if len(tail) == 9:
                    id_keys.add(f"0{tail[:2]}-{tail[2:]}")

    id_types = ("phone", "national_id", "id_number") if not has_letters else ("phone", "email", "national_id", "id_number", "org", "username", "address")
    other_ids = set()
    for ik in id_keys:
        if not ik:
            continue
        for t in id_types:
            for r in store.q(
                "SELECT id FROM entities WHERE type=? AND (key=? OR (key >= ? AND key < ?)) LIMIT 50",
                (t, ik, ik, ik + "\uffff")
            ):
                other_ids.add(r["id"])
    if other_ids:
        ph = ",".join(str(int(i)) for i in list(other_ids)[:200])
        lim2 = int(limit * 2)
        for r in store.q(
            f"SELECT b_id AS pid FROM relations WHERE a_id IN ({ph}) "
            f"UNION ALL "
            f"SELECT a_id AS pid FROM relations WHERE b_id IN ({ph}) LIMIT {lim2}"
        ):
            _add(r["pid"])
    return pids[:limit]


def cap_lists(row, cap):
    """Trim a row's emails/phones/orgs to `cap` items, keeping the true sizes in <field>_total. A common name can
    own hundreds of phones; the list views show the first few and the person's file shows them all."""
    if cap:
        for k in ("emails", "phones", "orgs"):
            vals = row.get(k) or []
            row[k + "_total"] = len(vals)
            row[k] = vals[:cap]
    return row


def contacts(store: Store, q="", only_contactable=False, limit=500, offset=0, cap=None):
    q = (q or "").strip()
    max_id_row = store.q1("SELECT COALESCE(MAX(id), 0) m FROM entities")
    is_large = bool(max_id_row and (max_id_row["m"] or 0) > 50000)

    osint_pids = set()
    try:
        osint_pids = {r["entity_id"] for r in store.q("SELECT DISTINCT entity_id FROM osint_findings LIMIT 500")}
    except Exception:
        pass

    if is_large and q:
        matched_pids = _fast_match_person_ids(store, q, limit=max(limit + offset, 200))
        if not matched_pids:
            total = (store.stats(blocking=False).get("by_type", {}).get("person") or max_id_row["m"])
            return dict(rows=[], total=total)
        ph = ",".join(str(int(x)) for x in matched_pids[:900])
        cond = f"p.type='person' AND p.id IN ({ph})"
        if only_contactable:
            cond += " AND " + linked_exists("p.id", "o.type IN ('email','phone')")
        raw_page = [dict(r) for r in store.q(
            f"SELECT p.id, p.display, p.first_seen, p.last_seen FROM entities p WHERE {cond}"
        )]
        rank_map = {pid: idx for idx, pid in enumerate(matched_pids)}
        raw_page.sort(key=lambda r: (0 if r["id"] in osint_pids else 1, rank_map.get(r["id"], 999999), -(r["last_seen"] or 0)))
        page = raw_page[offset:offset + limit]
    elif is_large and not q and not only_contactable:
        page = []
        seen_p = set()
        if offset == 0 and osint_pids:
            ph = ",".join(str(int(x)) for x in list(osint_pids)[:200])
            for r in store.q(
                f"SELECT p.id, p.display, p.first_seen, p.last_seen FROM entities p "
                f"WHERE p.type='person' AND p.id IN ({ph}) ORDER BY p.last_seen DESC, p.id DESC LIMIT ?",
                (limit,)
            ):
                page.append(r)
                seen_p.add(r["id"])
        rem = limit - len(page)
        if rem > 0:
            for r in store.q(
                "SELECT p.id, p.display, p.first_seen, p.last_seen FROM entities p "
                "WHERE p.type='person' ORDER BY p.last_seen DESC, p.id DESC LIMIT ? OFFSET ?",
                (rem + len(seen_p), offset)
            ):
                if r["id"] not in seen_p:
                    page.append(r)
                    if len(page) >= limit:
                        break
    else:
        where, args = ["p.type='person'"], []
        if q:
            like = f"%{q}%"
            q_clauses = [
                "p.display LIKE ?",
                "p.key LIKE ?",
                "p.id IN (SELECT entity_id FROM aliases WHERE alias LIKE ?)",
                linked_exists("p.id", "(o.display LIKE ? OR o.key LIKE ?)"),
            ]
            q_args = [like, like.lower(), like, like, like.lower(), like, like.lower()]
            try:
                from .extract import norm_phone_il
                np = norm_phone_il(q)
                if np:
                    q_clauses.append(linked_exists("p.id", "o.key=?"))
                    q_args += [np, np]
            except Exception:
                pass
            matched_pids = _fast_match_person_ids(store, q, limit=100)
            if matched_pids:
                q_clauses.append(f"p.id IN ({','.join(str(int(x)) for x in matched_pids)})")
            where.append("(" + " OR ".join(q_clauses) + ")")
            args += q_args
        if only_contactable:
            where.append(linked_exists("p.id", "o.type IN ('email','phone')"))
        w = " AND ".join(where)
        # Avoid correlated subquery in ORDER BY so SQLite uses entities_type_seen index
        raw_page = [dict(r) for r in store.q(
            f"SELECT p.id, p.display, p.first_seen, p.last_seen FROM entities p WHERE {w} "
            f"ORDER BY p.last_seen DESC, p.id DESC LIMIT ? OFFSET ?", (*args, limit, offset)
        )]
        if osint_pids and offset == 0:
            raw_page.sort(key=lambda r: (0 if r["id"] in osint_pids else 1, -(r["last_seen"] or 0), -r["id"]))
        page = raw_page

    ids = [r["id"] for r in page]
    det = _aggregate(store, ids) if ids else {}
    rows = []
    for r in page:
        d = det.get(r["id"], {})
        rows.append(dict(id=r["id"], name=r["display"],
                         emails=_dedupe(d.get("emails", [])), phones=_dedupe(d.get("phones", [])),
                         orgs=_dedupe(d.get("orgs", [])), sources=d.get("sources", 0),
                         osint_count=d.get("osint_count", 0), avatar=d.get("avatar", ""),
                         first_seen=r["first_seen"], last_seen=r["last_seen"]))
        cap_lists(rows[-1], cap)
    if is_large:
        total = store.stats(blocking=False).get("by_type", {}).get("person") or max_id_row["m"]
    else:
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
