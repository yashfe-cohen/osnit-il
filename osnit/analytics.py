"""Dashboard analytics: how much of each kind we hold, how complete the pictures are, and recent activity.

Public-source only. A "complete identity" means a person we can place and reach from public data
(name + organization/role + a public email or phone) — never passwords or any credential.
"""
import json
import threading
import time

from .store import Store

DAY = 86400


def _activity(store, now):
    """New entities per day over the last 30 days (cheap: one indexed-ish pass, fine for the fast paint)."""
    buckets = {}
    for r in store.q("SELECT CAST(first_seen/? AS INT) d, COUNT(*) n FROM entities WHERE first_seen>? GROUP BY d",
                     (DAY, now - 30 * DAY)):
        buckets[int(r["d"])] = r["n"]
    start = int((now - 29 * DAY) / DAY)
    return [{"date": time.strftime("%m-%d", time.localtime(d * DAY)), "count": buckets.get(d, 0)}
            for d in range(start, int(now / DAY) + 1)]


def _rows(store, sql, args=()):
    return [dict(r) for r in store.q(sql, args)]


def _full(store: Store) -> dict:
    now = time.time()
    g = lambda sql, a=(): store.q1(sql, a)["n"]
    by_type = {r["type"]: r["n"] for r in store.q("SELECT type, COUNT(*) n FROM entities GROUP BY type")}

    # person completeness: which facets each person has at least one relation to
    comp = store.q("""
      SELECT p.id,
        MAX(o.type='email')  has_email,
        MAX(o.type='phone')  has_phone,
        MAX(o.type='org')    has_org,
        MAX(o.type='role')   has_role,
        MAX(o.type='domain') has_domain
      FROM entities p
      JOIN relations r ON (r.a_id=p.id OR r.b_id=p.id)
      JOIN entities o ON o.id = CASE WHEN r.a_id=p.id THEN r.b_id ELSE r.a_id END
      WHERE p.type='person' GROUP BY p.id""")
    people_total = by_type.get("person", 0)
    named_only = people_total - len(comp)
    tiers = {"name_email_phone_org": 0, "name_and_contact": 0, "name_and_affiliation": 0, "name_only": named_only}
    has = {"email": 0, "phone": 0, "org": 0, "role": 0, "domain": 0}
    for r in comp:
        for k in has:
            if r["has_" + k]:
                has[k] += 1
        contact = r["has_email"] or r["has_phone"]
        affil = r["has_org"] or r["has_role"]
        if r["has_email"] and r["has_phone"] and affil:
            tiers["name_email_phone_org"] += 1
        elif contact:
            tiers["name_and_contact"] += 1
        elif affil:
            tiers["name_and_affiliation"] += 1
        else:
            tiers["name_only"] += 1

    completeness = dict(
        people=people_total, with_email=has["email"], with_phone=has["phone"], with_org=has["org"],
        with_role=has["role"], tiers=tiers,
        complete=tiers["name_email_phone_org"],
        complete_pct=round(100 * tiers["name_email_phone_org"] / people_total, 1) if people_total else 0.0)

    counts = dict(
        people=by_type.get("person", 0), orgs=by_type.get("org", 0), emails=by_type.get("email", 0),
        phones=by_type.get("phone", 0), domains=by_type.get("domain", 0), urls=by_type.get("url", 0),
        roles=by_type.get("role", 0), addresses=by_type.get("address", 0), usernames=by_type.get("username", 0),
        custom_ids=sum(n for t, n in by_type.items() if t.startswith("u_")),
        attributes=g("SELECT COUNT(*) n FROM attributes"),
        attribute_fields=g("SELECT COUNT(DISTINCT name) n FROM attributes"),
        files=g("SELECT COUNT(*) n FROM imports WHERE state='done'"),
        sources_file=g("SELECT COUNT(*) n FROM sources WHERE import_id IS NOT NULL OR state='imported'"),
        sources_web=g("SELECT COUNT(*) n FROM sources WHERE import_id IS NULL AND state!='imported' AND url LIKE 'http%'"),
        documents=g("SELECT COUNT(*) n FROM sources WHERE kind IN "
            "('pdf','docx','xlsx','csv','json','vcf','txt')"),
        sources=g("SELECT COUNT(*) n FROM sources"),
        sources_scanned=g("SELECT COUNT(*) n FROM sources WHERE state IN ('scanned','imported')"),
        relations=g("SELECT COUNT(*) n FROM relations"), evidence=g("SELECT COUNT(*) n FROM evidence"),
        subjects=g("SELECT COUNT(*) n FROM subjects"),
        subjects_active=g("SELECT COUNT(*) n FROM subjects WHERE status='active'"))

    sources_by_kind = {r["kind"] or "?": r["n"] for r in store.q(
        "SELECT kind, COUNT(*) n FROM sources WHERE state IN ('scanned','imported') GROUP BY kind ORDER BY n DESC")}
    page_types = {r["page_type"] or "normal": r["n"] for r in store.q(
        "SELECT page_type, COUNT(*) n FROM sources WHERE state='scanned' GROUP BY page_type")}

    top_orgs = _rows(store, """
      SELECT e.id, e.display, COUNT(DISTINCT CASE WHEN p.type='person' THEN p.id END) people,
             COUNT(DISTINCT v.source_id) sources
      FROM entities e
      LEFT JOIN relations r ON (r.a_id=e.id OR r.b_id=e.id)
      LEFT JOIN entities p ON p.id = CASE WHEN r.a_id=e.id THEN r.b_id ELSE r.a_id END
      LEFT JOIN evidence v ON v.entity_id=e.id
      WHERE e.type='org' GROUP BY e.id ORDER BY people DESC, sources DESC LIMIT 10""")
    top_domains = _rows(store, """
      SELECT e.id, e.display, COUNT(DISTINCT v.source_id) sources FROM entities e
      JOIN evidence v ON v.entity_id=e.id WHERE e.type='domain'
      GROUP BY e.id ORDER BY sources DESC LIMIT 10""")

    activity = _activity(store, now)

    recent_findings = []
    for r in _rows(store, """SELECT s.query subject, e.subject_id, e.at, e.payload FROM events e
      JOIN subjects s ON s.id=e.subject_id WHERE e.kind='finding' ORDER BY e.id DESC LIMIT 12"""):
        recent_findings.append(dict(subject=r["subject"], subject_id=r["subject_id"], at=r["at"],
                                    **json.loads(r["payload"])))
    data_quality = dict(
        high_conf=g("SELECT COUNT(DISTINCT entity_id) n FROM evidence WHERE confidence>=0.7"),
        corroborated=g("""SELECT COUNT(*) n FROM (SELECT entity_id FROM evidence
                          GROUP BY entity_id HAVING COUNT(DISTINCT source_id)>=2)"""),
        single_source=g("""SELECT COUNT(*) n FROM (SELECT entity_id FROM evidence
                           GROUP BY entity_id HAVING COUNT(DISTINCT source_id)=1)"""))

    from .linking import link_stats
    return dict(now=now, counts=counts, links=link_stats(store), completeness=completeness, sources_by_kind=sources_by_kind,
                page_types=page_types, top_orgs=top_orgs, top_domains=top_domains, activity=activity,
                recent_findings=recent_findings, data_quality=data_quality)


# ---------------------------------------------------------------- fast first paint + change-driven cache
# The full dashboard runs a dozen whole-table aggregates/joins; on a large DB that is seconds. Two problems to solve:
#   1. never sit blank on a cold load  -> serve the cheap counts (fast()) at once, fill the heavy sections behind.
#   2. never recompute when nothing changed -> once computed, the snapshot is served UNTOUCHED until new data actually
#      arrives (store.data_version changes). An idle database pays nothing; a changing one recomputes once (throttled)
#      in the background while the previous snapshot is still served. The snapshot is also persisted, so a freshly
#      (re)started server shows the last picture immediately instead of recomputing from a blank panel.
_MIN_RECOMPUTE = 4.0        # while data is actively changing (an import in flight), recompute at most this often
_SNAPSHOT_KEY = "dashboard_snapshot"
_LOCK = threading.Lock()   # guards the per-Store cache dict (store._dash_cache), which is GC'd with the store


def _empty_heavy():
    return dict(completeness=dict(people=0, with_email=0, with_phone=0, with_org=0, with_role=0,
                                  tiers={"name_email_phone_org": 0, "name_and_contact": 0,
                                         "name_and_affiliation": 0, "name_only": 0}, complete=0, complete_pct=0.0),
                links=dict(cross_source_entities=0, shared_identifiers=0),
                data_quality=dict(high_conf=0, corroborated=0, single_source=0),
                sources_by_kind={}, page_types={}, top_orgs=[], top_domains=[], activity=[], recent_findings=[])


def fast(store: Store) -> dict:
    """Only the cheap counts (a GROUP BY + a few COUNT(*)) — sub-100ms even at millions of rows — so the KPI row
    paints immediately while the heavy sections compute."""
    now = time.time()
    g = lambda sql, a=(): store.q1(sql, a)["n"]
    by_type = {r["type"]: r["n"] for r in store.q("SELECT type, COUNT(*) n FROM entities GROUP BY type")}
    counts = dict(
        people=by_type.get("person", 0), orgs=by_type.get("org", 0), emails=by_type.get("email", 0),
        phones=by_type.get("phone", 0), domains=by_type.get("domain", 0), urls=by_type.get("url", 0),
        roles=by_type.get("role", 0), addresses=by_type.get("address", 0), usernames=by_type.get("username", 0),
        custom_ids=sum(n for t, n in by_type.items() if t.startswith("u_")),
        attributes=g("SELECT COUNT(*) n FROM attributes"),
        attribute_fields=g("SELECT COUNT(DISTINCT name) n FROM attributes"),
        files=g("SELECT COUNT(*) n FROM imports WHERE state='done'"),
        sources_file=g("SELECT COUNT(*) n FROM sources WHERE import_id IS NOT NULL OR state='imported'"),
        sources_web=g("SELECT COUNT(*) n FROM sources WHERE import_id IS NULL AND state!='imported' AND url LIKE 'http%'"),
        documents=g("SELECT COUNT(*) n FROM sources WHERE kind IN ('pdf','docx','xlsx','csv','json','vcf','txt')"),
        sources=g("SELECT COUNT(*) n FROM sources"),
        sources_scanned=g("SELECT COUNT(*) n FROM sources WHERE state IN ('scanned','imported')"),
        relations=g("SELECT COUNT(*) n FROM relations"), evidence=g("SELECT COUNT(*) n FROM evidence"),
        subjects=g("SELECT COUNT(*) n FROM subjects"),
        subjects_active=g("SELECT COUNT(*) n FROM subjects WHERE status='active'"))
    heavy = _empty_heavy()
    heavy["activity"] = _activity(store, now)
    return dict(now=now, counts=counts, partial=True, **heavy)


def _load_snapshot(store):
    """The last full dashboard this database ever produced, persisted so a fresh server start is not blank."""
    try:
        raw = store.meta_get(_SNAPSHOT_KEY)
        return json.loads(raw) if raw else None
    except Exception:
        return None


def _refresh(store):
    # Capture the data-version BEFORE reading: if a write lands mid-compute, the snapshot's version stays below the
    # store's current one, so the next dashboard() call recomputes again instead of trusting a half-stale picture.
    v0 = store.data_version
    try:
        data = _full(store)
    except Exception:
        data = None
    with _LOCK:
        c = store._dash_cache
        now = time.time()
        if data is not None:
            c["data"], c["version"], c["day"] = data, v0, int(now / DAY)
            try:
                store.meta_set(_SNAPSHOT_KEY, json.dumps(data))   # silent write: does not itself count as new data
            except Exception:
                pass
        c["at"] = now
        c["computing"] = False


def dashboard(store: Store) -> dict:
    """Instant and idle-quiet. Once the full dashboard is computed it is served unchanged until new data actually
    arrives (tracked by store.data_version), so an unchanging database never recomputes. When data does change it is
    recomputed once in the background (throttled by _MIN_RECOMPUTE) while the last snapshot is served meanwhile; on a
    cold start the persisted snapshot is adopted so the panel shows the last picture at once rather than blank."""
    now = time.time()
    today = int(now / DAY)
    ver = store.data_version
    with _LOCK:
        c = getattr(store, "_dash_cache", None)
        if c is None:                                   # first touch in this process
            c = store._dash_cache = {"data": None, "version": None, "at": 0.0, "day": today, "computing": False}
            snap = _load_snapshot(store)
            if snap is not None:                        # adopt the persisted picture; version None -> refresh once
                c["data"], c["at"], c["day"] = snap, 0.0, today
        if c["data"] is not None and c["version"] == ver and c["day"] == today:
            return dict(c["data"], stale=False, partial=False)     # nothing changed -> serve as-is, no recompute
        have = c["data"]
        if not c["computing"] and now - c["at"] >= _MIN_RECOMPUTE:
            c["computing"] = True
            threading.Thread(target=_refresh, args=(store,), daemon=True).start()
    if have is not None:
        return dict(have, stale=True, partial=False)
    return fast(store)
