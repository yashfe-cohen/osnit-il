"""Dashboard analytics: how much of each kind we hold, how complete the pictures are, and recent activity.

Public-source only. A "complete identity" means a person we can place and reach from public data
(name + organization/role + a public email or phone) — never passwords or any credential.
"""
import json
import time

from .store import Store

DAY = 86400


def _rows(store, sql, args=()):
    return [dict(r) for r in store.q(sql, args)]


def dashboard(store: Store) -> dict:
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

    # 30-day activity: new entities/day
    buckets = {}
    for r in store.q("SELECT CAST(first_seen/? AS INT) d, COUNT(*) n FROM entities WHERE first_seen>? GROUP BY d",
                     (DAY, now - 30 * DAY)):
        buckets[int(r["d"])] = r["n"]
    start = int((now - 29 * DAY) / DAY)
    activity = [{"date": time.strftime("%m-%d", time.localtime(d * DAY)), "count": buckets.get(d, 0)}
                for d in range(start, int(now / DAY) + 1)]

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
