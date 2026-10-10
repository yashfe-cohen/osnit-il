"""Stage 1 of every import: understand the file before anything is written.

analyze_file() reads the file, finds every record table in it (also inside documents), catalogues each column
(what information type it holds, by header and by content), extracts a few sample records, and checks the
sample's identifiers (emails, phones, addresses, usernames, custom IDs…) against the database: values that are
already known from other files or from the web connect the new records to existing people.

import_summary() describes what an import actually added, and what it connected to.
"""
import os
import time
from collections import Counter, defaultdict, deque

from .catalog import blank
from .extract import Extractor
from .importdb import (DOC_EXT, Context, _peeked, cheap_count, describe, raw_tables, record_extraction,
                       apply_merges, big_text, table_delimiter)
from .parse import parse
from .semantic import TYPES

LINK_TYPES = ("email", "phone", "address", "username", "url", "domain", "national_id")


def source_label(store, src) -> str:
    """'file name' for imported sources, the site's domain for web pages."""
    if src["import_id"]:
        r = store.q1("SELECT name FROM imports WHERE id=?", (src["import_id"],))
        if r:
            return r["name"]
    url = src["url"] or ""
    if url.startswith("http"):
        return src["domain"] or url
    return (src["title"] or url).split(" / ")[0]


def origin_of(src) -> str:
    url = src["url"] or ""
    return "file" if (src["import_id"] or src["state"] == "imported" or url.startswith(("import://", "file://"))) else "web"


def known_links(store, keys, limit=12):
    """keys: {(type, key)} -> existing entities with the people/orgs they belong to and where they came from."""
    out = []
    for t, k in list(keys)[:2000]:
        e = store.q1("SELECT id, type, display FROM entities WHERE type=? AND key=?", (t, k))
        if not e:
            continue
        owners = store.q(
            "SELECT DISTINCT o.id, o.type, o.display FROM relations r JOIN entities o "
            "ON o.id = CASE WHEN r.a_id=? THEN r.b_id ELSE r.a_id END WHERE (r.a_id=? OR r.b_id=?) "
            "AND o.type IN ('person','org') LIMIT 5", (e["id"], e["id"], e["id"]))
        srcs = store.q("SELECT DISTINCT s.id, s.url, s.domain, s.title, s.state, s.import_id FROM evidence v "
                       "JOIN sources s ON s.id=v.source_id WHERE v.entity_id=? LIMIT 5", (e["id"],))
        out.append(dict(type=t, value=e["display"], entity_id=e["id"],
                        owners=[dict(id=o["id"], type=o["type"], name=o["display"]) for o in owners],
                        seen_in=sorted({source_label(store, s) for s in srcs})))
    out.sort(key=lambda x: -len(x["owners"]))
    return out[:limit], len(out)


def _short(v, n=120):
    if v is None:
        return None
    s = str(v)
    return s[:n] + "…" if len(s) > n else s


def _layout(ctx, table, cols, raw):
    """The sample rows as the operator arranged them (removed separators joined) — what the piece studio marks."""
    lcols, lrows = apply_merges(cols, raw, (ctx.overrides.get(table) or {}).get("__merge__"))
    return dict(layout_cols=[str(c) for c in lcols], layout_raw=list(lrows))


def repreview(store, preview, overrides=None) -> dict:
    """Re-catalogue and re-extract each table's kept sample rows with the user's corrections — WITHOUT reading
    the file again. Powers live editing on the analysis screen: change a column's type, see the 3 records update."""
    ctx = Context(store, overrides)
    tables = []
    for t in preview.get("tables", []):
        cols = t.get("cols") or [c["name"] for c in t.get("columns", [])]
        raw = t.get("raw") or []
        vcols, aug = ctx.prepare(t["table"], cols, raw)      # re-apply the piece rules to the kept rows
        aug = list(aug)
        plan = ctx.plan(t["table"], vcols, aug)
        samples = []
        for rec in aug:
            ex, _ = record_extraction(rec, plan, [], 0.8)
            if ex.ents and len(samples) < 3:
                samples.append(describe(ex, plan))
        tables.append(dict(t, **plan.summary(), **_layout(ctx, t["table"], cols, raw), samples=samples,
                           unknown=[c.name for c in plan.columns if c.status == "attribute" and c.type == "unknown"]))
    return dict(preview, tables=tables)


SWEEP_BYTES = 8 * 1024 * 1024
RAW_ROWS = 5                        # sample rows the operator sees, from the middle of the file
MID_CAP = 200_000                   # never stream further than this to reach the middle of a huge table


def middle_rows(rows, n, cols, k=RAW_ROWS, cap=MID_CAP):
    """k non-empty rows from the middle of a table of ~n rows, as [(row number, row)]. Streams only up to the
    middle (at most `cap` rows in); when the count was an estimate and the table ends sooner, the last rows seen."""
    start = max(1, min((n - k) // 2 + 1, cap))
    before, out = deque(maxlen=k), []
    for i, r in enumerate(rows, 1):
        if not any(r.get(c) not in (None, "") for c in cols):
            continue
        if i < start:
            before.append((i, r))
            continue
        out.append((i, r))
        if len(out) == k:
            break
    return (list(before) + out)[-k:]
BIG_FILE = 128 * 1024 * 1024        # above this, a SQL dump is previewed from its head only
HEAD_SLICE = 48 * 1024 * 1024


def _head_slice(path):
    """A temp copy of the first HEAD_SLICE bytes, cut at a statement end — enough to see every table's shape."""
    import tempfile
    with open(path, "rb") as f:
        data = f.read(HEAD_SLICE)
    cut = data.rfind(b";\n")
    data = data[:cut + 2] if cut > 0 else data
    fd, tmp = tempfile.mkstemp(suffix=os.path.splitext(path)[1])
    with os.fdopen(fd, "wb") as out:
        out.write(data)
    return tmp


def analyze_file(store, path, name=None, overrides=None, sample=300) -> dict:
    """Read-only analysis of one file. Returns what it holds; never writes to the database.
    Huge SQL dumps are previewed from a head slice (row counts still come from the whole file); the import
    itself always streams the entire file."""
    ext = os.path.splitext(path)[1].lower()
    size = os.path.getsize(path) if os.path.exists(path) else 0
    if ext in (".sql", ".dump") and size > BIG_FILE:
        tmp = _head_slice(path)
        try:
            res = _analyze(store, tmp, name or os.path.basename(path), overrides, sample)
        finally:
            os.remove(tmp)
        from .importdb import count_sql_tuples
        total = count_sql_tuples(path)
        for t in res["tables"]:
            t["rows_exact"] = False
        if len(res["tables"]) == 1:
            res["tables"][0]["rows"] = total
        res.update(records=total, bytes=size, partial_preview=True)
        return res
    return _analyze(store, path, name, overrides, sample)


def _analyze(store, path, name=None, overrides=None, sample=300) -> dict:
    t0 = time.time()
    name = name or os.path.basename(path)
    ext = os.path.splitext(path)[1].lower()
    ctx = Context(store, overrides)
    tables, info = [], defaultdict(lambda: dict(columns=[], tables=set()))
    anchors = set()
    security = []        # credential-type columns: stored (not dropped), surfaced so the operator knows they are kept
    counts = cheap_count(path)      # row counts without a full pass where possible (no cap on big files)
    for table, cols, rows in raw_tables(path):
        head, rest = _peeked(rows, sample)
        cols = cols or list(dict.fromkeys(k for r in head for k in r))
        if table in counts:
            n, exact = counts[table]
        else:                                       # json/xlsx/doc tables are already in memory: count them here
            rest = list(rest)                       # (rest replays head + remainder)
            n, exact = len(rest), True
        # raw sample rows, as they are in the file — for live re-cataloguing, for editing the row layout and for
        # marking pieces with ***…***. Taken from the MIDDLE of the file: its first rows are often titles or junk.
        picked = middle_rows(rest, n, cols)
        raw = [{k: _short(r.get(k), 600) for k in cols} for _, r in picked]
        raw_rows = [i for i, _ in picked]
        vcols, aug_head = ctx.prepare(table, cols, head)       # marker-taught pieces as their own columns
        aug_head = list(aug_head)
        plan = ctx.plan(table, vcols, aug_head)
        samples, recs = [], 0
        for rec in aug_head:
            ex, _ = record_extraction(rec, plan, [], 0.8)
            if not ex.ents:
                continue
            recs += 1
            if len(samples) < 3:
                samples.append(describe(ex, plan))
            anchors |= {k for k in ex.ents if k[0] in LINK_TYPES or k[0].startswith("u_")}
        for c in plan.columns:
            if c.status in ("entity", "attribute", "doc") and c.type not in ("unknown",):
                info[c.type]["columns"].append(c.name)
                info[c.type]["tables"].add(table)
            if ctx.registry.group(c.type) == "security" and c.status != "skip":
                security.append(dict(table=table, column=c.name, type=c.type, label=ctx.registry.label(c.type)))
        unknown = [c.name for c in plan.columns if c.status == "attribute" and c.type == "unknown"]
        tables.append(dict(table=table, rows=n, rows_exact=exact, sample_records=recs, cols=[str(c) for c in cols],
                           **plan.summary(), samples=samples, raw=raw, raw_rows=raw_rows, **_layout(ctx, table, cols, raw),
                           delim=table_delimiter(path, table), unknown=unknown))
    known, n_known = known_links(store, anchors)
    document = None
    huge = big_text(path)
    if ext in DOC_EXT and ext != ".xml" and not (huge and tables):   # a huge record file: its records say it all
        document = _document_sweep(path, name, 300_000 if huge else 2_000_000)
    info_types = sorted(
        (dict(type=t, label=ctx.registry.label(t), group=ctx.registry.types[t].group if t in ctx.registry.types else "",
              linkable=bool(ctx.registry.entity(t)), columns=v["columns"], tables=sorted(v["tables"]))
         for t, v in info.items()), key=lambda x: (not x["linkable"], x["label"]))
    return dict(
        file=name, ext=ext, bytes=os.path.getsize(path) if os.path.exists(path) else 0,
        tables=tables, info_types=info_types, security=security, document=document,
        known=dict(count=n_known, examples=known, checked=len(anchors)),
        records=sum(t["rows"] for t in tables if t["usable"]),
        took=round(time.time() - t0, 2), analyzed_at=time.time())


def _document_sweep(path, name, limit=2_000_000):
    """For documents: what the text extractor finds (people, emails, phones, orgs…) besides record tables."""
    try:
        with open(path, "rb") as f:
            # a sample of a huge text file is enough to say what it holds (binary documents need their whole body)
            body = f.read(SWEEP_BYTES if path.lower().endswith((".txt", ".log", ".md")) else -1)
        p = parse(body, "file://" + name, "")
    except Exception as e:
        return dict(error=str(e)[:200])
    ex = Extractor([]).extract(p.text[:limit], p.title)
    by = Counter(t for t, _ in ex.ents)
    ex_vals = defaultdict(list)
    for (t, _), e in ex.ents.items():
        if len(ex_vals[t]) < 6:
            ex_vals[t].append(e["display"])
    return dict(kind=p.kind, title=p.title[:200], chars=len(p.text), page_type=ex.page_type,
                counts=dict(by), examples=dict(ex_vals), links=len(ex.links))


SUMMARY_LINK_CAP = 40000      # above this many entities, skip the cross-source linkage scan (a display nicety)


def import_summary(store, import_id) -> dict:
    """What an import added: entities by type, kept fields, and how much of it connects to other sources.

    Keyed on sources.import_id (indexed) rather than a giant literal `source_id IN (…thousands…)` list, and the
    cross-source linkage — the only O(entities) part — is gated by size, so finalising a multi-GB import stays fast
    and flat in memory instead of spending minutes in a correlated `NOT IN (…)` scan."""
    nsrc = store.q1("SELECT COUNT(*) n FROM sources WHERE import_id=?", (import_id,))["n"]
    if not nsrc:
        return dict(sources=0, by_type={}, attributes=[], linked={}, linked_examples=[])
    by_type = {r["type"]: r["n"] for r in store.q(
        "SELECT e.type, COUNT(DISTINCT e.id) n FROM sources s JOIN evidence v ON v.source_id=s.id "
        "JOIN entities e ON e.id=v.entity_id WHERE s.import_id=? GROUP BY e.type", (import_id,))}
    attrs = [dict(r) for r in store.q(
        "SELECT a.name, a.kind, COUNT(*) n, COUNT(DISTINCT a.entity_id) entities FROM sources s "
        "JOIN attributes a ON a.source_id=s.id WHERE s.import_id=? GROUP BY a.name, a.kind ORDER BY n DESC LIMIT 40",
        (import_id,))]
    total = sum(by_type.values())
    linked, ex = {}, []
    if total <= SUMMARY_LINK_CAP:         # an entity is "linked" if it also has evidence from another source
        linked = {r["type"]: r["n"] for r in store.q(
            "SELECT e.type, COUNT(DISTINCT e.id) n FROM sources s JOIN evidence v ON v.source_id=s.id "
            "JOIN entities e ON e.id=v.entity_id WHERE s.import_id=? AND EXISTS ("
            "  SELECT 1 FROM evidence v2 JOIN sources s2 ON s2.id=v2.source_id "
            "  WHERE v2.entity_id=e.id AND (s2.import_id IS NULL OR s2.import_id<>?)) GROUP BY e.type",
            (import_id, import_id))}
        for r in store.q(
                "SELECT e.id, e.type, e.display FROM sources s JOIN evidence v ON v.source_id=s.id "
                "JOIN entities e ON e.id=v.entity_id WHERE s.import_id=? AND e.type NOT IN ('domain','role') "
                "AND EXISTS (SELECT 1 FROM evidence v2 JOIN sources s2 ON s2.id=v2.source_id "
                "  WHERE v2.entity_id=e.id AND (s2.import_id IS NULL OR s2.import_id<>?)) "
                "GROUP BY e.id LIMIT 12", (import_id, import_id)):
            others = store.q("SELECT DISTINCT s.id, s.url, s.domain, s.title, s.state, s.import_id FROM evidence v "
                             "JOIN sources s ON s.id=v.source_id WHERE v.entity_id=? AND "
                             "(s.import_id IS NULL OR s.import_id<>?) LIMIT 4", (r["id"], import_id))
            ex.append(dict(id=r["id"], type=r["type"], value=r["display"],
                           also_in=sorted({source_label(store, s) for s in others})))
    return dict(sources=nsrc, by_type=by_type, attributes=attrs, linked=linked, linked_examples=ex)


def type_labels(registry=None):
    reg = registry.types if registry else TYPES
    return {k: t.label for k, t in reg.items()}


def is_blank(v):
    return blank(v)
