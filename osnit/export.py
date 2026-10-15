"""Flatten a profile into rows for CSV/spreadsheet export."""
import csv
import io
import time

FACETS = ("orgs", "roles", "emails", "phones", "domains", "links", "documents_linked")


def _ts(t):
    return time.strftime("%Y-%m-%d %H:%M", time.localtime(t)) if t else ""


def profile_rows(p):
    idents = p["identities"] + ([dict(p["unattributed"], id="unattributed", label="")] if p["unattributed"] else [])
    for i in idents:
        for fk in FACETS:
            for it in i.get(fk, []):
                ev = it["evidence"][0] if it["evidence"] else {}
                yield dict(subject=p["subject"]["canonical"], identity=i["id"], identity_label=i.get("label", ""),
                           type=it["type"], value=it["value"], aliases=" | ".join(it.get("aliases", [])),
                           confidence=it["confidence"], status=it.get("status", ""), sources=it.get("sources", 1),
                           first_seen=_ts(it["first_seen"]), last_seen=_ts(it["last_seen"]),
                           evidence_url=ev.get("url", ""), evidence=ev.get("snippet", ""))
        for d in i.get("documents", []):
            yield dict(subject=p["subject"]["canonical"], identity=i["id"], identity_label=i.get("label", ""),
                       type="document", value=d.get("title") or d["url"], aliases="", confidence=i["confidence"],
                       status="", sources=1, first_seen=_ts(d.get("first_seen")), last_seen=_ts(d.get("last_scanned")),
                       evidence_url=d["url"], evidence="")


def profile_csv(p) -> str:
    buf = io.StringIO()
    rows = list(profile_rows(p))
    cols = ["subject", "identity", "identity_label", "type", "value", "aliases", "confidence", "status", "sources",
            "first_seen", "last_seen", "evidence_url", "evidence"]
    w = csv.DictWriter(buf, fieldnames=cols)
    w.writeheader()
    for r in rows:
        # neutralise spreadsheet formulas coming from scraped text
        w.writerow({k: ("'" + v if isinstance(v, str) and v[:1] in "=+-@" else v) for k, v in r.items()})
    return "﻿" + buf.getvalue()     # BOM: Excel opens Hebrew correctly
