"""Extraction quality against a labelled corpus: <name>.(html|txt|...) + <name>.gold.json.

gold: {"subject": opt, "page_type": opt, "persons": [...], "links": [[person, type, value]...],
       "not_links": [...], "max_link_confidence": opt}
"""
import glob
import json
import os

from .extract import Extractor, SubjectSpec, org_key
from .parse import parse
from .textnorm import fold, name_key
from .variants import build_matcher, name_variants
from .xling import role_canon


def _other_matches(typ, value, other_key, other_display):
    if typ in ("email", "phone", "domain", "url"):
        return other_key == value.lower()
    if typ == "org":
        want = set(org_key(value).split())
        return bool(want) and want <= set(other_key.split())
    if typ == "role":
        return role_canon(other_display) == role_canon(value) or fold(value) in fold(other_display)
    return fold(value) in fold(other_display)


def _find(ex, person, typ, value):
    pk = name_key(person)
    best = None
    for (a, b, _kind), hits in ex.links.items():
        for p, o in ((a, b), (b, a)):
            if p[0] == "person" and p[1] == pk and o[0] == typ:
                disp = ex.ents.get(o, {}).get("display", o[1])
                if _other_matches(typ, value, o[1], disp):
                    c = max(c for _, c in hits)
                    best = c if best is None else max(best, c)
    return best


def evaluate_doc(path, gold):
    with open(path, "rb") as f:
        body = f.read()
    ct = "text/html; charset=utf-8" if path.endswith(".html") else "text/plain; charset=utf-8"
    parsed = parse(body, "http://corpus.local/" + os.path.basename(path), ct)
    specs = []
    if gold.get("subject"):
        s = gold["subject"]
        specs.append(SubjectSpec(1, "person", s, name_key(s), build_matcher(name_variants(s))))
    ex = Extractor(specs).extract(parsed.text, parsed.title)
    got_p = {k for (t, k) in ex.ents if t == "person"}
    gold_p = {name_key(p) for p in gold.get("persons", [])}
    if gold.get("subject"):
        got_p.discard(name_key(gold["subject"]))
        gold_p.discard(name_key(gold["subject"]))
    res = dict(doc=os.path.basename(path), page_type=ex.page_type, expected_type=gold.get("page_type"),
               persons_tp=len(got_p & gold_p), persons_fp=sorted(got_p - gold_p), persons_fn=sorted(gold_p - got_p),
               links_found=0, links_missing=[], violations=[], over_confident=[])
    for person, typ, value in gold.get("links", []):
        c = _find(ex, person, typ, value)
        if c is None:
            res["links_missing"].append([person, typ, value])
        else:
            res["links_found"] += 1
            if gold.get("max_link_confidence") and c > gold["max_link_confidence"]:
                res["over_confident"].append([person, typ, value, c])
    for person, typ, value in gold.get("not_links", []):
        c = _find(ex, person, typ, value)
        if c is not None:
            res["violations"].append([person, typ, value, c])
    return res


def evaluate(folder):
    docs = []
    for gp in sorted(glob.glob(os.path.join(folder, "*.gold.json"))):
        base = gp[:-len(".gold.json")]
        src = next((p for p in glob.glob(base + ".*") if not p.endswith(".gold.json")), None)
        if src:
            with open(gp, encoding="utf-8") as f:
                docs.append(evaluate_doc(src, json.load(f)))
    tp = sum(d["persons_tp"] for d in docs)
    fp = sum(len(d["persons_fp"]) for d in docs)
    fn = sum(len(d["persons_fn"]) for d in docs)
    lf = sum(d["links_found"] for d in docs)
    lm = sum(len(d["links_missing"]) for d in docs)
    summary = dict(
        person_precision=round(tp / (tp + fp), 3) if tp + fp else 1.0,
        person_recall=round(tp / (tp + fn), 3) if tp + fn else 1.0,
        link_recall=round(lf / (lf + lm), 3) if lf + lm else 1.0,
        violations=sum(len(d["violations"]) for d in docs),
        page_type_errors=sum(1 for d in docs if d["expected_type"] and d["expected_type"] != d["page_type"]))
    return summary, docs
