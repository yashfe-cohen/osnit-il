"""Plain-text tree rendering of a profile (terminal / logs)."""
import time


def _ts(t):
    return time.strftime("%Y-%m-%d", time.localtime(t)) if t else "?"


def _items(label, items, lines, prefix, last=False):
    if not items:
        return
    lines.append(f"{prefix}{'└' if last else '├'}── {label}")
    pad = prefix + ("    " if last else "│   ")
    for it in items:
        ev = it["evidence"][0] if it.get("evidence") else {}
        alias = f" (גם: {' | '.join(it['aliases'])})" if it.get("aliases") else ""
        alias += {"gone": "  ✗ נעלם מהמקור", "historical": "  ⧗ היסטורי"}.get(it.get("status"), "")
        lines.append(f"{pad}• {it['value']}{alias}  [{int(it['confidence'] * 100)}%, {it.get('sources', 1)} src, "
                     f"{_ts(it['first_seen'])}→{_ts(it['last_seen'])}]")
        if ev.get("url"):
            lines.append(f"{pad}    ↳ {ev['url']}")


def render_tree(p: dict) -> str:
    s = p["subject"]
    out = [f"{s['canonical']}   (נושא #{s['id']}, {s['kind']}, סטטוס: {s['status']}, סבבים: {s['rounds']})", "│"]
    idents = p["identities"] + ([dict(p["unattributed"], label="לא משויך", id="?", unattr=True)] if p["unattributed"] else [])
    if not idents:
        out.append("└── (אין עדיין ממצאים — הסריקה ממשיכה ברקע)")
    for n, i in enumerate(idents):
        last = n == len(idents) - 1
        head = f"זהות/מופע {i['id']}: {i.get('label') or '—'}  [ביטחון {int(i['confidence'] * 100)}%, {i['source_count']} מקורות]"
        out.append(f"{'└' if last else '├'}── {head}")
        pre = "    " if last else "│   "
        if len(i["names"]) > 1:
            out.append(f"{pre}├── שמות חלופיים: " + " | ".join(i["names"]))
        facets = [("ארגונים", i["orgs"]), ("תפקידים", i["roles"]), ("מיילים ציבוריים", i["emails"]),
                  ("טלפונים ציבוריים", i["phones"]), ("דומיינים", i["domains"]), ("קישורים", i["links"] + i["documents_linked"])]
        facets = [f for f in facets if f[1]]
        for k, (lab, items) in enumerate(facets):
            _items(lab, items, out, pre, last=(k == len(facets) - 1 and not i["documents"] and not i["sources"]))
        if i["documents"]:
            out.append(f"{pre}├── מסמכים קשורים")
            for d in i["documents"]:
                out.append(f"{pre}│   • [{d['kind']}] {d['url']}")
        out.append(f"{pre}└── מקורות: " + ", ".join(sorted({x['url'] for x in i["sources"]})[:6]))
    if p["related"]:
        out += ["│", "├── קשרים לישויות אחרות"] + [
            f"│   • {r['value']} [{int(r['confidence'] * 100)}%] — {r['evidence'][0]['url']}" for r in p["related"][:10]]
    if p["similar_names"]:
        out += ["│", "├── שמות דומים (לא אוחדו — לבדיקה ידנית)"] + [
            f"│   • {r['value']} (דמיון {r['similarity']}, {r['sources']} מקורות)" for r in p["similar_names"]]
    if p["timeline"]:
        out += ["│", "└── היסטוריה"] + [
            f"    {_ts(t['at'])}  {'נעלם' if t['what'] == 'gone' else 'הופיע'}  {t['type']}: {t['value']}"
            for t in p["timeline"][-12:]]
    return "\n".join(out)
