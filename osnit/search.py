"""Deep search: instant profile from the accumulated DB, then background discovery rounds that keep refining it."""
import json
import re
import time

from .engine import Engine
from .extract import norm_phone_il, org_key
from .profile import build_profile, combine, subject_entity_ids
from .query import parse_query
from .store import similar_person_keys
from .textnorm import clean, name_key
from .urls import registered_domain
from .variants import name_variants

EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[a-z]{2,}$", re.I)
DOMAIN = re.compile(r"^(?:https?://)?(?:www\.)?((?:[a-z0-9-]+\.)+[a-z]{2,})/?$", re.I)
ORG_HINT = re.compile(r"בע\"?מ|עמותת|חברת|אוניברסיטת|מכללת|קרן |ארגון|\b(?:Ltd|Inc|LLC|Corp|GmbH|University|Institute|Foundation|Association|Bank)\b", re.I)


def detect_kind(q: str) -> str:
    q = q.strip()
    if EMAIL.match(q):
        return "email"
    if norm_phone_il(q) or re.fullmatch(r"\+\d[\d\s\-]{7,16}", q):
        return "phone"
    if DOMAIN.match(q):
        return "domain"
    return "org" if ORG_HINT.search(q) else "person"


def prepare(query: str, kind: str):
    """-> (canonical display, entity_type, entity_key, variants)"""
    q = clean(query).strip()
    if kind == "email":
        return q.lower(), "email", q.lower(), [[q.lower()]]
    if kind == "phone":
        n = norm_phone_il(q) or "+" + re.sub(r"\D", "", q)
        return n, "phone", n, [[n]]
    if kind == "domain":
        d = registered_domain(DOMAIN.match(q).group(1))
        return d, "domain", d, [[d]]
    if kind == "org":
        toks = q.replace('"', "").split()
        base = [t for t in toks if t.lower() not in ("בעמ", "ltd", "inc", "llc", "corp")]
        variants = [q.split(), base] if base != q.split() else [q.split()]
        return q, "org", org_key(q), variants
    v = name_variants(q)
    return q, "person", name_key(q), v


class SearchService:
    def __init__(self, engine: Engine):
        self.engine, self.store, self.cfg = engine, engine.store, engine.cfg
        engine.tickers.append(self.tick)

    # ---------------------------------------------------------------- start / backfill
    def search(self, query: str, kind: str = None, duration_h: float = None) -> dict:
        query = query.strip()
        intent = parse_query(query)
        kind = kind or detect_kind(intent.subject)
        canonical, etype, ekey, variants = prepare(intent.subject, kind)
        now = time.time()
        deadline = now + 3600 * (duration_h if duration_h is not None else self.cfg.default_duration_h)
        with self.store.tx() as c:
            r = c.execute("SELECT id FROM subjects WHERE query=?", (query,)).fetchone()
            if r:
                sid = r["id"]
                c.execute("UPDATE subjects SET status='active', deadline=?, rounds=0, last_round_at=?, intent=? WHERE id=?",
                          (deadline, now, json.dumps(intent.to_json(), ensure_ascii=False), sid))
            else:
                sid = c.execute(
                    "INSERT INTO subjects(query,kind,canonical,entity_type,entity_key,variants,created,deadline,last_round_at,intent) "
                    "VALUES(?,?,?,?,?,?,?,?,?,?)",
                    (query, kind, canonical, etype, ekey, json.dumps(variants, ensure_ascii=False), now, deadline,
                     now, json.dumps(intent.to_json(), ensure_ascii=False))).lastrowid
        self._backfill(sid, kind, etype, ekey, variants)
        self.engine.specs(force=True)
        self._round(sid, self._seed_queries(canonical, kind, variants, intent))
        self.store.add_event(sid, "started", {"query": query, "kind": kind})
        return {"subject_id": sid, "profile": self.profile(sid)}

    def _backfill(self, sid, kind, etype, ekey, variants):
        """Attach what the accumulated DB already knows (other spellings, typo variants) to this subject."""
        if kind not in ("person", "org"):
            return
        with self.store.tx() as c:
            keys = {name_key(" ".join(v)) if kind == "person" else org_key(" ".join(v)) for v in variants}
            for k in keys:
                for e in c.execute("SELECT id FROM entities WHERE type=? AND key=?", (etype, k)).fetchall():
                    c.execute("INSERT OR IGNORE INTO subject_entities VALUES(?,?,?,?)", (sid, e["id"], "variant", 1.0))
            if kind == "person":
                toks = {t[:3] for k in keys for t in k.split() if len(t) >= 3}
                for t in toks:
                    for e in c.execute("SELECT id,key FROM entities WHERE type='person' AND key LIKE ? LIMIT 300",
                                       (f"%{t}%",)).fetchall():
                        if any(similar_person_keys(k, e["key"]) for k in keys):
                            c.execute("INSERT OR IGNORE INTO subject_entities VALUES(?,?,?,?)", (sid, e["id"], "fuzzy", 0.8))

    # ---------------------------------------------------------------- query planning
    def _seed_queries(self, canonical, kind, variants, intent=None):
        if kind == "phone":
            from .extract import phone_variants
            qs = [(f'"{v}"', True) for v in phone_variants(canonical)]
            qs.append((f'"{canonical}" filetype:pdf', False))
            return qs
        if kind in ("email", "domain"):
            return [(f'"{canonical}"', True), (f'"{canonical}" filetype:pdf', False)]
        heb = lambda x: bool(re.search(r"[\u05d0-\u05ea]", x))
        straight = variants[::2] if variants and len(variants[0]) > 1 else variants   # skip reversed duplicates
        forms = [" ".join(v) for v in straight]
        names = [f for f in forms if heb(f)][:1] + [f for f in forms if not heb(f)][:2]
        qs = []
        if intent:   # what the user actually asked for goes first
            for n in names:
                he = heb(n)
                for ft in intent.filetypes:
                    qs.append((f'"{n}" filetype:{ft}', False))
                    qs.append((f'"{n}" {ft}', False))
                words = {"phone": "טלפון נייד" if he else "phone mobile", "email": "מייל" if he else "email",
                         "cv": "קורות חיים" if he else "resume CV", "org": "עובד ב" if he else "works at"}
                for w in intent.want:
                    qs.append((f'"{n}" {words[w]}', False))
        for n in names:
            he = heb(n)
            qs.append((f'"{n}"', True))
            qs.append((f'"{n}" ' + ("מייל טלפון" if he else "email phone"), False))
            qs.append((f'"{n}" filetype:pdf', False))
            if kind == "person":
                qs.append((f'"{n}" ' + ('מנכ"ל OR מנהל OR ד"ר OR עו"ד' if he else "CEO OR director OR founder"), False))
        return qs

    def _round(self, sid, queries) -> int:
        new = 0
        for text, plain_ok in queries:
            for name, prov in self.engine.providers.items():
                if getattr(prov, "plain", False) and not plain_ok:
                    continue
                if hasattr(prov, "accepts") and not prov.accepts(text):
                    continue
                q = text.strip('"') if getattr(prov, "plain", False) else text
                new += self.store.add_job(sid, name, q)
        return new

    def expand(self, sid) -> int:
        prof = build_profile(self.store, sid)
        subj = prof["subject"]
        qs = []
        name = subj["canonical"]
        for ident in prof["identities"][:3]:
            if ident["confidence"] < 0.4:
                continue
            for o in ident["orgs"][:2]:
                if o["confidence"] >= 0.5:
                    qs.append((f'"{name}" "{o["value"]}"', False))
            for e in ident["emails"][:2]:
                qs.append((f'"{e["value"]}"', True))
            from .extract import phone_variants
            for p in ident["phones"][:1]:
                for v in phone_variants(p["value"], cap=4):
                    qs.append((f'"{v}"', True))
            for d in ident["domains"][:2]:
                qs.append((f'site:{d["value"]} "{name}"', False))
                qs.append((f'archive:{d["value"]}', False))   # historical captures of the subject's own site
        new = self._round(sid, qs)
        if new:
            self.store.add_event(sid, "expansion", {"queries": [q for q, _ in qs][:8], "jobs": new})
        return new

    def tick(self):
        now = time.time()
        for s in self.store.q("SELECT * FROM subjects WHERE status='active'"):
            if now > s["deadline"]:
                with self.store.tx() as c:
                    c.execute("UPDATE subjects SET status='done' WHERE id=?", (s["id"],))
                self.store.add_event(s["id"], "finished", {"rounds": s["rounds"]})
                continue
            pending = self.store.q1("SELECT COUNT(*) n FROM jobs WHERE subject_id=? AND state IN ('pending','running')",
                                    (s["id"],))["n"]
            backlog = self.store.q1("SELECT COUNT(*) n FROM sources WHERE subject_id=? AND state='pending'", (s["id"],))["n"]
            wait = self.cfg.round_interval * (3 if backlog else 1)
            if pending or s["rounds"] >= self.cfg.max_rounds or now - s["last_round_at"] < wait:
                continue
            self.expand(s["id"])
            with self.store.tx() as c:
                c.execute("UPDATE subjects SET rounds=rounds+1, last_round_at=? WHERE id=?", (now, s["id"]))

    # ---------------------------------------------------------------- reads
    def profile(self, sid, since=None):
        return build_profile(self.store, sid, since)

    def events(self, sid, after=0):
        return [dict(id=e["id"], at=e["at"], type=e["kind"], data=json.loads(e["payload"]))
                for e in self.store.q("SELECT * FROM events WHERE subject_id=? AND id>? ORDER BY id LIMIT 200", (sid, after))]

    def stop(self, sid):
        with self.store.tx() as c:
            c.execute("UPDATE subjects SET status='done' WHERE id=?", (sid,))
        self.engine.specs(force=True)
