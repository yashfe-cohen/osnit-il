"""Deep search: instant profile from the accumulated DB, then background discovery rounds that keep refining it."""
import json
import re
import time

from .engine import Engine
from .extract import norm_phone_il, org_key
from .profile import build_profile, combine, subject_entity_ids
from .query import parse_query
from .linking import _neighbours
from .store import similar_person_keys
from .textnorm import clean, fold, name_key
from .urls import registered_domain
from .variants import name_variants

SOCIAL = ("site:linkedin.com/in OR site:facebook.com OR site:instagram.com OR site:x.com OR site:twitter.com "
          "OR site:github.com OR site:t.me")
INSTITUTIONS = "site:gov.il OR site:ac.il OR site:org.il OR site:muni.il OR site:co.il"
LEGAL_ACADEMIC = ('site:gov.il OR site:ac.il OR site:nevo.co.il OR site:psakdin.co.il OR site:court.gov.il '
                  'OR "תולעת המשפט" OR "פסק דין"')
NEWS = ("site:ynet.co.il OR site:globes.co.il OR site:calcalist.co.il OR site:themarker.com OR site:haaretz.co.il "
        "OR site:maariv.co.il OR site:mako.co.il OR site:walla.co.il OR site:bizportal.co.il OR site:israelhayom.co.il")
# strongest personal identifier first (matches the clustering data rules); a custom u_* id ranks with username
IDENT_RANK = {"national_id": 0, "email": 1, "username": 2, "url": 3, "phone": 4, "domain": 5}
EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[a-z]{2,}$", re.I)
DOMAIN = re.compile(r"^(?:https?://)?(?:www\.)?((?:[a-z0-9-]+\.)+[a-z]{2,})/?$", re.I)
ORG_HINT = re.compile(r"בע\"?מ|עמותת|חברת|אוניברסיטת|מכללת|קרן |ארגון|\b(?:Ltd|Inc|LLC|Corp|GmbH|University|Institute|Foundation|Association|Bank)\b", re.I)


def build_osint_dorks(name_or_query: str, identifiers: dict = None) -> list:
    """
    Targeted OSINT Dorking Generator (v2.0):
    Produces high-precision dork queries combining:
      1. Bilingual name variants (Hebrew + English transliteration)
      2. Cross-identifiers (phone, email, city, org/institution, national_id, username)
      3. Social networks (LinkedIn, Facebook, Instagram, X/Twitter, Telegram, GitHub)
      4. Academic, Legal & Government repositories (gov.il, ac.il, תולעת המשפט / פסקי דין, nevo.co.il)
      5. Exposed document filetypes (filetype:pdf, filetype:xlsx, filetype:docx)
    """
    import itertools
    from .extract import phone_variants
    from .translit import hebrew_to_latin, latin_to_hebrew

    q = clean(name_or_query).strip()
    if not q:
        return []

    heb = lambda x: bool(re.search(r"[\u05d0-\u05ea]", x))
    variants = name_variants(q)
    forms = [" ".join(v) for v in (variants[::2] if variants and len(variants[0]) > 1 else variants)]
    he_names = [f for f in forms if heb(f)]
    en_names = [f for f in forms if not heb(f)]

    # Rule-based fallback transliteration if one script is missing
    toks = [t for t in q.split() if t]
    if not en_names and heb(q) and toks:
        per_tok = [hebrew_to_latin(t, cap=2) or [t] for t in toks]
        for combo in itertools.islice(itertools.product(*per_tok), 4):
            en_names.append(" ".join(combo))
    elif not he_names and not heb(q) and toks:
        per_tok = [latin_to_hebrew(t, cap=2) or [t] for t in toks]
        for combo in itertools.islice(itertools.product(*per_tok), 4):
            he_names.append(" ".join(combo))

    names = he_names[:2] + en_names[:2]
    if not names:
        names = [q]

    dorks = []
    seen = set()

    def _add(dork_str: str):
        if dork_str and dork_str not in seen:
            seen.add(dork_str)
            dorks.append(dork_str)

    identifiers = identifiers or {}
    primary_he = he_names[0] if he_names else names[0]
    primary_en = en_names[0] if en_names else names[0]

    # 1. Cross-identifier combinations
    if identifiers.get("phone"):
        for pv in phone_variants(identifiers["phone"], cap=4):
            _add(f'"{primary_he}" "{pv}"')
            _add(f'"{pv}"')
    if identifiers.get("email"):
        em = identifiers["email"].strip()
        _add(f'"{primary_he}" "{em}"')
        _add(f'"{em}"')
    if identifiers.get("national_id"):
        nid = str(identifiers["national_id"]).strip()
        _add(f'"{primary_he}" "{nid}"')
        _add(f'"{nid}" (filetype:pdf OR filetype:xlsx OR filetype:docx)')
    if identifiers.get("city"):
        city = identifiers["city"].strip()
        _add(f'"{primary_he}" "{city}"')
    if identifiers.get("org"):
        org = identifiers["org"].strip()
        _add(f'"{primary_he}" "{org}"')
        if primary_en != primary_he:
            _add(f'"{primary_en}" "{org}"')
    if identifiers.get("username"):
        un = identifiers["username"].strip()
        _add(f'"{un}" ({SOCIAL})')

    # 2. Bilingual Name + Social, Legal/Academic, Gov, and Document Filetype Dorks
    for n in names:
        he = heb(n)
        _add(f'"{n}"')
        _add(f'"{n}" ({SOCIAL})')
        _add(f'"{n}" ({INSTITUTIONS})')
        if he:
            _add(f'"{n}" ({LEGAL_ACADEMIC})')
        _add(f'"{n}" filetype:pdf')
        _add(f'"{n}" filetype:xlsx')
        _add(f'"{n}" filetype:docx')
        _add(f'"{n}" ' + ('(מייל OR טלפון OR נייד OR "צור קשר")' if he else '(email OR phone OR contact)'))

    return dorks


def detect_kind(q: str) -> str:
    q = q.strip()
    if EMAIL.match(q):
        return "email"
    if norm_phone_il(q) or re.fullmatch(r"\+\d[\d\s\-]{7,16}", q):
        return "phone"
    from .semantic import il_id_ok
    d = re.sub(r"[\s\-]", "", q)
    if d.isdigit() and len(d) in (8, 9) and il_id_ok(d.zfill(9)):
        return "national_id"                      # a valid check digit; a bare 8-9 digit number is never a phone
    if DOMAIN.match(q):
        return "domain"
    return "org" if ORG_HINT.search(q) else "person"


def prepare(query: str, kind: str):
    """-> (canonical display, entity_type, entity_key, variants)"""
    q = clean(query).strip()
    if kind == "email":
        from .semantic import email_key
        return q.lower(), "email", email_key(q), [[q.lower()]]
    if kind == "phone":
        n = norm_phone_il(q) or "+" + re.sub(r"\D", "", q)
        return n, "phone", n, [[n]]
    if kind == "national_id":
        from .semantic import il_id_key
        k = il_id_key(q) or re.sub(r"\D", "", q)
        return k, "national_id", k, [[k]]
    if kind == "domain":
        m = DOMAIN.match(q)                       # a caller may force kind='domain' on a non-strict-domain query
        d = registered_domain(m.group(1) if m else q)
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

    def build_osint_dorks(self, name_or_query: str, identifiers: dict = None) -> list:
        return build_osint_dorks(name_or_query, identifiers=identifiers)

    # ---------------------------------------------------------------- start / backfill
    def search(self, query: str, kind: str = None, duration_h: float = None, wait: float = None) -> dict:
        """wait=None: build the profile inline (CLI/tests); a number: the page path — return it if it is ready
        within `wait` seconds, else {"building": True} and the page polls the investigation."""
        query = query.strip()
        intent = parse_query(query)
        clues = intent.clues or {}
        n_clues = sum(len(v) for v in clues.values())
        if n_clues == 1 and not kind and intent.subject in sum(clues.values(), []):
            clues = {}                            # a bare phone / email / ID: the plain identifier path below
        kind = kind or self._resolve_kind(intent.subject)
        canonical, etype, ekey, variants = prepare(intent.subject, kind)
        if kind == "person":                      # widen search with nicknames/diminutives (never the eval path)
            variants = self._widen_names(intent.subject, variants)
        now = time.time()
        deadline = now + 3600 * (duration_h if duration_h is not None else self.cfg.default_duration_h)
        with self.store.tx() as c:
            r = c.execute("SELECT id FROM subjects WHERE query=?", (query,)).fetchone()
            if r:
                sid = r["id"]
                # a repeated search re-plans from scratch: parsing may have improved, and the DB may have new owners
                c.execute("UPDATE subjects SET status='active', deadline=?, rounds=0, last_round_at=?, intent=?, kind=?, "
                          "canonical=?, entity_type=?, entity_key=?, variants=? WHERE id=?",
                          (deadline, now, json.dumps(intent.to_json(), ensure_ascii=False), kind, canonical, etype, ekey,
                           json.dumps(variants, ensure_ascii=False), sid))
                c.execute("DELETE FROM subject_entities WHERE subject_id=? AND how IN ('variant','fuzzy','owner','clue','exact')",
                          (sid,))
            else:
                sid = c.execute(
                    "INSERT INTO subjects(query,kind,canonical,entity_type,entity_key,variants,created,deadline,last_round_at,intent) "
                    "VALUES(?,?,?,?,?,?,?,?,?,?)",
                    (query, kind, canonical, etype, ekey, json.dumps(variants, ensure_ascii=False), now, deadline,
                     now, json.dumps(intent.to_json(), ensure_ascii=False))).lastrowid
        self._backfill(sid, kind, etype, ekey, variants)
        if clues:
            self._match_clues(sid, intent.subject if kind == "person" else "", clues)
        self.engine.specs(force=True)
        idents = self._db_identifiers(sid)       # the subject's OWN phone/email/username/id already in the DB
        self._round(sid, self._seed_queries(canonical, kind, variants, intent, idents))
        self.store.add_event(sid, "started", {"query": query, "kind": kind})
        self.drop_cached_profile(sid)            # re-planned: its old picture is no longer this investigation
        if wait is None:
            return {"subject_id": sid, "profile": self.profile(sid)}
        return {"subject_id": sid, "profile": self.profile_cached(sid, wait=wait)}

    def _resolve_kind(self, q):
        """detect_kind, with the database settling the one real ambiguity: a 9-digit number starting with 0 is both
        a valid landline (03-1234567) and, when its check digit is right, a valid national ID. Whichever the data
        holds wins; with neither, the shape decides (a landline)."""
        kind = detect_kind(q)
        d = re.sub(r"[\s\-]", "", q)
        if kind == "phone" and d.isdigit() and len(d) == 9 and d.startswith("0"):
            from .semantic import il_id_key, il_id_ok
            if il_id_ok(d):
                as_id = self.store.resolve_entity("national_id", il_id_key(d))
                as_phone = self.store.resolve_entity("phone", norm_phone_il(d) or d)
                if as_id and not as_phone:
                    return "national_id"
        return kind

    def _widen_names(self, name, variants):
        """Add nickname/diminutive spellings to a person's search variants: always the internal gazetteer
        (osnit.nicknames), rule-based Hebrew<->Latin transliteration when out-of-vocabulary, and, when opt-in AI
        name expansion is enabled, the model's forms too (cached, degrading to the gazetteer on any failure).
        This widens discovery queries and the DB backfill only — extraction and the eval matcher use
        variants.name_variants, which this never touches."""
        import itertools
        from . import ai
        from .nicknames import expanded_variants
        from .translit import hebrew_to_latin
        seen = {tuple(fold(t) for t in v) for v in variants}
        out = list(variants)

        def add(toks):
            key = tuple(fold(t) for t in toks if t)
            if key and key not in seen:
                seen.add(key)
                out.append([t for t in toks if t])

        for v in expanded_variants(name):
            add(v)
        # Ensure Hebrew names always have Latin transliteration variants for web dorking
        heb = lambda x: bool(re.search(r"[\u05d0-\u05ea]", x))
        if heb(name) and not any(not heb(" ".join(v)) for v in out):
            toks = [t for t in clean(name).split() if t]
            per_tok = [hebrew_to_latin(t, cap=2) for t in toks]
            if all(per_tok):
                for combo in itertools.islice(itertools.product(*per_tok), 4):
                    add(list(combo))
        try:
            for s in ai.name_expansions(self.cfg, self.store, name):
                toks = [t for t in clean(s).split() if t]
                if len(toks) > 1:
                    add(toks)
                    add(list(reversed(toks)))
        except Exception:
            pass
        return out[:120]

    def _backfill(self, sid, kind, etype, ekey, variants):
        """Attach what the accumulated DB already knows (other spellings, typo variants, identifier owners) to this subject."""
        if kind not in ("person", "org"):
            rid = self.store.resolve_entity(etype, ekey)
            if rid:
                with self.store.tx() as c:
                    c.execute("INSERT OR IGNORE INTO subject_entities VALUES(?,?,?,?)", (sid, rid, "exact", 1.0))
            return
        found_people = []
        if kind == "person":
            try:
                from .identity import find_people
                q_str = " ".join(variants[0]) if variants and variants[0] else ekey
                found_people = find_people(self.store, q_str, limit=60)
            except Exception:
                found_people = []
        with self.store.tx() as c:
            for fp in found_people:
                c.execute("INSERT OR IGNORE INTO subject_entities VALUES(?,?,?,?)", (sid, fp["id"], "variant", 1.0))
            keys = {name_key(" ".join(v)) if kind == "person" else org_key(" ".join(v)) for v in variants if v}
            for k in keys:
                if not k:
                    continue
                for e in c.execute("SELECT id FROM entities WHERE type=? AND (key=? OR (key>=? AND key<?)) LIMIT 200",
                                   (etype, k, k + "|", k + "|\uffff")).fetchall():
                    c.execute("INSERT OR IGNORE INTO subject_entities VALUES(?,?,?,?)", (sid, e["id"], "variant", 1.0))
            if kind == "person":
                # Check if query is a numeric national_id / id_number / phone and attach owning person entities
                digits = re.sub(r"\D", "", ekey)
                if len(digits) >= 5:
                    for id_type in ("national_id", "id_number", "phone"):
                        for ie in c.execute(
                            "SELECT id FROM entities WHERE type=? AND (key=? OR (key >= ? AND key < ?)) LIMIT 20",
                            (id_type, digits, digits, digits + "\uffff")
                        ).fetchall():
                            for rel in c.execute(
                                "SELECT a_id, b_id FROM relations WHERE a_id=? OR b_id=? LIMIT 40",
                                (ie["id"], ie["id"])
                            ).fetchall():
                                pid = rel["b_id"] if rel["a_id"] == ie["id"] else rel["a_id"]
                                pe = c.execute("SELECT id FROM entities WHERE id=? AND type='person'", (pid,)).fetchone()
                                if pe:
                                    c.execute("INSERT OR IGNORE INTO subject_entities VALUES(?,?,?,?)", (sid, pe["id"], "owner", 1.0))
                toks = {t[:3] for k in keys for t in k.split() if len(t) >= 3}
                for t in toks:
                    for e in c.execute(
                        "SELECT id,key FROM entities WHERE type='person' AND key >= ? AND key < ? LIMIT 200",
                        (t, t + "\uffff")
                    ).fetchall():
                        if any(similar_person_keys(k, e["key"]) for k in keys):
                            c.execute("INSERT OR IGNORE INTO subject_entities VALUES(?,?,?,?)", (sid, e["id"], "fuzzy", 0.8))

    def _match_clues(self, sid, name, clues):
        """'דנה לוי 054…' / 'דנה לוי חיפה' / phone + city: find the person matching ALL the given clues and make them
        the investigation's focus (how='clue'). When every clue matches, the other same-name records attached by the
        name backfill are detached, so the investigation shows the person asked about, not everyone with that name.
        When nothing matches every clue, nothing is detached and the partial matches are only recorded as an event."""
        from .multisearch import multi_find
        fields = {"name": name} if name else {}
        clues = {k: list(v) for k, v in clues.items()}
        for ph in list(clues.get("phone", [])):          # a 0-leading 9-digit "phone" the data holds as an ID
            if self._resolve_kind(ph) == "national_id":
                clues["phone"].remove(ph)
                clues.setdefault("national_id", []).append(re.sub(r"\D", "", ph))
        for k in ("phone", "email", "national_id", "address", "city", "birth_year", "age", "father"):
            if clues.get(k):
                fields[k] = clues[k][0]
        if len(fields) < 2 and not (len(fields) == 1 and "name" not in fields):
            return

        def matches(res, flds):
            """The individuals matching every clue (one person may span several identities), else the identities
            whose own records match every clue."""
            inds = [i for i in (res.get("individuals") or []) if i["status"] == "match"]
            flat = [r for r in (res.get("results") or []) if r["match_count"] == len(flds)]
            return inds, flat

        res = multi_find(self.store, fields, limit=20)
        results = res.get("results") or []
        full_ind, full = matches(res, fields)
        # "יהודה הלוי 12": the street may be two words; retry with the name's last word moved to the street
        words = (name or "").split()
        if not (full_ind or full) and fields.get("address") and len(words) >= 3:
            alt = dict(fields, name=" ".join(words[:-1]), address=f"{words[-1]} {fields['address']}")
            res2 = multi_find(self.store, alt, limit=20)
            full_ind2, full2 = matches(res2, alt)
            if full_ind2 or full2:
                fields, res, results, full_ind, full = alt, res2, res2.get("results") or [], full_ind2, full2
                canonical, etype, ekey, variants = prepare(alt["name"], "person")
                with self.store.tx() as c:
                    c.execute("UPDATE subjects SET canonical=?, entity_key=?, variants=? WHERE id=?",
                              (canonical, ekey, json.dumps(variants, ensure_ascii=False), sid))
        score_of = {r["id"]: r["score"] for r in results}
        focus = ([(m, score_of.get(m, 1.0)) for i in full_ind[:10] for m in i["ids"]]
                 or [(r["id"], r["score"]) for r in full[:10]])
        with self.store.tx() as c:
            if focus:
                c.execute("DELETE FROM subject_entities WHERE subject_id=? AND how IN ('variant','fuzzy','owner')", (sid,))
                for eid, sc in focus:
                    c.execute("INSERT OR REPLACE INTO subject_entities VALUES(?,?,?,?)", (sid, eid, "clue", 2.0 + sc))
        focus_ids = {e for e, _ in focus}
        self.store.add_event(sid, "clue_match", {
            "fields": fields,
            "full_matches": ([dict(id=i["ids"][0], name=i["name"], ids=i["ids"]) for i in full_ind[:10]]
                             or [dict(id=r["id"], name=r["name"]) for r in full[:10]]),
            "partial": [dict(id=r["id"], name=r["name"], matched=[m["field"] for m in r["matched"]])
                        for r in results if r["id"] not in focus_ids][:10],
            "individuals": [dict(index=i["index"], ids=i["ids"], name=i["name"], status=i["status"],
                                 distinct=i["distinct"], qualifiers=i["qualifiers"], family=i.get("family", []),
                                 possible=[dict(ids=p["ids"], name=p["name"], probability=p["probability"],
                                                decide=p["decide"]) for p in i["possible"]])
                            for i in (res.get("individuals") or [])[:12]],
            "counts": res.get("counts")})

    def _db_identifiers(self, sid):
        """The ranked, deduped identifiers the DB already attributes to this subject — so the opening web round
        searches the person's own phone/email/id, not just their name. Capped to the 6 strongest."""
        eids = [r["entity_id"] for r in self.store.q(
            "SELECT entity_id FROM subject_entities WHERE subject_id=?", (sid,))]
        if not eids:
            return []
        out, seen = [], set()
        for r in _neighbours(self.store, eids, "anchor"):
            t, v = r["type"], r["display"]
            if (t, v) in seen or not v:
                continue
            seen.add((t, v))
            out.append((t, v))
        out.sort(key=lambda tv: IDENT_RANK.get(tv[0], 2 if tv[0].startswith("u_") else 6))
        return out[:6]

    # ---------------------------------------------------------------- query planning
    def _seed_queries(self, canonical, kind, variants, intent=None, idents=()):
        if kind == "phone":
            from .extract import phone_variants
            qs = [(f'"{v}"', True) for v in phone_variants(canonical)]
            qs.append((f'"{canonical}" filetype:pdf', False))
            return qs
        if kind in ("email", "domain", "national_id"):
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
                         "cv": "קורות חיים" if he else "resume CV", "org": "עובד ב" if he else "works at",
                         "address": "כתובת" if he else "address"}
                for w in intent.want:
                    if w in words:
                        qs.append((f'"{n}" {words[w]}', False))
        if idents and names:       # the subject's OWN identifiers from the DB, most targeted first
            from .extract import phone_variants
            n0 = names[0]
            for t, v in idents:
                if t == "phone":
                    for pv in phone_variants(v, cap=6):
                        qs.append((f'"{n0}" "{pv}"', False))
                        qs.append((f'"{pv}"', True))
                else:
                    qs.append((f'"{n0}" "{v}"', False))
                    qs.append((f'"{v}"', True))
        for n in names:
            he = heb(n)
            qs.append((f'"{n}"', True))
            if kind == "person":   # where people actually appear: profiles, institutions, legal/academic, news, documents
                qs.append((f'"{n}" ({SOCIAL})', False))
                qs.append((f'"{n}" ' + ('(מייל OR טלפון OR נייד OR "צור קשר")' if he else '(email OR phone OR contact)'), False))
                qs.append((f'"{n}" ({INSTITUTIONS})', False))
                if he:
                    qs.append((f'"{n}" ({LEGAL_ACADEMIC})', False))
                qs.append((f'"{n}" ({NEWS})', False))
                qs.append((f'"{n}" filetype:pdf', False))
                qs.append((f'"{n}" filetype:xlsx', False))
                qs.append((f'"{n}" filetype:docx', False))
                qs.append((f'"{n}" ' + ('("קורות חיים" OR פרופיל OR אודות OR צוות)' if he else '(resume OR CV OR profile OR team)'), False))
                qs.append((f'"{n}" ' + ('(מנכ"ל OR מנהל OR ד"ר OR עו"ד OR מייסד)' if he else "(CEO OR director OR founder)"), False))
            else:
                qs.append((f'"{n}" ' + ("מייל טלפון" if he else "email phone"), False))
                qs.append((f'"{n}" filetype:pdf', False))
                qs.append((f'"{n}" filetype:xlsx', False))
                qs.append((f'"{n}" filetype:docx', False))
                qs.append((f'"{n}" ({NEWS})', False))
        out, by_text = [], {}                      # order-preserving dedup (a DB identifier may echo an intent query)
        for text, plain_ok in qs:
            if text in by_text:
                out[by_text[text]] = (text, out[by_text[text]][1] or plain_ok)
            else:
                by_text[text] = len(out)
                out.append((text, plain_ok))
        return out

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
            for u in ident.get("usernames", [])[:2]:      # the same handle on other platforms
                qs.append((f'"{u["value"]}"', True))
                qs.append((f'"{u["value"]}" ({SOCIAL})', False))
            for x in ident.get("identifiers", [])[:2]:
                qs.append((f'"{x["value"]}"', True))
            for a in ident.get("addresses", [])[:1]:
                qs.append((f'"{name}" "{a["value"].split(",")[0]}"', False))
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

    # ---------------------------------------------------------------- cached investigation pages
    # On a database of millions an investigation's picture can take minutes to assemble. The page is served from
    # a saved copy (subject_cache) that is rebuilt in the background when it is older than PROFILE_FRESH seconds,
    # and a first open never holds the request: it answers "building" and the page polls until the copy exists.
    PROFILE_FRESH = 30.0

    def _cache_get(self, sid):
        return self.store.q1("SELECT built, payload FROM subject_cache WHERE subject_id=?", (sid,))

    def _cache_put(self, sid, prof):
        payload = json.dumps(prof, ensure_ascii=False, default=str)
        with self.store.tx(silent=True) as c:          # a cache, not user data: must not bump the data-version
            c.execute("INSERT INTO subject_cache(subject_id, built, payload) VALUES(?,?,?) "
                      "ON CONFLICT(subject_id) DO UPDATE SET built=excluded.built, payload=excluded.payload",
                      (sid, time.time(), payload))

    def drop_cached_profile(self, sid=None):
        with self.store.tx(silent=True) as c:
            if sid is None:
                c.execute("DELETE FROM subject_cache")
            else:
                c.execute("DELETE FROM subject_cache WHERE subject_id=?", (sid,))

    def _build_in_background(self, sid):
        import threading
        lock = self.__dict__.setdefault("_build_lock", threading.Lock())
        with lock:
            building = self.__dict__.setdefault("_building", {})
            t = building.get(sid)
            if t and t.is_alive():
                return t

            def run():
                try:
                    prof = build_profile(self.store, sid)
                    if prof:
                        self._cache_put(sid, prof)
                except Exception:
                    pass
                finally:
                    with lock:
                        building.pop(sid, None)
            t = threading.Thread(target=run, daemon=True, name=f"profile-{sid}")
            building[sid] = t
            t.start()
            return t

    def profile_cached(self, sid, wait=3.0):
        """The investigation's picture for the page: the saved copy at once (refreshed in the background when
        stale), else a fresh build if it finishes within `wait` seconds, else None (still building)."""
        row = self._cache_get(sid)
        if row:
            age = time.time() - (row["built"] or 0)
            if age > self.PROFILE_FRESH:
                self._build_in_background(sid)
            prof = json.loads(row["payload"])
            prof["cached"] = dict(built=row["built"], age=round(age, 1), refreshing=age > self.PROFILE_FRESH)
            return prof
        if not self.store.q1("SELECT 1 FROM subjects WHERE id=?", (sid,)):
            return None
        self._build_in_background(sid).join(max(0.0, wait))
        row = self._cache_get(sid)
        if row:
            prof = json.loads(row["payload"])
            prof["cached"] = dict(built=row["built"], age=0.0, refreshing=False)
            return prof
        return {"building": True, "subject_id": sid}

    def events(self, sid, after=0):
        return [dict(id=e["id"], at=e["at"], type=e["kind"], data=json.loads(e["payload"]))
                for e in self.store.q("SELECT * FROM events WHERE subject_id=? AND id>? ORDER BY id LIMIT 200", (sid, after))]

    def stop(self, sid):
        with self.store.tx() as c:
            c.execute("UPDATE subjects SET status='done' WHERE id=?", (sid,))
        self.engine.specs(force=True)
