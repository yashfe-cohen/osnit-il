"""Unified Deep Web OSINT & Recursive Recon Engine (OSNIT-IL v2.0).

Implements the 6-Layer Deep OSINT & Recursive Pivot architecture:
  - Layer 1: Target Permutation & Bidirectional Transliteration (SearchTargetProfile)
  - Layer 2: Email, Breach & Infostealer Intelligence (Holehe, HudsonRock Cavalier, XposedOrNot, Gravatar/Libravatar, GitHub API & Commit Mining)
  - Layer 3: Username & Social Footprint Hunter (Telegram, GitHub, Reddit, TikTok, Instagram, X, Linktree, Steam, Medium, Pinterest, GitLab, Keybase + OpenGraph metadata & 200-OK False-Positive filter)
  - Layer 4: Phone & Messaging Recon (phonenumbers carrier/region/type analysis, ignorant check, WhatsApp & phone permutation web search)
  - Layer 5: Unified Multi-Engine Search & Automated Israeli Registries Dorker (psakdin, takdin, nevo, ruling, gov.il, guidestar, LinkedIn, leaked document filetypes + Relevance Scoring & NER extraction)
  - Layer 6: Recursive Pivot Loop (Online <-> Offline DB cross-matching in osnit.db, automatic entity linking with pivot provenance, and Hop-2 enrichment capped at max_depth=2)
"""
from __future__ import annotations

import asyncio
import hashlib
import html
import json
import re
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Callable

# Graceful optional imports (Rule 2: never break if an optional library is missing)
try:
    import httpx
    HAS_HTTPX = True
except ImportError:
    httpx = None
    HAS_HTTPX = False

try:
    import aiohttp
    HAS_AIOHTTP = True
except ImportError:
    aiohttp = None
    HAS_AIOHTTP = False

try:
    import phonenumbers
    from phonenumbers import carrier as pn_carrier, geocoder as pn_geocoder, PhoneNumberType
    HAS_PHONENUMBERS = True
except ImportError:
    phonenumbers = None
    pn_carrier = None
    pn_geocoder = None
    PhoneNumberType = None
    HAS_PHONENUMBERS = False

try:
    import holehe.core as holehe_core
    HAS_HOLEHE = True
except ImportError:
    holehe_core = None
    HAS_HOLEHE = False

try:
    import ignorant.core as ignorant_core
    HAS_IGNORANT = True
except ImportError:
    ignorant_core = None
    HAS_IGNORANT = False

from .textnorm import clean, fold, is_hebrew, name_key, tokens
from .translit import hebrew_to_latin, latin_to_hebrew
from .variants import _FOLDED, _REVERSE, latin_variants, name_variants, token_forms
from .name_validator import is_valid_person_name

GENERIC_EMAIL_PREFIXES = frozenset({
    "info", "admin", "office", "contact", "support", "sales", "billing",
    "service", "services", "help", "mail", "email", "noreply", "no-reply",
    "user", "users", "hr", "jobs", "careers", "security", "team", "hello",
    "general", "enquiries", "inquiries", "marketing", "press", "media",
    "finance", "accounting", "legal", "privacy", "abuse", "webmaster",
    "postmaster", "root", "system", "test", "demo", "reception", "desk",
})

ISRAELI_MOBILE_CARRIERS = {
    "050": "Pelephone (פלאפון)",
    "051": "We4G / 018 Xfone",
    "052": "Cellcom (סלקום)",
    "053": "Hot Mobile (הוט מובייל)",
    "054": "Partner / Orange (פרטנר)",
    "055": "Virtual Operator (רמי לוי / 019 / סלקום)",
    "056": "Wataniya / Ooredoo",
    "058": "Golan Telecom (גולן טלקום)",
    "059": "Jawwal",
}

ISRAELI_LANDLINE_REGIONS = {
    "02": "ירושלים והסביבה (Jerusalem)",
    "03": "תל אביב והמרכז (Tel Aviv & Center)",
    "04": "חיפה והצפון (Haifa & North)",
    "08": "השפלה והדרום (South & Shfela)",
    "09": "השרון (Sharon)",
    "072": "VoIP ארצי (012 Smile / Partner)",
    "073": "VoIP ארצי (Cellcom / Bezeq)",
    "074": "VoIP ארצי (Orange / Partner)",
    "076": "VoIP ארצי (Bezeq)",
    "077": "VoIP ארצי (Hot Telecom)",
}

DEFAULT_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/125.0.0.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8",
    "Accept-Language": "he-IL,he;q=0.9,en-US;q=0.8,en;q=0.7",
}


# ============================================================================
# Layer 1: Target Permutation & Bidirectional Transliteration
# ============================================================================

def generate_phone_permutations(phone_str: str) -> list[str]:
    """Generate all standard local and international permutations for an Israeli phone number.

    Example for '0547283832':
      - '0547283832'
      - '054-7283832'
      - '054-728-3832'
      - '054 728 3832'
      - '+972547283832'
      - '+972-54-7283832'
      - '+972-54-728-3832'
      - '972547283832'
    """
    raw = re.sub(r"[^\d+]", "", str(phone_str or "").strip())
    if not raw:
        return []
    digits = re.sub(r"\D", "", raw)
    if digits.startswith("972") and len(digits) in (11, 12):
        local = "0" + digits[3:]
    elif digits.startswith("0") and len(digits) in (9, 10):
        local = digits
    elif len(digits) == 9 and digits[0] == "5":
        local = "0" + digits
    else:
        return [phone_str.strip()] if phone_str.strip() else []

    body_no_zero = local[1:]
    intl_digits = "972" + body_no_zero
    perms = []
    if len(local) == 10:
        p3 = local[:3]
        p2 = local[1:3]
        mid3 = local[3:6]
        last4 = local[6:]
        rest7 = local[3:]
        perms.extend([
            local,
            f"{p3}-{rest7}",
            f"{p3}-{mid3}-{last4}",
            f"{p3} {mid3} {last4}",
            f"+{intl_digits}",
            f"+972-{p2}-{rest7}",
            f"+972-{p2}-{mid3}-{last4}",
            f"+972 {p2} {mid3} {last4}",
            intl_digits,
        ])
    elif len(local) == 9:
        p2 = local[:2]
        p1 = local[1:2]
        mid3 = local[2:5]
        last4 = local[5:]
        rest7 = local[2:]
        perms.extend([
            local,
            f"{p2}-{rest7}",
            f"{p2}-{mid3}-{last4}",
            f"{p2} {mid3} {last4}",
            f"+{intl_digits}",
            f"+972-{p1}-{rest7}",
            f"+972-{p1}-{mid3}-{last4}",
            intl_digits,
        ])
    seen = set()
    out = []
    for p in perms:
        if p not in seen:
            seen.add(p)
            out.append(p)
    return out


def harvest_usernames_from_emails(emails: list[str], english_names: list[str] | None = None) -> list[str]:
    """Extract and permute personal usernames from email addresses and English names,
    filtering out generic role prefixes (info, admin, office, etc.)."""
    candidates: list[str] = []
    seen: set[str] = set()

    def _add(u: str):
        u_clean = u.strip().lower()
        if not u_clean or len(u_clean) < 3 or len(u_clean) > 36:
            return
        if u_clean in GENERIC_EMAIL_PREFIXES:
            return
        # Strip pure numbers
        if u_clean.isdigit():
            return
        if u_clean not in seen:
            seen.add(u_clean)
            candidates.append(u_clean)

    for email in emails or []:
        if "@" not in str(email):
            continue
        local = str(email).split("@", 1)[0].strip().lower()
        # Remove +tag
        local = local.split("+", 1)[0]
        if not local or local in GENERIC_EMAIL_PREFIXES:
            continue
        base_alpha = re.sub(r"[^a-z]", "", local)
        if base_alpha in GENERIC_EMAIL_PREFIXES:
            continue
        # 1. Exact local part (if valid username chars)
        if re.match(r"^[a-z0-9._-]+$", local):
            _add(local)
        # 2. Without dots/hyphens/underscores
        compact = re.sub(r"[._-]+", "", local)
        _add(compact)
        # 3. With underscore instead of dot/hyphen
        if "." in local or "-" in local:
            _add(re.sub(r"[.-]+", "_", local))
        # 4. Stripped trailing digits (e.g. matanshi88 -> matanshi)
        no_digits = re.sub(r"\d+$", "", compact)
        if len(no_digits) >= 4:
            _add(no_digits)
        no_digits_local = re.sub(r"\d+$", "", local).rstrip("._-")
        if len(no_digits_local) >= 4:
            _add(no_digits_local)

    for en_name in (english_names or [])[:4]:
        toks = [re.sub(r"[^a-z]", "", t.lower()) for t in en_name.split() if t.strip()]
        toks = [t for t in toks if len(t) >= 2]
        if len(toks) >= 2:
            first, last = toks[0], toks[-1]
            _add(f"{first}{last}")
            _add(f"{first}.{last}")
            _add(f"{first}_{last}")
            _add(f"{first}{last[:3]}")
            _add(f"{first[0]}{last}")

    return candidates[:20]


def transliterate_name_bidirectional(
    names: list[str],
    hint_emails: list[str] | None = None,
    hint_usernames: list[str] | None = None,
) -> tuple[list[str], list[str]]:
    """Produce (hebrew_names, english_names) with smart email/username prefix alignment.

    For example:
      names=['מתן שנער'], hint_emails=['matanshi@gmail.com']
      -> hebrew_names=['מתן שנער']
      -> english_names=['Matan Shinar', 'Matan Shenar', 'Matan Shinaar', ...]
    """
    hebrew_out: list[str] = []
    english_out: list[str] = []
    seen_he: set[str] = set()
    seen_en: set[str] = set()

    def _add_he(s: str):
        c = clean(s)
        k = fold(c)
        if c and is_hebrew(c) and k not in seen_he:
            seen_he.add(k)
            hebrew_out.append(c)

    def _add_en(s: str):
        c = " ".join(w.capitalize() for w in clean(s).split() if w)
        k = fold(c)
        if c and not is_hebrew(c) and re.search(r"[a-zA-Z]", c) and k not in seen_en:
            seen_en.add(k)
            english_out.append(c)

    # Collect Latin hints from emails and usernames
    latin_hints: list[str] = []
    for em in hint_emails or []:
        if "@" in str(em):
            lp = str(em).split("@", 1)[0].lower()
            lp_clean = re.sub(r"\d+$", "", lp)
            latin_hints.append(lp_clean)
            # If email has explicit first.last structure (e.g., matan.shinar@...), extract directly
            parts = [p for p in re.split(r"[._-]+", lp_clean) if len(p) >= 2 and p.isalpha()]
            if len(parts) == 2 and parts[0] not in GENERIC_EMAIL_PREFIXES:
                _add_en(f"{parts[0]} {parts[1]}")
    for u in hint_usernames or []:
        u_clean = re.sub(r"\d+$", "", str(u).lower())
        if len(u_clean) >= 3:
            latin_hints.append(u_clean)

    for raw_name in names or []:
        raw_name = clean(raw_name)
        if not raw_name:
            continue
        toks = [t for t in raw_name.split() if t]
        if not toks:
            continue
        if is_hebrew(raw_name):
            _add_he(raw_name)
            # Generate English candidates per token
            per_tok_en: list[list[str]] = []
            for t in toks:
                forms = [f for f in token_forms(t) if not is_hebrew(f) and re.search(r"[a-zA-Z]", f)]
                if not forms:
                    forms = hebrew_to_latin(t, cap=6)
                per_tok_en.append(forms[:8] if forms else [t])

            import itertools
            raw_combos: list[str] = []
            for combo in itertools.islice(itertools.product(*per_tok_en), 80):
                if all(not is_hebrew(x) for x in combo):
                    raw_combos.append(" ".join(w.capitalize() for w in combo))

            # Score combos against email/username hints so matching prefixes come first!
            def _hint_score(cand: str) -> int:
                c_parts = [p.lower() for p in cand.split()]
                c_compact = "".join(c_parts)
                score = 0
                for h_str in latin_hints:
                    h_compact = re.sub(r"[^a-z]", "", h_str)
                    if not h_compact:
                        continue
                    if c_compact.startswith(h_compact) or h_compact.startswith(c_compact):
                        score += 100
                    elif len(c_parts) >= 2 and h_compact.startswith(c_parts[0]):
                        rem = h_compact[len(c_parts[0]):]
                        if rem and c_parts[1].startswith(rem):
                            score += 90 + len(rem)
                        elif rem and c_parts[-1].startswith(rem[:2]):
                            score += 50
                return score

            raw_combos.sort(key=_hint_score, reverse=True)
            for rc in raw_combos[:15]:
                _add_en(rc)
        else:
            _add_en(raw_name)
            # Generate Hebrew candidates per token
            per_tok_he: list[list[str]] = []
            for t in toks:
                forms = [f for f in token_forms(t) if is_hebrew(f)]
                if not forms:
                    forms = latin_to_hebrew(t, cap=6)
                per_tok_he.append(forms[:6] if forms else [])
            if all(per_tok_he):
                import itertools
                for combo in itertools.islice(itertools.product(*per_tok_he), 40):
                    _add_he(" ".join(combo))

    return hebrew_out, english_out


@dataclass
class SearchTargetProfile:
    """Layer 1: Unified target profile holding all expanded permutations for Layers 2-6."""
    entity_id: int | None = None
    primary_name: str = ""
    hebrew_names: list[str] = field(default_factory=list)
    english_names: list[str] = field(default_factory=list)
    emails: list[str] = field(default_factory=list)
    usernames: list[str] = field(default_factory=list)
    phones: list[str] = field(default_factory=list)
    phone_permutations: dict[str, list[str]] = field(default_factory=dict)
    national_ids: list[str] = field(default_factory=list)
    cities: list[str] = field(default_factory=list)
    organizations: list[str] = field(default_factory=list)
    known_urls: list[str] = field(default_factory=list)

    @classmethod
    def from_entity(cls, store, entity_id: int, extra_query: str = "") -> "SearchTargetProfile":
        """Build a comprehensive SearchTargetProfile from an entity (and its dossier cluster) in osnit.db."""
        from .identity import dossier
        ent = store.q1("SELECT * FROM entities WHERE id=?", (int(entity_id),))
        if not ent:
            return cls.from_raw(name=extra_query or f"Entity #{entity_id}", entity_id=entity_id)

        dos = dossier(store, entity_id=int(entity_id)) or {}
        names_seed: list[str] = []
        emails: list[str] = []
        phones: list[str] = []
        usernames: list[str] = []
        national_ids: list[str] = []
        cities: list[str] = []
        orgs: list[str] = []
        urls: list[str] = []

        primary = ent["display"] or ent["key"] or ""
        if ent["type"] == "person" and primary:
            names_seed.append(primary)
        elif ent["type"] == "email":
            emails.append(primary)
        elif ent["type"] == "phone":
            phones.append(primary)
        elif ent["type"] in ("username", "handle"):
            usernames.append(primary.lstrip("@"))

        for sp in dos.get("spellings", []):
            val = sp.get("name") or ""
            if val and val not in names_seed:
                names_seed.append(val)

        # Direct aliases from DB
        for al in store.q("SELECT alias FROM aliases WHERE entity_id=?", (int(entity_id),)):
            if al["alias"] and al["alias"] not in names_seed:
                names_seed.append(al["alias"])

        # Linked identifiers in dossier
        idents = dos.get("identifiers", {})
        for em in idents.get("email", []):
            v = (em.get("value") or em.get("key") or "").strip().lower()
            if v and "@" in v and v not in emails:
                emails.append(v)
        for ph in idents.get("phone", []):
            v = (ph.get("value") or ph.get("key") or "").strip()
            if v and v not in phones:
                phones.append(v)
        for un in idents.get("username", []) + idents.get("handle", []):
            v = (un.get("value") or un.get("key") or "").strip().lstrip("@")
            if v and v not in usernames:
                usernames.append(v)
        for nid in idents.get("national_id", []):
            v = (nid.get("value") or nid.get("key") or "").strip()
            if v and v not in national_ids:
                national_ids.append(v)
        for loc in idents.get("location", []):
            v = (loc.get("value") or "").strip()
            if v and v not in cities:
                cities.append(v)
        for org in idents.get("org", []):
            v = (org.get("value") or "").strip()
            if v and v not in orgs:
                orgs.append(v)
        for prof in idents.get("profile", []):
            v = (prof.get("value") or prof.get("key") or "").strip()
            if v and v not in urls:
                urls.append(v)

        # Also check attributes table directly
        for attr in store.q("SELECT name, value, kind FROM attributes WHERE entity_id=?", (int(entity_id),)):
            k = (attr["kind"] or attr["name"] or "").lower()
            val = (attr["value"] or "").strip()
            if not val:
                continue
            if "email" in k and "@" in val and val.lower() not in emails:
                emails.append(val.lower())
            elif "phone" in k and val not in phones:
                phones.append(val)
            elif ("city" in k or "address" in k or "יישוב" in k or "עיר" in k) and val not in cities:
                cities.append(val)
            elif ("org" in k or "company" in k or "חברה" in k) and val not in orgs:
                orgs.append(val)
            elif ("id" in k or "ת.ז" in k) and re.fullmatch(r"\d{7,9}", re.sub(r"\D", "", val)):
                clean_id = re.sub(r"\D", "", val).zfill(9)
                if clean_id not in national_ids:
                    national_ids.append(clean_id)

        # Also check sensitive table for national_id
        for sens in store.sensitive_for([int(entity_id)]):
            if sens.get("kind") == "national_id":
                v = str(sens.get("value") or "").strip()
                if v and v not in national_ids:
                    national_ids.append(v)

        return cls.from_raw(
            entity_id=int(entity_id),
            name=primary,
            names=names_seed,
            emails=emails,
            phones=phones,
            usernames=usernames,
            national_ids=national_ids,
            cities=cities,
            organizations=orgs,
            known_urls=urls,
        )

    @classmethod
    def from_raw(
        cls,
        name: str = "",
        entity_id: int | None = None,
        names: list[str] | None = None,
        emails: list[str] | None = None,
        phones: list[str] | None = None,
        usernames: list[str] | None = None,
        national_ids: list[str] | None = None,
        cities: list[str] | None = None,
        organizations: list[str] | None = None,
        known_urls: list[str] | None = None,
    ) -> "SearchTargetProfile":
        all_names = list(names or [])
        if name and name not in all_names:
            all_names.insert(0, name)
        clean_emails = []
        for e in emails or []:
            e_low = str(e).strip().lower()
            if "@" in e_low and e_low not in clean_emails:
                clean_emails.append(e_low)

        he_names, en_names = transliterate_name_bidirectional(
            all_names,
            hint_emails=clean_emails,
            hint_usernames=usernames,
        )
        harvested_users = list(usernames or [])
        for u in harvest_usernames_from_emails(clean_emails, en_names):
            if u not in harvested_users:
                harvested_users.append(u)

        clean_phones = []
        phone_perms: dict[str, list[str]] = {}
        for p in phones or []:
            p_str = str(p).strip()
            if not p_str:
                continue
            perms = generate_phone_permutations(p_str)
            canonical_p = perms[0] if perms else p_str
            if canonical_p not in clean_phones:
                clean_phones.append(canonical_p)
            phone_perms[canonical_p] = perms

        return cls(
            entity_id=entity_id,
            primary_name=name or (he_names[0] if he_names else (en_names[0] if en_names else "")),
            hebrew_names=he_names,
            english_names=en_names,
            emails=clean_emails,
            usernames=harvested_users,
            phones=clean_phones,
            phone_permutations=phone_perms,
            national_ids=list(national_ids or []),
            cities=list(cities or []),
            organizations=list(organizations or []),
            known_urls=list(known_urls or []),
        )

    @classmethod
    def from_query(cls, query: str, entity_id: int | None = None) -> "SearchTargetProfile":
        """Build a SearchTargetProfile from a free-text query string (which may contain a name, email, or phone)."""
        q = (query or "").strip()
        emails = re.findall(r"[\w.+-]+@[\w-]+\.[\w.-]+", q)
        phones = re.findall(r"(?:\+?972[-\s]?|0)(?:5\d|[23489]|7\d)[-\s]?\d{3}[-\s]?\d{4}", q)
        rem = q
        for em in emails:
            rem = rem.replace(em, " ")
        for ph in phones:
            rem = rem.replace(ph, " ")
        rem = re.sub(r"\s+", " ", rem).strip(" ,;-|")
        return cls.from_raw(
            name=rem or q,
            entity_id=entity_id,
            emails=emails,
            phones=phones,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "entity_id": self.entity_id,
            "primary_name": self.primary_name,
            "hebrew_names": self.hebrew_names,
            "english_names": self.english_names,
            "emails": self.emails,
            "usernames": self.usernames,
            "phones": self.phones,
            "phone_permutations": self.phone_permutations,
            "national_ids": self.national_ids,
            "cities": self.cities,
            "organizations": self.organizations,
            "known_urls": self.known_urls,
        }


# ============================================================================
# Fault-Isolated Async HTTP & Tool Execution Helpers
# ============================================================================

async def _async_http_get(
    url: str,
    headers: dict[str, str] | None = None,
    timeout: float = 8.0,
    http_fetcher: Callable | None = None,
) -> tuple[int, str, dict[str, str]]:
    """Fault-isolated async HTTP GET returning (status_code, body_text, response_headers).
    Supports an optional injected `http_fetcher(url, headers)` for offline/unit tests."""
    merged_headers = {**DEFAULT_HEADERS, **(headers or {})}
    if http_fetcher is not None:
        res = http_fetcher(url, merged_headers)
        if asyncio.iscoroutine(res):
            res = await res
        if isinstance(res, tuple):
            if len(res) == 3:
                return int(res[0]), str(res[1]), dict(res[2] or {})
            if len(res) == 2:
                return int(res[0]), str(res[1]), {}
        return 200, str(res or ""), {}

    if HAS_HTTPX:
        try:
            async with httpx.AsyncClient(
                timeout=timeout,
                follow_redirects=True,
                headers=merged_headers,
                verify=False,
            ) as client:
                resp = await client.get(url)
                return resp.status_code, resp.text, dict(resp.headers)
        except Exception:
            return 0, "", {}

    # Fallback to stdlib urllib in a thread
    def _sync_get():
        req = urllib.request.Request(url, headers=merged_headers)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                raw = r.read(512_000)
                return r.status, raw.decode("utf-8", "replace"), dict(r.headers)
        except urllib.error.HTTPError as e:
            return e.code, "", {}
        except Exception:
            return 0, "", {}

    return await asyncio.to_thread(_sync_get)


async def _safe_task(coro, tool_name: str, timeout: float = 12.0, log_fn: Callable[[str], None] | None = None):
    """Execute a single OSINT tool coroutine with strict timeout and fault isolation.
    Never raises an exception to the caller."""
    try:
        return await asyncio.wait_for(coro, timeout=timeout)
    except asyncio.TimeoutError:
        if log_fn:
            log_fn(f"⚠️ [{tool_name}] Timeout ({timeout:.0f}s) – ממשיך לשאר הכלים")
        return []
    except Exception as exc:
        if log_fn:
            log_fn(f"⚠️ [{tool_name}] שגיאה מבודדת ({type(exc).__name__}) – ממשיך לשאר הכלים")
        return []


# ============================================================================
# Layer 2: Email, Breach & Infostealer Intelligence
# ============================================================================

async def check_gravatar(
    email: str,
    store=None,
    http_fetcher: Callable | None = None,
) -> list[dict[str, Any]]:
    """Query Gravatar & Libravatar JSON/avatar endpoints using the MD5 hash of the email."""
    clean_em = email.strip().lower()
    if not clean_em or "@" not in clean_em:
        return []
    if store is not None:
        cached = store.osint_cache_get(clean_em, "gravatar")
        if cached is not None:
            return cached

    md5_hash = hashlib.md5(clean_em.encode("utf-8")).hexdigest()
    json_url = f"https://en.gravatar.com/{md5_hash}.json"
    avatar_url = f"https://www.gravatar.com/avatar/{md5_hash}?d=404&s=256"

    findings: list[dict[str, Any]] = []
    status, body, _ = await _async_http_get(json_url, timeout=7.0, http_fetcher=http_fetcher)
    if status == 200 and body:
        try:
            data = json.loads(body)
            entry = (data.get("entry") or [{}])[0]
            display_name = entry.get("displayName") or entry.get("name", {}).get("formatted") or ""
            pref_user = entry.get("preferredUsername") or ""
            location = entry.get("currentLocation") or ""
            bio = entry.get("aboutMe") or ""
            thumb = entry.get("thumbnailUrl") or f"https://www.gravatar.com/avatar/{md5_hash}?s=256"
            accounts = [
                {
                    "domain": a.get("domain") or a.get("shortname") or "",
                    "url": a.get("url") or "",
                    "username": a.get("username") or a.get("display") or "",
                }
                for a in (entry.get("accounts") or [])
                if isinstance(a, dict)
            ]
            urls = [u.get("value") for u in (entry.get("urls") or []) if isinstance(u, dict) and u.get("value")]
            summary_parts = [f"אימייל: {clean_em}"]
            if display_name:
                summary_parts.append(f"שם: {display_name}")
            if pref_user:
                summary_parts.append(f"משתמש: @{pref_user}")
            if location:
                summary_parts.append(f"מיקום: {location}")
            if bio:
                summary_parts.append(f"ביוגרפיה: {bio[:120]}")
            if accounts:
                summary_parts.append(f"חשבונות מקושרים: {len(accounts)}")

            findings.append({
                "category": "social_profile",
                "source_tool": "gravatar",
                "title": f"פרופיל Gravatar: {display_name or pref_user or clean_em}",
                "summary": " | ".join(summary_parts),
                "url": entry.get("profileUrl") or f"https://gravatar.com/{md5_hash}",
                "confidence": 0.95,
                "extracted_data": {
                    "email": clean_em,
                    "md5": md5_hash,
                    "display_name": display_name,
                    "username": pref_user,
                    "location": location,
                    "bio": bio,
                    "avatar_url": thumb,
                    "linked_accounts": accounts,
                    "urls": urls,
                },
            })
        except Exception:
            pass
    else:
        # Check Libravatar / Gravatar avatar existence even if JSON profile is hidden
        av_status, _, _ = await _async_http_get(avatar_url, timeout=5.0, http_fetcher=http_fetcher)
        if av_status == 200:
            findings.append({
                "category": "social_profile",
                "source_tool": "gravatar",
                "title": f"תמונת פרופיל Gravatar פעילה ({clean_em})",
                "summary": f"נמצא אווטאר רשום ב-Gravatar עבור {clean_em}",
                "url": avatar_url,
                "confidence": 0.85,
                "extracted_data": {
                    "email": clean_em,
                    "md5": md5_hash,
                    "avatar_url": avatar_url,
                },
            })

    if store is not None:
        store.osint_cache_put(clean_em, "gravatar", findings)
    return findings


async def check_hudsonrock(
    email_or_username: str,
    is_email: bool = True,
    store=None,
    http_fetcher: Callable | None = None,
) -> list[dict[str, Any]]:
    """Query HudsonRock Cavalier Public API for Infostealer compromise intelligence."""
    q = email_or_username.strip().lower()
    if not q:
        return []
    cache_tool = "hudsonrock_email" if is_email else "hudsonrock_user"
    if store is not None:
        cached = store.osint_cache_get(q, cache_tool)
        if cached is not None:
            return cached

    endpoint = "search-by-email?email=" if is_email else "search-by-username?username="
    url = f"https://cavalier.hudsonrock.com/api/json/v2/osint-tools/{endpoint}{urllib.parse.quote(q)}"
    status, body, _ = await _async_http_get(url, timeout=9.0, http_fetcher=http_fetcher)
    findings: list[dict[str, Any]] = []
    if status == 200 and body:
        try:
            data = json.loads(body)
            stealers = data.get("stealers") or []
            if isinstance(stealers, list) and len(stealers) > 0:
                for st in stealers[:5]:
                    comp_date = st.get("date_compromised") or st.get("date") or ""
                    comp_name = st.get("computer_name") or ""
                    os_name = st.get("operating_system") or ""
                    ip_addr = st.get("ip") or ""
                    logins = st.get("top_logins") or []
                    passwords = st.get("top_passwords") or []
                    parts = [f"זוהתה הדבקת Infostealer עבור {q}"]
                    if comp_date:
                        parts.append(f"תאריך: {comp_date}")
                    if comp_name:
                        parts.append(f"מחשב: {comp_name}")
                    if os_name:
                        parts.append(f"מערכת הפעלה: {os_name}")
                    if ip_addr:
                        parts.append(f"IP: {ip_addr}")
                    findings.append({
                        "category": "email_breach",
                        "source_tool": "hudsonrock",
                        "title": f"דליפת Infostealer (HudsonRock): {q}",
                        "summary": " | ".join(parts),
                        "url": url,
                        "confidence": 0.95,
                        "extracted_data": {
                            "query": q,
                            "date_compromised": comp_date,
                            "computer_name": comp_name,
                            "operating_system": os_name,
                            "ip": ip_addr,
                            "top_logins": logins,
                            "top_passwords_masked": [p[:2] + "***" for p in passwords[:3] if isinstance(p, str)],
                        },
                    })
        except Exception:
            pass

    if store is not None:
        store.osint_cache_put(q, cache_tool, findings)
    return findings


async def check_xposedornot(
    email: str,
    store=None,
    http_fetcher: Callable | None = None,
) -> list[dict[str, Any]]:
    """Query XposedOrNot free public breach API for email data breaches."""
    clean_em = email.strip().lower()
    if not clean_em or "@" not in clean_em:
        return []
    if store is not None:
        cached = store.osint_cache_get(clean_em, "xposedornot")
        if cached is not None:
            return cached

    url = f"https://api.xposedornot.com/v1/check-email/{urllib.parse.quote(clean_em)}"
    status, body, _ = await _async_http_get(url, timeout=9.0, http_fetcher=http_fetcher)
    findings: list[dict[str, Any]] = []
    if status == 200 and body:
        try:
            data = json.loads(body)
            breaches = data.get("breaches") or data.get("Breaches") or []
            # XposedOrNot often returns [["BreachA", "BreachB"]]
            flat_breaches: list[str] = []
            for item in breaches:
                if isinstance(item, list):
                    flat_breaches.extend(str(x) for x in item if x)
                elif isinstance(item, str):
                    flat_breaches.append(item)
                elif isinstance(item, dict) and item.get("breach"):
                    flat_breaches.append(str(item["breach"]))

            if flat_breaches:
                breach_list_str = ", ".join(flat_breaches[:12])
                findings.append({
                    "category": "email_breach",
                    "source_tool": "xposedornot",
                    "title": f"דליפות מאגרים (XposedOrNot): {clean_em} ({len(flat_breaches)} מאגרים)",
                    "summary": f"האימייל {clean_em} נמצא ב-{len(flat_breaches)} מאגרים שדלפו: {breach_list_str}",
                    "url": f"https://xposedornot.com/search?email={urllib.parse.quote(clean_em)}",
                    "confidence": 0.92,
                    "extracted_data": {
                        "email": clean_em,
                        "breach_count": len(flat_breaches),
                        "breaches": flat_breaches,
                    },
                })
        except Exception:
            pass

    if store is not None:
        store.osint_cache_put(clean_em, "xposedornot", findings)
    return findings


async def check_github(
    email: str = "",
    username: str = "",
    store=None,
    http_fetcher: Callable | None = None,
) -> list[dict[str, Any]]:
    """Query GitHub Public API for user accounts and commit history matching email or username."""
    query_key = f"{email.strip().lower()}|{username.strip().lower()}"
    if not query_key.strip("|"):
        return []
    if store is not None:
        cached = store.osint_cache_get(query_key, "github")
        if cached is not None:
            return cached

    gh_headers = {
        **DEFAULT_HEADERS,
        "Accept": "application/vnd.github.v3+json",
    }
    commit_headers = {
        **DEFAULT_HEADERS,
        "Accept": "application/vnd.github.cloak-preview+json",
    }

    findings: list[dict[str, Any]] = []
    discovered_logins: set[str] = set()
    commit_authors: list[dict[str, str]] = []

    # 1. Search users by email
    if email and "@" in email:
        u_url = f"https://api.github.com/search/users?q={urllib.parse.quote(email)}"
        st, body, _ = await _async_http_get(u_url, headers=gh_headers, timeout=8.0, http_fetcher=http_fetcher)
        if st == 200 and body:
            try:
                items = json.loads(body).get("items") or []
                for it in items[:3]:
                    if it.get("login"):
                        discovered_logins.add(it["login"])
            except Exception:
                pass

        # 2. Search commits by author-email
        c_url = f"https://api.github.com/search/commits?q=author-email:{urllib.parse.quote(email)}"
        st_c, body_c, _ = await _async_http_get(c_url, headers=commit_headers, timeout=8.0, http_fetcher=http_fetcher)
        if st_c == 200 and body_c:
            try:
                c_items = json.loads(body_c).get("items") or []
                for ci in c_items[:5]:
                    author_obj = ci.get("author") or {}
                    if author_obj.get("login"):
                        discovered_logins.add(author_obj["login"])
                    commit_author = (ci.get("commit") or {}).get("author") or {}
                    ca_name = commit_author.get("name") or ""
                    ca_email = commit_author.get("email") or ""
                    repo_name = (ci.get("repository") or {}).get("full_name") or ""
                    if ca_name or ca_email:
                        commit_authors.append({
                            "name": ca_name,
                            "email": ca_email,
                            "repo": repo_name,
                        })
            except Exception:
                pass

    if username and not discovered_logins:
        discovered_logins.add(username.strip())

    # 3. Fetch full user profile for discovered logins
    for login in list(discovered_logins)[:3]:
        prof_url = f"https://api.github.com/users/{urllib.parse.quote(login)}"
        st_p, body_p, _ = await _async_http_get(prof_url, headers=gh_headers, timeout=8.0, http_fetcher=http_fetcher)
        if st_p == 200 and body_p:
            try:
                p = json.loads(body_p)
                if not p.get("login"):
                    continue
                full_name = p.get("name") or ""
                company = p.get("company") or ""
                blog = p.get("blog") or ""
                location = p.get("location") or ""
                bio = p.get("bio") or ""
                pub_email = p.get("email") or email or ""
                avatar = p.get("avatar_url") or ""
                html_url = p.get("html_url") or f"https://github.com/{p['login']}"
                repos = p.get("public_repos", 0)

                parts = [f"משתמש: @{p['login']}"]
                if full_name:
                    parts.append(f"שם מלא: {full_name}")
                if company:
                    parts.append(f"חברה: {company}")
                if location:
                    parts.append(f"מיקום: {location}")
                if bio:
                    parts.append(f"ביו: {bio[:100]}")
                if repos:
                    parts.append(f"מאגרים: {repos}")

                findings.append({
                    "category": "code_intel",
                    "source_tool": "github",
                    "title": f"פרופיל GitHub: {full_name or p['login']} (@{p['login']})",
                    "summary": " | ".join(parts),
                    "url": html_url,
                    "confidence": 0.94 if email else 0.85,
                    "extracted_data": {
                        "login": p["login"],
                        "full_name": full_name,
                        "email": pub_email,
                        "company": company,
                        "blog": blog,
                        "location": location,
                        "bio": bio,
                        "avatar_url": avatar,
                        "public_repos": repos,
                        "commit_authors": commit_authors,
                    },
                })
            except Exception:
                pass

    if commit_authors and not findings:
        first_ca = commit_authors[0]
        findings.append({
            "category": "code_intel",
            "source_tool": "github",
            "title": f"תיעוד GitHub Commits: {first_ca.get('name') or email}",
            "summary": f"נמצאו קומיטים ב-GitHub עבור {email} (שם מחבר: {first_ca.get('name')}, מאגר: {first_ca.get('repo')})",
            "url": f"https://github.com/search?q={urllib.parse.quote(email)}&type=commits",
            "confidence": 0.92,
            "extracted_data": {
                "email": email,
                "full_name": first_ca.get("name") or "",
                "commit_authors": commit_authors,
            },
        })

    if store is not None:
        store.osint_cache_put(query_key, "github", findings)
    return findings


async def check_holehe(
    email: str,
    store=None,
    http_fetcher: Callable | None = None,
) -> list[dict[str, Any]]:
    """Run Holehe email registration checks across popular online services,
    saving ONLY confirmed `exists: True` hits."""
    clean_em = email.strip().lower()
    if not clean_em or "@" not in clean_em:
        return []
    if store is not None:
        cached = store.osint_cache_get(clean_em, "holehe")
        if cached is not None:
            return cached

    findings: list[dict[str, Any]] = []
    confirmed_sites: list[dict[str, Any]] = []

    if http_fetcher is not None:
        # Allow unit tests to simulate holehe via synthetic URL
        st, body, _ = await _async_http_get(
            f"https://holehe.local/check?email={urllib.parse.quote(clean_em)}",
            http_fetcher=http_fetcher,
        )
        if st == 200 and body:
            try:
                items = json.loads(body)
                for it in items:
                    if isinstance(it, dict) and it.get("exists") is True:
                        confirmed_sites.append(it)
            except Exception:
                pass
    elif HAS_HOLEHE and HAS_HTTPX:
        try:
            modules = holehe_core.import_submodules("holehe.modules")
            functions = holehe_core.get_functions(modules)
            # Pick fast, reliable modules to avoid 120-module long hangs
            priority_names = {
                "gravatar", "github", "spotify", "pinterest", "wordpress",
                "duolingo", "eventbrite", "firefox", "imgur", "lastfm",
                "vimeo", "adobe", "strava", "docker", "replit", "trello",
            }
            selected_fns = [
                fn for fn in functions
                if getattr(fn, "__name__", "").lower() in priority_names
            ] or functions[:15]

            out_list: list[dict[str, Any]] = []
            async with httpx.AsyncClient(timeout=6.0, follow_redirects=True) as client:
                tasks = [
                    _safe_task(fn(clean_em, client, out_list), f"holehe:{fn.__name__}", timeout=6.0)
                    for fn in selected_fns
                ]
                await asyncio.gather(*tasks, return_exceptions=True)

            for item in out_list:
                if isinstance(item, dict) and item.get("exists") is True:
                    confirmed_sites.append(item)
        except Exception:
            pass

    for site in confirmed_sites:
        name = site.get("name") or site.get("domain") or "Service"
        domain = site.get("domain") or name
        email_rec = site.get("emailrecovery") or ""
        phone_rec = site.get("phoneNumber") or ""
        extra = []
        if email_rec:
            extra.append(f"אימייל שחזור: {email_rec}")
        if phone_rec:
            extra.append(f"טלפון שחזור: {phone_rec}")
        extra_str = f" ({', '.join(extra)})" if extra else ""
        findings.append({
            "category": "social_profile",
            "source_tool": "holehe",
            "title": f"חשבון רשום מאומת ({name}): {clean_em}",
            "summary": f"האימייל {clean_em} רשום באופן פעיל בשירות {domain}{extra_str}",
            "url": f"https://{domain}" if "." in str(domain) else "",
            "confidence": 0.90,
            "extracted_data": {
                "email": clean_em,
                "service": name,
                "domain": domain,
                "email_recovery": email_rec,
                "phone_recovery": phone_rec,
            },
        })

    if store is not None:
        store.osint_cache_put(clean_em, "holehe", findings)
    return findings


# ============================================================================
# Layer 3: Username & Social Footprint Hunter + Deep Profile Metadata Extraction
# ============================================================================

SOCIAL_PLATFORMS = [
    {
        "name": "Telegram",
        "url": "https://t.me/{username}",
        "positive": ["tgme_page_title", "tgme_page_photo_image"],
        "negative": ["tgme_page_icon_user", "If you have <strong>Telegram</strong>, you can contact <a class=\"tgme_username_link\""],
        "require_title_tag": "tgme_page_title",
    },
    {
        "name": "GitHub",
        "url": "https://github.com/{username}",
        "positive": ["vcard-names", "p-nickname", "js-profile-editable-area"],
        "negative": ["Not Found", "This is not the web page you are looking for"],
    },
    {
        "name": "Reddit",
        "url": "https://www.reddit.com/user/{username}/about.json",
        "is_json": True,
        "positive": ["\"kind\": \"t2\""],
        "negative": ["\"error\": 404", "\"message\": \"Not Found\""],
    },
    {
        "name": "TikTok",
        "url": "https://www.tiktok.com/@{username}",
        "positive": ["\"uniqueId\":\"{username}\"", "tiktok.com/@{username}"],
        "negative": ["Couldn't find this account", "\"statusCode\":10202", "User not found"],
    },
    {
        "name": "Linktree",
        "url": "https://linktr.ee/{username}",
        "positive": ["\"username\":\"{username}\"", "linktr.ee/{username}"],
        "negative": ["The page you’re looking for doesn’t exist", "Page not found"],
    },
    {
        "name": "Steam",
        "url": "https://steamcommunity.com/id/{username}",
        "positive": ["actual_persona_name", "playerAvatar"],
        "negative": ["The specified profile could not be found", "Error"],
    },
    {
        "name": "Medium",
        "url": "https://medium.com/@{username}",
        "positive": ["property=\"profile:username\"", "@{username}"],
        "negative": ["PAGE NOT FOUND", "Out of nothing, something"],
    },
    {
        "name": "Pinterest",
        "url": "https://www.pinterest.com/{username}/",
        "positive": ["pinterestapp:pinner", "\"username\":\"{username}\""],
        "negative": ["User not found", "Sorry! We couldn't find that page"],
    },
    {
        "name": "GitLab",
        "url": "https://gitlab.com/{username}",
        "positive": ["user-profile", "property=\"og:title\""],
        "negative": ["Sign in", "Page Not Found", "404"],
    },
    {
        "name": "Keybase",
        "url": "https://keybase.io/{username}",
        "positive": ["profile-heading", "keybase.io/{username}"],
        "negative": ["Not found", "404"],
    },
    {
        "name": "Instagram",
        "url": "https://www.instagram.com/{username}/",
        "positive": ["property=\"og:title\"", "@{username}"],
        "negative": ["Sorry, this page isn't available", "Page Not Found", "Login • Instagram"],
    },
    {
        "name": "Twitter/X",
        "url": "https://x.com/{username}",
        "positive": ["property=\"og:title\"", "@{username}"],
        "negative": ["This account doesn’t exist", "Account suspended", "Page not found"],
    },
]

GENERIC_NOT_FOUND_PHRASES = (
    "user not found",
    "page not found",
    "this account doesn't exist",
    "this account doesn’t exist",
    "couldn't find this account",
    "the specified profile could not be found",
    "sorry, this page isn't available",
    "the page you’re looking for doesn’t exist",
    "404 not found",
)


def extract_profile_metadata(html_or_json: str, platform_name: str = "", username: str = "") -> dict[str, Any]:
    """Extract OpenGraph metadata (og:title, og:description, og:image), bio, display name,
    and outbound links from a social profile response."""
    meta: dict[str, Any] = {
        "display_name": "",
        "bio": "",
        "avatar_url": "",
        "outbound_links": [],
    }
    if not html_or_json:
        return meta

    # Handle Reddit about.json
    if platform_name == "Reddit" and html_or_json.strip().startswith("{"):
        try:
            d = json.loads(html_or_json).get("data") or {}
            sub = d.get("subreddit") or {}
            meta["display_name"] = sub.get("title") or d.get("name") or username
            meta["bio"] = sub.get("public_description") or ""
            meta["avatar_url"] = (d.get("icon_img") or "").split("?")[0]
            return meta
        except Exception:
            pass

    # Extract OpenGraph tags
    def _og(prop: str) -> str:
        m = re.search(
            rf'<meta[^>]+(?:property|name)=["\']{re.escape(prop)}["\'][^>]+content=["\']([^"\']+)["\']',
            html_or_json,
            re.IGNORECASE,
        )
        if not m:
            m = re.search(
                rf'<meta[^>]+content=["\']([^"\']+)["\'][^>]+(?:property|name)=["\']{re.escape(prop)}["\']',
                html_or_json,
                re.IGNORECASE,
            )
        return html.unescape(m.group(1)).strip() if m else ""

    og_title = _og("og:title") or _og("twitter:title")
    og_desc = _og("og:description") or _og("twitter:description") or _og("description")
    og_img = _og("og:image") or _og("twitter:image")

    # Telegram specific parsing
    if platform_name == "Telegram":
        m_title = re.search(r'<div class="tgme_page_title"[^>]*>\s*<span[^>]*>(.*?)</span>', html_or_json, re.DOTALL)
        if m_title:
            og_title = html.unescape(re.sub(r"<[^>]+>", "", m_title.group(1))).strip()
        m_desc = re.search(r'<div class="tgme_page_description"[^>]*>(.*?)</div>', html_or_json, re.DOTALL)
        if m_desc:
            og_desc = html.unescape(re.sub(r"<[^>]+>", " ", m_desc.group(1))).strip()

    # Clean common platform suffixes from og:title
    if og_title:
        cleaned_title = re.sub(
            r"\s*(?:\(@[^)]+\))?\s*(?:[-|•·]\s*(?:Telegram|GitHub|TikTok|Instagram|X|Twitter|Reddit|Medium|Pinterest|Steam|Linktree|GitLab)).*$",
            "",
            og_title,
            flags=re.IGNORECASE,
        ).strip()
        cleaned_title = re.sub(r"^Telegram:\s*Contact\s*@\w+$", "", cleaned_title, flags=re.IGNORECASE).strip()
        meta["display_name"] = cleaned_title
    meta["bio"] = og_desc[:300] if og_desc else ""
    meta["avatar_url"] = og_img

    # Extract outbound links (especially useful on Linktree / GitHub / Telegram bio)
    links = re.findall(r'href=["\'](https?://[^"\'\s<>]+)["\']', html_or_json, re.IGNORECASE)
    filtered_links = []
    skip_hosts = ("t.me", "telegram.org", "github.githubassets.com", "linktr.ee", "tiktok.com", "reddit.com",
                  "steamcommunity.com", "valvesoftware.com", "pinterest.com", "medium.com", "w3.org", "schema.org",
                  "googleapis.com", "gstatic.com", "cloudflare.com")
    for lnk in links:
        if any(sh in lnk.lower() for sh in skip_hosts):
            continue
        if lnk not in filtered_links:
            filtered_links.append(lnk)
    meta["outbound_links"] = filtered_links[:10]
    return meta


async def check_username_on_platform(
    username: str,
    platform: dict[str, Any],
    http_fetcher: Callable | None = None,
) -> dict[str, Any] | None:
    """Check if `username` exists on `platform` with strict 200-OK false-positive filtering."""
    u = username.strip()
    if not u:
        return None
    url = platform["url"].format(username=urllib.parse.quote(u))
    status, body, _ = await _async_http_get(url, timeout=7.0, http_fetcher=http_fetcher)
    if status != 200 or not body:
        return None

    body_low = body.lower()
    for neg in platform.get("negative", []):
        if neg.lower() in body_low:
            return None
    for generic_neg in GENERIC_NOT_FOUND_PHRASES:
        if generic_neg in body_low:
            return None

    # Telegram special check: t.me/<nonexistent> returns 200 with generic page lacking `tgme_page_title`
    req_tag = platform.get("require_title_tag")
    if req_tag and req_tag not in body:
        return None

    positives = [p.format(username=u).lower() for p in platform.get("positive", [])]
    if positives and not any(pos in body_low for pos in positives):
        return None

    meta = extract_profile_metadata(body, platform_name=platform["name"], username=u)
    disp = meta.get("display_name") or u
    bio = meta.get("bio") or ""
    parts = [f"פלטפורמה: {platform['name']}", f"משתמש: @{u}"]
    if disp and disp.lower() != u.lower():
        parts.append(f"שם פרופיל: {disp}")
    if bio:
        parts.append(f"תיאור: {bio[:120]}")
    if meta.get("outbound_links"):
        parts.append(f"קישורים חיצוניים: {len(meta['outbound_links'])}")

    return {
        "category": "social_profile",
        "source_tool": f"social_{platform['name'].lower().replace('/', '_')}",
        "title": f"פרופיל {platform['name']}: {disp} (@{u})",
        "summary": " | ".join(parts),
        "url": url.replace("/about.json", ""),
        "confidence": 0.88,
        "extracted_data": {
            "platform": platform["name"],
            "username": u,
            "display_name": meta.get("display_name") or "",
            "bio": bio,
            "avatar_url": meta.get("avatar_url") or "",
            "outbound_links": meta.get("outbound_links") or [],
        },
    }


async def run_layer3_username_intel(
    usernames: list[str],
    store=None,
    http_fetcher: Callable | None = None,
    log_fn: Callable[[str], None] | None = None,
) -> list[dict[str, Any]]:
    """Scan harvested usernames across all configured social platforms in parallel."""
    findings: list[dict[str, Any]] = []
    for u in (usernames or [])[:6]:
        if store is not None:
            cached = store.osint_cache_get(u, "social_hunter")
            if cached is not None:
                findings.extend(cached)
                continue
        tasks = [
            _safe_task(
                check_username_on_platform(u, plat, http_fetcher=http_fetcher),
                f"{plat['name']}:{u}",
                timeout=8.0,
                log_fn=log_fn,
            )
            for plat in SOCIAL_PLATFORMS
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        user_findings = [r for r in results if isinstance(r, dict) and r.get("title")]
        if store is not None:
            store.osint_cache_put(u, "social_hunter", user_findings)
        findings.extend(user_findings)
    return findings


# ============================================================================
# Layer 4: Phone & Messaging Recon
# ============================================================================

def analyze_phone_number(phone_str: str) -> dict[str, Any]:
    """Perform offline telecom analysis using `phonenumbers` + Israeli prefix intelligence."""
    perms = generate_phone_permutations(phone_str)
    local = perms[0] if perms else phone_str.strip()
    intl = next((p for p in perms if p.startswith("+972")), local)
    wa_digits = next((p for p in perms if p.startswith("972") and p.isdigit()), "")

    info: dict[str, Any] = {
        "input": phone_str,
        "local": local,
        "e164": intl,
        "whatsapp_url": f"https://wa.me/{wa_digits}" if wa_digits else "",
        "valid": False,
        "country": "IL",
        "carrier": "",
        "region": "ישראל",
        "line_type": "unknown",
        "permutations": perms,
    }

    if HAS_PHONENUMBERS:
        try:
            parsed = phonenumbers.parse(intl if intl.startswith("+") else local, "IL")
            info["valid"] = bool(phonenumbers.is_valid_number(parsed))
            info["e164"] = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164)
            c_name = pn_carrier.name_for_number(parsed, "en") or ""
            r_name = pn_geocoder.description_for_number(parsed, "he") or pn_geocoder.description_for_number(parsed, "en") or "ישראל"
            ntype = phonenumbers.number_type(parsed)
            if ntype == PhoneNumberType.MOBILE:
                info["line_type"] = "mobile (נייד)"
            elif ntype == PhoneNumberType.FIXED_LINE:
                info["line_type"] = "landline (נייח)"
            elif ntype == PhoneNumberType.VOIP:
                info["line_type"] = "voip (קו אינטרנטי)"
            else:
                info["line_type"] = "phone"
            if c_name:
                info["carrier"] = c_name
            if r_name:
                info["region"] = r_name
        except Exception:
            pass

    # Enrich with Israeli prefix table
    if local.startswith("05") and len(local) == 10:
        info["valid"] = True
        info["line_type"] = "mobile (נייד)"
        pref3 = local[:3]
        if pref3 in ISRAELI_MOBILE_CARRIERS:
            info["carrier"] = ISRAELI_MOBILE_CARRIERS[pref3]
    elif local.startswith("0") and len(local) in (9, 10):
        for pref, reg_desc in ISRAELI_LANDLINE_REGIONS.items():
            if local.startswith(pref):
                info["valid"] = True
                info["region"] = reg_desc
                if "VoIP" in reg_desc:
                    info["line_type"] = "voip (קו אינטרנטי)"
                else:
                    info["line_type"] = "landline (נייח)"
                break

    return info


async def check_ignorant_phone(
    phone_info: dict[str, Any],
    store=None,
    http_fetcher: Callable | None = None,
) -> list[dict[str, Any]]:
    """Check phone number registration across services using `ignorant` (Instagram, Amazon, Snapchat)
    plus WhatsApp wa.me metadata."""
    local = phone_info.get("local") or ""
    if not local:
        return []
    if store is not None:
        cached = store.osint_cache_get(local, "phone_recon")
        if cached is not None:
            return cached

    findings: list[dict[str, Any]] = []
    # 1. Telecom analysis finding
    if phone_info.get("valid"):
        carrier_str = phone_info.get("carrier") or "מפעיל ישראלי"
        line_str = phone_info.get("line_type") or "קו טלפון"
        reg_str = phone_info.get("region") or "ישראל"
        findings.append({
            "category": "phone_intel",
            "source_tool": "phonenumbers",
            "title": f"ניתוח טלקום ({local}): {carrier_str}",
            "summary": f"מספר: {local} ({phone_info.get('e164')}) | סוג קו: {line_str} | מפעיל: {carrier_str} | אזור: {reg_str}",
            "url": phone_info.get("whatsapp_url") or "",
            "confidence": 0.95,
            "extracted_data": phone_info,
        })

    # 2. Ignorant checks (if installed and real network or simulated via http_fetcher)
    body_no_zero = local[1:] if local.startswith("0") else local
    confirmed_apps: list[str] = []
    if http_fetcher is not None:
        st, body, _ = await _async_http_get(
            f"https://ignorant.local/check?phone={urllib.parse.quote(local)}",
            http_fetcher=http_fetcher,
        )
        if st == 200 and body:
            try:
                for it in json.loads(body):
                    if isinstance(it, dict) and it.get("exists") is True:
                        confirmed_apps.append(it.get("name") or it.get("domain") or "App")
            except Exception:
                pass
    elif HAS_IGNORANT and HAS_HTTPX and body_no_zero.isdigit():
        try:
            modules = ignorant_core.import_submodules("ignorant.modules")
            functions = ignorant_core.get_functions(modules)
            out_list: list[dict[str, Any]] = []
            async with httpx.AsyncClient(timeout=6.0, follow_redirects=True) as client:
                tasks = [
                    _safe_task(fn(body_no_zero, "972", client, out_list), f"ignorant:{fn.__name__}", timeout=6.0)
                    for fn in functions[:6]
                ]
                await asyncio.gather(*tasks, return_exceptions=True)
            for item in out_list:
                if isinstance(item, dict) and item.get("exists") is True:
                    confirmed_apps.append(item.get("name") or item.get("domain") or "App")
        except Exception:
            pass

    for app_name in confirmed_apps:
        findings.append({
            "category": "phone_intel",
            "source_tool": "ignorant",
            "title": f"חשבון משויך לטלפון ({app_name}): {local}",
            "summary": f"מספר הטלפון {local} משויך לחשבון פעיל בשירות {app_name}",
            "url": phone_info.get("whatsapp_url") or "",
            "confidence": 0.89,
            "extracted_data": {"phone": local, "service": app_name},
        })

    # 3. Check WhatsApp wa.me link metadata
    wa_url = phone_info.get("whatsapp_url")
    if wa_url:
        st_w, body_w, _ = await _async_http_get(wa_url, timeout=6.0, http_fetcher=http_fetcher)
        if st_w == 200 and body_w:
            meta = extract_profile_metadata(body_w, platform_name="WhatsApp", username=local)
            disp = meta.get("display_name") or ""
            # Filter generic WhatsApp title ("Share on WhatsApp")
            if disp and not any(g in disp.lower() for g in ("share on whatsapp", "whatsapp", "שיתוף ב-whatsapp")):
                findings.append({
                    "category": "phone_intel",
                    "source_tool": "whatsapp",
                    "title": f"פרופיל WhatsApp ({local}): {disp}",
                    "summary": f"קישור WhatsApp פעיל עבור {local} | שם תצוגה: {disp}",
                    "url": wa_url,
                    "confidence": 0.90,
                    "extracted_data": {
                        "phone": local,
                        "display_name": disp,
                        "avatar_url": meta.get("avatar_url") or "",
                        "whatsapp_url": wa_url,
                    },
                })

    if store is not None:
        store.osint_cache_put(local, "phone_recon", findings)
    return findings


# ============================================================================
# Layer 5: Unified Multi-Engine Search & Automated Israeli Registries Dorker
# ============================================================================

def build_israeli_dorks(profile: SearchTargetProfile) -> list[dict[str, str]]:
    """Build targeted Israeli OSINT dork queries across legal, governmental, corporate,
    social, and leaked document categories."""
    dorks: list[dict[str, str]] = []
    seen_q: set[str] = set()

    def _add(q: str, category: str, label: str):
        q_clean = q.strip()
        if q_clean and q_clean not in seen_q:
            seen_q.add(q_clean)
            dorks.append({"query": q_clean, "category": category, "label": label})

    primary_he = profile.hebrew_names[0] if profile.hebrew_names else ""
    primary_en = profile.english_names[0] if profile.english_names else ""
    anchor_name = primary_he or primary_en or profile.primary_name

    if primary_he:
        # 1. Legal & Court Rulings (פסקי דין ותולעת המשפט)
        _add(
            f'"{primary_he}" (site:psakdin.co.il OR site:takdin.co.il OR site:ruling.co.il OR site:nevo.co.il OR "תולעת המשפט")',
            "legal_doc",
            "פסקי דין והליכים משפטיים",
        )
        # 2. Gov, Registries & NGOs (ממשלתי, עמותות ורשם החברות)
        _add(
            f'"{primary_he}" (site:gov.il OR site:guidestar.org.il OR "רשם החברות" OR "ח.פ")',
            "legal_doc",
            "מאגרי ממשלה, רשם החברות וגיידסטאר",
        )
        # 3. Social & Professional Networks (Hebrew)
        _add(
            f'"{primary_he}" (site:il.linkedin.com/in/ OR site:linkedin.com/in/ OR site:facebook.com OR site:instagram.com)',
            "social_profile",
            "רשתות חברתיות ולינקדאין (עברית)",
        )
        # 4. Leaked / Public Documents (PDF, XLSX, DOCX, CSV)
        _add(
            f'"{primary_he}" (filetype:pdf OR filetype:xlsx OR filetype:xls OR filetype:docx OR filetype:csv)',
            "legal_doc",
            "מסמכים וקבצי אקסל/PDF פומביים",
        )
        # 5. General web mention with city/org context if available
        ctx = profile.cities[0] if profile.cities else (profile.organizations[0] if profile.organizations else "")
        if ctx:
            _add(f'"{primary_he}" "{ctx}"', "web_mention", f"אזכורי רשת ממוקדים ({ctx})")
        else:
            _add(f'"{primary_he}"', "web_mention", "אזכורי רשת כלליים (עברית)")

    if primary_en:
        _add(
            f'"{primary_en}" (site:il.linkedin.com/in/ OR site:linkedin.com/in/ OR site:github.com OR site:facebook.com)',
            "social_profile",
            "רשתות חברתיות ולינקדאין (אנגלית)",
        )
        _add(f'"{primary_en}"', "web_mention", "אזכורי רשת כלליים (אנגלית)")

    for em in profile.emails[:3]:
        _add(f'"{em}"', "web_mention", f"חיפוש אימייל מדויק ({em})")

    for ph, perms in list(profile.phone_permutations.items())[:2]:
        top_p = perms[:3]
        if top_p:
            or_clause = " OR ".join(f'"{p}"' for p in top_p)
            if anchor_name:
                _add(f'({or_clause})', "phone_intel", f"אזכורי מספר טלפון ({ph})")

    return dorks[:12]


def score_search_result(
    title: str,
    snippet: str,
    url: str,
    profile: SearchTargetProfile,
) -> float:
    """Compute a Relevance Score (0.0 to 1.0) for a search engine hit against `profile`."""
    blob = f"{title} {snippet} {url}".lower()
    blob_folded = fold(blob)
    score = 0.35

    # Exact full name match
    for nm in profile.hebrew_names + profile.english_names:
        nm_f = fold(nm)
        if nm_f and nm_f in blob_folded:
            score += 0.35
            break

    # Exact email / phone / username match
    for em in profile.emails:
        if em.lower() in blob:
            score += 0.30
            break
    for perms in profile.phone_permutations.values():
        if any(p.lower() in blob for p in perms):
            score += 0.25
            break
    for u in profile.usernames:
        if len(u) >= 4 and u.lower() in blob:
            score += 0.15
            break

    # Co-occurring city or organization
    for c in profile.cities + profile.organizations:
        if c and fold(c) in blob_folded:
            score += 0.12
            break

    # High-authority Israeli OSINT domains
    high_value_domains = (
        "psakdin.co.il", "takdin.co.il", "nevo.co.il", "ruling.co.il",
        "gov.il", "guidestar.org.il", "linkedin.com", "github.com",
        "t.me", "facebook.com", "instagram.com",
    )
    if any(d in url.lower() for d in high_value_domains):
        score += 0.12

    return round(min(0.99, max(0.10, score)), 2)


async def run_layer5_dork_search(
    profile: SearchTargetProfile,
    store=None,
    search_fn: Callable[[str], list[dict[str, str]]] | None = None,
    log_fn: Callable[[str], None] | None = None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Execute multi-engine OSINT dorks, score relevance, and run Extractor NER over snippets.
    Returns (osint_findings, extracted_leads)."""
    from .config import Config
    from .extract import Extractor
    from .providers import NativeMetaSearchProvider, harvest_snippet_intel

    dorks = build_israeli_dorks(profile)
    findings: list[dict[str, Any]] = []
    leads: list[dict[str, Any]] = []
    seen_urls: set[str] = set()
    extractor = Extractor()
    meta_provider = NativeMetaSearchProvider(Config()) if search_fn is None else None

    def _default_search_with_snippets(query_str: str, limit: int = 8) -> list[dict[str, str]]:
        if meta_provider is None:
            return []
        urls = meta_provider.search(query_str, limit=limit)
        if meta_provider.last_snippets:
            return list(meta_provider.last_snippets)[:limit]
        return [{"url": u, "title": u, "snippet": ""} for u in urls[:limit]]

    async def _run_single_dork(dork_item: dict[str, str]) -> list[dict[str, Any]]:
        q = dork_item["query"]
        cat = dork_item["category"]
        label = dork_item["label"]

        if store is not None:
            cached = store.osint_cache_get(q, "dork_search")
            if cached is not None:
                return cached

        if search_fn is not None:
            res = search_fn(q)
            if asyncio.iscoroutine(res):
                res = await res
            raw_hits = list(res or [])
        else:
            raw_hits = await asyncio.to_thread(_default_search_with_snippets, q, 8)

        dork_findings: list[dict[str, Any]] = []
        for hit in raw_hits[:8]:
            u = (hit.get("url") or "").strip()
            title = (hit.get("title") or u).strip()
            snippet = (hit.get("snippet") or "").strip()
            if not u:
                continue
            rel = score_search_result(title, snippet, u, profile)
            if rel < 0.40:
                continue

            # Categorize automatically by URL if needed
            eff_cat = cat
            u_low = u.lower()
            if any(d in u_low for d in ("psakdin", "takdin", "nevo", "ruling", "gov.il", "guidestar")) or u_low.endswith((".pdf", ".xlsx", ".xls", ".docx")):
                eff_cat = "legal_doc"
            elif any(d in u_low for d in ("linkedin.com", "facebook.com", "instagram.com", "tiktok.com", "t.me", "x.com", "twitter.com")):
                eff_cat = "social_profile"
            elif "github.com" in u_low or "gitlab.com" in u_low or "stackoverflow.com" in u_low:
                eff_cat = "code_intel"

            # Extract entities/attributes from title + snippet using Extractor & harvest_snippet_intel
            combined_text = f"{title} — {snippet}"
            ex = extractor.extract(combined_text, u)
            snippet_intel = harvest_snippet_intel([{"url": u, "title": title, "snippet": snippet}])
            extracted_emails = list(dict.fromkeys(
                [d["display"] for (et, _), d in ex.ents.items() if et == "email"] + list(snippet_intel.get("emails", []))
            ))
            extracted_phones = list(dict.fromkeys(
                [d["display"] for (et, _), d in ex.ents.items() if et == "phone"] + list(snippet_intel.get("phones", []))
            ))
            extracted_persons = [
                d["display"] for (et, _), d in ex.ents.items()
                if et == "person" and is_valid_person_name(d["display"])
            ]
            extracted_orgs = [d["display"] for (et, _), d in ex.ents.items() if et == "org"]

            dork_findings.append({
                "category": eff_cat,
                "source_tool": "dork_search",
                "title": f"[{label}] {title[:110]}",
                "summary": snippet[:280] if snippet else f"נמצא באמצעות שאילתת Dork: {q}",
                "url": u,
                "confidence": rel,
                "extracted_data": {
                    "query": q,
                    "label": label,
                    "emails": extracted_emails,
                    "phones": extracted_phones,
                    "persons": extracted_persons,
                    "orgs": extracted_orgs,
                    "national_ids": snippet_intel.get("national_ids", []),
                    "attributes": [{"name": a[1], "value": a[2], "kind": a[3]} for a in ex.attrs if len(a) >= 4],
                },
            })

        if store is not None:
            store.osint_cache_put(q, "dork_search", dork_findings)
        return dork_findings

    tasks = [
        _safe_task(_run_single_dork(d), f"dork:{d['label']}", timeout=14.0, log_fn=log_fn)
        for d in dorks
    ]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    for res_list in results:
        if not isinstance(res_list, list):
            continue
        for f in res_list:
            u = f.get("url") or ""
            if u in seen_urls:
                continue
            seen_urls.add(u)
            findings.append(f)
            ed = f.get("extracted_data") or {}
            for em in ed.get("emails") or []:
                leads.append({"type": "email", "value": em, "confidence": f["confidence"], "source": u})
            for ph in ed.get("phones") or []:
                leads.append({"type": "phone", "value": ph, "confidence": f["confidence"], "source": u})
            for per in ed.get("persons") or []:
                leads.append({"type": "person", "value": per, "confidence": f["confidence"], "source": u})
            for org in ed.get("orgs") or []:
                leads.append({"type": "org", "value": org, "confidence": f["confidence"], "source": u})

    return findings, leads


# ============================================================================
# Layer 6: Recursive Pivot Loop (Online <-> Offline DB Correlation & Hop 2)
# ============================================================================

def collect_leads_from_findings(
    findings: list[dict[str, Any]],
    profile: SearchTargetProfile,
) -> list[dict[str, Any]]:
    """Harvest newly discovered emails, usernames, full names, phones, and organizations
    from Layers 2–5 findings."""
    leads: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()

    def _add_lead(ltype: str, val: str, conf: float, source_tool: str, url: str = ""):
        v = str(val or "").strip()
        if not v:
            return
        k = (ltype, fold(v))
        if k in seen:
            return
        seen.add(k)
        leads.append({
            "type": ltype,
            "value": v,
            "confidence": float(conf),
            "source_tool": source_tool,
            "url": url,
        })

    for f in findings:
        ed = f.get("extracted_data") or {}
        conf = float(f.get("confidence") or 0.8)
        tool = f.get("source_tool") or "osint"
        url = f.get("url") or ""

        # Names discovered via Gravatar / GitHub / Social profiles
        for name_field in ("full_name", "display_name"):
            nm = (ed.get(name_field) or "").strip()
            if nm and len(nm.split()) >= 2 and is_valid_person_name(nm):
                _add_lead("person", nm, conf, tool, url)

        # Emails discovered via GitHub commits / snippets / recovery
        for em_field in ("email",):
            em = (ed.get(em_field) or "").strip().lower()
            if em and "@" in em and "*" not in em:
                _add_lead("email", em, conf, tool, url)
        for em in ed.get("emails") or []:
            if "@" in str(em):
                _add_lead("email", str(em).lower(), conf, tool, url)
        for ca in ed.get("commit_authors") or []:
            if isinstance(ca, dict):
                if ca.get("email") and "@" in ca["email"] and "noreply.github.com" not in ca["email"]:
                    _add_lead("email", ca["email"].lower(), conf, tool, url)
                if ca.get("name") and len(ca["name"].split()) >= 2 and is_valid_person_name(ca["name"]):
                    _add_lead("person", ca["name"], conf, tool, url)

        # Usernames discovered via Gravatar / GitHub / Social
        for u_field in ("username", "login"):
            u = (ed.get(u_field) or "").strip().lstrip("@")
            if u and len(u) >= 3 and " " not in u:
                _add_lead("username", u, conf, tool, url)
        for acc in ed.get("linked_accounts") or []:
            if isinstance(acc, dict) and acc.get("username"):
                _add_lead("username", str(acc["username"]).lstrip("@"), conf, tool, url)

        # Phones
        for ph in ed.get("phones") or []:
            _add_lead("phone", str(ph), conf, tool, url)

        # Organizations / Company / Location
        if ed.get("company"):
            _add_lead("org", str(ed["company"]).lstrip("@").strip(), conf, tool, url)
        for org in ed.get("orgs") or []:
            _add_lead("org", str(org), conf, tool, url)
        if ed.get("location"):
            _add_lead("location", str(ed["location"]).strip(), conf, tool, url)

    return leads


def cross_match_and_pivot_local_db(
    store,
    profile: SearchTargetProfile,
    leads: list[dict[str, Any]],
    findings: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Cross-reference all newly discovered OSINT leads (and transliterated names) against
    the local SQLite database (`osnit.db`).

    When a match is found in `osnit.db` (e.g., an existing local entity with the English name
    'Matan Shinar' or sharing a newly discovered email/phone/username), automatically links
    the entities in `osnit.db` with the provenance note:
      'אוחד/קושר באמצעות ממצא רשת (Pivot): [המזהה המשותף]'
    and returns pivot findings.
    """
    if store is None or not profile.entity_id:
        return []

    now = time.time()
    root_eid = int(profile.entity_id)
    pivot_findings: list[dict[str, Any]] = []
    linked_entity_ids: set[int] = {root_eid}

    # Create a dedicated source record for Deep OSINT Recon findings
    recon_src_url = f"osint://deep-recon/entity/{root_eid}"
    src_id, _ = store.add_source(recon_src_url, priority=10, origin="deep_osint_recon", now=now)
    store.update_source(
        src_id,
        state="scanned",
        kind="osint_recon",
        title=f"חקירת רשת עמוקה (Deep OSINT Recon): {profile.primary_name}",
        last_scanned=now,
    )

    # 1. Add transliterated names and discovered person names as aliases + check for existing local person entities!
    candidate_names = list(profile.english_names) + list(profile.hebrew_names)
    for ld in leads:
        if ld["type"] == "person" and ld["value"] not in candidate_names:
            candidate_names.append(ld["value"])

    for cname in candidate_names:
        ckey = name_key(cname)
        if not ckey:
            continue
        store.add_alias(root_eid, cname, src_id, now)
        # Search local DB for another person entity with this exact key or alias
        matching_rows = store.q(
            "SELECT id, display, key FROM entities WHERE type='person' AND id!=? AND (key=? OR LOWER(display)=?)",
            (root_eid, ckey, cname.strip().lower()),
        )
        if not matching_rows:
            matching_rows = store.q(
                "SELECT e.id, e.display, e.key FROM aliases a JOIN entities e ON e.id=a.entity_id "
                "WHERE e.type='person' AND e.id!=? AND LOWER(a.alias)=?",
                (root_eid, cname.strip().lower()),
            )
        for mrow in matching_rows:
            other_id = int(mrow["id"])
            if other_id in linked_entity_ids:
                continue
            linked_entity_ids.add(other_id)
            reason = f"אוחד/קושר באמצעות ממצא רשת (Pivot): {cname}"
            rel_id = store.add_relation(root_eid, other_id, "pivot_match", now)
            store.add_rel_evidence(rel_id, src_id, reason, 0.95, now)
            pivot_findings.append({
                "category": "pivot_link",
                "source_tool": "pivot_engine",
                "title": f"הצלבת מאגר מקומי (Pivot): {mrow['display'] or mrow['key']} (#{other_id})",
                "summary": f"{reason} — נמצאה ישות מקומית תואמת במסד הנתונים (ID #{other_id}) וקושרה אוטומטית לתיק הישות.",
                "url": f"#entity/{other_id}",
                "confidence": 0.96,
                "extracted_data": {
                    "matched_entity_id": other_id,
                    "matched_display": mrow["display"] or mrow["key"],
                    "shared_identifier": cname,
                    "reason": reason,
                },
            })

    # 2. Persist discovered emails, phones, usernames, orgs, locations into the entity graph & check local DB pivots
    for ld in leads:
        ltype = ld["type"]
        val = ld["value"]
        conf = float(ld.get("confidence") or 0.85)
        if ltype in ("email", "phone", "username", "org", "location"):
            key_val = val.lower().strip() if ltype != "phone" else (generate_phone_permutations(val)[0] if generate_phone_permutations(val) else val)
            # Check if this identifier ALREADY exists in osnit.db and is linked to any OTHER person entity!
            existing_ent = store.q1("SELECT id, display FROM entities WHERE type=? AND key=?", (ltype, key_val))
            if existing_ent:
                ident_eid = int(existing_ent["id"])
                # Find other persons connected to this identifier in local DB
                other_persons = store.q(
                    "SELECT e.id, e.display, e.key FROM relations r "
                    "JOIN entities e ON (e.id = CASE WHEN r.a_id=? THEN r.b_id ELSE r.a_id END) "
                    "WHERE (r.a_id=? OR r.b_id=?) AND e.type='person' AND e.id!=?",
                    (ident_eid, ident_eid, ident_eid, root_eid),
                )
                for op in other_persons:
                    op_id = int(op["id"])
                    if op_id not in linked_entity_ids:
                        linked_entity_ids.add(op_id)
                        reason = f"אוחד/קושר באמצעות ממצא רשת (Pivot): {val}"
                        rel_id = store.add_relation(root_eid, op_id, "pivot_match", now)
                        store.add_rel_evidence(rel_id, src_id, reason, 0.95, now)
                        pivot_findings.append({
                            "category": "pivot_link",
                            "source_tool": "pivot_engine",
                            "title": f"הצלבת מאגר מקומי (Pivot): {op['display'] or op['key']} דרך {val}",
                            "summary": f"{reason} — המזהה החדש שנמצא ברשת משויך במאגר המקומי גם לישות '{op['display']}' (#{op_id}).",
                            "url": f"#entity/{op_id}",
                            "confidence": 0.96,
                            "extracted_data": {
                                "matched_entity_id": op_id,
                                "matched_display": op["display"] or op["key"],
                                "shared_identifier": val,
                                "reason": reason,
                            },
                        })

            # Upsert the identifier entity and link it to root_eid so the Dossier graph updates immediately
            new_ident_id = store.resolve_entity(ltype, key_val, val, now, fuzzy=False)
            if new_ident_id and new_ident_id > 0 and new_ident_id != root_eid:
                store.add_evidence(new_ident_id, src_id, f"נמצא בחקירת רשת עמוקה ({ld.get('source_tool', 'osint')}): {val}", conf, now)
                rel_id = store.add_relation(root_eid, new_ident_id, "osint_discovered", now)
                store.add_rel_evidence(
                    rel_id,
                    src_id,
                    f"אוחד/קושר באמצעות ממצא רשת (Pivot): {val}",
                    conf,
                    now,
                )

            # Also search FTS5 documents_fts for local file mentions of newly discovered email/username
            if ltype in ("email", "username") and len(val) >= 5:
                fts_hits = store.search_fts(val, limit=3)
                for fh in fts_hits:
                    fp = fh.get("file_path") or "קובץ מקומי"
                    loc_ref = fh.get("location_ref") or ""
                    pivot_findings.append({
                        "category": "pivot_link",
                        "source_tool": "pivot_fts",
                        "title": f"הצלבת מסמך מקומי (FTS5 Pivot): {val} בתוך {fp}",
                        "summary": f"אוחד/קושר באמצעות ממצא רשת (Pivot): {val} נמצא בקובץ המקומי {fp} ({loc_ref})",
                        "url": "",
                        "confidence": 0.93,
                        "extracted_data": {
                            "shared_identifier": val,
                            "file_path": fp,
                            "location_ref": loc_ref,
                            "snippet": fh.get("snippet") or "",
                        },
                    })

    return pivot_findings


# ============================================================================
# Unified Recon Orchestrator & Live Progress Job Manager
# ============================================================================

LAYER_LABELS = {
    1: "[שכבה 1/6] מייצר וריאציות שמות (עברית/אנגלית), שמות משתמש ופרמוטציות טלפון...",
    2: "[שכבה 2/6] סורק דליפות מידע, Infostealers, Gravatar ו-GitHub Commits...",
    3: "[שכבה 3/6] מחפש פרופילי רשתות חברתיות ומחלץ מטא-דאטה (OpenGraph)...",
    4: "[שכבה 4/6] מנתח מספרי טלפון, מפעילים סלולריים וחשבונות מסרים...",
    5: "[שכבה 5/6] מריץ שאילתות Dorks במנועי חיפוש, פסקי דין ומאגרי ממשלה...",
    6: "[שכבה 6/6] מבצע הצלבה רקורסיבית (Pivot) מול מסד הנתונים המקומי...",
}


class UnifiedReconEngine:
    """Master orchestrator for the 6-Layer Deep Web OSINT & Recursive Recon Pipeline."""

    def __init__(
        self,
        store=None,
        http_fetcher: Callable | None = None,
        search_fn: Callable[[str], list[dict[str, str]]] | None = None,
        max_depth: int = 2,
    ):
        self.store = store
        self.http_fetcher = http_fetcher
        self.search_fn = search_fn
        self.max_depth = max(1, min(2, int(max_depth)))

    async def run_recon(
        self,
        entity_id: int | None = None,
        profile: SearchTargetProfile | None = None,
        progress_cb: Callable[[int, str, dict[str, Any]], None] | None = None,
    ) -> dict[str, Any]:
        """Run the full 6-layer Deep OSINT Recon pipeline asynchronously."""
        started_at = time.time()
        logs: list[str] = []

        def _log(msg: str):
            logs.append(msg)

        def _emit(layer_num: int, status_text: str, extra: dict[str, Any] | None = None):
            _log(status_text)
            if progress_cb:
                try:
                    progress_cb(layer_num, status_text, extra or {})
                except Exception:
                    pass

        # ------------------------------------------------------------------
        # Layer 1: Target Permutation & Bidirectional Transliteration
        # ------------------------------------------------------------------
        _emit(1, LAYER_LABELS[1])
        if profile is None:
            if self.store is not None and entity_id is not None:
                profile = SearchTargetProfile.from_entity(self.store, int(entity_id))
            else:
                profile = SearchTargetProfile(entity_id=entity_id)
        elif entity_id is not None and profile.entity_id is None:
            profile.entity_id = int(entity_id)

        _log(
            f"✓ פרופיל מטרה: עברית={profile.hebrew_names[:3]} | אנגלית={profile.english_names[:3]} | "
            f"אימיילים={len(profile.emails)} | שמות משתמש={len(profile.usernames)} | טלפונים={len(profile.phones)}"
        )

        all_findings: list[dict[str, Any]] = []

        # ------------------------------------------------------------------
        # Layer 2: Email, Breach & Infostealer Intelligence
        # ------------------------------------------------------------------
        _emit(2, LAYER_LABELS[2], {"profile": profile.to_dict()})
        l2_tasks = []
        for em in profile.emails[:5]:
            l2_tasks.extend([
                _safe_task(check_gravatar(em, store=self.store, http_fetcher=self.http_fetcher), f"gravatar:{em}", 8.0, _log),
                _safe_task(check_hudsonrock(em, is_email=True, store=self.store, http_fetcher=self.http_fetcher), f"hudsonrock:{em}", 9.0, _log),
                _safe_task(check_xposedornot(em, store=self.store, http_fetcher=self.http_fetcher), f"xposedornot:{em}", 9.0, _log),
                _safe_task(check_github(email=em, store=self.store, http_fetcher=self.http_fetcher), f"github:{em}", 9.0, _log),
                _safe_task(check_holehe(em, store=self.store, http_fetcher=self.http_fetcher), f"holehe:{em}", 10.0, _log),
            ])
        for u in profile.usernames[:3]:
            l2_tasks.extend([
                _safe_task(check_hudsonrock(u, is_email=False, store=self.store, http_fetcher=self.http_fetcher), f"hudsonrock_u:{u}", 9.0, _log),
                _safe_task(check_github(username=u, store=self.store, http_fetcher=self.http_fetcher), f"github_u:{u}", 9.0, _log),
            ])
        if l2_tasks:
            l2_res = await asyncio.gather(*l2_tasks, return_exceptions=True)
            for item in l2_res:
                if isinstance(item, list):
                    all_findings.extend(item)

        # Harvest any immediate usernames/names discovered in Layer 2 before Layer 3 runs!
        l2_leads = collect_leads_from_findings(all_findings, profile)
        for ld in l2_leads:
            if ld["type"] == "username" and ld["value"].lower() not in [u.lower() for u in profile.usernames]:
                profile.usernames.append(ld["value"].lower())
            elif ld["type"] == "person" and not is_hebrew(ld["value"]) and ld["value"] not in profile.english_names:
                profile.english_names.insert(0, ld["value"])

        # ------------------------------------------------------------------
        # Layer 3: Username & Social Footprint Hunter
        # ------------------------------------------------------------------
        _emit(3, LAYER_LABELS[3], {"findings_so_far": len(all_findings)})
        l3_findings = await run_layer3_username_intel(
            profile.usernames,
            store=self.store,
            http_fetcher=self.http_fetcher,
            log_fn=_log,
        )
        all_findings.extend(l3_findings)

        # ------------------------------------------------------------------
        # Layer 4: Phone & Messaging Recon
        # ------------------------------------------------------------------
        _emit(4, LAYER_LABELS[4], {"findings_so_far": len(all_findings)})
        l4_tasks = []
        for ph in profile.phones[:4]:
            p_info = analyze_phone_number(ph)
            l4_tasks.append(
                _safe_task(
                    check_ignorant_phone(p_info, store=self.store, http_fetcher=self.http_fetcher),
                    f"phone:{ph}",
                    10.0,
                    _log,
                )
            )
        if l4_tasks:
            l4_res = await asyncio.gather(*l4_tasks, return_exceptions=True)
            for item in l4_res:
                if isinstance(item, list):
                    all_findings.extend(item)

        # ------------------------------------------------------------------
        # Layer 5: Unified Multi-Engine Search & Israeli Registries Dorker
        # ------------------------------------------------------------------
        _emit(5, LAYER_LABELS[5], {"findings_so_far": len(all_findings)})
        l5_findings, l5_leads = await run_layer5_dork_search(
            profile,
            store=self.store,
            search_fn=self.search_fn,
            log_fn=_log,
        )
        all_findings.extend(l5_findings)

        # ------------------------------------------------------------------
        # Layer 6: Recursive Pivot Loop (Online <-> Offline DB & Hop 2)
        # ------------------------------------------------------------------
        _emit(6, LAYER_LABELS[6], {"findings_so_far": len(all_findings)})
        discovered_leads = collect_leads_from_findings(all_findings, profile)
        for extra_ld in l5_leads:
            discovered_leads.append(extra_ld)

        # Hop 2 Enrichment (if max_depth >= 2): run focused checks on newly discovered high-confidence (>0.80) emails/usernames
        if self.max_depth >= 2:
            initial_emails = {e.lower() for e in profile.emails}
            initial_users = {u.lower() for u in profile.usernames}
            hop2_emails = []
            hop2_users = []
            for ld in discovered_leads:
                if float(ld.get("confidence") or 0) > 0.80:
                    if ld["type"] == "email" and ld["value"].lower() not in initial_emails and ld["value"].lower() not in hop2_emails:
                        hop2_emails.append(ld["value"].lower())
                    elif ld["type"] == "username" and ld["value"].lower() not in initial_users and ld["value"].lower() not in hop2_users:
                        hop2_users.append(ld["value"].lower())

            hop2_tasks = []
            for em2 in hop2_emails[:2]:
                _log(f"🔄 [Hop 2 Pivot] מעשיר אימייל חדש שהתגלה: {em2}")
                hop2_tasks.extend([
                    _safe_task(check_gravatar(em2, store=self.store, http_fetcher=self.http_fetcher), f"hop2_gravatar:{em2}", 7.0, _log),
                    _safe_task(check_xposedornot(em2, store=self.store, http_fetcher=self.http_fetcher), f"hop2_xposed:{em2}", 7.0, _log),
                    _safe_task(check_github(email=em2, store=self.store, http_fetcher=self.http_fetcher), f"hop2_github:{em2}", 7.0, _log),
                ])
            if hop2_tasks:
                h2_res = await asyncio.gather(*hop2_tasks, return_exceptions=True)
                for item in h2_res:
                    if isinstance(item, list):
                        all_findings.extend(item)
                # Refresh leads after Hop 2
                discovered_leads = collect_leads_from_findings(all_findings, profile)

        # Cross-match and link in local osnit.db
        pivot_findings = cross_match_and_pivot_local_db(self.store, profile, discovered_leads, all_findings)
        all_findings.extend(pivot_findings)

        # Deduplicate and persist findings to osint_findings table
        deduped_findings: list[dict[str, Any]] = []
        seen_keys: set[tuple[str, str, str, str]] = set()
        now = time.time()
        for f in all_findings:
            key = (
                str(f.get("category") or ""),
                str(f.get("source_tool") or ""),
                str(f.get("url") or ""),
                str(f.get("title") or ""),
            )
            if key in seen_keys:
                continue
            seen_keys.add(key)
            f["timestamp"] = now
            f["tool"] = f.get("source_tool") or f.get("tool") or "OSINT"
            f["raw"] = f.get("extracted_data") or f.get("raw") or {}
            if self.store is not None and profile.entity_id is not None:
                fid = self.store.add_osint_finding(
                    entity_id=int(profile.entity_id),
                    category=f["category"],
                    source_tool=f["source_tool"],
                    title=f["title"],
                    summary=f.get("summary") or "",
                    url=f.get("url") or "",
                    extracted_data=f.get("extracted_data") or {},
                    confidence=float(f.get("confidence") or 0.8),
                    timestamp=now,
                )
                f["id"] = fid
            deduped_findings.append(f)

        deduped_findings.sort(key=lambda x: float(x.get("confidence") or 0), reverse=True)
        elapsed = round(time.time() - started_at, 2)
        _log(f"✅ חקירת רשת עמוקה הושלמה ב-{elapsed} שניות ({len(deduped_findings)} ממצאים אומתו ונשמרו).")

        return {
            "entity_id": profile.entity_id,
            "profile": profile.to_dict(),
            "findings": deduped_findings,
            "leads": discovered_leads,
            "pivots": pivot_findings,
            "logs": logs,
            "elapsed_s": elapsed,
            "counts_by_category": _count_by_category(deduped_findings),
        }

    def run_recon_sync(
        self,
        entity_id: int | None = None,
        profile: SearchTargetProfile | None = None,
        progress_cb: Callable[[int, str, dict[str, Any]], None] | None = None,
    ) -> dict[str, Any]:
        """Synchronous wrapper around `run_recon`."""
        return asyncio.run(self.run_recon(entity_id=entity_id, profile=profile, progress_cb=progress_cb))


def _count_by_category(findings: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for f in findings:
        cat = f.get("category") or "other"
        counts[cat] = counts.get(cat, 0) + 1
    return counts


class ReconJobManager:
    """Thread-safe background manager for Deep OSINT Recon jobs triggered from the UI."""

    def __init__(self, store):
        self.store = store
        self._lock = threading.Lock()
        self._jobs: dict[str, dict[str, Any]] = {}
        self._entity_latest_job: dict[int, str] = {}
        self._seq = 0

    def start_job(self, entity_id: int | None = None, query: str = "", max_depth: int = 2) -> dict[str, Any]:
        with self._lock:
            self._seq += 1
            job_id = f"recon_{int(time.time())}_{self._seq}"
            job_state = {
                "job_id": job_id,
                "entity_id": int(entity_id) if entity_id is not None else None,
                "query": query or "",
                "max_depth": int(max_depth or 2),
                "state": "running",
                "status": "running",
                "current_layer": 1,
                "total_layers": 6,
                "progress_pct": 10,
                "status_text": LAYER_LABELS[1],
                "layers": [
                    {"layer": i, "label": LAYER_LABELS[i], "state": "running" if i == 1 else "pending", "status": "running" if i == 1 else "pending", "message": LAYER_LABELS[1] if i == 1 else ""}
                    for i in range(1, 7)
                ],
                "logs": [LAYER_LABELS[1]],
                "findings_count": 0,
                "counts_by_category": {},
                "started_at": time.time(),
                "finished_at": None,
                "error": None,
            }
            self._jobs[job_id] = job_state
            if entity_id is not None:
                self._entity_latest_job[int(entity_id)] = job_id

        t = threading.Thread(
            target=self._run_worker,
            args=(job_id, entity_id, query or "", int(max_depth or 2)),
            daemon=True,
            name=f"deep-recon-{job_id}",
        )
        t.start()
        return job_state

    def _run_worker(self, job_id: str, entity_id: int | None, query: str, max_depth: int = 2):
        def _on_progress(layer_num: int, text: str, extra: dict[str, Any]):
            with self._lock:
                st = self._jobs.get(job_id)
                if not st:
                    return
                st["current_layer"] = layer_num
                st["progress_pct"] = min(95, int((layer_num - 1) * 16) + 12)
                st["status_text"] = text
                if text not in st["logs"]:
                    st["logs"].append(text)
                for l_obj in st["layers"]:
                    if l_obj["layer"] < layer_num:
                        l_obj["state"] = "done"
                        l_obj["status"] = "done"
                    elif l_obj["layer"] == layer_num:
                        l_obj["state"] = "running"
                        l_obj["status"] = "running"
                        l_obj["message"] = text
                    else:
                        l_obj["state"] = "pending"
                        l_obj["status"] = "pending"
                if "findings_so_far" in extra:
                    st["findings_count"] = extra["findings_so_far"]
                if "profile" in extra:
                    st["profile"] = extra["profile"]

        try:
            profile = None
            if entity_id is None and query:
                # Resolve or create entity if user launched recon by raw query
                eid = self.store.resolve_entity("person", name_key(query) or fold(query), query, time.time(), fuzzy=True)
                if eid and eid > 0:
                    entity_id = eid
                    with self._lock:
                        self._jobs[job_id]["entity_id"] = eid
                        self._entity_latest_job[eid] = job_id
                profile = SearchTargetProfile.from_query(query, entity_id=entity_id)

            engine = UnifiedReconEngine(store=self.store, max_depth=max_depth)
            res = engine.run_recon_sync(entity_id=entity_id, profile=profile, progress_cb=_on_progress)
            with self._lock:
                st = self._jobs.get(job_id)
                if st:
                    st["state"] = "done"
                    st["status"] = "done"
                    st["current_layer"] = 6
                    st["progress_pct"] = 100
                    st["status_text"] = f"✅ הסריקה הושלמה: נמצאו {len(res['findings'])} ממצאים מאומתים"
                    for l_obj in st["layers"]:
                        l_obj["state"] = "done"
                        l_obj["status"] = "done"
                    st["logs"] = res.get("logs") or st["logs"]
                    st["profile"] = res.get("profile")
                    st["findings"] = res.get("findings") or []
                    st["findings_count"] = len(st["findings"])
                    st["counts_by_category"] = res.get("counts_by_category") or {}
                    st["pivots"] = res.get("pivots") or []
                    st["finished_at"] = time.time()
        except Exception as exc:
            with self._lock:
                st = self._jobs.get(job_id)
                if st:
                    st["state"] = "error"
                    st["status"] = "error"
                    st["error"] = str(exc)
                    st["status_text"] = f"⚠️ שגיאה בסריקה: {exc}"
                    st["finished_at"] = time.time()

    def get_job(self, job_id: str) -> dict[str, Any] | None:
        with self._lock:
            j = self._jobs.get(job_id)
            return dict(j) if j else None

    def get_latest_for_entity(self, entity_id: int) -> dict[str, Any] | None:
        with self._lock:
            jid = self._entity_latest_job.get(int(entity_id))
            if not jid:
                return None
            j = self._jobs.get(jid)
            return dict(j) if j else None
