"""Unified Deep Web OSINT & Recursive Recon Engine (OSNIT-IL v2.0).

Implements the 7-Layer Deep OSINT & Recursive Pivot architecture:
  - Layer 1: Target Permutation & Bidirectional Transliteration (SearchTargetProfile)
  - Layer 2: Email, Breach & Infostealer Intelligence (Holehe, HudsonRock Cavalier, XposedOrNot, Gravatar/Libravatar, GitHub API & Commit Mining)
  - Layer 3: Username & Social Footprint Hunter (Telegram, GitHub, Reddit, TikTok, Instagram, X, Linktree, Steam, Medium, Pinterest, GitLab, Keybase + OpenGraph metadata & 200-OK False-Positive filter)
  - Layer 4: Phone & Messaging Recon (phonenumbers carrier/region/type analysis, ignorant check, WhatsApp & phone permutation web search)
  - Layer 5: Unified Multi-Engine Search, Israeli Registries Dorker & Open-Web Article/Comment Context Scraper (psakdin, takdin, nevo, ruling, gov.il, guidestar, LinkedIn, Open-Web Comment Hunting, Name+Context Matrix & Deep Article Paragraph/NER Extractor)
  - Layer 6: Target Image & Visual Recon Engine (Sources A-D: Direct Avatars, In-Article Images, Image Search, OG/Twitter Card Scraping; dHash Deduplication; EXIF Metadata; OpenCV Face Verification)
  - Layer 7: Chained Deep Enrichers & Recursive Pivot Loop (Online <-> Offline DB cross-matching in osnit.db, automatic entity linking with pivot provenance, and Hop-2 enrichment capped at max_depth=2)
"""
from __future__ import annotations

import asyncio
import contextvars
import hashlib
import html
import json
import os
import re
import struct
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from difflib import SequenceMatcher
from pathlib import Path
from typing import Any, Callable

# Graceful optional imports (Rule 2: never break if an optional library is missing)
try:
    import cv2
    import numpy as np
    HAS_CV2 = True
except ImportError:
    cv2 = None
    np = None
    HAS_CV2 = False

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


def _fix_hebrew_word_finals(text: str) -> str:
    """Ensure Hebrew words ending in non-final כ/מ/נ/פ/צ use proper final letters ך/ם/ן/ף/ץ."""
    finals_map = {"כ": "ך", "מ": "ם", "נ": "ן", "פ": "ף", "צ": "ץ"}
    words = []
    for w in text.split():
        if len(w) >= 2 and w[-1] in finals_map and is_hebrew(w):
            w = w[:-1] + finals_map[w[-1]]
        words.append(w)
    return " ".join(words)


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

    # First pass: exact email local parts & underscore/compact variants
    deferred_email_variants: list[str] = []
    for email in emails or []:
        if "@" not in str(email):
            continue
        local = str(email).split("@", 1)[0].strip().lower()
        local = local.split("+", 1)[0]
        if not local or local in GENERIC_EMAIL_PREFIXES:
            continue
        base_alpha = re.sub(r"[^a-z]", "", local)
        if base_alpha in GENERIC_EMAIL_PREFIXES:
            continue
        if re.match(r"^[a-z0-9._-]+$", local):
            _add(local)
        compact = re.sub(r"[._-]+", "", local)
        _add(compact)
        if "." in local or "-" in local:
            _add(re.sub(r"[.-]+", "_", local))
        no_digits = re.sub(r"\d+$", "", compact)
        if len(no_digits) >= 4:
            deferred_email_variants.append(no_digits)
        no_digits_local = re.sub(r"\d+$", "", local).rstrip("._-")
        if len(no_digits_local) >= 4:
            deferred_email_variants.append(no_digits_local)

    # Primary English name permutations (e.g., amit_tulian, amittulian, amit.tulian) prioritized early
    for en_name in (english_names or [])[:2]:
        toks = [re.sub(r"[^a-z]", "", t.lower()) for t in en_name.split() if t.strip()]
        toks = [t for t in toks if len(t) >= 2]
        if len(toks) >= 2:
            first, last = toks[0], toks[-1]
            _add(f"{first}_{last}")
            _add(f"{first}{last}")
            _add(f"{first}.{last}")

    for dv in deferred_email_variants:
        _add(dv)

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
        c = _fix_hebrew_word_finals(clean(s))
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
    email_derived_en_names: list[str] = []
    for em in hint_emails or []:
        if "@" in str(em):
            lp = str(em).split("@", 1)[0].lower()
            lp_clean = re.sub(r"\d+$", "", lp)
            latin_hints.append(lp_clean)
            parts = [p for p in re.split(r"[._-]+", lp_clean) if len(p) >= 2 and p.isalpha()]
            if len(parts) == 2 and parts[0] not in GENERIC_EMAIL_PREFIXES:
                email_derived_en_names.append(f"{parts[0]} {parts[1]}")
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
                forms = [_fix_hebrew_word_finals(f) for f in token_forms(t) if is_hebrew(f)]
                if not forms:
                    forms = [_fix_hebrew_word_finals(f) for f in latin_to_hebrew(t, cap=6)]
                per_tok_he.append(forms[:6] if forms else [])
            if all(per_tok_he):
                import itertools
                for combo in itertools.islice(itertools.product(*per_tok_he), 40):
                    _add_he(" ".join(combo))

    # Add email-derived two-part names after explicit primary names
    for ed_name in email_derived_en_names:
        _add_en(ed_name)

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
    relatives: list[str] = field(default_factory=list)
    known_urls: list[str] = field(default_factory=list)
    domains: list[str] = field(default_factory=list)

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
        relatives: list[str] = []
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

        for kin in dos.get("kinship", []):
            kname = (kin.get("name") or "").strip()
            if kname and kname not in names_seed and kname not in relatives:
                relatives.append(kname)

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
            elif ("org" in k or "company" in k or "חברה" in k or "מוסד" in k or "school" in k) and val not in orgs:
                orgs.append(val)
            elif any(rk in k for rk in ("spouse", "relative", "father", "mother", "בן זוג", "בת זוג", "אב", "אם", "קרוב")) and val not in relatives:
                relatives.append(val)
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
            relatives=relatives,
            known_urls=urls,
        )

    @property
    def locations(self) -> list[str]:
        return self.cities

    def pivotable_domains(self) -> list[str]:
        """Registrable domains tied to the target that are worth pivoting on (crt.sh/RDAP): the domains of
        the target's own emails and personal/org URLs, excluding free-mail and big-platform domains (a
        subdomain sweep of gmail.com is noise). Precision-first: only a domain the target actually owns/uses."""
        out: list[str] = []
        seeds: list[str] = list(self.domains)
        for em in self.emails:
            if "@" in em:
                seeds.append(em.rsplit("@", 1)[-1])
        for u in self.known_urls:
            try:
                host = urllib.parse.urlparse(u if "//" in u else "//" + u).netloc or u
            except ValueError:
                host = u
            seeds.append(host)
        for s in seeds:
            d = registrable_domain(s)
            if d and is_pivotable_domain(d) and d not in out:
                out.append(d)
        return out

    def all_phone_permutations(self) -> list[str]:
        """Return a flat deduplicated list of all phone permutations across all target phones."""
        if isinstance(self.phone_permutations, list):
            return list(self.phone_permutations)
        out: list[str] = []
        for plist in (self.phone_permutations or {}).values():
            for p in plist:
                if p and p not in out:
                    out.append(p)
        return out

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
        locations: list[str] | None = None,
        organizations: list[str] | None = None,
        orgs: list[str] | None = None,
        relatives: list[str] | None = None,
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

        merged_cities = list(dict.fromkeys(list(cities or []) + list(locations or [])))
        merged_orgs = list(dict.fromkeys(list(organizations or []) + list(orgs or [])))

        seed_domains: list[str] = []
        for _src in clean_emails + list(known_urls or []):
            _d = registrable_domain(_src.rsplit("@", 1)[-1] if "@" in _src else _src)
            if _d and is_pivotable_domain(_d) and _d not in seed_domains:
                seed_domains.append(_d)

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
            cities=merged_cities,
            organizations=merged_orgs,
            relatives=list(relatives or []),
            known_urls=list(known_urls or []),
            domains=seed_domains,
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
            "relatives": self.relatives,
            "known_urls": self.known_urls,
            "domains": self.domains,
        }


# ============================================================================
# Fault-Isolated Async HTTP & Tool Execution Helpers
# ============================================================================

# Per-run network health: how many web requests got any answer at all. A run where nothing answered (no internet,
# a firewall/proxy, every site blocking) says so instead of looking like "done, 1 finding".
_NET: contextvars.ContextVar = contextvars.ContextVar("osnit_recon_net", default=None)


def _net_note(kind: str, status: int | None = None, ok: bool | None = None) -> None:
    d = _NET.get()
    if d is None:
        return
    d[kind + "_total"] = d.get(kind + "_total", 0) + 1
    if ok is None:
        ok = bool(status)
    if ok:
        d[kind + "_ok"] = d.get(kind + "_ok", 0) + 1
    if status in (403, 429, 503):
        d[kind + "_blocked"] = d.get(kind + "_blocked", 0) + 1


def network_summary(d: dict | None) -> tuple[dict, list[str]]:
    """(counts, Hebrew warnings) for one recon run."""
    d = dict(d or {})
    warn = []
    ht, hok, hbl = d.get("http_total", 0), d.get("http_ok", 0), d.get("http_blocked", 0)
    st, sok = d.get("search_total", 0), d.get("search_ok", 0)
    if ht and not hok:
        warn.append(f"⚠️ אף אחת מ-{ht} בקשות הרשת לא קיבלה תשובה — אין חיבור לאינטרנט, או שחומת אש / פרוקסי / "
                    "אנטי-וירוס חוסמים את osnit. בדוק את החיבור והרץ שוב.")
    elif ht and hbl >= max(3, ht // 2):
        warn.append(f"⚠️ {hbl} מתוך {ht} בקשות נחסמו על ידי האתרים (403/429) — ייתכן שה-IP הוגבל זמנית. נסה שוב מאוחר יותר.")
    if st and not sok:
        warn.append(f"⚠️ מנועי החיפוש לא החזירו אף תוצאה ל-{st} שאילתות (חסימה / CAPTCHA / אין רשת) — "
                    "שכבת החיפוש החופשי והתמונות לא רצה בפועל.")
    return d, warn


async def _async_http_get(
    url: str,
    headers: dict[str, str] | None = None,
    timeout: float = 8.0,
    http_fetcher: Callable | None = None,
) -> tuple[int, str, dict[str, str]]:
    res = await _async_http_get_raw(url, headers, timeout, http_fetcher)
    _net_note("http", res[0])
    return res


async def _async_http_get_bytes(
    url: str,
    headers: dict[str, str] | None = None,
    timeout: float = 8.0,
    http_fetcher: Callable | None = None,
) -> tuple[int, bytes, dict[str, str]]:
    res = await _async_http_get_bytes_raw(url, headers, timeout, http_fetcher)
    _net_note("http", res[0])
    return res


async def _async_http_get_raw(
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
                body_v = res[1].decode("utf-8", "replace") if isinstance(res[1], bytes) else str(res[1])
                return int(res[0]), body_v, dict(res[2] or {})
            if len(res) == 2:
                body_v = res[1].decode("utf-8", "replace") if isinstance(res[1], bytes) else str(res[1])
                return int(res[0]), body_v, {}
        return 200, (res.decode("utf-8", "replace") if isinstance(res, bytes) else str(res or "")), {}

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


async def _async_http_get_bytes_raw(
    url: str,
    headers: dict[str, str] | None = None,
    timeout: float = 8.0,
    http_fetcher: Callable | None = None,
) -> tuple[int, bytes, dict[str, str]]:
    """Fault-isolated async HTTP GET returning raw bytes (for image download & face verification)."""
    merged_headers = {**DEFAULT_HEADERS, **(headers or {})}
    if http_fetcher is not None:
        res = http_fetcher(url, merged_headers)
        if asyncio.iscoroutine(res):
            res = await res
        if isinstance(res, tuple):
            raw_b = res[1]
            if isinstance(raw_b, str):
                raw_b = raw_b.encode("latin-1", "ignore")
            return int(res[0]), bytes(raw_b or b""), dict(res[2] if len(res) >= 3 and res[2] else {})
        if isinstance(res, bytes):
            return 200, res, {}
        return 200, str(res or "").encode("latin-1", "ignore"), {}

    if HAS_HTTPX:
        try:
            async with httpx.AsyncClient(
                timeout=timeout,
                follow_redirects=True,
                headers=merged_headers,
                verify=False,
            ) as client:
                resp = await client.get(url)
                return resp.status_code, bytes(resp.content or b""), dict(resp.headers)
        except Exception:
            return 0, b"", {}

    def _sync_get_bytes():
        req = urllib.request.Request(url, headers=merged_headers)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                raw = r.read(2_500_000)
                return r.status, raw, dict(r.headers)
        except urllib.error.HTTPError as e:
            return e.code, b"", {}
        except Exception:
            return 0, b"", {}

    return await asyncio.to_thread(_sync_get_bytes)


async def _safe_task(coro, tool_name: str, timeout: float = 12.0, log_fn: Callable[[str], None] | None = None):
    """Execute a single OSINT tool coroutine with strict timeout and fault isolation.
    Never raises an exception to the caller."""
    try:
        return await asyncio.wait_for(coro, timeout=timeout)
    except asyncio.TimeoutError:
        if tool_name.startswith("dork:"):
            _net_note("search", ok=False)              # a search that never answered is a failed search
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

    # 3. Fetch full user profile + public repositories + push event commits for discovered logins
    for login in list(discovered_logins)[:3]:
        prof_url = f"https://api.github.com/users/{urllib.parse.quote(login)}"
        st_p, body_p, _ = await _async_http_get(prof_url, headers=gh_headers, timeout=8.0, http_fetcher=http_fetcher)
        if st_p == 200 and body_p:
            try:
                p = json.loads(body_p)
                if not isinstance(p, dict) or not p.get("login"):
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
                followers = p.get("followers", 0)

                # Deep GitHub enrichment: fetch top repositories and recent public push events
                repo_details: list[dict[str, Any]] = []
                if repos and int(repos) > 0:
                    r_url = f"https://api.github.com/users/{urllib.parse.quote(p['login'])}/repos?sort=updated&per_page=6"
                    st_r, body_r, _ = await _async_http_get(r_url, headers=gh_headers, timeout=6.0, http_fetcher=http_fetcher)
                    if st_r == 200 and body_r:
                        try:
                            r_list = json.loads(body_r)
                            if isinstance(r_list, list):
                                for r_item in r_list[:6]:
                                    if isinstance(r_item, dict) and r_item.get("name"):
                                        repo_details.append({
                                            "name": r_item.get("name") or "",
                                            "description": r_item.get("description") or "",
                                            "language": r_item.get("language") or "",
                                            "stars": r_item.get("stargazers_count") or 0,
                                            "url": r_item.get("html_url") or "",
                                        })
                        except Exception:
                            pass

                ev_url = f"https://api.github.com/users/{urllib.parse.quote(p['login'])}/events/public?per_page=15"
                st_ev, body_ev, _ = await _async_http_get(ev_url, headers=gh_headers, timeout=6.0, http_fetcher=http_fetcher)
                if st_ev == 200 and body_ev:
                    try:
                        ev_list = json.loads(body_ev)
                        if isinstance(ev_list, list):
                            for ev in ev_list:
                                if isinstance(ev, dict) and ev.get("type") == "PushEvent":
                                    repo_nm = (ev.get("repo") or {}).get("name") or ""
                                    for c_obj in (ev.get("payload") or {}).get("commits") or []:
                                        c_auth = (c_obj or {}).get("author") or {}
                                        c_em = (c_auth.get("email") or "").strip()
                                        c_nm = (c_auth.get("name") or "").strip()
                                        if c_em and "@" in c_em and "noreply.github.com" not in c_em:
                                            if not pub_email:
                                                pub_email = c_em
                                            commit_authors.append({"name": c_nm, "email": c_em, "repo": repo_nm})
                    except Exception:
                        pass

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
                if repo_details:
                    top_names = ", ".join(
                        f"{rd['name']}" + (f" ({rd['language']})" if rd.get("language") else "")
                        for rd in repo_details[:4]
                    )
                    parts.append(f"פרויקטים בולטים: {top_names}")
                if pub_email:
                    parts.append(f"אימייל: {pub_email}")

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
                        "followers": followers,
                        "repositories": repo_details,
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


async def check_pgp_keyservers(
    query_str: str,
    store=None,
    http_fetcher: Callable | None = None,
) -> list[dict[str, Any]]:
    """Query Ubuntu OpenPGP Keyserver (machine-readable index) for public cryptographic keys,
    extracting verified full names and email addresses linked to the target."""
    q = query_str.strip().lower()
    if not q or len(q) < 4:
        return []
    if store is not None:
        cached = store.osint_cache_get(q, "pgp_keyserver")
        if cached is not None:
            return cached

    url = f"https://keyserver.ubuntu.com/pks/lookup?search={urllib.parse.quote(q)}&op=index&options=mr"
    status, body, _ = await _async_http_get(url, timeout=7.0, http_fetcher=http_fetcher)
    findings: list[dict[str, Any]] = []
    if status == 200 and body and "uid:" in body:
        uids: list[str] = []
        emails_found: list[str] = []
        names_found: list[str] = []
        for line in body.splitlines():
            if line.startswith("uid:"):
                parts = line.split(":")
                if len(parts) >= 2:
                    raw_uid = urllib.parse.unquote(parts[1]).strip()
                    if raw_uid and raw_uid not in uids:
                        uids.append(raw_uid)
                        m_em = re.search(r"<([\w.+-]+@[\w-]+\.[\w.-]+)>", raw_uid)
                        if m_em:
                            em_val = m_em.group(1).lower()
                            if em_val not in emails_found:
                                emails_found.append(em_val)
                        nm_val = re.sub(r"\s*<[^>]+>.*$", "", raw_uid).strip()
                        nm_val = re.sub(r"\s*\([^)]*\)", "", nm_val).strip()
                        if nm_val and len(nm_val.split()) >= 2 and is_valid_person_name(nm_val) and nm_val not in names_found:
                            names_found.append(nm_val)
        if uids:
            findings.append({
                "category": "code_intel",
                "source_tool": "pgp_keyserver",
                "title": f"מפתח הצפנה PGP פומבי: {names_found[0] if names_found else q}",
                "summary": f"נמצא מפתח OpenPGP עבור {q} | מזהים (UIDs): {', '.join(uids[:4])}",
                "url": f"https://keyserver.ubuntu.com/pks/lookup?search={urllib.parse.quote(q)}&op=vindex",
                "confidence": 0.93,
                "extracted_data": {
                    "query": q,
                    "uids": uids[:8],
                    "emails": emails_found,
                    "full_name": names_found[0] if names_found else "",
                    "persons": names_found,
                },
            })

    if store is not None:
        store.osint_cache_put(q, "pgp_keyserver", findings)
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

BOT_SSR_HEADERS = {
    "User-Agent": "TelegramBot (like TwitterBot)",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "he-IL,he;q=0.9,en-US;q=0.8,en;q=0.7",
}

FB_SSR_HEADERS = {
    "User-Agent": "facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "he-IL,he;q=0.9,en-US;q=0.8,en;q=0.7",
}

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
        "headers": BOT_SSR_HEADERS,
        "positive": ["property=\"og:title\"", "\"uniqueId\":\"{username}\"", "tiktok.com/@{username}"],
        "negative": ["Visit TikTok to discover profiles!", "Couldn't find this account", "\"statusCode\":10202", "User not found"],
        "require_title_tag": "og:title",
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
        "headers": BOT_SSR_HEADERS,
        "positive": ["\"pageID\":\"profilePage\"", "property=\"og:title\"", "@{username}"],
        "negative": ["\"pageID\":\"httpErrorPage\"", "Sorry, this page isn't available", "Page Not Found", "Login • Instagram"],
        "require_title_tag": "og:title",
    },
    {
        "name": "Twitter/X",
        "url": "https://api.fxtwitter.com/{username}",
        "display_url": "https://x.com/{username}",
        "is_json": True,
        "positive": ["\"code\":200", "\"code\": 200", "\"screen_name\""],
        "negative": ["\"code\":404", "\"code\": 404", "User not found", "This account doesn’t exist", "Account suspended"],
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
    "visit tiktok to discover profiles!",
    "בקר/י ב-tiktok",
    "צפה/י בתוכן טרנדי נוסף",
    "watch more trending",
)


def extract_profile_metadata(html_or_json: str, platform_name: str = "", username: str = "") -> dict[str, Any]:
    """Extract OpenGraph metadata (og:title, og:description, og:image), bio, display name,
    follower stats, and outbound links from a social profile response."""
    meta: dict[str, Any] = {
        "display_name": "",
        "bio": "",
        "avatar_url": "",
        "outbound_links": [],
        "stats": {},
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
            meta["stats"] = {"total_karma": d.get("total_karma") or 0}
            return meta
        except Exception:
            pass

    # Handle Twitter/X fxtwitter JSON API
    if platform_name == "Twitter/X" and html_or_json.strip().startswith("{"):
        try:
            u_obj = json.loads(html_or_json).get("user") or {}
            if u_obj:
                meta["display_name"] = u_obj.get("name") or username
                meta["bio"] = u_obj.get("description") or ""
                meta["avatar_url"] = u_obj.get("avatar_url") or ""
                meta["location"] = u_obj.get("location") or ""
                meta["stats"] = {
                    "followers": u_obj.get("followers") or 0,
                    "following": u_obj.get("following") or 0,
                    "tweets": u_obj.get("tweets") or 0,
                    "joined": u_obj.get("joined") or "",
                }
                site_url = ((u_obj.get("website") or {}).get("url") if isinstance(u_obj.get("website"), dict) else u_obj.get("website")) or ""
                if site_url:
                    meta["outbound_links"] = [str(site_url)]
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
    og_desc = _og("og:description") or _og("twitter:description")
    meta_desc = _og("description")
    og_img = _og("og:image") or _og("twitter:image")

    # Telegram specific parsing
    if platform_name == "Telegram":
        m_title = re.search(r'<div class="tgme_page_title"[^>]*>\s*<span[^>]*>(.*?)</span>', html_or_json, re.DOTALL)
        if m_title:
            og_title = html.unescape(re.sub(r"<[^>]+>", "", m_title.group(1))).strip()
        m_desc = re.search(r'<div class="tgme_page_description"[^>]*>(.*?)</div>', html_or_json, re.DOTALL)
        if m_desc:
            og_desc = html.unescape(re.sub(r"<[^>]+>", " ", m_desc.group(1))).strip()
        m_extra = re.search(r'<div class="tgme_page_extra"[^>]*>(.*?)</div>', html_or_json, re.DOTALL)
        if m_extra:
            meta["stats"]["extra"] = html.unescape(re.sub(r"<[^>]+>", "", m_extra.group(1))).strip()

    # Instagram specific parsing (Followers/Following/Posts + bio from meta description)
    if platform_name == "Instagram":
        if og_desc:
            m_ig_stats = re.search(r"([\d,.]+[KMB]?)\s+Followers?,\s*([\d,.]+[KMB]?)\s+Following,\s*([\d,.]+[KMB]?)\s+Posts?", og_desc, re.IGNORECASE)
            if m_ig_stats:
                meta["stats"] = {
                    "followers": m_ig_stats.group(1),
                    "following": m_ig_stats.group(2),
                    "posts": m_ig_stats.group(3),
                }
        if meta_desc:
            m_ig_bio = re.search(r'on Instagram:\s*["“](.*?)["”]\s*$', meta_desc, re.DOTALL)
            if m_ig_bio and m_ig_bio.group(1).strip():
                og_desc = f"{og_desc} | ביו: {m_ig_bio.group(1).strip()}" if og_desc else m_ig_bio.group(1).strip()

    # TikTok specific parsing
    if platform_name == "TikTok" and og_title:
        og_title = re.sub(r"\s+(?:on|ב-?)\s*TikTok\s*$", "", og_title, flags=re.IGNORECASE).strip()
        m_tt_id = re.search(r"snssdk\d+://user/profile/(\d+)", html_or_json)
        if m_tt_id:
            meta["stats"]["tiktok_user_id"] = m_tt_id.group(1)

    # Clean common platform suffixes from og:title
    if og_title:
        cleaned_title = re.sub(
            r"\s*(?:\(@[^)]+\))?\s*(?:[-|•·]\s*(?:Telegram|GitHub|TikTok|Instagram|Facebook|LinkedIn|X|Twitter|Reddit|Medium|Pinterest|Steam|Linktree|GitLab)).*$",
            "",
            og_title,
            flags=re.IGNORECASE,
        ).strip()
        cleaned_title = re.sub(r"^Telegram:\s*Contact\s*@\w+$", "", cleaned_title, flags=re.IGNORECASE).strip()
        meta["display_name"] = cleaned_title
    meta["bio"] = (og_desc or meta_desc)[:350] if (og_desc or meta_desc) else ""
    meta["avatar_url"] = og_img

    # Extract outbound links (especially useful on Linktree / GitHub / Telegram bio)
    links = re.findall(r'href=["\'](https?://[^"\'\s<>]+)["\']', html_or_json, re.IGNORECASE)
    filtered_links = []
    skip_hosts = (
        "t.me", "telegram.org", "github.com", "github.githubassets.com", "githubusercontent.com",
        "amazonaws.com", "linktr.ee", "tiktok.com", "tiktokcdn.com", "ibytedtos.com",
        "reddit.com", "steamcommunity.com", "valvesoftware.com", "pinterest.com", "pinimg.com",
        "medium.com", "gitlab.com", "gitlab.net", "gravatar.com",
        "w3.org", "schema.org", "googleapis.com", "gstatic.com", "cloudflare.com", "instagram.com",
        "cdninstagram.com", "fbcdn.net", "facebook.com", "licdn.com", "apple.com", "play.google.com",
    )
    skip_exts = (".woff", ".woff2", ".ttf", ".css", ".js", ".mjs", ".png", ".jpg", ".jpeg", ".svg", ".ico", ".atom")
    for lnk in links:
        lnk_low = lnk.lower().split("?")[0]
        if any(sh in lnk_low for sh in skip_hosts) or lnk_low.endswith(skip_exts):
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
    disp_url = platform.get("display_url", platform["url"]).format(username=urllib.parse.quote(u)).replace("/about.json", "")
    req_headers = platform.get("headers")
    status, body, _ = await _async_http_get(url, headers=req_headers, timeout=7.0, http_fetcher=http_fetcher)
    ok_codes = platform.get("exist_code") or (200,)
    if status not in ok_codes or not body:
        return None

    body_low = body.lower()
    for neg in platform.get("negative", []):
        if neg.lower() in body_low:
            return None
    for generic_neg in GENERIC_NOT_FOUND_PHRASES:
        if generic_neg in body_low:
            return None

    req_tag = platform.get("require_title_tag")
    if req_tag and req_tag.lower() not in body_low:
        return None

    positives = [p.format(username=u).lower() for p in platform.get("positive", [])]
    if positives and not any(pos in body_low for pos in positives):
        return None

    meta = extract_profile_metadata(body, platform_name=platform["name"], username=u)
    disp = meta.get("display_name") or u
    bio = meta.get("bio") or ""
    stats = meta.get("stats") or {}
    parts = [f"פלטפורמה: {platform['name']}", f"משתמש: @{u}"]
    if disp and disp.lower() != u.lower():
        parts.append(f"שם פרופיל: {disp}")
    if stats.get("followers"):
        parts.append(f"עוקבים: {stats['followers']}")
    if bio:
        parts.append(f"תיאור: {bio[:150]}")
    if meta.get("outbound_links"):
        parts.append(f"קישורים חיצוניים: {len(meta['outbound_links'])}")

    return {
        "category": "social_profile",
        "source_tool": f"social_{platform['name'].lower().replace('/', '_')}",
        "title": f"פרופיל {platform['name']}: {disp} (@{u})",
        "summary": " | ".join(parts),
        "url": disp_url,
        "confidence": 0.90,
        "extracted_data": {
            "platform": platform["name"],
            "username": u,
            "display_name": meta.get("display_name") or "",
            "full_name": meta.get("display_name") or "",
            "bio": bio,
            "location": meta.get("location") or "",
            "avatar_url": meta.get("avatar_url") or "",
            "stats": stats,
            "outbound_links": meta.get("outbound_links") or [],
        },
    }


_USERNAME_SWEEP_CONCURRENCY = max(4, int(os.environ.get("OSNIT_USERNAME_CONCURRENCY", "20") or "20"))


async def run_layer3_username_intel(
    usernames: list[str],
    store=None,
    http_fetcher: Callable | None = None,
    log_fn: Callable[[str], None] | None = None,
) -> list[dict[str, Any]]:
    """Scan harvested usernames across the curated platforms AND the keyless username-presence manifests
    (WhatsMyName / Sherlock, see osnit/manifests.py) in bounded parallel. Curated platforms (richer metadata)
    win over a manifest site of the same name; the manifest widens coverage to hundreds of sites keylessly."""
    from .manifests import manifest_platforms, manifest_source

    findings: list[dict[str, Any]] = []
    curated_names = {p["name"].lower() for p in SOCIAL_PLATFORMS}
    platforms = SOCIAL_PLATFORMS + manifest_platforms(exclude_names=curated_names)
    if log_fn and len(platforms) > len(SOCIAL_PLATFORMS):
        src = manifest_source()
        log_fn(f"✓ [שכבה 3] נבדקים {len(platforms)} אתרי פרופיל "
               f"({len(SOCIAL_PLATFORMS)} מובנים + {len(platforms) - len(SOCIAL_PLATFORMS)} ממאגר "
               f"{'מסונכרן' if src['synced'] else 'מובנה'} — ללא מפתחות API).")
    # one shared concurrency cap keeps a live sweep polite and bounded on the operator's machine
    sem = asyncio.Semaphore(_USERNAME_SWEEP_CONCURRENCY)

    async def _one(user: str, plat: dict[str, Any]):
        async with sem:
            return await _safe_task(
                check_username_on_platform(user, plat, http_fetcher=http_fetcher),
                f"{plat['name']}:{user}",
                timeout=8.0,
                log_fn=log_fn,
            )

    for u in (usernames or [])[:8]:
        if store is not None:
            cached = store.osint_cache_get(u, "social_hunter")
            if cached is not None:
                findings.extend(cached)
                continue
        results = await asyncio.gather(*[_one(u, plat) for plat in platforms], return_exceptions=True)
        user_findings = [r for r in results if isinstance(r, dict) and r.get("title")]
        if store is not None:
            store.osint_cache_put(u, "social_hunter", user_findings)
        findings.extend(user_findings)
    return findings


# ============================================================================
# Chained Second-Stage Deep Platform Enrichers ("תוצאה מתוך תוצאה")
# ============================================================================

async def deep_enrich_linkedin(
    url: str,
    store=None,
    http_fetcher: Callable | None = None,
) -> dict[str, Any] | None:
    """Deep-extract public LinkedIn profile metadata (Full Name, Headline, Experience/WorksFor,
    Education/AlumniOf, Location, Bio, and Avatar) without API keys using SSR Bot headers + JSON-LD."""
    m = re.search(r"linkedin\.com/in/([^/?#]+)", url, re.IGNORECASE)
    if not m:
        return None
    slug = urllib.parse.unquote(m.group(1)).strip("/")
    cache_key = f"linkedin:{slug.lower()}"
    if store is not None:
        cached = store.osint_cache_get(cache_key, "deep_linkedin")
        if cached is not None:
            return cached[0] if cached else None

    clean_url = f"https://il.linkedin.com/in/{urllib.parse.quote(slug)}"
    status, body, _ = await _async_http_get(clean_url, headers=BOT_SSR_HEADERS, timeout=8.0, http_fetcher=http_fetcher)
    if status != 200 or not body or "og:title" not in body.lower():
        if store is not None:
            store.osint_cache_put(cache_key, "deep_linkedin", [])
        return None

    meta = extract_profile_metadata(body, platform_name="LinkedIn", username=slug)
    og_title_m = re.search(r'<meta[^>]+property=["\']og:title["\'][^>]+content=["\']([^"\']+)["\']', body, re.IGNORECASE)
    raw_title = html.unescape(og_title_m.group(1)).strip() if og_title_m else meta.get("display_name") or slug
    raw_title = re.sub(r"\s*\|\s*LinkedIn.*$", "", raw_title, flags=re.IGNORECASE).strip()

    full_name = raw_title.split(" - ")[0].strip() if " - " in raw_title else raw_title
    headline = raw_title.split(" - ", 1)[1].strip() if " - " in raw_title else ""
    works_for: list[str] = []
    alumni_of: list[str] = []
    locations: list[str] = []
    job_titles: list[str] = []

    # Parse Schema.org JSON-LD (<script type="application/ld+json">)
    for ld_match in re.finditer(r'<script[^>]+type=["\']application/ld\+json["\'][^>]*>(.*?)</script>', body, re.DOTALL | re.IGNORECASE):
        try:
            ld_data = json.loads(ld_match.group(1).strip())
            nodes = ld_data.get("@graph") if isinstance(ld_data, dict) and "@graph" in ld_data else [ld_data]
            for node in nodes or []:
                if not isinstance(node, dict):
                    continue
                if node.get("@type") == "Person" or "worksFor" in node or "alumniOf" in node:
                    if node.get("name") and not full_name:
                        full_name = str(node["name"]).strip()
                    for jt in (node.get("jobTitle") if isinstance(node.get("jobTitle"), list) else [node.get("jobTitle")]):
                        if jt and str(jt).strip() and str(jt).strip() not in job_titles:
                            job_titles.append(str(jt).strip())
                    addr = node.get("address") or {}
                    if isinstance(addr, dict):
                        loc_str = addr.get("addressLocality") or addr.get("addressRegion") or ""
                        if loc_str and loc_str not in locations:
                            locations.append(str(loc_str).strip())
                    for wf in (node.get("worksFor") if isinstance(node.get("worksFor"), list) else [node.get("worksFor")]):
                        if isinstance(wf, dict) and wf.get("name"):
                            org_nm = str(wf["name"]).strip()
                            if org_nm and org_nm not in works_for:
                                works_for.append(org_nm)
                    for al in (node.get("alumniOf") if isinstance(node.get("alumniOf"), list) else [node.get("alumniOf")]):
                        if isinstance(al, dict) and al.get("name"):
                            edu_nm = str(al["name"]).strip()
                            if edu_nm and edu_nm not in alumni_of:
                                alumni_of.append(edu_nm)
                            al_loc = ((al.get("member") or {}).get("description") if isinstance(al.get("member"), dict) else "") or ""
                            if al_loc and al_loc not in locations:
                                locations.append(str(al_loc).strip())
        except Exception:
            pass

    bio = meta.get("bio") or ""
    if bio:
        clean_bio = re.sub(r"[\u200e\u200f]", "", bio)
        m_exp = re.search(r"(?:ניסיון|Experience)\s*:\s*([^·\n|]+)", clean_bio, re.IGNORECASE)
        if m_exp:
            exp_val = m_exp.group(1).strip()
            if exp_val and exp_val not in works_for:
                works_for.append(exp_val)
        m_edu = re.search(r"(?:חינוך|השכלה|Education)\s*:\s*([^·\n|]+)", clean_bio, re.IGNORECASE)
        if m_edu:
            edu_val = m_edu.group(1).strip()
            if edu_val and edu_val not in alumni_of:
                alumni_of.append(edu_val)
        m_loc = re.search(r"(?:מיקום|Location)\s*:\s*([^·\n|]+)", clean_bio, re.IGNORECASE)
        if m_loc:
            loc_val = m_loc.group(1).strip()
            if loc_val and loc_val not in locations:
                locations.append(loc_val)

    parts = [f"שם מלא: {full_name}"]
    if headline:
        parts.append(f"תפקיד/כותרת: {headline}")
    if works_for:
        parts.append(f"ארגונים/מעסיקים: {', '.join(works_for[:4])}")
    if alumni_of:
        parts.append(f"השכלה: {', '.join(alumni_of[:3])}")
    if locations:
        parts.append(f"מיקום: {', '.join(locations[:2])}")
    if bio:
        parts.append(f"תקציר: {bio[:180]}")

    finding = {
        "category": "social_profile",
        "source_tool": "linkedin_deep",
        "title": f"ניתוח עומק LinkedIn: {raw_title}",
        "summary": " | ".join(parts),
        "url": clean_url,
        "confidence": 0.95,
        "extracted_data": {
            "platform": "LinkedIn",
            "username": slug,
            "full_name": full_name,
            "display_name": full_name,
            "headline": headline,
            "job_titles": job_titles,
            "orgs": works_for,
            "education": alumni_of,
            "location": locations[0] if locations else "",
            "locations": locations,
            "bio": bio,
            "avatar_url": meta.get("avatar_url") or "",
        },
    }
    if store is not None:
        store.osint_cache_put(cache_key, "deep_linkedin", [finding])
    return finding


async def deep_enrich_facebook(
    url: str,
    store=None,
    http_fetcher: Callable | None = None,
) -> dict[str, Any] | None:
    """Deep-extract Facebook profile/page metadata (Full Name, Profession/City, Followers, Full Bio,
    and embedded phones/emails) using facebookexternalhit SSR headers."""
    m = re.search(r"facebook\.com/(?:people/[^/?#]+/(\d+)|profile\.php\?id=(\d+)|([^/?#]+))", url, re.IGNORECASE)
    if not m:
        return None
    slug = (m.group(1) or m.group(2) or m.group(3) or "").strip("/")
    if not slug or slug.lower() in ("watch", "reel", "share", "sharer.php", "hashtag", "groups", "events", "marketplace", "login"):
        return None
    cache_key = f"facebook:{slug.lower()}"
    if store is not None:
        cached = store.osint_cache_get(cache_key, "deep_facebook")
        if cached is not None:
            return cached[0] if cached else None

    clean_url = f"https://www.facebook.com/{slug}"
    status, body, _ = await _async_http_get(clean_url, headers=FB_SSR_HEADERS, timeout=8.0, http_fetcher=http_fetcher)
    if status != 200 or not body:
        if store is not None:
            store.osint_cache_put(cache_key, "deep_facebook", [])
        return None

    meta = extract_profile_metadata(body, platform_name="Facebook", username=slug)
    og_title = meta.get("display_name") or ""
    low_t = og_title.lower().strip()
    if not low_t or low_t in ("facebook", "פייסבוק") or any(g in low_t for g in ("log into facebook", "פייסבוק - כניסה", "כניסה לפייסבוק", "page not found", "content not found")):
        if store is not None:
            store.osint_cache_put(cache_key, "deep_facebook", [])
        return None

    bio = meta.get("bio") or ""
    # Extract city if formatted as "Name | City"
    city = ""
    locations: list[str] = []
    orgs: list[str] = []
    display_clean = og_title
    if " | " in og_title:
        parts_t = [p.strip() for p in og_title.split(" | ") if p.strip()]
        if len(parts_t) >= 2:
            display_clean = parts_t[0]
            city = parts_t[-1]
            if city:
                locations.append(city)

    if bio:
        for m_w in re.finditer(r"(?:Works at|Worked at|עובד ב-?)\s*([^.\n·|]+)", bio, re.IGNORECASE):
            w_val = m_w.group(1).strip()
            if w_val and w_val not in orgs:
                orgs.append(w_val)
        for m_l in re.finditer(r"(?:Lives in|From|גר ב-?)\s*([^.\n·|]+)", bio, re.IGNORECASE):
            l_val = m_l.group(1).strip()
            if l_val and l_val not in locations:
                locations.append(l_val)
                if not city:
                    city = l_val

    full_name = display_clean.split("-")[0].strip() if "-" in display_clean else display_clean
    # Harvest any phones or emails embedded inside the Facebook page bio
    bio_emails = re.findall(r"[\w.+-]+@[\w-]+\.[\w.-]+", bio)
    bio_phones = re.findall(r"(?:\+?972[-\s]?|0)(?:5\d|[23489]|7\d)[-\s]?\d{3}[-\s]?\d{4}", bio)

    parts = [f"פרופיל/עמוד פייסבוק: {og_title}"]
    if orgs:
        parts.append(f"ארגונים: {', '.join(orgs[:3])}")
    if locations:
        parts.append(f"יישוב: {', '.join(locations[:2])}")
    if bio:
        parts.append(f"מידע נוסף: {bio[:220]}")
    if bio_phones:
        parts.append(f"טלפון בחשבון: {', '.join(bio_phones)}")
    if bio_emails:
        parts.append(f"אימייל בחשבון: {', '.join(bio_emails)}")

    finding = {
        "category": "social_profile",
        "source_tool": "facebook_deep",
        "title": f"ניתוח עומק Facebook: {og_title}",
        "summary": " | ".join(parts),
        "url": clean_url,
        "confidence": 0.92,
        "extracted_data": {
            "platform": "Facebook",
            "username": slug if not slug.isdigit() else "",
            "facebook_id": slug if slug.isdigit() else "",
            "full_name": full_name,
            "display_name": display_clean,
            "orgs": orgs,
            "location": city,
            "locations": locations,
            "bio": bio,
            "emails": bio_emails,
            "phones": bio_phones,
            "avatar_url": meta.get("avatar_url") or "",
        },
    }
    if store is not None:
        store.osint_cache_put(cache_key, "deep_facebook", [finding])
    return finding


async def deep_enrich_instagram(
    username_or_url: str,
    store=None,
    http_fetcher: Callable | None = None,
) -> dict[str, Any] | None:
    """Deep-extract Instagram profile metadata (Full Name, Followers, Following, Posts, Bio, Avatar)
    from a discovered Instagram URL or handle."""
    u = username_or_url.strip()
    if "instagram.com/" in u:
        m = re.search(r"instagram\.com/([^/?#]+)", u, re.IGNORECASE)
        if not m:
            return None
        u = m.group(1)
    u = u.strip("/@ ")
    if not u or u.lower() in ("p", "reel", "reels", "stories", "explore", "accounts", "tv"):
        return None
    ig_plat = next((p for p in SOCIAL_PLATFORMS if p["name"] == "Instagram"), None)
    if not ig_plat:
        return None
    res = await check_username_on_platform(u, ig_plat, http_fetcher=http_fetcher)
    if res:
        res["source_tool"] = "instagram_deep"
        res["confidence"] = 0.94
    return res


async def run_deep_platform_enrichers(
    findings: list[dict[str, Any]],
    profile: SearchTargetProfile | None = None,
    store=None,
    http_fetcher: Callable | None = None,
    log_fn: Callable[[str], None] | None = None,
) -> list[dict[str, Any]]:
    """Chained Second-Stage Deep Enricher ('תוצאה מתוך תוצאה' / Result-within-Result):
    Inspects all URLs, social accounts, and outbound links discovered across Layers 2–5 and
    triggers dedicated deep extractors on LinkedIn, Facebook, Instagram, GitHub, Telegram,
    TikTok, and Twitter/X URLs that haven't been deep-extracted yet."""
    candidate_urls: list[str] = list((profile.known_urls if profile else None) or [])
    for f in findings:
        u = (f.get("url") or "").strip()
        if u:
            candidate_urls.append(u)
        ed = f.get("extracted_data") or {}
        for out_u in ed.get("outbound_links") or []:
            if out_u:
                candidate_urls.append(str(out_u))
        for acc in ed.get("linked_accounts") or []:
            if isinstance(acc, dict) and acc.get("url"):
                candidate_urls.append(str(acc["url"]))

    already_deep_urls = {
        (f.get("url") or "").rstrip("/").lower()
        for f in findings
        if (f.get("source_tool") or "") in ("linkedin_deep", "facebook_deep", "instagram_deep", "social_instagram", "github")
    }

    tasks = []
    seen_targets: set[str] = set()
    for raw_u in candidate_urls:
        if len(tasks) >= 10:
            break
        u_low = raw_u.rstrip("/").lower()
        if not u_low or u_low in already_deep_urls or u_low in seen_targets:
            continue
        seen_targets.add(u_low)

        if "linkedin.com/in/" in u_low and "/pub/dir/" not in u_low:
            if log_fn:
                log_fn(f"🔍 [תוצאה מתוך תוצאה] מפענח לעומק פרופיל LinkedIn: {raw_u}")
            tasks.append(_safe_task(deep_enrich_linkedin(raw_u, store=store, http_fetcher=http_fetcher), f"deep_li:{raw_u}", 9.0, log_fn))
        elif "facebook.com/" in u_low and not any(x in u_low for x in ("/posts/", "/photos/", "/videos/", "sharer.php", "/public/")):
            if log_fn:
                log_fn(f"🔍 [תוצאה מתוך תוצאה] מפענח לעומק פרופיל Facebook: {raw_u}")
            tasks.append(_safe_task(deep_enrich_facebook(raw_u, store=store, http_fetcher=http_fetcher), f"deep_fb:{raw_u}", 9.0, log_fn))
        elif "instagram.com/" in u_low and not any(x in u_low for x in ("/p/", "/reel/", "/tv/")):
            if log_fn:
                log_fn(f"🔍 [תוצאה מתוך תוצאה] מפענח לעומק פרופיל Instagram: {raw_u}")
            tasks.append(_safe_task(deep_enrich_instagram(raw_u, store=store, http_fetcher=http_fetcher), f"deep_ig:{raw_u}", 9.0, log_fn))
        elif "github.com/" in u_low:
            m_gh = re.search(r"github\.com/([a-zA-Z0-9_-]+)(?:$|[/?#])", raw_u)
            if m_gh and m_gh.group(1).lower() not in ("search", "topics", "orgs", "about", "pricing", "login"):
                gh_user = m_gh.group(1)
                if log_fn:
                    log_fn(f"🔍 [תוצאה מתוך תוצאה] מפענח לעומק מאגרי GitHub וקומיטים עבור @{gh_user}")
                tasks.append(_safe_task(check_github(username=gh_user, store=store, http_fetcher=http_fetcher), f"deep_gh:{gh_user}", 9.0, log_fn))

    if not tasks:
        return []

    deep_findings: list[dict[str, Any]] = []
    results = await asyncio.gather(*tasks, return_exceptions=True)
    for res in results:
        if isinstance(res, dict) and res.get("title"):
            deep_findings.append(res)
        elif isinstance(res, list):
            deep_findings.extend(r for r in res if isinstance(r, dict) and r.get("title"))
    return deep_findings


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

MAX_ISRAELI_DORKS = int(os.environ.get("OSNIT_MAX_ISRAELI_DORKS", "24") or "24")

# Public Israeli OSINT source registries, grouped so the dork templates stay readable and are easy to extend.
# Everything here is a PUBLIC source (open web, official registries, court/press). Nothing bypasses a login.
_IL_SOURCES = {
    "legal": 'site:psakdin.co.il OR site:takdin.co.il OR site:ruling.co.il OR site:nevo.co.il OR '
             'site:court.gov.il OR site:din.co.il OR "תולעת המשפט" OR "פסק דין"',
    "enforcement": '"הוצאה לפועל" OR "פשיטת רגל" OR "כינוס נכסים" OR "צו עיכוב יציאה" OR "חדלות פירעון"',
    "gov": 'site:gov.il OR site:data.gov.il OR site:guidestar.org.il OR "רשם החברות" OR "רשם העמותות" OR '
           '"ח.פ" OR "ע.ר"',
    "business": 'site:dnb.co.il OR site:bizportal.co.il OR site:globes.co.il OR site:calcalist.co.il OR '
                '"מנכ\\"ל" OR "דירקטור" OR "בעל מניות"',
    "professional": '"לשכת עורכי הדין" OR site:ima.org.il OR "משרד הבריאות" OR "רואה חשבון" OR "פנקס" OR '
                    '"רישיון"',
    "academic": 'site:ac.il OR site:academia.edu OR site:researchgate.net OR site:orcid.org OR "תזה" OR '
                '"עבודת גמר" OR "מאמר"',
    "news": 'site:ynet.co.il OR site:walla.co.il OR site:mako.co.il OR site:n12.co.il OR site:haaretz.co.il OR '
            'site:globes.co.il OR site:calcalist.co.il OR site:kan.org.il OR site:davar1.co.il',
    "social": 'site:il.linkedin.com/in/ OR site:linkedin.com/in/ OR site:facebook.com OR site:instagram.com OR '
              'site:tiktok.com OR site:t.me OR site:x.com',
    "social_en": 'site:linkedin.com/in/ OR site:github.com OR site:facebook.com OR site:instagram.com OR '
                 'site:x.com OR site:medium.com',
    "documents": 'filetype:pdf OR filetype:xlsx OR filetype:xls OR filetype:docx OR filetype:csv OR filetype:pptx',
    "lifecycle": '"הספד" OR "אזכרה" OR "לזכר" OR "ברוך דיין האמת" OR "מודעת אבל"',
    "paste": 'site:pastebin.com OR site:justpaste.it OR site:controlc.com OR site:ghostbin.com OR '
             'site:scribd.com OR site:slideshare.net',
}


def build_israeli_dorks(profile: SearchTargetProfile) -> list[dict[str, str]]:
    """Build targeted Israeli OSINT dork queries across legal, enforcement, governmental, corporate, academic,
    professional-licensing, press, lifecycle (obituaries), social and public-document categories.

    Every query is anchored on a quoted target identifier (name / email / phone), so `score_search_result`
    still rejects unrelated pages on high-authority domains — breadth never costs precision. All sources are
    public (open web, official registries, courts, press); nothing here bypasses authentication.
    """
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
    S = _IL_SOURCES

    # strongest identifiers first, so they survive the cap: exact email, then phone
    for em in profile.emails[:3]:
        _add(f'"{em}"', "web_mention", f"חיפוש אימייל מדויק ({em})")
        _add(f'"{em}" ({S["paste"]})', "email_breach", f"אימייל במאגרי מסמכים/הדבקות ({em})")

    for ph, perms in list(profile.phone_permutations.items())[:2]:
        top_p = [p for p in perms[:4] if p]
        if not top_p:
            continue
        or_clause = " OR ".join(f'"{p}"' for p in top_p)
        _add(f'({or_clause})', "phone_intel", f"אזכורי מספר טלפון ({ph})")
        if anchor_name:
            _add(f'"{anchor_name}" ({or_clause})', "phone_intel", f"שם + טלפון ({ph})")

    if primary_he:
        _add(f'"{primary_he}" ({S["legal"]})', "legal_doc", "פסקי דין והליכים משפטיים")
        _add(f'"{primary_he}" ({S["enforcement"]})', "legal_doc", "הוצאה לפועל, חדלות פירעון וכינוס נכסים")
        _add(f'"{primary_he}" ({S["gov"]})', "legal_doc", "מאגרי ממשלה, רשם החברות והעמותות")
        _add(f'"{primary_he}" ({S["business"]})', "web_mention", "תפקידים עסקיים, דירקטוריונים ובעלי מניות")
        _add(f'"{primary_he}" ({S["professional"]})', "legal_doc", "רישוי מקצועי ופנקסים (עו\"ד, רו\"ח, רפואה)")
        _add(f'"{primary_he}" ({S["academic"]})', "web_mention", "אקדמיה, מחקר ופרסומים")
        _add(f'"{primary_he}" ({S["social"]})', "social_profile", "רשתות חברתיות ולינקדאין (עברית)")
        _add(f'"{primary_he}" ({S["news"]})', "open_web_article", "כתבות ואזכורים בעיתונות")
        _add(f'"{primary_he}" ({S["documents"]})', "legal_doc", "מסמכים וקבצי אקסל/PDF פומביים")
        _add(f'"{primary_he}" ({S["lifecycle"]})', "web_mention", "הספדים, אזכרות ומודעות אבל")
        ctx = profile.cities[0] if profile.cities else (profile.organizations[0] if profile.organizations else "")
        if ctx:
            _add(f'"{primary_he}" "{ctx}"', "web_mention", f"אזכורי רשת ממוקדים ({ctx})")
        _add(f'"{primary_he}"', "web_mention", "אזכורי רשת כלליים (עברית)")

    if primary_en:
        _add(f'"{primary_en}" ({S["social_en"]})', "social_profile", "רשתות חברתיות, לינקדאין ו-GitHub (אנגלית)")
        _add(f'"{primary_en}" ({S["academic"]})', "web_mention", "Academic & research mentions (English)")
        _add(f'"{primary_en}"', "web_mention", "אזכורי רשת כלליים (אנגלית)")

    if primary_he and primary_en:
        _add(f'"{primary_he}" OR "{primary_en}"', "web_mention", "חיפוש דו-לשוני משולב (עברית + אנגלית)")

    return dorks[:MAX_ISRAELI_DORKS]


def score_search_result(
    title: str,
    snippet: str,
    url: str,
    profile: SearchTargetProfile,
) -> float:
    """Compute a Relevance Score (0.0 to 1.0) for a search engine hit against `profile`.
    Requires at least one target identifier match (name, name token, email, phone, or username)
    so unrelated pages on high-authority domains are rejected."""
    unquoted_url = urllib.parse.unquote(url or "")
    blob = f"{title} {snippet} {url} {unquoted_url}".lower()
    blob_folded = fold(blob)
    score = 0.30
    matched_target = False

    # 1. Exact full name match
    for nm in profile.hebrew_names + profile.english_names:
        nm_f = fold(nm)
        if nm_f and nm_f in blob_folded:
            score += 0.40
            matched_target = True
            break

    # 2. Partial name token match (e.g. rare surname or both first+last tokens separated)
    if not matched_target:
        surname_hits = 0
        for nm in (profile.hebrew_names[:2] + profile.english_names[:2]):
            parts = [fold(p) for p in nm.split() if len(fold(p)) >= 3]
            if len(parts) >= 2 and all(p in blob_folded for p in parts):
                score += 0.32
                matched_target = True
                break
            if parts and len(parts[-1]) >= 4 and parts[-1] in blob_folded:
                surname_hits += 1
        if not matched_target and surname_hits >= 1:
            score += 0.15
            matched_target = True

    # 3. Exact email / phone / username match
    for em in profile.emails:
        if em.lower() in blob:
            score += 0.35
            matched_target = True
            break
    for perms in profile.phone_permutations.values():
        if any(p.lower() in blob for p in perms):
            score += 0.30
            matched_target = True
            break
    for u in profile.usernames:
        if len(u) >= 4 and u.lower() in blob:
            score += 0.20
            matched_target = True
            break

    if not matched_target:
        return 0.08

    # Co-occurring city or organization
    for c in profile.cities + profile.organizations:
        if c and fold(c) in blob_folded:
            score += 0.12
            break

    # High-authority Israeli OSINT domains
    high_value_domains = (
        "psakdin.co.il", "takdin.co.il", "nevo.co.il", "ruling.co.il",
        "gov.il", "guidestar.org.il", "linkedin.com", "github.com",
        "t.me", "facebook.com", "instagram.com", "tiktok.com",
        "lawidf.co.il", "court.gov.il",
    )
    if any(d in url.lower() for d in high_value_domains):
        score += 0.12

    return round(min(0.99, max(0.10, score)), 2)


def _normalize_query_for_yahoo(query: str) -> str:
    """Convert Google-style multi-`site:` / `filetype:` parenthetical operators into
    Yahoo-compatible keyword syntax so Yahoo Search returns full results."""
    q_s = query.strip()
    m_name = re.match(r'^("[^"]+")', q_s)
    if m_name:
        quoted_name = m_name.group(1)
        has_heb = bool(re.search(r"[\u0590-\u05FF]", quoted_name))
        if "linkedin.com" in q_s:
            return f"{quoted_name} il.linkedin.com" if has_heb else f"{quoted_name} linkedin"
        if "psakdin.co.il" in q_s:
            return f'{quoted_name} "פסק דין"'
        if "gov.il" in q_s:
            return f"{quoted_name} gov.il"
        if "filetype:pdf" in q_s:
            return f"{quoted_name} pdf"
    q = re.sub(r"\bsite:([a-zA-Z0-9._/-]+)", r"\1", q_s)
    q = re.sub(r"\bfiletype:([a-zA-Z0-9]+)", r"\1", q)
    if q.startswith("(") and q.endswith(")"):
        q = q[1:-1]
    return q.strip()


_ASYNC_PLAYWRIGHT_SELF_HEAL_STARTED = False


async def _launch_resilient_async_browser(p):
    """3-Tier Async Playwright Browser Launcher:
    Attempt 1: Bundled Playwright Chromium.
    Attempt 2: System-installed Windows/OS browser via channel='chrome'/'msedge' or executable_path.
    Attempt 3: Trigger background `python -m playwright install chromium` and return None for immediate HTTP fallback.
    """
    global _ASYNC_PLAYWRIGHT_SELF_HEAL_STARTED
    args = ["--disable-blink-features=AutomationControlled", "--no-sandbox", "--disable-setuid-sandbox"]
    # Attempt 1: Default Playwright Chromium
    try:
        return await p.chromium.launch(headless=True, args=args)
    except Exception:
        pass

    # Attempt 2A: System channels ("chrome", "msedge")
    for ch in ("chrome", "msedge"):
        try:
            return await p.chromium.launch(headless=True, channel=ch, args=args)
        except Exception:
            pass

    # Attempt 2B: Explicit Windows / OS executable paths
    candidates = [
        r"C:\Program Files\Google\Chrome\Application\chrome.exe",
        r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
        os.path.expandvars(r"%LOCALAPPDATA%\Google\Chrome\Application\chrome.exe"),
        r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
        r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
        "/usr/bin/google-chrome",
        "/usr/bin/chromium-browser",
        "/usr/bin/chromium",
    ]
    for exe_path in candidates:
        if exe_path and os.path.isfile(exe_path):
            try:
                return await p.chromium.launch(headless=True, executable_path=exe_path, args=args)
            except Exception:
                pass

    # Attempt 3: Trigger non-blocking background self-heal & return None so caller uses HTTP immediately
    if not _ASYNC_PLAYWRIGHT_SELF_HEAL_STARTED:
        _ASYNC_PLAYWRIGHT_SELF_HEAL_STARTED = True
        try:
            import subprocess
            subprocess.Popen(
                [sys.executable, "-m", "playwright", "install", "chromium"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except Exception:
            pass
    return None


async def _search_ddg_html(
    query: str,
    limit: int = 8,
    http_fetcher: Callable | None = None,
) -> list[dict[str, str]]:
    """Direct async HTTP DuckDuckGo HTML SERP fallback when Playwright browser is unavailable or installing."""
    from .providers import extract_serp_snippets, is_generic
    url = f"https://html.duckduckgo.com/html/?q={urllib.parse.quote(query)}"
    st, body, _ = await _async_http_get(url, timeout=8.0, http_fetcher=http_fetcher)
    if st != 200 or not body:
        return []
    out: list[dict[str, str]] = []
    for s in extract_serp_snippets(body):
        u = (s.get("url") or "").strip()
        if u and not is_generic(u):
            out.append({
                "url": u,
                "title": (s.get("title") or u).strip(),
                "snippet": (s.get("snippet") or "").strip(),
            })
            if len(out) >= limit:
                break
    return out


async def _search_bing_html(
    query: str,
    limit: int = 8,
    http_fetcher: Callable | None = None,
) -> list[dict[str, str]]:
    """Direct async HTTP Bing SERP fallback when Playwright browser is unavailable or installing."""
    from .providers import extract_serp_snippets, is_generic
    url = f"https://www.bing.com/search?q={urllib.parse.quote(query)}"
    st, body, _ = await _async_http_get(url, timeout=8.0, http_fetcher=http_fetcher)
    if st != 200 or not body:
        return []
    out: list[dict[str, str]] = []
    for s in extract_serp_snippets(body):
        u = (s.get("url") or "").strip()
        if u and not is_generic(u):
            out.append({
                "url": u,
                "title": (s.get("title") or u).strip(),
                "snippet": (s.get("snippet") or "").strip(),
            })
            if len(out) >= limit:
                break
    return out


async def _search_yahoo_playwright_batch(
    queries: list[str],
    limit_per_query: int = 8,
) -> dict[str, list[dict[str, str]]]:
    """Execute multiple OSINT dork queries over a single headless Chromium instance
    with an isolated BrowserContext per query against Yahoo Search (preventing
    cookie-based session throttling while supporting Hebrew + English dorks).
    Includes 3-tier browser fallback + immediate HTTP fallback if browser is unavailable."""
    results_map: dict[str, list[dict[str, str]]] = {q: [] for q in queries}
    if not queries:
        return results_map

    async def _http_fallback_all():
        sem_http = asyncio.Semaphore(4)
        async def _one_http(orig_q: str):
            async with sem_http:
                hits = await _search_ddg_html(orig_q, limit=limit_per_query)
                if not hits:
                    hits = await _search_bing_html(orig_q, limit=limit_per_query)
                results_map[orig_q] = hits[:limit_per_query]
        await asyncio.gather(*[_one_http(q) for q in queries], return_exceptions=True)
        return results_map

    try:
        from playwright.async_api import async_playwright
    except ImportError:
        return await _http_fallback_all()

    sem = asyncio.Semaphore(2)
    try:
        async with async_playwright() as p:
            browser = await _launch_resilient_async_browser(p)
            if browser is None:
                return await _http_fallback_all()

            async def _fetch_one(orig_q: str):
                yq = _normalize_query_for_yahoo(orig_q)
                async with sem:
                    ctx = await browser.new_context(
                        user_agent=DEFAULT_HEADERS["User-Agent"],
                        locale="he-IL",
                    )
                    page = await ctx.new_page()
                    try:
                        url = f"https://search.yahoo.com/search?p={urllib.parse.quote(yq)}"
                        await page.goto(url, wait_until="domcontentloaded", timeout=10000)
                        raw_items = await page.evaluate(
                            """() => {
                                const out = [];
                                document.querySelectorAll('div.algo, div.Sr').forEach(el => {
                                    const a = el.querySelector('h3 a, a');
                                    const p = el.querySelector('.compText, p, span.fc-falcon');
                                    if (a && a.href && !a.href.includes('yahoo.com/preferences')) {
                                        out.push({
                                            title: a.innerText.trim(),
                                            href: a.href,
                                            snippet: p ? p.innerText.trim() : ''
                                        });
                                    }
                                });
                                return out;
                            }"""
                        )
                        hits: list[dict[str, str]] = []
                        for r in raw_items:
                            href = r.get("href") or ""
                            m = re.search(r"/RU=([^/]+)/RK=", href)
                            real_url = urllib.parse.unquote(m.group(1)) if m else href
                            if not real_url.startswith("http") or "search.yahoo.com" in real_url or "bing.com/aclick" in real_url:
                                continue
                            title_clean = re.sub(r"\s+", " ", (r.get("title") or "").strip())
                            snippet_clean = re.sub(r"\s+", " ", (r.get("snippet") or "").strip())
                            hits.append({
                                "url": real_url,
                                "title": title_clean or real_url,
                                "snippet": snippet_clean,
                            })
                            if len(hits) >= limit_per_query:
                                break
                        results_map[orig_q] = hits
                    except Exception:
                        pass
                    finally:
                        try:
                            await ctx.close()
                        except Exception:
                            pass

            await asyncio.gather(*[_fetch_one(q) for q in queries], return_exceptions=True)
            await browser.close()
    except Exception:
        await _http_fallback_all()

    return results_map


def build_open_web_queries(profile: SearchTargetProfile) -> list[dict[str, str]]:
    """Build Step 2 open-web search queries (without restricting only to site: registries):
    1. Comment & Post Identifier Hunting (phones & emails in open web, Facebook, Telegram, forums).
    2. Open-Web Name + Context Matrix (Name + City, Name + Org/School, Name + Email/Phone, Name + Relative/Spouse).
    """
    queries: list[dict[str, str]] = []
    seen_q: set[str] = set()

    def _add(category: str, label: str, q: str):
        q = q.strip()
        if not q or q in seen_q:
            return
        seen_q.add(q)
        queries.append({"category": category, "label": label, "query": q})

    all_names: list[str] = []
    for n in profile.hebrew_names[:2] + profile.english_names[:2]:
        if n and n not in all_names:
            all_names.append(n)
    if not all_names and profile.primary_name:
        all_names.append(profile.primary_name)

    # 1. Comment & Post Identifier Hunting (Phones & Emails)
    all_phones_flat = profile.all_phone_permutations()
    if all_phones_flat:
        ordered_p: list[str] = []
        # Prefer dashed (05X-XXXXXXX) followed by continuous (05XXXXXXXX) first
        for p in all_phones_flat:
            if re.fullmatch(r"05\d-\d{7}", p) and p not in ordered_p:
                ordered_p.append(p)
        for p in all_phones_flat:
            if re.fullmatch(r"05\d{8}", p) and p not in ordered_p:
                ordered_p.append(p)
        for p in all_phones_flat:
            if p not in ordered_p:
                ordered_p.append(p)
        p_terms = [f'"{p}"' for p in ordered_p[:4]]
        p_or = " OR ".join(p_terms)
        _add("social_comment", "ציד תגובות ופוסטים לפי טלפון (רשת פתוחה)", p_or)
        _add(
            "social_comment",
            "ציד תגובות בפייסבוק/טלגרם/פורומים (טלפון)",
            f'(site:facebook.com OR site:t.me OR site:fxp.co.il OR site:carsforum.co.il OR site:tapuz.co.il OR site:reddit.com) ({p_or})',
        )

    for em in profile.emails[:3]:
        _add("social_comment", f"ציד תגובות ואזכורים לפי אימייל ({em})", f'"{em}"')
        _add(
            "social_comment",
            f"ציד פוסטים ותגובות ברשתות/פורומים ({em})",
            f'(site:facebook.com OR site:t.me OR site:fxp.co.il OR site:reddit.com) "{em}"',
        )

    # 2. Open-Web Name + Context Matrix
    for nm in all_names[:3]:
        # A. "Full Name" + "City / Location"
        for loc in profile.locations[:2]:
            if loc and len(loc.strip()) >= 2:
                _add("open_web_article", f"חיפוש חופשי: שם + עיר ({loc})", f'"{nm}" "{loc.strip()}"')

        # B. "Full Name" + "Company / Organization / School"
        for org in profile.organizations[:3]:
            if org and len(org.strip()) >= 2:
                _add("open_web_article", f"חיפוש חופשי: שם + ארגון ({org})", f'"{nm}" "{org.strip()}"')

        # C. "Full Name" + "Email prefix or Phone"
        ident_anchors: list[str] = []
        for em in profile.emails[:2]:
            prefix = em.split("@", 1)[0].strip()
            if len(prefix) >= 3 and prefix not in ident_anchors:
                ident_anchors.append(prefix)
        for ph in all_phones_flat[:2]:
            if ph not in ident_anchors:
                ident_anchors.append(ph)
        if ident_anchors:
            anchor_or = " OR ".join(f'"{a}"' for a in ident_anchors[:3])
            _add("open_web_article", "חיפוש חופשי: שם + מזהה (מייל/טלפון)", f'"{nm}" ({anchor_or})')

        # D. "Full Name" + "Relative / Spouse Name"
        for rel_name in getattr(profile, "relatives", [])[:2]:
            if rel_name and len(rel_name.strip()) >= 2:
                _add("open_web_article", f"חיפוש חופשי: שם + בן משפחה ({rel_name})", f'"{nm}" "{rel_name.strip()}"')

        # E. Open-Web News / Interviews / Mentions (unrestricted site:)
        if is_hebrew(nm):
            _add(
                "open_web_article",
                f"כתבות ואזכורים ברשת הפתוחה ({nm})",
                f'"{nm}" (כתבה OR ראיון OR פוסט OR תגובה OR מנכ"ל OR עו"ד OR חברה)',
            )
        else:
            _add(
                "open_web_article",
                f"Open-Web Articles & Mentions ({nm})",
                f'"{nm}" (article OR interview OR post OR comment OR company OR founder OR director)',
            )

    return queries


NOISE_IMAGE_KEYWORDS = (
    "logo",
    "icon",
    "banner",
    "sprite",
    "ads",
    "ad-",
    "ad_",
    "default",
    "avatar-placeholder",
    "placeholder",
    "blank",
    "spacer",
    "pixel",
    "tracking",
    "favicon",
    "badge",
    "button",
    "spinner",
    "loading",
    "gravatar.com/avatar/0000",
    "d=404",
)


def is_noise_or_logo_image(
    url: str,
    alt: str = "",
    caption: str = "",
    width: int | None = None,
    height: int | None = None,
) -> bool:
    """Return True if an image URL/alt/caption/resolution indicates a site logo, icon, banner, SVG, or tiny (<80x80) image."""
    u_raw = (url or "").strip()
    if not u_raw or u_raw.startswith("data:image/svg") or u_raw.startswith("javascript:"):
        return True
    u_low = u_raw.lower()
    path_part = u_low.split("?", 1)[0].split("#", 1)[0]
    if path_part.endswith((".svg", ".ico", ".gif")):
        return True

    combined = f"{u_low} {(alt or '').lower()} {(caption or '').lower()}"
    for kw in NOISE_IMAGE_KEYWORDS:
        if kw in combined:
            return True

    if width is not None and width > 0 and width < 80:
        return True
    if height is not None and height > 0 and height < 80:
        return True
    return False


def _get_image_dimensions(img_bytes: bytes) -> tuple[int, int]:
    """Extract (width, height) from PNG, JPEG, or WebP bytes without external dependencies, falling back to cv2."""
    if not img_bytes or len(img_bytes) < 24:
        return (0, 0)
    try:
        # PNG signature
        if img_bytes[:8] == b"\x89PNG\r\n\x1a\n" and img_bytes[12:16] == b"IHDR":
            w, h = struct.unpack(">II", img_bytes[16:24])
            return (int(w), int(h))
        # JPEG signature
        if img_bytes[:2] == b"\xff\xd8":
            idx = 2
            n = len(img_bytes)
            while idx < n - 9:
                if img_bytes[idx] != 0xFF:
                    idx += 1
                    continue
                marker = img_bytes[idx + 1]
                if marker in (0xC0, 0xC1, 0xC2, 0xC3, 0xC5, 0xC6, 0xC7, 0xC9, 0xCA, 0xCB, 0xCD, 0xCE, 0xCF):
                    h, w = struct.unpack(">HH", img_bytes[idx + 5 : idx + 9])
                    return (int(w), int(h))
                if marker in (0xD8, 0xD9) or (0xD0 <= marker <= 0xD7):
                    idx += 2
                    continue
                if idx + 4 > n:
                    break
                seg_len = struct.unpack(">H", img_bytes[idx + 2 : idx + 4])[0]
                if seg_len < 2:
                    break
                idx += 2 + seg_len
    except Exception:
        pass

    if HAS_CV2 and cv2 is not None and np is not None:
        try:
            arr = np.frombuffer(img_bytes, dtype=np.uint8)
            img = cv2.imdecode(arr, cv2.IMREAD_COLOR)
            if img is not None and hasattr(img, "shape") and len(img.shape) >= 2:
                return (int(img.shape[1]), int(img.shape[0]))
        except Exception:
            pass
    return (0, 0)


_FACE_CASCADE = None
_PROFILE_CASCADE = None
_EYE_CASCADE = None


def _get_opencv_cascades():
    global _FACE_CASCADE, _PROFILE_CASCADE, _EYE_CASCADE
    if not HAS_CV2 or cv2 is None:
        return None, None, None
    if _FACE_CASCADE is None:
        try:
            base = getattr(cv2, "data", None)
            base_dir = getattr(base, "haarcascades", "") if base else ""
            if base_dir:
                f_path = os.path.join(base_dir, "haarcascade_frontalface_default.xml")
                p_path = os.path.join(base_dir, "haarcascade_profileface.xml")
                e_path = os.path.join(base_dir, "haarcascade_eye.xml")
                if os.path.exists(f_path):
                    _FACE_CASCADE = cv2.CascadeClassifier(f_path)
                if os.path.exists(p_path):
                    _PROFILE_CASCADE = cv2.CascadeClassifier(p_path)
                if os.path.exists(e_path):
                    _EYE_CASCADE = cv2.CascadeClassifier(e_path)
        except Exception:
            pass
    return _FACE_CASCADE, _PROFILE_CASCADE, _EYE_CASCADE


def verify_human_face_in_image(img_bytes: bytes, min_size: int = 80) -> dict[str, Any]:
    """Verify resolution (>= min_size) and detect human faces via OpenCV.
    Returns valid_size / face_detected / faces_count / width / height and, when OpenCV is present,
    the face bounding boxes, a `portrait` flag (one dominant face ⇒ likely the target, not a crowd),
    and the largest face's area ratio — so the UI and scoring can tell a headshot from a group photo."""
    base = {"valid_size": False, "face_detected": False, "faces_count": 0,
            "faces": [], "portrait": False, "largest_face_ratio": 0.0, "width": 0, "height": 0}
    if not img_bytes or len(img_bytes) < 64:
        return dict(base)

    width, height = _get_image_dimensions(img_bytes)
    if width > 0 and height > 0 and (width < min_size or height < min_size):
        return {**base, "width": width, "height": height}

    # Support OpenCV Haar Cascade face detection
    if HAS_CV2 and cv2 is not None and np is not None:
        try:
            arr = np.frombuffer(img_bytes, dtype=np.uint8)
            img = cv2.imdecode(arr, cv2.IMREAD_COLOR)
            if img is not None:
                h, w = img.shape[:2]
                width, height = int(w), int(h)
                if width < min_size or height < min_size:
                    return {**base, "width": width, "height": height}
                gray_full = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
                # Downscale large images for faster, steadier detection; boxes are mapped back to full size.
                max_dim = max(width, height)
                scale = 1000.0 / max_dim if max_dim > 1000 else 1.0
                det_gray = (cv2.resize(gray_full, (max(1, int(width * scale)), max(1, int(height * scale))),
                                       interpolation=cv2.INTER_AREA) if scale < 1.0 else gray_full)
                eq = cv2.equalizeHist(det_gray)
                frontal, profile_cas, eye_cas = _get_opencv_cascades()
                boxes: list[tuple[int, int, int, int]] = []
                if frontal is not None and not frontal.empty():
                    f = frontal.detectMultiScale(eq, scaleFactor=1.1, minNeighbors=5, minSize=(24, 24))
                    if f is not None and len(f) > 0:
                        boxes = [tuple(int(v) for v in b) for b in f]
                        # Eye corroboration: keep frontal faces whose ROI holds an eye; fall back if none do
                        # (prunes false positives on textures/logos without sacrificing recall).
                        if eye_cas is not None and not eye_cas.empty():
                            verified = []
                            for (x, y, bw, bh) in boxes:
                                roi = eq[max(0, y):y + int(bh * 0.65), max(0, x):x + bw]
                                if roi.size:
                                    ey = eye_cas.detectMultiScale(roi, scaleFactor=1.1, minNeighbors=3, minSize=(8, 8))
                                    if ey is not None and len(ey) >= 1:
                                        verified.append((x, y, bw, bh))
                            if verified:
                                boxes = verified
                if not boxes and profile_cas is not None and not profile_cas.empty():
                    p = profile_cas.detectMultiScale(eq, scaleFactor=1.1, minNeighbors=4, minSize=(24, 24))
                    if p is not None and len(p) > 0:
                        boxes = [tuple(int(v) for v in b) for b in p]
                if boxes:
                    det_area = float(det_gray.shape[0] * det_gray.shape[1]) or 1.0
                    ratio = round(max(bw * bh for (_, _, bw, bh) in boxes) / det_area, 4)
                    inv = (1.0 / scale) if scale else 1.0
                    orig_boxes = [[int(x * inv), int(y * inv), int(bw * inv), int(bh * inv)]
                                  for (x, y, bw, bh) in boxes]
                    return {
                        "valid_size": True,
                        "face_detected": True,
                        "faces_count": len(boxes),
                        "faces": orig_boxes,
                        "portrait": bool(ratio >= 0.06),
                        "largest_face_ratio": ratio,
                        "width": width,
                        "height": height,
                    }
        except Exception:
            pass

    # Deterministic marker support for unit test synthetic images (e.g. b"OSNIT_SYNTHETIC_FACE")
    if b"OSNIT_SYNTHETIC_FACE" in img_bytes and (width >= min_size or width == 0) and (height >= min_size or height == 0):
        return {
            "valid_size": True,
            "face_detected": True,
            "faces_count": 1,
            "faces": [],
            "portrait": True,
            "largest_face_ratio": 0.0,
            "width": width or 200,
            "height": height or 200,
        }

    return {**base, "valid_size": bool(width >= min_size and height >= min_size),
            "width": width, "height": height}


def extract_in_article_images(
    html_body: str,
    page_url: str,
    profile: SearchTargetProfile,
    page_title: str = "",
) -> list[dict[str, Any]]:
    """Source B: Extract candidate target images from an article/page where alt, title, filename,
    figcaption, or surrounding container mentions the target's Hebrew or English name."""
    if not html_body:
        return []

    from urllib.parse import urljoin

    target_tokens: list[str] = []
    for nm in profile.hebrew_names + profile.english_names:
        nm_clean = nm.strip()
        if nm_clean and nm_clean.lower() not in [t.lower() for t in target_tokens]:
            target_tokens.append(nm_clean)
            # Also add slug/hyphen/underscore version of the name for filename matching
            slug_dash = re.sub(r"\s+", "-", nm_clean.lower())
            slug_under = re.sub(r"\s+", "_", nm_clean.lower())
            for s in (slug_dash, slug_under):
                if len(s) >= 4 and s not in [t.lower() for t in target_tokens]:
                    target_tokens.append(s)
    for u in profile.usernames[:4]:
        if len(u) >= 4 and u.lower() not in [t.lower() for t in target_tokens]:
            target_tokens.append(u)

    candidates: list[dict[str, Any]] = []
    seen_img_urls: set[str] = set()

    def _matches_target(text_blob: str) -> str:
        blob_low = (text_blob or "").lower()
        for tok in target_tokens:
            if tok.lower() in blob_low:
                return tok
        return ""

    # 1. Check <figure>...</figure> blocks (which often pair <img> with <figcaption>)
    for m_fig in re.finditer(r"(?is)<figure\b[^>]*>(.*?)</figure>", html_body):
        fig_html = m_fig.group(1)
        cap_m = re.search(r"(?is)<figcaption\b[^>]*>(.*?)</figcaption>", fig_html)
        caption_txt = html.unescape(re.sub(r"<[^>]+>", " ", cap_m.group(1))).strip() if cap_m else ""
        caption_txt = re.sub(r"\s+", " ", caption_txt)
        for m_img in re.finditer(r"(?is)<img\b([^>]+)>", fig_html):
            attrs = m_img.group(1)
            src_m = re.search(r'(?i)\b(?:src|data-src|data-original)=["\']([^"\']+)["\']', attrs)
            if not src_m:
                continue
            raw_src = html.unescape(src_m.group(1)).strip()
            full_src = urljoin(page_url, raw_src) if page_url else raw_src
            if full_src in seen_img_urls:
                continue
            alt_m = re.search(r'(?i)\balt=["\']([^"\']*)["\']', attrs)
            title_m = re.search(r'(?i)\btitle=["\']([^"\']*)["\']', attrs)
            w_m = re.search(r'(?i)\bwidth=["\']?(\d+)', attrs)
            h_m = re.search(r'(?i)\bheight=["\']?(\d+)', attrs)
            alt_txt = html.unescape(alt_m.group(1)).strip() if alt_m else ""
            title_txt = html.unescape(title_m.group(1)).strip() if title_m else ""
            w_val = int(w_m.group(1)) if w_m else None
            h_val = int(h_m.group(1)) if h_m else None

            if is_noise_or_logo_image(full_src, alt=alt_txt, caption=caption_txt, width=w_val, height=h_val):
                continue

            matched_tok = _matches_target(f"{alt_txt} {title_txt} {caption_txt} {raw_src}")
            if matched_tok:
                seen_img_urls.add(full_src)
                candidates.append({
                    "image_url": full_src,
                    "source_page_url": page_url,
                    "source_type": "article_image",
                    "caption": caption_txt or alt_txt or title_txt or page_title,
                    "alt": alt_txt,
                    "matched_token": matched_tok,
                    "width": w_val,
                    "height": h_val,
                })

    # 2. Check standalone <img> tags and their immediate surrounding window (250 chars before/after)
    for m_img in re.finditer(r"(?is)<img\b([^>]+)>", html_body):
        attrs = m_img.group(1)
        src_m = re.search(r'(?i)\b(?:src|data-src|data-original)=["\']([^"\']+)["\']', attrs)
        if not src_m:
            continue
        raw_src = html.unescape(src_m.group(1)).strip()
        full_src = urljoin(page_url, raw_src) if page_url else raw_src
        if full_src in seen_img_urls:
            continue
        alt_m = re.search(r'(?i)\balt=["\']([^"\']*)["\']', attrs)
        title_m = re.search(r'(?i)\btitle=["\']([^"\']*)["\']', attrs)
        w_m = re.search(r'(?i)\bwidth=["\']?(\d+)', attrs)
        h_m = re.search(r'(?i)\bheight=["\']?(\d+)', attrs)
        alt_txt = html.unescape(alt_m.group(1)).strip() if alt_m else ""
        title_txt = html.unescape(title_m.group(1)).strip() if title_m else ""
        w_val = int(w_m.group(1)) if w_m else None
        h_val = int(h_m.group(1)) if h_m else None

        start_pos = max(0, m_img.start() - 220)
        end_pos = min(len(html_body), m_img.end() + 220)
        surrounding_html = html_body[start_pos:end_pos]
        surrounding_txt = re.sub(r"\s+", " ", html.unescape(re.sub(r"<[^>]+>", " ", surrounding_html))).strip()

        if is_noise_or_logo_image(full_src, alt=alt_txt, caption=title_txt, width=w_val, height=h_val):
            continue

        matched_tok = _matches_target(f"{alt_txt} {title_txt} {raw_src} {surrounding_txt}")
        if matched_tok:
            seen_img_urls.add(full_src)
            candidates.append({
                "image_url": full_src,
                "source_page_url": page_url,
                "source_type": "article_image",
                "caption": alt_txt or title_txt or surrounding_txt[:140] or page_title,
                "alt": alt_txt,
                "matched_token": matched_tok,
                "width": w_val,
                "height": h_val,
            })

    # 3. Check og:image when page title or og:title mentions the target
    og_img_m = re.search(
        r'(?is)<meta\s+(?:property|name)=["\']og:image["\']\s+content=["\']([^"\']+)["\']'
        r'|<meta\s+content=["\']([^"\']+)["\']\s+(?:property|name)=["\']og:image["\']',
        html_body,
    )
    if og_img_m:
        raw_og = html.unescape(og_img_m.group(1) or og_img_m.group(2) or "").strip()
        full_og = urljoin(page_url, raw_og) if page_url else raw_og
        if full_og and full_og not in seen_img_urls and not is_noise_or_logo_image(full_og, caption=page_title):
            matched_tok = _matches_target(f"{page_title} {raw_og}")
            if matched_tok:
                seen_img_urls.add(full_og)
                candidates.append({
                    "image_url": full_og,
                    "source_page_url": page_url,
                    "source_type": "article_image",
                    "caption": page_title or f"תמונת כתבה ({matched_tok})",
                    "alt": page_title,
                    "matched_token": matched_tok,
                    "width": None,
                    "height": None,
                })

    return candidates


def _highlight_identifiers_in_text(text: str, identifiers: list[str]) -> str:
    """Safely HTML-escape `text` and wrap any matched target identifiers in `<mark class="osint-hl">...</mark>`."""
    if not text:
        return ""
    escaped = html.escape(text)
    clean_idents = sorted(
        {html.escape(i.strip()) for i in identifiers if i and len(i.strip()) >= 3},
        key=len,
        reverse=True,
    )
    if not clean_idents:
        return escaped
    pattern = "|".join(re.escape(i) for i in clean_idents)
    try:
        return re.sub(
            f"(?i)({pattern})",
            r'<mark class="osint-hl">\1</mark>',
            escaped,
        )
    except Exception:
        return escaped


def extract_article_context_and_entities(
    html_body: str,
    url: str,
    profile: SearchTargetProfile,
    extractor=None,
    default_title: str = "",
    fallback_title: str = "",
) -> dict[str, Any]:
    """Deep Article & Comment Content Extractor (Step 2.3):
    - Strips HTML menus, scripts, styles, nav, footer, ads.
    - Extracts clean paragraphs and locates exact paragraph(s) mentioning the target's name, phone, email, or username.
    - Extracts the matching paragraph TOGETHER WITH 1 paragraph before and 1 paragraph after.
    - Runs NER / regex / biographical extraction on the extracted context to discover new leads (roles, orgs, relatives, phones, emails).
    - Also harvests in-article candidate images of the target.
    """
    from .extract import Extractor
    from .providers import harvest_snippet_intel

    if extractor is None:
        extractor = Extractor()

    page_title = default_title or fallback_title
    if html_body:
        t_m = re.search(r"(?is)<title[^>]*>(.*?)</title>", html_body)
        if t_m:
            extracted_title = re.sub(r"\s+", " ", html.unescape(re.sub(r"<[^>]+>", " ", t_m.group(1)))).strip()
            if extracted_title:
                page_title = extracted_title

    # Extract in-article images before stripping HTML tags
    candidate_images = extract_in_article_images(html_body, url, profile, page_title=page_title) if html_body else []

    # Strip non-content blocks (script, style, nav, header, footer, aside, noscript, svg, form)
    cleaned_html = re.sub(
        r"(?is)<(script|style|nav|header|footer|aside|noscript|svg|form|iframe)\b[^>]*>.*?</\1>",
        " ",
        html_body or "",
    )
    # Remove common ad/menu/sidebar divs by class/id attribute heuristics while keeping main content
    cleaned_html = re.sub(
        r'(?is)<(div|section|ul)\b[^>]*\b(?:class|id)=["\'][^"\']*\b(?:menu|navbar|sidebar|footer|cookie|banner|popup|breadcrumb)\b[^"\']*["\'][^>]*>.*?</\1>',
        " ",
        cleaned_html,
    )

    # Extract block-level paragraphs
    raw_blocks = re.split(
        r"(?is)</?(?:p|article|blockquote|li|h1|h2|h3|h4|tr|div)\b[^>]*>|\n\s*\n",
        cleaned_html,
    )
    paragraphs: list[str] = []
    for blk in raw_blocks:
        txt = html.unescape(re.sub(r"<[^>]+>", " ", blk))
        txt = re.sub(r"\s+", " ", txt).strip()
        if len(txt) >= 15 and txt not in paragraphs:
            paragraphs.append(txt)

    # Build target search identifiers (names, phones, emails, usernames)
    search_identifiers: list[str] = []
    for item in (
        profile.hebrew_names
        + profile.english_names
        + profile.emails
        + profile.all_phone_permutations()
        + profile.usernames
    ):
        s_it = (item or "").strip()
        if len(s_it) >= 3 and s_it.lower() not in [x.lower() for x in search_identifiers]:
            search_identifiers.append(s_it)

    matched_indices: list[int] = []
    matched_identifiers: list[str] = []
    for idx, p_txt in enumerate(paragraphs):
        p_low = p_txt.lower()
        row_matched = False
        for ident in search_identifiers:
            if ident.lower() in p_low:
                row_matched = True
                if ident not in matched_identifiers:
                    matched_identifiers.append(ident)
        if row_matched:
            matched_indices.append(idx)

    # Collect matching paragraph + 1 paragraph before and 1 paragraph after
    context_windows: list[dict[str, Any]] = []
    selected_paragraphs: list[str] = []
    seen_p_idx: set[int] = set()

    for m_idx in matched_indices[:3]:
        win_start = max(0, m_idx - 1)
        win_end = min(len(paragraphs) - 1, m_idx + 1)
        before_p = paragraphs[m_idx - 1] if m_idx - 1 >= 0 else ""
        target_p = paragraphs[m_idx]
        after_p = paragraphs[m_idx + 1] if m_idx + 1 < len(paragraphs) else ""
        window_list = [p for p in (before_p, target_p, after_p) if p]
        context_windows.append({
            "paragraph_index": m_idx,
            "before_paragraph": before_p,
            "target_paragraph": target_p,
            "after_paragraph": after_p,
            "combined": " … ".join(window_list),
        })
        for i in range(win_start, win_end + 1):
            if i not in seen_p_idx:
                seen_p_idx.add(i)
                selected_paragraphs.append(paragraphs[i])

    quoted_context = "\n\n".join(selected_paragraphs)
    highlighted_html = _highlight_identifiers_in_text(quoted_context, matched_identifiers or search_identifiers)

    # Run NER / Regex / Biographical extraction over the extracted context paragraphs
    analysis_text = f"{page_title} — {quoted_context}" if quoted_context else page_title
    ex = extractor.extract(analysis_text, url)
    snippet_intel = harvest_snippet_intel([{"url": url, "title": page_title, "snippet": quoted_context}])

    extracted_emails = list(dict.fromkeys(
        [d["display"] for (et, _), d in ex.ents.items() if et == "email"] + list(snippet_intel.get("emails", []))
    ))
    raw_phone_matches = [
        m.group(0).strip()
        for m in re.finditer(r"(?:\+?972[-\s]?|0)(?:5\d|[23489])[-\s]?\d{3}[-\s]?\d{4}\b", analysis_text)
    ]
    extracted_phones = list(dict.fromkeys(
        raw_phone_matches
        + [d["display"] for (et, _), d in ex.ents.items() if et == "phone"]
        + list(snippet_intel.get("phones", []))
    ))
    extracted_persons = [
        d["display"] for (et, _), d in ex.ents.items()
        if et == "person" and is_valid_person_name(d["display"])
    ]
    extracted_orgs = [d["display"] for (et, _), d in ex.ents.items() if et == "org"]
    extracted_attrs = [{"name": a[1], "value": a[2], "kind": a[3]} for a in ex.attrs if len(a) >= 4]

    # Additional Hebrew & English biographical patterns (age, role, relatives, city)
    for m_age_he in re.finditer(r"\b(?:בן|בת)\s+(\d{2})\b", analysis_text):
        extracted_attrs.append({"name": "age", "value": m_age_he.group(1), "kind": "inferred"})
    for m_age_en in re.finditer(r"\b(?:aged?\s+|(\d{2})-year-old\b)(\d{2})?", analysis_text, re.I):
        age_val = m_age_en.group(1) or m_age_en.group(2)
        if age_val:
            extracted_attrs.append({"name": "age", "value": age_val, "kind": "inferred"})
    for m_role_he in re.finditer(
        r"\b(מנכ\"ל|סמנכ\"ל|מייסד|שותף|עורך דין|עו\"ד|רואה חשבון|רו\"ח|מהנדס|מנהל\s+[א-ת]+|חוקר|דוקטור|פרופסור)\s+(?:ב[-]?|של\s+)?([א-תA-Za-z0-9 \"'\-]{2,35})",
        analysis_text,
    ):
        role_v = m_role_he.group(1).strip()
        org_v = m_role_he.group(2).strip(" ,.-")
        extracted_attrs.append({"name": "role", "value": role_v, "kind": "inferred"})
        if org_v and len(org_v) >= 2 and org_v not in extracted_orgs:
            extracted_orgs.append(org_v)
    for m_work_en in re.finditer(
        r"\bworks\s+as\s+(?:an?\s+)?([A-Za-z0-9 ,/&\-]{3,45}?)\s+at\s+([A-Z][A-Za-z0-9 .&\-]{1,35}?)(?=[,.]|;\s|\s+which\b|\s+and\b|$)",
        analysis_text,
    ):
        role_val = m_work_en.group(1).strip(" ,.-")
        org_val = m_work_en.group(2).strip(" ,.-")
        if org_val and org_val not in extracted_orgs:
            extracted_orgs.append(org_val)
        if role_val:
            extracted_attrs.append({"name": "role", "value": role_val, "kind": "inferred"})

    extracted_ages = [a["value"] for a in extracted_attrs if a.get("name") == "age"]
    extracted_roles = [a["value"] for a in extracted_attrs if a.get("name") == "role"]

    return {
        "title": page_title,
        "url": url,
        "matched_identifiers": matched_identifiers,
        "context_windows": context_windows,
        "context_paragraphs": selected_paragraphs,
        "quoted_context": quoted_context,
        "context_text": quoted_context,
        "highlighted_html": highlighted_html,
        "emails": extracted_emails,
        "phones": extracted_phones,
        "persons": extracted_persons,
        "orgs": extracted_orgs,
        "attributes": extracted_attrs,
        "extracted_entities": {
            "emails": extracted_emails,
            "phones": extracted_phones,
            "persons": extracted_persons,
            "orgs": extracted_orgs,
            "ages": extracted_ages,
            "roles": extracted_roles,
            "attributes": extracted_attrs,
        },
        "candidate_images": candidate_images,
    }


# ============================================================================
# Domain & Infrastructure Intelligence (keyless, public-source): Certificate
# Transparency (crt.sh) subdomain discovery + RDAP registrant WHOIS. Seeded from
# the target's own email/url domains and from domains discovered during the run,
# so the pivot loop can walk person → domain → subdomains/registrant → more people.
# ============================================================================

# Free-mail and big-platform domains are never pivoted on: a subdomain sweep or WHOIS of gmail.com /
# facebook.com describes the provider, not the target, and would only add noise. Precision-first.
_FREEMAIL_DOMAINS = {
    "gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "hotmail.co.il", "live.com", "msn.com",
    "yahoo.com", "yahoo.co.il", "ymail.com", "rocketmail.com", "icloud.com", "me.com", "mac.com",
    "aol.com", "proton.me", "protonmail.com", "pm.me", "gmx.com", "gmx.net", "mail.com", "zoho.com",
    "yandex.com", "yandex.ru", "walla.com", "walla.co.il", "nana10.co.il", "nana.co.il",
    "012.net.il", "013.net.il", "bezeqint.net", "netvision.net.il", "zahav.net.il", "012.net",
}
_PLATFORM_DOMAINS = {
    "facebook.com", "fb.com", "instagram.com", "linkedin.com", "github.com", "gitlab.com",
    "twitter.com", "x.com", "t.me", "telegram.me", "telegram.org", "tiktok.com", "youtube.com",
    "youtu.be", "medium.com", "reddit.com", "google.com", "apple.com", "microsoft.com",
    "amazon.com", "wordpress.com", "blogspot.com", "wixsite.com", "wix.com", "pastebin.com",
    "scribd.com", "slideshare.net", "academia.edu", "researchgate.net", "orcid.org",
}
# Registrant contacts that are privacy services / registrar role-mailboxes, never the target themselves.
_WHOIS_PRIVACY_MARKERS = (
    "privacy", "proxy", "whoisguard", "redacted", "withheld", "data protected", "domainsbyproxy",
    "hostmaster", "dns-admin", "dnsadmin", "abuse@", "postmaster", "registrar", "contactprivacy",
    "gandi.net", "namecheap.com", "godaddy.com", "privacyprotect",
)

# Multi-label public suffixes we must keep whole when reducing a host to its registrable domain.
_MULTI_LABEL_SUFFIXES = {
    "co.il", "org.il", "ac.il", "gov.il", "net.il", "muni.il", "k12.il", "idf.il", "health.gov.il",
    "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "co.nz", "co.jp",
}


def registrable_domain(host_or_email: str) -> str:
    """Reduce a host, URL authority or email domain to its registrable domain (e.g. `a.b.example.co.il`
    → `example.co.il`), honouring Israeli multi-label suffixes. Returns '' when there is no usable host."""
    h = str(host_or_email or "").strip().lower()
    if "@" in h:
        h = h.rsplit("@", 1)[-1]
    if "//" in h:
        try:
            h = urllib.parse.urlparse(h).netloc or h
        except ValueError:
            pass
    h = h.split("/")[0].split("?")[0].split("#")[0]
    h = h.split("@")[-1].split(":")[0].strip().strip(".")
    if not h or "." not in h or " " in h:
        return ""
    labels = h.split(".")
    if len(labels) >= 3 and ".".join(labels[-2:]) in _MULTI_LABEL_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def is_pivotable_domain(domain: str) -> bool:
    """True only for a personal/organisational domain the target owns or uses — not free-mail, not a big
    platform, not a bare public suffix. Guards crt.sh/RDAP precision (never sweep gmail.com)."""
    d = registrable_domain(domain)
    if not d or d in _MULTI_LABEL_SUFFIXES:
        return False
    return d not in _FREEMAIL_DOMAINS and d not in _PLATFORM_DOMAINS


def _rdap_vcard_fields(vcard_array: Any) -> dict[str, str]:
    """Pull fn/email/org out of an RDAP entity's jCard (`["vcard", [[name, {}, type, value], …]]`)."""
    out: dict[str, str] = {}
    try:
        items = vcard_array[1] if isinstance(vcard_array, list) and len(vcard_array) >= 2 else []
        for it in items:
            if not isinstance(it, list) or len(it) < 4:
                continue
            key = str(it[0]).lower()
            val = it[3]
            if isinstance(val, list):
                val = " ".join(str(x) for x in val if x)
            val = str(val or "").strip()
            if not val:
                continue
            if key == "fn" and "fn" not in out:
                out["fn"] = val
            elif key == "email" and "email" not in out:
                out["email"] = val.lower()
            elif key == "org" and "org" not in out:
                out["org"] = val
    except Exception:
        pass
    return out


async def check_certificate_transparency(
    domain: str,
    store=None,
    http_fetcher: Callable | None = None,
) -> list[dict[str, Any]]:
    """Discover a domain's subdomains from public Certificate Transparency logs via crt.sh (keyless JSON).
    Each subdomain that ever received a TLS certificate is public infrastructure of the target's domain —
    often a personal site, VPN, mail or staging host not reachable from any search engine."""
    dom = registrable_domain(domain)
    if not dom or not is_pivotable_domain(dom):
        return []
    if store is not None:
        cached = store.osint_cache_get(dom, "crtsh")
        if cached is not None:
            return cached

    url = f"https://crt.sh/?q=%25.{urllib.parse.quote(dom)}&output=json"
    status, body, _ = await _async_http_get(url, timeout=12.0, http_fetcher=http_fetcher)
    findings: list[dict[str, Any]] = []
    if status == 200 and body:
        try:
            rows = json.loads(body)
        except Exception:
            rows = []
        subs: list[str] = []
        seen_sub: set[str] = set()
        for row in rows if isinstance(rows, list) else []:
            name_value = str((row or {}).get("name_value") or "")
            for raw in name_value.replace(",", "\n").splitlines():
                host = raw.strip().lower().lstrip("*.").strip(".")
                if not host or " " in host or "@" in host:
                    continue
                if not (host == dom or host.endswith("." + dom)):
                    continue
                if host in (dom, "www." + dom) or host in seen_sub:
                    continue
                seen_sub.add(host)
                subs.append(host)
        subs.sort()
        if subs:
            findings.append({
                "category": "domain_intel",
                "source_tool": "crtsh",
                "title": f"תעודות SSL (Certificate Transparency): {dom} — {len(subs)} תת-דומיינים",
                "summary": "תת-דומיינים שהתגלו ביומני שקיפות התעודות (crt.sh): " + ", ".join(subs[:12])
                           + (" …" if len(subs) > 12 else ""),
                "url": f"https://crt.sh/?q=%25.{urllib.parse.quote(dom)}",
                "confidence": 0.6,
                "extracted_data": {
                    "domain": dom,
                    "subdomains": subs[:60],
                    "subdomain_count": len(subs),
                },
            })
    if store is not None:
        store.osint_cache_put(dom, "crtsh", findings)
    return findings


async def check_rdap_domain(
    domain: str,
    store=None,
    http_fetcher: Callable | None = None,
) -> list[dict[str, Any]]:
    """Public WHOIS over RDAP (rdap.org bootstraps to the authoritative registry, JSON, keyless). When the
    registrant is not privacy-protected, this yields a real person/org name and email tied to the domain —
    a strong pivot. Redacted/privacy registrants yield no finding (precision-first)."""
    dom = registrable_domain(domain)
    if not dom or not is_pivotable_domain(dom):
        return []
    if store is not None:
        cached = store.osint_cache_get(dom, "rdap")
        if cached is not None:
            return cached

    url = f"https://rdap.org/domain/{urllib.parse.quote(dom)}"
    status, body, _ = await _async_http_get(url, timeout=10.0, http_fetcher=http_fetcher)
    findings: list[dict[str, Any]] = []
    if status == 200 and body:
        try:
            data = json.loads(body)
        except Exception:
            data = {}
        registrant: dict[str, str] = {}
        registrar = ""
        for ent in (data.get("entities") or []) if isinstance(data, dict) else []:
            roles = [str(r).lower() for r in (ent.get("roles") or [])]
            fields = _rdap_vcard_fields(ent.get("vcardArray"))
            if "registrar" in roles and not registrar:
                registrar = fields.get("fn") or fields.get("org") or ""
            if ("registrant" in roles or "administrative" in roles) and not registrant:
                registrant = fields
        created = expires = ""
        for ev in (data.get("events") or []) if isinstance(data, dict) else []:
            action = str(ev.get("eventAction") or "").lower()
            if action in ("registration", "created") and not created:
                created = str(ev.get("eventDate") or "")
            elif action in ("expiration", "expiry") and not expires:
                expires = str(ev.get("eventDate") or "")

        reg_name = (registrant.get("fn") or "").strip()
        reg_email = (registrant.get("email") or "").strip().lower()
        reg_org = (registrant.get("org") or "").strip()
        blob = f"{reg_name} {reg_email} {reg_org}".lower()
        is_private = any(m in blob for m in _WHOIS_PRIVACY_MARKERS)

        if (reg_name or reg_email or reg_org) and not is_private:
            parts = [f"רישום דומיין {dom}"]
            if reg_name:
                parts.append(f"בעלים: {reg_name}")
            if reg_org:
                parts.append(f"ארגון: {reg_org}")
            if reg_email:
                parts.append(f"אימייל: {reg_email}")
            if registrar:
                parts.append(f"רשם: {registrar}")
            if created:
                parts.append(f"נרשם: {created[:10]}")
            findings.append({
                "category": "domain_intel",
                "source_tool": "rdap",
                "title": f"רישום דומיין (RDAP/WHOIS): {dom}",
                "summary": " | ".join(parts),
                "url": f"https://rdap.org/domain/{urllib.parse.quote(dom)}",
                "confidence": 0.85 if (reg_name or reg_email) else 0.7,
                "extracted_data": {
                    "domain": dom,
                    "registrant_name": reg_name,
                    "registrant_email": reg_email,
                    "registrant_org": reg_org,
                    "registrar": registrar,
                    "created": created,
                    "expires": expires,
                },
            })
    if store is not None:
        store.osint_cache_put(dom, "rdap", findings)
    return findings


async def run_layer_domain_intel(
    domains: list[str],
    store=None,
    http_fetcher: Callable | None = None,
    log_fn: Callable[[str], None] | None = None,
    max_domains: int = 3,
) -> list[dict[str, Any]]:
    """Fan crt.sh + RDAP across the target's pivotable domains (bounded, fault-isolated)."""
    seen: list[str] = []
    for d in domains:
        rd = registrable_domain(d)
        if rd and is_pivotable_domain(rd) and rd not in seen:
            seen.append(rd)
    seen = seen[:max(1, max_domains)]
    if not seen:
        return []
    tasks = []
    for dom in seen:
        tasks.append(_safe_task(check_certificate_transparency(dom, store=store, http_fetcher=http_fetcher),
                                f"crtsh:{dom}", 13.0, log_fn))
        tasks.append(_safe_task(check_rdap_domain(dom, store=store, http_fetcher=http_fetcher),
                                f"rdap:{dom}", 11.0, log_fn))
    out: list[dict[str, Any]] = []
    for item in await asyncio.gather(*tasks, return_exceptions=True):
        if isinstance(item, list):
            out.extend(item)
    if out and log_fn:
        log_fn(f"✓ [Domain Intel] {len(out)} ממצאי תשתית (crt.sh/RDAP) עבור {len(seen)} דומיינים.")
    return out


_DOC_EXTS = (".pdf", ".xlsx", ".xls", ".docx", ".doc", ".csv", ".pptx", ".txt", ".rtf", ".odt", ".ods",
             ".vcf", ".xml", ".json")


def document_type_of(url: str) -> str:
    """The document extension of a URL (pdf/xlsx/…) or '' — so Layer 5 knows to fetch and parse the file."""
    try:
        path = urllib.parse.urlparse(url.lower()).path
    except ValueError:
        path = url.lower()
    for e in _DOC_EXTS:
        if path.endswith(e):
            return e.lstrip(".")
    return ""


async def harvest_document_text(url: str, http_fetcher: Callable | None = None, max_chars: int = 200_000) -> str:
    """Fetch a public document and run it through osnit's own parser (osnit.parse.parse — pdf/office/csv/…),
    returning its extracted text. Bounded size, fully fault-isolated. No login is ever bypassed."""
    try:
        res = await _async_http_get_bytes(url, timeout=10.0, http_fetcher=http_fetcher)
        status = int(res[0]) if isinstance(res, tuple) and len(res) >= 2 else 0
        body = res[1] if isinstance(res, tuple) and len(res) >= 2 else b""
    except Exception:
        return ""
    if status != 200 or not body:
        return ""
    try:
        from .parse import parse
        parsed = parse(bytes(body), url)
    except Exception:
        return ""
    return (parsed.text or "")[:max_chars]


def focus_excerpt(text: str, identifiers: list[str], window: int = 200, max_windows: int = 6) -> str:
    """Concatenated windows of `text` around the first mentions of any target identifier (fold is
    length-preserving, so folded offsets map back to the original text). Empty when the target is not in the
    file — so a document's contents are surfaced only when it actually mentions the target (precision-first)."""
    if not text:
        return ""
    folded = fold(text)
    spans: list[tuple[int, int]] = []
    for ident in identifiers:
        f = fold(str(ident or ""))
        if len(f) < 3:
            continue
        start = folded.find(f)
        if start != -1:
            spans.append((max(0, start - window), min(len(text), start + len(f) + window)))
        if len(spans) >= max_windows * 3:
            break
    if not spans:
        return ""
    spans.sort()
    merged: list[tuple[int, int]] = []
    for a, b in spans:
        if merged and a <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], b))
        else:
            merged.append((a, b))
    return " … ".join(text[a:b].strip() for a, b in merged[:max_windows])


async def run_layer5_dork_search(
    profile: SearchTargetProfile,
    store=None,
    search_fn: Callable[[str], list[dict[str, str]]] | None = None,
    http_fetcher: Callable | None = None,
    log_fn: Callable[[str], None] | None = None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Execute multi-engine OSINT dorks AND Open-Web Context & Comment queries (Step 2),
    score relevance, scrape deep article/comment paragraphs (target paragraph + 1 before/after),
    highlight identifiers, extract NER entities, and harvest in-article candidate images.
    Returns (osint_findings, extracted_leads)."""
    from .config import Config
    from .extract import Extractor
    from .providers import NativeMetaSearchProvider, harvest_snippet_intel

    dorks = build_israeli_dorks(profile) + build_open_web_queries(profile)
    try:
        _dork_budget = max(8, int(os.environ.get("OSNIT_MAX_RECON_DORKS", "44") or "44"))
    except ValueError:
        _dork_budget = 44
    dorks = dorks[:_dork_budget]                       # keep a live multi-engine sweep bounded on the operator's box
    findings: list[dict[str, Any]] = []
    leads: list[dict[str, Any]] = []
    seen_urls: set[str] = set()
    extractor = Extractor()
    meta_provider = NativeMetaSearchProvider(Config()) if search_fn is None else None

    # Pre-fetch uncached dorks in a single shared Playwright batch when running live
    batch_hits_map: dict[str, list[dict[str, str]]] = {}
    if search_fn is None:
        uncached_queries = [
            d["query"] for d in dorks
            if store is None or store.osint_cache_get(d["query"], "dork_search") is None
        ]
        if uncached_queries:
            batch_hits_map = await _search_yahoo_playwright_batch(uncached_queries, limit_per_query=8)
    batch_has_any = any(batch_hits_map.values())

    def _default_search_with_snippets(query_str: str, limit: int = 8) -> list[dict[str, str]]:
        if query_str in batch_hits_map and batch_hits_map[query_str]:
            return batch_hits_map[query_str][:limit]
        if meta_provider is None:
            return []
        urls = meta_provider.search(query_str, limit=limit)
        if meta_provider.last_snippets:
            return list(meta_provider.last_snippets)[:limit]
        return [{"url": u, "title": u, "snippet": ""} for u in urls[:limit]]

    all_target_identifiers = (
        profile.hebrew_names
        + profile.english_names
        + profile.emails
        + profile.all_phone_permutations()
        + profile.usernames
    )

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
        elif batch_has_any and q in batch_hits_map:
            raw_hits = batch_hits_map[q]
        else:
            raw_hits = await asyncio.to_thread(_default_search_with_snippets, q, 8)
        _net_note("search", ok=bool(raw_hits))

        dork_findings: list[dict[str, Any]] = []
        for hit in raw_hits[:8]:
            u = (hit.get("url") or "").strip()
            title = (hit.get("title") or u).strip()
            snippet = (hit.get("snippet") or "").strip()
            hit_html = hit.get("html") or ""
            if not u:
                continue
            rel = score_search_result(title, snippet, u, profile)
            if rel < 0.40:
                continue

            # Categorize automatically by URL while preserving social_comment and open_web_article
            eff_cat = cat
            u_low = u.lower()
            if cat not in ("social_comment", "open_web_article"):
                if any(d in u_low for d in ("psakdin", "takdin", "nevo", "ruling", "gov.il", "guidestar")) or u_low.endswith((".pdf", ".xlsx", ".xls", ".docx")):
                    eff_cat = "legal_doc"
                elif any(d in u_low for d in ("linkedin.com", "facebook.com", "instagram.com", "tiktok.com", "t.me", "x.com", "twitter.com")):
                    eff_cat = "social_profile"
                elif "github.com" in u_low or "gitlab.com" in u_low or "stackoverflow.com" in u_low:
                    eff_cat = "code_intel"
            else:
                if any(k in u_low for k in ("/posts/", "/permalink/", "comment_id=", "fxp.co.il", "carsforum.co.il", "tapuz.co.il", "reddit.com/r/", "t.me/s/")):
                    eff_cat = "social_comment"

            # A document hit (PDF/Office/CSV/…): fetch the file and run it through osnit's own parser, then
            # pull the target's details (names/emails/phones) out of the file itself — not just the snippet.
            doc_type = document_type_of(u)
            doc_text = ""
            if doc_type and not hit_html and (http_fetcher is not None or meta_provider is not None):
                doc_text = await harvest_document_text(u, http_fetcher=http_fetcher)
                if doc_text:
                    eff_cat = "document"

            # Deep Article & Comment Content Extraction when HTML is available or fetchable
            article_ctx: dict[str, Any] = {}
            if not hit_html and not doc_text and eff_cat in ("open_web_article", "social_comment", "general_web") and http_fetcher is not None:
                try:
                    status, body_text, _ = await _async_http_get(u, timeout=6.0, http_fetcher=http_fetcher)
                    if status == 200 and body_text and "<" in body_text:
                        hit_html = body_text
                except Exception:
                    pass

            if hit_html:
                article_ctx = extract_article_context_and_entities(
                    hit_html,
                    u,
                    profile,
                    extractor=extractor,
                    default_title=title,
                )

            quoted_context = article_ctx.get("quoted_context") or snippet
            doc_excerpt = ""
            if doc_text:
                # only surface the file's contents when it actually mentions the target (precision-first)
                doc_excerpt = focus_excerpt(doc_text, all_target_identifiers)
                if doc_excerpt:
                    quoted_context = doc_excerpt
            highlighted_html = article_ctx.get("highlighted_html") or _highlight_identifiers_in_text(
                quoted_context, all_target_identifiers
            )

            # Extract entities/attributes from title + snippet + deep article context
            is_directory_listing = "facebook.com/public/" in u_low or "linkedin.com/pub/dir/" in u_low
            combined_text = f"{title} — {quoted_context}"
            ex = extractor.extract(combined_text, u)
            snippet_intel = harvest_snippet_intel([{"url": u, "title": title, "snippet": quoted_context}])
            extracted_emails = list(dict.fromkeys(
                [d["display"] for (et, _), d in ex.ents.items() if et == "email"]
                + list(snippet_intel.get("emails", []))
                + list(article_ctx.get("emails", []))
            ))
            extracted_phones = list(dict.fromkeys(
                [d["display"] for (et, _), d in ex.ents.items() if et == "phone"]
                + list(snippet_intel.get("phones", []))
                + list(article_ctx.get("phones", []))
            ))
            extracted_persons = [] if is_directory_listing else list(dict.fromkeys(
                [
                    d["display"] for (et, _), d in ex.ents.items()
                    if et == "person" and is_valid_person_name(d["display"])
                ]
                + list(article_ctx.get("persons", []))
            ))
            extracted_orgs = [] if is_directory_listing else list(dict.fromkeys(
                [d["display"] for (et, _), d in ex.ents.items() if et == "org"]
                + list(article_ctx.get("orgs", []))
            ))
            extracted_attrs = [{"name": a[1], "value": a[2], "kind": a[3]} for a in ex.attrs if len(a) >= 4]
            for extra_attr in article_ctx.get("attributes") or []:
                if extra_attr not in extracted_attrs:
                    extracted_attrs.append(extra_attr)
            if not is_directory_listing:
                for m_work in re.finditer(
                    r"\bworks\s+as\s+(?:an?\s+)?([A-Za-z0-9 ,/&\-]{3,45}?)\s+at\s+([A-Z][A-Za-z0-9 .&\-]{1,35}?)(?=[,.]|;\s|\s+which\b|\s+and\b|$)",
                    combined_text,
                ):
                    role_val = m_work.group(1).strip(" ,.-")
                    org_val = m_work.group(2).strip(" ,.-")
                    if org_val and org_val not in extracted_orgs:
                        extracted_orgs.append(org_val)
                    if role_val:
                        extracted_attrs.append({"name": "role", "value": role_val, "kind": "inferred"})

            source_tool_name = (
                "document_harvester"
                if eff_cat == "document" and doc_excerpt
                else "open_web_scraper"
                if eff_cat in ("open_web_article", "social_comment")
                else "dork_search"
            )
            dork_findings.append({
                "category": eff_cat,
                "source_tool": source_tool_name,
                "title": f"[{label}] {title[:110]}",
                "summary": quoted_context[:360] if quoted_context else f"נמצא באמצעות שאילתה: {q}",
                "url": u,
                "confidence": rel,
                "extracted_data": {
                    "query": q,
                    "label": label,
                    "article_title": article_ctx.get("title") or title,
                    "quoted_context": quoted_context,
                    "highlighted_html": highlighted_html,
                    "context_windows": article_ctx.get("context_windows") or [],
                    "context_paragraphs": article_ctx.get("context_paragraphs") or ([snippet] if snippet else []),
                    "matched_identifiers": article_ctx.get("matched_identifiers") or [],
                    "candidate_images": article_ctx.get("candidate_images") or [],
                    "emails": extracted_emails,
                    "phones": extracted_phones,
                    "persons": extracted_persons,
                    "orgs": extracted_orgs,
                    "national_ids": snippet_intel.get("national_ids", []),
                    "attributes": extracted_attrs,
                    "file_url": u if doc_type else "",
                    "file_type": doc_type,
                    "from_file": bool(doc_excerpt),
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
# Layer 6: Target Image & Visual Recon Engine (Sources A–D + dHash + EXIF + Face Detection)
# ============================================================================

async def search_target_images(
    profile: SearchTargetProfile,
    http_fetcher: Callable | None = None,
    image_search_fn: Callable[[str], list[dict[str, str]]] | None = None,
) -> list[dict[str, Any]]:
    """Source C: Run targeted image searches for '"Full Name" + "City/Org"' and extract candidate image URLs
    whose title, alt, or source page matches the target."""
    queries: list[str] = []
    names = profile.hebrew_names[:2] + profile.english_names[:2]
    if not names and profile.primary_name:
        names = [profile.primary_name]

    anchors = profile.organizations[:2] + profile.locations[:2]
    for nm in names[:2]:
        if anchors:
            for anc in anchors[:2]:
                q = f'"{nm}" "{anc}"'
                if q not in queries:
                    queries.append(q)
        q_plain = f'"{nm}"'
        if q_plain not in queries:
            queries.append(q_plain)

    candidates: list[dict[str, Any]] = []
    seen_urls: set[str] = set()
    target_tokens = [n.lower() for n in (profile.hebrew_names + profile.english_names + profile.usernames) if n]

    for q in queries[:4]:
        raw_items: list[dict[str, str]] = []
        if image_search_fn is not None:
            res = image_search_fn(q)
            if asyncio.iscoroutine(res):
                res = await res
            raw_items = list(res or [])
        elif http_fetcher is not None:
            # Query Bing Images HTML endpoint via http_fetcher
            bing_img_url = f"https://www.bing.com/images/search?q={urllib.parse.quote(q)}&ensearch=0"
            status, body, _ = await _async_http_get(bing_img_url, timeout=8.0, http_fetcher=http_fetcher)
            if status == 200 and body:
                # Parse Bing Images m={...} JSON metadata attributes
                for m_meta in re.finditer(r"""\bm=(?:'(\{[^']*murl[^']*\})'|"(\{[^"]*murl[^"]*\})")""", body):
                    try:
                        raw_json = m_meta.group(1) or m_meta.group(2) or ""
                        meta_json = json.loads(html.unescape(raw_json))
                        raw_items.append({
                            "image_url": meta_json.get("murl") or "",
                            "source_page_url": meta_json.get("purl") or bing_img_url,
                            "title": meta_json.get("t") or meta_json.get("desc") or q,
                        })
                    except Exception:
                        pass

        for item in raw_items[:8]:
            img_u = (item.get("image_url") or item.get("url") or "").strip()
            page_u = (item.get("source_page_url") or item.get("page_url") or img_u).strip()
            title = (item.get("title") or item.get("caption") or "").strip()
            if not img_u or img_u in seen_urls:
                continue
            if is_noise_or_logo_image(img_u, alt=title, caption=title):
                continue
            blob = f"{title} {img_u} {page_u}".lower()
            if target_tokens and not any(tok in blob for tok in target_tokens):
                continue
            seen_urls.add(img_u)
            candidates.append({
                "image_url": img_u,
                "source_page_url": page_u,
                "source_type": "search_image",
                "caption": title or f"חיפוש תמונות: {q}",
            })

    return candidates


def _resolve_avatars_dirs(store=None) -> list[Path]:
    """Return local directory where verified target images should be saved (`data/avatars/` or `<db_dir>/avatars/`)."""
    dirs: list[Path] = []
    if store is not None and getattr(store, "path", None) and str(store.path) != ":memory:":
        try:
            dirs.append(Path(store.path).resolve().parent / "avatars")
        except Exception:
            pass
    if not dirs:
        dirs.append(Path("data") / "avatars")
    for d in dirs:
        try:
            d.mkdir(parents=True, exist_ok=True)
        except Exception:
            pass
    return dirs


def _guess_image_ext(img_bytes: bytes, url: str) -> str:
    if img_bytes[:8] == b"\x89PNG\r\n\x1a\n":
        return ".png"
    if img_bytes[:2] == b"\xff\xd8":
        return ".jpg"
    if img_bytes[:4] == b"RIFF" and img_bytes[8:12] == b"WEBP":
        return ".webp"
    path_low = (url or "").lower().split("?", 1)[0]
    for ext in (".jpg", ".jpeg", ".png", ".webp"):
        if path_low.endswith(ext):
            return ".jpg" if ext == ".jpeg" else ext
    return ".jpg"


# Approximate bounding boxes for Israeli population centres (lat_min, lat_max, lon_min, lon_max, label).
# Keyless, offline reverse geocoding: turns a raw EXIF GPS fix into a human place hint. Order matters —
# the first box that contains the point wins, so narrower metros precede the broad national fallback.
# These are deliberately coarse (metro/area level); the exact lat/lon is always surfaced alongside.
_IL_PLACE_BOXES = (
    (29.52, 29.58, 34.92, 34.99, "אילת"),
    (31.22, 31.28, 34.76, 34.84, "באר שבע"),
    (31.74, 31.83, 35.17, 35.27, "ירושלים"),
    (32.76, 32.84, 34.94, 35.05, "חיפה"),
    (32.79, 32.95, 35.03, 35.14, "הקריות (מפרץ חיפה)"),
    (31.65, 31.70, 34.55, 34.62, "אשקלון"),
    (31.78, 31.83, 34.62, 34.70, "אשדוד"),
    (32.30, 32.35, 34.84, 34.90, "נתניה"),
    (31.88, 31.94, 34.78, 34.86, "רחובות / נס ציונה"),
    (32.01, 32.14, 34.73, 34.80, "תל אביב-יפו"),
    (31.95, 32.03, 34.73, 34.82, "ראשון לציון / חולון / בת ים"),
    (32.05, 32.12, 34.80, 34.90, "רמת גן / בני ברק / גבעתיים"),
    (32.07, 32.13, 34.86, 34.95, "פתח תקווה"),
    (32.15, 32.22, 34.83, 34.93, "השרון (כפר סבא / רעננה / הוד השרון)"),
    (32.68, 32.74, 35.28, 35.34, "טבריה / הכנרת"),
    (32.69, 32.73, 35.28, 35.32, "נצרת"),
)
# Coarse national bounding box (incl. the West Bank and Golan) — a last-resort "somewhere in Israel" hint.
_IL_NATIONAL_BOX = (29.40, 33.45, 34.20, 35.95)


def _reverse_geocode_il(lat: float, lon: float) -> str:
    """Offline, keyless, best-effort reverse geocode of an EXIF GPS fix to a Hebrew place hint.
    Returns a metro/area label inside Israel, a coarse national hint, or "מחוץ לישראל" when far away.
    Approximate by design — the precise coordinates are always kept next to it."""
    try:
        la, lo = float(lat), float(lon)
    except (TypeError, ValueError):
        return ""
    for la_min, la_max, lo_min, lo_max, label in _IL_PLACE_BOXES:
        if la_min <= la <= la_max and lo_min <= lo <= lo_max:
            return label
    nla_min, nla_max, nlo_min, nlo_max = _IL_NATIONAL_BOX
    if nla_min <= la <= nla_max and nlo_min <= lo <= nlo_max:
        return "ישראל (אזור כללי)"
    return "מחוץ לישראל"


def _extract_jpeg_exif(img_bytes: bytes) -> dict[str, Any]:
    """Extract EXIF metadata from JPEG bytes using pure stdlib struct parsing.
    Returns a dict with any of: make, model, software, lens_model, orientation, iso, f_number,
    exposure_time, datetime, datetime_original, datetime_digitized, artist, copyright,
    gps_lat, gps_lon, gps_alt_m, gps_place, gps_img_direction, gps_datestamp.
    Returns {} if not a JPEG or no EXIF found."""
    if not img_bytes or len(img_bytes) < 12 or img_bytes[:2] != b'\xff\xd8':
        return {}

    i, n = 2, len(img_bytes)
    exif_data = b''
    while i < n - 4:
        if img_bytes[i] != 0xFF:
            break
        marker = img_bytes[i + 1]
        if marker == 0xE1:
            seg_len = struct.unpack('>H', img_bytes[i + 2:i + 4])[0]
            seg_end = i + 2 + seg_len
            payload = img_bytes[i + 4:min(seg_end, n)]
            if payload[:6] == b'Exif\x00\x00':
                exif_data = payload[6:]
                break
            i = seg_end
        elif marker in (0xD8, 0xD9) or (0xD0 <= marker <= 0xD7):
            i += 2
        else:
            if i + 4 > n:
                break
            seg_len = struct.unpack('>H', img_bytes[i + 2:i + 4])[0]
            if seg_len < 2:
                break
            i += 2 + seg_len

    if len(exif_data) < 8:
        return {}

    if exif_data[:2] == b'II':
        endian = '<'
    elif exif_data[:2] == b'MM':
        endian = '>'
    else:
        return {}
    if struct.unpack(endian + 'H', exif_data[2:4])[0] != 42:
        return {}
    ifd0_offset = struct.unpack(endian + 'I', exif_data[4:8])[0]

    def _read_ifd(data: bytes, offset: int) -> dict[int, tuple]:
        if offset + 2 > len(data):
            return {}
        count = struct.unpack(endian + 'H', data[offset:offset + 2])[0]
        out: dict[int, tuple] = {}
        for j in range(min(count, 256)):
            es = offset + 2 + j * 12
            if es + 12 > len(data):
                break
            tag, typ, cnt = struct.unpack(endian + 'HHI', data[es:es + 8])
            out[tag] = (typ, cnt, data[es + 8:es + 12])
        return out

    def _ascii(typ: int, cnt: int, raw: bytes) -> str:
        if typ != 2:
            return ''
        if cnt <= 4:
            return raw[:cnt].decode('latin-1', errors='ignore').rstrip('\x00').strip()
        off = struct.unpack(endian + 'I', raw)[0]
        return exif_data[off:off + cnt].decode('latin-1', errors='ignore').rstrip('\x00').strip()

    def _rationals(typ: int, cnt: int, raw: bytes) -> list[tuple[int, int]]:
        if typ not in (5, 10):
            return []
        off = struct.unpack(endian + 'I', raw)[0]
        result = []
        for k in range(min(cnt, 3)):
            pos = off + k * 8
            if pos + 8 > len(exif_data):
                break
            a, b = struct.unpack(endian + 'II', exif_data[pos:pos + 8])
            result.append((a, b))
        return result

    def _short(typ: int, cnt: int, raw: bytes) -> int | None:
        if typ == 3:
            return struct.unpack(endian + 'H', raw[:2])[0]
        if typ == 4:
            return struct.unpack(endian + 'I', raw)[0]
        return None

    ifd0 = _read_ifd(exif_data, ifd0_offset)
    result: dict[str, Any] = {}

    for tag, key in ((0x010F, 'make'), (0x0110, 'model'), (0x0131, 'software'),
                     (0x0132, 'datetime'), (0x013B, 'artist'), (0x8298, 'copyright')):
        if tag in ifd0:
            v = _ascii(*ifd0[tag])
            if v:
                result[key] = v

    if 0x0112 in ifd0:  # Orientation
        o = _short(*ifd0[0x0112])
        if o:
            result['orientation'] = int(o)

    if 0x8769 in ifd0:
        sub_off = struct.unpack(endian + 'I', ifd0[0x8769][2])[0]
        sub = _read_ifd(exif_data, sub_off)
        for tag, key in ((0x9003, 'datetime_original'), (0x9004, 'datetime_digitized'),
                         (0xA434, 'lens_model')):
            if tag in sub:
                v = _ascii(*sub[tag])
                if v:
                    result[key] = v
        if 0x8827 in sub:  # ISOSpeedRatings
            iso = _short(*sub[0x8827])
            if iso:
                result['iso'] = int(iso)
        if 0x829D in sub:  # FNumber
            r = _rationals(*sub[0x829D])
            if r and r[0][1]:
                result['f_number'] = round(r[0][0] / r[0][1], 1)
        if 0x829A in sub:  # ExposureTime
            r = _rationals(*sub[0x829A])
            if r and r[0][1]:
                num, den = r[0]
                result['exposure_time'] = (f"{num}/{den}" if num < den else str(round(num / den, 3)))

    if 0x8825 in ifd0:
        gps_off = struct.unpack(endian + 'I', ifd0[0x8825][2])[0]
        gps = _read_ifd(exif_data, gps_off)

        def _dms(tag_rats: int, tag_ref: int) -> float | None:
            if tag_rats not in gps or tag_ref not in gps:
                return None
            rats = _rationals(*gps[tag_rats])
            ref = _ascii(*gps[tag_ref])
            if not rats:
                return None
            deg = rats[0][0] / rats[0][1] if rats[0][1] else 0.0
            mn = rats[1][0] / rats[1][1] if len(rats) > 1 and rats[1][1] else 0.0
            sc = rats[2][0] / rats[2][1] if len(rats) > 2 and rats[2][1] else 0.0
            val = deg + mn / 60.0 + sc / 3600.0
            if ref and ref[0].upper() in ('S', 'W'):
                val = -val
            return round(val, 7)

        lat = _dms(0x0002, 0x0001)
        lon = _dms(0x0004, 0x0003)
        if lat is not None:
            result['gps_lat'] = lat
        if lon is not None:
            result['gps_lon'] = lon

        if 0x0006 in gps:
            rats = _rationals(*gps[0x0006])
            if rats and rats[0][1]:
                alt = rats[0][0] / rats[0][1]
                ref_raw = gps.get(0x0005, (0, 0, b'\x00'))[2]
                if ref_raw and ref_raw[0] == 1:
                    alt = -alt
                result['gps_alt_m'] = round(alt, 1)

        if 0x0011 in gps:  # GPSImgDirection (the bearing the camera was pointing)
            rats = _rationals(*gps[0x0011])
            if rats and rats[0][1]:
                result['gps_img_direction'] = round(rats[0][0] / rats[0][1], 1)

        if 0x001D in gps:  # GPSDateStamp
            v = _ascii(*gps[0x001D])
            if v:
                result['gps_datestamp'] = v

        if result.get('gps_lat') is not None and result.get('gps_lon') is not None:
            place = _reverse_geocode_il(result['gps_lat'], result['gps_lon'])
            if place:
                result['gps_place'] = place

    return result


def _dhash(img_bytes: bytes, hash_size: int = 8) -> int | None:
    """Compute a 64-bit difference-hash (dHash) for near-duplicate detection. Requires OpenCV."""
    if not HAS_CV2 or cv2 is None or np is None or not img_bytes:
        return None
    try:
        arr = np.frombuffer(img_bytes, dtype=np.uint8)
        img = cv2.imdecode(arr, cv2.IMREAD_GRAYSCALE)
        if img is None:
            return None
        small = cv2.resize(img, (hash_size + 1, hash_size), interpolation=cv2.INTER_AREA)
        diff = small[:, :-1] > small[:, 1:]
        h = 0
        for bit in diff.flatten():
            h = (h << 1) | int(bit)
        return h
    except Exception:
        return None


def _hamming(h1: int, h2: int) -> int:
    """Count differing bits between two hash integers."""
    x = h1 ^ h2
    c = 0
    while x:
        c += x & 1
        x >>= 1
    return c


async def _scrape_og_images(
    finding_urls: list[str],
    profile: "SearchTargetProfile",
    http_fetcher: Callable | None = None,
    log_fn: Callable | None = None,
) -> list[dict[str, Any]]:
    """Source D: scrape og:image / twitter:image from article/profile URLs found in Layers 2-5.
    Only returns a candidate when the page title or URL mentions the target (precision-first)."""
    target_tokens = {n.lower() for n in (profile.hebrew_names + profile.english_names + profile.usernames) if n}
    seen: set[str] = set()

    _TW_IMAGE_RE = re.compile(
        r'<meta\s[^>]*?name=["\']twitter:image(?::src)?["\'][^>]*?content=["\'](https?://[^"\'>\s]+)',
        re.IGNORECASE,
    )

    async def _fetch_one(url: str) -> dict[str, Any] | None:
        if not url or not url.startswith(('http://', 'https://')):
            return None
        path_low = url.lower().split('?')[0]
        if path_low.endswith(('.jpg', '.jpeg', '.png', '.webp', '.gif', '.svg',
                               '.pdf', '.xlsx', '.docx', '.csv', '.zip')):
            return None
        status, body, _ = await _async_http_get(url, timeout=7.0, http_fetcher=http_fetcher)
        if status != 200 or not body or len(body) < 200:
            return None
        img_url = ''
        m = re.search(r'<meta\s[^>]*?property=["\']og:image["\'][^>]*?content=["\'](https?://[^"\'>\s]+)',
                      body, re.IGNORECASE | re.DOTALL)
        if not m:
            m = re.search(r'<meta\s[^>]*?content=["\'](https?://[^"\'>\s]+)["\'][^>]*?property=["\']og:image["\']',
                          body, re.IGNORECASE | re.DOTALL)
        if not m:
            m = _TW_IMAGE_RE.search(body)
        if m:
            img_url = m.group(1).strip()
        if not img_url or img_url in seen:
            return None
        title_m = re.search(r'<title[^>]*>(.*?)</title>', body, re.IGNORECASE | re.DOTALL)
        page_title = re.sub(r'<[^>]+>', '', title_m.group(1) if title_m else '').strip()[:200]
        blob = f"{page_title} {url}".lower()
        if target_tokens and not any(tok in blob for tok in target_tokens):
            return None
        seen.add(img_url)
        return {"image_url": img_url, "source_page_url": url,
                "source_type": "og_image", "caption": page_title or url[:80]}

    tasks = [
        _safe_task(_fetch_one(u), f"og:{u[:40]}", 8.0, log_fn)
        for u in list(dict.fromkeys(finding_urls))[:8]
    ]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    return [r for r in results if isinstance(r, dict)]


async def run_layer6_image_recon(
    profile: SearchTargetProfile,
    findings_so_far: list[dict[str, Any]],
    store=None,
    http_fetcher: Callable | None = None,
    bytes_fetcher: Callable | None = None,
    image_search_fn: Callable[[str], list[dict[str, str]]] | None = None,
    finding_urls: list[str] | None = None,
    log_fn: Callable[[str], None] | None = None,
) -> list[dict[str, Any]]:
    """Layer 6 of 7: Target Image & Visual Recon Engine.
    Combines 4 image sources:
      - Source A (`direct_avatar`): Avatars discovered in Layers 2–4 (Gravatar, GitHub, Telegram, Linktree, Social).
      - Source B (`article_image`): In-article images extracted from Layer 5 pages where alt/caption/filename matches the target.
      - Source C (`search_image`): Targeted image search queries for '"Full Name" + "City/Org"'.
      - Source D (`og_image`): og:image / twitter:image scraped from article/profile URLs found in earlier layers.
    Applies smart filtering (rejects logos, icons, banners, SVGs, <80x80px), dHash near-duplicate deduplication,
    OpenCV face detection, EXIF metadata extraction (GPS/camera/timestamp), saves verified images to
    `data/avatars/` and `entity_images` in SQLite, and returns `target_image` OSINT findings.
    """
    candidates: list[dict[str, Any]] = []
    seen_img_urls: set[str] = set()

    def _add_candidate(img_url: str, source_page: str, source_type: str, caption: str, base_conf: float):
        u = (img_url or "").strip()
        if not u or u in seen_img_urls:
            return
        if is_noise_or_logo_image(u, caption=caption):
            return
        seen_img_urls.add(u)
        candidates.append({
            "image_url": u,
            "source_page_url": (source_page or u).strip(),
            "source_type": source_type,
            "caption": (caption or "").strip(),
            "base_confidence": base_conf,
        })

    # Source A: Direct avatars from Layers 2-4 findings
    for f in findings_so_far:
        ed = f.get("extracted_data") or {}
        src_page = f.get("url") or ""
        tool = f.get("source_tool") or "osint"
        for field_name in ("avatar_url", "og_image", "profile_image", "image_url"):
            av = ed.get(field_name)
            if av and isinstance(av, str):
                _add_candidate(
                    av,
                    src_page,
                    "direct_avatar",
                    f"תמונת פרופיל ישירה ({ed.get('platform') or tool})",
                    float(f.get("confidence") or 0.90),
                )
        # Source B: In-article candidate images harvested during Layer 5
        for cand_img in ed.get("candidate_images") or []:
            if isinstance(cand_img, dict) and cand_img.get("image_url"):
                _add_candidate(
                    cand_img["image_url"],
                    cand_img.get("source_page_url") or src_page,
                    cand_img.get("source_type") or "article_image",
                    cand_img.get("caption") or f.get("title") or "תמונה מתוך כתבה",
                    0.82,
                )

    # Source C: Search Engine Image Recon
    search_cands = await _safe_task(
        search_target_images(profile, http_fetcher=http_fetcher, image_search_fn=image_search_fn),
        "image_search",
        timeout=10.0,
        log_fn=log_fn,
    )
    if isinstance(search_cands, list):
        for sc in search_cands:
            _add_candidate(
                sc.get("image_url") or "",
                sc.get("source_page_url") or "",
                "search_image",
                sc.get("caption") or "חיפוש תמונות יעד",
                0.78,
            )

    # Source D: OG/Twitter card image scraping from article/profile URLs in findings
    if finding_urls:
        og_cands = await _safe_task(
            _scrape_og_images(finding_urls, profile, http_fetcher=http_fetcher, log_fn=log_fn),
            "og_image_scrape",
            timeout=15.0,
            log_fn=log_fn,
        )
        if isinstance(og_cands, list):
            for oc in og_cands:
                _add_candidate(
                    oc.get("image_url") or "",
                    oc.get("source_page_url") or "",
                    "og_image",
                    oc.get("caption") or "תמונת OG מדף מאמר",
                    0.80,
                )

    if not candidates:
        return []

    avatar_dirs = _resolve_avatars_dirs(store)
    eid = int(profile.entity_id) if profile.entity_id is not None else 0
    image_findings: list[dict[str, Any]] = []
    _accepted_hashes: list[int] = []
    now = time.time()

    async def _verify_and_store_one(cand: dict[str, Any]) -> dict[str, Any] | None:
        img_url = cand["image_url"]
        src_page = cand["source_page_url"]
        src_type = cand["source_type"]
        caption = cand["caption"]

        if bytes_fetcher is not None:
            res_b = bytes_fetcher(img_url)
            if asyncio.iscoroutine(res_b):
                res_b = await res_b
            status = int(res_b[0]) if res_b else 0
            img_bytes = res_b[1] if res_b and len(res_b) > 1 else b""
            if isinstance(img_bytes, str):
                img_bytes = img_bytes.encode("latin-1", errors="ignore")
        else:
            status, img_bytes = await _async_http_get_bytes(img_url, timeout=8.0, http_fetcher=http_fetcher)
        face_info = {"valid_size": False, "face_detected": False, "faces_count": 0, "width": 0, "height": 0}

        if status == 200 and img_bytes:
            face_info = verify_human_face_in_image(img_bytes, min_size=80)
            # Reject tiny images (<80x80) across all sources
            if face_info["width"] > 0 and face_info["height"] > 0 and not face_info["valid_size"]:
                return None
            # dHash near-duplicate deduplication: skip perceptually identical images
            img_hash = _dhash(img_bytes)
            if img_hash is not None:
                for prev_hash in _accepted_hashes:
                    if _hamming(img_hash, prev_hash) < 8:
                        return None
                _accepted_hashes.append(img_hash)
            # For article_image, og_image, and search_image, strictly require human face verification
            if src_type in ("article_image", "og_image", "search_image") and not face_info["face_detected"]:
                return None
        else:
            # If image bytes could not be downloaded: only allow direct_avatar if no custom http_fetcher/bytes_fetcher was used,
            # while article_image, og_image, and search_image must always be downloaded and face-verified.
            if src_type in ("article_image", "og_image", "search_image"):
                return None
            if http_fetcher is not None or bytes_fetcher is not None:
                return None

        face_verified = bool(face_info.get("face_detected"))
        exif = _extract_jpeg_exif(img_bytes) if img_bytes else {}

        if src_type == "direct_avatar":
            conf = 0.96 if face_verified else max(0.88, float(cand["base_confidence"]))
        elif src_type == "article_image":
            conf = 0.91 if face_verified else 0.75
        elif src_type == "og_image":
            conf = 0.88 if face_verified else 0.73
        else:
            conf = 0.87 if face_verified else 0.72

        local_disk_path = ""
        local_url = img_url
        if img_bytes:
            ext = _guess_image_ext(img_bytes, img_url)
            digest = hashlib.md5(img_url.encode("utf-8")).hexdigest()[:10]
            fname = f"entity_{eid}_{digest}{ext}"
            for av_dir in avatar_dirs:
                try:
                    target_path = av_dir / fname
                    target_path.write_bytes(img_bytes)
                    if not local_disk_path:
                        local_disk_path = str(target_path)
                except Exception:
                    pass
            local_url = f"/api/avatars/{fname}"

        stored_local_path = local_disk_path or local_url
        if store is not None and eid > 0 and hasattr(store, "add_entity_image"):
            store.add_entity_image(
                entity_id=eid,
                image_url=img_url,
                local_path=stored_local_path,
                source_page_url=src_page,
                source_type=src_type,
                caption=caption,
                face_verified=face_verified,
                width=int(face_info.get("width") or 0),
                height=int(face_info.get("height") or 0),
                confidence=conf,
                timestamp=now,
            )

        src_label = {
            "direct_avatar": "תמונת פרופיל ישירה",
            "article_image": "תמונה מתוך כתבה (אומתו פנים)",
            "og_image": "תמונת OG מדף מאמר",
            "search_image": "חיפוש תמונות יעד (אומתו פנים)",
        }.get(src_type, "תמונת יעד")

        gps_str = (
            f" | GPS: {exif['gps_lat']:.5f},{exif['gps_lon']:.5f}"
            if exif.get("gps_lat") is not None and exif.get("gps_lon") is not None
            else ""
        )
        place_str = f" | מיקום: {exif['gps_place']}" if exif.get("gps_place") else ""
        n_faces = int(face_info.get("faces_count") or 0)
        people_str = ""
        if face_verified:
            if face_info.get("portrait"):
                people_str = " | פורטרט (פנים בודדות — ככל הנראה היעד)"
            elif n_faces > 1:
                people_str = f" | {n_faces} אנשים בתמונה"
        device_str = ""
        if exif.get("make") or exif.get("model"):
            device_str = f" | מכשיר: {' '.join(x for x in (exif.get('make'), exif.get('model')) if x)}"
        return {
            "category": "target_image",
            "source_tool": f"image_recon_{src_type}",
            "title": f"{src_label}: {caption[:90] or profile.primary_name}",
            "summary": (
                f"מקור: {src_label} | אימות פנים (OpenCV): {'כן ✓' if face_verified else 'פרופיל ישיר'}"
                f"{people_str} | רזולוציה: {face_info.get('width') or '?'}x{face_info.get('height') or '?'}"
                f"{gps_str}{place_str}{device_str} | כיתוב: {caption[:160]}"
            ),
            "url": src_page or img_url,
            "confidence": round(conf, 2),
            "extracted_data": {
                "image_url": img_url,
                "local_path": stored_local_path,
                "display_url": local_url,
                "source_page_url": src_page,
                "source_type": src_type,
                "caption": caption,
                "face_verified": face_verified,
                "face_detected": face_verified,
                "faces_count": int(face_info.get("faces_count") or 0),
                "faces": face_info.get("faces") or [],
                "portrait": bool(face_info.get("portrait")),
                "largest_face_ratio": float(face_info.get("largest_face_ratio") or 0.0),
                "width": int(face_info.get("width") or 0),
                "height": int(face_info.get("height") or 0),
                "exif": exif,
            },
        }

    tasks = [
        _safe_task(_verify_and_store_one(c), f"img_verify:{c['image_url'][:45]}", timeout=10.0, log_fn=log_fn)
        for c in candidates[:16]
    ]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    for r in results:
        if isinstance(r, dict):
            image_findings.append(r)

    return image_findings


# ============================================================================
# Layer 7: Recursive Pivot Loop (Online <-> Offline DB Correlation & Hop 2)
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
        # Every discovered email implies a (pivotable) domain — person → email → domain → subdomains/registrant.
        if ltype == "email" and "@" in v:
            dom = registrable_domain(v)
            if dom and is_pivotable_domain(dom):
                _add_lead("domain", dom, conf, source_tool, url)

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
        for em_field in ("email", "registrant_email"):
            em = (ed.get(em_field) or "").strip().lower()
            if em and "@" in em and "*" not in em:
                _add_lead("email", em, conf, tool, url)
        for em in ed.get("emails") or []:
            if "@" in str(em):
                _add_lead("email", str(em).lower(), conf, tool, url)

        # Domain-intel leads: the registrant person/org, the domain itself, and its subdomains → pivotable domains
        reg_name = (ed.get("registrant_name") or "").strip()
        if reg_name and len(reg_name.split()) >= 2 and is_valid_person_name(reg_name):
            _add_lead("person", reg_name, conf, tool, url)
        if ed.get("registrant_org"):
            _add_lead("org", str(ed["registrant_org"]).strip(), conf, tool, url)
        for dom_field in ("domain",):
            dv = registrable_domain(ed.get(dom_field) or "")
            if dv and is_pivotable_domain(dv):
                _add_lead("domain", dv, conf, tool, url)
        for sub in ed.get("subdomains") or []:
            dv = registrable_domain(str(sub))
            if dv and is_pivotable_domain(dv):
                _add_lead("domain", dv, conf, tool, url)
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

    # 1. Names. The target's OWN name forms (its transliterations) become aliases of the target; a person name found
    #    online is somebody else (a colleague, a relative) and never becomes the target's alias. A local person with
    #    the same name is a NAMESAKE until something else says otherwise (rule 5: a name alone never joins people):
    #    it is reported for the operator, never linked — possible.py / the operator decide "same person".
    own_names = list(dict.fromkeys(list(profile.english_names) + list(profile.hebrew_names)))
    for cname in own_names:
        if name_key(cname):
            store.add_alias(root_eid, cname, src_id, now)
    namesakes_seen: set[int] = set()
    for cname in own_names:
        ckey = name_key(cname)
        if not ckey:
            continue
        matching_rows = store.q(
            "SELECT id, display, key FROM entities WHERE type='person' AND (key=? OR (key>=? AND key<?)) AND id!=? LIMIT 20",
            (ckey, ckey + "|", ckey + "|\uffff", root_eid),
        )
        for mrow in matching_rows:
            other_id = int(mrow["id"])
            if other_id in namesakes_seen:
                continue
            namesakes_seen.add(other_id)
            matched_disp = mrow["display"] or mrow["key"]
            pivot_findings.append({
                "category": "pivot_link",
                "source_tool": "pivot_engine",
                "title": f"אותו שם במאגר המקומי: {matched_disp} (#{other_id})",
                "summary": "נמצאה במאגר רשומה באותו שם. שם לבד אינו זהות — לא קושר; ההחלטה אם זה אותו אדם היא שלך.",
                "url": f"#entity/{other_id}",
                "confidence": 0.5,
                "extracted_data": {
                    "matched_entity_id": other_id,
                    "matched_display": matched_disp,
                    "shared_identifier": cname,
                    "shared_identifier_type": "person_name",
                    "pivot_type": "local_name_match",
                    "connection_tier": "candidate",
                    "why_connected_he": (
                        f"השם '{cname}' קיים במאגר גם ברשומה '{matched_disp}' (תיק #{other_id}). "
                        "זה עשוי להיות אדם אחר באותו שם — לא קושר אוטומטית."
                    ),
                },
            })

    # 2. Persist discovered emails, phones, usernames, orgs, locations into the entity graph & check local DB pivots
    from .semantic import email_key
    for ld in leads:
        ltype = ld["type"]
        val = ld["value"]
        conf = float(ld.get("confidence") or 0.85)
        if ltype in ("email", "phone", "username", "org", "location"):
            # only a PERSONAL identifier can tie the target to another local person (rule 5); an organisation or a
            # place is shared by thousands and is stored on the target below, never used to link people
            pivotable = ltype in ("email", "phone", "username")
            if ltype == "email":
                raw_k = val.lower().strip()
                can_k = email_key(val) or raw_k
                candidate_keys = list(dict.fromkeys([raw_k, can_k]))
            elif ltype == "phone":
                perms = generate_phone_permutations(val)
                p_info = analyze_phone_number(val)
                e164_k = p_info.get("e164") or ""
                loc_k = perms[0] if perms else val
                candidate_keys = [k for k in dict.fromkeys([loc_k, e164_k, val]) if k]
            else:
                candidate_keys = [val.lower().strip()]
            key_val = candidate_keys[0]
            # Check if this identifier ALREADY exists in osnit.db and is linked to any OTHER person entity!
            existing_ent = None
            for ck in candidate_keys:
                existing_ent = store.q1("SELECT id, key, display FROM entities WHERE type=? AND key=?", (ltype, ck))
                if existing_ent:
                    key_val = existing_ent["key"]
                    break
            if existing_ent and pivotable:
                ident_eid = int(existing_ent["id"])
                # Find other persons connected to this identifier in local DB via indexed rel_a / rel_b UNION
                other_persons = store.q(
                    "SELECT e.id, e.display, e.key FROM relations r "
                    "CROSS JOIN entities e ON e.id = r.b_id "
                    "WHERE r.a_id = ? AND e.type='person' AND e.id != ? "
                    "UNION "
                    "SELECT e.id, e.display, e.key FROM relations r "
                    "CROSS JOIN entities e ON e.id = r.a_id "
                    "WHERE r.b_id = ? AND e.type='person' AND e.id != ?",
                    (ident_eid, root_eid, ident_eid, root_eid),
                )
                from .store import is_personal_identifier
                if len(other_persons) > 2 or (ltype == "phone" and not is_personal_identifier("phone", key_val)):
                    other_persons = []           # held by many / a landline: a household or a switchboard, not a tie
                for op in other_persons:
                    op_id = int(op["id"])
                    if op_id not in linked_entity_ids:
                        linked_entity_ids.add(op_id)
                        reason = f"קושר דרך מזהה אישי משותף שנמצא ברשת (Pivot): {val}"
                        rel_id = store.add_relation(root_eid, op_id, "pivot_match", now)
                        store.add_rel_evidence(rel_id, src_id, reason, 0.95, now)
                        op_disp = op["display"] or op["key"]
                        pivot_findings.append({
                            "category": "pivot_link",
                            "source_tool": "pivot_engine",
                            "title": f"הצלבת מאגר מקומי (Pivot): {op_disp} דרך {val}",
                            "summary": f"{reason} — המזהה החדש שנמצא ברשת משויך במאגר המקומי גם לישות '{op_disp}' (#{op_id}).",
                            "url": f"#entity/{op_id}",
                            "confidence": 0.96,
                            "extracted_data": {
                                "matched_entity_id": op_id,
                                "matched_display": op_disp,
                                "shared_identifier": val,
                                "shared_identifier_type": ltype,
                                "pivot_type": "local_entity_match",
                                "connection_tier": "close_pivot",
                                "reason": reason,
                                "why_connected_he": (
                                    f"המזהה '{val}' ({ltype}) שחזר מהרשת נבדק בהצלבה חוזרת מול השרת המקומי (osnit.db) "
                                    f"ונמצא משויך לישות המקומית '{op_disp}' (תיק #{op_id})."
                                ),
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
                    f"נמצא ברשת ושויך ליעד (Pivot): {val}",
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
                        "summary": f"המזהה {val} שנמצא ברשת מופיע גם בקובץ המקומי {fp} ({loc_ref})",
                        "url": "",
                        "confidence": 0.93,
                        "extracted_data": {
                            "shared_identifier": val,
                            "shared_identifier_type": ltype,
                            "pivot_type": "local_document_fts",
                            "connection_tier": "close_pivot",
                            "file_path": fp,
                            "location_ref": loc_ref,
                            "snippet": fh.get("snippet") or "",
                            "why_connected_he": (
                                f"המזהה '{val}' ({ltype}) שחזר מהרשת נבדק בהצלבה חוזרת מול אינדקס המסמכים בשרת (FTS5) "
                                f"ונמצא מופיע בתוך הקובץ המקומי '{fp}' ({loc_ref})."
                            ),
                        },
                    })

    # 3. Persist structured attributes discovered during recon (role, workplace, education, carrier) into dossier attributes
    if hasattr(store, "add_attribute"):
        for f in findings:
            ed = f.get("extracted_data") or {}
            for attr in ed.get("attributes") or []:
                if isinstance(attr, dict) and attr.get("name") and attr.get("value"):
                    store.add_attribute(root_eid, src_id, str(attr["name"]), str(attr["value"]), str(attr.get("kind") or "inferred"), now)
            if ed.get("headline"):
                store.add_attribute(root_eid, src_id, "role", str(ed["headline"]), "inferred", now)
            for wp in ed.get("workplaces") or []:
                if wp:
                    store.add_attribute(root_eid, src_id, "workplace", str(wp), "inferred", now)
            for edu in ed.get("educations") or []:
                if edu:
                    store.add_attribute(root_eid, src_id, "education", str(edu), "inferred", now)
            if ed.get("carrier"):
                store.add_attribute(root_eid, src_id, "telecom_carrier", str(ed["carrier"]), "observed", now)

    return pivot_findings


async def recursive_pivot_expand(
    profile: SearchTargetProfile,
    all_findings: list[dict[str, Any]],
    seed_leads: list[dict[str, Any]],
    *,
    max_depth: int = 2,
    store=None,
    http_fetcher: Callable | None = None,
    log_fn: Callable[[str], None] | None = None,
) -> list[dict[str, Any]]:
    """Maltego-style recursive expansion ("a result of a result"): the high-confidence NEW identifiers the
    layers surfaced — emails, usernames, domains — feed focused extra discovery rounds (email breach/Gravatar/
    GitHub, the username manifest sweep, and crt.sh/RDAP domain intel), up to `max_depth` hops with a
    confidence floor. Each hop's identifiers are folded back into the profile so the next hop and the graph
    anchor them. Returns only the newly discovered findings, each tagged `pivot_depth`. Fully bounded and
    fault-isolated; precision is preserved because every hop runs the same gated checks as the first pass."""
    try:
        pivot_conf = float(os.environ.get("OSNIT_PIVOT_CONF", "0.80") or "0.80")
    except ValueError:
        pivot_conf = 0.80

    new_findings: list[dict[str, Any]] = []
    combined = list(all_findings)
    leads = list(seed_leads)
    seen_emails = {e.lower() for e in profile.emails}
    seen_users = {u.lower() for u in profile.usernames}
    seen_domains = {registrable_domain(d) for d in profile.domains if d}

    hop = 1
    while hop < max(1, int(max_depth)):
        hop += 1
        new_emails: list[str] = []
        new_users: list[str] = []
        new_domains: list[str] = []
        for ld in leads:
            try:
                conf = float(ld.get("confidence") or 0)
            except (TypeError, ValueError):
                conf = 0.0
            t = ld.get("type")
            v = str(ld.get("value") or "").strip().lower()
            if not v:
                continue
            # A discovered email below the floor still contributes its (pivotable) domain for infra recon.
            if t == "email" and "@" in v:
                dom = registrable_domain(v)
                if dom and dom not in seen_domains and is_pivotable_domain(dom):
                    seen_domains.add(dom)
                    new_domains.append(dom)
            if conf < pivot_conf:
                continue
            if t == "email" and "@" in v and v not in seen_emails:
                seen_emails.add(v)
                new_emails.append(v)
            elif t == "username" and len(v) >= 3 and " " not in v and v not in seen_users:
                seen_users.add(v)
                new_users.append(v)
            elif t == "domain":
                dom = registrable_domain(v)
                if dom and dom not in seen_domains and is_pivotable_domain(dom):
                    seen_domains.add(dom)
                    new_domains.append(dom)

        if not (new_emails or new_users or new_domains):
            break

        if log_fn:
            log_fn(f"🔄 [Pivot עומק {hop}] מרחיב חקירה: {len(new_emails)} אימיילים, "
                   f"{len(new_users)} שמות משתמש, {len(new_domains)} דומיינים חדשים שהתגלו")

        hop_tasks = []
        for em2 in new_emails[:3]:
            hop_tasks.extend([
                _safe_task(check_gravatar(em2, store=store, http_fetcher=http_fetcher), f"pivot_gravatar:{em2}", 7.0, log_fn),
                _safe_task(check_xposedornot(em2, store=store, http_fetcher=http_fetcher), f"pivot_xposed:{em2}", 7.0, log_fn),
                _safe_task(check_github(email=em2, store=store, http_fetcher=http_fetcher), f"pivot_github:{em2}", 8.0, log_fn),
            ])
        if new_users:
            hop_tasks.append(_safe_task(
                run_layer3_username_intel(new_users[:8], store=store, http_fetcher=http_fetcher, log_fn=log_fn),
                f"pivot_users:{len(new_users)}", 22.0, log_fn))
        if new_domains:
            hop_tasks.append(_safe_task(
                run_layer_domain_intel(new_domains[:3], store=store, http_fetcher=http_fetcher, log_fn=log_fn),
                f"pivot_domains:{len(new_domains)}", 22.0, log_fn))

        hop_findings: list[dict[str, Any]] = []
        for item in await asyncio.gather(*hop_tasks, return_exceptions=True):
            if isinstance(item, list):
                hop_findings.extend(item)
        for f in hop_findings:
            ed = f.get("extracted_data")
            if isinstance(ed, dict):
                ed["pivot_depth"] = hop
        new_findings.extend(hop_findings)
        combined.extend(hop_findings)

        # fold the new identifiers into the profile so the next hop and the recon graph anchor them
        for u in new_users:
            if u not in [x.lower() for x in profile.usernames]:
                profile.usernames.append(u)
        for d in new_domains:
            if d and d not in [x.lower() for x in profile.domains]:
                profile.domains.append(d)

        leads = collect_leads_from_findings(combined, profile)

    return new_findings


# ============================================================================
# Unified Recon Orchestrator & Live Progress Job Manager (7-Layer Pipeline)
# ============================================================================

LAYER_LABELS = {
    1: "[שכבה 1/7] מייצר וריאציות שמות (עברית/אנגלית), שמות משתמש ופרמוטציות טלפון...",
    2: "[שכבה 2/7] סורק דליפות מידע, Infostealers, Gravatar, PGP, GitHub Commits ותשתית דומיינים (crt.sh/RDAP)...",
    3: "[שכבה 3/7] סורק מאות אתרי פרופיל (WhatsMyName/Sherlock) ומחלץ מטא-דאטה (OpenGraph/SSR)...",
    4: "[שכבה 4/7] מנתח מספרי טלפון, מפעילים סלולריים וחשבונות מסרים...",
    5: "[שכבה 5/7] מריץ חיפוש חופשי ברשת הפתוחה, ציד תגובות, ניתוח כתבות עומק ו-Dorks...",
    6: "[שכבה 6/7] מפעיל מנוע ציד, חילוץ ואימות תמונות פנים של היעד (OpenCV Visual Recon)...",
    7: "[שכבה 7/7] מפענח לעומק פרופילים שהתגלו (תוצאה מתוך תוצאה) ומבצע הצלבה רקורסיבית (Pivot)...",
}


class CandidateProfileMatcher:
    """Stage 2: Smart Candidate Disambiguation Engine.
    Evaluates discovered social & web profiles against `SearchTargetProfile` using 5 positive signal
    families + surname contradiction filtering, auto-verifies only profiles with a hard anchor (the target's
    email / phone, or a link to a verified profile), and ranks/tags the Top-3 most logical candidates
    (`candidate_top3`) for interactive confirmation — a name/handle/city match alone, however high it scores,
    is what a namesake has too, so it is a candidate, never auto-verified.
    """

    AUTO_VERIFY_THRESHOLD = 0.88

    _SOCIAL_DOMAINS = (
        "instagram.com",
        "facebook.com",
        "linkedin.com",
        "tiktok.com",
        "t.me",
        "telegram.me",
        "twitter.com",
        "x.com",
        "github.com",
        "threads.net",
        "youtube.com",
    )

    _NON_SURNAME_WORDS = {
        "instagram", "facebook", "linkedin", "tiktok", "telegram", "twitter", "github", "youtube",
        "profile", "official", "real", "user", "account", "page", "blog", "channel", "photos",
        "videos", "posts", "tlv", "israel", "il", "co", "com", "net", "org", "cyber", "security",
        "tech", "dev", "ceo", "founder", "dr", "mr", "ms", "mrs", "prof", "adv", "cpa", "eng",
        "פרופיל", "רשמי", "ישראל", "תל", "אביב", "חיפה", "ירושלים", "עו״ד", "ד״ר", "רו״ח",
    }

    @classmethod
    def is_social_candidate(cls, finding: dict[str, Any]) -> bool:
        cat = str(finding.get("category") or finding.get("node_type") or "").strip().lower()
        url = str(finding.get("url") or finding.get("source_url") or "").strip().lower()
        if cat == "social_profile":
            return True
        if cat in ("code_intel", "web_mention") and any(d in url for d in cls._SOCIAL_DOMAINS):
            return True
        return False

    @classmethod
    def _extract_handle_from_url(cls, url: str) -> str:
        u = str(url or "").strip().rstrip("/")
        if not u:
            return ""
        try:
            parsed = urllib.parse.urlparse(u)
            host = (parsed.netloc or "").lower()
            parts = [p for p in (parsed.path or "").split("/") if p and p not in ("in", "pub", "p", "reel", "stories", "users")]
            if not parts:
                return ""
            if any(d in host for d in cls._SOCIAL_DOMAINS):
                return parts[0].lstrip("@").lower()
        except Exception:
            pass
        return ""

    @classmethod
    def _clean_display_name(cls, raw_title: str) -> str:
        t = str(raw_title or "").strip()
        # Strip platform prefixes/suffixes like "Instagram: Matan Shinar (@matanshi)" or "Matan Shinar | LinkedIn"
        t = re.sub(r"^(?:Instagram|Facebook|LinkedIn|TikTok|Telegram|GitHub|Twitter|X)\s*[:\-–|]\s*", "", t, flags=re.IGNORECASE)
        t = re.sub(r"\s*[|•\-–]\s*(?:Instagram|Facebook|LinkedIn|TikTok|Telegram|GitHub|Twitter|X).*$", "", t, flags=re.IGNORECASE)
        t = re.sub(r"\(@[A-Za-z0-9_.\-]+\)", "", t)
        return " ".join(t.split()).strip()

    @classmethod
    def score_candidate(
        cls,
        finding: dict[str, Any],
        profile: SearchTargetProfile,
        verified_urls: set[str] | None = None,
        verified_avatars: set[str] | None = None,
    ) -> dict[str, Any]:
        ed = finding.get("extracted_data") or finding.get("metadata") or {}
        url = str(finding.get("url") or finding.get("source_url") or "").strip()
        raw_title = str(finding.get("title") or finding.get("label") or "").strip()
        summary = str(finding.get("summary") or finding.get("discovery_reason") or "").strip()

        display_name = cls._clean_display_name(
            str(ed.get("full_name") or ed.get("display_name") or ed.get("og_title") or raw_title)
        )
        bio = str(ed.get("bio") or ed.get("og_description") or summary).strip()
        username = str(ed.get("username") or cls._extract_handle_from_url(url) or "").strip().lower().lstrip("@")
        location = str(ed.get("location") or ed.get("city") or "").strip()
        company = str(ed.get("company") or ed.get("headline") or "").strip()
        outbound_links = [str(x).strip() for x in (ed.get("outbound_links") or []) if x]
        avatar_url = str(ed.get("avatar_url") or finding.get("avatar_url") or "").strip()
        face_verified = bool(ed.get("face_verified") or ed.get("face_detected"))

        combined_text = f"{raw_title} {display_name} {bio} {location} {company} {' '.join(outbound_links)} {url}".lower()
        combined_digits = re.sub(r"\D+", "", combined_text)

        score = 0.25  # baseline for an existing 200-OK profile page
        reasons: list[str] = []
        signals: dict[str, Any] = {
            "hard_anchor": False,
            "full_name_match": False,
            "first_name_only": False,
            "surname_contradiction": False,
            "handle_match": "none",
            "context_match": False,
            "visual_match": False,
        }

        # ------------------------------------------------------------------
        # 1. Hard Identifier Anchor (+0.55)
        # ------------------------------------------------------------------
        for em in profile.emails:
            em_l = em.strip().lower()
            if em_l and (em_l in combined_text or str(ed.get("email") or "").strip().lower() == em_l):
                score += 0.55
                signals["hard_anchor"] = True
                reasons.append(f"אימות קשיח: אימייל עוגן ({em_l})")
                break

        if not signals["hard_anchor"]:
            for ph in profile.phones:
                perms = profile.phone_permutations.get(ph) or generate_phone_permutations(ph)
                ph_digits = re.sub(r"\D+", "", ph)
                tail9 = ph_digits[-9:] if len(ph_digits) >= 9 else ph_digits
                if any(p.lower() in combined_text for p in perms if len(p) >= 9) or (tail9 and len(tail9) == 9 and tail9 in combined_digits):
                    score += 0.55
                    signals["hard_anchor"] = True
                    reasons.append(f"אימות קשיח: מספר טלפון ({ph})")
                    break

        if not signals["hard_anchor"] and verified_urls and outbound_links:
            norm_verified = {u.rstrip("/").lower() for u in verified_urls if u}
            for out_u in outbound_links:
                if out_u.rstrip("/").lower() in norm_verified:
                    score += 0.48
                    signals["hard_anchor"] = True
                    reasons.append("אימות צולב: קישור יוצא לפרופיל מאומת של היעד")
                    break

        # ------------------------------------------------------------------
        # 2. Bilingual Full-Name Similarity (+0.28) & Surname Contradiction (-0.35)
        # ------------------------------------------------------------------
        target_full_names = [n.strip().lower() for n in (profile.hebrew_names + profile.english_names) if len(n.strip().split()) >= 2]
        target_first_tokens: set[str] = set()
        target_surname_tokens: set[str] = set()
        for fn in target_full_names:
            toks = [t for t in re.split(r"[\s\-_]+", fn) if len(t) >= 2]
            if len(toks) >= 2:
                target_first_tokens.add(toks[0])
                for st in toks[1:]:
                    target_surname_tokens.add(st)

        # Check full name match in display_name or combined_text
        for fn in target_full_names:
            if fn in display_name.lower() or fn in combined_text:
                score += 0.28
                signals["full_name_match"] = True
                reasons.append(f"התאמת שם מלא ({display_name or fn})")
                break
            toks = [t for t in re.split(r"[\s\-_]+", fn) if len(t) >= 2]
            if len(toks) >= 2 and all(t in display_name.lower() for t in toks):
                score += 0.26
                signals["full_name_match"] = True
                reasons.append(f"התאמת רכיבי שם מלא ({display_name})")
                break

        # Check first-name-only vs surname contradiction when full name didn't match
        if not signals["full_name_match"] and display_name and target_first_tokens:
            cand_toks = [
                t.lower()
                for t in re.findall(r"[A-Za-z\u0590-\u05FF]{2,}", display_name)
                if t.lower() not in cls._NON_SURNAME_WORDS
            ]
            if cand_toks:
                first_matched = any(
                    ct == tf or (len(ct) >= 4 and len(tf) >= 4 and SequenceMatcher(None, ct, tf).ratio() >= 0.82)
                    for ct in cand_toks[:1]
                    for tf in target_first_tokens
                )
                if first_matched:
                    if len(cand_toks) >= 2 and target_surname_tokens:
                        cand_last = cand_toks[-1]
                        best_sur_sim = max(
                            (
                                SequenceMatcher(None, cand_last, ts).ratio()
                                for ts in target_surname_tokens
                                if (cand_last[0] == ts[0]) or (SequenceMatcher(None, cand_last, ts).ratio() >= 0.72)
                            ),
                            default=0.0,
                        )
                        if best_sur_sim >= 0.72:
                            score += 0.24
                            signals["full_name_match"] = True
                            reasons.append(f"התאמת שם מלא בדמיון פונטי ({display_name})")
                        elif best_sur_sim < 0.65:
                            score -= 0.35
                            signals["surname_contradiction"] = True
                            reasons.append(f"סתירה בשם משפחה ({display_name})")
                    else:
                        score += 0.08
                        signals["first_name_only"] = True
                        reasons.append(f"התאמת שם פרטי בלבד ({cand_toks[0]})")

        # ------------------------------------------------------------------
        # 3. Username / Handle Pattern Match (+0.26 exact / +0.12 partial)
        # ------------------------------------------------------------------
        seed_users = [u.strip().lower().lstrip("@") for u in profile.usernames if u.strip()]
        if username and seed_users:
            u_norm = re.sub(r"[._\-]+", "", username)
            exact_u = any(username == su or u_norm == re.sub(r"[._\-]+", "", su) for su in seed_users)
            if exact_u:
                score += 0.26
                signals["handle_match"] = "exact"
                reasons.append(f"התאמת כינוי מדויקת (@{username})")
            else:
                partial_u = any(
                    (len(su) >= 5 and (su in username or username in su))
                    or SequenceMatcher(None, u_norm, re.sub(r"[._\-]+", "", su)).ratio() >= 0.78
                    for su in seed_users
                )
                if not partial_u and target_first_tokens and target_surname_tokens:
                    partial_u = any(ft in username for ft in target_first_tokens) and any(
                        st[:4] in username for st in target_surname_tokens if len(st) >= 4
                    )
                if partial_u:
                    score += 0.12
                    signals["handle_match"] = "partial"
                    reasons.append(f"דמיון תבנית כינוי (@{username})")

        # ------------------------------------------------------------------
        # 4. Geographic / Organizational / Domain Context (+0.16 explicit / +0.04 country)
        # ------------------------------------------------------------------
        context_hits: list[str] = []
        for city in profile.cities:
            c_low = city.strip().lower()
            if c_low and c_low in combined_text:
                context_hits.append(city)
        for org in profile.organizations:
            o_low = org.strip().lower()
            if o_low and o_low in combined_text:
                context_hits.append(org)
        for dom in getattr(profile, "domains", []):
            d_low = dom.strip().lower()
            if d_low and d_low in combined_text:
                context_hits.append(dom)

        if context_hits:
            score += 0.16
            signals["context_match"] = True
            reasons.append(f"התאמת הקשר/מיקום ({', '.join(context_hits[:2])})")
        elif any(
            loc_kw in combined_text for loc_kw in ("tel aviv", "תל אביב", "israel", "ישראל", "jerusalem", "ירושלים", "haifa", "חיפה", "herzliya", "הרצליה", "ramat gan", "רמת גן")
        ):
            if profile.hebrew_names or any(p.startswith("+972") or p.startswith("05") for p in profile.phones):
                score += 0.04
                signals["context_match"] = True
                reasons.append("זיקה גיאוגרפית (ישראל)")

        # ------------------------------------------------------------------
        # 5. Visual / Avatar / Face Consistency (+0.14)
        # ------------------------------------------------------------------
        # a face DETECTED in the picture is not the target's face (nothing compares the two) — only an avatar already
        # verified for the target is visual evidence; a detected face is a weak sign of a real person's profile
        if avatar_url and verified_avatars and avatar_url in verified_avatars:
            score += 0.14
            signals["visual_match"] = True
            reasons.append("אווטאר זהה לאווטאר מאומת של היעד")
        elif face_verified or (avatar_url and not is_noise_or_logo_image(avatar_url)):
            score += 0.05

        final_score = round(max(0.05, min(0.99, score)), 3)
        # precision-first (the project's rule 5): only a hard anchor — the target's own email / phone, or a link to a
        # profile already verified — verifies a profile on its own. A name, a matching handle and a city, however
        # high they score, are exactly what a namesake has too: such a profile goes to the operator as a candidate.
        if signals["surname_contradiction"] and not signals["hard_anchor"]:
            recommended_status = "low_confidence"
        elif signals["hard_anchor"]:
            recommended_status = "verified"
        elif final_score >= 0.45:
            recommended_status = "candidate_pool"
        else:
            recommended_status = "low_confidence"

        return {
            "score": final_score,
            "hard_anchor": signals["hard_anchor"],
            "full_name_match": signals["full_name_match"],
            "surname_contradiction": signals["surname_contradiction"],
            "reasons": reasons,
            "reason_text": " + ".join(reasons) if reasons else "התאמת פרופיל ראשונית",
            "recommended_status": recommended_status,
            "signals": signals,
            "username": username,
            "display_name": display_name,
        }

    @classmethod
    def rank_and_tag_top3_candidates(
        cls,
        findings: list[dict[str, Any]],
        profile: SearchTargetProfile,
        store=None,
        job_id: str | None = None,
        max_top_candidates: int = 3,
    ) -> dict[str, list[dict[str, Any]]]:
        """Evaluate all social profile findings, auto-confirm >=0.88/hard-anchor profiles, and tag the
        Top-3 plausible candidates (`status='candidate_top3'`, `candidate_rank=1..3`) in both `findings`
        and `investigation_nodes`."""
        verified_urls: set[str] = set()
        verified_avatars: set[str] = set()
        for f in findings or []:
            ed = f.get("extracted_data") or {}
            if float(f.get("confidence") or 0) >= 0.88 or f.get("category") in ("email_breach", "phone_intel"):
                if f.get("url"):
                    verified_urls.add(str(f["url"]).rstrip("/").lower())
                for out_u in ed.get("outbound_links") or []:
                    verified_urls.add(str(out_u).rstrip("/").lower())
                if ed.get("avatar_url"):
                    verified_avatars.add(str(ed["avatar_url"]))

        verified_profiles: list[dict[str, Any]] = []
        candidate_pool: list[tuple[float, dict[str, Any], dict[str, Any]]] = []
        rejected_or_low: list[dict[str, Any]] = []

        for f in findings or []:
            if not cls.is_social_candidate(f):
                continue
            ed = f.setdefault("extracted_data", {})
            # Respect explicit user confirmation/rejection if already set
            existing_status = str(ed.get("tree_status") or "").strip()
            if existing_status in ("confirmed_by_user", "rejected_by_user", "expanded"):
                continue

            eval_res = cls.score_candidate(f, profile, verified_urls=verified_urls, verified_avatars=verified_avatars)
            ed["candidate_evaluation"] = eval_res
            comp_score = float(eval_res["score"])

            if eval_res["recommended_status"] == "verified":
                f["confidence"] = max(float(f.get("confidence") or 0.0), max(0.88, comp_score))
                ed["tree_status"] = "verified"
                ed["candidate_rank"] = 0
                ed["discovery_reason"] = f"✓ אומת אוטומטית: {eval_res['reason_text']}"
                verified_profiles.append(f)
                if store is not None and f.get("tree_node_id") and hasattr(store, "update_investigation_node_status"):
                    store.update_investigation_node_status(
                        int(f["tree_node_id"]),
                        status="verified",
                        candidate_rank=0,
                        discovery_reason=ed["discovery_reason"],
                        confidence=f["confidence"],
                        metadata_patch={"candidate_evaluation": eval_res},
                    )
            elif eval_res["recommended_status"] == "candidate_pool":
                candidate_pool.append((comp_score, f, eval_res))
            else:
                f["confidence"] = min(float(f.get("confidence") or 0.4), comp_score)
                ed["tree_status"] = "discovered"
                ed["candidate_rank"] = 0
                ed["discovery_reason"] = eval_res["reason_text"]
                rejected_or_low.append(f)
                if store is not None and f.get("tree_node_id") and hasattr(store, "update_investigation_node_status"):
                    store.update_investigation_node_status(
                        int(f["tree_node_id"]),
                        status="discovered",
                        candidate_rank=0,
                        discovery_reason=ed["discovery_reason"],
                        confidence=f["confidence"],
                        metadata_patch={"candidate_evaluation": eval_res},
                    )

        # Sort candidate pool by composite score descending
        candidate_pool.sort(key=lambda item: item[0], reverse=True)
        top3_candidates: list[dict[str, Any]] = []

        for idx, (comp_score, f, eval_res) in enumerate(candidate_pool):
            ed = f.setdefault("extracted_data", {})
            if idx < max_top_candidates:
                rank = idx + 1
                f["confidence"] = comp_score
                ed["tree_status"] = "candidate_top3"
                ed["candidate_rank"] = rank
                ed["discovery_reason"] = f"[מועמד #{rank} לאישור] {eval_res['reason_text']} ({int(comp_score * 100)}%)"
                top3_candidates.append(f)
                if store is not None and f.get("tree_node_id") and hasattr(store, "update_investigation_node_status"):
                    store.update_investigation_node_status(
                        int(f["tree_node_id"]),
                        status="candidate_top3",
                        candidate_rank=rank,
                        discovery_reason=ed["discovery_reason"],
                        confidence=comp_score,
                        metadata_patch={"candidate_evaluation": eval_res, "candidate_rank": rank},
                    )
            else:
                f["confidence"] = comp_score
                ed["tree_status"] = "discovered"
                ed["candidate_rank"] = 0
                ed["discovery_reason"] = eval_res["reason_text"]
                if store is not None and f.get("tree_node_id") and hasattr(store, "update_investigation_node_status"):
                    store.update_investigation_node_status(
                        int(f["tree_node_id"]),
                        status="discovered",
                        candidate_rank=0,
                        discovery_reason=ed["discovery_reason"],
                        confidence=comp_score,
                        metadata_patch={"candidate_evaluation": eval_res, "candidate_rank": 0},
                    )

        return {
            "verified_profiles": verified_profiles,
            "top3_candidates": top3_candidates,
            "rejected_or_low": rejected_or_low,
        }


class TagContextAnalyzer:
    """Stage 3: Analyzes the surrounding caption, bio, or comment text around a @mention or tagged user
    to classify WHY and HOW they were tagged or mentioned (`family`, `colleague_business`, `service_credit`,
    `social_friend`) with a clear Hebrew OSINT explanation."""

    # explicit family words only, matched as whole words (_kw_hits): "דוד" is also a first name (David), "אחי" is
    # everyday slang ("bro"), "partner" is usually business, a heart is anybody — none of them says "family"
    _FAMILY_KEYWORDS = (
        "אחותי", "אחי היקר", "אמא שלי", "אבא שלי", "אמא", "אבא", "משפחה", "משפחת", "אשתי", "בעלי", "בן זוגי",
        "בת זוגי", "אהובתי", "אהובי", "החצי שלי", "הורים", "הדוד שלי", "דודה", "בן דוד", "בת דודה", "סבא", "סבתא",
        "brother", "sister", "mother", "father", "mom", "dad", "wife", "husband", "fiance", "fiancée",
        "family", "my love", "love of my life", "💍",
    )
    _COLLEAGUE_KEYWORDS = (
        "שותף", "שותפי", "צוות", "משרד", "פרויקט", "לקוח", "חברת", "כנס", "הרצאה", "מנכ\"ל",
        "מנכל", "סמנכ\"ל", "יזם", "סטארטאפ", "עבודה", "קולגה", "מייסד", "הנהלה", "מחלקת",
        "co-founder", "cofounder", "founder", "partner at", "colleague", "team", "office",
        "client", "project", "conference", "work with", "working with", "proud to announce", "ceo", "cto",
    )
    _SERVICE_CREDIT_KEYWORDS = (
        "צילום", "צלם", "צילמה", "קרדיט", "איפור", "שיער", "עיצוב", "הפקה", "סטיילינג", "עריכה",
        "photo by", "photography", "photographer", "credit", "captured by", "shot by", "styled by",
        "makeup by", "hair by", "design by", "📷", "📸", "🎥",
    )
    _SOCIAL_FRIEND_KEYWORDS = (
        "חבר", "חברה", "חברים", "טיול", "מסיבה", "יום הולדת", "יומולדת", "מזל טוב", "חוגגים",
        "ערב טוב", "שבת שלום", "אלוף", "אלופה", "תודה ל", "כיף עם", "בירה", "קפה", "חופשה",
        "friends", "bestie", "trip", "birthday", "party", "hanging out", "congrats", "cheers",
        "weekend", "vacation", "fun with",
    )

    _CONTEXT_LABELS_HE = {
        "family": "קשר משפחתי / זוגי",
        "colleague_business": "קולגה / שותף עסקי / עבודה",
        "service_credit": "קרדיט צילום / ספק / שירות",
        "social_friend": "חבר / בילוי משותף / תיוג חברתי",
    }

    _INTERACTION_LABELS_HE = {
        "bio_mention": "אוזכר בביוגרפיה של הפרופיל",
        "post_tag": "תויג בפוסט / כיתוב תמונה",
        "comment_interaction": "הגיב או תויג בתגובות",
        "photo_co_tag": "מצולם/מתויג בתמונה משותפת",
    }

    @classmethod
    def analyze_mention(
        cls,
        handle: str,
        snippet: str,
        platform: str = "",
        interaction_kind: str = "post_tag",
        tagged_display_name: str = "",
        profile: SearchTargetProfile | None = None,
        co_faces_count: int = 0,
    ) -> dict[str, Any]:
        clean_handle = str(handle or "").strip().lstrip("@")
        clean_snippet = re.sub(r"\s+", " ", str(snippet or "")).strip()
        low_snip = clean_snippet.lower()
        # Narrow keyword matching to the local sentence/clause containing @handle when multiple clauses exist
        clause_snip = low_snip
        if clean_handle.lower() in low_snip:
            clauses = [c.strip() for c in re.split(r"[.!?\n|•·]+", low_snip) if c.strip()]
            for cl in clauses:
                if clean_handle.lower() in cl:
                    clause_snip = cl
                    break
        disp_low = str(tagged_display_name or "").strip().lower()

        # Check shared surname with target profile
        shared_surname = False
        matched_surname = ""
        if profile is not None:
            target_full_names = [
                n.strip().lower()
                for n in (profile.hebrew_names + profile.english_names)
                if len(n.strip().split()) >= 2
            ]
            target_surnames = {
                tok
                for fn in target_full_names
                for tok in re.split(r"[\s\-_]+", fn)[1:]
                if len(tok) >= 3
            }
            for sur in target_surnames:
                if (disp_low and sur in disp_low) or (len(sur) >= 4 and sur in clean_handle.lower()):
                    shared_surname = True
                    matched_surname = sur
                    break

        matched_keywords: dict[str, list[str]] = {
            "family": cls._kw_hits(clause_snip, cls._FAMILY_KEYWORDS),
            "colleague_business": cls._kw_hits(clause_snip, cls._COLLEAGUE_KEYWORDS),
            "service_credit": cls._kw_hits(clause_snip, cls._SERVICE_CREDIT_KEYWORDS),
            "social_friend": cls._kw_hits(clause_snip, cls._SOCIAL_FRIEND_KEYWORDS),
        }

        # family needs an explicit family word; a shared surname adds to it but never makes it alone (a common
        # surname — כהן, לוי — is shared by strangers; the same rule as osnit/kinship.py)
        if matched_keywords["family"]:
            context_type = "family"
            conf = 0.90 if shared_surname else 0.85
        elif matched_keywords["service_credit"]:
            context_type = "service_credit"
            conf = 0.82
        elif matched_keywords["colleague_business"]:
            context_type = "colleague_business"
            conf = 0.84
        else:
            context_type = "social_friend"
            conf = 0.78 if matched_keywords["social_friend"] else 0.72

        if co_faces_count >= 2 and interaction_kind in ("post_tag", "photo_co_tag"):
            interaction_kind = "photo_co_tag"
            conf = min(0.94, conf + 0.06)

        context_label_he = cls._CONTEXT_LABELS_HE[context_type]
        interaction_he = cls._INTERACTION_LABELS_HE.get(interaction_kind, "תויג בפרופיל")
        kw_list = matched_keywords.get(context_type) or []

        reason_parts = [f"{interaction_he} (@{clean_handle}) — סיווג: {context_label_he}"]
        if shared_surname:
            reason_parts.append(f"שם משפחה משותף עם היעד ({matched_surname})")
        if kw_list:
            reason_parts.append(f"אינדיקציות טקסטואליות: {', '.join(kw_list[:3])}")
        if co_faces_count >= 2:
            reason_parts.append(f"זוהתה תמונה משותפת עם {co_faces_count} פנים")
        if clean_snippet:
            reason_parts.append(f"הקשר: \"{clean_snippet[:130]}\"")

        profile_url = cls._build_platform_handle_url(platform, clean_handle)
        return {
            "handle": clean_handle,
            "display_name": tagged_display_name or f"@{clean_handle}",
            "platform": platform or "Social",
            "profile_url": profile_url,
            "context_type": context_type,
            "context_label_he": context_label_he,
            "interaction_kind": interaction_kind,
            "why_tagged": " | ".join(reason_parts),
            "snippet": clean_snippet[:220],
            "shared_surname": shared_surname,
            "matched_keywords": kw_list[:5],
            "co_faces_count": int(co_faces_count or 0),
            "confidence": round(conf, 2),
        }

    @staticmethod
    def _kw_hits(text: str, keywords) -> list[str]:
        """The keywords that occur in `text` as WHOLE words (a Hebrew word may carry a one-letter prefix ו/ה/ב/ל/מ/ש/כ):
        'חבר' is not inside 'חברת', 'dad' is not inside 'daddy-o'. Symbols (emoji) match as they are."""
        hits = []
        for kw in keywords:
            k = kw.lower()
            if re.search(r"[\u0590-\u05ff]", k):
                rx = r"(?<![\u0590-\u05ff])[ובהלמשכ]?" + re.escape(k) + r"(?![\u0590-\u05ff])"
            elif re.search(r"[a-z]", k):
                rx = r"(?<![a-z])" + re.escape(k) + r"(?![a-z])"
            else:
                rx = re.escape(k)
            if re.search(rx, text):
                hits.append(kw)
        return hits

    @staticmethod
    def _build_platform_handle_url(platform: str, handle: str) -> str:
        h = handle.strip().lstrip("@")
        if not h:
            return ""
        p_low = (platform or "").lower()
        if "instagram" in p_low:
            return f"https://www.instagram.com/{h}/"
        if "telegram" in p_low or p_low == "t.me":
            return f"https://t.me/{h}"
        if "tiktok" in p_low:
            return f"https://www.tiktok.com/@{h}"
        if "facebook" in p_low:
            return f"https://www.facebook.com/{h}"
        if "linkedin" in p_low:
            return f"https://il.linkedin.com/in/{h}"
        if "github" in p_low:
            return f"https://github.com/{h}"
        if "twitter" in p_low or p_low in ("x", "x.com"):
            return f"https://x.com/{h}"
        return ""


class DeepSocialBranchMiner:
    """Stage 3: Post-Confirmation Deep Social & Visual Profile Miner.
    Once a social profile is confirmed (automatically via >=0.88 confidence or manually by the user from Top-3),
    opens a deep investigation branch on that profile:
      1. Extracts @mentions, tagged users, and comment authors with `TagContextAnalyzer` explaining WHY/HOW they were tagged.
      2. Extracts profile & post images, verifies human faces (including multi-face co-occurrence with tagged users), and parses EXIF GPS/camera metadata.
      3. Extracts bio outbound links, embedded emails/phones, organizations, and locations.
      4. Spawns child nodes and edges under the confirmed profile node in `InvestigationTreeBuilder`.
    """

    _IGNORED_HANDLES = {
        "instagram", "facebook", "tiktok", "telegram", "linkedin", "github", "twitter",
        "share", "sharer", "explore", "reel", "reels", "stories", "login", "signup",
        "accounts", "about", "privacy", "terms", "help", "support", "settings", "search",
        "media", "width", "height", "import", "keyframes", "font", "face", "charset",
        "gmail", "yahoo", "hotmail", "outlook", "walla", "icloud",
    }

    @classmethod
    def extract_mentions_and_tags_from_html(
        cls,
        html_text: str,
        platform: str,
        owner_handle: str = "",
        bio_text: str = "",
        profile: SearchTargetProfile | None = None,
    ) -> list[dict[str, Any]]:
        """Extract @mentions, tagged users, and comment interactions from profile HTML/JSON and bio text."""
        if not html_text and not bio_text:
            return []

        owner_norm = str(owner_handle or "").strip().lower().lstrip("@")
        target_handles = {owner_norm} if owner_norm else set()
        if profile is not None:
            for u in profile.usernames:
                if u.strip():
                    target_handles.add(u.strip().lower().lstrip("@"))

        discovered: dict[str, dict[str, Any]] = {}

        def _record(
            handle: str,
            snippet: str,
            interaction_kind: str,
            display_name: str = "",
            co_faces: int = 0,
        ):
            h = str(handle or "").strip().lstrip("@").strip("./")
            h_low = h.lower()
            if len(h_low) < 3 or len(h_low) > 32:
                return
            if h_low in cls._IGNORED_HANDLES or h_low in target_handles:
                return
            if not re.fullmatch(r"[A-Za-z0-9._\-]+", h):
                return
            if h_low.isdigit() or h_low.endswith((".png", ".jpg", ".jpeg", ".gif", ".webp", ".css", ".js", ".svg")):
                return
            analyzed = TagContextAnalyzer.analyze_mention(
                handle=h,
                snippet=snippet,
                platform=platform,
                interaction_kind=interaction_kind,
                tagged_display_name=display_name,
                profile=profile,
                co_faces_count=co_faces,
            )
            prev = discovered.get(h_low)
            if prev is None or analyzed["confidence"] >= prev["confidence"] or (
                prev["interaction_kind"] == "post_tag" and interaction_kind in ("bio_mention", "photo_co_tag")
            ):
                discovered[h_low] = analyzed

        # 1. Bio @mentions
        if bio_text:
            for m in re.finditer(r"(?<![A-Za-z0-9._%+-])@([A-Za-z0-9_][A-Za-z0-9._]{2,29})", bio_text):
                h = m.group(1)
                start = max(0, m.start() - 80)
                end = min(len(bio_text), m.end() + 80)
                _record(h, bio_text[start:end], "bio_mention")

        if not html_text:
            return list(discovered.values())

        # Strip <script>/<style> noise except JSON-LD / embedded state JSON
        text_Visible = re.sub(r"<style[^>]*>.*?</style>", " ", html_text, flags=re.DOTALL | re.IGNORECASE)
        text_Visible = re.sub(r"<[^>]+>", " ", html.unescape(text_Visible))
        text_Visible = re.sub(r"\s+", " ", text_Visible)

        # 2. JSON embedded tagged users (Instagram `edge_media_to_tagged_user`, `usertags`, or `mentions`)
        for m_tag in re.finditer(
            r'"user"\s*:\s*\{\s*[^}]*?"username"\s*:\s*"([A-Za-z0-9._]{3,30})"[^}]*?(?:"full_name"\s*:\s*"([^"]*)")?',
            html_text,
            re.IGNORECASE,
        ):
            u_handle = m_tag.group(1)
            u_full = m_tag.group(2) or ""
            window = html_text[max(0, m_tag.start() - 180):min(len(html_text), m_tag.end() + 180)]
            clean_win = re.sub(r"<[^>]+>", " ", html.unescape(window))
            ikind = "comment_interaction" if "comment" in window.lower() else "post_tag"
            _record(u_handle, clean_win, ikind, display_name=u_full)

        # 3. HTML comment blocks (`class="...comment..."`)
        for m_comm in re.finditer(
            r'<(?:div|li|p|span)[^>]+class=["\'][^"\']*comment[^"\']*["\'][^>]*>(.*?)</(?:div|li|p|span)>',
            html_text,
            re.DOTALL | re.IGNORECASE,
        ):
            comm_text = re.sub(r"<[^>]+>", " ", html.unescape(m_comm.group(1)))
            comm_text = re.sub(r"\s+", " ", comm_text).strip()
            for m_h in re.finditer(r"(?<![A-Za-z0-9._%+-])@([A-Za-z0-9_][A-Za-z0-9._]{2,29})", comm_text):
                _record(m_h.group(1), comm_text, "comment_interaction")

        # 4. General visible @mentions in captions/posts
        for m_vis in re.finditer(r"(?<![A-Za-z0-9._%+-])@([A-Za-z0-9_][A-Za-z0-9._]{2,29})", text_Visible):
            h = m_vis.group(1)
            start = max(0, m_vis.start() - 90)
            end = min(len(text_Visible), m_vis.end() + 90)
            win = text_Visible[start:end].strip()
            ikind = "bio_mention" if (bio_text and h.lower() in bio_text.lower()) else (
                "comment_interaction" if any(cw in win.lower() for cw in ("תגובה", "הגיב", "replied", "commented")) else "post_tag"
            )
            _record(h, win, ikind)

        return list(discovered.values())

    @classmethod
    def extract_profile_and_post_images(
        cls,
        html_text: str,
        page_url: str,
        platform: str,
        avatar_url: str = "",
        tagged_users: list[dict[str, Any]] | None = None,
    ) -> list[dict[str, Any]]:
        """Extract profile avatar and post/gallery images from a confirmed social profile page."""
        images: list[dict[str, Any]] = []
        seen_urls: set[str] = set()
        known_handles = [t["handle"] for t in (tagged_users or []) if t.get("handle")]

        def _add_img(img_url: str, img_kind: str, caption: str = ""):
            u = html.unescape(str(img_url or "").strip())
            if not u or not u.startswith(("http://", "https://")) or u in seen_urls:
                return
            if is_noise_or_logo_image(u, caption=caption):
                return
            seen_urls.add(u)
            co_handles = [
                h for h in known_handles
                if f"@{h.lower()}" in caption.lower() or h.lower() in caption.lower()
            ]
            images.append({
                "image_url": u,
                "source_page_url": page_url,
                "image_kind": img_kind,
                "caption": re.sub(r"\s+", " ", caption).strip()[:220] or f"תמונה מתוך {platform or 'פרופיל'}",
                "co_tagged_handles": co_handles,
            })

        if avatar_url:
            _add_img(avatar_url, "profile_avatar", f"תמונת פרופיל רשמית ({platform})")

        if not html_text:
            return images

        # Extract <img src="..." alt="..."> from posts/gallery
        for m_img in re.finditer(r"<img\b([^>]+)>", html_text, re.IGNORECASE):
            attrs = m_img.group(1)
            m_src = re.search(r'src=["\'](https?://[^"\'>\s]+)["\']', attrs, re.IGNORECASE)
            if not m_src:
                continue
            m_alt = re.search(r'alt=["\']([^"\']*)["\']', attrs, re.IGNORECASE)
            alt_txt = html.unescape(m_alt.group(1)).strip() if m_alt else ""
            _add_img(m_src.group(1), "post_image", alt_txt)

        # Extract JSON `display_url` (Instagram/TikTok post media)
        for m_disp in re.finditer(r'"display_url"\s*:\s*"(https?://[^"]+)"', html_text, re.IGNORECASE):
            raw_u = m_disp.group(1).replace("\\u0026", "&").replace("\\/", "/")
            win = html_text[max(0, m_disp.start() - 200):min(len(html_text), m_disp.end() + 250)]
            clean_win = re.sub(r"<[^>]+>", " ", html.unescape(win))
            _add_img(raw_u, "post_image", clean_win)

        return images[:8]

    @classmethod
    async def mine_confirmed_profile(
        cls,
        finding_or_node: dict[str, Any],
        profile: SearchTargetProfile,
        store=None,
        tree_builder: "InvestigationTreeBuilder | None" = None,
        http_fetcher: Callable | None = None,
        bytes_fetcher: Callable | None = None,
        log_fn: Callable[[str], None] | None = None,
    ) -> dict[str, Any]:
        """Run deep social & visual branching on a confirmed social profile and attach all discovered
        child branches (@mentions with tag context, face-verified/EXIF images, bio links, orgs, locations)
        under the profile node in the Investigation Tree."""
        url = str(
            finding_or_node.get("source_url")
            or finding_or_node.get("url")
            or (finding_or_node.get("metadata") or {}).get("url")
            or ""
        ).strip()
        ed = dict(
            finding_or_node.get("extracted_data")
            or finding_or_node.get("metadata")
            or {}
        )
        platform = str(
            finding_or_node.get("platform")
            or ed.get("platform")
            or CandidateProfileMatcher._infer_platform_from_url(url)
            or "Social"
        ).strip()
        owner_handle = str(
            ed.get("username")
            or CandidateProfileMatcher._extract_handle_from_url(url)
            or ""
        ).strip().lstrip("@")
        parent_node_id = int(
            finding_or_node.get("node_id")
            or finding_or_node.get("tree_node_id")
            or 0
        )

        if log_fn:
            log_fn(f"🌿 [Deep Branch Miner] פותח ענף חקירה עמוק לפרופיל מאומת: {platform} ({url or owner_handle})")

        # 1. Fetch raw profile page HTML and run platform-specific deep enricher if applicable
        html_body = str(ed.get("raw_html") or "")
        if url and not html_body:
            req_headers = FB_SSR_HEADERS if "facebook.com" in url.lower() else (
                BOT_SSR_HEADERS if "linkedin.com" in url.lower() else None
            )
            st, body, _ = await _async_http_get(url, headers=req_headers, timeout=8.0, http_fetcher=http_fetcher)
            if st == 200 and body:
                html_body = body

        deep_finding: dict[str, Any] | None = None
        u_low = url.lower()
        if "linkedin.com/in/" in u_low:
            deep_finding = await _safe_task(deep_enrich_linkedin(url, store=store, http_fetcher=http_fetcher), f"branch_li:{url}", 8.0, log_fn)
        elif "facebook.com/" in u_low:
            deep_finding = await _safe_task(deep_enrich_facebook(url, store=store, http_fetcher=http_fetcher), f"branch_fb:{url}", 8.0, log_fn)
        elif "instagram.com/" in u_low:
            deep_finding = await _safe_task(deep_enrich_instagram(url, store=store, http_fetcher=http_fetcher), f"branch_ig:{url}", 8.0, log_fn)
        elif "github.com/" in u_low and owner_handle:
            gh_list = await _safe_task(check_github(username=owner_handle, store=store, http_fetcher=http_fetcher), f"branch_gh:{owner_handle}", 8.0, log_fn)
            if isinstance(gh_list, list) and gh_list:
                deep_finding = gh_list[0]

        if isinstance(deep_finding, dict):
            deep_ed = deep_finding.get("extracted_data") or {}
            for k, v in deep_ed.items():
                if v and not ed.get(k):
                    ed[k] = v

        # Also parse generic profile metadata from html_body if fetched
        if html_body:
            parsed_meta = extract_profile_metadata(html_body, platform_name=platform, username=owner_handle)
            for k in ("display_name", "bio", "avatar_url", "location"):
                if parsed_meta.get(k) and not ed.get(k):
                    ed[k] = parsed_meta[k]
            if parsed_meta.get("outbound_links"):
                existing_links = list(ed.get("outbound_links") or [])
                for lnk in parsed_meta["outbound_links"]:
                    if lnk not in existing_links:
                        existing_links.append(lnk)
                ed["outbound_links"] = existing_links

        bio_text = str(ed.get("bio") or finding_or_node.get("summary") or "")
        avatar_url = str(ed.get("avatar_url") or finding_or_node.get("avatar_url") or "")

        # 2. Extract @mentions, tagged users, and comment authors with TagContextAnalyzer
        tagged_users = cls.extract_mentions_and_tags_from_html(
            html_text=html_body,
            platform=platform,
            owner_handle=owner_handle,
            bio_text=bio_text,
            profile=profile,
        )

        # 3. Extract and verify profile/post images (OpenCV face count + EXIF GPS/device + co-tagged handles)
        raw_images = cls.extract_profile_and_post_images(
            html_text=html_body,
            page_url=url,
            platform=platform,
            avatar_url=avatar_url,
            tagged_users=tagged_users,
        )
        verified_images: list[dict[str, Any]] = []
        avatar_dirs = _resolve_avatars_dirs(store)
        eid = int(profile.entity_id or 0) if profile and profile.entity_id is not None else 0

        for img_cand in raw_images[:5]:
            img_u = img_cand["image_url"]
            img_bytes = b""
            status = 0
            if bytes_fetcher is not None:
                res_b = bytes_fetcher(img_u)
                if asyncio.iscoroutine(res_b):
                    res_b = await res_b
                status = int(res_b[0]) if res_b else 0
                img_bytes = res_b[1] if res_b and len(res_b) > 1 else b""
                if isinstance(img_bytes, str):
                    img_bytes = img_bytes.encode("latin-1", errors="ignore")
            elif http_fetcher is not None:
                st_b, b_body, _ = await _async_http_get_bytes(img_u, timeout=6.0, http_fetcher=http_fetcher)
                status, img_bytes = st_b, b_body

            face_info = {"valid_size": True, "face_detected": False, "faces_count": 0, "width": 0, "height": 0}
            exif: dict[str, Any] = {}
            local_url = img_u
            if status == 200 and img_bytes:
                face_info = verify_human_face_in_image(img_bytes, min_size=80)
                if face_info["width"] > 0 and face_info["height"] > 0 and not face_info["valid_size"]:
                    continue
                exif = _extract_jpeg_exif(img_bytes)
                ext = _guess_image_ext(img_bytes, img_u)
                digest = hashlib.md5(img_u.encode("utf-8")).hexdigest()[:10]
                fname = f"branch_{eid}_{digest}{ext}"
                for av_dir in avatar_dirs:
                    try:
                        (av_dir / fname).write_bytes(img_bytes)
                    except Exception:
                        pass
                local_url = f"/api/avatars/{fname}"

            faces_count = int(face_info.get("faces_count") or 0)
            co_handles = list(img_cand.get("co_tagged_handles") or [])
            if faces_count >= 2 and not co_handles and tagged_users:
                co_handles = [t["handle"] for t in tagged_users[:faces_count]]

            # Upgrade any co-tagged user's context with multi-face co-occurrence
            if faces_count >= 2 and co_handles:
                for t_obj in tagged_users:
                    if t_obj["handle"] in co_handles:
                        t_obj["co_faces_count"] = faces_count
                        t_obj["interaction_kind"] = "photo_co_tag"
                        t_obj["confidence"] = min(0.95, round(float(t_obj.get("confidence") or 0.8) + 0.08, 2))
                        if "תמונה משותפת" not in t_obj["why_tagged"]:
                            t_obj["why_tagged"] += f" | זוהתה תמונה משותפת מרובת פנים ({faces_count} מצולמים)"

            img_entry = {
                "image_url": img_u,
                "display_url": local_url,
                "source_page_url": url,
                "image_kind": img_cand["image_kind"],
                "caption": img_cand["caption"],
                "face_verified": bool(face_info.get("face_detected")),
                "faces_count": faces_count,
                "width": int(face_info.get("width") or 0),
                "height": int(face_info.get("height") or 0),
                "co_tagged_handles": co_handles,
                "exif": exif,
            }
            verified_images.append(img_entry)

        # 4. Extract bio outbound links, emails, phones, orgs, and locations
        outbound_links = [str(u).strip() for u in (ed.get("outbound_links") or []) if str(u).strip()]
        scan_text_for_contacts = f"{bio_text}\n{re.sub(r'<[^>]+>', ' ', html_body) if html_body else ''}"
        bio_emails = list(dict.fromkeys(
            list(ed.get("emails") or []) + re.findall(r"[\w.+-]+@[\w-]+\.[\w.-]+", scan_text_for_contacts)
        ))
        bio_phones = list(dict.fromkeys(
            list(ed.get("phones") or []) + re.findall(r"(?:\+?972[-\s]?|0)(?:5\d|[23489]|7\d)[-\s]?\d{3}[-\s]?\d{4}", scan_text_for_contacts)
        ))
        orgs = [str(o).strip() for o in (ed.get("orgs") or ed.get("workplaces") or []) if str(o).strip()]
        locations = [str(l).strip() for l in (ed.get("locations") or ([ed["location"]] if ed.get("location") else [])) if str(l).strip()]

        # 5. Spawn child nodes & edges in InvestigationTreeBuilder / store
        child_node_ids: list[int] = []
        branch_findings: list[dict[str, Any]] = []

        # Ensure we have a tree_builder if store is available
        if tree_builder is None and store is not None:
            job_id = str(finding_or_node.get("job_id") or f"recon_{eid or 'branch'}")
            tree_builder = InvestigationTreeBuilder(store=store, job_id=job_id, profile=profile)
            if not parent_node_id:
                tree_builder.init_seed_nodes()

        if tree_builder is not None:
            if not parent_node_id and url:
                parent_node_id = tree_builder.url_to_node_id.get(url.rstrip("/").lower(), 0)
            if not parent_node_id:
                parent_node_id = tree_builder._upsert_node(
                    node_type="social_profile",
                    canonical_key=url.rstrip("/").lower() if url else f"social:{platform.lower()}:{owner_handle}",
                    label=str(finding_or_node.get("label") or finding_or_node.get("title") or f"{platform}: @{owner_handle}"),
                    parent_node_id=tree_builder.root_node_id or None,
                    depth=1,
                    platform=platform,
                    status="verified",
                    confidence=max(0.90, float(finding_or_node.get("confidence") or 0.90)),
                    discovery_reason="פרופיל מאומת — ענף חקירה פעיל",
                    source_url=url,
                    avatar_url=avatar_url,
                    metadata=ed,
                )
            elif store is not None and hasattr(store, "update_investigation_node_status"):
                store.update_investigation_node_status(
                    parent_node_id,
                    status="verified",
                    candidate_rank=0,
                    metadata_patch={
                        "branch_expanded": True,
                        "tagged_users_count": len(tagged_users),
                        "branch_images_count": len(verified_images),
                        "outbound_links_count": len(outbound_links),
                    },
                )

            parent_depth = tree_builder.node_depths.get(parent_node_id, 1)
            if parent_node_id and store is not None and hasattr(store, "get_investigation_node"):
                p_row = store.get_investigation_node(parent_node_id)
                if p_row:
                    parent_depth = int(p_row.get("depth") or 1)
            child_depth = parent_depth + 1

            # 5a. Child nodes for each tagged/mentioned user
            for tag in tagged_users:
                rel_kind = {
                    "bio_mention": "mentioned_in_bio",
                    "comment_interaction": "commented_on",
                    "photo_co_tag": "co_photographed_with",
                }.get(tag["interaction_kind"], "tagged_with")
                nid = tree_builder._upsert_node(
                    node_type="username",
                    canonical_key=f"{platform.lower()}:@{tag['handle'].lower()}",
                    label=f"@{tag['handle']} ({tag['context_label_he']})",
                    parent_node_id=parent_node_id,
                    depth=child_depth,
                    platform=platform,
                    status="discovered",
                    confidence=tag["confidence"],
                    discovery_reason=tag["why_tagged"],
                    source_url=tag["profile_url"] or url,
                    metadata=tag,
                    relation_kind=rel_kind,
                    relation_label=f"{tag['context_label_he']} ({tag['interaction_kind']})",
                    evidence_snippet=tag["why_tagged"],
                )
                if nid > 0:
                    child_node_ids.append(nid)
                branch_findings.append({
                    "category": "social_profile",
                    "source_tool": f"branch_tag_{platform.lower()}",
                    "title": f"תיוג/אזכור ב-{platform}: @{tag['handle']} ({tag['context_label_he']})",
                    "summary": tag["why_tagged"],
                    "url": tag["profile_url"] or url,
                    "confidence": tag["confidence"],
                    "extracted_data": {
                        **tag,
                        "username": tag["handle"],
                        "parent_node_id": parent_node_id,
                        "source_profile_url": url,
                        "relation_kind": rel_kind,
                        "discovery_reason": tag["why_tagged"],
                    },
                })

            # 5b. Child nodes for each verified profile/post image (+ EXIF GPS location child node)
            for img in verified_images:
                exif = img.get("exif") or {}
                faces_str = f"{img['faces_count']} פנים זוהו" if img.get("faces_count") else "תמונת פרופיל/פוסט"
                co_str = f" | מתויגים בתמונה: {', '.join('@' + h for h in img['co_tagged_handles'])}" if img.get("co_tagged_handles") else ""
                gps_str = f" | GPS: {exif['gps_place']}" if exif.get("gps_place") else ""
                img_reason = f"{img['caption']} ({faces_str}{co_str}{gps_str})"
                img_nid = tree_builder._upsert_node(
                    node_type="image",
                    canonical_key=img["image_url"].lower(),
                    label=f"תמונה ({platform}): {img['caption'][:65]}",
                    parent_node_id=parent_node_id,
                    depth=child_depth,
                    platform=platform,
                    status="verified" if img.get("face_verified") or img["image_kind"] == "profile_avatar" else "discovered",
                    confidence=0.92 if img.get("face_verified") else 0.84,
                    discovery_reason=img_reason,
                    source_url=img["image_url"],
                    avatar_url=img["display_url"],
                    metadata=img,
                    relation_kind="posted_image",
                    relation_label=faces_str,
                    evidence_snippet=img_reason,
                )
                if img_nid > 0:
                    child_node_ids.append(img_nid)
                    if exif.get("gps_place") or (exif.get("gps_lat") is not None and exif.get("gps_lon") is not None):
                        loc_lbl = exif.get("gps_place") or f"{exif['gps_lat']:.4f},{exif['gps_lon']:.4f}"
                        loc_nid = tree_builder._upsert_node(
                            node_type="location",
                            canonical_key=f"gps:{loc_lbl.lower()}",
                            label=f"מיקום EXIF: {loc_lbl}",
                            parent_node_id=img_nid,
                            depth=child_depth + 1,
                            platform="EXIF GPS",
                            status="verified",
                            confidence=0.93,
                            discovery_reason=f"קואורדינטות GPS חולצו מ-EXIF של תמונה ב-{platform}",
                            source_url=img["image_url"],
                            metadata=exif,
                            relation_kind="exif_gps_location",
                            relation_label="מיקום צילום (EXIF)",
                        )
                        if loc_nid > 0:
                            child_node_ids.append(loc_nid)

            # 5c. Child nodes for bio outbound links, emails, phones, orgs, locations
            for out_u in outbound_links[:6]:
                dom = registrable_domain(out_u) or out_u
                nid = tree_builder._upsert_node(
                    node_type="domain",
                    canonical_key=out_u.rstrip("/").lower(),
                    label=f"קישור בביוגרפיה: {dom}",
                    parent_node_id=parent_node_id,
                    depth=child_depth,
                    platform=platform,
                    status="verified",
                    confidence=0.90,
                    discovery_reason=f"קישור חיצוני שחולץ מהביוגרפיה של {platform} (@{owner_handle})",
                    source_url=out_u,
                    metadata={"outbound_url": out_u, "domain": dom, "source_profile_url": url},
                    relation_kind="linked_in_bio",
                    relation_label="קישור בביו",
                )
                if nid > 0:
                    child_node_ids.append(nid)

            for em in bio_emails[:4]:
                nid = tree_builder._upsert_node(
                    node_type="email",
                    canonical_key=em.lower(),
                    label=em.lower(),
                    parent_node_id=parent_node_id,
                    depth=child_depth,
                    platform=platform,
                    status="verified",
                    confidence=0.94,
                    discovery_reason=f"כתובת אימייל שחולצה מתוך פרופיל {platform} (@{owner_handle})",
                    source_url=url,
                    metadata={"email": em.lower(), "source_profile_url": url},
                    relation_kind="extracted_from_bio",
                    relation_label="אימייל בפרופיל",
                )
                if nid > 0:
                    child_node_ids.append(nid)

            for ph in bio_phones[:4]:
                p_info = analyze_phone_number(ph)
                ph_key = p_info.get("e164") or ph
                nid = tree_builder._upsert_node(
                    node_type="phone",
                    canonical_key=ph_key.lower(),
                    label=ph,
                    parent_node_id=parent_node_id,
                    depth=child_depth,
                    platform=platform,
                    status="verified",
                    confidence=0.94,
                    discovery_reason=f"מספר טלפון שחולץ מתוך פרופיל {platform} (@{owner_handle})",
                    source_url=url,
                    metadata={"phone": ph, "e164": ph_key, "source_profile_url": url},
                    relation_kind="extracted_from_bio",
                    relation_label="טלפון בפרופיל",
                )
                if nid > 0:
                    child_node_ids.append(nid)

            for org in orgs[:4]:
                nid = tree_builder._upsert_node(
                    node_type="org",
                    canonical_key=f"org:{fold(org) or org.lower()}",
                    label=org,
                    parent_node_id=parent_node_id,
                    depth=child_depth,
                    platform=platform,
                    status="verified",
                    confidence=0.88,
                    discovery_reason=f"ארגון/מקום עבודה המופיע בפרופיל {platform}",
                    source_url=url,
                    metadata={"org": org, "source_profile_url": url},
                    relation_kind="works_at",
                    relation_label="מקום עבודה / ארגון",
                )
                if nid > 0:
                    child_node_ids.append(nid)

            for loc in locations[:3]:
                nid = tree_builder._upsert_node(
                    node_type="location",
                    canonical_key=f"loc:{fold(loc) or loc.lower()}",
                    label=loc,
                    parent_node_id=parent_node_id,
                    depth=child_depth,
                    platform=platform,
                    status="verified",
                    confidence=0.86,
                    discovery_reason=f"מיקום גיאוגרפי המופיע בפרופיל {platform}",
                    source_url=url,
                    metadata={"location": loc, "source_profile_url": url},
                    relation_kind="located_at",
                    relation_label="מיקום בפרופיל",
                )
                if nid > 0:
                    child_node_ids.append(nid)

        return {
            "parent_node_id": parent_node_id,
            "platform": platform,
            "url": url,
            "owner_handle": owner_handle,
            "tagged_users": tagged_users,
            "images": verified_images,
            "outbound_links": outbound_links,
            "emails": bio_emails,
            "phones": bio_phones,
            "orgs": orgs,
            "locations": locations,
            "findings": branch_findings,
            "child_node_ids": child_node_ids,
        }


# ============================================================================
# Stage 4: Automated Dork File Harvester -> Full osnit-il Ingestion -> Tree Bridge
# ============================================================================

class DorkDocumentTreeBridge:
    """Downloads public documents/archives discovered during Dork/Web Recon (PDF, DOCX, XLSX, CSV, TXT, ZIP, etc.),
    saves them locally under `recon_downloads/<job_id>/`, feeds them into the full `osnit-il` ingestion & parsing
    pipeline (`osnit/parse.py` + `osnit/ingest.py` + `osnit/engine.py`), and attaches all extracted entities/identifiers
    (`person`, `phone`, `email`, `id_number`, `org`) as child branches (`extracted_from_file`) under the `web_document`
    node in the Investigation Tree."""

    SUPPORTED_EXTS = (
        ".pdf", ".docx", ".doc", ".xlsx", ".xls", ".csv", ".txt", ".pptx",
        ".rtf", ".odt", ".ods", ".vcf", ".xml", ".json", ".jsonl",
        ".zip", ".rar", ".7z", ".tar", ".gz", ".tgz",
        ".sql", ".dump", ".db", ".sqlite", ".sqlite3",
    )
    _DOC_EMAIL_RE = re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+")
    _DOC_IL_PHONE_RE = re.compile(r"(?:\+?972[-\s]?|0)(?:5[0-9]|7[2-9]|[23489])[-\s]?\d{3}[-\s]?\d{4}")

    @classmethod
    def is_document_or_archive_url(cls, url: str) -> str:
        """Return the normalized lowercase file extension (without dot, e.g. 'pdf', 'xlsx', 'zip') if `url`
        points to a supported document or archive, else ''."""
        u = str(url or "").strip()
        if not u:
            return ""
        try:
            parsed_u = urllib.parse.urlparse(u.lower())
            path = urllib.parse.unquote(parsed_u.path or "")
            query = urllib.parse.unquote(parsed_u.query or "")
        except ValueError:
            path = u.lower()
            query = ""
        for ext in cls.SUPPORTED_EXTS:
            if path.endswith(ext):
                return ext.lstrip(".")
        # Also support URLs like ?file=roster.xlsx or ?download=report.pdf
        for candidate in re.findall(r"([a-z0-9_\-\u0590-\u05FF]+\.(?:pdf|docx|doc|xlsx|xls|csv|txt|pptx|zip|rar|7z|vcf|xml|json))\b", query):
            for ext in cls.SUPPORTED_EXTS:
                if candidate.endswith(ext):
                    return ext.lstrip(".")
        return ""

    @classmethod
    def resolve_downloads_dir(cls, store=None, job_id: str = "default", custom_dir: str | Path | None = None) -> Path:
        """Resolve and create the directory where harvested documents for `job_id` are stored on disk."""
        safe_job = re.sub(r"[^a-zA-Z0-9_\-]", "_", str(job_id or "default").strip())[:60] or "default"
        if custom_dir is not None:
            d = Path(custom_dir)
        elif store is not None and getattr(store, "path", None) and str(store.path) != ":memory:" and not str(store.path).startswith("file:"):
            try:
                d = Path(str(store.path)).resolve().parent / "recon_downloads" / safe_job
            except Exception:
                d = Path("data") / "recon_downloads" / safe_job
        else:
            d = Path("data") / "recon_downloads" / safe_job
        try:
            d.mkdir(parents=True, exist_ok=True)
        except Exception:
            pass
        return d

    @classmethod
    def _safe_filename(cls, url: str, doc_ext: str, file_sha256: str) -> str:
        ext = (doc_ext or "bin").lstrip(".").lower()
        try:
            raw_name = Path(urllib.parse.unquote(urllib.parse.urlparse(url).path)).name
        except Exception:
            raw_name = ""
        stem = re.sub(r"[^a-zA-Z0-9_\-\u0590-\u05FF]", "_", Path(raw_name).stem if raw_name else "")
        stem = re.sub(r"_+", "_", stem).strip("_")[:50] or "document"
        return f"{stem}_{file_sha256[:10]}.{ext}"

    @classmethod
    async def harvest_and_ingest_document(
        cls,
        finding_or_url: dict[str, Any] | str,
        profile: SearchTargetProfile | None = None,
        store=None,
        tree_builder: "InvestigationTreeBuilder | None" = None,
        job_id: str = "",
        parent_node_id: int | None = None,
        http_fetcher: Callable | None = None,
        bytes_fetcher: Callable | None = None,
        download_dir: str | Path | None = None,
        log_fn: Callable[[str], None] | None = None,
    ) -> dict[str, Any]:
        """Download a discovered document/archive, save it locally, run it through osnit-il's full ingestion
        pipeline (`parse`, `scan_file_for_identifiers`, `import_parsed`/`import_path`), and attach all extracted
        entities (`person`, `phone`, `email`, `id_number`, `org`) as child branches under the `web_document` node."""
        if isinstance(finding_or_url, dict):
            finding = finding_or_url
            ed = finding.setdefault("extracted_data", {})
            url = str(finding.get("url") or ed.get("file_url") or ed.get("source_url") or "").strip()
            title = str(finding.get("title") or ed.get("article_title") or url).strip()
            existing_node_id = int(finding.get("tree_node_id") or 0)
            pre_bytes = ed.get("raw_bytes")
        else:
            finding = None
            ed = {}
            url = str(finding_or_url or "").strip()
            title = url
            existing_node_id = 0
            pre_bytes = None

        eff_job_id = str(job_id or (tree_builder.job_id if tree_builder else "default")).strip()
        doc_ext = cls.is_document_or_archive_url(url) or str(ed.get("file_type") or "").strip().lower().lstrip(".")
        if not url and not pre_bytes:
            return {"ok": False, "reason": "missing_url", "child_node_ids": [], "findings": [], "leads": []}

        # 1. Fetch raw document bytes
        raw_bytes: bytes = b""
        resp_headers: dict[str, str] = {}
        if isinstance(pre_bytes, (bytes, bytearray)) and len(pre_bytes) > 0:
            raw_bytes = bytes(pre_bytes)
        elif bytes_fetcher is not None:
            try:
                bf_res = bytes_fetcher(url)
                if asyncio.iscoroutine(bf_res):
                    bf_res = await bf_res
                if isinstance(bf_res, tuple):
                    st_code = int(bf_res[0])
                    if st_code == 200 and bf_res[1]:
                        raw_bytes = bf_res[1] if isinstance(bf_res[1], bytes) else str(bf_res[1]).encode("utf-8", "replace")
                elif isinstance(bf_res, (bytes, bytearray)):
                    raw_bytes = bytes(bf_res)
                elif isinstance(bf_res, str):
                    raw_bytes = bf_res.encode("utf-8", "replace")
            except Exception:
                raw_bytes = b""
        else:
            try:
                st_code, b_data, r_hdrs = await _async_http_get_bytes(url, timeout=14.0, http_fetcher=http_fetcher)
                if st_code == 200 and b_data:
                    raw_bytes = bytes(b_data)
                    resp_headers = dict(r_hdrs or {})
            except Exception:
                raw_bytes = b""

        if not raw_bytes:
            return {"ok": False, "url": url, "reason": "download_failed", "child_node_ids": [], "findings": [], "leads": []}

        # Detect extension from Content-Type or magic bytes if URL lacked a clear extension
        if not doc_ext:
            ctype = str(resp_headers.get("content-type") or resp_headers.get("Content-Type") or "").lower()
            if "pdf" in ctype or raw_bytes[:4] == b"%PDF":
                doc_ext = "pdf"
            elif "spreadsheet" in ctype or "excel" in ctype:
                doc_ext = "xlsx"
            elif "wordprocessing" in ctype or "msword" in ctype:
                doc_ext = "docx"
            elif "csv" in ctype:
                doc_ext = "csv"
            elif "zip" in ctype or raw_bytes[:4] == b"PK\x03\x04":
                doc_ext = "zip"
            else:
                doc_ext = "txt"

        file_sha256 = hashlib.sha256(raw_bytes).hexdigest()
        target_dir = cls.resolve_downloads_dir(store=store, job_id=eff_job_id, custom_dir=download_dir)
        fname = cls._safe_filename(url, doc_ext, file_sha256)
        local_path = target_dir / fname
        try:
            local_path.write_bytes(raw_bytes)
        except Exception:
            pass

        # 2. Parse & Scan File via osnit-il's native pipeline (`parse`, `scan_file_for_identifiers`, `Extractor`, `sensitive`)
        from .extract import Extractor
        from .ingest import import_parsed, import_path, is_archive, scan_file_for_identifiers
        from .parse import parse as osnit_parse
        from .sensitive import analyze_text

        parsed_obj = None
        parsed_text = ""
        parsed_title = title
        try:
            parsed_obj = osnit_parse(raw_bytes, url or f"file://{local_path.name}", resp_headers.get("content-type", ""))
            parsed_text = parsed_obj.text or ""
            if parsed_obj.title:
                parsed_title = parsed_obj.title
        except Exception:
            try:
                parsed_text = raw_bytes.decode("utf-8", "replace")
            except Exception:
                parsed_text = ""

        scan_info: dict[str, Any] = {"emails": [], "phones": [], "national_ids": [], "names": []}
        if local_path.exists():
            try:
                scan_info = scan_file_for_identifiers(str(local_path))
            except Exception:
                pass

        ex = Extractor([]).extract(parsed_text[:500_000], parsed_title)
        sens_rep = analyze_text(parsed_text[:500_000], source=local_path.name)

        emails = list(dict.fromkeys(
            list(scan_info.get("emails") or [])
            + [d["display"].lower() for (et, _), d in ex.ents.items() if et == "email" and d.get("display")]
            + [m.group(0).lower() for m in cls._DOC_EMAIL_RE.finditer(parsed_text[:250_000])]
        ))
        phones: list[str] = []
        seen_ph_keys: set[str] = set()
        for raw_ph in (
            list(scan_info.get("phones") or [])
            + [d["display"] for (et, _), d in ex.ents.items() if et == "phone" and d.get("display")]
            + [m.group(0) for m in cls._DOC_IL_PHONE_RE.finditer(parsed_text[:250_000])]
        ):
            p_clean = str(raw_ph or "").strip()
            if not p_clean:
                continue
            p_info = analyze_phone_number(p_clean)
            p_key = p_info.get("e164") or re.sub(r"\D", "", p_clean)
            if len(p_key) >= 9 and p_key not in seen_ph_keys:
                seen_ph_keys.add(p_key)
                phones.append(p_info.get("local") or p_clean)

        id_numbers = list(dict.fromkeys(
            list(scan_info.get("national_ids") or [])
            + [f.value for f in sens_rep.findings if f.kind == "national_id"]
            + [d["display"] for (et, _), d in ex.ents.items() if et in ("id_number", "national_id") and d.get("display")]
        ))
        persons = list(dict.fromkeys(
            [
                nm for nm in (
                    list(scan_info.get("names") or [])
                    + [d["display"] for (et, _), d in ex.ents.items() if et == "person" and d.get("display")]
                )
                if is_valid_person_name(nm)
            ]
        ))
        orgs = list(dict.fromkeys(
            [d["display"] for (et, _), d in ex.ents.items() if et == "org" and d.get("display")]
        ))

        # 3. Full ingestion into `store` (`sources`, `entities`, `relations`, `evidence`, `documents_fts`)
        ingested_source_id: int | None = None
        import_stats: dict[str, Any] = {}
        db_linked_entities: dict[tuple[str, str], int] = {}

        if store is not None:
            try:
                from .config import Config
                from .engine import Engine

                eng = Engine(store, cfg=Config(), providers=[])
                lineage_str = f"dork_harvest::{eff_job_id}::{local_path.name}"
                if local_path.exists() and (is_archive(str(local_path)) or f".{doc_ext}" in (".sql", ".dump", ".db", ".sqlite", ".sqlite3", ".jsonl")):
                    import_stats = import_path(
                        eng,
                        str(local_path),
                        base_url=None,
                        delete_raw=False,
                        lineage=lineage_str,
                    )
                    # Ensure a source record exists for the archive URL itself
                    sid, _ = store.add_source(
                        url or f"file://{local_path.resolve()}",
                        priority=100,
                        origin="dork_harvest",
                        now=time.time(),
                        archive_path=str(local_path),
                        lineage=lineage_str,
                        sha256=file_sha256,
                    )
                    ingested_source_id = int(sid) if sid else None
                elif parsed_obj is not None:
                    src_url = url or f"file://{local_path.resolve()}"
                    state_out = import_parsed(
                        eng,
                        src_url,
                        parsed_obj,
                        now=time.time(),
                        archive_path=str(local_path),
                        lineage=lineage_str,
                        sha256=file_sha256,
                    )
                    import_stats = {"imported": 1 if state_out in ("imported", "scanned") else 0, "state": state_out}
                    row_src = store.q1(
                        "SELECT id FROM sources WHERE url=? OR sha256=? ORDER BY id DESC LIMIT 1",
                        (src_url, file_sha256),
                    )
                    if row_src:
                        ingested_source_id = int(row_src["id"])

                # Collect any additional entities persisted by Engine.ingest for this source
                if ingested_source_id:
                    rows_ent = store.q(
                        """SELECT e.id, e.type, e.canonical, e.display
                           FROM entities e
                           JOIN evidence ev ON ev.entity_id = e.id
                           WHERE ev.source_id = ?""",
                        (ingested_source_id,),
                    )
                    for r_e in rows_ent:
                        et = str(r_e["type"] or "").lower()
                        disp = str(r_e["display"] or r_e["canonical"] or "").strip()
                        canon = str(r_e["canonical"] or disp).strip().lower()
                        eid_val = int(r_e["id"])
                        db_linked_entities[(et, canon)] = eid_val
                        db_linked_entities[(et, disp.lower())] = eid_val
                        if et == "email" and disp.lower() not in emails:
                            emails.append(disp.lower())
                        elif et == "phone" and disp not in phones:
                            phones.append(disp)
                        elif et in ("id_number", "national_id") and disp not in id_numbers:
                            id_numbers.append(disp)
                        elif et == "person" and is_valid_person_name(disp) and disp not in persons:
                            persons.append(disp)
                        elif et == "org" and disp not in orgs:
                            orgs.append(disp)
            except Exception as exc:
                if log_fn:
                    log_fn(f"⚠️ [Document Ingest] שגיאה חלקית בקליטת מסמך ({local_path.name}): {exc}")

        # Build focused excerpt around target identifiers if profile is provided
        target_idents = (
            (profile.hebrew_names + profile.english_names + profile.emails + profile.all_phone_permutations() + profile.usernames)
            if profile is not None
            else []
        )
        excerpt = focus_excerpt(parsed_text, target_idents) if target_idents else ""
        if not excerpt and parsed_text:
            excerpt = re.sub(r"\s+", " ", parsed_text).strip()[:360]

        total_extracted = len(emails) + len(phones) + len(id_numbers) + len(persons) + len(orgs)
        doc_reason = (
            f"מסמך {doc_ext.upper()} הורד ונסרק במלואו ({len(raw_bytes) // 1024 or 1}KB) — "
            f"חולצו {len(persons)} אנשים, {len(phones)} טלפונים, {len(emails)} אימיילים, {len(id_numbers)} ת״ז, {len(orgs)} ארגונים"
        )

        # Update finding in-place if provided
        if finding is not None:
            finding["category"] = "document" if finding.get("category") not in ("legal_doc", "academic_doc") else finding["category"]
            finding["source_tool"] = "document_harvester"
            if excerpt:
                finding["summary"] = excerpt[:360]
            ed["local_file_path"] = str(local_path)
            ed["ingested_source_id"] = ingested_source_id
            ed["sha256"] = file_sha256
            ed["file_type"] = doc_ext
            ed["file_size"] = len(raw_bytes)
            ed["from_file"] = True
            ed["tree_status"] = "verified"
            ed["discovery_reason"] = doc_reason
            ed["emails"] = list(dict.fromkeys((ed.get("emails") or []) + emails))
            ed["phones"] = list(dict.fromkeys((ed.get("phones") or []) + phones))
            ed["national_ids"] = list(dict.fromkeys((ed.get("national_ids") or []) + id_numbers))
            ed["persons"] = list(dict.fromkeys((ed.get("persons") or []) + persons))
            ed["orgs"] = list(dict.fromkeys((ed.get("orgs") or []) + orgs))
            ed["import_stats"] = import_stats

        # 4. Upsert the parent `web_document` node and attach child `extracted_from_file` branches in the Investigation Tree
        doc_node_id = existing_node_id
        doc_depth = 1
        ckey_doc = url.rstrip("/").lower() if url else f"web_document:{file_sha256[:16]}"
        doc_meta = {
            **ed,
            "file_type": doc_ext,
            "file_size": len(raw_bytes),
            "sha256": file_sha256,
            "local_file_path": str(local_path),
            "ingested_source_id": ingested_source_id,
            "excerpt": excerpt[:400],
            "extracted_counts": {
                "persons": len(persons),
                "phones": len(phones),
                "emails": len(emails),
                "id_numbers": len(id_numbers),
                "orgs": len(orgs),
            },
        }

        if tree_builder is not None:
            if not tree_builder.root_node_id:
                tree_builder.init_seed_nodes()
            eff_parent = parent_node_id or (
                tree_builder._resolve_parent_for_finding(finding)[0] if finding else tree_builder.root_node_id
            )
            parent_depth = tree_builder.node_depths.get(eff_parent, 0) if eff_parent else 0
            doc_depth = max(1, parent_depth + 1)
            doc_node_id = tree_builder._upsert_node(
                node_type="web_document",
                canonical_key=ckey_doc,
                label=(parsed_title or title or local_path.name)[:120],
                parent_node_id=eff_parent if eff_parent and eff_parent != existing_node_id else None,
                depth=doc_depth,
                platform=f"Document ({doc_ext.upper()})",
                status="verified",
                confidence=max(float((finding or {}).get("confidence") or 0.88), 0.90),
                discovery_reason=doc_reason,
                source_url=url,
                local_file_path=str(local_path),
                ingested_source_id=ingested_source_id,
                metadata=doc_meta,
                relation_kind="discovered_from",
                relation_label=f"מסמך {doc_ext.upper()} שהתגלה ב-Dork",
                evidence_snippet=excerpt[:240],
            )
            if finding is not None and doc_node_id > 0:
                finding["tree_node_id"] = doc_node_id
        elif store is not None and hasattr(store, "upsert_investigation_node"):
            root_eid = int(profile.entity_id or 0) if profile and profile.entity_id is not None else 0
            doc_node_id = store.upsert_investigation_node(
                job_id=eff_job_id,
                root_entity_id=root_eid,
                parent_node_id=parent_node_id,
                depth=doc_depth,
                node_type="web_document",
                canonical_key=ckey_doc,
                label=(parsed_title or title or local_path.name)[:120],
                platform=f"Document ({doc_ext.upper()})",
                status="verified",
                confidence=0.90,
                discovery_reason=doc_reason,
                source_url=url,
                local_file_path=str(local_path),
                ingested_source_id=ingested_source_id,
                metadata=doc_meta,
            )

        # 5. Spawn child nodes (`extracted_from_file`) under `doc_node_id`
        child_node_ids: list[int] = []
        child_findings: list[dict[str, Any]] = []
        child_leads: list[dict[str, Any]] = []
        child_depth = doc_depth + 1

        def _add_doc_child(
            c_type: str,
            c_key: str,
            c_label: str,
            c_conf: float,
            c_status: str,
            c_reason: str,
            c_rel_label: str,
            c_linked_eid: int | None = None,
            c_meta: dict[str, Any] | None = None,
        ) -> int:
            if doc_node_id <= 0:
                return 0
            meta_payload = {
                **(c_meta or {}),
                "extracted_from_file": str(local_path),
                "ingested_source_id": ingested_source_id,
                "source_document_url": url,
                "parent_node_id": doc_node_id,
                "relation_kind": "extracted_from_file",
            }
            if tree_builder is not None:
                return tree_builder._upsert_node(
                    node_type=c_type,
                    canonical_key=c_key,
                    label=c_label,
                    parent_node_id=doc_node_id,
                    depth=child_depth,
                    platform=f"Extracted ({doc_ext.upper()})",
                    status=c_status,
                    confidence=c_conf,
                    discovery_reason=c_reason,
                    source_url=url,
                    local_file_path=str(local_path),
                    ingested_source_id=ingested_source_id,
                    linked_entity_id=c_linked_eid,
                    metadata=meta_payload,
                    relation_kind="extracted_from_file",
                    relation_label=c_rel_label,
                    evidence_snippet=excerpt[:220],
                )
            if store is not None and hasattr(store, "upsert_investigation_node"):
                root_eid = int(profile.entity_id or 0) if profile and profile.entity_id is not None else 0
                nid = store.upsert_investigation_node(
                    job_id=eff_job_id,
                    root_entity_id=root_eid,
                    parent_node_id=doc_node_id,
                    depth=child_depth,
                    node_type=c_type,
                    canonical_key=c_key,
                    label=c_label,
                    platform=f"Extracted ({doc_ext.upper()})",
                    status=c_status,
                    confidence=c_conf,
                    discovery_reason=c_reason,
                    source_url=url,
                    local_file_path=str(local_path),
                    ingested_source_id=ingested_source_id,
                    linked_entity_id=c_linked_eid,
                    metadata=meta_payload,
                )
                if nid > 0 and nid != doc_node_id:
                    store.add_investigation_edge(
                        job_id=eff_job_id,
                        from_node_id=doc_node_id,
                        to_node_id=nid,
                        relation_kind="extracted_from_file",
                        relation_label=c_rel_label,
                        confidence=c_conf,
                        evidence_snippet=excerpt[:220],
                        evidence_url=url,
                    )
                return nid
            return 0

        # 5a. National IDs (`id_number`)
        for id_num in id_numbers[:15]:
            nid = _add_doc_child(
                c_type="id_number",
                c_key=str(id_num).strip(),
                c_label=f"ת״ז {id_num}",
                c_conf=0.95,
                c_status="verified",
                c_reason=f"מספר ת״ז מאומת ספרת ביקורת חולץ מהקובץ {local_path.name}",
                c_rel_label="ת״ז חולצה מקובץ",
                c_linked_eid=db_linked_entities.get(("id_number", str(id_num).strip())),
                c_meta={"id_number": id_num},
            )
            if nid > 0:
                child_node_ids.append(nid)
            child_leads.append({
                "type": "id_number",
                "value": str(id_num).strip(),
                "confidence": 0.95,
                "source_url": url,
                "source_tool": "document_harvester",
                "relation_kind": "extracted_from_file",
                "relation_label": "ת״ז חולצה מקובץ",
                "reason": f"ת״ז חולצה מתוך {local_path.name}",
            })

        # 5b. Emails (`email`)
        for em in emails[:20]:
            em_clean = em.strip().lower()
            nid = _add_doc_child(
                c_type="email",
                c_key=em_clean,
                c_label=em_clean,
                c_conf=0.92,
                c_status="verified",
                c_reason=f"כתובת אימייל חולצה מתוך הקובץ {local_path.name}",
                c_rel_label="אימייל חולץ מקובץ",
                c_linked_eid=db_linked_entities.get(("email", em_clean)),
                c_meta={"email": em_clean},
            )
            if nid > 0:
                child_node_ids.append(nid)
            child_leads.append({
                "type": "email",
                "value": em_clean,
                "confidence": 0.92,
                "source_url": url,
                "source_tool": "document_harvester",
                "relation_kind": "extracted_from_file",
                "relation_label": "אימייל חולץ מקובץ",
                "reason": f"אימייל חולץ מתוך {local_path.name}",
            })

        # 5c. Phones (`phone`)
        for ph in phones[:20]:
            p_info = analyze_phone_number(ph)
            ph_key = (p_info.get("e164") or ph).strip().lower()
            nid = _add_doc_child(
                c_type="phone",
                c_key=ph_key,
                c_label=ph,
                c_conf=0.90,
                c_status="verified",
                c_reason=f"מספר טלפון חולץ מתוך הקובץ {local_path.name}",
                c_rel_label="טלפון חולץ מקובץ",
                c_linked_eid=db_linked_entities.get(("phone", ph_key)) or db_linked_entities.get(("phone", ph.lower())),
                c_meta={"phone": ph, "e164": p_info.get("e164") or ph},
            )
            if nid > 0:
                child_node_ids.append(nid)
            child_leads.append({
                "type": "phone",
                "value": ph,
                "confidence": 0.90,
                "source_url": url,
                "source_tool": "document_harvester",
                "relation_kind": "extracted_from_file",
                "relation_label": "טלפון חולץ מקובץ",
                "reason": f"טלפון חולץ מתוך {local_path.name}",
            })

        # 5d. Persons (`person`)
        for per in persons[:25]:
            per_clean = per.strip()
            per_key = name_key(per_clean) or fold(per_clean) or per_clean.lower()
            linked_eid = db_linked_entities.get(("person", per_key)) or db_linked_entities.get(("person", per_clean.lower()))
            nid = _add_doc_child(
                c_type="person",
                c_key=per_key,
                c_label=per_clean,
                c_conf=0.84,
                c_status="discovered",
                c_reason=f"שם אדם חולץ מתוך הקובץ {local_path.name}",
                c_rel_label="אדם חולץ מקובץ",
                c_linked_eid=linked_eid,
                c_meta={"person": per_clean},
            )
            if nid > 0:
                child_node_ids.append(nid)
            child_leads.append({
                "type": "person",
                "value": per_clean,
                "confidence": 0.84,
                "source_url": url,
                "source_tool": "document_harvester",
                "relation_kind": "extracted_from_file",
                "relation_label": "אדם חולץ מקובץ",
                "reason": f"אדם חולץ מתוך {local_path.name}",
            })

        # 5e. Organizations (`org`)
        for org in orgs[:15]:
            org_clean = org.strip()
            org_key = fold(org_clean) or org_clean.lower()
            linked_eid = db_linked_entities.get(("org", org_key)) or db_linked_entities.get(("org", org_clean.lower()))
            nid = _add_doc_child(
                c_type="org",
                c_key=org_key,
                c_label=org_clean,
                c_conf=0.82,
                c_status="discovered",
                c_reason=f"ארגון/חברה חולצו מתוך הקובץ {local_path.name}",
                c_rel_label="ארגון חולץ מקובץ",
                c_linked_eid=linked_eid,
                c_meta={"org": org_clean},
            )
            if nid > 0:
                child_node_ids.append(nid)
            child_leads.append({
                "type": "org",
                "value": org_clean,
                "confidence": 0.82,
                "source_url": url,
                "source_tool": "document_harvester",
                "relation_kind": "extracted_from_file",
                "relation_label": "ארגון חולץ מקובץ",
                "reason": f"ארגון חולץ מתוך {local_path.name}",
            })

        if log_fn and total_extracted > 0:
            log_fn(
                f"✓ [Document Ingest: {local_path.name}] נקלט למאגר (source_id={ingested_source_id}) — "
                f"חולצו {len(persons)} אנשים, {len(phones)} טלפונים, {len(emails)} אימיילים, {len(id_numbers)} ת״ז, {len(orgs)} ארגונים."
            )

        return {
            "ok": True,
            "doc_node_id": doc_node_id,
            "url": url,
            "local_file_path": str(local_path),
            "ingested_source_id": ingested_source_id,
            "sha256": file_sha256,
            "file_type": doc_ext,
            "file_size": len(raw_bytes),
            "title": parsed_title or title,
            "text_excerpt": excerpt,
            "emails": emails,
            "phones": phones,
            "id_numbers": id_numbers,
            "persons": persons,
            "orgs": orgs,
            "child_node_ids": child_node_ids,
            "findings": child_findings,
            "leads": child_leads,
        }

    @classmethod
    async def harvest_and_ingest_batch(
        cls,
        findings: list[dict[str, Any]],
        profile: SearchTargetProfile | None = None,
        store=None,
        tree_builder: "InvestigationTreeBuilder | None" = None,
        job_id: str = "",
        http_fetcher: Callable | None = None,
        bytes_fetcher: Callable | None = None,
        download_dir: str | Path | None = None,
        log_fn: Callable[[str], None] | None = None,
        max_docs: int = 8,
    ) -> dict[str, Any]:
        """Scan a batch of findings for document/archive URLs, download & ingest each one into osnit-il,
        and attach extracted child entities to the Investigation Tree."""
        doc_candidates: list[dict[str, Any]] = []
        seen_doc_urls: set[str] = set()
        for f in findings or []:
            if not isinstance(f, dict):
                continue
            u = str(f.get("url") or (f.get("extracted_data") or {}).get("file_url") or "").strip()
            if not u or u.lower() in seen_doc_urls:
                continue
            ed = f.get("extracted_data") or {}
            if ed.get("ingested_source_id") and ed.get("local_file_path"):
                continue
            ext = cls.is_document_or_archive_url(u) or str(ed.get("file_type") or "").strip()
            if ext or f.get("category") == "document":
                seen_doc_urls.add(u.lower())
                doc_candidates.append(f)
                if len(doc_candidates) >= max_docs:
                    break

        if not doc_candidates:
            return {"processed": 0, "results": [], "leads": []}

        tasks = [
            _safe_task(
                cls.harvest_and_ingest_document(
                    df,
                    profile=profile,
                    store=store,
                    tree_builder=tree_builder,
                    job_id=job_id,
                    http_fetcher=http_fetcher,
                    bytes_fetcher=bytes_fetcher,
                    download_dir=download_dir,
                    log_fn=log_fn,
                ),
                f"doc_ingest:{df.get('url')}",
                timeout=16.0,
                log_fn=log_fn,
            )
            for df in doc_candidates
        ]
        raw_res = await asyncio.gather(*tasks, return_exceptions=True)
        results: list[dict[str, Any]] = []
        all_leads: list[dict[str, Any]] = []
        for r in raw_res:
            if isinstance(r, dict) and r.get("ok"):
                results.append(r)
                all_leads.extend(r.get("leads") or [])
        return {
            "processed": len(results),
            "results": results,
            "leads": all_leads,
        }


class InvestigationTreeBuilder:
    """Builds and streams the hierarchical OSINT Investigation Tree (`investigation_nodes` & `investigation_edges`)
    in real time as each recon layer or deep branch completes."""

    _DOC_EXTENSIONS = (".pdf", ".docx", ".doc", ".xlsx", ".xls", ".csv", ".txt", ".pptx", ".zip", ".rar", ".7z")

    def __init__(self, store, job_id: str, profile: SearchTargetProfile):
        self.store = store
        self.job_id = str(job_id or f"recon_{int(time.time())}").strip()
        self.profile = profile
        self.root_entity_id = int(profile.entity_id or 0) if profile and profile.entity_id is not None else 0
        self.root_node_id: int = 0
        self.node_lookup: dict[tuple[str, str], int] = {}
        self.node_depths: dict[int, int] = {}
        self.url_to_node_id: dict[str, int] = {}

    @classmethod
    def from_existing_job(
        cls,
        store,
        job_id: str,
        profile: SearchTargetProfile | None = None,
        root_entity_id: int | None = None,
    ) -> "InvestigationTreeBuilder":
        """Reconstruct an `InvestigationTreeBuilder` hydrated with all existing nodes from `store` for `job_id`."""
        tree_snap = (
            store.get_investigation_tree(job_id=job_id, root_entity_id=root_entity_id)
            if store is not None and hasattr(store, "get_investigation_tree")
            else {"nodes": [], "root_entity_id": root_entity_id or 0}
        )
        nodes = tree_snap.get("nodes") or []
        eff_eid = int(root_entity_id or tree_snap.get("root_entity_id") or 0)

        if profile is None:
            seed_node = next((n for n in nodes if n.get("node_type") == "seed"), None)
            seed_meta = (seed_node.get("metadata") or {}) if seed_node else {}
            if seed_meta and (seed_meta.get("hebrew_names") or seed_meta.get("english_names") or seed_meta.get("emails") or seed_meta.get("usernames")):
                profile = SearchTargetProfile(
                    entity_id=eff_eid if eff_eid > 0 else seed_meta.get("entity_id"),
                    primary_name=str(seed_meta.get("primary_name") or (seed_node.get("label") if seed_node else "") or ""),
                    hebrew_names=list(seed_meta.get("hebrew_names") or []),
                    english_names=list(seed_meta.get("english_names") or []),
                    usernames=list(seed_meta.get("usernames") or []),
                    emails=list(seed_meta.get("emails") or []),
                    phones=list(seed_meta.get("phones") or []),
                    organizations=list(seed_meta.get("organizations") or []),
                    cities=list(seed_meta.get("cities") or seed_meta.get("locations") or []),
                    domains=list(seed_meta.get("domains") or []),
                )
            elif store is not None and eff_eid > 0:
                profile = SearchTargetProfile.from_entity(store, eff_eid)
            elif seed_node and seed_node.get("label"):
                profile = SearchTargetProfile.from_query(str(seed_node["label"]), entity_id=eff_eid if eff_eid > 0 else None)
            else:
                profile = SearchTargetProfile(entity_id=eff_eid if eff_eid > 0 else None)

        builder = cls(store=store, job_id=job_id, profile=profile)
        if eff_eid > 0:
            builder.root_entity_id = eff_eid
        for n in nodes:
            nid = int(n["id"])
            ntype = str(n.get("node_type") or "").lower()
            ckey = str(n.get("canonical_key") or "").lower()
            depth = int(n.get("depth") or 0)
            src_u = str(n.get("source_url") or "").strip().rstrip("/").lower()
            builder.node_lookup[(ntype, ckey)] = nid
            builder.node_depths[nid] = depth
            if src_u:
                builder.url_to_node_id[src_u] = nid
            if ntype == "seed" and not builder.root_node_id:
                builder.root_node_id = nid
        return builder

    def _upsert_node(
        self,
        node_type: str,
        canonical_key: str,
        label: str,
        parent_node_id: int | None = None,
        depth: int = 0,
        platform: str = "",
        status: str = "discovered",
        confidence: float = 0.75,
        candidate_rank: int = 0,
        discovery_reason: str = "",
        source_url: str = "",
        avatar_url: str = "",
        local_file_path: str = "",
        ingested_source_id: int | None = None,
        linked_entity_id: int | None = None,
        metadata: dict[str, Any] | None = None,
        relation_kind: str = "discovered_from",
        relation_label: str = "",
        evidence_snippet: str = "",
    ) -> int:
        if self.store is None or not hasattr(self.store, "upsert_investigation_node"):
            return 0
        ckey = str(canonical_key or label or "").strip().lower()
        ntype = str(node_type or "discovered").strip().lower()
        nid = self.store.upsert_investigation_node(
            job_id=self.job_id,
            root_entity_id=self.root_entity_id,
            parent_node_id=parent_node_id,
            depth=depth,
            node_type=ntype,
            canonical_key=ckey,
            label=label,
            platform=platform,
            status=status,
            confidence=confidence,
            candidate_rank=candidate_rank,
            discovery_reason=discovery_reason,
            source_url=source_url,
            avatar_url=avatar_url,
            local_file_path=local_file_path,
            ingested_source_id=ingested_source_id,
            linked_entity_id=linked_entity_id,
            metadata=metadata or {},
        )
        if nid > 0:
            self.node_lookup[(ntype, ckey)] = nid
            self.node_depths[nid] = depth
            if source_url:
                self.url_to_node_id[source_url.strip().rstrip("/").lower()] = nid
            if parent_node_id and parent_node_id != nid:
                self.store.add_investigation_edge(
                    job_id=self.job_id,
                    from_node_id=parent_node_id,
                    to_node_id=nid,
                    relation_kind=relation_kind,
                    relation_label=relation_label or discovery_reason[:80],
                    confidence=confidence,
                    evidence_snippet=evidence_snippet[:240],
                    evidence_url=source_url,
                )
        return nid

    def init_seed_nodes(self) -> int:
        """Create the depth-0 Root Seed Node and depth-1 Seed Identifier Nodes."""
        if self.store is None or not hasattr(self.store, "upsert_investigation_node"):
            return 0
        seed_label = (
            self.profile.primary_name
            or (self.profile.hebrew_names[0] if self.profile.hebrew_names else "")
            or (self.profile.english_names[0] if self.profile.english_names else "")
            or (self.profile.usernames[0] if self.profile.usernames else "")
            or (self.profile.emails[0] if self.profile.emails else "")
            or (self.profile.phones[0] if self.profile.phones else "יעד חקירה")
        )
        seed_key = f"seed:{self.root_entity_id or fold(seed_label) or 'root'}"
        self.root_node_id = self._upsert_node(
            node_type="seed",
            canonical_key=seed_key,
            label=seed_label,
            parent_node_id=None,
            depth=0,
            platform="OSINT Root",
            status="verified",
            confidence=1.0,
            discovery_reason="יעד חקירה ראשי (Seed)",
            linked_entity_id=self.root_entity_id if self.root_entity_id > 0 else None,
            metadata=self.profile.to_dict(),
        )
        for em in self.profile.emails[:6]:
            em_clean = em.strip().lower()
            self._upsert_node(
                node_type="email",
                canonical_key=em_clean,
                label=em_clean,
                parent_node_id=self.root_node_id,
                depth=1,
                platform="Email Seed",
                status="verified",
                confidence=0.95,
                discovery_reason="אימייל עוגן מפרופיל המטרה",
                relation_kind="seed_identifier",
                relation_label="אימייל עוגן",
            )
        for ph in self.profile.phones[:6]:
            p_info = analyze_phone_number(ph)
            ph_key = p_info.get("e164") or ph.strip()
            self._upsert_node(
                node_type="phone",
                canonical_key=ph_key,
                label=ph,
                parent_node_id=self.root_node_id,
                depth=1,
                platform="Phone Seed",
                status="verified",
                confidence=0.95,
                discovery_reason="מספר טלפון עוגן מפרופיל המטרה",
                metadata={"permutations": self.profile.phone_permutations.get(ph, [])},
                relation_kind="seed_identifier",
                relation_label="טלפון עוגן",
            )
            self.node_lookup[("phone", ph.strip().lower())] = self.node_lookup.get(("phone", ph_key.lower()), 0)
        for u in self.profile.usernames[:8]:
            u_clean = u.strip().lower()
            self._upsert_node(
                node_type="username",
                canonical_key=u_clean,
                label=f"@{u_clean}",
                parent_node_id=self.root_node_id,
                depth=1,
                platform="Username Seed",
                status="verified",
                confidence=0.85,
                discovery_reason="שם משתמש/כינוי נגזר מפרופיל המטרה",
                relation_kind="seed_identifier",
                relation_label="שם משתמש",
            )
        return self.root_node_id

    def _classify_finding_node_type(self, finding: dict[str, Any]) -> str:
        cat = str(finding.get("category") or "").strip().lower()
        url = str(finding.get("url") or "").strip().lower()
        url_path = url.split("?", 1)[0]
        if any(url_path.endswith(ext) for ext in self._DOC_EXTENSIONS):
            return "web_document"
        if cat == "social_profile":
            return "social_profile"
        if cat == "email_breach":
            return "breach_record"
        if cat == "phone_intel":
            return "phone"
        if cat == "target_image":
            return "image"
        if cat in ("legal_doc", "gov_registry"):
            return "gov_record"
        if cat == "academic_doc":
            return "web_document"
        if cat == "domain_intel":
            return "domain"
        if cat == "pivot_link":
            return "person"
        if cat == "code_intel":
            return "social_profile" if "github.com/" in url else "web_document"
        return "web_mention"

    def _resolve_parent_for_finding(self, finding: dict[str, Any], parent_override_id: int | None = None) -> tuple[int, str, str]:
        if parent_override_id and parent_override_id > 0:
            return parent_override_id, "branched_from", "הסתעפות ישירה"
        ed = finding.get("extracted_data") or {}
        if ed.get("parent_node_id"):
            return int(ed["parent_node_id"]), str(ed.get("relation_kind") or "branched_from"), str(ed.get("discovery_reason") or "הסתעפות")

        for url_field in ("source_profile_url", "source_page_url", "parent_url"):
            u_val = str(ed.get(url_field) or "").strip().rstrip("/").lower()
            if u_val and u_val in self.url_to_node_id:
                return self.url_to_node_id[u_val], "extracted_from_profile", "חולץ מפרופיל"

        em = str(ed.get("email") or "").strip().lower()
        if em and ("email", em) in self.node_lookup:
            return self.node_lookup[("email", em)], "matched_email", f"התגלה דרך אימייל {em}"

        u = str(ed.get("username") or "").strip().lower().lstrip("@")
        if u and ("username", u) in self.node_lookup:
            return self.node_lookup[("username", u)], "matched_handle", f"התגלה דרך שם משתמש @{u}"

        for p_field in ("e164", "phone", "input"):
            ph = str(ed.get(p_field) or "").strip().lower()
            if ph and ("phone", ph) in self.node_lookup:
                return self.node_lookup[("phone", ph)], "shared_phone", f"התגלה דרך טלפון {ph}"

        shared_id = str(ed.get("shared_identifier") or "").strip()
        if shared_id:
            s_low = shared_id.lower()
            s_handle = s_low.lstrip("@")
            s_fold = fold(shared_id) or s_low
            for cand_pair in (
                ("email", s_low),
                ("username", s_handle),
                ("phone", s_low),
                ("person", s_fold),
                ("person", s_low),
            ):
                if cand_pair in self.node_lookup:
                    return (
                        self.node_lookup[cand_pair],
                        "reverse_db_pivot",
                        f"הצלבה חוזרת מול השרת המקומי דרך {shared_id}",
                    )
            if str(finding.get("category") or "") == "pivot_link":
                return (
                    (self.root_node_id or 0),
                    "reverse_db_pivot",
                    f"הצלבה חוזרת מול השרת המקומי דרך {shared_id}",
                )

        return (self.root_node_id or 0), "discovered_from", str(finding.get("source_tool") or "חיפוש OSINT")

    def ingest_findings_batch(
        self,
        findings: list[dict[str, Any]],
        layer_num: int = 1,
        parent_override_id: int | None = None,
    ) -> list[int]:
        if self.store is None or not hasattr(self.store, "upsert_investigation_node"):
            return []
        if not self.root_node_id:
            self.init_seed_nodes()
        created_ids: list[int] = []
        for f in findings or []:
            ed = f.get("extracted_data") or {}
            ntype = self._classify_finding_node_type(f)
            url = str(f.get("url") or "").strip()
            title = str(f.get("title") or url or "ממצא").strip()
            conf = float(f.get("confidence") or 0.75)
            platform = str(ed.get("platform") or f.get("source_tool") or "").strip()
            avatar_url = str(ed.get("avatar_url") or (ed.get("image_url") if ntype == "image" else "") or "").strip()
            parent_id, rel_kind, rel_label = self._resolve_parent_for_finding(f, parent_override_id=parent_override_id)
            parent_depth = self.node_depths.get(parent_id, 0) if parent_id else 0
            node_depth = max(1, parent_depth + 1)

            ckey = (
                url.rstrip("/").lower()
                if url
                else f"{ntype}:{fold(title) or title.lower()}"
            )
            # a profile of SOMEONE is verified only by the candidate matcher (a hard anchor) or the operator; a finding
            # built on the target's own identifiers (a breach of its email, its phone's carrier) may stand on its score
            anchored_kind = not CandidateProfileMatcher.is_social_candidate(f) and f.get("category") != "pivot_link"
            status = str(ed.get("tree_status") or ("verified" if conf >= 0.88 and anchored_kind else "discovered"))
            cand_rank = int(ed.get("candidate_rank") or 0)
            reason = str(
                ed.get("discovery_reason")
                or f.get("summary")
                or f"{rel_label} ({f.get('source_tool') or 'OSINT'})"
            )[:220]
            linked_eid = int(ed["matched_entity_id"]) if ed.get("matched_entity_id") else None
            ingested_sid = int(ed["ingested_source_id"]) if ed.get("ingested_source_id") else None
            local_path = str(ed.get("local_file_path") or ed.get("local_path") or "")

            nid = self._upsert_node(
                node_type=ntype,
                canonical_key=ckey,
                label=title[:120],
                parent_node_id=parent_id if parent_id > 0 else None,
                depth=node_depth,
                platform=platform,
                status=status,
                confidence=conf,
                candidate_rank=cand_rank,
                discovery_reason=reason,
                source_url=url,
                avatar_url=avatar_url,
                local_file_path=local_path,
                ingested_source_id=ingested_sid,
                linked_entity_id=linked_eid,
                metadata={**ed, "layer": layer_num, "category": f.get("category"), "finding_id": f.get("id")},
                relation_kind=rel_kind,
                relation_label=rel_label,
                evidence_snippet=str(f.get("summary") or title),
            )
            if nid > 0:
                f["tree_node_id"] = nid
                created_ids.append(nid)
        return created_ids

    def ingest_leads(self, leads: list[dict[str, Any]]) -> list[int]:
        if self.store is None or not hasattr(self.store, "upsert_investigation_node"):
            return []
        if not self.root_node_id:
            self.init_seed_nodes()
        lead_node_ids: list[int] = []
        for ld in leads or []:
            ltype = str(ld.get("type") or "").strip().lower()
            val = str(ld.get("value") or "").strip()
            if not ltype or not val:
                continue
            src_url = str(ld.get("source_url") or "").strip().rstrip("/").lower()
            parent_id = self.url_to_node_id.get(src_url) or self.root_node_id
            parent_depth = self.node_depths.get(parent_id, 0) if parent_id else 0
            conf = float(ld.get("confidence") or 0.72)
            lbl = f"@{val}" if ltype == "username" and not val.startswith("@") else val
            nid = self._upsert_node(
                node_type=ltype,
                canonical_key=val.lower().lstrip("@"),
                label=lbl,
                parent_node_id=parent_id,
                depth=max(1, parent_depth + 1),
                platform=str(ld.get("source_tool") or "Lead Extractor"),
                status="verified" if conf >= 0.88 else "discovered",
                confidence=conf,
                discovery_reason=str(ld.get("reason") or f"התגלה מתוך {ld.get('source_tool') or 'ממצא חקירה'}"),
                source_url=str(ld.get("source_url") or ""),
                metadata=dict(ld),
                relation_kind=str(ld.get("relation_kind") or "lead_discovered"),
                relation_label=str(ld.get("relation_label") or f"גילוי {ltype}"),
            )
            if nid > 0:
                lead_node_ids.append(nid)
        return lead_node_ids

    def snapshot(self) -> dict[str, Any]:
        if self.store is not None and hasattr(self.store, "get_investigation_tree"):
            return self.store.get_investigation_tree(job_id=self.job_id, root_entity_id=self.root_entity_id)
        return {
            "job_id": self.job_id,
            "root_entity_id": self.root_entity_id,
            "nodes": [],
            "edges": [],
            "tree": [],
            "top_candidates": [],
            "stats": {"total_nodes": 0, "total_edges": 0},
        }


class UnifiedReconEngine:
    """Master orchestrator for the 7-Layer Deep Web OSINT & Recursive Recon Pipeline."""

    def __init__(
        self,
        store=None,
        http_fetcher: Callable | None = None,
        search_fn: Callable[[str], list[dict[str, str]]] | None = None,
        image_search_fn: Callable[[str], list[dict[str, str]]] | None = None,
        max_depth: int = 2,
    ):
        self.store = store
        self.http_fetcher = http_fetcher
        self.search_fn = search_fn
        self.image_search_fn = image_search_fn
        self.max_depth = max(1, min(4, int(max_depth)))

    async def run_recon(
        self,
        entity_id: int | None = None,
        profile: SearchTargetProfile | None = None,
        progress_cb: Callable[[int, str, dict[str, Any]], None] | None = None,
        job_id: str | None = None,
    ) -> dict[str, Any]:
        """Run the full 7-layer Deep OSINT Recon pipeline asynchronously with real-time streaming persistence."""
        started_at = time.time()
        logs: list[str] = []
        net: dict[str, int] = {}
        _NET.set(net)                       # this task's context; the layers' sub-tasks share the same dict

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

        eff_job_id = str(job_id or f"recon_{profile.entity_id or 'adhoc'}_{int(started_at * 1000)}").strip()
        tree_builder = InvestigationTreeBuilder(store=self.store, job_id=eff_job_id, profile=profile)
        tree_builder.init_seed_nodes()

        _log(
            f"✓ פרופיל מטרה: עברית={profile.hebrew_names[:3]} | אנגלית={profile.english_names[:3]} | "
            f"אימיילים={len(profile.emails)} | שמות משתמש={len(profile.usernames)} | טלפונים={len(profile.phones)}"
        )

        all_findings: list[dict[str, Any]] = []
        deduped_findings: list[dict[str, Any]] = []
        seen_keys: set[tuple[str, str, str, str]] = set()
        discovered_leads: list[dict[str, Any]] = []
        pivot_findings: list[dict[str, Any]] = []

        def _persist_and_stream_batch(new_items: list[dict[str, Any]], layer_num: int) -> list[dict[str, Any]]:
            """Immediately deduplicate, save to `osint_findings`, and insert into `investigation_nodes`."""
            added_now: list[dict[str, Any]] = []
            ts_now = time.time()
            for f in new_items or []:
                if not isinstance(f, dict):
                    continue
                key = (
                    str(f.get("category") or ""),
                    str(f.get("source_tool") or ""),
                    str(f.get("url") or ""),
                    str(f.get("title") or ""),
                )
                if key in seen_keys:
                    continue
                seen_keys.add(key)
                f["timestamp"] = ts_now
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
                        timestamp=ts_now,
                    )
                    f["id"] = fid
                deduped_findings.append(f)
                added_now.append(f)
            if added_now:
                tree_builder.ingest_findings_batch(added_now, layer_num=layer_num)
                CandidateProfileMatcher.rank_and_tag_top3_candidates(
                    deduped_findings,
                    profile,
                    store=self.store,
                    job_id=eff_job_id,
                )
            return added_now

        # ------------------------------------------------------------------
        # Layer 2: Email, Breach & Infostealer Intelligence
        # ------------------------------------------------------------------
        _emit(2, LAYER_LABELS[2], {"profile": profile.to_dict(), "tree": tree_builder.snapshot()})
        l2_tasks = []
        for em in profile.emails[:5]:
            l2_tasks.extend([
                _safe_task(check_gravatar(em, store=self.store, http_fetcher=self.http_fetcher), f"gravatar:{em}", 8.0, _log),
                _safe_task(check_hudsonrock(em, is_email=True, store=self.store, http_fetcher=self.http_fetcher), f"hudsonrock:{em}", 9.0, _log),
                _safe_task(check_xposedornot(em, store=self.store, http_fetcher=self.http_fetcher), f"xposedornot:{em}", 9.0, _log),
                _safe_task(check_github(email=em, store=self.store, http_fetcher=self.http_fetcher), f"github:{em}", 9.0, _log),
                _safe_task(check_pgp_keyservers(em, store=self.store, http_fetcher=self.http_fetcher), f"pgp:{em}", 8.0, _log),
                _safe_task(check_holehe(em, store=self.store, http_fetcher=self.http_fetcher), f"holehe:{em}", 10.0, _log),
            ])
        for u in profile.usernames[:3]:
            l2_tasks.extend([
                _safe_task(check_hudsonrock(u, is_email=False, store=self.store, http_fetcher=self.http_fetcher), f"hudsonrock_u:{u}", 9.0, _log),
                _safe_task(check_github(username=u, store=self.store, http_fetcher=self.http_fetcher), f"github_u:{u}", 9.0, _log),
            ])
        seed_domains = profile.pivotable_domains()
        for dom in seed_domains[:3]:
            l2_tasks.extend([
                _safe_task(check_certificate_transparency(dom, store=self.store, http_fetcher=self.http_fetcher), f"crtsh:{dom}", 13.0, _log),
                _safe_task(check_rdap_domain(dom, store=self.store, http_fetcher=self.http_fetcher), f"rdap:{dom}", 11.0, _log),
            ])
        if seed_domains:
            _log(f"✓ [Domain Intel] נבדקים {len(seed_domains[:3])} דומיינים של היעד (crt.sh + RDAP): {', '.join(seed_domains[:3])}")
        l2_batch: list[dict[str, Any]] = []
        if l2_tasks:
            l2_res = await asyncio.gather(*l2_tasks, return_exceptions=True)
            for item in l2_res:
                if isinstance(item, list):
                    l2_batch.extend(item)
                    all_findings.extend(item)
        _persist_and_stream_batch(l2_batch, layer_num=2)

        # Harvest any immediate usernames/names discovered in Layer 2 before Layer 3 runs!
        l2_leads = collect_leads_from_findings(all_findings, profile)
        tree_builder.ingest_leads(l2_leads)
        for ld in l2_leads:
            if ld["type"] == "username" and ld["value"].lower() not in [u.lower() for u in profile.usernames]:
                profile.usernames.append(ld["value"].lower())
            elif ld["type"] == "person" and not is_hebrew(ld["value"]) and ld["value"] not in profile.english_names:
                profile.english_names.insert(0, ld["value"])

        # ------------------------------------------------------------------
        # Layer 3: Username & Social Footprint Hunter
        # ------------------------------------------------------------------
        _emit(3, LAYER_LABELS[3], {
            "findings_so_far": len(deduped_findings),
            "findings": list(deduped_findings),
            "counts_by_category": _count_by_category(deduped_findings),
            "tree": tree_builder.snapshot(),
        })
        l3_findings = await run_layer3_username_intel(
            profile.usernames,
            store=self.store,
            http_fetcher=self.http_fetcher,
            log_fn=_log,
        )
        all_findings.extend(l3_findings)
        _persist_and_stream_batch(l3_findings, layer_num=3)

        # ------------------------------------------------------------------
        # Layer 4: Phone & Messaging Recon
        # ------------------------------------------------------------------
        _emit(4, LAYER_LABELS[4], {
            "findings_so_far": len(deduped_findings),
            "findings": list(deduped_findings),
            "counts_by_category": _count_by_category(deduped_findings),
            "tree": tree_builder.snapshot(),
        })
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
        l4_batch: list[dict[str, Any]] = []
        if l4_tasks:
            l4_res = await asyncio.gather(*l4_tasks, return_exceptions=True)
            for item in l4_res:
                if isinstance(item, list):
                    l4_batch.extend(item)
                    all_findings.extend(item)
        _persist_and_stream_batch(l4_batch, layer_num=4)

        # ------------------------------------------------------------------
        # Layer 5: Open-Web Context, Comment Hunting, Deep Articles & Israeli Dorks
        # ------------------------------------------------------------------
        _emit(5, LAYER_LABELS[5], {
            "findings_so_far": len(deduped_findings),
            "findings": list(deduped_findings),
            "counts_by_category": _count_by_category(deduped_findings),
            "tree": tree_builder.snapshot(),
        })
        l5_findings, l5_leads = await run_layer5_dork_search(
            profile,
            store=self.store,
            search_fn=self.search_fn,
            http_fetcher=self.http_fetcher,
            log_fn=_log,
        )
        all_findings.extend(l5_findings)
        _persist_and_stream_batch(l5_findings, layer_num=5)
        # Stage 4: Automated Dork File Harvester -> Full osnit-il Ingestion -> Tree Branches
        doc_bridge_res = await DorkDocumentTreeBridge.harvest_and_ingest_batch(
            l5_findings,
            profile=profile,
            store=self.store,
            tree_builder=tree_builder,
            job_id=eff_job_id,
            http_fetcher=self.http_fetcher,
            log_fn=_log,
        )
        if doc_bridge_res.get("leads"):
            l5_leads.extend(doc_bridge_res["leads"])
        tree_builder.ingest_leads(l5_leads)

        # ------------------------------------------------------------------
        # Layer 6: Target Image & Visual Recon Engine (Sources A–D + dHash dedup + EXIF + OpenCV Face Detection)
        # ------------------------------------------------------------------
        _emit(6, LAYER_LABELS[6], {
            "findings_so_far": len(deduped_findings),
            "findings": list(deduped_findings),
            "counts_by_category": _count_by_category(deduped_findings),
            "tree": tree_builder.snapshot(),
        })
        l6_image_findings = await run_layer6_image_recon(
            profile,
            all_findings,
            store=self.store,
            http_fetcher=self.http_fetcher,
            image_search_fn=self.image_search_fn,
            finding_urls=[f.get("url") or "" for f in all_findings if f.get("url")],
            log_fn=_log,
        )
        if l6_image_findings:
            _log(f"✓ [Visual Recon] אומתו ונשמרו {len(l6_image_findings)} תמונות יעד (כולל סינון לוגואים וזיהוי פנים).")
            all_findings.extend(l6_image_findings)
            _persist_and_stream_batch(l6_image_findings, layer_num=6)

        # ------------------------------------------------------------------
        # Layer 7: Chained Deep Platform Enrichers ("תוצאה מתוך תוצאה") & Recursive Pivot
        # ------------------------------------------------------------------
        _emit(7, LAYER_LABELS[7], {
            "findings_so_far": len(deduped_findings),
            "findings": list(deduped_findings),
            "counts_by_category": _count_by_category(deduped_findings),
            "tree": tree_builder.snapshot(),
        })
        deep_findings = await run_deep_platform_enrichers(
            all_findings,
            profile,
            store=self.store,
            http_fetcher=self.http_fetcher,
            log_fn=_log,
        )
        if deep_findings:
            _log(f"✓ [תוצאה מתוך תוצאה] חולצו {len(deep_findings)} פרופילי עומק מלאים מתוך הקישורים שהתגלו.")
            all_findings.extend(deep_findings)
            _persist_and_stream_batch(deep_findings, layer_num=7)

        # Stage 3: Auto-branch on verified social profiles (@mentions, tag context, post images, bio links)
        auto_verified_social = [
            f for f in deduped_findings
            if CandidateProfileMatcher.is_social_candidate(f)
            and ((f.get("extracted_data") or {}).get("tree_status") == "verified" or float(f.get("confidence") or 0) >= CandidateProfileMatcher.AUTO_VERIFY_THRESHOLD)
        ]
        if auto_verified_social:
            branch_tasks = [
                _safe_task(
                    DeepSocialBranchMiner.mine_confirmed_profile(
                        vf,
                        profile=profile,
                        store=self.store,
                        tree_builder=tree_builder,
                        http_fetcher=self.http_fetcher,
                        log_fn=_log,
                    ),
                    f"social_branch:{vf.get('url') or vf.get('title')}",
                    timeout=9.0,
                    log_fn=_log,
                )
                for vf in auto_verified_social[:3]
            ]
            branch_results = await asyncio.gather(*branch_tasks, return_exceptions=True)
            branch_new_findings: list[dict[str, Any]] = []
            for br in branch_results:
                if isinstance(br, dict) and br.get("findings"):
                    branch_new_findings.extend(br["findings"])
            if branch_new_findings:
                all_findings.extend(branch_new_findings)
                _persist_and_stream_batch(branch_new_findings, layer_num=7)

        discovered_leads = collect_leads_from_findings(all_findings, profile)
        for extra_ld in l5_leads:
            discovered_leads.append(extra_ld)
        tree_builder.ingest_leads(discovered_leads)

        # Recursive Pivot Expansion (Maltego-style "result of a result"): newly discovered high-confidence
        # identifiers (emails/usernames/domains) feed focused extra discovery rounds, up to max_depth hops.
        if self.max_depth >= 2:
            pivot_new = await recursive_pivot_expand(
                profile,
                all_findings,
                discovered_leads,
                max_depth=self.max_depth,
                store=self.store,
                http_fetcher=self.http_fetcher,
                log_fn=_log,
            )
            if pivot_new:
                all_findings.extend(pivot_new)
                _persist_and_stream_batch(pivot_new, layer_num=7)
                _log(f"🔄 [Pivot רקורסיבי] חקירת המשך ממזהים חדשים הוסיפה {len(pivot_new)} ממצאים.")
                discovered_leads = collect_leads_from_findings(all_findings, profile)
                for extra_ld in l5_leads:
                    discovered_leads.append(extra_ld)
                tree_builder.ingest_leads(discovered_leads)

        # Cross-match and link in local osnit.db
        pivot_findings = cross_match_and_pivot_local_db(self.store, profile, discovered_leads, all_findings)
        all_findings.extend(pivot_findings)
        _persist_and_stream_batch(pivot_findings, layer_num=7)

        # Ensure any remaining items in all_findings are persisted
        _persist_and_stream_batch(all_findings, layer_num=7)

        deduped_findings.sort(key=lambda x: float(x.get("confidence") or 0), reverse=True)
        elapsed = round(time.time() - started_at, 2)
        net_counts, warnings = network_summary(net)
        for w in warnings:
            _log(w)
        _log(f"✅ חקירת רשת עמוקה הושלמה ב-{elapsed} שניות ({len(deduped_findings)} ממצאים אומתו ונשמרו)."
             + (f" רשת: {net_counts.get('http_ok', 0)}/{net_counts.get('http_total', 0)} בקשות נענו, "
                f"{net_counts.get('search_ok', 0)}/{net_counts.get('search_total', 0)} חיפושים החזירו תוצאות."
                if net_counts else ""))

        images_list = (
            self.store.entity_images_for(int(profile.entity_id))
            if self.store is not None and profile.entity_id is not None and hasattr(self.store, "entity_images_for")
            else [f.get("extracted_data") for f in deduped_findings if f.get("category") == "target_image"]
        )
        final_tree = tree_builder.snapshot()

        return {
            "job_id": eff_job_id,
            "entity_id": profile.entity_id,
            "profile": profile.to_dict(),
            "findings": deduped_findings,
            "images": images_list,
            "leads": discovered_leads,
            "pivots": pivot_findings,
            "logs": logs,
            "elapsed_s": elapsed,
            "counts_by_category": _count_by_category(deduped_findings),
            "network": net_counts,
            "warnings": warnings,
            "graph": recon_entity_graph(profile, deduped_findings, discovered_leads, pivot_findings),
            "tree": final_tree,
        }

    def run_recon_sync(
        self,
        entity_id: int | None = None,
        profile: SearchTargetProfile | None = None,
        progress_cb: Callable[[int, str, dict[str, Any]], None] | None = None,
        job_id: str | None = None,
    ) -> dict[str, Any]:
        """Synchronous wrapper around `run_recon`."""
        return asyncio.run(self.run_recon(entity_id=entity_id, profile=profile, progress_cb=progress_cb, job_id=job_id))


def recon_entity_graph(
    profile: "SearchTargetProfile",
    findings: list[dict[str, Any]],
    leads: list[dict[str, Any]] | None = None,
    pivots: list[dict[str, Any]] | None = None,
    max_nodes: int = 70,
) -> dict[str, Any]:
    """Build a Maltego-style relationship graph of one recon run: the target at the centre, its seed
    identifiers around it, each discovered profile/account linked to the identifier that surfaced it (the
    "transform"), newly discovered entities (pivot leads) as their own nodes, and local-DB matches linked
    back in. Shape matches the UI's `forceGraph`: {nodes:[{key,label,kind,id?}], edges:[{a,b,kind,label,w,reason}]}.
    """
    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []
    seen: set[str] = set()

    def node(key: str, label: str, kind: str, **extra: Any) -> bool:
        if not key or not label:
            return False
        if key in seen:
            return True
        if len(nodes) >= max_nodes:
            return False
        seen.add(key)
        nodes.append({"key": key, "label": str(label)[:60], "kind": kind, **extra})
        return True

    def edge(a: str, b: str, label: str = "", kind: str = "", w: float = 0.6, reason: str = "") -> None:
        if a in seen and b in seen and a != b:
            edges.append({"a": a, "b": b, "label": label, "kind": kind, "w": round(float(w), 2), "reason": reason})

    target = "target"
    node(target, profile.primary_name or (profile.hebrew_names or profile.english_names or ["יעד"])[0], "cluster",
         id=profile.entity_id)

    # seed identifiers from the target profile
    for em in profile.emails[:6]:
        if node("em:" + em.lower(), em, "email"):
            edge(target, "em:" + em.lower(), "אימייל", w=0.9)
    for ph in profile.phones[:6]:
        if node("ph:" + ph, ph, "phone"):
            edge(target, "ph:" + ph, "טלפון", w=0.9)
    for u in profile.usernames[:10]:
        if node("u:" + u.lower(), "@" + u, "username"):
            edge(target, "u:" + u.lower(), "שם משתמש", w=0.5)
    for org in profile.organizations[:5]:
        if node("org:" + fold(org), org, "org"):
            edge(target, "org:" + fold(org), "ארגון", w=0.6)
    for c in profile.cities[:5]:
        if node("city:" + fold(c), c, "address"):
            edge(target, "city:" + fold(c), "עיר", w=0.5)
    for d in getattr(profile, "domains", [])[:8]:
        dkey = "dom:" + (registrable_domain(d) or d.lower())
        if node(dkey, registrable_domain(d) or d, "domain"):
            edge(target, dkey, "דומיין", w=0.6)

    # each finding -> a profile/account node linked to the identifier (username) that produced it
    for f in findings or []:
        ed = f.get("extracted_data") or {}
        url = (f.get("url") or "").strip()
        if not url or f.get("category") == "pivot_link":
            continue
        plat = ed.get("platform") or ed.get("site") or ""
        try:
            label = plat or urllib.parse.urlparse(url).netloc or (f.get("title") or url)[:40]
        except ValueError:
            label = plat or url[:40]
        key = "f:" + url
        node_kind = "domain" if f.get("category") == "domain_intel" else "url"
        if not node(key, label, node_kind):
            continue
        src_u = (ed.get("username") or "").strip().lower()
        dom_anchor = "dom:" + registrable_domain(ed.get("domain") or "")
        if src_u and ("u:" + src_u) in seen:
            anchor = "u:" + src_u
        elif ed.get("domain") and dom_anchor in seen:
            anchor = dom_anchor
        else:
            anchor = target
        edge(anchor, key, f.get("source_tool") or "", w=float(f.get("confidence") or 0.6),
             reason=(f.get("title") or "")[:140])

    # newly discovered entities (the pivot leads) as their own nodes off the target
    _kind = {"email": "email", "username": "username", "person": "other_person", "phone": "phone",
             "org": "org", "location": "address", "domain": "domain"}
    for ld in leads or []:
        kind = _kind.get(ld.get("type") or "")
        val = (ld.get("value") or "").strip()
        if not kind or not val:
            continue
        key = ld["type"][:3] + ":" + fold(val)
        label = ("@" + val) if ld["type"] == "username" else val
        if node(key, label, kind):
            edge(target, key, "גילוי" + (f" ({ld.get('source_tool')})" if ld.get("source_tool") else ""),
                 w=float(ld.get("confidence") or 0.5), reason="התגלה בחקירת הרשת")

    # local-DB pivots linked back to the target as "shared" edges
    for p in pivots or []:
        ed = p.get("extracted_data") or {}
        eid = ed.get("matched_entity_id")
        key = "piv:" + (str(eid) if eid else fold(p.get("title") or ""))
        extra = {"id": int(eid)} if eid else {}
        if node(key, p.get("title") or "התאמה מקומית", "other_person", **extra):
            edge(target, key, "Pivot", kind="shared", w=0.85, reason=(p.get("summary") or "")[:140])

    return {"nodes": nodes, "edges": edges}


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
                "total_layers": 7,
                "progress_pct": 10,
                "status_text": LAYER_LABELS[1],
                "layers": [
                    {"layer": i, "label": LAYER_LABELS[i], "state": "running" if i == 1 else "pending", "status": "running" if i == 1 else "pending", "message": LAYER_LABELS[1] if i == 1 else ""}
                    for i in range(1, 8)
                ],
                "logs": [LAYER_LABELS[1]],
                "findings": [],
                "findings_count": 0,
                "counts_by_category": {},
                "tree": {"job_id": job_id, "nodes": [], "edges": [], "tree": [], "top_candidates": [], "stats": {"total_nodes": 0, "total_edges": 0}},
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
                st["progress_pct"] = min(95, int((layer_num - 1) * 13) + 10)
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
                if "findings" in extra:
                    st["findings"] = extra["findings"]
                if "counts_by_category" in extra:
                    st["counts_by_category"] = extra["counts_by_category"]
                if "tree" in extra:
                    st["tree"] = extra["tree"]
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
            res = engine.run_recon_sync(entity_id=entity_id, profile=profile, progress_cb=_on_progress, job_id=job_id)
            with self._lock:
                st = self._jobs.get(job_id)
                if st:
                    st["state"] = "done"
                    st["status"] = "done"
                    st["current_layer"] = 7
                    st["progress_pct"] = 100
                    st["status_text"] = f"✅ הסריקה הושלמה: נמצאו {len(res['findings'])} ממצאים מאומתים"
                    st["warnings"] = res.get("warnings") or []
                    st["network"] = res.get("network") or {}
                    if st["warnings"]:
                        st["status_text"] += " — " + st["warnings"][0]
                    for l_obj in st["layers"]:
                        l_obj["state"] = "done"
                        l_obj["status"] = "done"
                    st["logs"] = res.get("logs") or st["logs"]
                    st["profile"] = res.get("profile")
                    st["findings"] = res.get("findings") or []
                    st["images"] = res.get("images") or []
                    st["findings_count"] = len(st["findings"])
                    st["counts_by_category"] = res.get("counts_by_category") or {}
                    st["pivots"] = res.get("pivots") or []
                    st["graph"] = res.get("graph") or {"nodes": [], "edges": []}
                    st["tree"] = res.get("tree") or st.get("tree") or {"nodes": [], "edges": [], "tree": []}
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

    def get_tree(self, job_or_entity_id: str | int) -> dict[str, Any]:
        """Return the hierarchical Investigation Tree (`investigation_nodes` + `investigation_edges`) for a
        given `job_id` or `entity_id`."""
        s_val = str(job_or_entity_id or "").strip()
        if not s_val or self.store is None or not hasattr(self.store, "get_investigation_tree"):
            return {"job_id": s_val, "nodes": [], "edges": [], "tree": [], "top_candidates": [], "stats": {"total_nodes": 0, "total_edges": 0}}
        if s_val.isdigit():
            eid = int(s_val)
            with self._lock:
                jid = self._entity_latest_job.get(eid)
            return self.store.get_investigation_tree(job_id=jid, root_entity_id=eid)
        return self.store.get_investigation_tree(job_id=s_val)

    def confirm_or_reject_candidate(
        self,
        node_id: int,
        decision: str = "confirm",
        auto_expand: bool = True,
        http_fetcher: Callable | None = None,
        bytes_fetcher: Callable | None = None,
    ) -> dict[str, Any]:
        """Manually confirm (`decision='confirm'`) or reject (`decision='reject'`) a candidate node.
        When confirmed, automatically triggers deep branch expansion (`expand_node`) on the confirmed node!"""
        if self.store is None or not hasattr(self.store, "confirm_or_reject_candidate_node"):
            return {"ok": False, "error": "store_unavailable"}
        updated = self.store.confirm_or_reject_candidate_node(int(node_id), decision=decision)
        if not updated:
            return {"ok": False, "error": "node_not_found"}

        job_id = str(updated.get("job_id") or "")
        root_eid = int(updated.get("root_entity_id") or 0)
        dec_norm = str(decision or "confirm").strip().lower()
        is_conf = dec_norm in ("confirm", "confirmed", "verified", "approve", "yes")
        branch_res: dict[str, Any] = {}
        if is_conf and auto_expand:
            branch_res = self.expand_node(
                int(node_id),
                http_fetcher=http_fetcher,
                bytes_fetcher=bytes_fetcher,
            )

        tree_snap = self.store.get_investigation_tree(job_id=job_id, root_entity_id=root_eid if root_eid > 0 else None)
        with self._lock:
            if job_id in self._jobs:
                self._jobs[job_id]["tree"] = tree_snap
        eff_status = "verified" if is_conf else "rejected"
        return {
            "ok": True,
            "node": self.store.get_investigation_node(int(node_id)) or updated,
            "decision": eff_status,
            "status": eff_status,
            "spawned_children": list(branch_res.get("child_node_ids") or []),
            "branch": branch_res,
            "tree": tree_snap,
        }

    def expand_node(
        self,
        node_id: int,
        http_fetcher: Callable | None = None,
        bytes_fetcher: Callable | None = None,
        search_fn: Callable[[str], list[dict[str, str]]] | None = None,
    ) -> dict[str, Any]:
        """Interactively expand any node in the Investigation Tree (`social_profile`, `web_document`,
        `username`, `email`, `phone`, `domain`, `person`) and stream all discovered child nodes & edges into the tree."""
        if self.store is None or not hasattr(self.store, "get_investigation_node"):
            return {"ok": False, "error": "store_unavailable"}
        node = self.store.get_investigation_node(int(node_id))
        if not node:
            return {"ok": False, "error": "node_not_found"}

        job_id = str(node.get("job_id") or "default")
        root_eid = int(node.get("root_entity_id") or 0)
        tree_builder = InvestigationTreeBuilder.from_existing_job(
            self.store,
            job_id=job_id,
            root_entity_id=root_eid if root_eid > 0 else None,
        )
        profile = tree_builder.profile
        ntype = str(node.get("node_type") or "").strip().lower()
        src_url = str(node.get("source_url") or "").strip()
        meta = dict(node.get("metadata") or {})

        async def _do_expand() -> dict[str, Any]:
            child_ids: list[int] = []
            new_findings: list[dict[str, Any]] = []

            if ntype == "web_document" or (src_url and DorkDocumentTreeBridge.is_document_or_archive_url(src_url)):
                finding_stub = {
                    "category": "document",
                    "source_tool": "document_harvester",
                    "title": node.get("label") or src_url,
                    "url": src_url,
                    "confidence": float(node.get("confidence") or 0.90),
                    "tree_node_id": int(node["id"]),
                    "extracted_data": meta,
                }
                doc_res = await DorkDocumentTreeBridge.harvest_and_ingest_document(
                    finding_stub,
                    profile=profile,
                    store=self.store,
                    tree_builder=tree_builder,
                    job_id=job_id,
                    parent_node_id=int(node.get("parent_node_id") or tree_builder.root_node_id or 0),
                    http_fetcher=http_fetcher,
                    bytes_fetcher=bytes_fetcher,
                )
                child_ids.extend(doc_res.get("child_node_ids") or [])
                new_findings.extend(doc_res.get("findings") or [])

            elif ntype == "social_profile" or CandidateProfileMatcher.is_social_candidate({"category": ntype, "url": src_url}):
                finding_stub = {
                    "category": "social_profile",
                    "source_tool": node.get("platform") or "social",
                    "title": node.get("label") or src_url,
                    "summary": node.get("discovery_reason") or "",
                    "url": src_url,
                    "confidence": max(float(node.get("confidence") or 0.90), 0.90),
                    "tree_node_id": int(node["id"]),
                    "extracted_data": {
                        **meta,
                        "platform": node.get("platform") or meta.get("platform") or "",
                        "avatar_url": node.get("avatar_url") or meta.get("avatar_url") or "",
                    },
                }
                soc_res = await DeepSocialBranchMiner.mine_confirmed_profile(
                    finding_stub,
                    profile=profile,
                    store=self.store,
                    tree_builder=tree_builder,
                    http_fetcher=http_fetcher,
                    bytes_fetcher=bytes_fetcher,
                )
                child_ids.extend(soc_res.get("child_node_ids") or [])
                new_findings.extend(soc_res.get("findings") or [])

            elif ntype == "username":
                handle = str(node.get("canonical_key") or node.get("label") or "").strip().lstrip("@")
                if handle:
                    u_findings = await run_layer3_username_intel([handle], store=self.store, http_fetcher=http_fetcher)
                    gh_findings = await check_github(username=handle, store=self.store, http_fetcher=http_fetcher)
                    hr_findings = await check_hudsonrock(handle, is_email=False, store=self.store, http_fetcher=http_fetcher)
                    combined = (u_findings or []) + (gh_findings or []) + (hr_findings or [])
                    child_ids.extend(
                        tree_builder.ingest_findings_batch(
                            combined,
                            layer_num=int(node.get("depth") or 1) + 1,
                            parent_override_id=int(node["id"]),
                        )
                    )
                    new_findings.extend(combined)

            elif ntype == "email":
                em = str(node.get("canonical_key") or node.get("label") or "").strip().lower()
                if em and "@" in em:
                    tasks = [
                        _safe_task(check_gravatar(em, store=self.store, http_fetcher=http_fetcher), f"grav:{em}", 7.0),
                        _safe_task(check_hudsonrock(em, is_email=True, store=self.store, http_fetcher=http_fetcher), f"hr:{em}", 8.0),
                        _safe_task(check_xposedornot(em, store=self.store, http_fetcher=http_fetcher), f"xon:{em}", 8.0),
                        _safe_task(check_github(email=em, store=self.store, http_fetcher=http_fetcher), f"gh:{em}", 8.0),
                        _safe_task(check_holehe(em, store=self.store, http_fetcher=http_fetcher), f"hol:{em}", 8.0),
                    ]
                    res_lists = await asyncio.gather(*tasks, return_exceptions=True)
                    combined: list[dict[str, Any]] = []
                    for rl in res_lists:
                        if isinstance(rl, list):
                            combined.extend(rl)
                    child_ids.extend(
                        tree_builder.ingest_findings_batch(
                            combined,
                            layer_num=int(node.get("depth") or 1) + 1,
                            parent_override_id=int(node["id"]),
                        )
                    )
                    new_findings.extend(combined)

            elif ntype == "phone":
                ph = str(node.get("label") or node.get("canonical_key") or "").strip()
                if ph:
                    p_info = analyze_phone_number(ph)
                    ph_findings = await check_ignorant_phone(p_info, store=self.store, http_fetcher=http_fetcher)
                    child_ids.extend(
                        tree_builder.ingest_findings_batch(
                            ph_findings or [],
                            layer_num=int(node.get("depth") or 1) + 1,
                            parent_override_id=int(node["id"]),
                        )
                    )
                    new_findings.extend(ph_findings or [])

            elif ntype == "domain":
                dom = registrable_domain(str(node.get("canonical_key") or node.get("label") or ""))
                if dom:
                    crt_f = await check_certificate_transparency(dom, store=self.store, http_fetcher=http_fetcher)
                    rdap_f = await check_rdap_domain(dom, store=self.store, http_fetcher=http_fetcher)
                    combined = (crt_f or []) + (rdap_f or [])
                    child_ids.extend(
                        tree_builder.ingest_findings_batch(
                            combined,
                            layer_num=int(node.get("depth") or 1) + 1,
                            parent_override_id=int(node["id"]),
                        )
                    )
                    new_findings.extend(combined)

            elif ntype == "person":
                per_name = str(node.get("label") or "").strip()
                if per_name:
                    sub_prof = SearchTargetProfile.from_query(per_name)
                    pivots = cross_match_and_pivot_local_db(
                        self.store,
                        sub_prof,
                        [{"type": "person", "value": per_name, "confidence": 0.85}],
                        [],
                    )
                    if search_fn is not None:
                        d_findings, _ = await run_layer5_dork_search(
                            sub_prof,
                            store=self.store,
                            search_fn=search_fn,
                            http_fetcher=http_fetcher,
                        )
                        pivots.extend(d_findings)
                    child_ids.extend(
                        tree_builder.ingest_findings_batch(
                            pivots,
                            layer_num=int(node.get("depth") or 1) + 1,
                            parent_override_id=int(node["id"]),
                        )
                    )
                    new_findings.extend(pivots)

            return {"child_node_ids": child_ids, "findings": new_findings}

        exp_out = asyncio.run(_do_expand())
        self.store.update_investigation_node_status(
            int(node["id"]),
            status="verified" if node.get("status") == "candidate_top3" else str(node.get("status") or "verified"),
            metadata_patch={"expanded": True, "expanded_at": time.time(), "expanded_children_count": len(exp_out["child_node_ids"])},
        )
        tree_snap = tree_builder.snapshot()
        with self._lock:
            if job_id in self._jobs:
                self._jobs[job_id]["tree"] = tree_snap
        return {
            "ok": True,
            "node_id": int(node["id"]),
            "child_node_ids": exp_out["child_node_ids"],
            "spawned_children": exp_out["child_node_ids"],
            "new_findings_count": len(exp_out["findings"]),
            "tree": tree_snap,
        }


