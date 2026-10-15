"""
osnit.kinship: Explicit & Heuristic Kinship Inference Engine (Phase 4 — OSNIT-IL v2.0).

Capabilities:
1. Explicit Kinship Extraction from Hebrew & English free text and tabular columns:
   - Parent (אב / אם / Father / Mother)
   - Spouse (בן/בת זוג / בעל / אישה / נשוי ל / Spouse / Husband / Wife)
   - Sibling (אח / אחות / Brother / Sister)
   - Child (בן / בת / ילד / ילדה / Son / Daughter / Child)
   - Emergency Contact / Next of Kin (איש קשר לחירום / קרוב משפחה)
   Automatically resolves single-token given names (e.g. 'שם האב: אברהם') by inheriting
   the primary subject's family surname when in the same script.
2. Heuristic Kinship & Household Graph Inference across documents and databases:
   - Shared family surname (including cross-script Hebrew <-> English transliteration)
     + shared residential street address or city
   - Shared landline phone (02/03/04/08/09) or shared family phone with distinct given names
   - Sequential / close Israeli National IDs (Luhn-valid 9-digit IDs with close base numbers)
   - Document co-occurrence with shared family surname
   Produces scored kinship edges with human-readable Hebrew explanations for Dossier & Graph UI.
"""
import re
from typing import Dict, List, Optional, Set, Tuple

from .quality import is_dummy_name, valid_national_id
from .semantic import address_key, has_city, il_id_key, il_id_ok, is_city, CITY_KEYS
from .textnorm import clean, fold, is_hebrew, name_key, squash, tokens
from .variants import token_forms
from .xling import same_person_name, skeletons

# ---------------------------------------------------------------------------
# Role definitions & Hebrew labels
# ---------------------------------------------------------------------------
KINSHIP_ROLE_LABELS: Dict[str, str] = {
    "father": "אב",
    "mother": "אם",
    "parent": "הורה",
    "spouse": "בן/בת זוג",
    "sibling": "אח/אחות",
    "child": "ילד/ה",
    "emergency_contact": "איש קשר לחירום",
    "relative": "קרוב משפחה",
    "household": "בן בית / קרוב משפחה",
}

INVERSE_KINSHIP_ROLE: Dict[str, str] = {
    "father": "child",
    "mother": "child",
    "parent": "child",
    "child": "parent",
    "spouse": "spouse",
    "sibling": "sibling",
    "emergency_contact": "emergency_contact",
    "relative": "relative",
    "household": "household",
}

# Explicit text patterns: (role_code, compiled_regex)
# Captures group 'name' (1 to 3 Hebrew or Latin name tokens) and optional trailing inline context
_HE_NAME_1_3 = r"[א-ת]{2,15}(?:['״\"\-][א-ת]{1,15})?(?:[ ]+[א-ת]{2,15}(?:['״\"\-][א-ת]{1,15})?){0,2}"
_EN_NAME_1_3 = r"[A-Z][a-z]{1,18}(?:[ ]+[A-Z][a-z]{1,18}){0,2}"
_ANY_NAME_1_3 = rf"(?:{_HE_NAME_1_3}|{_EN_NAME_1_3})"

EXPLICIT_TEXT_PATTERNS: List[Tuple[str, re.Pattern]] = [
    ("father", re.compile(
        rf"(?:^|[\n,;()|])[ ]*(?:שם[ ]+האב|שם[ ]+אב|אב|אבא|Father(?:'s[ ]+Name)?|Dad)[ ]*[:\-–][ ]*(?P<name>{_ANY_NAME_1_3})",
        re.IGNORECASE | re.MULTILINE
    )),
    ("mother", re.compile(
        rf"(?:^|[\n,;()|])[ ]*(?:שם[ ]+האם|שם[ ]+אם|אם|אמא|Mother(?:'s[ ]+Name)?|Mom)[ ]*[:\-–][ ]*(?P<name>{_ANY_NAME_1_3})",
        re.IGNORECASE | re.MULTILINE
    )),
    ("spouse", re.compile(
        rf"(?:^|[\n,;()|])[ ]*(?:שם[ ]+בן[ ]+ה?זוג|שם[ ]+בת[ ]+ה?זוג|בן[ ]+זוג|בת[ ]+זוג|בעל|אישה|אשה|נשוי[ ]+ל|נשואה[ ]+ל|"
        rf"Spouse(?:'s[ ]+Name)?|Husband|Wife|Married[ ]+to|Partner)[ ]*[:\-–]?[ ]*(?P<name>{_ANY_NAME_1_3})",
        re.IGNORECASE | re.MULTILINE
    )),
    ("sibling", re.compile(
        rf"(?:^|[\n,;()|])[ ]*(?:שם[ ]+האח|שם[ ]+האחות|אח|אחות|Brother|Sister|Sibling)[ ]*[:\-–][ ]*(?P<name>{_ANY_NAME_1_3})",
        re.IGNORECASE | re.MULTILINE
    )),
    ("child", re.compile(
        rf"(?:^|[\n,;()|])[ ]*(?:שם[ ]+הבן|שם[ ]+הבת|שם[ ]+הילד(?:ה)?|ילד(?:ה)?|Son|Daughter|Child)[ ]*[:\-–][ ]*(?P<name>{_ANY_NAME_1_3})",
        re.IGNORECASE | re.MULTILINE
    )),
    ("emergency_contact", re.compile(
        rf"(?:^|[\n,;()|])[ ]*(?:איש[ ]+קשר[ ]+לחירום|קרוב[ ]+משפחה|שאר[ ]+בשר|Emergency[ ]+Contact|Next[ ]+of[ ]+Kin)"
        rf"(?:[ ]*\([^)]*\))?[ ]*[:\-–][ ]*(?P<name>{_ANY_NAME_1_3})",
        re.IGNORECASE | re.MULTILINE
    )),
    # Inline patronymic pattern: "דניאל בן אברהם כהן" or "ת.ז ... בן/בת אברהם ושרה"
    ("father", re.compile(
        rf"(?<=[א-ת][ ])(?:בן|בת)[ ]+(?P<name>[א-ת]{{2,12}})[ ]+ו(?P<mother>[א-ת]{{2,12}})(?![א-ת])"
    )),
]

# Column header patterns for tabular databases (SQL, SQLite, CSV, XLSX)
TABULAR_KINSHIP_HEADERS: List[Tuple[str, re.Pattern]] = [
    ("father", re.compile(r"^(?:father(?:_?name)?|fathers_?name|dad|שם_?ה?אב|אב)$", re.I)),
    ("mother", re.compile(r"^(?:mother(?:_?name)?|mothers_?name|mom|שם_?ה?אם|אם)$", re.I)),
    ("parent", re.compile(r"^(?:parent(?:_?name)?|guardian|הורה|אפוטרופוס)$", re.I)),
    ("spouse", re.compile(r"^(?:spouse(?:_?name)?|husband|wife|partner|בן_?זוג|בת_?זוג|שם_?בן_?זוג|שם_?בת_?זוג|בעל|אישה|אשה)$", re.I)),
    ("sibling", re.compile(r"^(?:sibling(?:_?name)?|brother|sister|אח|אחות|שם_?אח|שם_?אחות)$", re.I)),
    ("child", re.compile(r"^(?:child(?:_?name)?|son|daughter|ילד|ילדה|שם_?ילד)$", re.I)),
    ("emergency_contact", re.compile(r"^(?:emergency_?contact(?:_?name)?|next_?of_?kin|ice_?contact|איש_?קשר_?לחירום|איש_?קשר_?חירום|קרוב_?משפחה)$", re.I)),
]

TABULAR_EMERGENCY_PHONE_HEADERS = re.compile(
    r"^(?:emergency_?(?:contact_?)?(?:phone|tel|mobile)|ice_?phone|טלפון_?חירום|טלפון_?איש_?קשר_?לחירום|נייד_?חירום)$",
    re.I,
)

# Stopwords that must never be mistaken for a relative's name
_BAD_REL_TOKENS = {
    "לא", "אין", "כן", "זכר", "נקבה", "רווק", "רווקה", "נשוי", "נשואה", "גרוש", "גרושה",
    "אלמן", "אלמנה", "ישראל", "ישראלי", "בעיר", "ברחוב", "טלפון", "נייד", "תז", "מייל",
    "none", "null", "n/a", "na", "yes", "no", "male", "female", "single", "married", "divorced",
    "phone", "mobile", "email", "address", "unknown", "לא ידוע",
}


def surname_of(full_name: str) -> str:
    """Extracts the likely surname from a 2+ token person name."""
    toks = [t for t in clean(full_name).split() if t and not re.search(r"\d", t)]
    if len(toks) < 2:
        return ""
    # Check two-word Israeli surnames (בן דוד, בר לב, אבן חן, etc.)
    if len(toks) >= 3 and fold(toks[-2]) in ("בן", "בר", "אבן", "אבו", "אל", "דא", "דה", "ואן", "ben", "bar", "abu", "al"):
        return f"{toks[-2]} {toks[-1]}"
    return toks[-1]


def given_name_of(full_name: str) -> str:
    """Extracts the primary given name (first token) from a person name."""
    toks = [t for t in clean(full_name).split() if t and not re.search(r"\d", t)]
    return toks[0] if toks else ""


def _tokens_match_cross_script(tok_a: str, tok_b: str) -> bool:
    """Returns True if two single tokens match (exact, typo-tolerant, or Hebrew<->Latin transliteration)."""
    fa, fb = fold(tok_a), fold(tok_b)
    if not fa or not fb:
        return False
    if fa == fb:
        return True
    if is_hebrew(fa) == is_hebrew(fb):
        # Same script: allow 1-char edit distance only on long tokens (>= 5 chars)
        if len(fa) >= 5 and len(fb) >= 5 and abs(len(fa) - len(fb)) <= 1:
            from .store import _ed1
            return _ed1(fa, fb)
        return False
    # Cross-script: check dictionary forms + consonant skeletons
    forms_a = {fold(x) for x in token_forms(fa)}
    forms_b = {fold(x) for x in token_forms(fb)}
    if fb in forms_a or fa in forms_b or (forms_a & forms_b):
        return True
    sk_a = {s for s in skeletons(fa) if len(s) >= 2}
    sk_b = {s for s in skeletons(fb) if len(s) >= 2}
    return bool(sk_a & sk_b)


def shared_surname(name_a: str, name_b: str) -> Optional[str]:
    """
    Checks if two DISTINCT people share a family surname (same script or Hebrew <-> Latin).
    Returns the matched surname string if they share a surname and have different given names, else None.
    """
    if not name_a or not name_b:
        return None
    if name_key(name_a) == name_key(name_b) or same_person_name(name_a, name_b):
        return None
    ta = tokens(name_a)
    tb = tokens(name_b)
    if len(ta) < 2 or len(tb) < 2:
        return None

    # Check compound surname first (e.g. בן דוד / Ben David)
    sa = surname_of(name_a)
    sb = surname_of(name_b)
    ga = given_name_of(name_a)
    gb = given_name_of(name_b)

    # Given names must be distinct (otherwise they might be the same person)
    if _tokens_match_cross_script(ga, gb):
        return None

    if " " in sa or " " in sb:
        if fold(sa) == fold(sb) or same_person_name(sa, sb):
            return sa if is_hebrew(sa) else sb

    last_a, last_b = ta[-1], tb[-1]
    if _tokens_match_cross_script(last_a, last_b):
        return last_a if is_hebrew(last_a) else last_b

    return None


def normalize_relative_name(raw_name: str, primary_person_name: str = "") -> Optional[Tuple[str, List[str]]]:
    """
    Cleans a relative's name extracted from text or a table cell.
    If the relative is given as a single first name (e.g. 'אברהם' in 'שם האב: אברהם')
    and `primary_person_name` has a surname in the same script (e.g. 'דניאל כהן'),
    expands it to 'אברהם כהן' while preserving 'אברהם' as an alias.
    Returns (full_display_name, aliases) or None if invalid.
    """
    cleaned = clean(raw_name or "").strip(" ,.;:-–()[]{}\"'")
    # Strip trailing stop tokens like "ת.ז" / "טלפון" / "נייד" if captured
    cleaned = re.split(r"\b(?:ת[\".״']?ז|טלפון|נייד|מייל|כתובת|id|phone|tel|mobile)\b", cleaned, flags=re.I)[0].strip(" ,.;:-–()")
    if not cleaned:
        return None
    toks = [t for t in cleaned.split() if t and not re.search(r"\d", t)]
    if not toks or len(toks) > 4:
        return None
    if any(fold(t) in _BAD_REL_TOKENS for t in toks):
        return None
    candidate = " ".join(toks)
    if is_dummy_name(candidate):
        return None

    aliases: List[str] = []
    if len(toks) == 1:
        single = toks[0]
        if len(single) < 2:
            return None
        sur = surname_of(primary_person_name) if primary_person_name else ""
        if sur and is_hebrew(single) == is_hebrew(sur) and fold(single) != fold(sur):
            full_disp = f"{single} {sur}"
            aliases.append(single)
            return full_disp, aliases
        # Without a surname to inherit, a 1-word relative is only kept if it's a valid name token
        return single, aliases

    return candidate, aliases


def extract_explicit_kinship_from_text(text: str, primary_person_name: str = "") -> List[Dict]:
    """
    Scans unstructured text for explicit kinship declarations (e.g. 'שם האב: אברהם כהן',
    'איש קשר לחירום: משה כהן 052-9998877').
    Returns a list of dicts:
      {
        "role": role_code ("father", "mother", "spouse", "sibling", "child", "emergency_contact"),
        "label": Hebrew role label,
        "name": resolved full name,
        "key": name_key(resolved full name),
        "aliases": [...],
        "phones": [...],         # normalized +972 phones found on the same kinship line
        "national_ids": [...],   # canonical 9-digit national IDs found on the same kinship line
        "line": line_number,
        "start": char_start,
        "end": char_end,
        "snippet": snippet_str,
      }
    """
    if not text:
        return []
    from .extract import norm_phone_il

    results: List[Dict] = []
    seen: Set[Tuple[str, str]] = set()
    lines = text.split("\n")

    for role, rx in EXPLICIT_TEXT_PATTERNS:
        for m in rx.finditer(text):
            pairs_to_process = [(role, m.group("name"))]
            if "mother" in m.groupdict() and m.group("mother"):
                pairs_to_process.append(("mother", m.group("mother")))

            line_no = text.count("\n", 0, m.start("name"))
            line_str = lines[line_no] if 0 <= line_no < len(lines) else ""

            # Check if the same line has a phone number or national ID belonging to the relative
            rel_phones: List[str] = []
            rel_ids: List[str] = []
            if len(pairs_to_process) == 1 and line_str:
                after_name = line_str[max(0, m.end("name") - (text.rfind("\n", 0, m.start("name")) + 1)):]
                for pm in re.finditer(r"(?:\+?972[\s\-]?0?|0)(?:[23489][\s\-]?\d{7}|[57]\d[\s\-]?\d{3}[\s\-]?\d{4})", after_name):
                    np = norm_phone_il(pm.group(0))
                    if np and np not in rel_phones:
                        rel_phones.append(np)
                for im in re.finditer(r"(?<!\d)\d{8,9}(?!\d)", after_name):
                    raw_d = im.group(0)
                    if not raw_d.startswith(("05", "07")) and valid_national_id(raw_d):
                        ik = il_id_key(raw_d)
                        if ik and ik not in rel_ids:
                            rel_ids.append(ik)

            for r_code, raw_n in pairs_to_process:
                norm_res = normalize_relative_name(raw_n, primary_person_name)
                if not norm_res:
                    continue
                disp, aliases = norm_res
                k = name_key(disp)
                if not k or (primary_person_name and k == name_key(primary_person_name)):
                    continue
                if (r_code, k) in seen:
                    continue
                seen.add((r_code, k))
                snip = squash(line_str or text[max(0, m.start() - 30):min(len(text), m.end() + 50)])[:240]
                results.append({
                    "role": r_code,
                    "label": KINSHIP_ROLE_LABELS.get(r_code, "קרוב משפחה"),
                    "name": disp,
                    "key": k,
                    "aliases": aliases,
                    "phones": rel_phones,
                    "national_ids": rel_ids,
                    "line": line_no,
                    "start": m.start("name"),
                    "end": m.end("name"),
                    "snippet": snip,
                })
    return results


def detect_kinship_column_role(col_name: str) -> Optional[str]:
    """Returns the kinship role code if a tabular column header represents a relative (e.g. 'father_name', 'שם האב')."""
    k = re.sub(r"[\s\-./]+", "_", fold(str(col_name or "")).strip()).strip("_")
    if not k:
        return None
    for role, rx in TABULAR_KINSHIP_HEADERS:
        if rx.match(k):
            return role
    return None


def is_emergency_phone_column(col_name: str) -> bool:
    """Returns True if a column header represents an emergency contact's phone number."""
    k = re.sub(r"[\s\-./]+", "_", fold(str(col_name or "")).strip()).strip("_")
    return bool(k and TABULAR_EMERGENCY_PHONE_HEADERS.match(k))


def _extract_cities_from_strings(strings: List[str]) -> Set[str]:
    """Extracts canonical city names from a list of address or city strings."""
    found: Set[str] = set()
    for s in strings:
        if not s:
            continue
        fs = fold(s).replace("-", " ").strip()
        if is_city(fs):
            found.add(fs)
            continue
        # Check last 1-3 tokens of an address
        parts = [p.strip() for p in re.split(r"[,/|\-]+", s) if p.strip()]
        for part in parts:
            toks = part.split()
            for n in (3, 2, 1):
                if len(toks) >= n:
                    cand = fold(" ".join(toks[-n:])).replace("-", " ")
                    if cand in CITY_KEYS:
                        found.add(cand)
                        break
    return found


def _is_landline_il(phone_key: str) -> bool:
    """True for Israeli landline numbers (+9722..., +9723..., +9724..., +9728..., +9729...)."""
    d = re.sub(r"\D", "", str(phone_key or ""))
    return d.startswith("972") and len(d) == 11 and d[3:4] in "23489"


def _close_national_ids(ids_a: Set[str], ids_b: Set[str]) -> Optional[Tuple[str, str]]:
    """
    Checks if two sets of 9-digit Israeli National IDs contain sequential or very close IDs
    (differing by <= 25 in the 8-digit base number, or <= 150 in full 9-digit integer value,
    excluding identical IDs).
    """
    for a in ids_a:
        da = re.sub(r"\D", "", str(a)).zfill(9)
        if len(da) != 9 or not il_id_ok(da):
            continue
        for b in ids_b:
            db = re.sub(r"\D", "", str(b)).zfill(9)
            if len(db) != 9 or da == db or not il_id_ok(db):
                continue
            base_diff = abs(int(da[:8]) - int(db[:8]))
            full_diff = abs(int(da) - int(db))
            if 0 < base_diff <= 25 or 0 < full_diff <= 150:
                return (da, db)
    return None


def infer_kinship_for_dossier(store, clusters: list, ents: dict, rels: list) -> List[Dict]:
    """
    Computes explicit and heuristic kinship relationships for each person cluster in `dossier()`.
    Mutates each cluster `c["kinship"] = [...]` AND returns a deduplicated top-level list of all
    kinship findings for the dossier.
    """
    person_clusters = [c for c in clusters if c.get("type") in (None, "person")]
    if not person_clusters:
        for c in clusters:
            c.setdefault("kinship", [])
        return []

    def _cluster_mids(c: dict) -> List[int]:
        if "member_ids" in c:
            return list(c["member_ids"])
        if "records" in c:
            return [r["id"] for r in c["records"] if isinstance(r, dict) and "id" in r]
        if "members" in c:
            return list(c["members"])
        if "id" in c:
            return [c["id"]]
        return []

    # Map every member entity_id -> its cluster so we never report a cluster's own merged member as a relative
    member_to_cluster: Dict[int, dict] = {}
    for c in person_clusters:
        for mid in _cluster_mids(c):
            member_to_cluster[mid] = c

    # Gather all person entities in the store to evaluate family surname / address / landline / ID heuristics
    all_person_rows = store.q("SELECT id, key, display FROM entities WHERE type='person'")
    person_by_id: Dict[int, dict] = {r["id"]: dict(r) for r in all_person_rows}

    # Pre-fetch all person->entity relations (address, city, phone, national_id, kinship:*) across the store
    all_rel_rows = store.q("""
        SELECT r.id, r.a_id, r.b_id, r.kind,
               ea.type AS a_type, ea.key AS a_key, ea.display AS a_disp,
               eb.type AS b_type, eb.key AS b_key, eb.display AS b_disp,
               MAX(re.confidence) AS conf,
               MAX(re.snippet) AS snippet
        FROM relations r
        JOIN entities ea ON ea.id = r.a_id
        JOIN entities eb ON eb.id = r.b_id
        LEFT JOIN rel_evidence re ON re.relation_id = r.id
        WHERE ea.type = 'person' OR eb.type = 'person'
        GROUP BY r.id
    """)

    # Build per-person profile of identifiers & attributes across the DB
    person_addrs: Dict[int, Dict[str, str]] = {}     # pid -> {addr_key: display}
    person_cities: Dict[int, Set[str]] = {}          # pid -> {city_folded}
    person_phones: Dict[int, Dict[str, str]] = {}    # pid -> {phone_key: display}
    person_nat_ids: Dict[int, Set[str]] = {}         # pid -> {9-digit id}
    explicit_kin: Dict[int, List[Tuple[int, str, float, str]]] = {}  # pid -> [(other_pid, role_code, conf, snippet)]
    co_mentions: Dict[int, Set[int]] = {}            # pid -> {other_pid}

    for r in all_rel_rows:
        aid, bid, kind = r["a_id"], r["b_id"], r["kind"] or ""
        at, bt = r["a_type"], r["b_type"]
        conf = float(r["conf"] or 0.75)
        snip = r["snippet"] or ""

        if at == "person" and bt == "person":
            if kind.startswith("kinship:"):
                role_code = kind.split(":", 1)[1]
                explicit_kin.setdefault(aid, []).append((bid, role_code, max(conf, 0.92), snip))
                inv_role = INVERSE_KINSHIP_ROLE.get(role_code, role_code)
                explicit_kin.setdefault(bid, []).append((aid, inv_role, max(conf, 0.92), snip))
            else:
                co_mentions.setdefault(aid, set()).add(bid)
                co_mentions.setdefault(bid, set()).add(aid)
            continue

        pid, oid, ot, ok, odisp = (
            (aid, bid, bt, r["b_key"], r["b_disp"] or r["b_key"])
            if at == "person"
            else (bid, aid, at, r["a_key"], r["a_disp"] or r["a_key"])
        )
        if ot == "address":
            ak = address_key(odisp or ok)
            if ak:
                person_addrs.setdefault(pid, {})[ak] = odisp
            for c_name in _extract_cities_from_strings([odisp, ok]):
                person_cities.setdefault(pid, set()).add(c_name)
        elif ot == "city":
            for c_name in _extract_cities_from_strings([odisp, ok]):
                person_cities.setdefault(pid, set()).add(c_name)
        elif ot == "phone":
            person_phones.setdefault(pid, {})[ok] = odisp
        elif ot == "national_id":
            ik = il_id_key(ok)
            if ik:
                person_nat_ids.setdefault(pid, set()).add(ik)

    # Also include attributes (city, address, street, national_id, kinship columns) from `attributes` table
    attr_rows = store.q("""
        SELECT a.entity_id, a.name, a.value, a.kind
        FROM attributes a
        JOIN entities e ON e.id = a.entity_id
        WHERE e.type = 'person'
    """)
    for ar in attr_rows:
        pid = ar["entity_id"]
        akind = (ar["kind"] or "").lower()
        aname = (ar["name"] or "").lower()
        aval = str(ar["value"] or "").strip()
        if not aval:
            continue
        if akind == "address" or "כתובת" in aname or "address" in aname or "רחוב" in aname:
            ak = address_key(aval)
            if len(ak) >= 4:
                person_addrs.setdefault(pid, {})[ak] = aval
            for c_name in _extract_cities_from_strings([aval]):
                person_cities.setdefault(pid, set()).add(c_name)
        elif akind == "city" or "עיר" in aname or "יישוב" in aname or "city" in aname:
            for c_name in _extract_cities_from_strings([aval]):
                person_cities.setdefault(pid, set()).add(c_name)
        elif akind == "national_id" or "ת.ז" in aname or "תעודת זהות" in aname:
            ik = il_id_key(aval)
            if ik:
                person_nat_ids.setdefault(pid, set()).add(ik)

    all_dossier_kinship: List[Dict] = []
    seen_dossier_pairs: Set[Tuple[int, str]] = set()

    for idx_c, c in enumerate(person_clusters, 1):
        c_mids = set(_cluster_mids(c))
        c_names = list(c.get("names") or ([c["name"]] if c.get("name") else [])) + list(c.get("aliases", []))
        c_primary_name = c_names[0] if c_names else ""
        c_num = c.get("n", idx_c)
        c_id = c.get("id") or (next(iter(c_mids)) if c_mids else c_num)

        # Aggregate cluster-level addresses, cities, phones, national_ids
        c_addrs: Dict[str, str] = {}
        c_cities: Set[str] = set()
        c_phones: Dict[str, str] = {}
        c_nat_ids: Set[str] = set()
        c_co_pids: Set[int] = set()
        c_explicit: List[Tuple[int, str, float, str]] = []

        for mid in c_mids:
            c_addrs.update(person_addrs.get(mid, {}))
            c_cities |= person_cities.get(mid, set())
            c_phones.update(person_phones.get(mid, {}))
            c_nat_ids |= person_nat_ids.get(mid, set())
            c_co_pids |= co_mentions.get(mid, set())
            c_explicit.extend(explicit_kin.get(mid, []))

        facets = c.get("facets", {})
        for a_item in list(c.get("addresses", [])) + list(facets.get("address", [])):
            av = a_item["value"] if isinstance(a_item, dict) else str(a_item)
            ak = address_key(av)
            if ak:
                c_addrs.setdefault(ak, av)
            c_cities |= _extract_cities_from_strings([av])
        for ci_item in c.get("cities", []):
            cv = ci_item["value"] if isinstance(ci_item, dict) else str(ci_item)
            c_cities |= _extract_cities_from_strings([cv])
        for attr_item in c.get("attributes", []):
            if isinstance(attr_item, dict) and attr_item.get("kind") == "city":
                for v in attr_item.get("values", [attr_item.get("value", "")]):
                    c_cities |= _extract_cities_from_strings([str(v)])

        # Candidate evaluation: map candidate_pid -> {roles, signals: [(score, reason_he)], types: set, snippets}
        cand_map: Dict[int, Dict] = {}

        def _add_signal(other_pid: int, role_code: str, score: float, reason_he: str, snippet: str = "", sig_type: str = "heuristic"):
            if other_pid in c_mids:
                return
            info = cand_map.setdefault(other_pid, {
                "roles": [],
                "signals": [],
                "types": set(),
                "snippets": [],
            })
            info["types"].add(sig_type)
            if role_code and role_code not in info["roles"]:
                info["roles"].append(role_code)
            if not any(r == reason_he for _, r in info["signals"]):
                info["signals"].append((score, reason_he))
            if snippet and snippet not in info["snippets"]:
                info["snippets"].append(snippet)

        # 1. Explicit kinship links
        for other_pid, role_code, conf, snip in c_explicit:
            if other_pid in c_mids or other_pid not in person_by_id:
                continue
            role_he = KINSHIP_ROLE_LABELS.get(role_code, "קרוב משפחה")
            _add_signal(
                other_pid,
                role_code,
                max(0.92, conf),
                f"קשר משפחתי מפורש במסמך/מסד: {role_he}",
                snip,
                sig_type="explicit",
            )

        # 2. Heuristic kinship scan across all other person entities
        same_id_pids = {x["id"] for x in c.get("same_identity", []) if x.get("relation") == "same_person"}

        for other_pid, p_row in person_by_id.items():
            if other_pid in c_mids or other_pid in same_id_pids:
                continue
            other_disp = p_row["display"] or p_row["key"]
            # Skip if other_disp is actually a transliteration/same-name of the cluster itself without conflicting IDs
            other_ids = person_nat_ids.get(other_pid, set())
            has_id_conflict = bool(c_nat_ids and other_ids and not (c_nat_ids & other_ids))
            if not has_id_conflict and any(
                name_key(cn) == name_key(other_disp) or same_person_name(cn, other_disp)
                for cn in c_names
            ):
                continue

            # Check shared surname (same script or cross-script)
            matched_sur = None
            for cn in c_names:
                matched_sur = shared_surname(cn, other_disp)
                if matched_sur:
                    break

            # Signal B: Shared residential address
            other_addrs = person_addrs.get(other_pid, {})
            shared_ak = set(c_addrs.keys()) & set(other_addrs.keys())
            if shared_ak:
                ak0 = next(iter(shared_ak))
                addr_disp = c_addrs.get(ak0) or other_addrs.get(ak0)
                if matched_sur:
                    _add_signal(
                        other_pid,
                        "relative",
                        0.88,
                        f"קשר משפחתי סביר: שם משפחה זהה ({matched_sur}) + כתובת מגורים משותפת ({addr_disp})",
                        sig_type="heuristic",
                    )
                else:
                    _add_signal(
                        other_pid,
                        "household",
                        0.72,
                        f"מגורים משותפים / משק בית: כתובת מגורים זהה ({addr_disp})",
                        sig_type="heuristic",
                    )

            # Signal C: Shared surname + Shared city (only if not already matched on full street address)
            if matched_sur and not shared_ak:
                other_cities = person_cities.get(other_pid, set())
                shared_ct = c_cities & other_cities
                if shared_ct:
                    city_disp = next(iter(shared_ct))
                    _add_signal(
                        other_pid,
                        "relative",
                        0.70,
                        f"קשר משפחתי אפשרי: שם משפחה זהה ({matched_sur}) + יישוב מגורים משותף ({city_disp})",
                        sig_type="heuristic",
                    )

            # Signal D: Shared landline phone OR shared mobile phone with shared surname & distinct given name
            other_phones = person_phones.get(other_pid, {})
            shared_ph = set(c_phones.keys()) & set(other_phones.keys())
            for pk in shared_ph:
                ph_disp = c_phones.get(pk) or other_phones.get(pk) or pk
                if _is_landline_il(pk):
                    if matched_sur:
                        _add_signal(
                            other_pid,
                            "relative",
                            0.86,
                            f"קשר משפחתי סביר: שם משפחה זהה ({matched_sur}) + טלפון נייח משותף ({ph_disp})",
                            sig_type="heuristic",
                        )
                    else:
                        _add_signal(
                            other_pid,
                            "household",
                            0.78,
                            f"קשר משק בית סביר: טלפון נייח משותף ({ph_disp})",
                            sig_type="heuristic",
                        )
                elif matched_sur:
                    _add_signal(
                        other_pid,
                        "relative",
                        0.82,
                        f"קשר משפחתי סביר: שם משפחה זהה ({matched_sur}) + מספר טלפון משפחתי משותף ({ph_disp})",
                        sig_type="heuristic",
                    )

            # Signal E: Sequential / Close Israeli National IDs
            if c_nat_ids and other_ids:
                close_pair = _close_national_ids(c_nat_ids, other_ids)
                if close_pair:
                    id_a, id_b = close_pair
                    if matched_sur:
                        _add_signal(
                            other_pid,
                            "relative",
                            0.89,
                            f"קשר משפחתי סביר: שם משפחה זהה ({matched_sur}) + מספרי ת\"ז עוקבים/קרובים ({id_a}, {id_b})",
                            sig_type="heuristic",
                        )
                    else:
                        _add_signal(
                            other_pid,
                            "relative",
                            0.76,
                            f"קשר משפחתי אפשרי: מספרי ת\"ז עוקבים/קרובים ({id_a}, {id_b})",
                            sig_type="heuristic",
                        )

            # Signal F: Co-mentioned in document/record + Shared surname
            if matched_sur and other_pid in c_co_pids:
                _add_signal(
                    other_pid,
                    "relative",
                    0.74,
                    f"קשר משפחתי סביר: שם משפחה זהה ({matched_sur}) + הופעה משותפת במסמך/רשומה",
                    sig_type="heuristic",
                )

        # Deduplicate & merge relatives that are cross-script/alias variants of each other
        cluster_kinship: List[Dict] = []
        for other_pid, info in cand_map.items():
            p_row = person_by_id.get(other_pid)
            if not p_row:
                continue
            other_name = p_row["display"] or p_row["key"]
            signals = sorted(info["signals"], key=lambda x: -x[0])
            best_score = signals[0][0]
            # Multi-signal reinforcement boost
            combined_score = round(min(0.99, best_score + 0.06 * (len(signals) - 1)), 2)
            # Pick the most specific role
            specific_roles = [r for r in info["roles"] if r not in ("relative", "household")]
            role_code = specific_roles[0] if specific_roles else (info["roles"][0] if info["roles"] else "relative")
            role_label = KINSHIP_ROLE_LABELS.get(role_code, "קרוב משפחה")
            reason_str = " · ".join(r for _, r in signals)
            types_set = info.get("types", {"heuristic"})
            ev_type = (
                "explicit+heuristic"
                if ("explicit" in types_set and "heuristic" in types_set)
                else ("explicit" if "explicit" in types_set else "heuristic")
            )

            # Check if we already added a cross-script / same-name relative to `cluster_kinship`
            existing = next(
                (k for k in cluster_kinship
                 if name_key(k["name"]) == name_key(other_name) or same_person_name(k["name"], other_name)),
                None,
            )
            if existing:
                existing["confidence"] = round(max(existing["confidence"], combined_score), 2)
                if other_name not in existing.get("aliases", []) and other_name != existing["name"]:
                    existing.setdefault("aliases", []).append(other_name)
                if role_code not in ("relative", "household") and existing["role"] in ("relative", "household"):
                    existing["role"] = role_code
                    existing["relation"] = role_label
                if ev_type != existing.get("evidence_type"):
                    existing["evidence_type"] = "explicit+heuristic"
                for _, r in signals:
                    if r not in existing["reason"]:
                        existing["reason"] += f" · {r}"
                continue

            item = {
                "id": other_pid,
                "person_id": other_pid,
                "subject_id": c_id,
                "cluster": c_num,
                "person_name": c_primary_name,
                "name": other_name,
                "aliases": [],
                "role": role_code,
                "relation": role_label,
                "confidence": combined_score,
                "evidence_type": ev_type,
                "reason": reason_str,
                "snippet": info["snippets"][0] if info["snippets"] else "",
            }
            cluster_kinship.append(item)

            pair_key = (c_num, name_key(other_name))
            if pair_key not in seen_dossier_pairs:
                seen_dossier_pairs.add(pair_key)
                all_dossier_kinship.append(item)

        cluster_kinship.sort(key=lambda x: (-x["confidence"], x["name"]))
        c["kinship"] = cluster_kinship

    all_dossier_kinship.sort(key=lambda x: (-x["confidence"], x["name"]))
    return all_dossier_kinship
