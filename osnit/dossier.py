"""
osnit.dossier: Unified Identity Dossier & Entity Correlation Engine (v2.0).
Provides identity dossiers, entity clustering, relational cross-source analysis,
and automatic cross-language (Hebrew <-> English) record unification.
"""
from .identity import (
    dossier,
    find_people,
    suggest_same_person,
    _name_matches,
    _personal,
    _is_strong,
    _is_mobile,
    _attach_cross_source,
    _connected,
    _graph,
    STRONG,
    WEAK,
    WEAK_MERGE,
    FACET_ORDER,
)
from .xling import same_person_name, skeletons, name_skeleton_keys


def is_cross_language_match(name1: str, name2: str) -> bool:
    """
    Returns True if name1 and name2 represent the same person across Hebrew and Latin scripts
    (e.g., 'יונתן חייט' vs 'Yonatan Hayat', 'ברקת כהן' vs 'Bareket Cohen').
    """
    if not name1 or not name2:
        return False
    return same_person_name(name1, name2) or _name_matches(name1, name2)


def can_unify_records(name1: str, name2: str, shared_anchors: list) -> bool:
    """
    Evaluates whether two records should be automatically unified into a single identity dossier:
    1. Names match cross-language (Hebrew <-> Latin) or exact transliteration.
    2. Share at least one exclusive personal anchor (national_id, email, url, personal mobile phone).
    """
    if not is_cross_language_match(name1, name2):
        return False

    for anchor in shared_anchors:
        if isinstance(anchor, dict):
            atype = anchor.get("type", "")
            aval = anchor.get("value", "")
            exclusive = anchor.get("exclusive", True)
        elif isinstance(anchor, (tuple, list)) and len(anchor) >= 2:
            atype, aval = anchor[0], anchor[1]
            exclusive = True
        else:
            continue

        if atype in STRONG or atype.startswith("u_"):
            return True
        if atype == "phone" and (_is_mobile(aval) or exclusive):
            return True

    return False


__all__ = [
    "dossier",
    "find_people",
    "suggest_same_person",
    "is_cross_language_match",
    "can_unify_records",
    "STRONG",
    "WEAK",
]
