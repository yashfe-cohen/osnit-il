"""Given-name nickname / diminutive equivalence, across Hebrew and English — e.g. אסתר ≈ אסתי ≈ אתי ≈ Esther ≈
Etti ≈ Eti. Used ONLY as a SUGGESTION signal (dossier "possibly the same person", cross-source correlation),
never as an automatic merge key and never in the extraction/eval path: a nickname is ambiguous (Eti could be
several names), so it proposes a link for the operator to confirm, it does not assert identity on its own."""
import itertools

from .textnorm import clean, fold, is_hebrew, tokens
from .xling import skeletons

# Each group = spellings of ONE given name that people use interchangeably (formal + nicknames, Hebrew + English).
# Curated and conservative — only genuine nickname/transliteration equivalences, never two distinct names.
_GROUPS = [
    ["אסתר", "אסתי", "אתי", "אטי", "אסי", "esther", "esti", "etti", "ettie", "eti", "esty"],
    ["שרה", "שרי", "שרהלה", "sara", "sarah", "sari"],
    ["רבקה", "ריקי", "ריקה", "rivka", "rivki", "rivky", "riki", "rebecca", "becky"],
    ["מרים", "מירי", "מימי", "miriam", "miri", "mimi", "mary"],
    ["רחל", "רחלי", "rachel", "racheli", "rochel"],
    ["לאה", "לאהלה", "lea", "leah"],
    ["חנה", "חני", "hana", "chana", "channa", "hani", "hannah"],
    ["דבורה", "דבי", "דבורי", "dvora", "devora", "deborah", "debbie", "dvori"],
    ["יהודית", "דיתי", "yehudit", "judith", "judy"],
    ["תמר", "תמי", "tamar", "tami", "tammy"],
    ["פנינה", "פני", "pnina", "penny"],
    ["נחמה", "נחי", "nechama", "nehama"],
    ["רות", "רותי", "rut", "ruth", "ruti"],
    ["נעמי", "נומי", "naomi", "nomi"],
    ["מלכה", "מלי", "malka", "mali"],
    ["גיטל", "גולדה", "gittel", "golda"],
    ["ביילא", "בתיה", "batya", "basya", "bat-sheva"],
    ["משה", "מושי", "מוש", "moshe", "moshi", "moishe", "moses", "mo"],
    ["יעקב", "קובי", "יענקל", "יענקי", "yaakov", "jacob", "koby", "kobi", "yankel", "jake"],
    ["יצחק", "איציק", "יצי", "yitzhak", "itzik", "isaac", "yitzchak"],
    ["אברהם", "אבי", "אברימי", "avraham", "abraham", "avi", "abe", "avrumi"],
    ["דוד", "דודי", "david", "dudi", "dave", "davi"],
    ["יוסף", "יוסי", "ספי", "yosef", "yossi", "joseph", "sefi", "joey"],
    ["חיים", "חיימק", "chaim", "haim", "hyman"],
    ["מרדכי", "מוטי", "מוטקה", "mordechai", "moti", "motke", "mordy"],
    ["שלמה", "שלומי", "shlomo", "shlomi", "solomon", "sol"],
    ["מיכאל", "מיקי", "michael", "miki", "mike", "mikey"],
    ["דניאל", "דני", "daniel", "dani", "danny"],
    ["אליהו", "אלי", "eliyahu", "eli", "elijah"],
    ["בנימין", "בני", "binyamin", "benjamin", "benny", "beni", "ben"],
    ["שמואל", "מולי", "סמי", "shmuel", "samuel", "muli", "sami", "sam"],
    ["נתנאל", "נתן", "נתי", "netanel", "natan", "nathan", "nati", "nathaniel"],
    ["גבריאל", "גבי", "gabriel", "gabi", "gaby"],
    ["רפאל", "רפי", "rafael", "raphael", "rafi"],
    ["אהרון", "aharon", "aaron", "aron"],
    ["יהושע", "שוקי", "yehoshua", "shuki", "joshua"],
    ["ישראל", "סרולי", "israel", "yisrael", "sruli"],
    ["מנחם", "מנדי", "menachem", "mendy", "mendi"],
    ["אריה", "לייב", "arie", "aryeh", "leib"],
    ["צבי", "הרשי", "tzvi", "zvi", "hershy", "herschel"],
    ["יהונתן", "יונתן", "jonathan", "yonatan", "yehonatan", "yoni"],
    ["אלחנן", "חנן", "elchanan", "chanan"],
    ["מאיר", "meir", "mair"],
    ["עמנואל", "מני", "emanuel", "immanuel", "mani"],
    # Russian-speaking Israelis: the formal name and its everyday short form, in both scripts
    ["אלכסנדר", "סשה", "אלכס", "שורה", "alexander", "aleksandr", "alexandr", "sasha", "alex", "shura"],
    ["דמיטרי", "דימה", "dmitry", "dmitri", "dmitriy", "dima"],
    ["סבטלנה", "סבטה", "svetlana", "sveta"],
    ["אולגה", "אוליה", "olga", "olya"],
    ["נטליה", "נטשה", "natalia", "natalya", "natasha"],
    ["יקטרינה", "קטיה", "ekaterina", "yekaterina", "katya", "katia"],
    ["ולדימיר", "וולודיה", "ווה", "vladimir", "volodya", "vova"],
    ["מיכאיל", "מישה", "mikhail", "misha"],
    ["יבגני", "ז'ניה", "yevgeny", "evgeny", "zhenya"],
    ["אנסטסיה", "נסטיה", "anastasia", "nastya"],
    ["סרגיי", "סריוז'ה", "sergey", "sergei", "seryozha"],
    ["ויקטוריה", "ויקה", "victoria", "viktoria", "vika"],
]

_LOOKUP = {}
for _gi, _g in enumerate(_GROUPS):
    for _f in _g:
        _LOOKUP.setdefault(fold(_f), set()).add(_gi)


def nick_equiv(a, b):
    """True if two given-name tokens are interchangeable spellings/nicknames of one name (any script)."""
    ga, gb = _LOOKUP.get(fold(a)), _LOOKUP.get(fold(b))
    return bool(ga and gb and (ga & gb))


def _tok_same(x, y):
    """(match, via_nickname) for two name tokens: equal, cross-script skeleton, or a nickname equivalence."""
    if fold(x) == fold(y):
        return True, False
    if nick_equiv(x, y):
        return True, True
    if skeletons(x) & skeletons(y):            # same token in Hebrew vs Latin (consonant skeleton)
        return True, False
    return False, False


def names_nick_match(a, b):
    """True when two full names are the SAME person reached only by allowing a nickname — every token pairs up
    (equal / cross-script / nickname) and at least one pairing needed a nickname. (A plain same-name or pure
    transliteration match returns False here; it is caught by the existing matchers.)"""
    ta, tb = tokens(a), tokens(b)
    if len(ta) != len(tb) or len(ta) < 2:
        return False
    rest, used_nick = list(tb), False
    for x in ta:
        hit = None
        for y in rest:
            m, isn = _tok_same(x, y)
            if m:
                hit = (y, isn)
                break
        if hit is None:
            return False
        used_nick = used_nick or hit[1]
        rest.remove(hit[0])
    return used_nick


def nick_forms(tok):
    """Every interchangeable spelling (both scripts) of one given-name token, excluding the token itself; [] when
    the token is not a known given name."""
    out, seen = [], {fold(tok)}
    for gi in _LOOKUP.get(fold(tok), ()):
        for f in _GROUPS[gi]:
            if fold(f) not in seen:
                seen.add(fold(f))
                out.append(f)
    return out


def expanded_variants(name, cap=48):
    """SEARCH-ONLY name variants that cross nicknames/diminutives (אסתר↔אתי↔Etti) on top of the ordinary
    spelling/order variants — e.g. a search for 'אסתר כהן' also looks for 'אתי כהן' and 'Etti Cohen'. Deliberately
    kept OUT of the extraction/eval path (variants.name_variants): a nickname may widen a search, but it must never
    assert identity. Returns script-consistent token-lists, both name orders."""
    from .variants import token_forms
    base = [t for t in clean(name).split() if t]       # keep the original spelling (unfolded) for query text
    if len(base) < 2:
        return []
    per_token = []
    for t in base:
        forms, seen = list(token_forms(t)[:6]), set()
        for nf in nick_forms(t):                       # add nickname equivalents and THEIR spellings
            forms.extend(token_forms(nf)[:4])
        uniq = []
        for f in forms:
            if fold(f) not in seen:
                seen.add(fold(f))
                uniq.append(f)
        per_token.append(uniq[:10])
    seen, out = set(), []
    for combo in itertools.islice(itertools.product(*per_token), 600):
        if len({is_hebrew(c) for c in combo}) > 1:     # keep every variant in a single script
            continue
        for order in (combo, tuple(reversed(combo))):
            key = tuple(fold(x) for x in order)
            if key not in seen:
                seen.add(key)
                out.append(list(order))
    return out[:cap]
