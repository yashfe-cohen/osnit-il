"""Length-preserving text folding so match offsets map back onto the cleaned original."""
import html
import re
import unicodedata

NIQQUD = re.compile(r"[֑-ׇ]")
INVISIBLE = re.compile(r"[\u200b-\u200f\u202a-\u202e\u2060-\u206f\ufeff\u061c\xad]")
_FINALS = str.maketrans("ךםןףץ", "כמנפצ")
_QUOTES = str.maketrans({"״": '"', "”": '"', "“": '"', "׳": "'", "’": "'", "‘": "'", "`": "'",
                         "–": "-", "—": "-", "־": "-"})
TOKEN = re.compile(r"[^\W_]+(?:['\-][^\W_]+)*")
HEBREW = re.compile(r"[א-ת]")
_HTML_ENT_RE = re.compile(r"&(?:#\d+|#x[0-9a-fA-F]+|[a-zA-Z]{2,8});")
# Pattern 1: Windows-1255 bytes decoded as Latin-1/CP1252 (e.g. 'àìéðä' -> 'אלינה')
_LATIN1_HEB_RE = re.compile(r"[\u00e0-\u00fa]{2,}")
# Pattern 2: UTF-8 Hebrew bytes decoded as Windows-1255 ('׳' = 0xD7 followed by CP1255/1252 chars, e.g. '׳•׳™׳¡׳׳')
_UTF8_CP1255_MOJIBAKE_RE = re.compile(r"(?:׳[\x80-\xff•™¡¢£¤¥¦§¨©ª«¬®¯°±²³´µ¶·¸¹º»¼½¾¿׳]){2,}")


def repair_mojibake(text: str) -> str:
    """Detects and repairs common Hebrew UTF-8 / Windows-1255 / Latin-1 mojibake sequences."""
    if not text:
        return text
    if "&" in text and _HTML_ENT_RE.search(text):
        try:
            text = html.unescape(text)
        except Exception:
            pass
    if "׳" in text and _UTF8_CP1255_MOJIBAKE_RE.search(text):
        def _fix_utf8_in_cp1255(m):
            chunk = m.group(0)
            raw = bytearray()
            for ch in chunk:
                if ch == "׳":
                    raw.append(0xD7)
                else:
                    try:
                        raw.extend(ch.encode("cp1255"))
                    except UnicodeEncodeError:
                        try:
                            raw.extend(ch.encode("cp1252"))
                        except UnicodeEncodeError:
                            pass
            # Strip trailing lone 0xD7 bytes that lost their second byte
            while raw and raw[-1] in (0xD7, 0xD6):
                raw.pop()
            try:
                decoded = bytes(raw).decode("utf-8", errors="ignore")
                if HEBREW.search(decoded):
                    return decoded
            except Exception:
                pass
            return ""
        text = _UTF8_CP1255_MOJIBAKE_RE.sub(_fix_utf8_in_cp1255, text)
    if _LATIN1_HEB_RE.search(text) and not HEBREW.search(text):
        def _fix_latin1_heb(m):
            chunk = m.group(0)
            try:
                return chunk.encode("latin1").decode("cp1255")
            except Exception:
                return chunk
        text = _LATIN1_HEB_RE.sub(_fix_latin1_heb, text)
    return text


def clean(text: str) -> str:
    if not text:
        return ""
    text = repair_mojibake(text)
    text = unicodedata.normalize("NFKC", text)
    text = NIQQUD.sub("", INVISIBLE.sub("", text))
    return text.replace("\xa0", " ").translate(_QUOTES)


def fold(s: str) -> str:
    """Lowercase + final-letter fold; always the same length as the input."""
    s = s.translate(_FINALS)
    low = s.lower()
    # common case: no character lowercases to several (lower() never shrinks), and no Greek capital sigma (the only
    # context-dependent lowercase: str.lower() gives a word-final 'ς' where per-character lowering gives 'σ')
    if len(low) == len(s) and "Σ" not in s:
        return low
    return "".join(c.lower() if len(c.lower()) == 1 else c for c in s)


def tokens(s: str) -> list:
    return TOKEN.findall(fold(clean(s)))


def name_key(name: str) -> str:
    """Order-insensitive, niqqud/final-letter/case-insensitive identity key for names."""
    return " ".join(sorted(tokens(name)))


def is_hebrew(s: str) -> bool:
    return bool(HEBREW.search(s))


def squash(s: str) -> str:
    return re.sub(r"\s+", " ", s).strip()

