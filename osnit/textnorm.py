"""Length-preserving text folding so match offsets map back onto the cleaned original."""
import re
import unicodedata

NIQQUD = re.compile(r"[֑-ׇ]")
INVISIBLE = re.compile(r"[​-‏‪-‮⁠﻿⁦-⁩؜]")
_FINALS = str.maketrans("ךםןףץ", "כמנפצ")
_QUOTES = str.maketrans({"״": '"', "”": '"', "“": '"', "׳": "'", "’": "'", "‘": "'", "`": "'",
                         "–": "-", "—": "-", "־": "-"})
TOKEN = re.compile(r"[^\W_]+(?:['\-][^\W_]+)*")
HEBREW = re.compile(r"[א-ת]")


def clean(text: str) -> str:
    text = unicodedata.normalize("NFKC", text)
    text = NIQQUD.sub("", INVISIBLE.sub("", text))
    return text.replace("\xa0", " ").translate(_QUOTES)


def fold(s: str) -> str:
    """Lowercase + final-letter fold; always the same length as the input."""
    s = s.translate(_FINALS)
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
