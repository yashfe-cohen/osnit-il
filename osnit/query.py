"""Free-text query understanding: 'יונתן חייט pdf', 'יונתן חייט מספר טלפון', 'Jane Doe filetype:docx email'."""
import re
from dataclasses import asdict, dataclass, field

FILETYPES = {"pdf": "pdf", "doc": "docx", "docx": "docx", "xls": "xlsx", "xlsx": "xlsx", "csv": "csv", "txt": "txt",
             "json": "json", "vcf": "vcf", "ppt": "ppt", "pptx": "ppt"}
WANT = {
    "phone": ["מספר טלפון", "מספר נייד", "מס' טלפון", "טלפון", "נייד", "פלאפון", "טל'", "phone number", "phone", "mobile", "cell", "tel"],
    "email": ["כתובת מייל", "כתובת אימייל", "דואר אלקטרוני", "דוא\"ל", "אימייל", "מייל", "email", "e-mail", "mail"],
    "cv": ["קורות חיים", "קו\"ח", "resume", "cv"],
    "org": ["מקום עבודה", "חברה", "עובד ב", "employer", "company", "works at"],
}
_PHRASES = sorted(((p, k) for k, ps in WANT.items() for p in ps), key=lambda x: -len(x[0]))


@dataclass
class Intent:
    raw: str
    subject: str
    filetypes: list = field(default_factory=list)
    want: list = field(default_factory=list)

    def to_json(self):
        return asdict(self)


def parse_query(raw: str) -> Intent:
    s = " " + raw.strip() + " "
    filetypes, want = [], []

    def ft(m):
        t = FILETYPES.get(m.group(1).lower())
        if t and t not in filetypes:
            filetypes.append(t)
        return " "

    s = re.sub(r"(?i)\b(?:filetype|ext|type):\s*(\w+)", lambda m: ft(m) if m.group(1).lower() in FILETYPES else m.group(), s)
    s = re.sub(r"(?i)(?:\bנקודה\s+|(?<=\s)\.)(" + "|".join(FILETYPES) + r")(?=\s)", ft, s)
    s = re.sub(r"(?i)(?<=\s)(" + "|".join(FILETYPES) + r")(?=\s)", ft, s)
    for phrase, kind in _PHRASES:
        pat = re.compile(r"(?<![\wא-ת])" + re.escape(phrase) + r"(?![\wא-ת])", re.I)
        if pat.search(s):
            s = pat.sub(" ", s)
            if kind not in want:
                want.append(kind)
    subject = re.sub(r"\s+", " ", re.sub(r'(^|\s)"|"(?=\s|$)', " ", s)).strip()
    return Intent(raw=raw.strip(), subject=subject or raw.strip(), filetypes=filetypes, want=want)
