"""Network benchmark: does the map around a person put the people who are really tied to them first?

A synthetic population with known truth is imported through the real pipeline (tables + articles), then the map
(network.ego_network) of every person with at least one true tie is scored.

Truly tied (should be near the top):
  household     the same family at the same address in the same years (and a father named in a column)
  coworkers     a small workplace (3-8 people) at the same time
  couples       one shared mobile
  text          two people an article says worked together / are partners

Traps — they share SOMETHING, but are not tied (must rank below the true ties, or not show at all):
  former tenant the same address, years apart                   (time, periods.py)
  big employer  the same 300-person employer                     (exclusivity)
  ex-coworker   the same small workplace, years apart            (time)
  co-mentioned  named in the same article with no stated relation (text precision)

Scores (averaged over centres): r_precision (precision at k = number of true ties), recall_at_10, order_auc (share of
(true, trap) pairs where the true tie ranks higher; a trap not on the map counts as ranked last), trap_in_top
(share of traps that made the top k). `python -m osnit neteval`; thresholds in tools/gate.py."""
import os
import random
import tempfile
import time
from collections import defaultdict

FIRST = ("דנה רון שרה אבי מאיה נועה יוסי משה רחל דוד עומר תמר אורי מיכל גיל שירה עידו יעל אלון ליאת חיים "
         "אסתר יעקב רבקה איתי הדס נתן אורית עמית ענבל").split()
LAST = ("כהן לוי מזרחי פרץ ביטון אברהם פרידמן אזולאי דהן אוחיון גבאי שפירא רוזנברג קצב חדד וקנין עמר צור אלמוג "
        "ברק גולדשטיין שטרנברג טביב בן-דוד קרויטורו זילברמן הרשקוביץ ליברמן חסון בוזגלו נחום סגל אשכנזי מלכה "
        "יוסף טל שושן רביבו אלבז").split()
STREETS = "הרצל ויצמן ז'בוטינסקי רוטשילד בן-גוריון הנביאים סוקולוב ביאליק".split()
TOWNS = "גן-יבנה חיפה אשדוד רחובות נתניה כרמיאל".split()


def _mobile(i):
    """A plausible, distinct mobile per person (never one the phone gate rejects as fake, e.g. 1234567)."""
    from .extract import norm_phone_il
    from .quality import valid_phone
    k = 0
    while True:
        m = f"05{2 + i % 7}{(i * 104729 + k * 7919 + 3141592) % 8000000 + 1000000:07d}"
        if valid_phone(norm_phone_il(m)):
            return m
        k += 1


def generate(seed=3, families=60):
    """-> (people, rows_residents, rows_jobs, articles, truth, traps)
    people: [{name, mobile}], truth / traps: {frozenset({i, j}): kind}."""
    rng = random.Random(seed)
    people, residents, jobs, articles = [], [], [], []
    truth, traps = {}, {}
    used = set()

    def person(last=None, father=""):
        for _ in range(200):
            n = f"{rng.choice(FIRST)} {last or rng.choice(LAST)}"
            if n not in used:
                used.add(n)
                i = len(people)
                people.append({"name": n, "mobile": _mobile(i), "father": father})
                return i
        raise RuntimeError("names exhausted")

    addr_of = {}
    # households: 2-4 people, one address, one period; a later family at the same address = former tenants (trap)
    for f in range(families):
        last = rng.choice(LAST)
        addr = f"{rng.choice(STREETS)} {f + 1} {rng.choice(TOWNS)}"
        start = rng.randint(2000, 2012)
        end = start + rng.randint(3, 7)
        dad = person(last)
        members = [dad] + [person(last, father=people[dad]["name"].split()[0]) for _ in range(rng.randint(1, 3))]
        for m in members:
            residents.append((m, addr, start, end))
            addr_of[m] = addr
        for a in members:
            for b in members:
                if a < b:
                    truth[frozenset((a, b))] = "household"
        if rng.random() < 0.5:                         # someone else lived there long after they left
            later = person()
            s2 = end + rng.randint(4, 8)
            residents.append((later, addr, s2, s2 + 3))
            for m in members:
                traps[frozenset((m, later))] = "former_tenant"
    n_people = len(people)
    # couples sharing a mobile (one of the pair's own phone)
    for _ in range(families // 6):
        a, b = rng.sample(range(n_people), 2)
        if frozenset((a, b)) not in truth:
            people[b]["mobile2"] = people[a]["mobile"]
            truth[frozenset((a, b))] = "couple"
    # small workplaces, two shifts years apart (the second shift is a trap for the first)
    for w in range(families // 4):
        org = f"מפעל {rng.choice(LAST)} {w + 1}"
        staff = rng.sample(range(n_people), rng.randint(3, 6))
        later = rng.sample([i for i in range(n_people) if i not in staff], 2)
        s = rng.randint(2003, 2010)
        for i in staff:
            jobs.append((i, org, s, s + 4))
        for i in later:
            jobs.append((i, org, s + 10, s + 13))
        for a in staff:
            for b in staff:
                if a < b and frozenset((a, b)) not in truth:
                    truth[frozenset((a, b))] = "coworker"
            for b in later:
                key = frozenset((a, b))
                if key not in truth:
                    traps.setdefault(key, "ex_coworker")
    # one big employer: 300 people (or everyone), never a tie on its own
    big = rng.sample(range(n_people), min(300, n_people))
    for i in big:
        jobs.append((i, "משרד הביטחון", 2005, 2020))
    for _ in range(80):
        a, b = rng.sample(big, 2)
        key = frozenset((a, b))
        if key not in truth:
            traps.setdefault(key, "big_employer")
    # articles: a stated relation (truth) next to a bystander named in the same text (trap)
    for k in range(families // 3):
        a, b, c = rng.sample(range(n_people), 3)
        verb = rng.choice(["עבד עם", "עבדה עם", "הוא שותפו של", "היא שותפתו של"])
        articles.append(f"כתבה מקומית {k}\n\n{people[a]['name']} {verb} {people[b]['name']} בשנים האחרונות. "
                        f"בטקס נכח גם {people[c]['name']}.\n")
        truth.setdefault(frozenset((a, b)), "text")
        for x in (a, b):
            key = frozenset((x, c))
            if key not in truth:
                traps.setdefault(key, "co_mentioned")
    traps = {k: v for k, v in traps.items() if k not in truth}      # a pair that is truly tied is never a trap
    return people, residents, jobs, articles, truth, traps


def _import(folder, people, residents, jobs, articles):
    from .config import Config
    from .engine import Engine
    from .importdb import import_db
    from .ingest import import_path
    from .store import Store
    cfg = Config(db_path=os.path.join(folder, "net.db"), request_delay=0, workers=1)
    cfg.providers = []
    store = Store(cfg.db_path)
    eng = Engine(store, cfg, providers={})
    p = os.path.join(folder, "residents.csv")
    with open(p, "w", encoding="utf-8") as f:
        f.write("שם מלא,טלפון נייד,כתובת,מתאריך,עד תאריך,שם האב\n")
        for i, addr, s, e in residents:
            f.write(f"{people[i]['name']},{people[i]['mobile']},{addr},{s},{e},{people[i]['father']}\n")
    import_db(eng, p, label="residents", crawl_urls=False)
    p = os.path.join(folder, "jobs.csv")
    with open(p, "w", encoding="utf-8") as f:
        f.write("שם מלא,טלפון נייד,מקום עבודה,תאריך התחלה,תאריך סיום\n")
        for i, org, s, e in jobs:
            f.write(f"{people[i]['name']},{people[i]['mobile']},{org},{s},{e}\n")
    import_db(eng, p, label="jobs", crawl_urls=False)
    p = os.path.join(folder, "phones.csv")              # a couple: one row with their own and the shared phone
    with open(p, "w", encoding="utf-8") as f:
        f.write("שם מלא,טלפון נייד,טלפון נוסף\n")
        for pp in people:
            if pp.get("mobile2"):
                f.write(f"{pp['name']},{pp['mobile']},{pp['mobile2']}\n")
    import_db(eng, p, label="phones", crawl_urls=False)
    d = os.path.join(folder, "articles")
    os.makedirs(d, exist_ok=True)
    for k, text in enumerate(articles):
        with open(os.path.join(d, f"a{k}.txt"), "w", encoding="utf-8") as f:
            f.write(text)
    import_path(eng, d)
    store.reindex_names(1_000_000)
    return store


def _entity_of(store, people):
    """roster index -> person entity id (through the person's own mobile)."""
    from .extract import norm_phone_il
    from .multisearch import _persons_on
    out = {}
    for i, p in enumerate(people):
        ids = _persons_on(store, "phone", norm_phone_il(p["mobile"]))
        names = {r["id"]: r["display"] for r in store.q(
            f"SELECT id, display FROM entities WHERE id IN ({','.join('?' * len(ids))})", tuple(ids))} if ids else {}
        mine = [x for x in ids if names.get(x) == p["name"]]
        if mine:
            out[i] = mine[0]
    return out


def run(seed=3, families=60, keep=None):
    from .network import ego_network
    t0 = time.time()
    people, residents, jobs, articles, truth, traps = generate(seed, families)
    folder = keep or tempfile.mkdtemp(prefix="osnit_net_")
    store = _import(folder, people, residents, jobs, articles)
    ent = _entity_of(store, people)
    idx = {e: i for i, e in ent.items()}
    true_of, trap_of = defaultdict(set), defaultdict(set)
    for pair in truth:
        a, b = tuple(pair)
        true_of[a].add(b)
        true_of[b].add(a)
    for pair in traps:
        a, b = tuple(pair)
        trap_of[a].add(b)
        trap_of[b].add(a)
    rp, r10, auc_num, auc_den, trap_top, trap_n, centres = 0.0, 0.0, 0, 0, 0, 0, 0
    by_kind_hit = defaultdict(lambda: [0, 0])
    for i in sorted(true_of):
        if i not in ent:
            continue
        net = ego_network(store, ent[i], max_people=200)
        ranked = [idx[p["id"]] for p in net["people"] if p["id"] in idx]
        pos = {j: k for k, j in enumerate(ranked)}
        k = len(true_of[i])
        top_k = set(ranked[:k])
        rp += len(top_k & true_of[i]) / k
        r10 += len(set(ranked[:10]) & true_of[i]) / min(k, 10)
        for j in true_of[i]:
            kind = truth[frozenset((i, j))]
            by_kind_hit[kind][0] += 1
            by_kind_hit[kind][1] += j in pos
        last = len(ranked) + 1
        for t in true_of[i]:
            for x in trap_of[i]:
                auc_den += 1
                auc_num += pos.get(t, last) < pos.get(x, last + 1) if (t in pos or x in pos) else 0.5
        for x in trap_of[i]:
            trap_n += 1
            trap_top += x in top_k
        centres += 1
    return dict(people=len(people), resolved=len(ent), centres=centres, true_ties=len(truth), traps=len(traps),
                r_precision=round(rp / centres, 4) if centres else 0.0,
                recall_at_10=round(r10 / centres, 4) if centres else 0.0,
                order_auc=round(auc_num / auc_den, 4) if auc_den else 1.0,
                trap_in_top=round(trap_top / trap_n, 4) if trap_n else 0.0,
                found_by_kind={k: round(v[1] / v[0], 3) for k, v in sorted(by_kind_hit.items())},
                took=round(time.time() - t0, 2))
