"""The operator's word on whether two people are related — it overrides every computed link.

The map (network.py) and the chain search (connect.py) compute ties from shared values, family, time and text. The
operator knows things the data does not: two people at one address who never met, a co-mention that means nothing,
or a real tie the files never show. A decision is per PAIR of people (any of their links):

  related      the two are connected: the tie is shown at full strength (0.95) — even when the data has no link —
               labelled "אושר על ידי המפעיל", with the operator's note
  unrelated    every computed link between the two is ignored: they leave each other's map, and a chain never steps
               from one straight to the other (a chain THROUGH a third person is still possible)
  clear        forget the decision

Kept in link_decisions (a < b), audited (who-when-note), and never touches identity: "unrelated" is not "different
person", and "related" is not "same person" (that is possible.decide)."""
import time

DECISIONS = ("related", "unrelated")
CONFIRMED_W = 0.95


def decide(store, a, b, decision, note=""):
    a, b = sorted((int(a), int(b)))
    if a == b:
        raise ValueError("the same person")
    for x in (a, b):
        if not store.q1("SELECT 1 x FROM entities WHERE id=? AND type='person'", (x,)):
            raise ValueError(f"{x} is not a person")
    with store.tx() as c:
        if decision == "clear":
            c.execute("DELETE FROM link_decisions WHERE a=? AND b=?", (a, b))
        elif decision in DECISIONS:
            c.execute("INSERT INTO link_decisions(a, b, decision, note, at) VALUES(?,?,?,?,?) "
                      "ON CONFLICT(a, b) DO UPDATE SET decision=excluded.decision, note=excluded.note, at=excluded.at",
                      (a, b, decision, str(note or "")[:500], time.time()))
        else:
            raise ValueError("decision must be related, unrelated or clear")
        c.execute("DELETE FROM subject_cache")
    return {"a": a, "b": b, "decision": decision}


def decisions_for(store, ids):
    """{(a, b): (decision, note)} for every decision touching any of these people (a < b)."""
    ids = list({int(i) for i in ids})
    out = {}
    for i in range(0, len(ids), 400):
        part = tuple(ids[i:i + 400])
        ph = ",".join("?" * len(part))
        for r in store.q(f"SELECT a, b, decision, note FROM link_decisions WHERE a IN ({ph}) OR b IN ({ph})",
                         part + part):
            out[(r["a"], r["b"])] = (r["decision"], r["note"] or "")
    return out


def pair(decisions, x, y):
    """The decision on two people from a decisions_for() dict, or (None, '')."""
    return decisions.get((min(x, y), max(x, y)), (None, ""))


def log(store, limit=100):
    return [dict(a=r["a"], b=r["b"], a_name=r["na"], b_name=r["nb"], decision=r["decision"], note=r["note"],
                 at=r["at"]) for r in store.q(
        "SELECT d.a, d.b, d.decision, d.note, d.at, ea.display na, eb.display nb FROM link_decisions d "
        "LEFT JOIN entities ea ON ea.id=d.a LEFT JOIN entities eb ON eb.id=d.b ORDER BY d.at DESC LIMIT ?",
        (int(limit),))]
