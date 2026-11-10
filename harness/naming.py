"""
naming.py -- the ONE singular rule for object-type names derived from routes.

Object types are named from route segments ("/api/notes/{id}" -> "note") in
several places: the business-context agent's objects, the access matrix's
object keys, the self-observed ownership facts and the experiments built from
them. They must agree, or an ownership fact for one spelling never meets the
object named by another. A naive `word[:-1]` turned "status" into "statu";
this rule never strips a word ending in -ss, -us or -is.
"""
from __future__ import annotations

import re


def singular(word: str) -> str:
    """The singular of a route noun, keeping the input's case.

    -ies -> -y ("categories" -> "category"); -sses / -xes / -zzes / -ches / -shes
    and Latin -uses drop "es" ("addresses", "boxes", "matches", "statuses");
    a word ending in -ss, -us or -is is already singular ("address", "status",
    "analysis"); otherwise one trailing "s" is dropped. Words under three
    letters are returned unchanged."""
    w = str(word or "")
    low = w.lower()
    if len(low) < 3:
        return w
    if low.endswith("ies") and len(low) > 4:
        return w[:-3] + ("Y" if w[-3:].isupper() else "y")
    if low.endswith(("sses", "xes", "zzes", "shes")) or (
            low.endswith("ches") and not low.endswith("aches")):
        return w[:-2]
    if low.endswith("uses") and len(low) > 4 and not low.endswith(("ouses", "auses")):
        return w[:-2]      # statuses, bonuses, campuses (not houses, causes)
    if low.endswith(("ss", "us", "is")):
        return w
    if low.endswith("s"):
        return w[:-1]
    return w


def object_key(name: str) -> str:
    """The comparison key of an object type: "Notes", "note", "NOTE" and
    "no-tes" agree. Singular first, then everything but [a-z0-9] removed."""
    return re.sub(r"[^a-z0-9]", "", singular(str(name or "").strip()).lower())


def legacy_object_key(name: str) -> str:
    """The key the pre-r7 rule produced (one trailing "s" stripped unless -ss),
    so data saved under it -- an operator's access-matrix answer about
    "statu" -- is still found. Lookups only; nothing is saved under it."""
    word = str(name or "").strip()
    low = word.lower()
    if low.endswith("ies") and len(word) > 4:
        word = word[:-3] + "y"
    elif low.endswith(("sses", "xes", "ches", "shes")):
        word = word[:-2]
    elif low.endswith("s") and not low.endswith("ss") and len(word) > 2:
        word = word[:-1]
    return re.sub(r"[^a-z0-9]", "", word.lower())
