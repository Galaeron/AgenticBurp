"""Parsing of sqlmap's report: injection points, payload boundaries, union column counts and
verdict lines. Moved verbatim out of sqlmap.py (ARC-9); the validator reads these through its
own module so a patch on `sqlmap.parse_injection_points` still reaches it."""

from __future__ import annotations

import re


# Ticket 2B: sqlmap's own report of WHERE it found injection. The block starts with
# "sqlmap identified|resumed the following injection point(s)" and holds, per
# parameter, a "Parameter: <name> (<place>)" line followed by repeated
# Type/Title/Payload lines.
_POINTS_HEADER_RE = re.compile(r"sqlmap (?:identified|resumed) the following injection point", re.I)
_POINT_PARAM_RE = re.compile(r"^Parameter:\s*(?P<name>.+?)\s*\((?P<place>.+)\)\s*$")
_POINT_FIELD_RE = re.compile(r"^(?P<key>Type|Title|Payload):\s*(?P<value>.*)$", re.I)
_HEADER_PLACES = frozenset({"user-agent", "referer", "host", "x-forwarded-for", "x-forwarded-host"})
# Where the harness's boolean differential can mutate a parameter (see
# _boolean_probe_fallback's only_params).
_DIFFERENTIAL_LOCATIONS = ("query", "body_form", "body_json")
_MAX_REPRODUCED_POINTS = 3
_MAX_LISTED_POINTS = 8
_PAYLOAD_LINE_CAP = 200
_TAIL_MARKER = "--- sqlmap output (tail) ---"


def _point_location(place: str, name: str) -> tuple[str, str]:
    """(harness parameter location, parameter name) for sqlmap's "(place)" label and
    its parameter name ("JSON email" is the JSON body field "email")."""
    label = place.strip().lower()
    if label == "get":
        return "query", name
    if label == "post":
        return "body_form", name
    if label == "(custom) post":
        return "body_json", name[5:].strip() if name[:5].lower() == "json " else name
    if label == "uri":
        return "path", name
    if label == "cookie":
        return "cookie", name
    if label in _HEADER_PLACES or label.startswith("x-"):
        return "header", name
    return label, name


def parse_injection_points(output: str) -> list[dict]:
    """The injection points sqlmap reported in its output: one dict per
    (parameter, type) with place (the harness's parameter location), parameter,
    type, title and payload. Missing lines leave "" and Windows line endings are
    fine. [] when the output has no injection-point block."""
    points: list[dict] = []
    in_block = False
    param: tuple[str, str] | None = None
    entry: dict | None = None
    for raw in (output or "").splitlines():
        line = raw.strip()
        if _POINTS_HEADER_RE.search(line):
            in_block, param, entry = True, None, None
            continue
        if not in_block:
            continue
        if line.startswith("[") and "] [" in line[:30]:
            in_block, param, entry = False, None, None   # a log line ends the block
            continue
        found = _POINT_PARAM_RE.match(line)
        if found:
            param, entry = _point_location(found.group("place"), found.group("name").strip()), None
            continue
        field = _POINT_FIELD_RE.match(line)
        if field is None or param is None:
            continue
        key, value = field.group("key").lower(), field.group("value").strip()
        # A Type line, or a Title/Payload that repeats one this entry already has,
        # starts a new entry for the parameter.
        if entry is None or key == "type" or entry[key]:
            entry = {"place": param[0], "parameter": param[1], "type": "", "title": "", "payload": ""}
            points.append(entry)
        entry[key] = value
    unique: list[dict] = []
    seen: set[tuple[str, str, str]] = set()
    for point in points:
        ident = (point["place"], point["parameter"], point["type"])
        if ident not in seen:
            seen.add(ident)
            unique.append(point)
    return unique


def _point_technique(point: dict) -> str:
    """The technique the harness can reproduce for one sqlmap point: "boolean",
    "error", "union", or "" (time-based and stacked queries are not replayed)."""
    kind = point.get("type", "").lower()
    for technique in ("boolean", "error", "union"):
        if technique in kind:
            return technique
    return ""


# Where sqlmap's payload leaves the original value: its first SQL keyword.
_PAYLOAD_KEYWORD = re.compile(r"\s(?:AND|OR|UNION|RLIKE|PROCEDURE|HAVING)\b|\bUNION\b", re.I)


def _payload_boundary(payload: str) -> str | None:
    """The characters that close the injected value in sqlmap's reported payload:
    "'" for a string, "')" for a string inside parentheses, "" for a number. Read
    only for context. None when no SQL keyword is found or the closing characters
    are anything else (the point is then not reproduced)."""
    found = _PAYLOAD_KEYWORD.search(payload or "")
    if found is None:
        return None
    prefix = payload[:found.start()].rstrip()
    closing = re.search(r"[^\w\s]*$", prefix).group(0)
    # The value's own punctuation (a JSON '"' opening the string, a sign) is not
    # part of the closing sequence; keep only quote, parenthesis and LIKE wildcard.
    closing = closing.lstrip(":=\"{[,-+")
    if closing and not re.fullmatch(r"%?['\"]\)*", closing):
        return None
    return closing


def _union_column_count(payload: str) -> int:
    """How many columns sqlmap's UNION SELECT projects (top-level commas, outside
    quotes and parentheses), or 0 when it is not a plain UNION SELECT or has more
    than _MAX_UNION_COLUMNS columns."""
    found = re.search(r"\bUNION\s+(?:ALL\s+)?SELECT\s+", payload or "", re.I)
    if found is None:
        return 0
    depth, quote, count = 0, "", 1
    for ch in payload[found.end():]:
        if quote:
            quote = "" if ch == quote else quote
        elif ch in "'\"":
            quote = ch
        elif ch == "(":
            depth += 1
        elif ch == ")":
            if depth == 0:
                break
            depth -= 1
        elif ch == "," and depth == 0:
            count += 1
        elif ch in "#-" and depth == 0:
            break                       # the trailing comment (-- or #)
    return count if count <= _MAX_UNION_COLUMNS else 0


_MAX_UNION_COLUMNS = 10


def _point_label(point: dict) -> str:
    return f"{point['place']}:{point['parameter']}"


def _points_evidence(points: list[dict], tail: str, differential: str = "") -> str:
    """The evidence of a sqlmap confirmation: what it found where, then its payloads
    (and the harness's own differential, when it reproduced one), then the output
    tail (callers keep only the first 1000 characters)."""
    if not points:
        return tail
    listed = points[:_MAX_LISTED_POINTS]
    lines = [f"injection point: {_point_label(p)} — {p['type'] or 'injection'}"
             + (f" ({p['title']})" if p["title"] else "") for p in listed]
    lines += [f"payload ({_point_label(p)}): {p['payload'][:_PAYLOAD_LINE_CAP]}"
              for p in listed if p["payload"]]
    if differential:
        lines.append(f"harness differential: {differential}")
    return "\n".join(lines) + f"\n{_TAIL_MARKER}\n" + tail


# sqlmap's own conclusions: its warning/critical/error lines and any line about
# injectability. The decision lines come LAST in its output, after an early
# "heuristics detected ... WAF/IPS" line, so a head-truncated copy (the ledger keeps
# 1000 characters) lost the verdict on every not-confirmed run of the 8h juice-shop run.
_VERDICT_LINE = re.compile(r"\[(?:WARNING|CRITICAL|ERROR)\]|injectable|is vulnerable", re.I)
_LOG_TIME = re.compile(r"^\s*\[\d{2}:\d{2}:\d{2}\]\s*")
_VERDICT_MARKER = "sqlmap verdict:"
_MAX_VERDICT_LINES = 6
_VERDICT_LINE_CAP = 160


def verdict_lines(output: str) -> list[str]:
    """sqlmap's last few distinct verdict lines, oldest first, without timestamps."""
    picked: list[str] = []
    for line in reversed((output or "").splitlines()):
        if not _VERDICT_LINE.search(line):
            continue
        text = _LOG_TIME.sub("", line).strip()[:_VERDICT_LINE_CAP]
        if text and text not in picked:
            picked.append(text)
            if len(picked) == _MAX_VERDICT_LINES:
                break
    return picked[::-1]


def _verdict_evidence(output: str) -> tuple[str, str]:
    """(evidence, limitation) for a run sqlmap did not confirm: the parsed verdict
    lines first, so any head-truncated copy keeps them, then the output tail."""
    lines = verdict_lines(output)
    if not lines:
        return output, ""
    return (f"{_VERDICT_MARKER}\n" + "\n".join(lines) + f"\n{_TAIL_MARKER}\n" + output,
            "sqlmap: " + "; ".join(lines))
