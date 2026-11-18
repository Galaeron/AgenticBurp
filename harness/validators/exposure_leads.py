"""
Content-exposure leads -> verdicts (r9).

r9 raised exposure leads that no validator decided. A model finding labelled
`exposed_directory_listing`, `exposed_metrics_endpoint` or `public_metrics_endpoint`
canonicalises to nothing, so it got "no confirmation validator available". The passive
AV-EXPOSURE-01 leg did confirm the same listing and metrics captures, but it sends
nothing, so its proofs were legacy (no exchange artifacts). These GET-only legs fetch
what such a capture points at and keep the exchanges as proof artifacts.

- ListingExposureValidator: the capture is a directory listing (an HTML index, or a
  JSON array/object of file entries). It fetches each listed file and classifies the
  content: backups, configuration, keys and keystores, credentials, documents marked
  confidential, data dumps, package manifests. A sensitive file confirms. Listed
  files the server refuses (403 and similar) are named in the evidence.
- FilterBypassValidator: a listed file the server refuses while it serves a sibling
  with another extension (an extension allow-list). It tries the standard NUL
  encodings before an allowed extension (`name.bak%2500.md`, `name.bak%00.md`). The
  encoding must pass two checks. Positive control: the same encoding on a served
  listed file returns that file's exact bytes. Negative control: the same encoding
  on a name that does not exist must not return a file. The bypass is its own finding
  (improper input validation / path filter bypass), apart from the listing.
- MetricsExposureValidator: the capture is a metrics exposition (Prometheus /
  OpenMetrics text). A credential-free GET must return the exposition. A
  credential-free GET of a sibling path that does not exist must not. It records what
  the exposition reveals: family names, prefixes, label keys and build-info versions.
- SensitiveFileValidator: the capture is one file, not a listing, and the listing
  classifier calls it sensitive (an information_disclosure lead on a confidential
  document, say). A credential-free GET must still return a sensitive file. A
  credential-free GET of a nonexistent sibling with the same extension must not
  return the same body. If it does, the route is a catch-all and the verdict is
  inconclusive.
- WellKnownValidator: once per origin, fetches /.well-known/security.txt
  (RFC 9116) and /.well-known/csaf/provider-metadata.json. It reports what is
  published as an observation (severity info), never as a vulnerability.

Every send goes through the run executor (scope lock, safety gate, budget) as a GET
with no redirects, and every verdict names its baseline, attack and control exchanges.
Evidence names files, sizes, hashes and content classes, never a file's values.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from html.parser import HTMLParser
from typing import TYPE_CHECKING
from urllib.parse import quote, unquote, urljoin, urlsplit, urlunsplit

from harness import scope_lock
from harness.categories import canonicalize
from .base import Validator, ValidationResult
from .content_exposure_validator import _LISTING, _PROM_HELP, _PROM_TYPE

if TYPE_CHECKING:
    from harness.models import Finding, HttpExchange

# Listed files fetched per listing; the rest are named as not fetched.
MAX_LISTED_FETCHES = 25
# Refused listed files a bypass is tried on.
MAX_BYPASS_TARGETS = 5
# Standard NUL encodings placed between a refused name and an allowed extension:
# a filter that checks the decoded suffix sees the allowed extension, while a
# backend that stops at the NUL opens the refused file. %2500 is the double-encoded
# form, for a server that decodes the path twice.
NUL_ENCODINGS = ("%2500", "%00")
# Statuses that mean "the server refused this file", not "it does not exist".
_REFUSED_STATUSES = frozenset({400, 403, 406, 415, 451})

_SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _is_2xx(status) -> bool:
    return isinstance(status, int) and 200 <= status < 300


def _header(headers: dict | None, name: str) -> str:
    return next((str(v) for k, v in (headers or {}).items() if k.lower() == name), "")


def _sha(text: str) -> str:
    return hashlib.sha256((text or "").encode("utf-8", errors="replace")).hexdigest()[:16]


def _origin(url: str) -> str:
    parts = urlsplit(url)
    return urlunsplit((parts.scheme, parts.netloc, "", "", ""))


def _is_html(body: str) -> bool:
    from harness.api_surface_discovery import _is_html_document
    return _is_html_document(body or "")


def _is_get(exchange) -> bool:
    return (getattr(exchange, "method", "") or "GET").upper() == "GET"


def _class_tokens(finding) -> tuple[str, str | None]:
    raw = (getattr(finding, "vulnerability_class", "") or "").lower()
    return raw, canonicalize(raw)


# --------------------------------------------------------------------------- #
# Listing parsing
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class ListedEntry:
    name: str             # decoded file name, as listed
    url: str              # absolute URL of the entry
    is_dir: bool = False
    size: int | None = None


class _Anchors(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.hrefs: list[str] = []

    def handle_starttag(self, tag, attrs):
        if tag.lower() == "a":
            href = dict(attrs).get("href")
            if href:
                self.hrefs.append(href)


def _directory_url(url: str) -> str:
    """The listing URL as a directory (trailing slash), without query or fragment."""
    parts = urlsplit(url)
    path = parts.path or "/"
    if not path.endswith("/"):
        path += "/"
    return urlunsplit((parts.scheme, parts.netloc, path, "", ""))


def _child_entry(directory: str, href: str, size: int | None = None, *,
                 page: str | None = None) -> ListedEntry | None:
    """The entry an href names when it is a direct child of `directory` on the same
    origin; None for the parent, the directory itself, sort links and other routes.
    `page` is the URL the href appeared on, resolved as a browser would. A listing
    served at `/dir` (no slash) links its files as `dir/name`."""
    href = (href or "").strip()
    if not href or href.startswith(("#", "?", "javascript:", "mailto:", "data:")):
        return None
    absolute = urljoin(page or directory, href)
    parts, base = urlsplit(absolute), urlsplit(directory)
    if (parts.scheme, parts.netloc) != (base.scheme, base.netloc):
        return None
    if parts.query or not parts.path.startswith(base.path):
        return None
    rest = parts.path[len(base.path):]
    is_dir = rest.endswith("/")
    rest = rest.rstrip("/")
    if not rest or "/" in rest or rest in (".", ".."):
        return None
    clean = urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))
    return ListedEntry(unquote(rest), clean, is_dir, size)


_JSON_NAME_KEYS = ("name", "filename", "file", "path", "href", "url", "key")
_JSON_LIST_KEYS = ("files", "entries", "items", "children", "contents", "listing")
_FILE_NAME = re.compile(r"[^/\\\s<>\"']{1,200}/?")
_HAS_EXTENSION = re.compile(r"\.[A-Za-z0-9]{1,10}$|~$")


def _json_entries(doc, directory: str) -> list[ListedEntry]:
    if isinstance(doc, dict):
        lists = [doc[k] for k in _JSON_LIST_KEYS if isinstance(doc.get(k), list)]
        if len(lists) != 1:
            return []
        doc = lists[0]
    if not isinstance(doc, list) or not doc:
        return []
    entries: list[ListedEntry] = []
    file_like = 0
    for item in doc:
        size = None
        if isinstance(item, str):
            name, href = item, item
        elif isinstance(item, dict):
            name = next((str(item[k]) for k in _JSON_NAME_KEYS if isinstance(item.get(k), str)), "")
            href = next((str(item[k]) for k in ("href", "url", "path") if isinstance(item.get(k), str)), name)
            raw_size = item.get("size", item.get("length", item.get("bytes")))
            size = raw_size if isinstance(raw_size, int) and raw_size >= 0 else None
            kind = str(item.get("type", "")).lower()
            if size is not None or kind in ("file", "dir", "directory", "folder"):
                file_like += 1
            if kind in ("dir", "directory", "folder") and not href.endswith("/"):
                href += "/"
        else:
            return []
        leaf = name.rstrip("/").rsplit("/", 1)[-1]
        if not leaf or not _FILE_NAME.fullmatch(leaf):
            return []
        if _HAS_EXTENSION.search(leaf) or name.endswith("/"):
            file_like += 1
        if "/" not in href.rstrip("/"):
            href = quote(href.rstrip("/"), safe="~@!$&'()*+,;=:.-_") + ("/" if href.endswith("/") else "")
        entry = _child_entry(directory, href, size)
        if entry is None and isinstance(item, dict):
            entry = _child_entry(directory, quote(leaf), size)
        if entry is not None:
            entries.append(entry)
    # A JSON array of words is not a listing: most items must look like files.
    return entries if entries and file_like >= max(1, len(doc) // 2) else []


def parse_listing(exchange) -> list[ListedEntry]:
    """The entries of a directory listing capture (a 2xx GET), else []."""
    if exchange is None or not _is_get(exchange) or not _is_2xx(getattr(exchange, "response_status", None)):
        return []
    body = getattr(exchange, "response_body", "") or ""
    if not body.strip():
        return []
    directory = _directory_url(exchange.url)
    if _LISTING.search(body):
        parser = _Anchors()
        try:
            parser.feed(body)
        except Exception:
            return []
        # Resolve as the browser does. If no link then names a child, fall back to
        # the slash form, for a page whose links assume a trailing slash.
        for base in (exchange.url, None):
            seen, entries = set(), []
            for href in parser.hrefs:
                entry = _child_entry(directory, href, page=base)
                if entry is not None and entry.url not in seen:
                    seen.add(entry.url)
                    entries.append(entry)
            if entries:
                return entries
        return []
    ctype = _header(getattr(exchange, "response_headers", {}), "content-type").lower()
    if "json" in ctype or body.lstrip()[:1] in ("[", "{"):
        try:
            doc = json.loads(body)
        except (ValueError, TypeError):
            return []
        seen, entries = set(), []
        for entry in _json_entries(doc, directory):
            if entry.url not in seen:
                seen.add(entry.url)
                entries.append(entry)
        return entries
    return []


# --------------------------------------------------------------------------- #
# Sensitive-content classification
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class Sensitivity:
    label: str
    severity: str
    reason: str


_BACKUP_SUFFIXES = (".bak", "~", ".old", ".orig", ".save", ".swp", ".backup", ".bkp",
                    ".copy", ".tmp", ".dist")
_KEY_SUFFIXES = (".pem", ".key", ".p12", ".pfx", ".jks", ".keystore", ".kdbx", ".kdb",
                 ".ppk", ".gpg", ".pgp", ".asc", ".der", ".p8")
_KEY_NAMES = ("id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "known_hosts", "authorized_keys")
_DB_SUFFIXES = (".sql", ".sqlite", ".sqlite3", ".db", ".dump", ".mdb", ".bson")
_CONFIG_SUFFIXES = (".env", ".ini", ".conf", ".cfg", ".config", ".properties", ".yml",
                    ".yaml", ".toml", ".xml", ".json", ".htaccess", ".htpasswd")
_MANIFEST_NAMES = ("package.json", "package-lock.json", "npm-shrinkwrap.json", "yarn.lock",
                   "pnpm-lock.yaml", "composer.json", "composer.lock", "requirements.txt",
                   "pipfile", "pipfile.lock", "poetry.lock", "pyproject.toml", "gemfile",
                   "gemfile.lock", "pom.xml", "build.gradle", "go.mod", "go.sum",
                   "cargo.toml", "cargo.lock", "packages.config", "bower.json")
_DOCUMENT_SUFFIXES = (".md", ".txt", ".pdf", ".doc", ".docx", ".odt", ".rtf", ".csv",
                      ".xls", ".xlsx", ".ods", ".ppt", ".pptx", ".html", ".htm")
_PRIVATE_KEY = re.compile(r"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----|-----BEGIN PGP PRIVATE KEY BLOCK-----")
_CREDENTIAL = re.compile(
    r"""(?im)^[\s"']*(?:export\s+)?[\w.\-]*(?:password|passwd|pwd|secret|api[_-]?key|apikey|"""
    r"""access[_-]?key|private[_-]?key|client[_-]?secret|auth[_-]?token|access[_-]?token|"""
    r"""connection[_-]?string|db[_-]?pass)[\w.\-]*["']?\s*[:=]\s*"""
    r"""(?:"(?P<dq>[^"\r\n]*)"|'(?P<sq>[^'\r\n]*)'|(?P<bare>[^\s"'<>,;]+))""")
# A value that names the field (a UI label such as "Repeat Password"), a reference
# to elsewhere, or a placeholder is not a secret.
_LABEL_WORDS = re.compile(r"(?i)pass|pwd|secret|key|token|auth|credential|login")
_PLACEHOLDER = re.compile(
    r"(?i)^(?:true|false|null|none|nil|undefined|changeme|change_me|example|sample|redacted|"
    r"required|optional|string|\*+|x+|\.+|<[^>]*>|\$\{[^}]*\}|\{\{.*\}\}|%[^%]*%|\$[A-Za-z_]\w*|"
    r"(?:process\.env|os\.environ|env)\b.*)$")
_CONFIDENTIAL = re.compile(
    r"(?i)\b(?:confidential|internal use only|for internal use|do not (?:distribute|share)|"
    r"proprietary and confidential|strictly private|restricted distribution|not for distribution)\b")
_SQL_CONTENT = re.compile(r"(?i)\b(?:CREATE TABLE|INSERT INTO)\b")
_MANIFEST_CONTENT = re.compile(r'"(?:dependencies|devDependencies|require|packages|lockfileVersion)"\s*:')


_MARKED_DOCUMENT_SUFFIXES = tuple(s for s in _DOCUMENT_SUFFIXES if s not in (".html", ".htm"))


def _assigns_credential(body: str) -> bool:
    """A line that assigns a password, secret, key or token a literal value. The
    value must have no spaces, not name the field, and not be a placeholder."""
    for match in _CREDENTIAL.finditer(body):
        value = next(v for v in (match["dq"], match["sq"], match["bare"]) if v is not None).strip()
        if len(value) < 4 or any(c.isspace() for c in value):
            continue
        if _LABEL_WORDS.search(value) or _PLACEHOLDER.match(value):
            continue
        return True
    return False


def _base_of_backup(name: str) -> str | None:
    low = name.lower()
    for suffix in _BACKUP_SUFFIXES:
        if low.endswith(suffix) and len(low) > len(suffix):
            return name[: len(name) - len(suffix)]
    return None


# --------------------------------------------------------------------------- #
# Log content: access logs, error logs and logs that carry secrets. Only counts
# are kept; no log line, address, path or value reaches the evidence.
# --------------------------------------------------------------------------- #

_LOG_SCAN_CHARS = 65536
_LOG_SCAN_LINES = 500
# "app.log", rotated "access.log.2026-11-14" / "error.log.1" / "app.log-20240101",
# Apache's "access_log" / "error_log".
_LOG_NAME = re.compile(r"(?i)(?:\.log(?:[._-][\w.-]*)?|[._-]log(?:[._-][\w.-]*)?)$")
# Common / combined log format (Apache, nginx, morgan "combined"): client, ident,
# user, [time], "METHOD target HTTP/x", status.
_ACCESS_LINE = re.compile(
    r"^\s*\S+ \S+ \S+ \[\d{1,2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2}(?: [+-]\d{4})?\] "
    r"\"[A-Z]{3,10} [^\s\"]+(?: HTTP/[\d.]+)?\" \d{3}\b")
_ACCESS_USER_AGENT = re.compile(r"\"[^\"]*\" \"[^\"]+\"\s*$")
# One JSON object per line with a method, a target and a status (pino, bunyan,
# nginx/envoy JSON access logs).
_JSON_ACCESS_LINE = re.compile(
    r"^\s*\{.*\"(?:method|verb|request_method|httpMethod)\"\s*:\s*\"[A-Z]{3,10}\""
    r".*\"(?:url|uri|path|request_uri|originalUrl|requestUrl)\"\s*:\s*\"(?:/|https?://)"
    r".*\"(?:status|statusCode|status_code|response_status)\"\s*:\s*\"?\d{3}\b")
_JSON_LOG_LINE = re.compile(
    r"^\s*\{.*\"(?:time|timestamp|@timestamp|ts|date|datetime)\"\s*:"
    r".*\"(?:level|severity|lvl|msg|message)\"\s*:"
    r"|^\s*\{.*\"(?:level|severity|lvl|msg|message)\"\s*:"
    r".*\"(?:time|timestamp|@timestamp|ts|date|datetime)\"\s*:")
_W3C_FIELDS = re.compile(r"(?im)^#Fields:.*\bcs-method\b.*\bcs-uri-stem\b")
_STACK_FRAME = re.compile(
    r"^\s+at [\w$.<>\[\]/ -]+\([^()]*:\d+(?::\d+)?\)\s*$"               # JS / Java "at f (file:1:2)"
    r"|^\s+at (?:file://|/|[A-Za-z]:\\|node:)\S*:\d+:\d+\s*$"             # JS "at /app/x.js:1:2"
    r"|^\s+at [\w$.<>]+\((?:Native Method|Unknown Source)\)"              # Java
    r"|^\s*File \"[^\"]+\", line \d+(?:, in \S+)?\s*$"                     # Python
    r"|^#\d+ (?:/|[A-Za-z]:\\)\S+\(\d+\): "                                # PHP
    r"|^\s+at \S+\(.*\) in \S.*:line \d+\s*$"                              # .NET
    r"|^\s+from \S+\.rb:\d+:in ")                                          # Ruby
_LOG_SECRET = re.compile(
    r"(?P<jwt>eyJ[\w-]{8,}\.eyJ[\w-]{8,}\.[\w-]*)"
    r"|(?i:\bbearer\s+(?P<bearer>[\w\-.~+/]{16,}=*))"
    r"|(?i:(?:^|[?&;\s\"'{,])(?:access_?token|id_?token|refresh_?token|auth_?token|token|jwt|"
    r"session_?id|session|sid|jsessionid|phpsessid|connect\.sid|api_?key|apikey|password|passwd|"
    r"pwd|secret|client_?secret)[\"']?\s*[=:]\s*"
    r"(?:[\"'](?P<q>[^\"'\r\n]*)[\"']|(?P<b>[^\s&\"',;}<>]+)))"
    r"|(?i:\b(?:authorization|cookie|set-cookie|x-api-key)\s*[:=]\s*[\"']?(?P<h>[^\s\"']{8,}))")
_REDACTED_VALUE = re.compile(r"(?i)redact|filtered|masked|hidden|removed|omitted|^\*+$|^x{3,}$|^-+$")


def _log_secret_line(line: str) -> bool:
    for match in _LOG_SECRET.finditer(line):
        if match["jwt"] or match["bearer"]:
            return True
        value = (match["q"] if match["q"] is not None else match["b"] or match["h"] or "").strip()
        if (len(value) >= 6 and not any(c.isspace() for c in value)
                and not _PLACEHOLDER.match(value) and not _REDACTED_VALUE.search(value)):
            return True
    return False


def _log_sensitivity(name: str, body: str) -> Sensitivity | None:
    """Why a body is a sensitive log, judged by its content. An HTTP access log
    (client addresses, request targets, statuses), an error log (stack frames), or
    any log whose lines carry a token, session id or credential. A log-named file
    with timestamped lines is a plain log. Benign prose, a changelog and a single
    JSON document are not logs. Returns None when nothing here applies."""
    from harness.api_surface_discovery import _LOG_LINE
    text = (body or "")[:_LOG_SCAN_CHARS]
    lines = [ln for ln in text.splitlines()[:_LOG_SCAN_LINES] if ln.strip()]
    if not lines:
        return None
    log_named = bool(_LOG_NAME.search(name or ""))
    w3c = bool(_W3C_FIELDS.search(text))
    access = stamped = frames = secret = agents = 0
    for line in lines:
        is_access = bool(_ACCESS_LINE.match(line) or _JSON_ACCESS_LINE.match(line)
                         or (w3c and not line.startswith("#")))
        is_stamped = bool(_LOG_LINE.match(line) or _JSON_LOG_LINE.match(line))
        if is_access:
            access += 1
            agents += bool(_ACCESS_LINE.match(line) and _ACCESS_USER_AGENT.search(line))
        if is_access or is_stamped:
            stamped += 1
            secret += _log_secret_line(line)
        elif _STACK_FRAME.match(line):
            frames += 1
    # W3C directive lines ("#Fields: ...") are headers, not entries.
    total = len(lines) - (sum(ln.startswith("#") for ln in lines) if w3c else 0)
    one_line_ok = log_named and total <= 2
    access_shaped = access >= 1 and (access >= 0.3 * total) and (access >= 2 or one_line_ok)
    log_shaped = stamped >= 1 and (stamped >= 0.3 * total) and (stamped >= 2 or one_line_ok)
    error_shaped = frames >= 2 and (log_shaped or log_named or frames >= 0.5 * total)
    if secret and (access_shaped or log_shaped or error_shaped):
        kind = "access log" if access_shaped else "error log" if error_shaped else "log"
        return Sensitivity("log_with_secrets", "high",
                           f"a served {kind} with {secret} line(s) carrying a token, session id, "
                           f"credential or authorization value (values redacted)")
    if access_shaped:
        what = "client addresses, request targets and statuses" + (
            ", and user agents" if agents else "")
        return Sensitivity("access_log", "medium",
                           f"an HTTP access log: {access} request line(s) with {what}")
    if error_shaped:
        return Sensitivity("error_log", "medium",
                           f"an error log with {frames} stack-trace frame(s) (internal file paths "
                           f"and code structure)")
    if log_shaped and log_named and not (name or "").lower().endswith(".log"):
        # A rotated log ("app.log.1"); a plain ".log" name keeps its existing rules.
        return Sensitivity("log_file", "medium", f"{stamped} timestamped log line(s) in a log file")
    return None


def _classify_by_name_and_body(name: str, body: str) -> Sensitivity | None:
    from harness.api_surface_discovery import sensitive_file_verdict
    low = name.lower()
    if _PRIVATE_KEY.search(body):
        return Sensitivity("private_key", "high", "body carries a PEM/PGP private-key block")
    logged = _log_sensitivity(name, body)
    if logged is not None:
        return logged
    verdict = sensitive_file_verdict(name, 200, body)
    if verdict.structure and verdict.structure != "directory_listing":
        severity = ("high" if verdict.structure in ("private_key", "aws_credentials", "cloud_credentials_json",
                                                    "htpasswd", "sql_dump", "dotenv") else "medium")
        if verdict.structure in ("npm_manifest", "composer_manifest", "composer_lock", "pip_requirements"):
            return Sensitivity("package_manifest", "low", verdict.reason)
        return Sensitivity(verdict.structure, severity, verdict.reason)
    if low.endswith(_KEY_SUFFIXES) or low in _KEY_NAMES:
        return Sensitivity("key_or_keystore", "high",
                           f"a key or keystore file ({low.rsplit('.', 1)[-1] if '.' in low else low}) "
                           "served with a non-HTML body")
    if low.endswith(_DB_SUFFIXES) and (_SQL_CONTENT.search(body) or body.startswith("SQLite format 3")
                                        or low.endswith((".sqlite", ".sqlite3", ".db", ".mdb", ".bson"))):
        return Sensitivity("database_or_dump", "high", "a database file or SQL dump")
    if _assigns_credential(body):
        return Sensitivity("credentials", "high", "body assigns a password, secret, key or token value")
    if low in _MANIFEST_NAMES or (low.endswith(".json") and _MANIFEST_CONTENT.search(body)):
        return Sensitivity("package_manifest", "low",
                           "a package manifest or lock file (dependency names and versions)")
    # Only a document is "marked confidential"; the word in a JSON or script string is not.
    if low.endswith(_MARKED_DOCUMENT_SUFFIXES) and _CONFIDENTIAL.search(body[:20000]):
        return Sensitivity("confidential_document", "medium",
                           "the document is marked confidential / internal / not for distribution")
    if low.endswith(_CONFIG_SUFFIXES) and not low.endswith((".json", ".xml")):
        return Sensitivity("configuration_file", "medium", "a server or application configuration file")
    if low.endswith(".log"):
        return Sensitivity("log_file", "low", "an application log file")
    return None


def classify_listed_file(name: str, status, headers: dict | None, body: str) -> Sensitivity | None:
    """Why a served listed file is sensitive, or None for a harmless one. Only a 2xx
    with a non-empty body that is not an HTML page (a catch-all) counts."""
    if not _is_2xx(status) or not (body or "").strip():
        return None
    if _is_html(body) and not name.lower().endswith((".html", ".htm")):
        return None
    base = _base_of_backup(name)
    if base is not None:
        inner = _classify_by_name_and_body(base, body)
        severity = "high" if inner and inner.severity == "high" else "medium"
        what = f"; the original is {inner.label} ({inner.reason})" if inner else ""
        return Sensitivity("backup_file", severity, f"a backup copy of {base!r} served as a file{what}")
    return _classify_by_name_and_body(name, body)


# --------------------------------------------------------------------------- #
# Metrics exposition
# --------------------------------------------------------------------------- #

_SAMPLE = re.compile(r"^([A-Za-z_:][\w:]*)(\{[^}]*\})?\s+[-+0-9.eEInfNa]+(?:\s+\d+)?\s*$", re.M)
_LABEL = re.compile(r'([A-Za-z_]\w*)="((?:[^"\\]|\\.)*)"')
_VERSION_KEYS = ("version", "revision", "branch", "goversion", "go_version", "nodejs_version",
                 "runtime_version", "build", "release")


def is_metrics_exposition(status, headers: dict | None, body: str) -> bool:
    """A 2xx Prometheus/OpenMetrics text exposition: a `# HELP` and a `# TYPE` line,
    or a text/plain; version=0.0.4 / openmetrics body with sample lines."""
    if not _is_2xx(status) or not (body or "").strip() or _is_html(body):
        return False
    if _PROM_HELP.search(body) and _PROM_TYPE.search(body):
        return True
    ctype = _header(headers, "content-type").lower()
    declared = "openmetrics" in ctype or ("text/plain" in ctype and "version=0.0.4" in ctype)
    return declared and len(_SAMPLE.findall(body)) >= 3


def summarize_metrics(body: str) -> dict:
    """What an exposition reveals, without sample values: metric families, name
    prefixes, label keys, and the version labels of build-info families."""
    declared = set(re.findall(r"^# TYPE ([A-Za-z_:][\w:]*) ", body or "", re.M))
    families = set(declared)
    label_keys: set[str] = set()
    versions: dict[str, str] = {}
    for metric, labels in _SAMPLE.findall(body or ""):
        if not declared:
            families.add(re.sub(r"_(?:bucket|sum|count|total|created)$", "", metric))
        for key, value in _LABEL.findall(labels or ""):
            label_keys.add(key)
            if key.lower() in _VERSION_KEYS and value and len(versions) < 8:
                versions.setdefault(f"{metric}.{key}", value[:40])
    prefixes = sorted({f.split("_", 1)[0] for f in families if "_" in f})
    return {"families": sorted(families), "family_count": len(families),
            "prefixes": prefixes, "label_keys": sorted(label_keys), "versions": versions}


# --------------------------------------------------------------------------- #
# .well-known
# --------------------------------------------------------------------------- #

_SECURITY_TXT_FIELDS = ("contact", "expires", "encryption", "acknowledgments", "preferred-languages",
                        "canonical", "policy", "hiring", "csaf")


def parse_security_txt(status, headers: dict | None, body: str) -> dict | None:
    """RFC 9116 fields of a served security.txt, else None (no Contact field, an
    HTML page or a non-2xx answer)."""
    if not _is_2xx(status) or not (body or "").strip() or _is_html(body):
        return None
    fields: dict[str, list[str]] = {}
    for line in (body or "").splitlines():
        match = re.match(r"^\s*([A-Za-z-]+)\s*:\s*(\S.*?)\s*$", line)
        if match and match.group(1).lower() in _SECURITY_TXT_FIELDS:
            fields.setdefault(match.group(1).lower(), []).append(match.group(2)[:200])
    if not fields.get("contact"):
        return None
    expired = None
    if fields.get("expires"):
        try:
            when = datetime.fromisoformat(fields["expires"][0].replace("Z", "+00:00"))
            expired = when.astimezone(timezone.utc) < datetime.now(timezone.utc)
        except ValueError:
            expired = None
    return {"fields": fields, "signed": (body or "").lstrip().startswith("-----BEGIN PGP SIGNED MESSAGE-----"),
            "expired": expired}


def parse_csaf_metadata(status, body: str) -> dict | None:
    """The CSAF provider-metadata keys of a served document, else None."""
    if not _is_2xx(status):
        return None
    try:
        doc = json.loads(body or "")
    except (ValueError, TypeError):
        return None
    if not isinstance(doc, dict) or not {"canonical_url", "publisher"} <= set(doc):
        return None
    publisher = doc.get("publisher") if isinstance(doc.get("publisher"), dict) else {}
    return {"canonical_url": str(doc.get("canonical_url"))[:200], "role": str(doc.get("role", ""))[:60],
            "metadata_version": str(doc.get("metadata_version", ""))[:20],
            "publisher": str(publisher.get("name", ""))[:120],
            "distributions": len(doc.get("distributions") or [])}


# --------------------------------------------------------------------------- #
# Shared sending
# --------------------------------------------------------------------------- #

def _without_credentials(headers: dict | None) -> dict:
    from harness.security import is_identity_credential_header
    return {k: v for k, v in (headers or {}).items()
            if k.lower() not in ("host", "content-length", "content-type")
            and not is_identity_credential_header(k)}


class _GetLeg(Validator):
    """A GET-only leg that sends through the run executor."""

    active = True

    def __init__(self, allowed_hosts=None, timeout: float = 10.0, run_context=None):
        self.allowed_hosts = list(allowed_hosts or [])
        self.timeout = timeout
        self.run_context = run_context

    def get_name(self) -> str:
        return self.name

    def get_capability(self) -> str:
        return self.capability

    def _result(self, finding, status, summary, *, confirmed=False, finding_class=None,
                **kwargs) -> ValidationResult:
        return ValidationResult(self.name, status, finding_class or finding.vulnerability_class,
                                confidence=kwargs.pop("confidence", 0.95 if confirmed else 0.0),
                                confirmed=confirmed, summary=summary, **kwargs)

    def _precheck(self, finding, exchange) -> ValidationResult | None:
        if self.run_context is None:
            return self._result(finding, "skipped", f"{self.name}: no run context to send under")
        if self.allowed_hosts and not scope_lock.host_in_scope(exchange.url, self.allowed_hosts):
            return self._result(finding, "skipped",
                                f"host {urlsplit(exchange.url).hostname!r} out of scope")
        return None

    async def _get(self, finding, url: str, headers: dict, session_ref):
        """One GET; returns the ExecutionOutcome (refused sends included)."""
        from harness.run_context import TypedRequest
        return await self.run_context.executor().execute(
            TypedRequest("GET", url, headers=dict(headers)), capability=self.name,
            session_ref=session_ref, case_ref=getattr(finding, "finding_id", "") or "", max_redirects=0)

    def _captured_identity(self, exchange):
        from .injection_targets import replay_headers
        from .transport import bind_session
        headers = replay_headers(exchange)
        headers.pop("Content-Type", None)
        return bind_session(self.run_context, headers)

    @staticmethod
    def _refusal(outcome) -> str:
        why = getattr(outcome, "error", "") or ""
        return f"{outcome.outcome}" + (f" ({why})" if why else "")


def _absent_name(seed: str, extension: str = "") -> str:
    return f"av-absent-{_sha(seed)[:10]}{extension}"


def _extension(name: str) -> str:
    leaf = name.rsplit("/", 1)[-1]
    return "." + leaf.rsplit(".", 1)[-1] if "." in leaf.strip(".") else ""


def _fetch_summary(entry: ListedEntry, outcome) -> str:
    size = len((outcome.body or "").encode("utf-8", errors="replace"))
    return f"{entry.name} (HTTP {outcome.status}, {size} bytes, sha256 {_sha(outcome.body)})"


class _ListingLeg(_GetLeg):
    """Shared listing fetch: re-fetch the listing, a nonexistent sibling and the
    listed files."""

    async def _survey(self, finding, exchange, entries):
        session_ref, headers = self._captured_identity(exchange)
        directory = _directory_url(exchange.url)
        files = [e for e in entries if not e.is_dir]
        out = {"baseline": None, "control": None, "fetched": [], "unsent": [], "refused_run": "",
               "session": (session_ref, headers), "directory": directory, "files": files}
        baseline = await self._get(finding, exchange.url, headers, session_ref)
        if not baseline.executed:
            out["refused_run"] = self._refusal(baseline)
            return out
        out["baseline"] = baseline
        control_ext = _extension(files[0].name) if files else ".txt"
        control = await self._get(finding, directory + _absent_name(exchange.url, control_ext),
                                  headers, session_ref)
        out["control"] = control if control.executed else None
        for entry in files[:MAX_LISTED_FETCHES]:
            got = await self._get(finding, entry.url, headers, session_ref)
            if not got.executed:
                if got.outcome in ("out_of_scope", "blocked"):
                    out["unsent"].append(f"{entry.name}: {got.outcome}")
                    continue
                out["refused_run"] = self._refusal(got)
                break
            out["fetched"].append((entry, got))
        return out

    @staticmethod
    def _served(outcome, control) -> bool:
        """A 2xx file body that the nonexistent-name control does not also return."""
        if not (outcome.ok and _is_2xx(outcome.status) and (outcome.body or "").strip()):
            return False
        if control is not None and control.ok and _is_2xx(control.status) and control.body == outcome.body:
            return False
        return True


def _listing_class_matches(finding) -> bool:
    raw, canonical = _class_tokens(finding)
    tokens = ("listing", "directory", "index", "exposure", "exposed", "disclosure", "sensitive",
              "backup", "discovery", "files", "file_", "confidential", "leak")
    return (any(t in raw for t in tokens)
            or canonical in {"info_disclosure", "misconfig", "recon", "path_traversal"})


class ListingExposureValidator(_ListingLeg):
    """Fetch the files a directory listing names and classify their content."""

    name = "listing_exposure_validator"
    capability = "listing_exposure"
    finding_classes = {"exposed_directory_listing", "directory_listing", "directory listing",
                       "directory_indexing", "sensitive_file_exposure", "backup_file_exposure",
                       "information_disclosure", "info_disclosure", "endpoint_discovery"}

    def applies(self, finding, exchange) -> bool:
        return bool(parse_listing(exchange)) and (super().applies(finding, exchange)
                                                  or _listing_class_matches(finding))

    async def validate(self, finding, exchange) -> ValidationResult:
        early = self._precheck(finding, exchange)
        if early is not None:
            return early
        entries = parse_listing(exchange)
        if not entries:
            return self._result(finding, "skipped", "not_a_listing: the capture is not a directory "
                                                    "listing (2xx GET HTML index or JSON file list)")
        if not any(not e.is_dir for e in entries):
            return self._result(finding, "skipped", "the listing names only sub-directories; no file to fetch")
        survey = await self._survey(finding, exchange, entries)
        baseline, control = survey["baseline"], survey["control"]
        if baseline is None:
            return self._result(finding, "skipped", f"listing re-fetch declined: {survey['refused_run']}")
        if not baseline.ok:
            return self._result(finding, "inconclusive",
                                f"the listing re-fetch got no answer ({self._refusal(baseline)}); "
                                f"not a negative result")
        relisted = parse_listing(_as_exchange(exchange.url, baseline))
        if not relisted:
            return self._result(finding, "not_confirmed",
                                f"the listing re-fetch (HTTP {baseline.status}) no longer lists files",
                                ).with_artifacts(baseline=baseline, attack=baseline, controls=[control])
        sensitive, harmless, refused, missing = [], [], [], []
        for entry, got in survey["fetched"]:
            if self._served(got, control):
                why = classify_listed_file(entry.name, got.status, got.headers, got.body or "")
                (sensitive.append((entry, got, why)) if why else harmless.append((entry, got)))
            elif got.status in _REFUSED_STATUSES:
                refused.append((entry, got))
            else:
                missing.append((entry, got))
        total = len(survey["files"])
        not_fetched = max(0, total - len(survey["fetched"]) - len(survey["unsent"]))
        notes = []
        if refused:
            notes.append(f"{len(refused)} listed file(s) refused by the server: "
                         + ", ".join(f"{e.name} (HTTP {g.status})" for e, g in refused[:8])
                         + " -- AV-FILTER-01 tests whether the refusal is an extension filter "
                           "that an encoding bypasses")
        if missing:
            notes.append(f"{len(missing)} listed file(s) not served: "
                         + ", ".join(f"{e.name} (HTTP {g.status})" for e, g in missing[:5]))
        if harmless:
            notes.append(f"{len(harmless)} harmless file(s): " + ", ".join(e.name for e, _ in harmless[:8]))
        if survey["unsent"]:
            notes.append(f"{len(survey['unsent'])} could not be sent ({survey['unsent'][0]})")
        if not_fetched:
            notes.append(f"{not_fetched} listed file(s) not fetched (cap {MAX_LISTED_FETCHES}"
                         + (f"; {survey['refused_run']}" if survey["refused_run"] else "") + ")")
        control_note = (f"nonexistent sibling control answered HTTP {control.status}" if control is not None
                        else "nonexistent sibling control was not sent")
        if sensitive and (control is None or not control.ok):
            return self._result(finding, "inconclusive",
                                f"{len(sensitive)} sensitive listed file(s) served, but the nonexistent-"
                                f"sibling control got no answer, so a catch-all cannot be ruled out; "
                                f"not a negative result", evidence="; ".join(notes + [control_note]))
        if sensitive:
            sensitive.sort(key=lambda item: -_SEVERITY_RANK.get(item[2].severity, 0))
            top_entry, top_got, top_why = sensitive[0]
            lines = [f"{e.name}: {why.label} ({why.severity}) -- {why.reason}; {_fetch_summary(e, g)}"
                     for e, g, why in sensitive]
            return self._result(
                finding, "confirmed",
                f"Directory listing {exchange.url} serves {len(sensitive)} sensitive file(s) to this "
                f"caller: " + ", ".join(f"{e.name} ({why.label})" for e, _g, why in sensitive[:6]),
                confirmed=True, severity=top_why.severity,
                evidence="; ".join(lines + notes + [control_note]) + "; file values redacted",
            ).with_artifacts(baseline=baseline, attack=top_got, controls=[control])
        fetched = [g for _e, g in survey["fetched"]]
        attack = next((g for _e, g in harmless), fetched[0] if fetched else None)
        if survey["refused_run"] and not_fetched:
            return self._result(finding, "inconclusive",
                                f"listing check incomplete: {not_fetched} of {total} listed file(s) "
                                f"were not fetched ({survey['refused_run']}); not a negative result",
                                evidence="; ".join(notes + [control_note]),
                                ).with_artifacts(baseline=baseline, attack=attack, controls=[control])
        if not fetched:
            return self._result(finding, "inconclusive",
                                "no listed file could be sent; not a negative result",
                                evidence="; ".join(notes + [control_note]))
        return self._result(
            finding, "not_confirmed",
            f"Directory listing {exchange.url}: {len(fetched)} listed file(s) fetched, none sensitive",
            confidence=0.9, evidence="; ".join(notes + [control_note]),
        ).with_artifacts(baseline=baseline, attack=attack, controls=[control])


def _as_exchange(url: str, outcome):
    from harness.models import HttpExchange
    return HttpExchange(url=url, method="GET", response_status=outcome.status,
                        response_headers=dict(outcome.headers or {}), response_body=outcome.body or "")


def _bypass_url(entry: ListedEntry, encoding: str, allowed_ext: str) -> str:
    parts = urlsplit(entry.url)
    return urlunsplit((parts.scheme, parts.netloc, parts.path + encoding + allowed_ext, "", ""))


class FilterBypassValidator(_ListingLeg):
    """A listed file refused for its extension, fetched through a NUL encoding."""

    name = "filter_bypass_validator"
    capability = "filter_bypass"
    finding_classes = {"path_filter_bypass", "filter_bypass", "extension_filter_bypass",
                       "improper_input_validation", "null_byte_injection", "poison_null_byte",
                       "potential_directory_traversal"}

    def applies(self, finding, exchange) -> bool:
        if not parse_listing(exchange):
            return False
        raw, _canonical = _class_tokens(finding)
        return super().applies(finding, exchange) or any(
            t in raw for t in ("bypass", "null_byte", "null byte", "poison", "input_validation",
                               "extension_filter", "file_filter"))

    async def validate(self, finding, exchange) -> ValidationResult:
        early = self._precheck(finding, exchange)
        if early is not None:
            return early
        entries = parse_listing(exchange)
        if not entries:
            return self._result(finding, "skipped", "not_a_listing: the capture is not a directory listing")
        survey = await self._survey(finding, exchange, entries)
        baseline_listing, control = survey["baseline"], survey["control"]
        if baseline_listing is None:
            return self._result(finding, "skipped", f"listing re-fetch declined: {survey['refused_run']}")
        if not baseline_listing.ok:
            return self._result(finding, "inconclusive",
                                f"the listing re-fetch got no answer ({self._refusal(baseline_listing)}); "
                                f"not a negative result")
        served = [(e, g) for e, g in survey["fetched"] if self._served(g, control)]
        refused = [(e, g) for e, g in survey["fetched"] if g.status in _REFUSED_STATUSES]
        if not refused:
            return self._result(finding, "not_confirmed",
                                f"no listed file is refused by the server ({len(served)} served); "
                                f"there is no file filter to bypass", confidence=0.9,
                                ).with_artifacts(baseline=baseline_listing, attack=baseline_listing,
                                                 controls=[control])
        calibration = next(((e, g) for e, g in served if _extension(e.name)), None)
        if calibration is None:
            return self._result(finding, "inconclusive",
                                f"{len(refused)} listed file(s) refused, but no listed file with an "
                                f"extension is served, so no allowed extension is known to calibrate "
                                f"the bypass; not a negative result")
        cal_entry, cal_got = calibration
        allowed_ext = _extension(cal_entry.name)
        session_ref, headers = survey["session"]
        absent = ListedEntry(_absent_name(exchange.url, ".bak"), survey["directory"] + _absent_name(exchange.url, ".bak"))
        tried, unsent = [], []
        targets = [(e, g) for e, g in refused if _extension(e.name).lower() != allowed_ext.lower()][:MAX_BYPASS_TARGETS]
        for encoding in NUL_ENCODINGS:
            cal = await self._get(finding, _bypass_url(cal_entry, encoding, allowed_ext), headers, session_ref)
            if not cal.executed:
                unsent.append(f"{encoding}: {self._refusal(cal)}")
                continue
            neg = await self._get(finding, _bypass_url(absent, encoding, allowed_ext), headers, session_ref)
            calibrated = cal.ok and _is_2xx(cal.status) and cal.body == cal_got.body
            bypassed = []
            for entry, direct in targets:
                attempt = await self._get(finding, _bypass_url(entry, encoding, allowed_ext), headers, session_ref)
                if not attempt.executed:
                    unsent.append(f"{entry.name}{encoding}{allowed_ext}: {self._refusal(attempt)}")
                    continue
                body = attempt.body or ""
                distinct = (attempt.ok and _is_2xx(attempt.status) and body.strip()
                            and body != (direct.body or "") and body != cal_got.body
                            and not (neg.executed and _is_2xx(neg.status) and neg.body == body)
                            and not _is_html(body))
                # A listed size is compared only for a text body: a decoded binary body
                # does not re-encode to its wire length.
                size_ok = (entry.size is None or not body.isascii()
                           or entry.size == len(body.encode("ascii")))
                tried.append((encoding, entry, direct, attempt, bool(distinct and size_ok)))
                if distinct and size_ok:
                    bypassed.append((entry, direct, attempt))
            # The nonexistent name must not come back as one of the bypassed files
            # (`distinct` above already compares each body with it).
            negative_held = neg.ok
            if calibrated and negative_held and bypassed:
                entry, direct, attempt = bypassed[0]
                kinds = [classify_listed_file(e.name, a.status, a.headers, a.body or "") for e, _d, a in bypassed]
                severity = max((k.severity for k in kinds if k), key=lambda s: _SEVERITY_RANK[s], default="medium")
                if _SEVERITY_RANK[severity] < _SEVERITY_RANK["medium"]:
                    severity = "medium"
                lines = [f"{e.name}: direct GET HTTP {d.status}; {e.name}{encoding}{allowed_ext} "
                         f"HTTP {a.status}, {len((a.body or '').encode('utf-8', errors='replace'))} bytes, "
                         f"sha256 {_sha(a.body)}" + (f" ({k.label})" if k else "")
                         for (e, d, a), k in zip(bypassed, kinds)]
                return self._result(
                    finding, "confirmed",
                    f"File filter bypass: the server refuses {entry.name} by extension but serves it as "
                    f"{entry.name}{encoding}{allowed_ext} (NUL-byte encoding before an allowed extension)",
                    confirmed=True, severity=severity,
                    evidence="; ".join(lines + [
                        f"positive control: {cal_entry.name}{encoding}{allowed_ext} returned the exact "
                        f"bytes of {cal_entry.name} (sha256 {_sha(cal_got.body)})",
                        f"negative control: {absent.name}{encoding}{allowed_ext} answered HTTP {neg.status}",
                        "file values redacted"]),
                ).with_artifacts(baseline=direct, attack=attempt, controls=[neg, cal])
        if not tried and unsent:
            return self._result(finding, "skipped",
                                f"filter-bypass probes could not be sent ({unsent[0]})")
        first = next(iter(tried), None)
        detail = (f"{len(targets)} refused listed file(s) tried with {', '.join(NUL_ENCODINGS)} before "
                  f"{allowed_ext}; " + "; ".join(f"{e.name}{enc}{allowed_ext}: HTTP {a.status}"
                                                  for enc, e, _d, a, _ok in tried[:6]))
        if unsent:
            detail += f"; {len(unsent)} probe(s) unsent ({unsent[0]})"
        result = self._result(finding, "not_confirmed",
                              f"The file filter held: no NUL encoding returned a refused listed file "
                              f"with a calibrated positive control", confidence=0.9, evidence=detail)
        if first is not None:
            _enc, _e, direct, attempt, _ok = first
            result.with_artifacts(baseline=direct, attack=attempt, controls=[control])
        return result


def _metrics_class_matches(finding) -> bool:
    raw, canonical = _class_tokens(finding)
    return (any(t in raw for t in ("metric", "prometheus", "monitoring", "telemetry", "exposure",
                                   "exposed", "disclosure", "unauthenticated", "endpoint"))
            or canonical in {"info_disclosure", "misconfig", "recon", "auth"})


class MetricsExposureValidator(_GetLeg):
    """A metrics exposition that answers without credentials."""

    name = "metrics_exposure_validator"
    capability = "metrics_exposure"
    finding_classes = {"exposed_metrics_endpoint", "public_metrics_endpoint", "metrics_exposure",
                       "unauthenticated_metrics", "information_disclosure", "info_disclosure"}

    def applies(self, finding, exchange) -> bool:
        if exchange is None or not _is_get(exchange) or not is_metrics_exposition(
                exchange.response_status, exchange.response_headers, exchange.response_body or ""):
            return False
        return super().applies(finding, exchange) or _metrics_class_matches(finding)

    async def validate(self, finding, exchange) -> ValidationResult:
        early = self._precheck(finding, exchange)
        if early is not None:
            return early
        if not _is_get(exchange) or not is_metrics_exposition(
                exchange.response_status, exchange.response_headers, exchange.response_body or ""):
            return self._result(finding, "skipped", "not_metrics: the capture is not a 2xx GET metrics exposition")
        session_ref, headers = self._captured_identity(exchange)
        baseline = await self._get(finding, exchange.url, headers, session_ref)
        if not baseline.executed:
            return self._result(finding, "skipped", f"metrics replay declined: {self._refusal(baseline)}")
        anonymous = _without_credentials(headers)
        attack = await self._get(finding, exchange.url, anonymous, None)
        parts = urlsplit(exchange.url)
        sibling = urlunsplit((parts.scheme, parts.netloc,
                              parts.path.rstrip("/") + "-" + _absent_name(exchange.url), "", ""))
        control = await self._get(finding, sibling, anonymous, None)
        if not (baseline.ok and attack.ok and control.ok):
            refused = next(o for o in (baseline, attack, control) if not o.ok)
            return self._result(finding, "inconclusive",
                                f"metrics check incomplete: {self._refusal(refused)}; not a negative result")
        if not (attack.ok and is_metrics_exposition(attack.status, attack.headers, attack.body or "")):
            return self._result(
                finding, "not_confirmed",
                f"Without credentials {exchange.url} answered HTTP {attack.status} with no metrics "
                f"exposition: the endpoint is not exposed to anonymous callers", confidence=0.9,
            ).with_artifacts(baseline=baseline, attack=attack, controls=[control])
        if is_metrics_exposition(control.status, control.headers, control.body or ""):
            return self._result(
                finding, "inconclusive",
                f"a nonexistent sibling path also answers with a metrics exposition (HTTP {control.status}); "
                f"the route cannot be told apart; not a negative result",
            ).with_artifacts(baseline=baseline, attack=attack, controls=[control])
        summary = summarize_metrics(attack.body or "")
        families = summary["families"]
        reveals = [f"{summary['family_count']} metric families"
                   + (f" (prefixes: {', '.join(summary['prefixes'][:12])})" if summary["prefixes"] else "")]
        if summary["label_keys"]:
            reveals.append("label keys: " + ", ".join(summary["label_keys"][:20]))
        if summary["versions"]:
            reveals.append("build/version labels: " + ", ".join(f"{k}={v}" for k, v in summary["versions"].items()))
        reveals.append("families: " + ", ".join(families[:25]) + (" ..." if len(families) > 25 else ""))
        return self._result(
            finding, "confirmed",
            f"Metrics endpoint {exchange.url} is exposed without authentication: a credential-free GET "
            f"returns the exposition ({summary['family_count']} metric families)",
            confirmed=True, severity="medium",
            evidence="; ".join(reveals + [
                f"credential-free GET HTTP {attack.status}",
                f"nonexistent sibling control {sibling} answered HTTP {control.status} with no exposition",
                "sample values not recorded"]),
        ).with_artifacts(baseline=baseline, attack=attack, controls=[control])


# --------------------------------------------------------------------------- #
# A sensitive file captured on its own (not through a listing)
# --------------------------------------------------------------------------- #

def direct_file_sensitivity(exchange) -> tuple[str, Sensitivity] | None:
    """(file name, why it is sensitive) when the capture is a 2xx GET of one file.
    The last path segment must name a file, and the capture must not be a listing.
    Otherwise None."""
    if exchange is None or not _is_get(exchange):
        return None
    path = urlsplit(exchange.url).path or "/"
    if path.endswith("/"):
        return None
    leaf = unquote(path.rsplit("/", 1)[-1])
    low = leaf.lower()
    if not leaf or not (_HAS_EXTENSION.search(leaf) or low in _KEY_NAMES or low in _MANIFEST_NAMES):
        return None
    if parse_listing(exchange):
        return None
    found = classify_listed_file(leaf, exchange.response_status, exchange.response_headers,
                                 exchange.response_body or "")
    return (leaf, found) if found else None


def _sensitive_file_class_matches(finding) -> bool:
    raw, canonical = _class_tokens(finding)
    tokens = ("exposure", "exposed", "disclosure", "sensitive", "backup", "confidential", "leak",
              "file", "credential", "secret", "config", "dump", "manifest", "discovery")
    return any(t in raw for t in tokens) or canonical in {"info_disclosure", "misconfig", "recon"}


class SensitiveFileValidator(_GetLeg):
    """A sensitive file, captured on its own, that is served without credentials."""

    name = "sensitive_file_validator"
    capability = "sensitive_file"
    finding_classes = {"sensitive_file_exposure", "backup_file_exposure", "exposed_backup_file",
                       "exposed_file", "confidential_document_exposure", "credential_exposure",
                       "config_file_exposure", "exposed_configuration", "information_disclosure",
                       "info_disclosure"}

    def applies(self, finding, exchange) -> bool:
        return direct_file_sensitivity(exchange) is not None and (
            super().applies(finding, exchange) or _sensitive_file_class_matches(finding))

    async def validate(self, finding, exchange) -> ValidationResult:
        early = self._precheck(finding, exchange)
        if early is not None:
            return early
        found = direct_file_sensitivity(exchange)
        if found is None:
            return self._result(finding, "skipped",
                                "not_a_sensitive_file: the capture is not a 2xx GET of a sensitive file")
        name, _captured = found
        session_ref, headers = self._captured_identity(exchange)
        baseline = await self._get(finding, exchange.url, headers, session_ref)
        if not baseline.executed:
            return self._result(finding, "skipped", f"file replay declined: {self._refusal(baseline)}")
        anonymous = _without_credentials(headers)
        attack = await self._get(finding, exchange.url, anonymous, None)
        parts = urlsplit(exchange.url)
        directory = parts.path.rsplit("/", 1)[0] + "/"
        sibling = urlunsplit((parts.scheme, parts.netloc,
                              directory + _absent_name(exchange.url, _extension(name)), "", ""))
        control = await self._get(finding, sibling, anonymous, None)
        if not (baseline.ok and attack.ok and control.ok):
            refused = next(o for o in (baseline, attack, control) if not o.ok)
            return self._result(finding, "inconclusive",
                                f"file check incomplete: {self._refusal(refused)}; not a negative result")
        artifacts = dict(baseline=baseline, attack=attack, controls=[control])
        served = classify_listed_file(name, attack.status, attack.headers, attack.body or "")
        if served is None:
            authed = classify_listed_file(name, baseline.status, baseline.headers, baseline.body or "")
            why = ("it is served only with the captured credential" if authed and session_ref
                   else "it is no longer served as a sensitive file")
            return self._result(
                finding, "not_confirmed",
                f"Without credentials {exchange.url} answered HTTP {attack.status}: {why}",
                confidence=0.9).with_artifacts(**artifacts)
        if _is_2xx(control.status) and (control.body or "") and (
                control.body == attack.body
                or classify_listed_file(name, control.status, control.headers, control.body or "")):
            return self._result(
                finding, "inconclusive",
                f"a nonexistent sibling {sibling} is served the same way (HTTP {control.status}); the "
                f"file cannot be told apart from a catch-all; not a negative result",
            ).with_artifacts(**artifacts)
        size = len((attack.body or "").encode("utf-8", errors="replace"))
        return self._result(
            finding, "confirmed",
            f"Sensitive file {exchange.url} is served without authentication: {served.label} "
            f"({served.reason})",
            confirmed=True, severity=served.severity,
            evidence="; ".join([
                f"{name}: {served.label} ({served.severity}) -- {served.reason}",
                f"credential-free GET HTTP {attack.status}, {size} bytes, sha256 {_sha(attack.body or '')}",
                f"nonexistent sibling control answered HTTP {control.status}",
                "file values redacted"]),
        ).with_artifacts(**artifacts)


# Once per (run, origin): the origin's .well-known result.
_WELL_KNOWN_SEEN: dict[tuple, ValidationResult] = {}
_WELL_KNOWN_SEEN_LIMIT = 256


class WellKnownValidator(_GetLeg):
    """security.txt and CSAF provider metadata, once per origin, as observations."""

    name = "well_known_validator"
    capability = "well_known"
    finding_classes = {"security_txt", "security.txt", "well_known", "csaf", "csaf_provider_metadata"}

    def applies(self, finding, exchange) -> bool:
        raw, _canonical = _class_tokens(finding)
        path = urlsplit(getattr(exchange, "url", "") or "").path.lower()
        return (super().applies(finding, exchange)
                or any(t in raw for t in ("security.txt", "security_txt", "well-known", "well_known", "csaf"))
                or path.startswith("/.well-known/"))

    def claims_class(self, finding, exchange=None) -> bool:
        """R11-1: the class half of applies(); the /.well-known/ path alone routes a
        finding here but its observation is never that finding's proof."""
        raw, _canonical = _class_tokens(finding)
        return (Validator.applies(self, finding, exchange)
                or any(t in raw for t in ("security.txt", "security_txt", "well-known", "well_known", "csaf")))

    async def validate(self, finding, exchange) -> ValidationResult:
        early = self._precheck(finding, exchange)
        if early is not None:
            return early
        origin = _origin(exchange.url)
        run_key = getattr(self.run_context, "run_id", "") or id(self.run_context)
        key = (run_key, origin)
        if key in _WELL_KNOWN_SEEN:
            from dataclasses import replace
            prior = _WELL_KNOWN_SEEN[key]
            return replace(prior, finding_class=finding.vulnerability_class,
                           summary=prior.summary + " (probed once per origin; this result is reused)")
        security_url = origin + "/.well-known/security.txt"
        csaf_url = origin + "/.well-known/csaf/provider-metadata.json"
        baseline = await self._get(finding, security_url, {}, None)
        if not baseline.executed:
            return self._result(finding, "skipped", f".well-known probe declined: {self._refusal(baseline)}")
        security = parse_security_txt(baseline.status, baseline.headers, baseline.body or "")
        named = [u for u in (security or {}).get("fields", {}).get("csaf", [])
                 if _origin(u) == origin and u != csaf_url][:1]
        attack = await self._get(finding, named[0] if named else csaf_url, {}, None)
        csaf = parse_csaf_metadata(attack.status, attack.body or "")
        control_url = origin + "/.well-known/" + _absent_name(origin, ".txt")
        control = await self._get(finding, control_url, {}, None)
        if not (baseline.ok and attack.ok and control.ok):
            refused = next(o for o in (baseline, attack, control) if not o.ok)
            return self._result(finding, "inconclusive",
                                f".well-known probe incomplete: {self._refusal(refused)}; "
                                f"not a negative result")
        if parse_security_txt(control.status, control.headers, control.body or ""):
            result = self._result(finding, "inconclusive",
                                  "a nonexistent .well-known path also answers with security.txt fields; "
                                  "the files cannot be told apart from a catch-all")
        elif security or csaf:
            notes = []
            if security:
                fields = security["fields"]
                notes.append(f"security.txt at {security_url}: "
                             + ", ".join(f"{name.title()}: {' | '.join(values[:2])}"
                                         for name, values in fields.items())
                             + ("; PGP-signed" if security["signed"] else "; not signed")
                             + ("; EXPIRED" if security["expired"] else "")
                             + ("" if fields.get("expires") else "; no Expires field (required by RFC 9116)"))
            else:
                notes.append(f"no security.txt at {security_url} (HTTP {baseline.status})")
            if csaf:
                notes.append(f"CSAF provider metadata at {attack.final_url or (named[0] if named else csaf_url)}: "
                             f"publisher {csaf['publisher']!r}, role {csaf['role']!r}, "
                             f"metadata_version {csaf['metadata_version']!r}, "
                             f"{csaf['distributions']} distribution(s)")
            else:
                notes.append(f"no CSAF provider metadata (HTTP {attack.status})")
            published = " and ".join(n for n, ok in (("security.txt", security), ("CSAF provider metadata", csaf)) if ok)
            result = self._result(
                finding, "confirmed",
                f"Observation (not a vulnerability): {origin} publishes {published}",
                confirmed=True, severity="info", evidence="; ".join(notes),
                observation=True, mechanism_classes=("security_txt" if security else "csaf",),
            ).with_artifacts(baseline=baseline, attack=attack, controls=[control])
        else:
            result = self._result(
                finding, "not_confirmed",
                f"{origin} publishes no security.txt (HTTP {baseline.status}) and no CSAF provider "
                f"metadata (HTTP {attack.status})", confidence=0.9,
            ).with_artifacts(baseline=baseline, attack=attack, controls=[control])
        if len(_WELL_KNOWN_SEEN) >= _WELL_KNOWN_SEEN_LIMIT:
            _WELL_KNOWN_SEEN.clear()
        _WELL_KNOWN_SEEN[key] = result
        return result
