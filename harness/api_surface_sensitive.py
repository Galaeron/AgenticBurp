"""WL-05 sensitive-file content signatures: which artifact class a path is, whether a 2xx body
carries that class's structure, the verdict and the finding it becomes.

Part of the ARC-9 split of harness.api_surface_discovery. Import these names from
harness.api_surface_discovery, the facade, not from this module.
"""
from __future__ import annotations

import json
import re
from typing import NamedTuple
from urllib.parse import urlsplit


# ---------------------------------------------------------------------------
# WL-05 (E39): sensitive-file content signatures.
#
# A status code alone never proves a sensitive file is exposed: a redirect to a
# login page, a catch-all HTML shell, an empty 200 or an error page all answer
# 2xx/3xx at /.env. A hit is CONFIRMED only when a 2xx body carries the structure
# specific to its artifact class. The classes below are derived from
# DEFAULT_SENSITIVE_FILES. Entries with no specific structure (config.json/.yaml/
# .yml, secrets.json, .gitignore, .well-known/security.txt) are never confirmed
# by this probe: they stay existence-only candidates for content review.
# Evidence names the class and counts lines; it never quotes a value.
# ---------------------------------------------------------------------------

_SIG_SCAN = 65536  # characters of body any signature looks at

# Exact relative paths (lowercased) first, then basenames.
_SENSITIVE_CLASS_BY_PATH = {
    ".git/config": "git_config", ".git/head": "git_head", ".svn/entries": "svn_entries",
    ".aws/credentials": "aws_credentials",
}
_SENSITIVE_CLASS_BY_NAME = {
    "application.properties": "java_properties", "id_rsa": "private_key",
    ".htpasswd": "htpasswd", ".htaccess": "htaccess", ".npmrc": "npmrc", ".pypirc": "pypirc",
    "web.config": "web_config", ".ds_store": "ds_store",
    "phpinfo.php": "phpinfo", "info.php": "phpinfo", "server-status": "server_status",
    "package.json": "npm_manifest", "composer.json": "composer_manifest",
    "composer.lock": "composer_lock", "requirements.txt": "pip_requirements",
    "dockerfile": "dockerfile", "docker-compose.yml": "compose_file",
    "docker-compose.yaml": "compose_file", "settings.py": "django_settings",
    "credentials.json": "cloud_credentials_json", "appsettings.json": "dotnet_appsettings",
}
_SENSITIVE_CLASS_BY_SUFFIX = (
    (".sql", "sql_dump"), (".sqlite", "sqlite_db"), (".sqlite3", "sqlite_db"),
    (".zip", "zip_archive"), (".tar.gz", "gzip_archive"), (".tgz", "gzip_archive"),
    (".log", "log_file"),
)
# Classes whose genuine artifact IS an HTML page (so an HTML body is not a veto).
_HTML_ARTIFACT_CLASSES = frozenset({"phpinfo", "server_status", "directory_listing"})


def sensitive_artifact_class(path: str) -> str | None:
    """The artifact class a sensitive-file path names, or None when the wordlist
    entry has no content signature specific enough to confirm it."""
    rel = (path or "").split("?", 1)[0].split("#", 1)[0].lstrip("/")
    if not rel:
        return None
    if rel.endswith("/"):
        return "directory_listing"
    low = rel.lower()
    name = low.rsplit("/", 1)[-1]
    if low in _SENSITIVE_CLASS_BY_PATH:
        return _SENSITIVE_CLASS_BY_PATH[low]
    if name == ".env" or name.startswith(".env."):
        return "dotenv"
    if name in _SENSITIVE_CLASS_BY_NAME:
        return _SENSITIVE_CLASS_BY_NAME[name]
    for suffix, cls in _SENSITIVE_CLASS_BY_SUFFIX:
        if name.endswith(suffix):
            return cls
    return None


def _content_lines(body: str, comments=("#",)) -> list[str]:
    lines = (ln.strip() for ln in body[:_SIG_SCAN].splitlines())
    return [ln for ln in lines if ln and not ln.startswith(comments)]


def _matching_lines(lines: list[str], rx, min_ratio: float = 0.8, min_count: int = 1) -> int:
    """How many lines fully match rx; 0 unless there are at least min_count of
    them and they are at least min_ratio of all lines."""
    n = sum(1 for ln in lines if rx.fullmatch(ln))
    return n if lines and n >= max(1, min_count) and n >= min_ratio * len(lines) else 0


def _json_object(body: str) -> dict | None:
    try:
        doc = json.loads(body)
    except (ValueError, TypeError):
        return None
    return doc if isinstance(doc, dict) else None


_DOTENV_LINE = re.compile(r"(?:export\s+)?[A-Za-z_][A-Za-z0-9_]*\s*=.*")
_PROPERTIES_LINE = re.compile(r"[A-Za-z_][\w.\-]*\s*[=:].*")
_GIT_HEAD = re.compile(r"\s*(?:ref:\s*refs/[\w./-]+|[0-9a-f]{40}|[0-9a-f]{64})\s*")
_SQL_DUMP_HEADER = re.compile(
    r"^\s*--\s*(?:MySQL dump|MariaDB dump|PostgreSQL database dump|phpMyAdmin SQL Dump)",
    re.M | re.I)
_SQL_STATEMENT = re.compile(
    r"^\s*(?:CREATE\s+TABLE|INSERT\s+INTO|DROP\s+TABLE|ALTER\s+TABLE|CREATE\s+DATABASE"
    r"|LOCK\s+TABLES|COPY\s+[\w.\"]+\s*\([^)\n]*\)\s+FROM\s+stdin)\b", re.M | re.I)
_PRIVATE_KEY = re.compile(r"-----BEGIN (?:RSA |DSA |EC |OPENSSH |ENCRYPTED )?PRIVATE KEY-----")
_INI_SECTION = re.compile(r"^\s*\[[^\]\n]+\]\s*$", re.M)
_HTPASSWD_LINE = re.compile(r"[^:\s#]+:(?:\$apr1\$\S+|\$2[abxy]?\$\S+|\{SHA\}\S+|\$[156]\$\S+"
                            r"|[./0-9A-Za-z]{13})")
_HTACCESS_DIRECTIVES = frozenset((
    "rewriteengine rewriterule rewritecond rewritebase options directoryindex errordocument "
    "authtype authname authuserfile authgroupfile require order deny allow satisfy header "
    "setenv setenvif redirect redirectmatch addtype addhandler adddefaultcharset php_value "
    "php_flag expiresactive expiresbytype fileetag <ifmodule </ifmodule <files </files "
    "<filesmatch </filesmatch <limit </limit"
).split())
_NPMRC_LINE = re.compile(r"[^\s=<>\[\]]+\s*=\s*\S.*")
_NPMRC_KEYS = frozenset(("registry", "always-auth", "email", "strict-ssl", "save-exact",
                         "engine-strict", "package-lock", "_auth", "_authtoken", "_password"))
_REQ_LINE = re.compile(
    r"-[rcei]\s+\S+|--[\w-]+(?:[ =]\S+)?"
    r"|[A-Za-z0-9][A-Za-z0-9._-]*(?:\[[\w,.\s-]*\])?\s*"
    r"(?:(?:===|==|>=|<=|~=|!=|>|<)\s*[\w.*+!-]+(?:\s*,\s*(?:==|>=|<=|~=|!=|>|<)\s*[\w.*+!-]+)*)?"
    r"\s*(?:;.*)?")
_REQ_PIN = re.compile(r"===|==|>=|<=|~=|!=")
_DJANGO_SETTING = re.compile(
    r"^(SECRET_KEY|INSTALLED_APPS|DATABASES|ALLOWED_HOSTS|MIDDLEWARE|ROOT_URLCONF)\s*=", re.M)
_LOG_LINE = re.compile(
    r"\[?\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}"                     # ISO-8601 timestamp
    r"|\[\w{3} \w{3} [ \d]?\d \d{2}:\d{2}:\d{2}"               # Apache error log
    r"|\S+ \S+ \S+ \[\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2}"      # common/combined log
    r"|\w{3} [ \d]\d \d{2}:\d{2}:\d{2} ")                      # syslog


def _dotenv_has_credentials(body: str) -> bool:
    """Classify credential assignments without retaining values in evidence."""
    for line in _content_lines(body):
        if not _DOTENV_LINE.fullmatch(line):
            continue
        name, value = line.split("=", 1)
        name = re.sub(r"^export\s+", "", name).strip()
        value = value.strip()
        if value.startswith(("'", '"')):
            end = value.find(value[0], 1)
            value = value[1:end] if end >= 1 else ""
        else:
            value = value.split("#", 1)[0]
        if not value.strip():
            continue
        if re.search(r"PASSWORD|PASSWD|SECRET|TOKEN|API_KEY|ACCESS_KEY|PRIVATE_KEY", name, re.I):
            return True
        # Connection URLs can hold credentials even without a secret-named key.
        if "URL" in name.upper() or "DSN" in name.upper():
            try:
                if urlsplit(value).password:
                    return True
            except ValueError:
                pass
    return False


def _sig_dotenv(body):
    # Two or more assignments: a lone "status=ok" line is not a dotenv file.
    n = _matching_lines(_content_lines(body), _DOTENV_LINE, min_count=2)
    return f"{n} KEY=VALUE assignments" if n else None


def _sig_java_properties(body):
    lines = _content_lines(body, ("#", "!"))
    n = _matching_lines(lines, _PROPERTIES_LINE, min_count=2)
    if n and any("." in re.split(r"\s*[=:]", ln, maxsplit=1)[0] for ln in lines):
        return f"{n} dotted key=value propert(ies)"
    return None


def _sig_git_config(body):
    head = body[:_SIG_SCAN]
    if (re.search(r"^\s*\[core\]\s*$", head, re.M)
            and re.search(r"^\s*repositoryformatversion\s*=", head, re.M)):
        return "a [core] section with repositoryformatversion"
    return None


def _sig_git_head(body):
    return "a ref or object id" if len(body) <= 300 and _GIT_HEAD.fullmatch(body) else None


def _sig_svn_entries(body):
    lines = [ln.strip() for ln in body[:4000].splitlines()[:6]]
    if lines and lines[0].isdigit() and "dir" in lines[1:]:
        return "an entries format number followed by a dir record"
    return "a wc-entries document" if "<wc-entries" in body[:4000] else None


def _sig_sql_dump(body):
    if _SQL_DUMP_HEADER.search(body[:4000]):
        return "a SQL dump header comment"
    n = len(_SQL_STATEMENT.findall(body[:_SIG_SCAN]))
    return f"{n} DDL/DML statement(s) at line start" if n else None


def _sig_sqlite_db(body):
    return "the SQLite 3 database header" if body.startswith("SQLite format 3\x00") else None


def _sig_zip_archive(body):
    return "a ZIP archive header" if body.startswith(("PK\x03\x04", "PK\x05\x06")) else None


def _sig_gzip_archive(body):
    # Bodies arrive decoded as text: 0x8b survives as itself (latin-1) or U+FFFD (utf-8).
    return "a gzip member header" if body[:3] in ("\x1f\x8b\x08", "\x1f�\x08") else None


def _sig_private_key(body):
    return "a PEM private-key header" if _PRIVATE_KEY.search(body[:4000]) else None


def _sig_aws_credentials(body):
    head = body[:_SIG_SCAN]
    if _INI_SECTION.search(head) and re.search(r"^\s*aws_access_key_id\s*=", head, re.M | re.I):
        return "a profile section with aws_access_key_id"
    return None


def _sig_htpasswd(body):
    n = _matching_lines(_content_lines(body), _HTPASSWD_LINE)
    return f"{n} user:hash entr(ies)" if n else None


def _sig_htaccess(body):
    lines = _content_lines(body)
    n = sum(1 for ln in lines if ln.split(None, 1)[0].lower().rstrip(">") in _HTACCESS_DIRECTIVES)
    return f"{n} Apache directive line(s)" if lines and n and n >= 0.8 * len(lines) else None


def _sig_npmrc(body):
    lines = _content_lines(body, ("#", ";"))
    n = _matching_lines(lines, _NPMRC_LINE)
    if not n:
        return None
    keys = [ln.split("=", 1)[0].strip().lower() for ln in lines]
    if any(k in _NPMRC_KEYS or k.endswith((":_authtoken", ":_auth", ":_password", ":registry"))
           for k in keys):
        return f"{n} npm config setting(s)"
    return None


def _sig_pypirc(body):
    head = body[:_SIG_SCAN]
    if (re.search(r"^\s*\[(?:distutils|pypi|testpypi)\]\s*$", head, re.M)
            and re.search(r"^\s*(?:index-servers|repository|username|password)\s*[=:]", head, re.M)):
        return "a distutils/pypi section with repository settings"
    return None


def _sig_web_config(body):
    head = body[:_SIG_SCAN]
    if (re.search(r"<configuration[\s>]", head)
            and re.search(r"<(?:system\.web(?:Server)?|appSettings|connectionStrings)[\s>/]", head)):
        return "an ASP.NET <configuration> document"
    return None


def _sig_ds_store(body):
    return "the .DS_Store Bud1 header" if body.startswith("\x00\x00\x00\x01Bud1") else None


def _sig_phpinfo(body):
    head = body[:_SIG_SCAN]
    return "a phpinfo() page" if "phpinfo()" in head and re.search(r"PHP Version\s*\d", head) else None


def _sig_server_status(body):
    head = body[:_SIG_SCAN]
    if "Apache Server Status for" in head and "Server Version:" in head:
        return "an Apache mod_status page"
    if re.search(r"^Active connections:\s*\d+", head, re.M) and "server accepts handled requests" in head:
        return "an nginx stub_status page"
    return None


def _sig_npm_manifest(body):
    d = _json_object(body)
    if d and isinstance(d.get("name"), str) and any(
            isinstance(d.get(k), dict) for k in ("dependencies", "devDependencies", "scripts")):
        return "an npm manifest (name with dependencies/scripts)"
    return None


def _sig_composer_manifest(body):
    d = _json_object(body)
    if d and any(isinstance(d.get(k), dict) for k in ("require", "require-dev", "autoload")):
        return "a composer manifest (require/autoload)"
    return None


def _sig_composer_lock(body):
    d = _json_object(body)
    if d and isinstance(d.get("packages"), list) and ("content-hash" in d or "_readme" in d):
        return "a composer lock (packages with content-hash)"
    return None


def _sig_pip_requirements(body):
    lines = _content_lines(body)
    n = _matching_lines(lines, _REQ_LINE)
    if n and any(_REQ_PIN.search(ln) for ln in lines):
        return f"{n} requirement line(s) with version specifiers"
    return None


def _sig_dockerfile(body):
    lines = _content_lines(body)
    if (lines and re.match(r"(?:FROM|ARG)\s+\S", lines[0], re.I)
            and any(re.match(r"FROM\s+\S", ln, re.I) for ln in lines)):
        return "a Dockerfile FROM instruction"
    return None


def _sig_compose_file(body):
    head = body[:_SIG_SCAN]
    if re.search(r"^services:\s*$", head, re.M) and re.search(r"^\s+(?:image|build)\s*:", head, re.M):
        return "compose services with image/build"
    return None


def _sig_django_settings(body):
    names = set(_DJANGO_SETTING.findall(body[:_SIG_SCAN]))
    return f"{len(names)} Django settings assignment(s)" if len(names) >= 2 else None


def _sig_cloud_credentials_json(body):
    d = _json_object(body)
    if not d:
        return None
    for k in ("installed", "web"):
        v = d.get(k)
        if isinstance(v, dict) and "client_id" in v and "client_secret" in v:
            return f"an OAuth client secret ({k})"
    if d.get("type") == "service_account" and "private_key" in d:
        return "a service-account key"
    if "client_id" in d and "client_secret" in d:
        return "a client_id with client_secret"
    return None


def _sig_dotnet_appsettings(body):
    d = _json_object(body)
    if d and (isinstance(d.get("ConnectionStrings"), dict) or isinstance(d.get("Kestrel"), dict)
              or (isinstance(d.get("Logging"), dict) and "AllowedHosts" in d)):
        return "ASP.NET appsettings (ConnectionStrings/Kestrel/Logging)"
    return None


def _sig_log_file(body):
    lines = [ln for ln in body[:_SIG_SCAN].splitlines()[:500] if ln.strip()]
    n = sum(1 for ln in lines if _LOG_LINE.match(ln))
    return f"{n} timestamped log line(s)" if n and n >= 0.3 * len(lines) else None


def _sig_directory_listing(body):
    # "listing directory /" is Express serve-index's title (r5: /ftp).
    if re.search(r"<title>\s*(?:Index of /|Directory listing for /|listing directory /)",
                 body[:4000], re.I):
        return "a web-server directory index"
    return None


_SENSITIVE_SIGNATURES = {
    "dotenv": _sig_dotenv, "java_properties": _sig_java_properties,
    "git_config": _sig_git_config, "git_head": _sig_git_head, "svn_entries": _sig_svn_entries,
    "sql_dump": _sig_sql_dump, "sqlite_db": _sig_sqlite_db, "zip_archive": _sig_zip_archive,
    "gzip_archive": _sig_gzip_archive, "private_key": _sig_private_key,
    "aws_credentials": _sig_aws_credentials, "htpasswd": _sig_htpasswd,
    "htaccess": _sig_htaccess, "npmrc": _sig_npmrc, "pypirc": _sig_pypirc,
    "web_config": _sig_web_config, "ds_store": _sig_ds_store, "phpinfo": _sig_phpinfo,
    "server_status": _sig_server_status, "npm_manifest": _sig_npm_manifest,
    "composer_manifest": _sig_composer_manifest, "composer_lock": _sig_composer_lock,
    "pip_requirements": _sig_pip_requirements, "dockerfile": _sig_dockerfile,
    "compose_file": _sig_compose_file, "django_settings": _sig_django_settings,
    "cloud_credentials_json": _sig_cloud_credentials_json,
    "dotnet_appsettings": _sig_dotnet_appsettings, "log_file": _sig_log_file,
    "directory_listing": _sig_directory_listing,
}


def _is_html_document(body: str) -> bool:
    head = (body or "").lstrip("﻿ \t\r\n")[:1024].lower()
    if head.startswith(("<!doctype html", "<html")):
        return True
    return head.startswith("<") and any(
        tag in head for tag in ("<html", "<head", "<body", "<title", "<meta", "<div", "<script"))


class SensitiveFileVerdict(NamedTuple):
    """`structure` is the matched artifact class (None = not confirmed); `outcome`
    is a short code; `reason` is evidence text that never quotes the body."""
    structure: str | None
    outcome: str
    reason: str


def sensitive_file_verdict(path: str, status: int, body: str) -> SensitiveFileVerdict:
    """The single confirmation decision for a sensitive-file hit (WL-05). Only a
    2xx whose body carries its artifact class's content signature confirms."""
    if 300 <= status < 400:
        return SensitiveFileVerdict(None, "redirect", f"HTTP {status} redirect, not the file itself")
    if not 200 <= status < 300:
        return SensitiveFileVerdict(None, "non_success", f"HTTP {status} is not a success response")
    if not (body or "").strip():
        return SensitiveFileVerdict(None, "empty_body", "empty body")
    cls = sensitive_artifact_class(path)
    if cls is None:
        return SensitiveFileVerdict(None, "unknown_type",
                                    "no content signature is defined for this file type")
    if cls not in _HTML_ARTIFACT_CLASSES and _is_html_document(body):
        return SensitiveFileVerdict(None, "html_page",
                                    f"an HTML page, not a {cls} file (catch-all, login or error page)")
    detail = _SENSITIVE_SIGNATURES[cls](body)
    if not detail:
        return SensitiveFileVerdict(None, "signature_mismatch",
                                    f"body does not match the {cls} structure")
    return SensitiveFileVerdict(cls, "content_signature",
                                f"body matches the {cls} structure: {detail}")


def sensitive_file_finding(record: dict) -> dict:
    """The engagement finding for one sensitive-file evidence record. Confirmed
    only when the record says its body matched the artifact's content signature;
    otherwise an existence-only candidate quoting the real status. Never carries
    a value from the file."""
    path = str(record.get("path") or "")
    status = record.get("status")
    status_text = (f"HTTP {status}" if status else
                   "an HTTP redirect" if record.get("redirected_to") else "HTTP status not recorded")
    content_type = record.get("content_type") or "unspecified"
    size = f"{int(record.get('length') or 0)} bytes"
    if record.get("fingerprint"):
        size += f", sha256 {record['fingerprint']}"
    if record.get("confirmed") and record.get("structure"):
        return {"vulnerability_class": "sensitive_file_exposure", "severity": ("high" if record["structure"] == "private_key" or
                    (record["structure"] == "dotenv" and record.get("contains_credentials")) else "medium"),
                "confidence": 0.95,
                "summary": f"Sensitive file exposed: {path} ({record['structure']})",
                "evidence": (f"{status_text} at {path}; "
                             f"{record.get('reason') or 'content signature matched'}; "
                             f"content-type {content_type}; {size}; file values redacted"),
                "confirmed": True, "confirmation_method": "sensitive_file_probe"}
    # Existence-only 2xx responses are low; non-2xx and followed redirects are informational.
    served = isinstance(status, int) and 200 <= status < 300 and not record.get("redirected_to")
    return {"vulnerability_class": "sensitive_file_exposure",
            "severity": "low" if served else "info",
            "confidence": 0.4 if served else 0.2,
            "summary": f"Possible sensitive file (existence only): {path}",
            "evidence": (f"existence only: {status_text} at {path}; "
                         f"{record.get('reason') or 'content not examined'}; "
                         f"content-type {content_type}; {size}; not confirmed -- a status "
                         f"code alone does not prove the file is exposed"),
            "confirmed": False}
