"""
Web-application security tool catalog + recommendation -- A3.

Two things this gives the harness:

  1. A structured CATALOG of the external tools a web-app assessment actually
     reaches for -- content discovery, parameter mining, injection, recon, and
     so on. ffuf is one entry, not the feature: the catalog covers the standard
     toolset a methodology like HackTricks or the PortSwigger Web Security
     Academy would point you at, each tagged with the vulnerability classes and
     situations it applies to. (Tool names and one-line purposes only -- facts,
     not any source's prose.)

  2. A RECOMMENDATION path so an agent that hits the edge of what the harness can
     do itself -- "this needs a wordlist fuzzer", "confirming this blind SSRF
     needs an out-of-band listener" -- can hand the tester a concrete next step:
     which tool, why, and a ready-to-run command templated to the finding. The
     harness runs what it safely can in-process (the JS/crawler discovery, the
     validators, sqlmap); everything else it can't or shouldn't run itself, it
     RETURNS to the user instead of pretending it did nothing.

Deterministic and self-contained: the catalog is data, recommend_for() is a
lookup, and the command templates are plain string substitution -- no tool is
ever executed here (that stays the operator's decision), and nothing calls out.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from harness.categories import canonicalize


@dataclass(frozen=True)
class Tool:
    name: str
    category: str            # content_discovery | parameter_discovery | recon | injection | ...
    purpose: str             # one factual line
    url: str                 # project / docs
    # Canonical vulnerability categories this tool helps with (see categories.py);
    # empty for general-purpose discovery/recon tools matched by situation instead.
    vuln_classes: tuple[str, ...] = ()
    # Free situation tags an agent can match on: "content_discovery", "blind",
    # "waf", "oob", "wordlist", "api", "subdomains", ...
    situations: tuple[str, ...] = ()
    # A command template. {url} {host} {origin} {param} are substituted when a
    # recommendation is built; leave a token in if the tester must fill it.
    command: str = ""
    kind: str = "cli"        # cli | burp_extension | service | web

    def to_dict(self) -> dict:
        return {
            "name": self.name, "category": self.category, "purpose": self.purpose,
            "url": self.url, "vuln_classes": list(self.vuln_classes),
            "situations": list(self.situations), "command": self.command, "kind": self.kind,
        }


# The catalog. Grouped by category in source for readability; order within a
# category is roughly "reach for this first" to "situational alternative".
_CATALOG: tuple[Tool, ...] = (
    # --- content / endpoint discovery (the generalized "A3 is not just ffuf") ---
    Tool("ffuf", "content_discovery",
         "Fast web fuzzer for directory/file and virtual-host discovery and parameter fuzzing.",
         "https://github.com/ffuf/ffuf", situations=("content_discovery", "wordlist", "vhost", "fuzzing"),
         command="ffuf -u {origin}/FUZZ -w /path/to/wordlist.txt"),
    Tool("feroxbuster", "content_discovery",
         "Recursive content discovery in Rust; follows discovered directories automatically.",
         "https://github.com/epi052/feroxbuster", situations=("content_discovery", "wordlist", "recursive"),
         command="feroxbuster -u {origin} -w /path/to/wordlist.txt"),
    Tool("dirsearch", "content_discovery",
         "Python path bruteforcer with extension and recursion support.",
         "https://github.com/maurosoria/dirsearch", situations=("content_discovery", "wordlist"),
         command="dirsearch -u {origin} -e php,asp,aspx,jsp,html,js"),
    Tool("gobuster", "content_discovery",
         "Go directory/DNS/vhost bruteforcer.",
         "https://github.com/OJ/gobuster", situations=("content_discovery", "wordlist", "vhost", "subdomains"),
         command="gobuster dir -u {origin} -w /path/to/wordlist.txt"),
    Tool("kiterunner", "content_discovery",
         "API-route discovery using request signatures rather than plain paths -- finds API endpoints wordlists miss.",
         "https://github.com/assetnote/kiterunner", vuln_classes=("api_security",),
         situations=("content_discovery", "api")),

    # --- parameter discovery ---
    Tool("Arjun", "parameter_discovery",
         "Discovers hidden HTTP query/body parameters an endpoint accepts.",
         "https://github.com/s0md3v/Arjun", situations=("parameter_discovery", "hidden_params"),
         command="arjun -u {url}"),
    Tool("Param Miner", "parameter_discovery",
         "Burp extension that finds hidden, unlinked parameters and headers (incl. cache-poisoning inputs).",
         "https://github.com/PortSwigger/param-miner", vuln_classes=("web_cache_poisoning",),
         situations=("parameter_discovery", "hidden_params"), kind="burp_extension"),

    # --- recon / attack surface ---
    Tool("nuclei", "scanning",
         "Template-based vulnerability scanner covering misconfigurations, exposures, and known CVEs.",
         "https://github.com/projectdiscovery/nuclei", vuln_classes=("misconfig", "info_disclosure", "supply_chain"),
         situations=("scanning", "templates"), command="nuclei -u {url}"),
    Tool("nikto", "scanning",
         "Classic web-server scanner for dangerous files, outdated software, and misconfigurations.",
         "https://github.com/sullo/nikto", vuln_classes=("misconfig", "info_disclosure"),
         situations=("scanning",), command="nikto -h {origin}"),
    Tool("httpx", "recon",
         "Fast HTTP prober -- status, titles, tech, TLS -- for triaging a host/endpoint list.",
         "https://github.com/projectdiscovery/httpx", situations=("recon", "triage")),
    Tool("amass", "recon",
         "In-depth subdomain enumeration and attack-surface mapping.",
         "https://github.com/owasp-amass/amass", vuln_classes=("subdomain_takeover",),
         situations=("recon", "subdomains"), command="amass enum -d {host}"),
    Tool("subfinder", "recon",
         "Passive subdomain discovery from public sources.",
         "https://github.com/projectdiscovery/subfinder", vuln_classes=("subdomain_takeover",),
         situations=("recon", "subdomains"), command="subfinder -d {host}"),
    Tool("nmap", "recon",
         "Port/service scanner and script engine for host-level surface.",
         "https://nmap.org/", situations=("recon", "ports"), command="nmap -sV -sC {host}"),

    # --- injection / exploitation ---
    Tool("sqlmap", "injection",
         "Automated SQL injection detection and exploitation (the harness also runs this itself).",
         "https://sqlmap.org/", vuln_classes=("sqli",), situations=("injection", "blind"),
         command="sqlmap -u {url} --batch"),
    Tool("NoSQLMap", "injection",
         "Automated NoSQL injection and MongoDB attack tooling.",
         "https://github.com/codingo/NoSQLMap", vuln_classes=("nosql",), situations=("injection",)),
    Tool("commix", "injection",
         "Automated OS command-injection detection and exploitation.",
         "https://github.com/commixproject/commix", vuln_classes=("command_injection",),
         situations=("injection",), command="commix -u {url}"),
    Tool("tplmap", "injection",
         "Server-side template injection detection and exploitation across engines.",
         "https://github.com/epinna/tplmap", vuln_classes=("ssti",), situations=("injection",),
         command="tplmap -u {url}"),
    Tool("dalfox", "injection",
         "Fast parameter-analysis XSS scanner with DOM verification.",
         "https://github.com/hahwul/dalfox", vuln_classes=("xss",), situations=("injection", "xss"),
         command="dalfox url {url}"),
    Tool("XSStrike", "injection",
         "XSS suite with context analysis, WAF detection, and payload fuzzing.",
         "https://github.com/s0md3v/XSStrike", vuln_classes=("xss",), situations=("injection", "xss", "waf"),
         command="xsstrike -u {url}"),

    # --- specialized confirmation ---
    Tool("interactsh", "oob",
         "Out-of-band interaction server -- the listener that confirms blind SSRF/RCE/XXE via callbacks.",
         "https://github.com/projectdiscovery/interactsh", vuln_classes=("ssrf", "xxe", "command_injection"),
         situations=("oob", "blind")),
    Tool("SSRFmap", "exploitation",
         "Automated SSRF exploitation (internal port scan, cloud metadata, etc.) from a captured request.",
         "https://github.com/swisskyrepo/SSRFmap", vuln_classes=("ssrf",), situations=("exploitation", "ssrf")),
    Tool("jwt_tool", "exploitation",
         "JWT analysis and attacks: alg-none, key confusion, weak-secret cracking, claim tampering.",
         "https://github.com/ticarpi/jwt_tool", vuln_classes=("jwt", "auth"), situations=("exploitation", "jwt"),
         command="jwt_tool {token}"),
    Tool("Corsy", "scanning",
         "Scanner for misconfigured CORS policies (reflected origin, null origin, etc.).",
         "https://github.com/s0md3v/Corsy", vuln_classes=("cors",), situations=("scanning", "cors"),
         command="corsy -u {url}"),
    Tool("testssl.sh", "scanning",
         "TLS/SSL configuration and cipher/vulnerability checker.",
         "https://testssl.sh/", vuln_classes=("crypto",), situations=("scanning", "tls"),
         command="testssl.sh {host}"),
    Tool("tusk / smuggler", "exploitation",
         "HTTP request-smuggling detection (CL.TE / TE.CL desync probing).",
         "https://github.com/defparam/smuggler", vuln_classes=("http_request_smuggling",),
         situations=("exploitation", "desync"), command="smuggler -u {url}"),

    # --- upload / deserialization ---
    Tool("ysoserial", "exploitation",
         "Generates Java deserialization gadget-chain payloads.",
         "https://github.com/frohoff/ysoserial", vuln_classes=("deserialization",), situations=("exploitation",)),
    Tool("fuxploider", "exploitation",
         "Automated file-upload restriction bypass and vulnerability discovery.",
         "https://github.com/almandin/fuxploider", vuln_classes=("file_upload",),
         situations=("exploitation", "upload"), command="fuxploider -u {url}"),
)

_BY_NAME = {t.name.lower(): t for t in _CATALOG}


def all_tools() -> list[Tool]:
    return list(_CATALOG)


def get(name: str) -> Tool | None:
    return _BY_NAME.get((name or "").lower())


def by_category() -> dict[str, list[Tool]]:
    out: dict[str, list[Tool]] = {}
    for t in _CATALOG:
        out.setdefault(t.category, []).append(t)
    return out


def recommend_for(vulnerability_class: str | None = None,
                  situations: list[str] | tuple[str, ...] | None = None,
                  limit: int = 5) -> list[Tool]:
    """Tools relevant to a vulnerability class and/or a set of situation tags,
    ranked by relevance. A tool matches on canonical vuln class (exact) or on
    any shared situation tag; class matches rank above situation-only matches."""
    canon = canonicalize(vulnerability_class) if vulnerability_class else None
    want_sits = {s.lower() for s in (situations or [])}
    scored: list[tuple[int, Tool]] = []
    for t in _CATALOG:
        score = 0
        if canon and canon in t.vuln_classes:
            score += 10
        if want_sits:
            score += len(want_sits & {s.lower() for s in t.situations})
        if score > 0:
            scored.append((score, t))
    scored.sort(key=lambda pair: pair[0], reverse=True)
    return [t for _, t in scored[:limit]]


@dataclass
class ToolRecommendation:
    """A tool the harness is handing back to the tester for a specific finding or
    situation it can't (or shouldn't) run itself."""
    tool: str
    category: str
    reason: str
    command: str
    url: str
    kind: str
    for_finding: str = ""   # the vulnerability_class / situation this is for
    target_url: str = ""

    def to_dict(self) -> dict:
        return {
            "tool": self.tool, "category": self.category, "reason": self.reason,
            "command": self.command, "url": self.url, "kind": self.kind,
            "for_finding": self.for_finding, "target_url": self.target_url,
        }


def _fill_command(tool: Tool, url: str, token: str = "") -> str:
    if not tool.command:
        return ""
    parts = urlsplit(url) if url else None
    origin = f"{parts.scheme}://{parts.netloc}" if parts and parts.scheme else ""
    host = (parts.hostname or "") if parts else ""
    return (tool.command
            .replace("{url}", url or "{url}")
            .replace("{origin}", origin or "{origin}")
            .replace("{host}", host or "{host}")
            .replace("{token}", token or "{token}"))


def recommend_for_finding(vulnerability_class: str, url: str, *,
                          situations: list[str] | None = None, limit: int = 3) -> list[ToolRecommendation]:
    """Build ready-to-hand-back recommendations for one finding: the top tools
    for its class, each with its command templated to the finding's URL."""
    recs: list[ToolRecommendation] = []
    for t in recommend_for(vulnerability_class, situations, limit=limit):
        recs.append(ToolRecommendation(
            tool=t.name, category=t.category,
            reason=f"{t.purpose} (relevant to {vulnerability_class})",
            command=_fill_command(t, url), url=t.url, kind=t.kind,
            for_finding=vulnerability_class, target_url=url))
    return recs


def recommendations_for_findings(findings: list, *, per_class_limit: int = 2,
                                 max_total: int = 12) -> list[ToolRecommendation]:
    """Map a set of findings to tool recommendations, deduplicated by (tool,
    class) and bounded. This is the deterministic "an agent needs a tool ->
    return it to the user" path: given what was found, what should the tester
    reach for to confirm or exploit it. `findings` are objects/dicts with
    vulnerability_class and (source_exchange_url or url)."""
    seen: set[tuple[str, str]] = set()
    out: list[ToolRecommendation] = []
    for f in findings:
        vc = getattr(f, "vulnerability_class", None) if not isinstance(f, dict) else f.get("vulnerability_class")
        url = ""
        if isinstance(f, dict):
            url = f.get("url") or f.get("source_exchange_url") or ""
        else:
            url = getattr(f, "url", "") or getattr(f, "source_exchange_url", "")
        if not vc:
            continue
        for rec in recommend_for_finding(vc, url, limit=per_class_limit):
            key = (rec.tool, rec.for_finding)
            if key in seen:
                continue
            seen.add(key)
            out.append(rec)
            if len(out) >= max_total:
                return out
    return out
