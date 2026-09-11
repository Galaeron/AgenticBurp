from __future__ import annotations
from .base import Validator
from .sqlmap import SqlmapValidator
from .cors_validator import CorsValidator
from .recon_validator import ReconValidator
from .http_request_smuggling_validator import HttpRequestSmugglingValidator
from .web_cache_poisoning_validator import WebCachePoisoningValidator
from .oauth_validator import OAuthValidator
from .subdomain_takeover_validator import SubdomainTakeoverValidator
from .crypto_validator import CryptoValidator
from .csp_validator import CspValidator
from .header_injection_validator import HeaderInjectionValidator
from .api_security_validator import ApiSecurityValidator
from .websocket_validator import WebsocketValidator
from .race_condition_validator import RaceConditionValidator
from .deserialization_validator import DeserializationValidator
from .deserialization_oob_validator import DeserializationOobValidator
from .browser_xss_validator import BrowserXssValidator
from .cross_identity_validator import CrossIdentityValidator
from .jwt_forge_validator import JwtForgeValidator
from .ssrf_validator import SsrfValidator
from .xxe_validator import XxeValidator
from .command_injection_validator import CommandInjectionValidator
from .ssti_validator import SstiValidator
from .path_traversal_validator import PathTraversalValidator
from .open_redirect_validator import OpenRedirectValidator
from .sequence_validator import SequenceValidator
from .auth_sequence_validator import AuthSequenceValidator
from .stored_xss_validator import StoredXssValidator
from .verb_tamper_validator import VerbTamperValidator
from .csrf_validator import CsrfValidator
from .file_upload_validator import FileUploadValidator
from .rate_limit_validator import RateLimitValidator
from .reset_token_validator import ResetTokenValidator
from .dom_xss_validator import DomXssValidator
from .toctou_validator import ToctouValidator
from .verbose_error_validator import VerboseErrorValidator
from safety_gate import get_default_gate, reset_default_gate


class ValidatorRegistry:
    def __init__(self, config: dict):
        cfg = config.get("validators", {})
        self.enabled = bool(cfg.get("enabled", True))
        self.active_enabled = bool(cfg.get("active_enabled", False))
        # Seed the process-wide safety gate from the real config now,
        # before any validator's validate() call can lazily initialize
        # it with defaults. reset_default_gate() first so re-creating a
        # ValidatorRegistry (e.g. in tests, or a config reload) doesn't
        # keep stale gate settings from a previous instantiation.
        reset_default_gate()
        get_default_gate(cfg)
        sqlmap_cfg = cfg.get("sqlmap", {})
        self.validators: dict[str, Validator] = {}
        if sqlmap_cfg.get("enabled", True):
            self.validators["sqlmap"] = SqlmapValidator(
                binary=sqlmap_cfg.get("binary", "sqlmap"),
                timeout_seconds=int(sqlmap_cfg.get("timeout_seconds", 90)),
                level=int(sqlmap_cfg.get("level", 1)),
                risk=int(sqlmap_cfg.get("risk", 1)),
                container_image=sqlmap_cfg.get("container_image"),
            )
        
        # CORS validator
        cors_cfg = cfg.get("cors", {})
        if cors_cfg.get("enabled", True):
            self.validators["cors"] = CorsValidator(
                timeout=float(cors_cfg.get("timeout", 10.0)),
                max_redirects=int(cors_cfg.get("max_redirects", 5)),
            )
        
        # Recon validator
        recon_cfg = cfg.get("recon", {})
        if recon_cfg.get("enabled", True):
            self.validators["recon"] = ReconValidator(
                timeout=float(recon_cfg.get("timeout", 15.0)),
                max_redirects=int(recon_cfg.get("max_redirects", 10)),
                max_depth=int(recon_cfg.get("max_depth", 5)),
            )
        
        # HTTP Request Smuggling validator
        hrs_cfg = cfg.get("http_request_smuggling", {})
        if hrs_cfg.get("enabled", True):
            self.validators["http_request_smuggling"] = HttpRequestSmugglingValidator(
                timeout=float(hrs_cfg.get("timeout", 30.0)),
                max_redirects=int(hrs_cfg.get("max_redirects", 0)),
            )

        # Web Cache Poisoning validator
        cache_cfg = cfg.get("web_cache_poisoning", {})
        if cache_cfg.get("enabled", True):
            self.validators["web_cache_poisoning"] = WebCachePoisoningValidator(
                timeout=float(cache_cfg.get("timeout", 15.0)),
                max_redirects=int(cache_cfg.get("max_redirects", 5)),
            )

        # OAuth / OIDC validator
        oauth_cfg = cfg.get("oauth", {})
        if oauth_cfg.get("enabled", True):
            self.validators["oauth"] = OAuthValidator(
                timeout=float(oauth_cfg.get("timeout", 10.0)),
                max_redirects=int(oauth_cfg.get("max_redirects", 0)),
            )

        # Subdomain Takeover validator
        takeover_cfg = cfg.get("subdomain_takeover", {})
        if takeover_cfg.get("enabled", True):
            self.validators["subdomain_takeover"] = SubdomainTakeoverValidator(
                timeout=float(takeover_cfg.get("timeout", 15.0)),
                max_redirects=int(takeover_cfg.get("max_redirects", 3)),
            )

        # Crypto / TLS validator
        crypto_cfg = cfg.get("crypto", {})
        if crypto_cfg.get("enabled", True):
            self.validators["crypto"] = CryptoValidator(
                timeout=float(crypto_cfg.get("timeout", 10.0)),
            )

        # CSP / Clickjacking validator
        csp_cfg = cfg.get("csp", {})
        if csp_cfg.get("enabled", True):
            self.validators["csp"] = CspValidator(
                timeout=float(csp_cfg.get("timeout", 10.0)),
                max_redirects=int(csp_cfg.get("max_redirects", 5)),
            )

        # Header Injection validator
        header_inj_cfg = cfg.get("header_injection", {})
        if header_inj_cfg.get("enabled", True):
            self.validators["header_injection"] = HeaderInjectionValidator(
                timeout=float(header_inj_cfg.get("timeout", 10.0)),
            )

        # API Security validator
        api_sec_cfg = cfg.get("api_security", {})
        if api_sec_cfg.get("enabled", True):
            self.validators["api_security"] = ApiSecurityValidator(
                timeout=float(api_sec_cfg.get("timeout", 10.0)),
            )

        # WebSocket validator
        websocket_cfg = cfg.get("websocket", {})
        if websocket_cfg.get("enabled", True):
            self.validators["websocket"] = WebsocketValidator(
                timeout=float(websocket_cfg.get("timeout", 10.0)),
            )

        # Race Condition validator
        race_cfg = cfg.get("race_condition", {})
        if race_cfg.get("enabled", True):
            self.validators["race_condition"] = RaceConditionValidator(
                timeout=float(race_cfg.get("timeout", 15.0)),
                burst_size=int(race_cfg.get("burst_size", 12)),
            )

        # Insecure Deserialization validator (passive local inspection, not active)
        deser_cfg = cfg.get("deserialization", {})
        if deser_cfg.get("enabled", True):
            self.validators["deserialization"] = DeserializationValidator()

        _allowed = config.get("server", {}).get("allowed_hosts", [])
        # JWT-forgery leg -- pure Python, forge alg:none/reused-sig and replay to
        # prove the signature isn't verified. Active (sends replays), GET-only.
        jwt_cfg = cfg.get("jwt_forge", {})
        if jwt_cfg.get("enabled", True):
            self.validators["jwt_forge"] = JwtForgeValidator(
                allowed_hosts=_allowed, timeout=float(jwt_cfg.get("timeout", 10.0)))
        # SSRF leg -- OOB via the in-process collaborator (redirect a URL param to
        # a callback and watch for the hit). Active.
        ssrf_cfg = cfg.get("ssrf", {})
        if ssrf_cfg.get("enabled", True):
            self.validators["ssrf"] = SsrfValidator(
                allowed_hosts=_allowed, timeout=float(ssrf_cfg.get("timeout", 10.0)))
        # XXE leg -- OOB via the collaborator (external entity -> callback). Active.
        xxe_cfg = cfg.get("xxe", {})
        if xxe_cfg.get("enabled", True):
            self.validators["xxe"] = XxeValidator(
                allowed_hosts=_allowed, timeout=float(xxe_cfg.get("timeout", 10.0)))
        # Command-injection leg -- OOB via the collaborator (shell payload -> callback).
        # Active; a non-GET replay also needs allow_mutating_replay.
        cmdi_cfg = cfg.get("command_injection", {})
        if cmdi_cfg.get("enabled", True):
            self.validators["command_injection"] = CommandInjectionValidator(
                allowed_hosts=_allowed, timeout=float(cmdi_cfg.get("timeout", 10.0)))
        # SSTI leg -- in-band arithmetic differential (proves template evaluation). Active.
        ssti_cfg = cfg.get("ssti", {})
        if ssti_cfg.get("enabled", True):
            self.validators["ssti"] = SstiValidator(
                allowed_hosts=_allowed, timeout=float(ssti_cfg.get("timeout", 10.0)))
        # Path-traversal leg -- reads a canonical system file via a traversal payload. Active.
        pt_cfg = cfg.get("path_traversal", {})
        if pt_cfg.get("enabled", True):
            self.validators["path_traversal"] = PathTraversalValidator(
                allowed_hosts=_allowed, timeout=float(pt_cfg.get("timeout", 10.0)))
        # Open-redirect leg -- points a redirect param off-origin and checks Location. Active.
        or_cfg = cfg.get("open_redirect", {})
        if or_cfg.get("enabled", True):
            self.validators["open_redirect"] = OpenRedirectValidator(
                allowed_hosts=_allowed, timeout=float(or_cfg.get("timeout", 10.0)))
        # Stateful sequence leg -- write-then-re-read differential (mass-assignment /
        # privilege escalation the single-shot echo check misses). Active; the write
        # is mutating, so it also needs allow_mutating_replay.
        seq_cfg = cfg.get("sequence", {})
        if seq_cfg.get("enabled", True):
            self.validators["sequence"] = SequenceValidator(
                allowed_hosts=_allowed, timeout=float(seq_cfg.get("timeout", 10.0)))
        # Active deserialization leg -- Python-pickle OOB beacon (benign loopback
        # fetch proving code execution). Active; executes code, so self-gated on
        # allow_mutating_replay. Distinct from the passive format-fingerprint
        # "deserialization" validator, which stays registered above.
        deser_oob_cfg = cfg.get("deserialization_oob", {})
        if deser_oob_cfg.get("enabled", True):
            self.validators["deserialization_oob"] = DeserializationOobValidator(
                allowed_hosts=_allowed, timeout=float(deser_oob_cfg.get("timeout", 10.0)))
        # Auth-mechanism legs -- session fixation / weak-password / username enum
        # multi-request flows. Active; POST sends need allow_mutating_replay.
        auth_cfg = cfg.get("auth_sequence", {})
        if auth_cfg.get("enabled", True):
            self.validators["auth_sequence"] = AuthSequenceValidator(
                allowed_hosts=_allowed, timeout=float(auth_cfg.get("timeout", 10.0)))
        # Stored/second-order XSS leg -- plant via a write, confirm on an
        # independent HTML render. Active; mutating plant needs allow_mutating_replay.
        sxss_cfg = cfg.get("stored_xss", {})
        if sxss_cfg.get("enabled", True):
            self.validators["stored_xss"] = StoredXssValidator(
                allowed_hosts=_allowed, timeout=float(sxss_cfg.get("timeout", 10.0)))

        # Verb-tamper leg -- safe subset: read-only method alternates + override
        # headers. Active; does NOT send blind mutating methods (PUT/DELETE).
        vt_cfg = cfg.get("verb_tamper", {})
        if vt_cfg.get("enabled", True):
            self.validators["verb_tamper"] = VerbTamperValidator(
                allowed_hosts=_allowed, timeout=float(vt_cfg.get("timeout", 10.0)),
                try_mutating_methods=bool(vt_cfg.get("try_mutating_methods", False)))
        # CSRF leg -- deterministic property check: replays a state-changing
        # request without the CSRF token and checks SameSite. Active; mutating
        # replay gated by allow_mutating_replay.
        csrf_cfg = cfg.get("csrf", {})
        if csrf_cfg.get("enabled", True):
            self.validators["csrf"] = CsrfValidator(
                allowed_hosts=_allowed, timeout=float(csrf_cfg.get("timeout", 10.0)))
        # File-upload extension bypass -- uploads a benign .html file and checks
        # if it is stored and retrievable. Active; the upload is mutating.
        fu_cfg = cfg.get("file_upload", {})
        if fu_cfg.get("enabled", True):
            self.validators["file_upload"] = FileUploadValidator(
                allowed_hosts=_allowed, timeout=float(fu_cfg.get("timeout", 15.0)))
        # Rate-limit / lockout absence -- replays the captured auth request N times
        # (safe subset: unchanged, valid creds) via authorize_burst and confirms no
        # 429/lockout after min_attempts. Active; gated by max_burst_size + mutating.
        rl_cfg = cfg.get("rate_limit", {})
        if rl_cfg.get("enabled", True):
            self.validators["rate_limit"] = RateLimitValidator(
                allowed_hosts=_allowed, timeout=float(rl_cfg.get("timeout", 10.0)),
                min_attempts=int(rl_cfg.get("min_attempts", 12)))
        # Predictable reset-token -- samples reset tokens and confirms only the
        # unambiguous predictability cases (sequential/timestamp/below-floor/
        # derived). Active; the reset trigger is a mutating POST (allow_mutating_replay).
        rt_cfg = cfg.get("reset_token", {})
        if rt_cfg.get("enabled", True):
            self.validators["reset_token"] = ResetTokenValidator(
                allowed_hosts=_allowed, timeout=float(rt_cfg.get("timeout", 10.0)),
                samples=int(rt_cfg.get("samples", 5)))
        # TOCTOU privilege-escalation race -- concurrent burst of an authority write
        # + baseline/verify re-reads. Active; burst gated by max_burst_size + mutating.
        toctou_cfg = cfg.get("toctou", {})
        if toctou_cfg.get("enabled", True):
            self.validators["toctou"] = ToctouValidator(
                allowed_hosts=_allowed, timeout=float(toctou_cfg.get("timeout", 10.0)),
                burst_size=int(toctou_cfg.get("burst_size", 12)))

        # DOM-based XSS leg -- drives a real browser with the payload in the URL
        # FRAGMENT (never sent to the server), so execution proves a client-side
        # source->sink taint. Same browser seam as browser_xss; active.
        dom_cfg = cfg.get("dom_xss", {})
        if dom_cfg.get("enabled", True):
            self.validators["dom_xss"] = DomXssValidator(
                timeout=float(dom_cfg.get("timeout", 15.0)),
                allowed_hosts=config.get("server", {}).get("allowed_hosts", []),
                wait_ms=int(dom_cfg.get("wait_ms", 1200)),
                max_visits=int(dom_cfg.get("max_visits", 8)),
                cdp_endpoint=dom_cfg.get("cdp_endpoint") or None)

        # Verbose error / stack trace / debug info validator (passive -- no network).
        verbose_cfg = cfg.get("verbose_error", {})
        if verbose_cfg.get("enabled", True):
            self.validators["verbose_error"] = VerboseErrorValidator()

        # Browser-driven XSS validator (A2) -- active: loads candidate URLs in a
        # real headless browser and confirms only on observed script execution.
        # Enabled here just registers it; it still only RUNS when
        # validators.active_enabled is set (active=True) AND a browser engine is
        # installed (else it skips). Scope comes from server.allowed_hosts.
        bxss_cfg = cfg.get("browser_xss", {})
        if bxss_cfg.get("enabled", True):
            self.validators["browser_xss"] = BrowserXssValidator(
                timeout=float(bxss_cfg.get("timeout", 15.0)),
                allowed_hosts=config.get("server", {}).get("allowed_hosts", []),
                wait_ms=int(bxss_cfg.get("wait_ms", 1200)),
                max_visits=int(bxss_cfg.get("max_visits", 8)),
                cdp_endpoint=bxss_cfg.get("cdp_endpoint") or None,
            )

        # Cross-identity (Autorize-style) access-control validator. DEFAULT OFF
        # (opt-in): it sends live requests and needs tester-supplied identities.
        # Registering it only arms it; it still runs only when active_enabled is
        # set (active=True) AND identities are configured for the host.
        # Config + allowed_hosts are stashed so the tester can arm it at run time
        # (Burp "Cross-Identity" panel -> POST /settings) without a restart or a
        # config-file edit -- in-memory only, gone on restart, matching how the
        # identities it needs are supplied (identity_headers.py).
        self._xid_cfg = cfg.get("cross_identity", {})
        self._allowed_hosts = config.get("server", {}).get("allowed_hosts", [])
        if self._xid_cfg.get("enabled", False):
            self.validators["cross_identity"] = self._build_cross_identity()

    def _build_cross_identity(self) -> CrossIdentityValidator:
        return CrossIdentityValidator(
            allowed_hosts=self._allowed_hosts,
            timeout=float(self._xid_cfg.get("timeout", 10.0)),
            max_identities=int(self._xid_cfg.get("max_identities", 3)),
        )

    def set_active_enabled(self, enabled: bool) -> None:
        """Runtime toggle for the active-validator gate (validators.active_enabled).
        In-memory only; never written back to config. Does NOT persist across a
        server restart -- deliberately, like the identities it authorizes."""
        self.active_enabled = bool(enabled)

    def set_cross_identity_enabled(self, enabled: bool) -> None:
        """Arm/disarm the cross-identity validator at run time. Arming lazily
        constructs it from the stashed config; disarming removes it. Still gated
        by active_enabled at dispatch (set_active_enabled) and by tester-supplied
        identities per host -- this only decides whether it is registered at all."""
        if enabled:
            if "cross_identity" not in self.validators:
                self.validators["cross_identity"] = self._build_cross_identity()
        else:
            self.validators.pop("cross_identity", None)

    def cross_identity_enabled(self) -> bool:
        return "cross_identity" in self.validators

    def state(self) -> dict:
        """The live validator-gating state the UI reflects (GET /settings)."""
        return {
            "enabled": self.enabled,
            "active_enabled": self.active_enabled,
            "cross_identity_enabled": self.cross_identity_enabled(),
            "registered": sorted(self.validators.keys()),
        }

    def for_finding(self, finding, exchange):
        if not self.enabled:
            return []
        return [v for v in self.validators.values()
                if v.applies(finding, exchange) and (not v.active or self.active_enabled)]

    def bind_run_context(self, validators, run_context):
        """Return invocation-bound copies without changing for_finding's public seam."""
        # Registry instances are shared by an Orchestrator and may serve concurrent
        # invocations. Bind context on shallow per-dispatch copies, never by mutating
        # the registered singleton validator.
        import copy
        bound = []
        for validator in validators:
            if hasattr(validator, "run_context"):
                validator = copy.copy(validator)
                validator.run_context = run_context
            bound.append(validator)
        return bound

    def passive_validators(self) -> list[Validator]:
        """Return validators that can run without sending any network traffic
        (active=False). Used by the universal header audit to scan every
        captured exchange regardless of agent findings."""
        return [v for v in self.validators.values() if not v.active]

    def header_audit_validators(self) -> list[Validator]:
        """Return validators suitable for a universal header audit pass
        (CORS, CSP, verbose_error). These are run against every captured
        exchange regardless of whether any agent flagged their class --
        closing the passive analysis gap where header-level issues are
        missed because the LLM never labelled them."""
        names = {"cors", "csp", "verbose_error"}
        return [v for n, v in self.validators.items()
                if n in names and (not v.active or self.active_enabled)]
