# Practitioner assessments and alternatives — 2026-10-21

The practitioner views below are analytical perspectives from this audit. They are not the opinions
of credentialed practitioners, and no practitioner was consulted. The AgenticVibe cells rest on this
audit's evidence ([EVIDENCE_INDEX.md](EVIDENCE_INDEX.md)). The alternatives section is
**PROVISIONAL**, for the reasons given in §3.

## 1. Enterprise pentester, on time-boxed client engagements under rules of engagement

| | Advisory mode | Automated mode |
|---|---|---|
| Appropriate users | A tester who wants a second opinion on individual Burp exchanges and runs a local model | A tester running a lab pre-assessment, or a scoped owned staging target, with the operator watching |
| Demonstrated utility | Single-exchange triage with deterministic passive checks. No current measurement of model value (I14). History is limited to same path, same identity (E12–E14). | Bounded discovery and validator legs under one run budget, scope and cancellation (I03/I05, reported). Proof records persist. |
| Remaining manual work | Comparing users, relating requests across endpoints, declaring tenants (API only), and reading results outside Burp. Copying findings into a report (LIMITATIONS "Results live outside Burp"). | Declaring identities with distinct role *labels* to work around E33; checking every BOLA and sensitive-file confirmation by hand (E38, E39); starting jobs by API (E21); reading JSON job results |
| Dealbreakers | (1) Component names leave the machine by default, undocumented (E19). This is a client-confidentiality problem until it is disclosed or disabled. (2) Default-pile knowledge notes are global across clients (E23). (3) Burp hides `degraded` (E21), so an outage can look like "nothing found". | (1) Historical false confirmations with an unresolved cause (H01), plus two open false-confirmation paths (E38, E39). (2) Same-role BOLA is missed (E33). (3) No Burp entry point and no resume (E21, E30). |
| Adoption verdict | **Not for client work yet.** Acceptable for private lab experimentation, with lookups disabled once WL-11 lands. | **Not for client work.** Lab use only. |
| Evidence that would change it | WL-11 and WL-10 landed. WL-08 shows degraded state in Burp. WL-14 meets the spec §9 gates on Q1–Q3, with an analyst-effort gain over arm H. | WL-02, WL-04 and WL-05 caller-verified; WL-14 A3 with 0 false confirmations; WL-15 adjudicated on a frozen target; an exact signed release (I15) |

## 2. Bug bounty practitioner, on high-volume programs where duplicates and noise are costly

| | Advisory mode | Automated mode |
|---|---|---|
| Appropriate users | A hunter who wants local-only analysis of selected requests, and who accepts minutes per request on a consumer GPU (USER_MANUAL) | A hunter with ≥2 test accounts on an in-scope program, if the program permits automated testing |
| Demonstrated utility | Same as the enterprise view. The IDOR/BOLA question across two accounts cannot be answered today (E14). | Cross-identity replay exists, but it needs registered identities, and same-role accounts collapse in the matrix (E33) |
| Remaining manual work | All cross-account comparison (as with Autorize or a manual Repeater diff); proving ownership | Ownership proof, deduplication across runs, and turning a lead into a report-ready PoC |
| Dealbreakers | Speed (sequential agents, about 80–100 s per call, reported). No multi-request question (E10). | A false BOLA confirmation on a shared resource (E38) would damage a report submission. `run` execute has no ceiling, though it is off by default (E40). Request volume against third-party programs needs explicit throttle settings (LIMITATIONS: no default rate limit). |
| Adoption verdict | **Low value today** relative to existing in-Burp comparison workflows (§3, Autorize) | **Not ready.** The precision risk outweighs the recall upside. |
| Evidence that would change it | WL-07 plus WL-03 answering Q1 with correct citations at ≥ the spec §9 margins, faster than arm H | WL-02 and WL-04 with 0 false confirmations on X2 twins; per-program request accounting (I12) |

## 3. Eight alternatives (PROVISIONAL)

- **Research date:** 2026-10-21.
- **Method:** a delegated, read-only research pass collected the material. The full cell-by-cell
  record, with every URL and a VERIFIED, VENDOR CLAIM or UNKNOWN status, is in
  [ALTERNATIVES_RESEARCH_PROVISIONAL.md](ALTERNATIVES_RESEARCH_PROVISIONAL.md).
- **Caveat:** that sandbox could fetch GitHub pages directly but **not** the vendor domains. Cells
  tagged [S] there come from search-tool extraction of the named primary page, summarised by an
  intermediate model. They must be spot-checked in a browser before any external use.
- **No superiority claims:** no shared evaluation of AgenticVibe and these tools exists, so this
  section compares documented scope only.

**Selection criteria** (declared before selection):

1. Relevant to web or API application security.
2. A proxy, interception or Burp integration, or ingestion of captured traffic.
3. Automated testing and/or AI-assisted analysis.
4. Maintained in 2025–2026.
5. At least 3 commercial and at least 3 open-source tools.
6. At least two that address multi-identity access comparison.
7. Primary sources reachable.
8. Near-duplicates folded together.

**Selected:**

1. Burp Suite Professional with Burp AI and Burp AT (beta), with Burp Suite DAST noted.
2. ZAP 2.17 with its Access Control Testing and LLM Support add-ons.
3. Caido, with Assistant, Shift and the Autorize plugins.
4. XBOW.
5. Escape.
6. Autorize (Burp extension).
7. Strix.
8. ProjectDiscovery Nuclei, with Neo noted.

**Adjacent, not selected:**

- Shannon: its open-source edition needs the target's source code.
- PentestGPT: CTF and general pentest focus.
- AuthMatrix: no 2025–2026 activity.
- StackHawk: CI developer DAST.
- Invicti/Acunetix: the same category as Burp DAST.

### 3.1 Automated testing

| Tool | Deployment / licence | Discovery and auth scanning | Budget / scope controls | Confirmation evidence | Status of key cells |
|---|---|---|---|---|---|
| **AgenticVibe (this audit)** | Local Python service plus Burp extension; licence in repo `LICENSE` | Crawl, role crawl, API discovery, optional browser capture | One run budget, scope and cancel on investigate (reported); `run` execute unbounded (E40) | Validators with proof records; two paths over-confirm (E38, E39) | Audit evidence |
| Burp Pro + AI / AT | Desktop, commercial ($399/user/yr) | Scanner crawl and audit; recorded logins | Resource pools, crawl limits; Burp AT scope checks in the tooling layer | Issues with request/response; AI BAC false-positive filtering | VERIFIED [S]; accuracy is a VENDOR CLAIM |
| ZAP | Desktop/daemon/Docker, Apache-2.0 | Spider and AJAX spider; per-context auth | Context scope regexes, scan-duration and thread limits | Alerts with request/response | VERIFIED [S]/[D] |
| Caido | Desktop/CLI, proprietary freemium | No built-in crawler found; Scanner plugin | Scope presets (host/IP), rate limits | Findings tied to requests | VERIFIED [S]; crawler UNKNOWN |
| XBOW | SaaS, proprietary | Autonomous agents; many login methods | Endpoint lists, scope locked at launch | Separate validators; "zero false positives" is a VENDOR CLAIM | VERIFIED [S] / VENDOR CLAIM |
| Escape | SaaS, proprietary | API/web DAST; per-user exploration | Requests/s, allow/block lists | Retest scans, multi-step rules | VERIFIED [S] |
| Autorize | Burp extension, licence unstated | None (replays observed traffic) | Interception filters / Burp scope | Bypassed/Enforced labels; README warns of false positives and false negatives | VERIFIED [D] |
| Strix | CLI plus Docker, Apache-2.0 | Agent graph; contracts and URLs | USD `--max-budget`; network scope UNKNOWN | PoC validation is a VENDOR CLAIM; SARIF and JSON per run | VERIFIED [D]/[S] |
| Nuclei | CLI, MIT | Templates; Burp XML and proxy-mode input | Rate, concurrency, host error caps, scope regexes | Deterministic matchers; `-irr` request/response | VERIFIED [D] |

### 3.2 Advisory and multi-request workflow

| Tool | Session / identity context | Multi-request / cross-identity comparison | Provenance | Proxy integration | Oversight | Privacy (AI data path) | Reporting | Switching cost from Burp |
|---|---|---|---|---|---|---|---|---|
| **AgenticVibe (this audit)** | Credential context plus optional analyst attribution (API only) | Same path and same context only; no cross-principal or cross-endpoint relation (E14); matrix role-keyed (E33) | Observation ids in the response only; no persisted citation (E17) | Burp extension | Analyst-triggered; Burp hides degraded state (E21) | Local Ollama; **third-party lookups by default** (E19) | Markdown, SARIF, issue export | Low (in Burp) |
| Burp Pro + AI / AT | Session handling rules | Compare site maps (needs a human); Autorize recommended | Activity in Logger, Issues and Dashboard | Native | AI opt-in; Burp AT autonomy modes | PortSwigger plus OpenAI/Anthropic; no local model documented | HTML, XML | Baseline |
| ZAP | Multiple users per context | Access Control Testing add-on (declared Allowed/Denied per node) | LLM chat shows each tool call; linking conclusions to messages UNKNOWN | Native; chainable | LLM add-on opt-in, trust tiers | Local Ollama supported; remote providers optional | HTML, JSON, SARIF, XML, Markdown, PDF | Separate proxy; HAR import |
| Caido | Environments, workflows, Authswap | Autorize, AuthMatrix and Authify plugins | Findings tied to requests | Native, replaces Burp | Assistant chat; Shift call limits | Assistant: OpenAI (US); local models undocumented | Exports | High (replaces Burp; BApps do not run) |
| XBOW | Multi-account roles (VENDOR CLAIM) | Cross-account IDOR (VENDOR CLAIM) | "Every action logged" (VENDOR CLAIM) | None documented | Pre-launch scope and guidance | SaaS; global model providers | API reports; format UNKNOWN | High (separate SaaS) |
| Escape | Multiple users, victim user, tenants | `multi_user_access_control`; natural-language rules | Reports with cURL reproductions; audit logs | Imports Burp exports and HAR | Configuration-first | SaaS; cloud AI | PDF, CSV, API | Medium (import, then SaaS) |
| Autorize | Several low-privilege users | Core function: per-request replay table | Original, modified and unauthenticated viewers | In Burp | Analyst resolves "Is enforced???" | No AI | HTML, CSV | Minimal |
| Strix | Credentials via instructions | None documented | Per-run report, JSON, SARIF, `run.json` cost | Uses Caido internally; no Burp integration | TUI or headless | Provider-configurable incl. local | Markdown, JSON, SARIF | High (separate agent) |
| Nuclei | Secrets file | None documented | Template id plus request/response | Burp XML import; proxy mode | CLI | Local for `-llm`; `-ai` needs PD Cloud | JSON, SARIF, Markdown, PDF | Medium |

**Reading this comparison:**

- **Cross-identity comparison the analyst can inspect.** The documented capability AgenticVibe aims
  at exists today as Autorize (in Burp, heuristic, no AI), ZAP's Access Control Testing (declared
  matrix) and Escape (SaaS, multi-user, tenants).
- **Local inference.** Its differentiator is supported by ZAP's LLM add-on and by Strix and Nuclei
  (`-llm`). That differentiator is weakened in practice by AgenticVibe's own default third-party
  lookups (E19).
- **Remaining distinctive scope.** What is still distinctive, *if* WL-03 and WL-06 deliver and WL-14
  measures them, is passive, cited cross-request reasoning over supplied captures inside Burp,
  with no new target traffic. That claim is untested.
