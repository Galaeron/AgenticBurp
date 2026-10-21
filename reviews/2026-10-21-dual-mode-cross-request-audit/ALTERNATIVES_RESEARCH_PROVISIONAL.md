> **PROVISIONAL — delegated research record, 2026-10-21.** This file was produced by a read-only
> research pass delegated from the audit session. Vendor domains were not directly reachable from
> that sandbox; cells tagged [S] come from search-tool extraction of the named primary page and must
> be spot-checked in a browser before external use. No tool was run and no claim was tested. The
> audit's own summary is in [PRACTITIONER_AND_ALTERNATIVES.md](PRACTITIONER_AND_ALTERNATIVES.md).

# AgenticVibe competitive research: eight alternatives

- **Research date:** 2026-10-21 for every tool and cell below.
- **Scope:** Read-only desk research of public documentation, pricing pages, official repositories and release notes. No tool was installed or run, no scan was performed, and no target was contacted.
- **Subject:** AgenticVibe (`/home/user/AgenticBurp`) is a local-first Burp Suite copilot. It has two modes:
  - an advisory/passive mode: a local Ollama model plus deterministic validators analyse captured exchanges;
  - an automated-testing "engagement" mode: discovery, role crawl, worklist and validators, with budget and scope gates.
- **Its differentiators** (as described by the caller, not verified here): cross-request and cross-identity evidence, role/access matrices, evidence provenance, local inference, and analyst-in-the-loop oversight.
- **No superiority claims:** No shared evaluation of AgenticVibe and these tools exists, so this document compares documented scope only. It makes no quality or effectiveness claims in either direction.

---

## 0. Method and how to read the evidence labels

### Status labels used in every cell

| Label | Meaning |
|---|---|
| **VERIFIED** | The feature, setting or fact appears in the vendor's or project's own primary material: docs, repository, release notes or pricing page. The link is given. "Verified" means *documented*, not *independently tested*. |
| **VENDOR CLAIM** | A marketing, outcome or assurance statement that cannot be checked from documentation alone, such as accuracy, "zero false positives", or contractual data-handling promises. The link is given. |
| **UNKNOWN** | I could not find the fact in a primary source during this research. It may still exist. |

### Retrieval tags

| Tag | Meaning |
|---|---|
| **[D]** | Direct fetch of the primary page: GitHub repos, raw GitHub files and GitHub release pages. |
| **[S]** | Fetched through the web-search tool, restricted to the vendor's own domain, which returns extracted and quoted text of the named primary page. The sandbox could not reach the vendor domains directly (portswigger.net, zaproxy.org, caido.io, xbow.com, escape.tech, strix.ai, projectdiscovery.io: DNS and egress were refused). Only GitHub was directly reachable. |

**Limitation.** The [S] extraction is summarised by an intermediary model, so its wording may be imprecise. Before any external publication, spot-check [S] cells against the live pages. Third-party sites that appeared in results were not used.

**Citation format.** Each cell carries a short ID such as `B3` that links to its URL. All IDs and URLs are listed in §6.

---

## 1. Selection criteria (declared before selection)

| # | Criterion |
|---|---|
| C1 | Relevant to web or API application security testing, not only network or infrastructure scanning. |
| C2 | Has a proxy or interception workflow or a Burp integration, **or** can ingest proxy-captured traffic (such as Burp exports or HAR). |
| C3 | Offers automated testing and/or AI- or LLM-assisted advisory or multi-request analysis. |
| C4 | Shows evidence of active maintenance in 2025–2026: a dated release, commit, changelog or doc in that window. |
| C5 | Gives a portfolio mix of at least 3 commercial and at least 3 open-source tools. |
| C6 | Includes at least two tools that address access control or multi-identity comparison. |
| C7 | Has reachable primary sources (official docs or repo), so that cells can be marked. |
| C8 | Occupies a distinct position: near-duplicates are folded together. Burp Suite DAST is folded into PortSwigger, Acunetix into Invicti, and Neo into ProjectDiscovery. |

## 2. Selection

### 2.1 The eight selected

| # | Tool (edition evaluated) | Type | Criteria met | Why selected |
|---|---|---|---|---|
| 1 | **PortSwigger Burp Suite Professional + Burp AI + Burp AT (beta)**; Burp Suite DAST noted | Commercial | C1–C4, C6, C7 | AgenticVibe's host platform and nearest functional neighbour. It has AI advisory features, an agentic tester and compare-site-maps for access control. |
| 2 | **ZAP (ZAP by Checkmarx)** 2.17.x + Access Control Testing + LLM Support add-ons | Open source (Apache-2.0) | C1–C4, C6, C7 | Open-source intercepting proxy and scanner, with a multi-user access-control add-on and (since Aug 2026) a local-LLM-capable add-on. |
| 3 | **Caido** (Basic, Individual, Team) + Assistant, Shift and Autorize plugin | Commercial (freemium) | C1–C4, C6, C7 | Burp-alternative proxy with AI features and Autorize- and AuthMatrix-style plugins. |
| 4 | **XBOW** (autonomous pentest platform, Pentest On-Demand) | Commercial SaaS | C1, C3, C4, C6*, C7 | Autonomous AI pentesting with separate "validators" and multi-account IDOR testing (*vendor claim). |
| 5 | **Escape** (DAST / business-logic, AI Pentesting) | Commercial SaaS | C1–C4, C6, C7 | Documented multi-user access-control testing (roles and tenants), and it imports Burp exports. |
| 6 | **Autorize** (Burp extension, v1.9.4) | Open source (licence unstated) | C1, C2, C4, C6, C7 | The de facto in-Burp cross-identity replay and comparison extension, recommended in PortSwigger's docs. |
| 7 | **Strix** (OSS agent v1.7.0; Strix Cloud noted) | Open source (Apache-2.0) | C1, C3, C4, C7 | Open-source AI agent pentester with local-model support and an explicit USD budget cap. |
| 8 | **ProjectDiscovery Nuclei** (OSS v3.11.x; Neo noted) | Open source (MIT) | C1–C4, C7 | Deterministic, template-based validation with Burp XML import and a DAST proxy mode, plus LLM matchers with local providers. |

- **Mix (C5):** 4 commercial (Burp, Caido, XBOW, Escape) and 4 open source (ZAP, Autorize, Strix, Nuclei).
- **Access-control / multi-identity tools (C6):** Escape, ZAP and Autorize are documented. Burp has compare-site-maps. Caido covers it via plugins. XBOW's support is a vendor claim.

### 2.2 Adjacent tools considered but not selected

| Tool | Key verified facts | Reason not selected |
|---|---|---|
| **Shannon (Keygraph)** | AGPL-3.0. The open-source edition is white-box and needs the target's source repo; black-box testing is Pro/Enterprise only. Pro is $50 per active developer per month. Local models via Ollama, vLLM or LM Studio. VERIFIED [D] [J1](https://github.com/KeygraphHQ/shannon) | Its OSS mode depends on source code, which differs from AgenticVibe's black-box, proxy-captured context. The AI-agent category is already covered by Strix (OSS) and XBOW (SaaS). |
| **PentestGPT** | MIT. v1.0 "Agentic Upgrade" drives Claude Code or Codex. The default mode is CTF solving; there is a separate pentest mode. The legacy mode supports Ollama. VERIFIED [D] [J2](https://github.com/GreyDGL/PentestGPT) | General and CTF pentest focus, with no proxy or web-app evidence workflow. |
| **AuthMatrix** (Burp extension) | A users × roles × requests matrix, colour-coded results, MIT, runs on Jython. Last commit 2021-06-15. VERIFIED [D] [J3](https://github.com/SecurityInnovation/AuthMatrix), [J4](https://github.com/SecurityInnovation/AuthMatrix/commits/master) | Fails C4 (no 2025–2026 activity). It is conceptually the closest to an explicit role/access matrix; Autorize was selected as the maintained in-Burp alternative. |
| **StackHawk** | CI/CD-first DAST. Vendor pages list $10/user/month with a 14-day trial (Aug 2026) and a $5/month "Vibe" plan. VENDOR CLAIM [S] [J5](https://www.stackhawk.com/blog/dynamic-application-security-testing-tools-comparison/), [J6](https://www.stackhawk.com/) | Developer CI scanner without a proxy or advisory workflow. Escape already represents SaaS API DAST with multi-user testing. |
| **Invicti (incl. Acunetix, now "Invicti Web + API")** | Proof-based scanning ("Proof of Exploit"). Agentic Pentest tier capped at $500 per pentest. AI features off by default. The Acunetix site says Acunetix is now Invicti Web + API. VERIFIED/VENDOR CLAIM [S] [J7](https://www.invicti.com/pricing), [J8](https://www.acunetix.com/pricing/), [J9](https://www.invicti.com/blog/web-security/how-ai-enhances-dast-on-invicti-platform), [J10](https://www.acunetix.com/comparisons/acunetix-vs-invicti/) | Enterprise DAST, the same category as Burp Suite DAST (C8). No proxy-centric advisory workflow. |

---

## 3. Per-tool assessments

### 3.1 PortSwigger Burp Suite Professional + Burp AI + Burp AT (beta); Burp Suite DAST

**Profile**

| Field | Value | Status |
|---|---|---|
| Research date | 2026-10-21 | — |
| Edition / product | Burp Suite Professional, a desktop app. Includes Burp AI: Explore Issue, Explainer, Burp AI in Repeater, AI recorded logins, and AI broken-access-control false-positive filtering. Also includes **Burp AT**, an agentic AI in public beta for Pro users. Burp Suite DAST is the separate scheduled/CI scanning product. | VERIFIED [S] [B3](https://portswigger.net/burp/documentation/desktop/burp-ai), [B10](https://portswigger.net/blog/introducing-burp-at), [B11](https://portswigger.net/burp/burp-at) |
| Deployment | Pro runs as a desktop app. DAST has five options: PortSwigger-hosted cloud; cloud with a scanning agent in your network; self-hosted standard installer; self-hosted Kubernetes (Helm); and CI-driven "no dashboard" container. A DAST server must reach portswigger.net:443 to activate its licence. | VERIFIED [S] [B23](https://portswigger.net/burp/dast/hosting-options), [B24](https://portswigger.net/burp/documentation/dast/setup/self-hosted/which-deployment-option-is-right-for-me) |
| Licensing / pricing | Pro is **$399 per user per year** (€349 / £319; 2 years $798, 3 years $1,197). A "user" is a named individual, and licences cannot be shared. | VERIFIED [S] [B1](https://portswigger.net/pricing), [B2](https://portswigger.net/support/burp-suite-licensing-model) |
| AI pricing | AI features consume **AI credits**, bought separately; cost varies with the number and complexity of requests. The 2025 launch materials state 10,000 free credits (≈ US$5) per licence; this may be dated. Credits are per user and cannot be pooled. A "Burp AI Subscription" team add-on exists, price UNKNOWN. Burp AT has Individual, Team and Enterprise tiers, prices UNKNOWN. DAST pricing UNKNOWN. | VERIFIED [S] [B3](https://portswigger.net/burp/documentation/desktop/burp-ai), [B4](https://portswigger.net/burp/releases/professional-community-2025-2-3), [B5](https://portswigger.net/blog/welcome-to-the-next-generation-of-burp-suite-elevate-your-testing-with-burp-ai), [B27](https://portswigger.net/burp/ai/subscriptions), [B28](https://portswigger.net/burp/documentation/desktop/burp-ai/ai-credits), [B12](https://portswigger.net/burp/burp-at/pricing) |
| Maintenance | Release notes for 2026.7 and 2026.7.1 exist; the Burp AT release notes are dated 16 July 2026. | VERIFIED [S] [B13](https://portswigger.net/burp/releases/professional-community-2026-7) |

**A. Automated testing**

| Dimension | Assessment | Status |
|---|---|---|
| Discovery / crawl | Burp Scanner offers crawl and audit. Built-in "crawl limit" presets cap the crawl at 10, 30 or 60 minutes and 1,500 unique locations; a Lightweight preset caps scans at 15 minutes. Burp AT plans and runs tasks with Burp's own tools. | VERIFIED [S] [B16](https://portswigger.net/burp/documentation/desktop/running-scans/webapp-scans/full-crawl-and-audit), [B18](https://portswigger.net/burp/documentation/scanner/scan-configurations/burp-scanner-built-in-configs), [B10](https://portswigger.net/blog/introducing-burp-at) |
| Authenticated scanning | Recorded logins, including AI-generated recorded logins. For these, usernames and passwords are replaced with placeholders before anything is sent to AI. | VERIFIED [S] [B3](https://portswigger.net/burp/documentation/desktop/burp-ai), [B6](https://portswigger.net/burp/documentation/burp-ai/trust) |
| Budget / scope controls | Resource pools set maximum concurrent requests and automatic throttling on chosen response codes. Crawls have a maximum crawl time and request count; DAST adds a "Total scan time". If AI credits run out mid-scan, you choose to pause or continue without AI. | VERIFIED [S] [B19](https://portswigger.net/burp/documentation/desktop/running-scans/managing-resource-pools), [B18](https://portswigger.net/burp/documentation/scanner/scan-configurations/burp-scanner-built-in-configs), [B31](https://portswigger.net/burp/documentation/dast/user-guide/working-with-scans/best-scanning-practices), [B16](https://portswigger.net/burp/documentation/desktop/running-scans/webapp-scans/full-crawl-and-audit) |
| Burp AT scope enforcement | Scope, tool access and approval rules "live in Burp's tooling layer, architecturally separate from the model". Each tool call is checked against scope before it runs, and scope changes always need manual approval. The docs warn that prompt-written limits are *not* security controls, and that custom scripts can send requests outside scope. This describes the design; enforcement was not tested. | VERIFIED [S] [B8](https://portswigger.net/burp/documentation/ai-features/trust), [B14](https://portswigger.net/burp/documentation/desktop/burp-at/setting-up), [B15](https://portswigger.net/burp/documentation/desktop/burp-at/prompting) |
| Confirmation / evidence | Scanner issues carry request/response evidence, which XML export can include in base64. "Explore Issue" autonomously follows up Scanner issues, "attempting exploits, identifying additional attack vectors". AI broken-access-control (BAC) false-positive filtering requires a scan that performs **both authenticated and unauthenticated crawls**. | VERIFIED [S] [B20](https://portswigger.net/burp/documentation/desktop/running-scans/reporting), [B3](https://portswigger.net/burp/documentation/desktop/burp-ai), [B16](https://portswigger.net/burp/documentation/desktop/running-scans/webapp-scans/full-crawl-and-audit) |
| Accuracy of BAC filtering | Described as "significantly more accuracy". | VENDOR CLAIM [B17](https://portswigger.net/burp/ai/capabilities) |
| CI integration | Burp Suite DAST offers Docker CI-driven scans with JUnit or Burp XML output, a GitHub Actions example that fails the build on an issue threshold, and a Jenkins site-driven plugin; it can also run CI-only with no dashboard. CI use of Pro itself: UNKNOWN. | VERIFIED [S] [B21](https://portswigger.net/burp/documentation/dast/user-guide/ci-cd), [B22](https://portswigger.net/burp/documentation/dast/user-guide/ci-cd/ci-driven-scans/example-integrations/integrate-github), [B30](https://portswigger.net/burp/documentation/dast/setup/self-hosted/ci-driven-no-dashboard) |

**B. Advisory / multi-request workflow**

| Dimension | Assessment | Status |
|---|---|---|
| Session / identity context | Session handling rules can set a second user's session cookie on Target-tool requests. | VERIFIED [S] [B25](https://portswigger.net/burp/documentation/desktop/tools/target/site-map/comparing) |
| Multi-request / cross-identity comparison | **Compare site maps** re-requests a site map in a different session context and diffs the responses. The docs say interpreting the results "requires human intelligence". PortSwigger's privilege-escalation guide recommends the Autorize BApp. A built-in role × endpoint matrix in core Burp: UNKNOWN (none found). | VERIFIED [S] [B25](https://portswigger.net/burp/documentation/desktop/tools/target/site-map/comparing), [B26](https://portswigger.net/burp/documentation/desktop/testing-workflow/vulnerabilities/access-controls/privilege-escalation) |
| Provenance / traceability | Burp AT activity is recorded in existing tools: traffic in Logger, scans on the Dashboard, and confirmed vulnerabilities in Issues and the site map. PortSwigger stores prompts, AI responses and metadata for troubleshooting, auditing and billing. | VERIFIED [S] [B13](https://portswigger.net/burp/releases/professional-community-2026-7), [B6](https://portswigger.net/burp/documentation/burp-ai/trust), [B7](https://portswigger.net/burp/documentation/burp-ai/trust/data-storage) |
| Proxy integration | Native: Burp is the proxy. AI features operate on Repeater messages, Scanner issues and so on. | VERIFIED [S] [B33](https://portswigger.net/burp/documentation/desktop/tools/repeater/http-messages/ai-explainer), [B34](https://portswigger.net/burp/documentation/desktop/tools/repeater/http-messages/burp-ai-in-repeater) |
| Human oversight | AI features run only when explicitly activated, and AI is disabled by default for extensions. Burp AT has three autonomy modes: Manual, **Smart (default)**, which pauses for approval on actions it judges risky, and Autonomous. | VERIFIED [S] [B3](https://portswigger.net/burp/documentation/desktop/burp-ai), [B6](https://portswigger.net/burp/documentation/burp-ai/trust), [B14](https://portswigger.net/burp/documentation/desktop/burp-at/setting-up) |
| Privacy: does traffic leave the machine? | **Yes, when AI is used.** Data goes to PortSwigger and to its AI providers: OpenAI and Anthropic for Burp AI, Anthropic for Burp AT. There is no automatic redaction except credentials in recorded logins. Processing is on AWS US-East and EU-West, and the providers process requests in US data centres. | VERIFIED [S] [B6](https://portswigger.net/burp/documentation/burp-ai/trust), [B8](https://portswigger.net/burp/documentation/ai-features/trust) |
| Provider retention, training and storage | Providers "do not retain" data and are contractually barred from training on it. PortSwigger's own retention wording is inconsistent ("retained indefinitely" vs "no fixed deletion schedule"); operational logs are kept for 31 days. Storage uses AES-256 and transport uses TLS 1.2+. | VENDOR CLAIM [S] [B6](https://portswigger.net/burp/documentation/burp-ai/trust), [B7](https://portswigger.net/burp/documentation/burp-ai/trust/data-storage) |
| Local model support | Not documented for Burp AI or Burp AT. AI extensions must use Burp AI as their default provider. They *may additionally* call third-party providers, but only via Montoya networking with upstream TLS verification. | Local model: UNKNOWN. Extension rule: VERIFIED [S] [B9](https://portswigger.net/burp/documentation/desktop/extend-burp/extensions/creating/creating-ai-extensions) |
| Reporting / export | HTML reports (summary or detailed) and XML (optionally with base64 request/response). DAST offers downloadable reports. | VERIFIED [S] [B20](https://portswigger.net/burp/documentation/desktop/running-scans/reporting), [B32](https://portswigger.net/burp/documentation/dast/user-guide/work-with-scan-results/generate-reports) |
| Switching cost vs Burp-centric workflow | None: this is the baseline, and AgenticVibe runs inside it. | — |

**Overlap with AgenticVibe**

- **Overlap.** Burp is AgenticVibe's host platform and also its closest neighbour:
  - Burp AI's Explainer, Repeater prompts and Explore Issue overlap the advisory mode on individual exchanges and Scanner issues.
  - Burp AT (beta) overlaps the bounded "engagement" concept. It has tooling-layer scope checks, approval modes, and activity recorded in Burp's own tools.
- **Documented differences in design:**
  - Burp AI and Burp AT send data to PortSwigger and cloud model providers, with no documented local-model option. AgenticVibe targets local Ollama inference.
  - Burp's cross-identity support is compare-site-maps, BApps such as Autorize, and BAC checks that need authenticated plus unauthenticated crawls. No documented role matrix exists in core.
- **No quality ranking.** No shared evaluation exists, so these are scope differences only. The two can also coexist in one Burp project.

---

### 3.2 ZAP (Zed Attack Proxy, "ZAP by Checkmarx")

**Profile**

| Field | Value | Status |
|---|---|---|
| Research date | 2026-10-21 | — |
| Edition / product | ZAP core, latest stable **2.17.0** (announced 2025-12-15), with weekly builds up to w2026-10-15. Add-ons assessed: Access Control Testing, LLM Support (v0.0.1, 2026-08-07), MCP Integration (alpha), Report Generation, Import/Export, and Automation Framework. | VERIFIED [D] [Z2](https://github.com/zaproxy/zaproxy/releases), [Z3](https://github.com/zaproxy/zaproxy/releases/tag/v2.17.0); [S] [Z4](https://www.zaproxy.org/blog/2025-12-15-zap-2-17-0/), [Z9](https://www.zaproxy.org/docs/addons/llm/changelog/) |
| Deployment | Desktop app (Java 17+), headless/daemon, Docker packaged scans, API, and Automation Framework. | VERIFIED [S] [Z14](https://www.zaproxy.org/docs/docker/about/), [Z27](https://www.zaproxy.org/pdf/ZAPGettingStartedGuide-2.17.pdf), [Z30](https://www.zaproxy.org/docs/api/) |
| Licensing / pricing | Apache-2.0. The README brands it "The Zed Attack Proxy (ZAP) by Checkmarx". No licence fee. Paid support offerings: UNKNOWN. | VERIFIED [D] [Z1](https://github.com/zaproxy/zaproxy) |

**A. Automated testing**

| Dimension | Assessment | Status |
|---|---|---|
| Discovery / crawl | Traditional spider (thread count, maximum duration with 0 = unlimited) and AJAX spider. The Import/Export add-on imports HAR files, optionally re-sending the requests. | VERIFIED [S] [Z13](https://www.zaproxy.org/docs/desktop/addons/spider/options/), [Z25](https://www.zaproxy.org/docs/desktop/addons/import-export/) |
| Authenticated scanning | Per-context authentication (form, JSON or script-based), users, and session management (cookie, HTTP auth header or script). An Authentication Helper add-on produces an auth diagnostics report. The Automation Framework is recommended for authenticated automation. | VERIFIED [S] [Z17](https://www.zaproxy.org/docs/desktop/start/features/authentication/), [Z19](https://www.zaproxy.org/docs/desktop/start/features/sessionmanagement/), [Z22](https://www.zaproxy.org/docs/desktop/addons/authentication-helper/), [Z14](https://www.zaproxy.org/docs/docker/about/) |
| Budget / scope controls | Contexts define scope with URL regexes. Active scan settings include max scan duration, max rule duration (0 = unlimited), threads per host, hosts per scan and delay in ms. Access-control testing is blocked in Safe mode, and in Protected mode when the context is out of scope. In 2.17, "Insights" can stop a scan early when significant problems appear. | VERIFIED [S] [Z18](https://www.zaproxy.org/docs/desktop/start/features/contexts/), [Z12](https://www.zaproxy.org/docs/desktop/ui/dialogs/options/ascan/), [Z5](https://www.zaproxy.org/docs/desktop/addons/access-control-testing/), [Z4](https://www.zaproxy.org/blog/2025-12-15-zap-2-17-0/) |
| Confirmation / evidence | Alerts carry their request and response, and report templates "with Requests and Responses" exist. 2.17 adds alert de-duplication via the Sites Tree and "Systemic" alerts. Exploit-confirmation beyond scan-rule evidence: UNKNOWN. | VERIFIED [S] [Z16](https://www.zaproxy.org/docs/desktop/addons/report-generation/templates/), [Z4](https://www.zaproxy.org/blog/2025-12-15-zap-2-17-0/) |
| CI integration | GitHub Actions: the full-scan action keeps a GitHub issue updated and attaches a report. Docker packaged scans and the Automation Framework are also available. | VERIFIED [S] [Z15](https://www.zaproxy.org/blog/2020-05-15-dynamic-application-security-testing-with-zap-and-github-actions/), [Z14](https://www.zaproxy.org/docs/docker/about/) |

**B. Advisory / multi-request workflow**

| Dimension | Assessment | Status |
|---|---|---|
| Session / identity context | Multiple users per context. The HTTP Sessions tool can create or force an active session. Forced User mode is meant for manual testing only. | VERIFIED [S] [Z17](https://www.zaproxy.org/docs/desktop/start/features/authentication/), [Z28](https://www.zaproxy.org/docs/desktop/start/features/httpsessions/) |
| Multi-request / cross-identity comparison | The **Access Control Testing add-on** (from the Marketplace, not bundled by default) works as follows:<ul><li>Each user gets an Allowed, Denied or Unknown rule per URL-tree node, inherited by subtrees.</li><li>ZAP tries every URL as every user.</li><li>A status tab shows which users reached which pages and flags rule violations.</li><li>It can be driven via the API.</li></ul>Separately, "Compare with another Session" lists URLs across two sessions, for example two users. | VERIFIED [S] [Z5](https://www.zaproxy.org/docs/desktop/addons/access-control-testing/), [Z6](https://www.zaproxy.org/docs/desktop/ui/tlmenu/report/) |
| Provenance / traceability | Each tool call the LLM makes, and its result, is shown in the LLM Chat tab. Reports can embed requests and responses. Linking LLM conclusions to specific stored messages: UNKNOWN. | VERIFIED [S] [Z21](https://www.zaproxy.org/docs/desktop/addons/llm-support/chat/), [Z16](https://www.zaproxy.org/docs/desktop/addons/report-generation/templates/) |
| Proxy integration | Native intercepting proxy, with upstream proxy chaining via Network options and API. | VERIFIED [S] [Z20](https://www.zaproxy.org/docs/desktop/start/), [Z26](https://www.zaproxy.org/docs/desktop/addons/network/options/) |
| Human oversight | LLM Support is opt-in: ZAP shares nothing with an LLM unless the add-on is installed and configured. Tools are offered only to providers marked **Trusted**; local providers are trusted by default, while remote providers get only the minimum data and no tools. The MCP server is alpha and must not be exposed beyond localhost. | VERIFIED [S] [Z7](https://www.zaproxy.org/blog/2026-08-07-zap-llm-support/), [Z23](https://www.zaproxy.org/docs/desktop/addons/llm-support/options/), [Z10](https://www.zaproxy.org/docs/desktop/addons/mcp-integration/) |
| Privacy / local model | The ZAP core runs locally. LLM Support covers **Ollama** (default `http://localhost:11434/`, no API key), LM Studio and OpenAI-compatible endpoints, plus Azure OpenAI, Claude and Gemini. Release status conflicts: the July 2026 update said alpha and unreleased, while the 2026-08-07 post announces the launch. | VERIFIED [S] [Z7](https://www.zaproxy.org/blog/2026-08-07-zap-llm-support/), [Z8](https://www.zaproxy.org/docs/desktop/addons/llm-support/), [Z9](https://www.zaproxy.org/docs/addons/llm/changelog/), [Z11](https://www.zaproxy.org/blog/2026-08-06-zap-updates-july-2026/) |
| Reporting / export | Report Generation templates in HTML variants, JSON, **SARIF**, XML, Markdown and PDF. Custom Thymeleaf templates are supported, and the Automation Framework has a `report` job. | VERIFIED [S] [Z16](https://www.zaproxy.org/docs/desktop/addons/report-generation/templates/), [Z24](https://www.zaproxy.org/docs/desktop/addons/report-generation/automation/) |
| Switching cost vs Burp | A separate proxy and session format. It can import HAR and chain to an upstream proxy, so it could sit in front of or behind Burp. Direct import of Burp project files: UNKNOWN. | VERIFIED [S] [Z25](https://www.zaproxy.org/docs/desktop/addons/import-export/), [Z26](https://www.zaproxy.org/docs/desktop/addons/network/options/) |

**Overlap with AgenticVibe**

- **Overlap.** ZAP is the open-source tool whose documented shape most resembles AgenticVibe's combination:
  - an intercepting proxy, automated scanning with time and thread caps, and a multi-user access-control tester;
  - since August 2026, an opt-in LLM add-on that supports local Ollama, with a trust model that restricts data and tools for remote providers.
- **Documented difference: matrix origin.**
  - In ZAP, the analyst writes the expected-access matrix up front (Allowed/Denied rules per node), and ZAP checks reality against it.
  - In AgenticVibe, per the caller's description, role and access evidence is derived from captured exchanges.
- **Workflow.** ZAP is not a Burp extension, so a Burp-centric analyst would run it alongside Burp or chain the two proxies.

---

### 3.3 Caido

**Profile**

| Field | Value | Status |
|---|---|---|
| Research date | 2026-10-21 | — |
| Edition / product | Caido desktop app and CLI instance. Plans: Basic (free), Individual, Team. AI components: the **Assistant** (cloud), the **Shift** official AI plugin (acquired in 2025), and the Caido MCP server. Community plugins are also assessed: Autorize, Scanner, AuthMatrix and Authify. The latest GitHub release is v0.58.3, dated "04 Sep"; the page shows no year. | VERIFIED [S] [C1](https://www.caido.io/pricing/), [C9](https://www.caido.io/blog/2025-07-16-shift-acquisition/), [C26](https://docs.caido.io/app/tutorials/mcp); [D] [C22](https://github.com/caido/caido/releases) |
| Deployment | The CLI is a self-contained binary that runs the instance (proxy). The desktop app spawns a local CLI or connects to a remote instance. A Docker image is available. Headless instances use a registration key plus a Personal Access Token, described as the main method for CI/CD. The docs warn that "proxy traffic is currently unprotected" and advise not exposing instances to the internet. | VERIFIED [S] [C18](https://docs.caido.io/app/guides/docker), [C19](https://docs.caido.io/app/tutorials/headless_orchestration), [C20](https://docs.caido.io/app/concepts/pat), [C21](https://docs.caido.io/app/concepts/instance_authentication) |
| Licensing | Proprietary core: the public `caido/caido` repo holds releases, wiki and roadmap only. Shift, Autorize and Scanner plugins are MIT. | VERIFIED [D] [C27](https://github.com/caido), [C6](https://github.com/caido-community/shift), [C12](https://github.com/caido-community/autorize) |
| Pricing | <ul><li>**Basic:** free, with 2 projects and 7 workflows and no Assistant.</li><li>**Individual:** $200/yr on Caido's Burp comparison page; an older mirror shows $20/mo. The live page did not return dollar figures.</li><li>**Team:** price UNKNOWN (conflicting).</li><li>**Localized pricing:** about 50% lower in Brazil and about 65% lower in India.</li></ul> | VERIFIED [S] [C1](https://www.caido.io/pricing/), [C2](https://www.caido.io/compare/burpsuite/), [C3](https://www.caido.io/blog/2025-08-21-localized-pricing/) |

**A. Automated testing**

| Dimension | Assessment | Status |
|---|---|---|
| Discovery / crawl | No built-in crawler was found (UNKNOWN). The Scanner plugin runs passive checks, on by default for in-scope proxied traffic, and active checks on selected requests. | Crawler: UNKNOWN. Scanner: VERIFIED [S] [C13](https://docs.caido.io/app/tutorials/scanner), [C14](https://github.com/caido-community/scanner) |
| Authenticated scanning | Uses Environment variables, Workflows, Match & Replace and the Authswap plugin. The docs say there is no equivalent of Burp's session-handling rules or macros. | VERIFIED [S] [C15](https://docs.caido.io/burp-suite/core/project-and-configuration) |
| Budget / scope controls | Scope presets are allow/deny lists matched on host or IP; paths are not supported in presets. Scanner has rate limits and per-check "aggressivity". Shift's AI settings limit how many calls a Shift Agent can make. | VERIFIED [S] [C23](https://docs.caido.io/app/guides/scopes_defining), [C13](https://docs.caido.io/app/tutorials/scanner), [C28](https://docs.caido.io/app/tutorials/shift) |
| Confirmation / evidence | Findings can be created manually or from workflows, with a dedupe key matched on the raw request or response; Scanner results land in Findings. Exploit confirmation: UNKNOWN. | VERIFIED [S] [C24](https://docs.caido.io/app/guides/workflows_findings), [C29](https://docs.caido.io/burp-suite/core/scans) |
| CI integration | A headless instance with a PAT, orchestrated with `@caido/sdk-client`. Native CI plugins: UNKNOWN. | VERIFIED [S] [C19](https://docs.caido.io/app/tutorials/headless_orchestration), [C20](https://docs.caido.io/app/concepts/pat) |

**B. Advisory / multi-request workflow**

| Dimension | Assessment | Status |
|---|---|---|
| Session / identity context | Environments, workflows and the Authswap plugin handle session switching. | VERIFIED [S] [C15](https://docs.caido.io/burp-suite/core/project-and-configuration) |
| Multi-request / cross-identity comparison | The caido-community **Autorize** plugin (MIT) is described as "Automated authorization testing for web applications". It "automatically test[s] if lower-privilege users can access resources they shouldn't", but the README does not document its comparison mechanism. The **AuthMatrix** and **Authify** plugins are listed as covering parts of Burp's AuthMatrix and Auth Analyzer. | VERIFIED [D] [C12](https://github.com/caido-community/autorize); [S] [C16](https://docs.caido.io/burp-suite/extensibility/extensions) |
| Provenance / traceability | Findings are tied to requests, and HTTPQL searches traffic. Traceability of AI conclusions back to exchanges: UNKNOWN. | Partly VERIFIED [S] [C24](https://docs.caido.io/app/guides/workflows_findings), [C15](https://docs.caido.io/burp-suite/core/project-and-configuration) |
| Proxy integration | Native intercepting proxy, as a Burp replacement rather than a Burp add-on. | VERIFIED [S] [C15](https://docs.caido.io/burp-suite/core/project-and-configuration) |
| Human oversight | The Assistant is a chat over content the user submits. Shift acts in Replay on request and has per-agent call limits. In-run approval gates: UNKNOWN. | VERIFIED [D] [C6](https://github.com/caido-community/shift); [S] [C28](https://docs.caido.io/app/tutorials/shift) |
| Privacy: does traffic leave the machine? | **Assistant:** "uses OpenAI services hosted in the US", data "can be stored for up to 30 days", and the docs say it "does not support API keys for other AI providers or configuration for use with local LLMs". **Shift:** "will be communicating with our backend and SOTA AI models". **Caido Cloud:** "We NEVER collect project data, HTTP requests, payloads". | Assistant and Shift: VERIFIED [D] [C4](https://raw.githubusercontent.com/caido/documentation/main/src/app/guides/assistant_model.md), [C5](https://raw.githubusercontent.com/caido/documentation/main/src/app/concepts/cloud.md), [C6](https://github.com/caido-community/shift). Cloud non-collection: VENDOR CLAIM [D] [C5](https://raw.githubusercontent.com/caido/documentation/main/src/app/concepts/cloud.md) |
| Privacy: own keys and local models | Marketing says teams can bring their own Anthropic, OpenAI, Google or OpenRouter keys, and that a self-hosted Team keeps traffic off Caido's servers. This conflicts with the Assistant docs. A LiteLLM tutorial routes Caido and Shift through an OpenAI-compatible base URL, but it does not mention local models (UNKNOWN). An open PR (#104, Oct 2026) moves Shift onto Caido's AI providers and model registry (Caido 0.59); its merge status is UNKNOWN. | Own keys / self-hosted: VENDOR CLAIM [S] [C11](https://www.caido.io/orgs/), [C10](https://www.caido.io/blog/2026-03-24-ai-enhanced-hacking/). LiteLLM route: VERIFIED [D] [C7](https://raw.githubusercontent.com/caido/documentation/main/src/app/tutorials/litellm.md). PR: VERIFIED [S] [C8](https://github.com/caido-community/shift/pull/104) |
| Reporting / export | Request-data Exports and per-feature configuration export. A formal report generator: UNKNOWN. | VERIFIED [S] [C25](https://docs.caido.io/app/guides/exports_requests), [C15](https://docs.caido.io/burp-suite/core/project-and-configuration) |
| Switching cost vs Burp | Caido publishes a Burp feature-mapping guide. There is no unified config library, Burp project-file import is undocumented (UNKNOWN), and BApps do not run because the plugin API differs. Caido "has no bundled AI product like Burp AI". | VERIFIED [S] [C15](https://docs.caido.io/burp-suite/core/project-and-configuration), [C16](https://docs.caido.io/burp-suite/extensibility/extensions), [C17](https://docs.caido.io/burp-suite/core/ai) |

**Overlap with AgenticVibe**

- **Advisory overlap.** Caido's AI pieces (Assistant, Shift) overlap AgenticVibe's per-request advisory help.
- **Cross-identity overlap.** Its community authorization plugins (Autorize, AuthMatrix, Authify) overlap cross-identity comparison.
- **Structural difference.** Caido *replaces* the host proxy, whereas AgenticVibe extends Burp.
- **Data-path difference.** Caido's documented AI data path is cloud-based (OpenAI for the Assistant; Caido's backend for Shift). Local-model use is undocumented for the Assistant and only indirectly possible via a LiteLLM gateway for Shift.

---

### 3.4 XBOW

**Profile**

| Field | Value | Status |
|---|---|---|
| Research date | 2026-10-21 | — |
| Edition / product | XBOW autonomous offensive-security platform: Pentest On-Demand and Autonomous Exposure Management. The public API has been in Public Preview since 2026-02-01. | VERIFIED [S] [X2](https://xbow.com/news/announcing-xbow-pentest-on-demand-for-security-at-machine-speed), [X13](https://xbow.com/blog/introducing-the-xbow-public-api) |
| Deployment | SaaS, plus a "Managed Hosted" single-tenant deployment model and an AWS Marketplace listing. Self-hosted or on-prem: UNKNOWN. | VERIFIED [S] [X11](https://xbow.com/blog/xbow-available-eu-data-residency), [X17](https://xbow.com/blog/xbow-is-now-available-on-aws-marketplace) |
| Licensing / pricing | Proprietary. Pentest On-Demand "starts at $4,000" per the Nov 2025 press release, but a blog post says "starts at $6,000" (conflict). The pricing page describes scoped, usage-based pricing. | VERIFIED [S] (conflicting) [X2](https://xbow.com/news/announcing-xbow-pentest-on-demand-for-security-at-machine-speed), [X3](https://xbow.com/blog/pentest-on-demand), [X1](https://xbow.com/pricing) |

**A. Automated testing**

| Dimension | Assessment | Status |
|---|---|---|
| Discovery / crawl | Autonomous agents work from a supplied attack surface; Assessment Guidance can restrict them to listed endpoints. Coverage claims about the "whole estate": VENDOR CLAIM. | VERIFIED [S] [X7](https://xbow.com/blog/introducing-assessment-guidance); VENDOR CLAIM [X5](https://xbow.com/platform) |
| Authenticated scanning | Supported: username/password, TOTP MFA, SSO (e.g. Okta), magic links, GitHub or Microsoft social login, static bearer tokens and HTTP basic auth. Unsupported: SMS MFA, Google social login and CAPTCHA-gated logins. | VERIFIED [S] [X8](https://docs.xbow.com/console/reference/authentication-methods/) |
| Budget / scope controls | Testing can be limited to listed endpoints or scoped to one vulnerability class. URL patterns can be marked auth-only or blocked, and scope is locked at launch. | VERIFIED [S] [X7](https://xbow.com/blog/introducing-assessment-guidance), [X6](https://xbow.com/blog/autonomous-agent-safety-guardrails) |
| Action vetting | XBOW says the platform "vets every action before it executes" and enforces scope at the network level. | VENDOR CLAIM [X6](https://xbow.com/blog/autonomous-agent-safety-guardrails), [X18](https://xbow.com/blog/we-ran-1060-autonomous-attacks) |
| Cost / request budgets | No documented budget controls. | UNKNOWN |
| Confirmation / evidence | Separate "validators", either LLM-based or programmatic (for example, a headless browser checks that a payload actually executed). Discovery and validation agents are said to be separate, with "zero false positives". | VENDOR CLAIM [X4](https://xbow.com/blog/top-1-how-xbow-did-it), [X5](https://xbow.com/platform) |
| CI integration | The public API triggers assessments and retrieves validated findings, and the docs list webhooks. Native CI plugins: UNKNOWN. | VERIFIED [S] [X12](https://xbow.com/api), [X14](https://docs.xbow.com/) |

**B. Advisory / multi-request workflow**

| Dimension | Assessment | Status |
|---|---|---|
| Session / identity context | Multi-account testing: agents "log in as specific roles, browse the application normally, and document what they can and cannot do" before attacking. | VENDOR CLAIM [X9](https://xbow.com/blog/xbow-finds-idors-high-accuracy-ambiguous-context) |
| Multi-request / cross-identity comparison | IDOR findings come from comparing access across accounts, according to the blog. The output format (for example, a matrix) and the number of roles supported: UNKNOWN. | VENDOR CLAIM [X9](https://xbow.com/blog/xbow-finds-idors-high-accuracy-ambiguous-context) |
| Provenance / traceability | The demo shows inspecting requests and responses, grouping activity by attack, and a detailed record of the test. XBOW also says "every action is logged and auditable". | VENDOR CLAIM [X15](https://xbow.com/videos/xbow-run-autonomous-penetration-test), [X16](https://xbow.com/) |
| Proxy integration | No Burp or proxy integration was found. | UNKNOWN |
| Human oversight | Users set scope and guidance before launch. Its HackerOne findings were human-reviewed "for compliance", but humans "did not participate in discovery or exploitation". In-run approval gates: UNKNOWN. | VERIFIED [S] [X7](https://xbow.com/blog/introducing-assessment-guidance); VENDOR CLAIM [X4](https://xbow.com/blog/top-1-how-xbow-did-it) |
| Privacy / data residency | **Traffic originates from XBOW's infrastructure (SaaS).** Data is stored in-region for the EU, Singapore, Australia, Canada and Japan (the last three in Private Preview). Billing, support and telemetry stay global. Model processing uses "approved global model providers" and may happen out of region, although the earlier EU post says the models are served from EU infrastructure (conflict). Local model support: none documented (UNKNOWN). | VERIFIED [S] [X10](https://xbow.com/blog/xbow-data-residency-now-available-in-australia-canada-and-japan), [X11](https://xbow.com/blog/xbow-available-eu-data-residency) |
| Reporting / export | The docs have a "Reports" reference page, and the API exposes reports. Report format: UNKNOWN. | VERIFIED [S] (existence only) [X14](https://docs.xbow.com/), [X13](https://xbow.com/blog/introducing-the-xbow-public-api) |
| Switching cost vs Burp | A separate SaaS console with no documented Burp import or export. | UNKNOWN |

**Overlap with AgenticVibe**

- **Overlap with the engagement mode:**
  - autonomous agents with discovery separated from validation;
  - scope locked at launch with allow/deny URL controls;
  - a multi-account method for finding IDORs that resembles cross-identity comparison.
- **No documented overlap with:**
  - the in-proxy, analyst-in-the-loop advisory workflow;
  - local or private inference (XBOW states it uses global model providers).
- **Evidence caveat.** XBOW's quality claims (zero false positives, validator efficacy) are vendor claims.

---

### 3.5 Escape

**Profile**

| Field | Value | Status |
|---|---|---|
| Research date | 2026-10-21 | — |
| Edition / product | The Escape platform: DAST for API, web app and "business logic", AI Pentesting, ASM, CLI, public API, and an MCP server. | VERIFIED [S] [E1](https://escape.tech/product/dast), [E6](https://docs.escape.tech/documentation/automate/cli/), [E13](https://docs.escape.tech/documentation/automate/public-api/) |
| Deployment | SaaS. **Private Locations** create a reverse SOCKS5 tunnel from on-prem or VPC networks to Escape's cloud so internal apps can be tested. | VERIFIED [S] [E8](https://docs.escape.tech/documentation/asm/quickstart/), [E9](https://docs.escape.tech/documentation/automate/cli/configuration/) |
| Licensing / pricing | Proprietary, with no public price list. AWS Marketplace public offers are tiered by scanned applications (up to 15, 60 or 120). The terms say fees are based on the monthly "Endpoint Count". A free trial exists per Escape's blog. | VERIFIED [S] [E15](https://escape.tech/blog/escape-now-available-on-aws-marketplace/), [E16](https://escape.tech/terms); trial: VENDOR CLAIM |

**A. Automated testing**

| Dimension | Assessment | Status |
|---|---|---|
| Discovery / crawl | API exploration can run once per authenticated user (`explore_with_all_users`). Web-app testing and ASM are also available. | VERIFIED [S] [E4](https://docs.escape.tech/documentation/reference/configuration-schemas/api-dast-rest/) |
| Authenticated scanning | Authentication presets (including OAuth client credentials) with an optional role per user. The CLI can override authentication at scan time with `-c` or `--override`. | VERIFIED [S] [E2](https://docs.escape.tech/documentation/dast/multi-user-testing/), [E6](https://docs.escape.tech/documentation/automate/cli/) |
| Budget / scope controls | `network.requests_per_second` ranges from 1 to 1000 (default 100; browser crawling excluded). A global allow/block scope applies, with blocklist precedence. AI Pentesting adds a rate limit, max duration (`maxDurationMinutes`) and a path blocklist. Incremental CI scans need the pipeline to compute the changed scope. A standard DAST duration cap: UNKNOWN. | VERIFIED [S] [E4](https://docs.escape.tech/documentation/reference/configuration-schemas/api-dast-rest/), [E20](https://docs.escape.tech/documentation/reference/configuration-schemas/asm/), [E14](https://docs.escape.tech/documentation/ai-pentesting/scope/), [E13](https://docs.escape.tech/documentation/automate/public-api/), [E7](https://docs.escape.tech/documentation/automate/ci-cd/incremental-scanning/) |
| Confirmation / evidence | An issue *retest* scan re-validates findings with outcomes such as VERIFIED_FIXED or VULNERABLE. Multi-step custom rules chain requests and reuse extracted tokens or IDs. AI-pentest evidence (attack path, request chain, screenshots) is described in a blog. | Retest and rules: VERIFIED [S] [E13](https://docs.escape.tech/documentation/automate/public-api/), [E18](https://escape.tech/blog/reproduce-complex-exploits-multi-step-custom-rules/). Evidence: VENDOR CLAIM [E21](https://escape.tech/blog/what-is-ai-pentesting/) |
| CI integration | A GitHub Action (profile ID and API key; `watch` waits for the result). The CLI also works with GitLab, Bitbucket, CircleCI, Jenkins, Azure DevOps and other CI systems. | VERIFIED [S] [E5](https://docs.escape.tech/documentation/dast/ci-cd/github/), [E6](https://docs.escape.tech/documentation/automate/cli/) |

**B. Advisory / multi-request workflow**

| Dimension | Assessment | Status |
|---|---|---|
| Session / identity context | Several configured users. The "Main User is treated as the victim", and other users try to reach its data. | VERIFIED [S] [E2](https://docs.escape.tech/documentation/dast/multi-user-testing/) |
| Multi-request / cross-identity comparison | Configured under `security_tests.multi_user_access_control`. Different roles drive privilege-escalation tests, and the same role (or no role) drives tenant-isolation tests. Detection uses fingerprints, custom detectors or a **natural-language rule**. BOLA analysis needs at least 2 users, and `cross_user_memory_enabled` shares extracted state across users. | VERIFIED [S] [E2](https://docs.escape.tech/documentation/dast/multi-user-testing/), [E3](https://docs.escape.tech/documentation/reference/vulnerabilities/bola/), [E4](https://docs.escape.tech/documentation/reference/configuration-schemas/api-dast-rest/) |
| Effectiveness of BOLA/IDOR detection | Described as a "proprietary business logic testing engine". | VENDOR CLAIM [E1](https://escape.tech/product/dast), [E19](https://escape.tech/blog/ai-pentesting-agents/) |
| Provenance / traceability | Technical reports and CSV include full reproduction details, with cURL commands for APIs. The CLI exposes audit logs. | VERIFIED [S] [E17](https://docs.escape.tech/documentation/comply/issue-management/), [E22](https://docs.escape.tech/documentation/automate/cli/audit-logs/) |
| Proxy integration | No interception proxy is documented (UNKNOWN). REST scans import **Burp Suite Export** and **HAR** as well as OpenAPI, Postman and Insomnia. | VERIFIED [S] [E11](https://docs.escape.tech/documentation/dast/start-scan) |
| Human oversight | Configuration-first: YAML/profile rules, natural-language detection rules, and issue management. In-run approval gates: UNKNOWN. | VERIFIED [S] [E2](https://docs.escape.tech/documentation/dast/multi-user-testing/) |
| Privacy / data residency | **Scans originate from Escape's cloud,** or are tunnelled to it via a Private Location. AI runs on proprietary models on AWS, Azure LLM deployments and Cloudflare Workers AI. Escape says customer data is never used for training, but external AI services may retain data for up to 30 days. Customers can request that external AI features be disabled. SOC 2 Type II. Local model: none documented (UNKNOWN). | VENDOR CLAIM [S] [E10](https://docs.escape.tech/documentation/enterprise/privacy-and-security/); deployment VERIFIED [S] [E8](https://docs.escape.tech/documentation/asm/quickstart/) |
| Reporting / export | PDF compliance, executive and technical reports; single-issue PDF; CSV; API export jobs (beta). | VERIFIED [S] [E12](https://docs.escape.tech/documentation/governance/vulnerability-management), [E13](https://docs.escape.tech/documentation/automate/public-api/) |
| Switching cost vs Burp | Importing Burp exports eases onboarding of the API inventory. Findings and workflow then live in Escape's SaaS rather than in Burp. | VERIFIED [S] [E11](https://docs.escape.tech/documentation/dast/start-scan) |

**Overlap with AgenticVibe**

- **Overlap.** Among the eight, Escape's documented multi-user access-control testing (roles, tenants, a victim user, cross-user memory) is the feature set most directly comparable to AgenticVibe's role/access-matrix and cross-identity evidence goals. It can also start from Burp exports.
- **Documented differences:**
  - Escape is a SaaS scanner configured through profiles and YAML and driven from CI or its console, not an in-proxy analyst copilot.
  - Its AI processing is cloud-hosted.

---

### 3.6 Autorize (Burp extension)

**Profile**

| Field | Value | Status |
|---|---|---|
| Research date | 2026-10-21 | — |
| Edition / product | Autorize v1.9.4 on the BApp Store (last updated Feb 2026; author Barak Tawily). `PortSwigger/autorize` is a fork of `Quitten/Autorize`, with its latest commits on 2026-02-23/24. | VERIFIED [S] [A7](https://portswigger.net/bappstore/f9bbac8c4acf4aefa4d7dc92a991af2f); [D] [A1](https://github.com/PortSwigger/autorize), [A3](https://github.com/PortSwigger/autorize/commits/master) |
| Deployment | Runs inside Burp Suite (desktop), written in **Jython**, and needs the Jython standalone JAR. | VERIFIED [D] [A1](https://github.com/PortSwigger/autorize) |
| Licensing / pricing | The README calls it "open-source" but no licence is named and no LICENSE file is visible (UNKNOWN). Price: none stated; distributed through the BApp Store. | VERIFIED [D] [A4](https://github.com/Quitten/Autorize), [A8](https://github.com/Quitten/Autorize/tree/master) |

**A. Automated testing**

| Dimension | Assessment | Status |
|---|---|---|
| Discovery / crawl | None. It "passively monitors traffic generated by a high-privileged user" and replays it. | VERIFIED [D] [A1](https://github.com/PortSwigger/autorize) |
| Authenticated scanning | Replays with headers or cookies supplied for low-privileged users, plus an optional "Check unauthenticated" replay. | VERIFIED [D] [A1](https://github.com/PortSwigger/autorize), [A2](https://raw.githubusercontent.com/PortSwigger/autorize/master/README.md) |
| Budget / scope controls | Interception filters, including Burp Scope, "control which requests are analyzed". Request-count budgets: UNKNOWN. | VERIFIED [D] [A2](https://raw.githubusercontent.com/PortSwigger/autorize/master/README.md) |
| Confirmation / evidence | Each request is labelled Bypassed, Enforced or "Is enforced???". An enforcement detector uses fingerprints (string or regex in the body or headers, or content length). The README warns that "false positives or false negatives are possible". | VERIFIED [D] [A1](https://github.com/PortSwigger/autorize), [A2](https://raw.githubusercontent.com/PortSwigger/autorize/master/README.md) |
| CI integration | Not applicable; it is an interactive Burp extension. | UNKNOWN (none documented) |

**B. Advisory / multi-request workflow**

| Dimension | Assessment | Status |
|---|---|---|
| Session / identity context | Supports "multiple low-privileged users simultaneously", each with its own viewer. | VERIFIED [D] [A2](https://raw.githubusercontent.com/PortSwigger/autorize/master/README.md) |
| Multi-request / cross-identity comparison | This is the core function: each original request is compared with its replays per identity, in a request × user status table. | VERIFIED [D] [A1](https://github.com/PortSwigger/autorize) |
| Provenance / traceability | Original, modified and unauthenticated request/response viewers. Results export to **HTML or CSV**. | VERIFIED [D] [A1](https://github.com/PortSwigger/autorize), [A6](https://raw.githubusercontent.com/Quitten/Autorize/master/gui/export.py) |
| Proxy integration | Runs inside Burp and consumes Burp's proxied traffic. PortSwigger's docs recommend it for access-control testing. | VERIFIED [S] [B26](https://portswigger.net/burp/documentation/desktop/testing-workflow/vulnerabilities/access-controls/privilege-escalation) |
| Human oversight | The analyst configures users and filters and resolves "Is enforced???" results. | VERIFIED [D] [A1](https://github.com/PortSwigger/autorize) |
| Privacy / local model | No AI or LLM component is documented. Replays go only to the target. | VERIFIED [D] (absence of an AI component in the README) [A1](https://github.com/PortSwigger/autorize) |
| Reporting / export | HTML or CSV export. | VERIFIED [D] [A6](https://raw.githubusercontent.com/Quitten/Autorize/master/gui/export.py) |
| Switching cost vs Burp | Minimal: it installs into Burp. It needs a Jython runtime. | VERIFIED [D] [A1](https://github.com/PortSwigger/autorize) |

**Overlap with AgenticVibe**

- **Overlap.** Autorize overlaps AgenticVibe's cross-identity replay and comparison inside Burp.
- **Differences in scope:**
  - It uses heuristic response comparison with analyst-supplied fingerprints.
  - It has no LLM, no discovery, no engagement budget, and no application-state reasoning beyond the paired replays.
- **Complementary use.** Because both live in Burp, they can be used side by side. In that sense Autorize is a reference point for what the analyst already sees in a Burp-centric access-control workflow.

---

### 3.7 Strix (open-source AI agents)

**Profile**

| Field | Value | Status |
|---|---|---|
| Research date | 2026-10-21 | — |
| Edition / product | Strix open-source CLI agent, **v1.7.0** tagged 2026-10-05. Also Strix Cloud (`app.strix.ai`) and Enterprise (VPC or self-hosted). | VERIFIED [D] [S3](https://github.com/usestrix/strix/tags), [S1](https://github.com/usestrix/strix) |
| Deployment | A local CLI that requires a running Docker instance. Installs via script, pipx, uv or pip. | VERIFIED [D] [S1](https://github.com/usestrix/strix) |
| Licensing / pricing | Apache-2.0. The OSS agent is free; you pay your own model tokens. Pro is $29/seat/month, with pentests billed separately: a "Rightsized Pentest" costs $60–$300 and a "Full Audit" starts at $2,000. Enterprise is custom. | Licence: VERIFIED [D] [S1](https://github.com/usestrix/strix). Pricing: VERIFIED [S] [S9](https://www.strix.ai/pricing) |

**A. Automated testing**

| Dimension | Assessment | Status |
|---|---|---|
| Discovery / crawl | Targets can be live URLs, GitHub repos, local code, API contracts (OpenAPI, Swagger, Postman) and target lists. A "Graph of Agents" covers recon, exploitation and post-exploitation. | VERIFIED [D] [S2](https://raw.githubusercontent.com/usestrix/strix/main/README.md) |
| Authenticated scanning | Grey-box testing works by passing credentials through `--instruction` or an instruction file. | VERIFIED [D] [S2](https://raw.githubusercontent.com/usestrix/strix/main/README.md); [S] [S4](https://docs.strix.ai/usage/cli) |
| Budget / scope controls | <ul><li>`--max-budget` caps total LLM spend in USD across the root agent and every child agent. Sub-agents stop at 90% of the cap. Headless runs end with status "stopped"; interactive runs pause.</li><li>Scan modes are quick, standard and deep (deep is the default).</li><li>CI scans can be limited to the diff.</li><li>Caveat: a run that hits the cap can still exit 0, so the CI guide says to check `run.json`.</li><li>Network-level target scope enforcement: UNKNOWN. The agent guide only says "Only scan targets the user is authorized to test".</li></ul> | VERIFIED [S] [S4](https://docs.strix.ai/usage/cli), [S5](https://docs.strix.ai/usage/scan-modes), [S6](https://github.com/usestrix/strix/blob/main/skills/ci-security-scanning-with-strix/SKILL.md); [D] [S7](https://raw.githubusercontent.com/usestrix/strix/main/AGENTS.md) |
| Confirmation / evidence | Agents "validate them through actual proofs-of-concept". | VENDOR CLAIM [D] [S1](https://github.com/usestrix/strix) |
| CI integration | A GitHub Actions example. Headless mode exits non-zero when it finds vulnerabilities. SARIF output. | VERIFIED [D] [S1](https://github.com/usestrix/strix), [S7](https://raw.githubusercontent.com/usestrix/strix/main/AGENTS.md) |

**B. Advisory / multi-request workflow**

| Dimension | Assessment | Status |
|---|---|---|
| Session / identity context | Credentials are passed through instructions. Multiple identities as a first-class concept: UNKNOWN. | VERIFIED [D] [S2](https://raw.githubusercontent.com/usestrix/strix/main/README.md) |
| Multi-request / cross-identity comparison | None documented. | UNKNOWN |
| Provenance / traceability | Each run writes `strix_runs/<run>/` containing `penetration_test_report.md`, `vulnerabilities/*.md`, `vulnerabilities.json`, `findings.sarif` (SARIF 2.1.0) and `run.json` (with status and `llm_usage.cost`). Findings carry CVSS and OWASP classification. | VERIFIED [D] [S7](https://raw.githubusercontent.com/usestrix/strix/main/AGENTS.md), [S2](https://raw.githubusercontent.com/usestrix/strix/main/README.md) |
| Proxy integration | The agents include an "HTTP Interception Proxy … with Caido". Burp integration: UNKNOWN. | VERIFIED [D] [S2](https://raw.githubusercontent.com/usestrix/strix/main/README.md) |
| Human oversight | Interactive TUI or headless mode. A local false-positive triage feature for the TUI and viewer is an **open** PR (#1326, 2026-09-16), not merged at check time. | VERIFIED [D] [S10](https://github.com/usestrix/strix/pull/1326); [S] [S4](https://docs.strix.ai/usage/cli) |
| Privacy / local model | The provider is configurable, and `LLM_API_BASE` supports local setups "such as Ollama or LM Studio". Telemetry uses PostHog and Scarf with opt-out via `STRIX_TELEMETRY=0`. Strix says targets, code and findings are not collected; the telemetry details are a vendor claim. The local viewer states "Nothing leaves your machine". | Local model: VERIFIED [D] [S1](https://github.com/usestrix/strix). Telemetry: VERIFIED/VENDOR CLAIM [S] [S8](https://github.com/usestrix/strix/blob/main/strix/telemetry/README.md) |
| Reporting / export | Markdown report, JSON and SARIF. | VERIFIED [D] [S7](https://raw.githubusercontent.com/usestrix/strix/main/AGENTS.md) |
| Switching cost vs Burp | A separate CLI plus Docker runtime. It ingests API contracts. Burp-export ingestion: UNKNOWN. | VERIFIED [D] [S2](https://raw.githubusercontent.com/usestrix/strix/main/README.md) |

**Overlap with AgenticVibe**

- **Overlap.** Strix is the open-source agent whose documented controls most resemble AgenticVibe's bounded engagement mode:
  - an explicit cost budget that cascades to sub-agents;
  - scan depth modes;
  - a local-model option;
  - structured per-run artifacts.
- **Documented differences:**
  - Strix is a standalone agent: it uses Caido internally and has no Burp integration.
  - It is LLM-driven end to end, with exploitation by PoC.
  - It does not document a cross-identity matrix or proxy-history advisory analysis.

---

### 3.8 ProjectDiscovery Nuclei (with Neo noted)

**Profile**

| Field | Value | Status |
|---|---|---|
| Research date | 2026-10-21 | — |
| Edition / product | Nuclei OSS CLI, latest release **v3.11.1** ("08 Aug"; the year is not shown on the page). Earlier releases on the same page: v3.11.0 (06 Jul), v3.10.0 (30 Jun), v3.9.0 (10 Jun) and v3.8.0 (18 Apr). Also the ProjectDiscovery Cloud dashboard (free tier) and **Neo**, an "AI security engineer" SaaS. | VERIFIED [D] [N2](https://github.com/projectdiscovery/nuclei/releases), [N3](https://github.com/projectdiscovery/nuclei/releases/tag/v3.11.1); [S] [N13](https://projectdiscovery.io/blog/neo-v1) |
| Deployment | A local CLI. Neo is SaaS; Enterprise can have a dedicated VPC. | VERIFIED [D] [N1](https://raw.githubusercontent.com/projectdiscovery/nuclei/dev/README.md); [S] [N10](https://projectdiscovery.io/pricing) |
| Licensing / pricing | Nuclei is MIT and free. Neo plans: <ul><li>**Free:** 1 seat, open-weight models picked by Neo.</li><li>**Pay as you go:** from $200/seat/month on the pricing page, but "$250/mo per seat" on a sign-in page (conflict).</li><li>**Enterprise:** custom, with bring-your-own model keys.</li></ul>Usage is metered in credits. | Licence: VERIFIED [D] [N1](https://raw.githubusercontent.com/projectdiscovery/nuclei/dev/README.md). Neo pricing: VERIFIED [S] [N10](https://projectdiscovery.io/pricing), [N11](https://docs.neo.projectdiscovery.io/concepts/cost) |

**A. Automated testing**

| Dimension | Assessment | Status |
|---|---|---|
| Discovery / crawl | Nuclei is a template scanner, not a crawler. Inputs can be lists, **Burp XML**, proxify JSONL/YAML and OpenAPI/Swagger. A built-in crawler: UNKNOWN. | VERIFIED [S] [N4](https://docs.projectdiscovery.io/opensource/nuclei/input-formats) |
| Authenticated scanning | `-sf` takes a "config file containing secrets for nuclei authenticated scan". Also custom headers (`-H`) and client certificates. | VERIFIED [D] [N1](https://raw.githubusercontent.com/projectdiscovery/nuclei/dev/README.md); [S] [N12](https://projectdiscovery.io/blog/nuclei-3-2) |
| Budget / scope controls | Flags: `-rl` (default 150 req/s), `-c` (25), `-bs` (25), `-mhe` (30 errors per host), `-host-backoff`, `-eh` to exclude hosts, `-cs`/`-cos` for fuzz in-scope and out-of-scope regexes, `-timeout` and `-retries`. DAST (fuzz) templates run only with `-dast`. | VERIFIED [D] [N1](https://raw.githubusercontent.com/projectdiscovery/nuclei/dev/README.md); [S] [N5](https://projectdiscovery.io/blog/nuclei-fuzzing-for-unknown-vulnerabilities) |
| Confirmation / evidence | Deterministic template matchers and extractors. `-irr` includes request/response pairs in JSON, JSONL and Markdown findings. `-llm` enables LLM-based matchers and extractors. v3.10.0 validates code-template signatures before DAST loading. | VERIFIED [D] [N1](https://raw.githubusercontent.com/projectdiscovery/nuclei/dev/README.md), [N2](https://github.com/projectdiscovery/nuclei/releases) |
| CI integration | The official `nuclei-action` exports SARIF for upload to GitHub code scanning. | VERIFIED [S] [N8](https://github.com/projectdiscovery/nuclei-action), [N9](https://docs.projectdiscovery.io/opensource/nuclei/ci-cd) |

**B. Advisory / multi-request workflow**

| Dimension | Assessment | Status |
|---|---|---|
| Session / identity context | A secrets file for authentication. | VERIFIED [D] [N1](https://raw.githubusercontent.com/projectdiscovery/nuclei/dev/README.md) |
| Multi-request / cross-identity comparison | None documented. | UNKNOWN |
| Provenance / traceability | Findings carry the template ID and request/response pairs (`-irr`). Template signature validation is documented. | VERIFIED [D] [N1](https://raw.githubusercontent.com/projectdiscovery/nuclei/dev/README.md), [N2](https://github.com/projectdiscovery/nuclei/releases) |
| Proxy integration | `-proxy` takes a list of HTTP/SOCKS5 proxies. `-dtp` is a "dast proxy mode (fuzz live traffic proxied through nuclei)". Burp XML exports can be imported. | VERIFIED [D] [N1](https://raw.githubusercontent.com/projectdiscovery/nuclei/dev/README.md); [S] [N4](https://docs.projectdiscovery.io/opensource/nuclei/input-formats) |
| Human oversight | CLI-driven with deterministic templates. `-ai "<prompt>"` generates a template and runs it immediately. | VERIFIED [D] [N1](https://raw.githubusercontent.com/projectdiscovery/nuclei/dev/README.md); [S] [N6](https://docs.projectdiscovery.io/opensource/nuclei/running) |
| Privacy / local model | Scanning runs locally. `-ai` needs a ProjectDiscovery Cloud API key and internet access, and stores generated templates both locally and in the PD cloud account (documented cap: 100 queries/day). `-llm-provider` supports **ollama, llamacpp, vllm, lmstudio** and others, with `-llm-base-url`. `-dashboard` uploads results to the PD cloud (opt-in flag). | VERIFIED [D] [N1](https://raw.githubusercontent.com/projectdiscovery/nuclei/dev/README.md); [S] [N6](https://docs.projectdiscovery.io/opensource/nuclei/running), [N7](https://github.com/projectdiscovery/nuclei/pull/6053) |
| Reporting / export | JSON, JSONL, SARIF, Markdown and PDF (`-pe`). | VERIFIED [D] [N1](https://raw.githubusercontent.com/projectdiscovery/nuclei/dev/README.md) |
| Switching cost vs Burp | It imports Burp XML exports and can be pointed at an upstream proxy. Templates use a YAML DSL. | VERIFIED [D] [N1](https://raw.githubusercontent.com/projectdiscovery/nuclei/dev/README.md); [S] [N4](https://docs.projectdiscovery.io/opensource/nuclei/input-formats) |

**Overlap with AgenticVibe**

- **Overlap.** Nuclei overlaps AgenticVibe's deterministic-validator layer: repeatable, rule-defined checks that emit request/response evidence. It can consume Burp exports, and its LLM matchers can use local providers.
- **No documented support for:** cross-identity comparison, role matrices, or an analyst-in-proxy advisory flow.
- **Cloud dependency.** Its `-ai` generation path depends on ProjectDiscovery Cloud.
- **Neo.** Neo, ProjectDiscovery's SaaS AI agent, is a separate, cloud-hosted product.

---

## 4. Cross-cutting view

This section restates documented facts from §3 only. It is not a ranking.

| Tool | Licence model | Relation to Burp | Documented multi-identity comparison | Documented local-model option | Automated engagement | Data leaves the machine for AI? |
|---|---|---|---|---|---|---|
| Burp Pro + AI / AT | Commercial | Host | Compare site maps; BAC checks; BApps | Not documented | Scanner; Burp AT (beta) | Yes: PortSwigger plus OpenAI and/or Anthropic |
| ZAP | Apache-2.0 | Separate proxy (chainable; HAR import) | Access Control Testing add-on | Yes (Ollama, LM Studio) | Yes | Only if a remote LLM provider is configured |
| Caido | Proprietary (freemium) | Replacement proxy | Autorize, AuthMatrix and Authify plugins | Assistant: no. Shift: via a LiteLLM gateway, local use undocumented | Scanner plugin and workflows | Assistant: OpenAI (US). Shift: Caido backend plus models |
| XBOW | Proprietary SaaS | None documented | Multi-account (vendor claim) | Not documented | Yes | Yes (SaaS) |
| Escape | Proprietary SaaS | Imports Burp exports | `multi_user_access_control` | Not documented | Yes | Yes (SaaS) |
| Autorize | Open source (licence unstated) | Runs in Burp | Core function | n/a (no AI) | No | No AI component |
| Strix | Apache-2.0 | None (uses Caido internally) | Not documented | Yes (`LLM_API_BASE`) | Yes | Depends on the provider; telemetry can be opted out |
| Nuclei | MIT | Imports Burp XML; proxy mode | Not documented | Yes for `-llm`; `-ai` needs PD Cloud | Yes (templates) | Only with `-ai`, `-dashboard` or a remote LLM |

## 5. Facts that could not be verified, and conflicts found

**Conflicting sources**

1. **Burp AI data retention.** PortSwigger's pages disagree: "retained indefinitely" vs "no fixed deletion schedule" ([B7](https://portswigger.net/burp/documentation/burp-ai/trust/data-storage), [B8](https://portswigger.net/burp/documentation/ai-features/trust)).
2. **ZAP LLM Support status.** The July 2026 update says "alpha, not released", while the 2026-08-07 post announces the launch ([Z11](https://www.zaproxy.org/blog/2026-08-06-zap-updates-july-2026/), [Z7](https://www.zaproxy.org/blog/2026-08-07-zap-llm-support/)).
3. **Caido AI providers.** The Assistant docs say there are no other provider keys and no local LLMs, while marketing says teams can bring their own keys ([C4](https://raw.githubusercontent.com/caido/documentation/main/src/app/guides/assistant_model.md) vs [C11](https://www.caido.io/orgs/)).
4. **Caido prices.** $200/yr vs $20/mo, from different page versions.
5. **XBOW price.** $4,000 vs $6,000 starting price ([X2](https://xbow.com/news/announcing-xbow-pentest-on-demand-for-security-at-machine-speed), [X3](https://xbow.com/blog/pentest-on-demand)).
6. **XBOW model processing region.** Global providers vs EU-served models ([X10](https://xbow.com/blog/xbow-data-residency-now-available-in-australia-canada-and-japan), [X11](https://xbow.com/blog/xbow-available-eu-data-residency)).
7. **Neo price.** $200 vs $250 per seat per month.

**Not verified (UNKNOWN)**

8. **Burp pricing gaps:** Burp AT prices, Burp AI Subscription price, and Burp Suite DAST price.
9. **Local or self-hosted models for Burp AI / Burp AT:** not documented.
10. **Burp core role matrix:** none found.
11. **Caido:** current Team price; whether Shift PR #104 is merged; local-model support end to end; a built-in crawler; Burp project import.
12. **XBOW:** cost/request budget controls, Burp/proxy integration, report format, how credentials are stored, and the number of roles per assessment.
13. **Escape:** a duration cap for standard DAST, in-run approval gates, and a local model option.
14. **Autorize:** its licence (no LICENSE file visible).
15. **Strix:** network-level scope enforcement, multi-identity support, and Burp-export ingestion.
16. **Release years not shown on GitHub pages:** Nuclei v3.11.1 ("08 Aug") and Caido v0.58.3 ("04 Sep"). ZAP 2.17.0 is dated by its 2025-12-15 blog post.
17. **Unexecuted:** none of the security, accuracy or "no false positive" claims was tested, and none of the tools was executed.

**Method caveat**

18. Vendor domains could not be fetched directly from this sandbox, so all [S] cells rely on search-tool extraction of the named primary page. Spot-check them before external use.

---

## 6. Source list (every URL used)

The tag after each URL shows how it was retrieved: [D] for a direct fetch, [S] for search-tool extraction restricted to the primary domain.

### PortSwigger / Burp (B)
- B1 https://portswigger.net/pricing [S]
- B2 https://portswigger.net/support/burp-suite-licensing-model [S]
- B3 https://portswigger.net/burp/documentation/desktop/burp-ai [S]
- B4 https://portswigger.net/burp/releases/professional-community-2025-2-3 [S]
- B5 https://portswigger.net/blog/welcome-to-the-next-generation-of-burp-suite-elevate-your-testing-with-burp-ai [S]
- B6 https://portswigger.net/burp/documentation/burp-ai/trust [S]
- B7 https://portswigger.net/burp/documentation/burp-ai/trust/data-storage [S]
- B8 https://portswigger.net/burp/documentation/ai-features/trust [S]
- B9 https://portswigger.net/burp/documentation/desktop/extend-burp/extensions/creating/creating-ai-extensions [S]
- B10 https://portswigger.net/blog/introducing-burp-at [S]
- B11 https://portswigger.net/burp/burp-at [S]
- B12 https://portswigger.net/burp/burp-at/pricing [S]
- B13 https://portswigger.net/burp/releases/professional-community-2026-7 [S]
- B14 https://portswigger.net/burp/documentation/desktop/burp-at/setting-up [S]
- B15 https://portswigger.net/burp/documentation/desktop/burp-at/prompting [S]
- B16 https://portswigger.net/burp/documentation/desktop/running-scans/webapp-scans/full-crawl-and-audit [S]
- B17 https://portswigger.net/burp/ai/capabilities [S]
- B18 https://portswigger.net/burp/documentation/scanner/scan-configurations/burp-scanner-built-in-configs [S]
- B19 https://portswigger.net/burp/documentation/desktop/running-scans/managing-resource-pools [S]
- B20 https://portswigger.net/burp/documentation/desktop/running-scans/reporting [S]
- B21 https://portswigger.net/burp/documentation/dast/user-guide/ci-cd [S]
- B22 https://portswigger.net/burp/documentation/dast/user-guide/ci-cd/ci-driven-scans/example-integrations/integrate-github [S]
- B23 https://portswigger.net/burp/dast/hosting-options [S]
- B24 https://portswigger.net/burp/documentation/dast/setup/self-hosted/which-deployment-option-is-right-for-me [S]
- B25 https://portswigger.net/burp/documentation/desktop/tools/target/site-map/comparing [S]
- B26 https://portswigger.net/burp/documentation/desktop/testing-workflow/vulnerabilities/access-controls/privilege-escalation [S]
- B27 https://portswigger.net/burp/ai/subscriptions [S]
- B28 https://portswigger.net/burp/documentation/desktop/burp-ai/ai-credits [S]
- B29 https://portswigger.net/burp/releases/professional-community-2025-3 [S]
- B30 https://portswigger.net/burp/documentation/dast/setup/self-hosted/ci-driven-no-dashboard [S]
- B31 https://portswigger.net/burp/documentation/dast/user-guide/working-with-scans/best-scanning-practices [S]
- B32 https://portswigger.net/burp/documentation/dast/user-guide/work-with-scan-results/generate-reports [S]
- B33 https://portswigger.net/burp/documentation/desktop/tools/repeater/http-messages/ai-explainer [S]
- B34 https://portswigger.net/burp/documentation/desktop/tools/repeater/http-messages/burp-ai-in-repeater [S]
- B35 https://portswigger.net/blog/from-capable-ai-models-to-trusted-security-testing [S] (consulted)

### ZAP (Z)
- Z1 https://github.com/zaproxy/zaproxy [D]
- Z2 https://github.com/zaproxy/zaproxy/releases [D]
- Z3 https://github.com/zaproxy/zaproxy/releases/tag/v2.17.0 [D]
- Z4 https://www.zaproxy.org/blog/2025-12-15-zap-2-17-0/ [S]
- Z5 https://www.zaproxy.org/docs/desktop/addons/access-control-testing/ [S]
- Z6 https://www.zaproxy.org/docs/desktop/ui/tlmenu/report/ [S]
- Z7 https://www.zaproxy.org/blog/2026-08-07-zap-llm-support/ [S]
- Z8 https://www.zaproxy.org/docs/desktop/addons/llm-support/ [S]
- Z9 https://www.zaproxy.org/docs/addons/llm/changelog/ [S]
- Z10 https://www.zaproxy.org/docs/desktop/addons/mcp-integration/ [S]
- Z11 https://www.zaproxy.org/blog/2026-08-06-zap-updates-july-2026/ [S]
- Z12 https://www.zaproxy.org/docs/desktop/ui/dialogs/options/ascan/ [S]
- Z13 https://www.zaproxy.org/docs/desktop/addons/spider/options/ [S]
- Z14 https://www.zaproxy.org/docs/docker/about/ [S]
- Z15 https://www.zaproxy.org/blog/2020-05-15-dynamic-application-security-testing-with-zap-and-github-actions/ [S]
- Z16 https://www.zaproxy.org/docs/desktop/addons/report-generation/templates/ [S]
- Z17 https://www.zaproxy.org/docs/desktop/start/features/authentication/ [S]
- Z18 https://www.zaproxy.org/docs/desktop/start/features/contexts/ [S]
- Z19 https://www.zaproxy.org/docs/desktop/start/features/sessionmanagement/ [S]
- Z20 https://www.zaproxy.org/docs/desktop/start/ [S]
- Z21 https://www.zaproxy.org/docs/desktop/addons/llm-support/chat/ [S]
- Z22 https://www.zaproxy.org/docs/desktop/addons/authentication-helper/ [S]
- Z23 https://www.zaproxy.org/docs/desktop/addons/llm-support/options/ [S]
- Z24 https://www.zaproxy.org/docs/desktop/addons/report-generation/automation/ [S]
- Z25 https://www.zaproxy.org/docs/desktop/addons/import-export/ [S]
- Z26 https://www.zaproxy.org/docs/desktop/addons/network/options/ [S]
- Z27 https://www.zaproxy.org/pdf/ZAPGettingStartedGuide-2.17.pdf [S]
- Z28 https://www.zaproxy.org/docs/desktop/start/features/httpsessions/ [S]
- Z29 https://www.zaproxy.org/docs/desktop/releases/2.17.0/ [S]
- Z30 https://www.zaproxy.org/docs/api/ [S]
- Z31 https://www.zaproxy.org/docs/desktop/addons/network/api/ [S] (consulted)

### Caido (C)
- C1 https://www.caido.io/pricing/ [S]
- C2 https://www.caido.io/compare/burpsuite/ [S]
- C3 https://www.caido.io/blog/2025-08-21-localized-pricing/ [S]
- C4 https://raw.githubusercontent.com/caido/documentation/main/src/app/guides/assistant_model.md [D]
- C5 https://raw.githubusercontent.com/caido/documentation/main/src/app/concepts/cloud.md [D]
- C6 https://github.com/caido-community/shift [D]
- C7 https://raw.githubusercontent.com/caido/documentation/main/src/app/tutorials/litellm.md [D]
- C8 https://github.com/caido-community/shift/pull/104 [S]
- C9 https://www.caido.io/blog/2025-07-16-shift-acquisition/ [S]
- C10 https://www.caido.io/blog/2026-03-24-ai-enhanced-hacking/ [S]
- C11 https://www.caido.io/orgs/ [S]
- C12 https://github.com/caido-community/autorize [D]
- C13 https://docs.caido.io/app/tutorials/scanner [S]
- C14 https://github.com/caido-community/scanner [S]
- C15 https://docs.caido.io/burp-suite/core/project-and-configuration [S]
- C16 https://docs.caido.io/burp-suite/extensibility/extensions [S]
- C17 https://docs.caido.io/burp-suite/core/ai [S]
- C18 https://docs.caido.io/app/guides/docker [S]
- C19 https://docs.caido.io/app/tutorials/headless_orchestration [S]
- C20 https://docs.caido.io/app/concepts/pat [S]
- C21 https://docs.caido.io/app/concepts/instance_authentication [S]
- C22 https://github.com/caido/caido/releases [D]
- C23 https://docs.caido.io/app/guides/scopes_defining [S]
- C24 https://docs.caido.io/app/guides/workflows_findings [S]
- C25 https://docs.caido.io/app/guides/exports_requests [S]
- C26 https://docs.caido.io/app/tutorials/mcp [S]
- C27 https://github.com/caido [D]
- C28 https://docs.caido.io/app/tutorials/shift [S]
- C29 https://docs.caido.io/burp-suite/core/scans [S]

### XBOW (X)
- X1 https://xbow.com/pricing [S]
- X2 https://xbow.com/news/announcing-xbow-pentest-on-demand-for-security-at-machine-speed [S]
- X3 https://xbow.com/blog/pentest-on-demand [S]
- X4 https://xbow.com/blog/top-1-how-xbow-did-it [S]
- X5 https://xbow.com/platform [S]
- X6 https://xbow.com/blog/autonomous-agent-safety-guardrails [S]
- X7 https://xbow.com/blog/introducing-assessment-guidance [S]
- X8 https://docs.xbow.com/console/reference/authentication-methods/ [S]
- X9 https://xbow.com/blog/xbow-finds-idors-high-accuracy-ambiguous-context [S]
- X10 https://xbow.com/blog/xbow-data-residency-now-available-in-australia-canada-and-japan [S]
- X11 https://xbow.com/blog/xbow-available-eu-data-residency [S]
- X12 https://xbow.com/api [S]
- X13 https://xbow.com/blog/introducing-the-xbow-public-api [S]
- X14 https://docs.xbow.com/ [S]
- X15 https://xbow.com/videos/xbow-run-autonomous-penetration-test [S]
- X16 https://xbow.com/ [S]
- X17 https://xbow.com/blog/xbow-is-now-available-on-aws-marketplace [S]
- X18 https://xbow.com/blog/we-ran-1060-autonomous-attacks [S]

### Escape (E)
- E1 https://escape.tech/product/dast [S]
- E2 https://docs.escape.tech/documentation/dast/multi-user-testing/ [S]
- E3 https://docs.escape.tech/documentation/reference/vulnerabilities/bola/ [S]
- E4 https://docs.escape.tech/documentation/reference/configuration-schemas/api-dast-rest/ [S]
- E5 https://docs.escape.tech/documentation/dast/ci-cd/github/ [S]
- E6 https://docs.escape.tech/documentation/automate/cli/ [S]
- E7 https://docs.escape.tech/documentation/automate/ci-cd/incremental-scanning/ [S]
- E8 https://docs.escape.tech/documentation/asm/quickstart/ [S]
- E9 https://docs.escape.tech/documentation/automate/cli/configuration/ [S]
- E10 https://docs.escape.tech/documentation/enterprise/privacy-and-security/ [S]
- E11 https://docs.escape.tech/documentation/dast/start-scan [S]
- E12 https://docs.escape.tech/documentation/governance/vulnerability-management [S]
- E13 https://docs.escape.tech/documentation/automate/public-api/ [S]
- E14 https://docs.escape.tech/documentation/ai-pentesting/scope/ [S]
- E15 https://escape.tech/blog/escape-now-available-on-aws-marketplace/ [S]
- E16 https://escape.tech/terms [S]
- E17 https://docs.escape.tech/documentation/comply/issue-management/ [S]
- E18 https://escape.tech/blog/reproduce-complex-exploits-multi-step-custom-rules/ [S]
- E19 https://escape.tech/blog/ai-pentesting-agents/ [S]
- E20 https://docs.escape.tech/documentation/reference/configuration-schemas/asm/ [S]
- E21 https://escape.tech/blog/what-is-ai-pentesting/ [S]
- E22 https://docs.escape.tech/documentation/automate/cli/audit-logs/ [S]

### Autorize (A)
- A1 https://github.com/PortSwigger/autorize [D]
- A2 https://raw.githubusercontent.com/PortSwigger/autorize/master/README.md [D]
- A3 https://github.com/PortSwigger/autorize/commits/master [D]
- A4 https://github.com/Quitten/Autorize [D]
- A5 https://github.com/Quitten/Autorize/tree/master/gui [D]
- A6 https://raw.githubusercontent.com/Quitten/Autorize/master/gui/export.py [D]
- A7 https://portswigger.net/bappstore/f9bbac8c4acf4aefa4d7dc92a991af2f [S]
- A8 https://github.com/Quitten/Autorize/tree/master [D]

### Strix (S)
- S1 https://github.com/usestrix/strix [D]
- S2 https://raw.githubusercontent.com/usestrix/strix/main/README.md [D]
- S3 https://github.com/usestrix/strix/tags [D]
- S4 https://docs.strix.ai/usage/cli [S]
- S5 https://docs.strix.ai/usage/scan-modes [S]
- S6 https://github.com/usestrix/strix/blob/main/skills/ci-security-scanning-with-strix/SKILL.md [S]
- S7 https://raw.githubusercontent.com/usestrix/strix/main/AGENTS.md [D]
- S8 https://github.com/usestrix/strix/blob/main/strix/telemetry/README.md [S]
- S9 https://www.strix.ai/pricing [S]
- S10 https://github.com/usestrix/strix/pull/1326 [D]

### ProjectDiscovery / Nuclei (N)
- N1 https://raw.githubusercontent.com/projectdiscovery/nuclei/dev/README.md [D]
- N2 https://github.com/projectdiscovery/nuclei/releases [D]
- N3 https://github.com/projectdiscovery/nuclei/releases/tag/v3.11.1 [D]
- N4 https://docs.projectdiscovery.io/opensource/nuclei/input-formats [S]
- N5 https://projectdiscovery.io/blog/nuclei-fuzzing-for-unknown-vulnerabilities [S]
- N6 https://docs.projectdiscovery.io/opensource/nuclei/running [S]
- N7 https://github.com/projectdiscovery/nuclei/pull/6053 [S]
- N8 https://github.com/projectdiscovery/nuclei-action [S]
- N9 https://docs.projectdiscovery.io/opensource/nuclei/ci-cd [S]
- N10 https://projectdiscovery.io/pricing [S]
- N11 https://docs.neo.projectdiscovery.io/concepts/cost [S]
- N12 https://projectdiscovery.io/blog/nuclei-3-2 [S]
- N13 https://projectdiscovery.io/blog/neo-v1 [S]

### Adjacent tools (J)
- J1 https://github.com/KeygraphHQ/shannon [D]
- J2 https://github.com/GreyDGL/PentestGPT [D]
- J3 https://github.com/SecurityInnovation/AuthMatrix [D]
- J4 https://github.com/SecurityInnovation/AuthMatrix/commits/master [D]
- J5 https://www.stackhawk.com/blog/dynamic-application-security-testing-tools-comparison/ [S]
- J6 https://www.stackhawk.com/ [S]
- J7 https://www.invicti.com/pricing [S]
- J8 https://www.acunetix.com/pricing/ [S]
- J9 https://www.invicti.com/blog/web-security/how-ai-enhances-dast-on-invicti-platform [S]
- J10 https://www.acunetix.com/comparisons/acunetix-vs-invicti/ [S]
