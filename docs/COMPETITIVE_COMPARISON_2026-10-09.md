# Competitive comparison — 2026-10-09

This is the current R26 comparison. It supersedes competitive conclusions in
`COMPETITIVE_LANDSCAPE.md`, whose older research remains preserved. Selection:
exactly eight distinct alternatives spanning analyst tooling, developer DAST,
hosted assessment and self-hosted research frameworks. They address overlapping
jobs, but are not interchangeable editions of one product. Sources below were
read on 2026-10-08/09; no competitor was installed or evaluated in this loop.

Every capability and data-policy statement below is a publisher claim, not our
hands-on verification. Unknown means not established by the cited material.
Prices are deliberately not inferred from old reviews, repository popularity,
free trials or open-source licenses. Procurement requires a current quotation
or edition-specific price and contractual data terms.

| Alternative and edition examined | Workflow / deployment | Data handling boundary stated by publisher | Price / cost evidence | Relation to this project and primary source |
|---|---|---|---|---|
| Burp Suite Professional, including Burp AI and Burp AT | Analyst tooling; AT acts through Burp tools, AI assists individual tools. | AI requests use PortSwigger infrastructure; vendor says its AI providers do not store requests. This does not mean inference is local. | Current license and AI charges unknown in this review. | Closest existing analyst workspace; harness is an extension/complement. [AI features and editions](https://portswigger.net/burp/documentation/ai-features). |
| ZAP with Automation Framework | Local application or stable container; YAML automation includes passive scanning and report jobs. | Local execution is supported; telemetry, add-on and remote-service policies were not audited. No zero-egress claim. | Current support/operating costs unknown; no numerical price comparison. | Established proxy/automation alternative; not evidence that harness replaces its coverage. [Official framework](https://www.zaproxy.org/docs/automate/automation-framework/). |
| Invicti enterprise DAST, On Demand / on-premises | Application/API scanning; vendor describes AWS-hosted and customer-environment installations. | Requests/responses, findings and configured authentication data are stored in the chosen environment. Exact retention and deployment terms require agreement. | Edition-specific quotation unknown. | Team scanning alternative; deployment comparison must specify edition. [Security and data collection](https://www.invicti.com/compliance). |
| StackHawk HawkScan and StackHawk Platform | Developer DAST; scanner runs as Docker/CLI, including locally or in CI. Results go to the platform. | Local scanner execution does not keep all results local. Exact platform retention/residency unknown here. | Current plan and usage costs unknown. | CI workflow alternative, not a passive-only captured-review substitute. [Scanner/platform architecture](https://docs.stackhawk.com/hawkscan/). |
| Escape AI Pentesting | Managed assessment platform; current FAQ describes its Cascade assessment workflow. On-premises availability unknown here. | Vendor describes organization-scoped context, AI policy and commercial-provider zero-retention agreements **where available**; no universal zero-retention inference. | Current quotation unknown. | Managed assessment alternative; claims about business-logic depth are not comparative measurements. [Product and data FAQ](https://docs.escape.tech/documentation/ai-pentesting/faq/). |
| PentestGPT, GreyDGL repository, v1.0 agentic description | Locally installed/Docker framework; autonomous mode uses Claude Code or Codex backends. Wider providers, including Ollama, are documented for the separate interactive legacy mode. | Data boundary depends on selected mode/backend; local orchestration does not establish local inference. Retention of all integrations unknown. | MIT source license; model, infrastructure and operational costs unmeasured. | Research framework alternative; avoid conflating legacy multi-provider support with the autonomous mode. [Official repository](https://github.com/GreyDGL/PentestGPT). |
| PentAGI, vxcontrol repository | Self-hosted framework, container execution and persistent PostgreSQL state; documents multiple providers including Ollama. | Provider, external-search and monitoring configuration matter. Self-hosting alone is not proof of zero egress or isolation. | MIT source license; provider, hardware and operations costs unmeasured. | Broader automation research alternative; not tested in this loop. [Official repository](https://github.com/vxcontrol/pentagi), [deployment/provider README](https://raw.githubusercontent.com/vxcontrol/pentagi/main/README.md). |
| XBOW platform, multi-tenant SaaS described in current docs | Hosted assessment service; AWS US, with Europe/Singapore residency options described as private preview. Self-hosting unknown here. | Vendor says training needs express customer permission; retention follows its policy. Regional availability and contractual guarantees need confirmation. | Current commercial quotation unknown. | Hosted assessment alternative; no comparable efficacy study was performed. [Trust and data handling](https://docs.xbow.com/console/get-started/trust-and-safety/). |

AgenticVibe's supported positioning for this remediation is a Burp copilot for
reviewing supplied HTTP captures, with bounded passive inference accounting and
explicit evidence limitations. It complements established analyst and scanning
workflows. Local inference is conditional on configuration and the documented
[privacy boundaries](PRIVACY_BOUNDARIES.md) and [data lifecycle](DATA_LIFECYCLE.md):
optional providers, advisory lookups, logs, raw databases and exports all matter.
There is no verified replacement, legal-compliance, superior recall, unique
discovery, analyst-time reduction or token-saving claim. R25 practical studies,
R19 intact packaging and R28 release adjudication remain independent open gates.

R26 disposition: source-supported documentation correction; comparative
effectiveness is withheld pending R25, and operator workflow verification remains
under R20. Historical competitive prose must not be used as current sales proof.
