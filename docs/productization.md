# ScopeRook product and pricing outline

## Position

ScopeRook should sell a reliable authorization, research, synthetic-validation, evidence, and reporting workflow for security agents. It should not sell a promise to find bounties, access to exploit code, or unrestricted target automation.

The useful differentiator is local-first privacy with a bring-your-own-cloud sandbox: sensitive engagement records stay on the researcher's machine, while an optional disposable worker runs only reviewed synthetic fixtures in the customer's cloud account.

## Initial offer

Run a free public beta until at least ten outside researchers have completed a full workflow and several use it repeatedly. Measure activation, weekly retained use, reports produced from evidence, time saved, support load, and sandbox-job cost. Do not choose pricing from download count.

After validation:

| Plan | Suggested price | Included value |
| --- | ---: | --- |
| Community | Free | Local MCP, scope records, current public-source lookups, existing-tool routing, sanitized HAR/OpenAPI import, symbolic simulation, bundled synthetic labs, local evidence files |
| Pro | $19/month or $190/year | Signed policy snapshots and change alerts, private lab packs, richer evidence export, job history, update channel, BYOC Oracle orchestration, individual commercial use |
| Team | $49/user/month, three-seat minimum | Shared policy packs, role controls, centralized audit records, reusable team labs, support, and organization billing |
| Enterprise | Custom | Self-hosted control plane, SSO, retention controls, deployment review, procurement, and support commitments |

Cloud compute is separate. With BYOC, the customer pays Oracle directly and ScopeRook charges for orchestration. If managed compute is added later, include a small monthly allowance and require explicit top-ups with a hard spending cap. Never silently pass through uncapped usage.

## Pricing rules

- Charge for workflow, provenance, isolation controls, updates, collaboration, and support. Public vulnerability records remain attributed source material.
- Do not take a percentage of bug-bounty awards. Accepted findings and payout timing are outside the product's control, and success fees would encourage exaggerated impact and unsafe testing.
- Do not charge per failed lab or rejected authorization check. Usage charging should apply only to a successfully started managed worker.
- Keep a useful free tier. Security researchers are price-sensitive and need to verify that the tool fits their process before paying.
- Publish exact limits, cancellation, data handling, retention, and refund terms in plain language.

## Before charging

- Select a repository license and decide which cloud and team components, if any, remain proprietary. Apache-2.0 maximizes adoption; AGPL protects hosted improvements but can slow enterprise adoption.
- Review the redistribution, attribution, and commercial-use terms for every external data source. Prefer live links and normalized metadata over repackaging third-party exploit content.
- Add signed releases, an update provenance story, a security policy, vulnerability reporting address, privacy notice, acceptable-use terms, and a clear statement that program authorization remains target-specific.
- Keep telemetry opt-in. Never collect target URLs, credentials, program text, evidence bodies, or report drafts by default.
- Validate willingness to pay with a checkout-free pricing page and interviews before building billing.

The first price to test is **$19/month for Pro**. It is low enough for an independent hunter, leaves room below established professional testing suites, and can support a local-first product when cloud compute remains BYOC.

## Current price anchors

Verified from official product pages on 2026-10-04:

- Caido positions its individual plan at roughly **$20/month or $200/year** in the United States and offers a free basic tier: https://www.caido.io/pricing/ and https://www.caido.io/blog/2025-08-21-localized-pricing/
- Semgrep Teams starts at **$30 per contributor per month**, while its free tier includes up to ten repositories and ten contributors: https://semgrep.dev/pricing/
- ProjectDiscovery Neo starts at **$200 per seat per month** for recurring agentic testing and also offers limited one-time free usage: https://projectdiscovery.io/pricing
- Burp Suite Professional advertises **$499** and Burp AT is currently a public beta whose individual page does not publish a separate numeric price: https://portswigger.net/burp/pro and https://portswigger.net/burp/burp-at/pricing

ScopeRook's proposed $19 price is therefore plausible for an independent-researcher workflow layer, but the comparison does not prove willingness to pay. The product must first show that its evidence and selection workflow saves time or improves report completeness for outside researchers.
