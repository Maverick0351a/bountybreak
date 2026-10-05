# ProjectDiscovery integration plan

Reviewed 2026-10-04 from ProjectDiscovery's official open-source, research, documentation, and GitHub pages.

## MIT-only admission rule

ScopeRook admits an integration only when the upstream repository's own license file currently says MIT. The catalog records that license URL and review date, and loading fails closed on any other license. MIT permits commercial use, modification, distribution, and sublicensing, while still requiring the copyright and license notice to remain with copied or substantial portions. Before ScopeRook ever bundles a binary, a separate dependency and notice audit is still required.

Neo is not in this catalog. ProjectDiscovery presents Neo as a hosted product and distinguishes it from the open-source tools on the same site; no MIT-licensed Neo repository was identified. We use only the article's general engineering lesson: source review should produce hypotheses, and a researcher-owned running build should test role, state, sequence, negative controls, and observed impact before a claim advances.

ProjectDiscovery already supplies capable executors. ScopeRook should not reproduce them. It should tell the agent which capability fits the current phase, verify the exact installed handoff, bind active work to current program rules, and retain a compact evidence receipt.

| Integration | ScopeRook use | Default state |
| --- | --- | --- |
| Nuclei and nuclei-templates | Read reviewed template metadata for candidate research; run only pinned, reviewed template ids through a future bounded executor | Metadata allowed; execution blocked |
| ProjectDiscovery httpx | One-exact-URL status, hash, TLS, and response-metadata baseline | Blocked until exact URL and numeric request receipt |
| Katana | Same-FQDN route inventory when crawling is expressly permitted | Disabled; depth/page/request caps required |
| Interactsh | Researcher-controlled out-of-band confirmation | Disabled; self-hosted canary and explicit OOB permission required |
| Subfinder | Passive asset leads | Discovered names never inherit scope |
| DNSx | Bounded DNS verification for already admitted names | Disabled until exact assets and query cap are recorded |
| Naabu | Small explicit port allowlist on one authorized host | Disabled by default; Nmap probe data excluded |
| Vulnx | Public vulnerability and technology metadata | Research only; never proof of target exposure |

The live machine inventory on 2026-10-04 found none of these ProjectDiscovery binaries. The `httpx` command on PATH belongs to Python's HTTP client package and must not be treated as ProjectDiscovery httpx. ScopeRook therefore catalogs these integrations as `not_checked` and will not route to them until an exact installed executable is separately registered.

ProjectDiscovery's research page reports that most observed agent failures came from execution rather than missing security knowledge. That supports ScopeRook's product focus: deterministic phase selection, exact scope, narrow executor contracts, negative controls, and evidence receipts instead of another broad autonomous scanner.

Primary sources:

- https://projectdiscovery.io/open-source
- https://projectdiscovery.io/research
- https://projectdiscovery.io/blog/ai-code-review-vs-neo
- https://github.com/projectdiscovery
- https://github.com/projectdiscovery/nuclei
- https://github.com/projectdiscovery/nuclei-templates
- https://github.com/projectdiscovery/httpx
- https://github.com/projectdiscovery/katana
- https://github.com/projectdiscovery/interactsh

Each accepted repository's `license_source` is stored in `integrations/projectdiscovery.json`. Hosted ProjectDiscovery services, Neo, Nmap service-probe data, and third-party datasets or SDKs without separate MIT verification are excluded.

## Future executor receipt

Every target-facing adapter should produce a short-lived receipt containing:

- engagement and candidate ids;
- exact asset and operation class;
- executable hash and reported version;
- pinned template or configuration hash;
- permitted protocol, method, redirects, concurrency, rate, and total-request ceiling;
- identity and required researcher marker;
- deadline and stop conditions;
- sanitized output hash and actual request count.

Nuclei needs extra controls because templates can span protocols and initialize Interactsh. Katana needs hard crawl limits because route discovery expands. Subfinder output remains leads until an authoritative program record places each name in scope. Naabu remains unavailable unless the brief explicitly permits port scanning. These constraints belong in code outside the model.
