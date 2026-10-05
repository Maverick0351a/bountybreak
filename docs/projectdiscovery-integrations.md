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

## Implemented Nuclei metadata intake

ScopeRook now has a dependency-free Nuclei template importer for researcher-reviewed local YAML files. It is an intelligence boundary, not an executor. The importer requires an exact immutable ProjectDiscovery `nuclei-templates` commit and repository path, verifies the MIT catalog record, hashes the local source, extracts a small metadata allowlist, flags risky or expanding template features, and stores a sanitized JSON record under the engagement. Request bodies, raw requests, payload values, matchers, extractors, and code are never retained.

The lexical parser intentionally rejects ambiguous YAML instead of trying to reproduce Nuclei's full parser. It does not resolve workflows or includes, contact the upstream repository, validate a template signature, invoke Nuclei, or infer that a target is affected. The recorded upstream URL is declared provenance until separately network-verified.

Nuclei's `metadata.max-request` is descriptive template metadata rather than an engine-enforced hard ceiling. ScopeRook therefore marks it `metadata_only_unenforced`; a future executor must independently count requests. The importer also treats code, JavaScript, headless, file, workflow, fuzzing, payload, raw-request, OOB, unsafe, redirect, race, state-changing, and expanding-template features as explicit review flags.

The strict boundary also reflects upstream security history. The published advisory GHSA-jpf4-98qj-qr67 says Nuclei before 3.10.0 could run unsigned code templates through the DAST path; 3.10.0 fixed that route. Current Nuclei 3.11 release notes say JavaScript templates require signatures. ScopeRook does not treat a signature field or a newer engine version as sufficient authorization to run a template.

The live machine inventory on 2026-10-04 found none of these ProjectDiscovery binaries. The `httpx` command on PATH belongs to Python's HTTP client package and must not be treated as ProjectDiscovery httpx. ScopeRook therefore catalogs these integrations as `not_checked` and will not route to them until an exact installed executable is separately registered.

ProjectDiscovery's research page reports that most observed agent failures came from execution rather than missing security knowledge. That supports ScopeRook's product focus: deterministic phase selection, exact scope, narrow executor contracts, negative controls, and evidence receipts instead of another broad autonomous scanner.

Primary sources:

- https://projectdiscovery.io/open-source
- https://projectdiscovery.io/research
- https://projectdiscovery.io/blog/ai-code-review-vs-neo
- https://github.com/projectdiscovery
- https://github.com/projectdiscovery/nuclei
- https://github.com/projectdiscovery/nuclei-templates
- https://github.com/projectdiscovery/nuclei/blob/dev/SYNTAX-REFERENCE.md
- https://github.com/projectdiscovery/nuclei/blob/dev/nuclei-jsonschema.json
- https://github.com/projectdiscovery/nuclei-templates/discussions/7723
- https://github.com/projectdiscovery/nuclei/security/advisories/GHSA-jpf4-98qj-qr67
- https://github.com/projectdiscovery/nuclei/releases
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
