# ScopeRook

**Scope first. Proof always.** ScopeRook is a downloadable, red team themed research desk for authorized bug bounty work and researcher-owned labs. It keeps a continuous portfolio of targets, dated scope and asset revisions, coverage history, candidates, evidence, outcomes, and public vulnerability intelligence so an agent can stop and resume without reconstructing the hunt from chat. The name pairs the scope boundary with a rook: a deliberate move backed by evidence. The app, exploit intelligence index, symbolic sandbox, and local-model adapter use **Python 3.11+ standard library only**. Model weights are separate, so the repository stays small.

## Run

On Windows, double-click `Start-ScopeRook.cmd`. On any supported system:

```sh
python workbench.py --open
```

The app binds to `http://127.0.0.1:8766/`. Close the launcher window or press Ctrl+C to stop it. Engagement JSON and the generated SQLite index live under `data/`, which Git ignores. AI drafting is off by default. To choose another data location and app port:

```sh
python workbench.py --data-dir /private/path --port 8767
```

No installation, cloud account, Docker runtime, or scanner download is required. To enable **AI assistant**, start a model you chose on a separate **OpenAI-compatible local model server** with `/v1/models` and `/v1/chat/completions`, then explicitly launch ScopeRook with `--model-port PORT`. It connects only to `127.0.0.1:PORT` when you request a draft. Without that flag, the draft endpoint rejects requests and no model is contacted. There is no cloud fallback, API key collection, automatic model download, or background prompt transfer. This is an API-compatible local model integration; it is not a ChatGPT plugin or OpenAI service integration.

## Codex and Claude tool

`scoperook_daybreak_server.py` is the primary dependency-free stdio MCP server for Codex and Claude. It gives an agent a durable local source of truth for a cross-target hunting portfolio, program scope, exact assets, coverage history, candidate selection, sanitized surface inventory, observations, evidence integrity, report readiness, triage state, submission outcomes, received cash, costs, human time, public prior art, offline validation, and handoffs to existing tools. Successful tools return structured MCP content as well as readable JSON. Portfolio listings are metadata-only. Reading one full engagement or its detailed history requires an explicit tool call. The server intentionally omits target requests, generic commands, credentials, and report submission. `scoperook_mcp.py` remains the smaller core-compatibility server.

Register it with an explicit Python executable and repository path. For example:

```sh
codex mcp add scoperook -- python C:/path/to/scoperook/scoperook_daybreak_server.py --data-dir C:/path/to/scoperook/data --sandbox-distro Ubuntu
```

Claude uses the same command and arguments in an `mcpServers.scoperook` stdio entry. Tool outputs can be sent to the connected agent provider. Prior-art records are public; create/add tools store exactly what the agent supplies. Do not put secrets, customer data, private program text, or live session material in tool arguments.

The continuous-hunting agent sequence is:

1. Call `scoperook_hunt_portfolio` for the ranked cross-target queue. Resume the selected target with `scoperook_get_target_history`, `scoperook_get_engagement`, and `scoperook_agent_brief`.
2. Set the target profile, including platform, status, priority, plausible attacker payoffs, technologies, account-state label, strategy, next action, revisit date, and tags. Document every exact asset with its type, scope, reward, test status, constraints, and notes. Scope and profile revisions remain dated and hashable.
3. Save the current program intake. The gate checks the program URL, exclusions, rewards, technique limits, rate limits, account and identity rules, safe harbor, evidence rules, prior-art sources, open questions, and exact assets. Unknown or pending material values keep the gate closed.
4. Search the bundled prior-art index, current CISA KEV, CVE List v5, NVD, FIRST EPSS, GitHub Advisories, CIRCL sightings, Exploit-DB metadata, OSV package records, and reviewed Nuclei template metadata. Manually review relevant primary references before saving a candidate with minimum access, negative control, evidence need, affected version, remediation, and stop conditions.
5. Record the candidate's attacker motive, plausible payoff, duplicate risk, setup cost, proof strength, request estimate, and pursue/hold/stop decision. `scoperook_rank_candidates` explains every ranking factor and never labels the result an acceptance probability.
6. Use `scoperook_set_validation_contract` to bind the candidate to controlled actors, starting state, a short sequence, the expected secure result, suspected result, negative control, independent impact check, cleanup, environment, and hard request ceiling. It never executes the plan or grants authorization.
7. Search `scoperook_search_integration_catalog` for reviewed optional integrations, then register an exact installed tool file once. `scoperook_route_existing_tools` chooses the smallest available capability for the current phase. It returns a human, CLI, service, or MCP handoff; ScopeRook never downloads or launches it. A CLI or UI directory alone is not considered available. Every target-facing handoff stays blocked on a separate exact executor preflight.
8. Import a Burp/ZAP HAR or OpenAPI JSON file from the engagement directory. ScopeRook saves only same-origin method, redacted route, status, parameter names, and schema shape; it drops headers, cookies, bodies, examples, defaults, query values, response content, and off-origin HAR requests.
9. Record sanitized observations as `observed`, `derived`, or `unverified`, with reproduction, control result, independent impact check, and local evidence references. Close each working pass with `scoperook_record_hunt_session`, including its coverage lane, result, request accounting, time, cost, next action, and revisit date.
10. Review the candidate, hash the referenced local evidence into a manifest, and build a concise report. Saving the manifest fails if scope, assessment, observed evidence, controls, impact check, or evidence files are incomplete.
11. Record each candidate's submission reference, state, and financial facts. Pending awards, received cash, paid costs, and measured human time remain separate; omitted values stay unknown instead of becoming zero.

This split lets the agent organize and audit the whole bounty workflow without giving a generic MCP permission to scan whatever text appears in a conversation.

### Daybreak Blue profile

`scoperook_agent_brief` is tuned for a Daybreak Blue workflow: it returns the selected engagement's compact state, the highest-value next action, waiting items, up to five transparently ranked candidates, and the exact ScopeRook tools for the current phase. The server publishes three MCP resources and three reusable prompts, including `scoperook-continuous-hunt`, so an agent can load the operating method without expanding the tool catalog. Daybreak access is not bundled, proxied, or resold; the user brings an approved Codex workspace or API project. ScopeRook supplies context and controls, not model access.

Use Daybreak Blue for defensive discovery, source review, vulnerability triage, threat modeling, synthetic validation, evidence reduction, remediation, and patch verification. Advanced live penetration testing or exploit development requires a separately authorized executor and the appropriate model access. See [`docs/competitive-analysis.md`](docs/competitive-analysis.md) for the product boundary and competitor review.

The live intelligence tools use fixed official or project-maintained endpoints for CISA KEV, CVE List v5, NVD, FIRST EPSS, GitHub Global Security Advisories, OSV, CIRCL Vulnerability-Lookup, and Exploit-DB's GitLab metadata. Broad KEV and Exploit-DB filters run locally after their public catalogs are fetched. Exact-CVE tools send only the public CVE identifier; OSV receives only the ecosystem-native package name and optional version. Responses have fixed size limits and in-memory caches, are reduced to reference metadata, and remain untrusted data. Social and Telegram CIRCL sightings are leads until a primary source confirms them. ScopeRook never downloads or executes Exploit-DB files or other proof-of-concept code.

### Nuclei template intelligence

`scoperook_import_nuclei_template` reads one researcher-reviewed local Nuclei YAML file and stores a sanitized metadata record. It retains the template id, title, severity, authors, tags, references, CVE/CWE/CVSS fields, product metadata, protocols, HTTP methods, source hash, exact declared upstream commit, and risk flags. It discards request bodies, raw requests, payload values, matchers, extractors, and executable code. The importer never invokes Nuclei or a YAML engine, resolves includes, validates a signature, or grants permission to execute a template.

The record flags code, JavaScript, headless, workflow, file, fuzzing, out-of-band, unsafe, redirect, race, state-changing, and expanding-template features. Nuclei's `max-request` metadata is recorded as descriptive and unenforced because the engine does not treat it as a hard request limit. Any future executor still needs a separate pinned-template capability with independent request counting. See [`docs/projectdiscovery-integrations.md`](docs/projectdiscovery-integrations.md).

## Synthetic execution sandbox

The MCP exposes two synthetic-lab tools. `scoperook_list_synthetic_labs` validates bundled manifests and reports whether the explicitly selected WSL backend is ready. `scoperook_run_synthetic_lab` accepts only a reviewed lab id and runs every declared candidate and negative-control case. It does not accept code, commands, paths, environment variables, images, packages, or network destinations.

The WSL runner creates fresh network, mount, and PID namespaces; builds a temporary chroot; mounts the reviewed lab read-only; drops to uid 65534 with no capabilities and `no_new_privs`; supplies an empty environment; and applies CPU, memory, process, file, output, and wall-clock limits. The bundled access-control fixture verifies those properties from inside the run. Bounded stdout and stderr, hashes, manifest and entrypoint hashes, limits, and control results are saved under ignored `data/lab-runs/`.

This is an application-level fixture runner, not a kernel or hypervisor sandbox. A passing result demonstrates only the bundled synthetic behavior. It does not establish that a bounty target is affected and sends no target traffic. The optional Oracle design is documented in [`docs/oracle-sandbox-plan.md`](docs/oracle-sandbox-plan.md); it is not enabled and makes no cloud calls.

## Research workflow

1. Create an engagement and record the authority source and optional URL or asset. Bounty and internal entries are planning records.
2. Use **Exploit intelligence** to search the four bundled public-source records by product, CVE, or mechanism. Check the linked primary source and affected version before relying on a result. The generated SQLite FTS index refreshes when the bundled JSON changes.
3. Use **Logic sandbox** to simulate a hypothesis and negative control offline. Load the synthetic example to see the format. `intelligence/logic_sandbox.py` accepts bounded JSON state transitions, never code or payloads. A short result summary appears above the expandable full trace. Its result is supported or unsupported **in the model**.
4. Optionally ask **AI assistant** for a hypothesis draft. The prior-art search is optional; leave it blank for a synthetic lab question. When used, it sends up to two matching prior-art records along with the entered question and optional selected engagement name/assets to the loopback model. You can include the current Logic sandbox world and plan; code simulates them first, then sends a concise result and negative-control outcome. Review the unverified answer and save a plan yourself.
5. For a researcher-owned lab, run the bundled two-request demo. To check your own separate loopback service, record its exact `http://127.0.0.1:<port>` origin, start the service, and use **Check a local URL** with two exact paths and a negative control. `examples/local_lab.py` provides a synthetic server on port 8866; use `/api/me` as the primary path, `/api/admin` as the negative control, and expected control status `403`.

The local check makes at most two GET requests, waits at least 0.5 seconds between them, applies a 3-second timeout and 64 KiB response ceiling, and stops on redirects, throttling, server errors, or failed primary responses. It saves statuses, lengths, hashes, and stop reasons without response bodies. A passing control means the check worked; it does not establish a vulnerability.

## Boundaries

The web server requires the exact loopback Host, matching Origin, and a CSRF token for changes. It has no remote access mode. The AI adapter uses a fixed loopback IP and no proxy or cloud fallback. Treat locally hosted model servers as trusted components and keep them private. Do not put credentials, customer data, private program text, or live session material in app records or prompts.

The app does not contact bounty targets, launch ZAP/Nuclei/ffuf/Shannon, or submit reports. The synthetic runner executes only reviewed local fixtures without a network. The optional integration catalog describes tools without claiming they are installed. The local capability registry points the agent to tools already installed by the researcher and requires an exact file for CLI and UI handoffs; it does not certify configuration or execute them. A live adapter would need current program scope, technique permission, identities, numeric traffic limits, and request-time enforcement. Saved URLs, model drafts, database records, passing planning gates, routes, and synthetic results are not authorization.

ProjectDiscovery integrations are documented in [`docs/projectdiscovery-integrations.md`](docs/projectdiscovery-integrations.md). Catalog admission is MIT-only and fails closed on another license; every accepted record includes the upstream license URL and review date. Nuclei, nuclei-templates, httpx, Katana, Interactsh, Subfinder, DNSx, Naabu, and Vulnx remain separately installed executors or intelligence sources; ScopeRook contributes the program-specific gates and evidence contract around them. Neo and non-MIT auxiliary components are excluded.

The architecture study behind the integration is in [`docs/projectdiscovery-architecture-review.md`](docs/projectdiscovery-architecture-review.md). ScopeRook reimplements the useful boundaries in its own standard-library code; it does not copy or vendor ProjectDiscovery source.

The durable portfolio and resume model is documented in [`docs/continuous-hunting.md`](docs/continuous-hunting.md). The concrete engineering and beta gates for a paid launch are in [`docs/launch-readiness.md`](docs/launch-readiness.md).

The bundled seed index contains four records backed by direct primary sources at the time of this release. Two incomplete records from the private research index were withheld. Use the live CISA/CVE tools for current verification. Bundled records and live feed entries are public prior art, not target findings; source URLs, version applicability, and status can change.

## Test

```sh
python -m unittest discover -s tests -v
```

The tests exercise the app API, cross-target portfolio and history, Nuclei metadata reduction, local-model adapter with a fake loopback model, live-source reduction, advisory metadata search, manifest validation, mandatory synthetic negative controls, symbolic hypothesis/control, owned-lab request budget, redirect stop, and Host/Origin/CSRF boundary.

## Project status

The current worktree supports a continuous cross-target portfolio, target and asset documentation with revision history, coverage-session closeout, source-backed current research, sanitized Nuclei template intelligence, a compact Daybreak Blue workflow, existing-tool routing, secret-reducing HAR/OpenAPI import, symbolic modeling, reviewed network-isolated synthetic labs, optional local AI drafts, and bounded loopback checks. It does not include model weights, live bounty adapters, scanner execution, a private sensitive-value vault, executor capability receipts, or a deployed Oracle backend. A product and pricing outline is in [`docs/productization.md`](docs/productization.md). The repository currently has no license; choose one before redistributing derivative builds or charging for it.

The dashboard's pre-run card is a manual reminder. It does not evaluate an engagement or authorize a run.
