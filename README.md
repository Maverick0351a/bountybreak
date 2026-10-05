# ScopeRook

**Scope first. Proof always.** ScopeRook is a downloadable, red team themed research desk for authorized bug bounty work and researcher-owned labs. The name pairs the scope boundary with a rook: a deliberate move backed by evidence. The app, exploit intelligence index, symbolic sandbox, and local-model adapter use **Python 3.11+ standard library only**. Model weights are separate, so the repository stays small.

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

`scoperook_mcp.py` is a dependency-free stdio MCP server that both Codex and Claude can launch. It gives an agent a durable local source of truth for program scope, exact assets, bounded candidates, sanitized observations, report readiness, submission outcomes, received cash, costs, human time, public prior art, and offline symbolic simulation. Engagement listings are metadata-only. Reading one full engagement requires an explicit tool call. The server intentionally omits target requests, scanners, credentials, and report submission.

Register it with an explicit Python executable and repository path. For example:

```sh
codex mcp add scoperook -- python C:/path/to/scoperook/scoperook_mcp.py --data-dir C:/path/to/scoperook/data
```

Claude uses the same command and arguments in an `mcpServers.scoperook` stdio entry. Tool outputs can be sent to the connected agent provider. Prior-art records are public; create/add tools store exactly what the agent supplies. Do not put secrets, customer data, private program text, or live session material in tool arguments.

The useful agent sequence is:

1. Call `scoperook_status` and `scoperook_list_engagements`, then explicitly read only the engagement being worked on.
2. Create the engagement, record each exact asset, and save the current program intake. The gate checks the program URL, exclusions, rewards, technique limits, rate limits, account and identity rules, safe harbor, evidence rules, prior-art sources, open questions, and exact assets. Unknown or pending material values keep the gate closed.
3. Search the bundled prior-art index, manually verify relevant primary sources, and save a candidate with minimum access, negative control, evidence need, affected version, remediation, and stop conditions.
4. Perform any authorized live work separately through the normal browser or terminal. The MCP never turns a saved URL into traffic.
5. Record sanitized observations as `observed`, `derived`, or `unverified`, with reproduction, control result, independent impact check, and local evidence references.
6. Build a concise report. ScopeRook refuses to build it until the scope gate, candidate fields, observed evidence, negative control, independent impact check, and evidence references are complete.
7. Record each candidate's submission reference, state, and financial facts. Pending awards, received cash, paid costs, and measured human time remain separate; omitted values stay unknown instead of becoming zero.

This split lets the agent organize and audit the whole bounty workflow without giving a generic MCP permission to scan whatever text appears in a conversation.

## Research workflow

1. Create an engagement and record the authority source and optional URL or asset. Bounty and internal entries are planning records.
2. Use **Exploit intelligence** to search the four bundled public-source records by product, CVE, or mechanism. Check the linked primary source and affected version before relying on a result. The generated SQLite FTS index refreshes when the bundled JSON changes.
3. Use **Logic sandbox** to simulate a hypothesis and negative control offline. Load the synthetic example to see the format. `intelligence/logic_sandbox.py` accepts bounded JSON state transitions, never code or payloads. A short result summary appears above the expandable full trace. Its result is supported or unsupported **in the model**.
4. Optionally ask **AI assistant** for a hypothesis draft. The prior-art search is optional; leave it blank for a synthetic lab question. When used, it sends up to two matching prior-art records along with the entered question and optional selected engagement name/assets to the loopback model. You can include the current Logic sandbox world and plan; code simulates them first, then sends a concise result and negative-control outcome. Review the unverified answer and save a plan yourself.
5. For a researcher-owned lab, run the bundled two-request demo. To check your own separate loopback service, record its exact `http://127.0.0.1:<port>` origin, start the service, and use **Check a local URL** with two exact paths and a negative control. `examples/local_lab.py` provides a synthetic server on port 8866; use `/api/me` as the primary path, `/api/admin` as the negative control, and expected control status `403`.

The local check makes at most two GET requests, waits at least 0.5 seconds between them, applies a 3-second timeout and 64 KiB response ceiling, and stops on redirects, throttling, server errors, or failed primary responses. It saves statuses, lengths, hashes, and stop reasons without response bodies. A passing control means the check worked; it does not establish a vulnerability.

## Boundaries

The web server requires the exact loopback Host, matching Origin, and a CSRF token for changes. It has no remote access mode. The AI adapter uses a fixed loopback IP and no proxy or cloud fallback. Treat locally hosted model servers as trusted components and keep them private. Do not put credentials, customer data, private program text, or live session material in app records or prompts.

The app does not contact bounty targets, launch ZAP/Nuclei/ffuf/Shannon, or submit reports. The tool catalog is for choosing and reviewing tools. A live adapter would need current program scope, technique permission, identities, numeric traffic limits, and request-time enforcement. Saved URLs, model drafts, database records, and passing planning gates are not authorization.

The public seed index contains four records backed by direct primary sources at the time of this release. Two incomplete records from the private research index were withheld. Records are public prior art, not live findings; source URLs, version applicability, and status can change.

## Test

```sh
python -m unittest discover -s tests -v
```

The tests exercise the app API, local-model adapter with a fake loopback model, intelligence search, sandbox hypothesis/control, owned-lab request budget, redirect stop, and Host/Origin/CSRF boundary.

## Project status

This release supports local planning, source-backed prior-art search, symbolic modeling, optional local AI drafts, and bounded loopback checks. It does not include model weights, live bounty adapters, or scanner execution. The repository currently has no license; choose one before redistributing derivative builds.

The dashboard's pre-run card is a manual reminder. It does not evaluate an engagement or authorize a run.
