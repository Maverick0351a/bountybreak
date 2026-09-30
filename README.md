# ScopeRook

**Scope first. Proof always.** ScopeRook is a downloadable, red team themed research desk for authorized bug bounty work and researcher-owned labs. The name pairs the scope boundary with a rook: a deliberate move backed by evidence. The app, exploit intelligence index, symbolic sandbox, and local-model adapter use **Python 3.11+ standard library only**. Model weights are separate, so the repository stays small.

## Run

On Windows, double-click `Start-ScopeRook.cmd`. On any supported system:

```sh
python workbench.py --open
```

The app binds to `http://127.0.0.1:8766/`. Close the launcher window or press Ctrl+C to stop it. Engagement JSON and the generated SQLite index live under `data/`, which Git ignores. To choose another data location, app port, or local model port:

```sh
python workbench.py --data-dir /private/path --port 8767 --model-port 1234
```

No installation, cloud account, Docker runtime, or scanner download is required. The AI feature requires a separate **OpenAI-compatible local model server** at `127.0.0.1:<model-port>` with `/v1/models` and `/v1/chat/completions`. Start your own server and load a model before using **AI assistant**. There is no cloud fallback, API key collection, automatic model download, or background prompt transfer. This is an API-compatible local model integration; it is not a ChatGPT plugin or OpenAI service integration.

## Research workflow

1. Create an engagement and record the authority source and optional URL or asset. Bounty and internal entries are planning records.
2. Use **Exploit intelligence** to search the four bundled public-source records by product, CVE, or mechanism. Check the linked primary source and affected version before relying on a result. The generated SQLite FTS index refreshes when the bundled JSON changes.
3. Use **Logic sandbox** to simulate a hypothesis and negative control offline. Load the synthetic example to see the format. `intelligence/logic_sandbox.py` accepts bounded JSON state transitions, never code or payloads. Its result is supported or unsupported **in the model**.
4. Optionally ask **AI assistant** for a hypothesis draft. It sends the entered question, up to two matching prior-art records, and an optional selected engagement name/assets to the loopback model. You can include the current Logic sandbox world and plan; code simulates them first, then sends a concise result and negative-control outcome. Review the unverified answer and save a plan yourself.
5. For a researcher-owned lab, run the bundled two-request demo. To check your own separate loopback service, record its exact `http://127.0.0.1:<port>` origin, start the service, and use **Check a local URL** with two exact paths and a negative control. `examples/local_lab.py` provides a synthetic server on port 8866.

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
