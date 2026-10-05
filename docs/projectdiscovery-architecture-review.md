# ProjectDiscovery architecture review

Reviewed 2026-10-04 from the upstream MIT repositories. This is a clean-room product analysis: BountyBreak uses the architectural ideas below but does not copy or vendor ProjectDiscovery code.

## What transfers well

### Compile before execute

Nuclei treats a template as a unit that describes requests, matchers, and extractors; it validates and compiles templates into protocol executors before running them. Its protocol interface also exposes the request count, while result events flow through a separate output layer.

BountyBreak applies the same separation at the product boundary:

1. program intake and the candidate define what may be considered;
2. a validation contract binds identity, state, sequence, control, cleanup, and request ceiling;
3. a tool adapter is selected by capability;
4. a separate executor receipt is required before target-facing work;
5. sanitized result events become observations and evidence manifests.

This keeps the model in planning and interpretation while deterministic code enforces the limits.

Source: https://github.com/projectdiscovery/nuclei/blob/HEAD/DESIGN.md

### Keep matching separate from extraction

Nuclei's operators separate matchers from extractors and return a structured result. BountyBreak mirrors that distinction by keeping an observed result separate from derived impact. A scanner match or source pattern can create a candidate, but it cannot become a report until the negative control and independent impact check are recorded.

Source: https://github.com/projectdiscovery/nuclei/blob/HEAD/DESIGN.md

### Scope and expansion must be explicit

Katana exposes separate in-scope and out-of-scope expressions, a field-scope choice, depth and duration controls, and opt-in JavaScript crawling, known-file checks, headless mode, and automatic form filling. Its JSONL output can omit raw requests and bodies.

BountyBreak therefore treats crawling as an expanding operation. A future Katana adapter must require an exact FQDN, exclusion pattern, depth, page count, duration, request ceiling, and disabled headless/form-fill defaults. Output ingestion should request JSONL with raw data and bodies omitted, then retain only route shape.

Source: https://github.com/projectdiscovery/katana/blob/HEAD/README.md

### Correlate proof without retaining payloads

Interactsh uses correlation identifiers and session state to associate callbacks with the originating check. BountyBreak can use that pattern only with a researcher-controlled service: one short-lived correlation reference per candidate, no file hosting, no response-body retention, and an expiry in the executor receipt.

Source: https://github.com/projectdiscovery/interactsh/blob/HEAD/README.md

### Normalize outputs at the boundary

ProjectDiscovery httpx exposes validated options, a runner, and JSONL output. BountyBreak should continue to use external tools as replaceable executors and import narrow structured results instead of embedding their runtime. Executable hash, reported version, exact configuration hash, actual request count, sanitized output hash, and exit state belong in the receipt.

Source: https://github.com/projectdiscovery/httpx/blob/HEAD/README.md

## What the Neo comparison changes

Neo is excluded because no MIT-licensed repository was identified. Its published comparison still highlights a useful test-design gap: source review is a hypothesis engine, while authorization and business-logic flaws often depend on identity, state, and sequence in a running build.

BountyBreak v0.7.0 adds `bountybreak_set_validation_contract` for that gap. The contract records candidate and control actors, starting state, ordered steps, expected secure behavior, suspected behavior, negative control, independent impact check, cleanup, environment, and a request ceiling. The contract always reports `execution_ready: false`; an authorized executor remains a separate gate.

Source: https://projectdiscovery.io/blog/ai-code-review-vs-neo

## License boundary

Only records whose upstream repository license file says MIT enter the integration catalog. Hosted services, Neo, Nmap service-probe data, public Interactsh infrastructure, and third-party datasets or SDKs without separate MIT verification are excluded. If BountyBreak later bundles code or binaries, it must preserve the MIT copyright and permission notice and audit bundled dependencies separately.
