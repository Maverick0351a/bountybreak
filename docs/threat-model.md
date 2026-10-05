# Threat model

## Security objective

BountyBreak should help an agent preserve authorized bug-bounty state without turning stored research into permission, leaking sensitive values, or creating unbounded execution. It is an operations layer; target traffic and arbitrary command execution stay outside the MCP.

## Assets

- current program rules and exact scope state;
- target history, candidates, controls, and stop reasons;
- sanitized observations and local evidence hashes;
- request, time, cost, award, and received-cash records;
- local tool metadata and reviewed synthetic-lab manifests.

Passwords, tokens, cookies, MFA material, customer data, raw target responses, and private keys are prohibited values rather than protected BountyBreak assets. A short local account alias may point the human to a separately protected credential.

## Trust boundaries

| Boundary | Untrusted input | Control |
|---|---|---|
| MCP client and model | Tool arguments and generated text | Typed schemas, length limits, allowlists, explicit full-record reads, no shell or target executor |
| Local filesystem | Engagement JSON, imports, evidence paths, registry paths | Atomic writes, path confinement, symlink rejection, hashes, schema checks, corrupt-record preservation |
| Browser and imported artifacts | HAR, OpenAPI, and template files | Structural reduction, sensitive-field removal, same-origin filtering, size ceilings, no execution |
| Public intelligence sources | Advisory and exploit metadata | Named sources, bounded responses, metadata reduction, no proof-of-concept download or execution |
| Optional local model | Generated hypotheses | Explicit loopback port, off by default, unverified classification, no cloud fallback |
| Separate security tools | Tool capability claims and outputs | Metadata-only registry and routing; BountyBreak does not launch the tool |
| Synthetic labs | Reviewed fixture code and results | Pinned manifests, hashes, candidate and negative control, no arbitrary code input |
| Backup archives | Local engagement records and evidence | Hash manifest, path and symlink rejection, expanded-size limits, exact verification, restore to a new directory only |

## Primary abuse cases

1. **Stale rules treated as current.** Historical intake preserves the source review timestamp and optional program-specific freshness limit. Stale active targets require policy refresh before hunting.
2. **Closed work silently reopened.** Closed and paused targets enter the waiting queue with their recorded stop or setup condition. The agent brief cannot manufacture a candidate task for them.
3. **Unknown values converted to zero.** Unmeasured time, cost, awards, cash, and request counts remain null or explicitly unknown.
4. **Secrets placed in agent context.** Asset URLs reject credentials and query tokens; account references reject addresses, URLs, and secret-shaped values. Importers remove sensitive bodies and headers. Documentation prohibits raw secret input.
5. **Path escape or evidence substitution.** Evidence references must be relative regular files inside the engagement directory. Parent paths and symbolic links fail closed; accepted files are hashed.
6. **Malicious or newer record format.** New records use engagement schema version 1. Unsupported future versions and malformed records are preserved but excluded from work queues.
7. **Tool metadata mistaken for authorization.** The registry returns a recommendation and an execution boundary. Target-facing work still needs a separate current authorization and executor preflight.
8. **Source intelligence mistaken for a live finding.** Advisory, CVE, template, or package matches remain research leads. Report gating requires observed evidence, a negative control, an independent impact check, and prior-art review.
9. **Corrupt or malicious backup.** Every declared file is size- and SHA-256-checked before restore. Duplicate paths, undeclared files, traversal, symlinks, encryption, oversized payloads, and unsupported engagement schemas fail closed. Restore extraction uses a staging directory and never replaces an existing path.

## Residual risks

- The configured MCP client and model provider can see values the user submits through tools.
- A user can deliberately place a secret in free-form text despite the documented boundary.
- The operating system account can read the local data directory unless the user applies filesystem protection.
- Local backups are not encrypted. Filesystem permissions and encrypted storage remain the user's responsibility.
- Release artifacts are not yet signed.
- A separately installed executor can exceed scope; BountyBreak neither launches nor contains it.

## Release gates

Security changes require the deterministic suite, stdio handshake, extracted-archive test, and a review of this model. Active adapters, if ever added, also require short-lived capability receipts, independent request counting, redirect and destination pinning, hard budgets, and adversarial stale-scope tests.
