# Real-program workflow validation — 2026-10-05

## Purpose

This pass tested whether BountyBreak can preserve and resume real bug-bounty work without inventing activity or sending target traffic. Three sanitized existing program states were loaded into a fresh private data directory through the public MCP tools:

- a closed offline firmware review;
- a closed no-account web pass with a measured request count;
- a paused authenticated identity program waiting on manual account setup.

No credentials, assigned hosts, session material, private submissions, customer data, or raw evidence entered the validation store. The validation itself sent no target traffic.

## Workflow exercised

The pass used nine ordinary BountyBreak tools: status, engagement creation, program intake, target profile, asset context, hunt-session closeout, portfolio, target history, and agent brief. The fresh store produced three documented targets and eighteen chronological history events.

The test intentionally included different evidence states:

| State | Expected behavior | Observed after fixes |
|---|---|---|
| Closed offline review | Preserve the stop reason; do not propose more research | Wait state with the recorded regression-only condition |
| Closed no-candidate web pass | Keep the measured request total and prohibit retry | Wait state with the recorded no-retry condition and 26 measured requests |
| Paused authenticated setup | Surface the manual setup blocker without starting a hunt | Wait state with the recorded MFA handoff action |

The resulting portfolio reported zero active targets, zero hunt-ready targets, and no next target. Historical program reviews retained their actual source timestamps and their 24-hour freshness limits, so all three remained visibly stale. Unmeasured human time and paid cost remained `null`; BountyBreak did not convert missing measurements into zero.

## Defects found and corrected

The first run found three release-blocking workflow defects:

1. Historical policy imports were stamped with the import time and could appear current. The intake tool now accepts a validated source review timestamp and an optional program-specific freshness limit.
2. Hunt-session closeout forced numeric time and cost values. These measurements are now optional, and omitted values remain unknown throughout portfolio totals.
3. The Daybreak brief proposed new candidate research on closed and paused targets. The agent queue now inherits the portfolio gate and returns the recorded wait or stop condition instead.

The engagement record now carries schema version `1`. Legacy unversioned records remain readable and acquire the current version on the next successful write. Records from an unsupported future schema are preserved and fail closed.

## Verification

- 53 deterministic unit tests pass, including the 100-target and 5,000-session scale trial.
- A fresh stdio client completed initialize, tool listing, and status calls against the primary server; 40 tools were listed and stderr remained empty.
- Python compilation and Git whitespace checks pass.
- A local scan of the private validation store found none of the forbidden credential, assigned-host, email-provider, bearer-token, or session-cookie patterns checked for this pass.
- The private raw validation output remains under the Git-ignored `data/` directory and is not distributed.

## Product decision

The local MCP core is functional enough for a small, supervised private beta. This pass does not establish that the product is ready for an unattended paid public launch. A threat model, privacy notice, and SPDX SBOM generator are now present. The remaining gates are release signing, backup and restore for versioned data, and repeated use by outside researchers. Willingness to pay is still unverified.

BountyBreak should be offered first as a limited beta whose value claim is continuity, scope discipline, and evidence completeness. It must not promise accepted findings, bounty income, autonomous target testing, or Daybreak Blue access.
