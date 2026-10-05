# Continuous hunting model

BountyBreak treats each bounty target as a durable engagement rather than a temporary chat. The engagement keeps the current program intake, exact assets, target profile, asset context, coverage sessions, candidates, evidence, reports, outcomes, and sanitized research artifacts. Dated revisions preserve how the record changed without widening authorization automatically.

## What the agent records

The target profile stores the platform, lifecycle status, priority, plausible attacker payoffs, technologies, an account-state and optional short local alias, strategy, next action, revisit date, and tags. The alias field rejects email addresses, URLs, and credential punctuation. It must never contain a password, token, session material, MFA value, or private customer data.

Each asset has its own type, scope state, reward state, test state, constraints, and notes. An out-of-scope asset must be closed for testing. An asset marked in scope still does not authorize a technique; the current structured program intake remains the controlling record.

Every working pass ends with a hunt session in one of these coverage lanes:

- identity and access;
- business logic;
- APIs;
- integrations and webhooks;
- file processing;
- AI and agents;
- client and mobile;
- supply chain;
- infrastructure and configuration.

The session records its environment, result, short summary, candidate links, source references, request-accounting state, measured target requests when known, human time, paid cost, next action, and revisit date. Local, source-only, and synthetic sessions must record zero or not-applicable target requests. An authorized-target session may explicitly preserve unknown request count rather than inventing zero.

## Resume flow

1. Call `bountybreak_hunt_portfolio` to see every target's documentation state, policy age, coverage, candidate state, outcomes, recorded cost and time, and deterministic next action.
2. Read `bountybreak_get_target_history` for the selected target. Detailed snapshots are opt-in, and pagination bounds the returned context.
3. Read the full engagement and `bountybreak_agent_brief` only for that target.
4. Refresh any stale or incomplete policy record before target traffic. The portfolio's default 14-day freshness window is an administrative reminder; it is not authorization and programs may require a shorter window.
5. Perform one bounded pass, save observations and candidate decisions, then close the pass with `bountybreak_record_hunt_session`.
6. Return to the portfolio for the next target or the recorded revisit date.

The portfolio ranks active targets by explicit priority, readiness, required administrative work, and oldest activity. It does not predict acceptance, bounty value, or vulnerability presence. A target stays visible when blocked, paused, or closed so the agent does not repeat old work or lose outcome history.

## Privacy and authority boundary

Portfolio output is metadata-only. It omits asset values, scope text, hypotheses, evidence contents, and credentials. Full records require an explicit single-target read. History snapshots are also opt-in.

Scope completeness, a passing intake gate, and an in-scope asset are necessary records for active work, but none of them grants a generic scanner permission. Active execution remains outside the MCP until a separate executor can enforce an exact asset, allowed operation, identity, deadline, concurrency, rate, request ceiling, redirect rule, and stop conditions at request time.
