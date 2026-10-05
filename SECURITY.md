# Security policy

## Supported version

Security fixes are applied to the current release line. Reproduce a report against the latest tagged version or the current `main` branch when possible.

## Reporting a ScopeRook vulnerability

Use [GitHub private vulnerability reporting](https://github.com/Maverick0351a/scoperook/security/advisories/new) for vulnerabilities in ScopeRook itself. Include:

- the affected version or commit;
- the minimum attacker access;
- a short synthetic reproduction;
- observed behavior and a negative control;
- practical impact;
- suggested remediation, if known.

Do not include credentials, private bounty-program text, session cookies, customer data, or evidence from a live target. If the private reporting form is unavailable, open a public issue requesting a private contact route without disclosing the vulnerability.

## Scope

Good-faith testing is limited to researcher-controlled local ScopeRook installations and synthetic data. ScopeRook does not grant permission to test any bounty target, third-party service, MCP client, model provider, or integrated tool.

Avoid availability testing, persistence, destructive actions, credential attacks, or access to another person's data. Stop after demonstrating the minimum controlled impact.

## What is not a ScopeRook vulnerability

- a public advisory or template that has not been shown to affect ScopeRook;
- a target vulnerability discovered while using ScopeRook;
- an unsafe command that a separate executor runs outside ScopeRook;
- disclosure of secrets that a user deliberately placed in an MCP argument or local record despite the documented boundary.

We will acknowledge a complete private report, preserve reporter credit when desired, and coordinate remediation before public disclosure.
