# Privacy

BountyBreak is local-first. By default it stores engagement records, sanitized imports, evidence hashes, and workflow history only in the data directory selected by the user. It has no telemetry, analytics, hosted account, advertising identifier, crash uploader, or background cloud synchronization.

## Data BountyBreak accepts

BountyBreak is designed for current program rules, exact asset labels, non-secret account aliases, sanitized observations, local evidence references and hashes, candidate state, request accounting, time and cost measurements, and submission outcomes.

Do not put passwords, access tokens, session cookies, MFA material, private keys, raw HAR files, customer data, assigned-host secrets, or private program text into MCP arguments or engagement records. Keep those values in the researcher's protected credential store or interactive browser session.

## Agent and source boundaries

An MCP client may send tool arguments and returned records to its configured model provider. The user controls that provider and its data terms. BountyBreak does not proxy model access or receive those requests.

Public advisory tools make bounded read-only requests to their named public sources when explicitly called. The optional local-model adapter connects only to an explicitly selected loopback port. Synthetic labs are local and reviewed. BountyBreak contains no target-facing scanner or generic shell.

## Retention and deletion

Records remain until the user removes the selected local data directory or an individual engagement. The current release does not provide cloud recovery. Back up the data directory before upgrades or deletion.

## Product support

Do not attach live credentials, private target evidence, or customer data to a public issue. Follow [SECURITY.md](SECURITY.md) for private vulnerability reporting about BountyBreak itself.
