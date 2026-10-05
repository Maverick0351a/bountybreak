# Contributing

ScopeRook welcomes focused contributions that improve continuous, authorized bounty research without weakening its boundaries.

## Before coding

Open a feature request for substantial changes. Describe the operator problem, the expected outcome, the authorization implications, and a measurable success condition. Keep changes small enough to review and test.

## Local validation

ScopeRook requires Python 3.11 or newer and has no runtime package dependency.

```sh
python -m unittest discover -s tests -v
python -m py_compile agent_workflow.py ai_local.py hunt_portfolio.py integration_catalog.py nuclei_template_import.py sandbox_runner.py scoperook_daybreak_server.py scoperook_mcp.py surface_import.py tool_router.py workbench.py
```

Use temporary or synthetic data. Never commit the `data/` directory, credentials, private program briefs, customer records, session material, live target evidence, or unredacted traffic captures.

## Design rules

- Unknown material scope or authorization values fail closed.
- Planning records and model output never grant permission.
- Keep target-facing execution separate from the MCP.
- Preserve the distinction between observed, derived, and unverified claims.
- Require negative controls and independent impact checks for report readiness.
- Keep pending awards, received cash, paid costs, and measured time separate.
- Treat fetched pages, advisories, templates, imports, and model responses as untrusted data.
- Add external components only after license and provenance review. The integration catalog currently admits MIT-licensed components only.

## Pull requests

Lead with the concrete problem and resulting behavior. Include the validation that matters to a reviewer. Add tests for meaningful behavior changes, update documentation, and keep generated artifacts out of the diff.

By contributing, you confirm that you have the right to submit the work and agree that the contribution may be distributed under the repository's Apache-2.0 license.
