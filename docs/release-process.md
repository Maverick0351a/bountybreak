# Release process

This process keeps the downloadable package tied to a reviewed Git commit and verifies the package independently of the development checkout.

1. Confirm the version in both MCP servers, the changelog, README, and release notes.
2. Run the complete test and compile checks.
3. Confirm the worktree contains no private `data/` directory, credentials, local tool paths, live evidence, or target-specific records.
4. Confirm the repository license and third-party notices are current.
5. Commit the reviewed source and create the archive from that exact commit:

   ```powershell
   git archive --format=zip --prefix=scoperook-v0.8.1/ --output=dist/scoperook-v0.8.1.zip HEAD
   Get-FileHash -Algorithm SHA256 dist/scoperook-v0.8.1.zip
   ```

6. Extract the archive into a fresh temporary directory and run:

   ```powershell
   python -m unittest discover -s tests -v
   python -m py_compile agent_workflow.py ai_local.py hunt_portfolio.py integration_catalog.py nuclei_template_import.py sandbox_runner.py scoperook_daybreak_server.py scoperook_mcp.py surface_import.py tool_router.py workbench.py
   ```

7. Review the archive file list and the social preview. Record the byte count and SHA-256 in the release draft.
8. Tag the verified commit, publish the matching archive and checksum, and confirm GitHub CI passes.
9. Verify the public release page, installation command, security-reporting link, and a clean first launch from the downloadable archive.

Signing and an SBOM remain public-beta gates. A local archive and checksum alone do not satisfy those gates.
