"""Compatibility entry point for the former ScopeRook module name.

BountyBreak 0.8.x keeps this wrapper so existing MCP client registrations and
imports continue to work. New integrations should use ``bountybreak_mcp.py``.
"""

from bountybreak_mcp import *  # noqa: F401,F403
from bountybreak_mcp import main


if __name__ == "__main__":
    main()
