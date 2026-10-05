"""Compatibility entry point for the former ScopeRook Daybreak server name.

BountyBreak 0.8.x keeps this wrapper so existing MCP client registrations
continue to work. New integrations should use ``bountybreak_daybreak_server.py``.
"""

from bountybreak_daybreak_server import *  # noqa: F401,F403
from bountybreak_daybreak_server import main


if __name__ == "__main__":
    main()
