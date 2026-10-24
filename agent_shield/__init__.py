"""
Agent Shield MCP - Enterprise Security Firewall for Model Context Protocol.

Author: Frank Emiliano Vargas Huamán (Frankosyni / Φρανκοσύνη)
License: MIT
"""

from agent_shield.models import (
    PolicyAction,
    ShieldConfig,
    ShieldViolationError,
    ToolCallRequest,
    ToolDecision,
)
from agent_shield.shield import AgentShield

__all__ = [
    "AgentShield",
    "PolicyAction",
    "ShieldConfig",
    "ShieldViolationError",
    "ToolCallRequest",
    "ToolDecision",
]

__version__ = "1.0.0"
