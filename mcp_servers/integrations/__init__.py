"""
External API Integrations for MCP Server

All external integrations (SIEM, Threat Intel, etc.) should be defined here.
The MCP server acts as a gateway/abstraction layer.
"""

from .virustotal_integration import VirusTotalThreatIntel, get_virustotal_client

__all__ = [
    "VirusTotalThreatIntel",
    "get_virustotal_client"
]
