"""UI Configuration - Agents, Theme, Constants"""

from ui.config.agents import AGENT_CONFIG, NODE_PROGRESS_MAP, get_agent_config, get_node_progress
from ui.config.constants import COLORS, SEVERITY_COLORS, get_severity_color, get_severity_label

__all__ = [
    "AGENT_CONFIG",
    "NODE_PROGRESS_MAP",
    "get_agent_config",
    "get_node_progress",
    "COLORS",
    "SEVERITY_COLORS",
    "get_severity_color",
    "get_severity_label",
]
