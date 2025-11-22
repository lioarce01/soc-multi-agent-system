"""
Agent Configuration
Centralized configuration for all SOC agents
"""

from typing import Dict, Any

# Agent visual configuration for chat display
AGENT_CONFIG: Dict[str, Dict[str, str]] = {
    "supervisor": {"emoji": "🎯", "color": "#3b82f6", "name": "SUPERVISOR"},
    "enrichment": {"emoji": "🔍", "color": "#10b981", "name": "ENRICHMENT"},
    "analysis": {"emoji": "🧠", "color": "#f59e0b", "name": "ANALYSIS"},
    "investigation": {"emoji": "🔬", "color": "#8b5cf6", "name": "INVESTIGATION"},
    "response": {"emoji": "🛡️", "color": "#ef4444", "name": "RESPONSE"},
    "communication": {"emoji": "📝", "color": "#06b6d4", "name": "COMMUNICATION"},
    "memory": {"emoji": "💾", "color": "#ec4899", "name": "MEMORY"},
}

# Node progress tracking for status panel
NODE_PROGRESS_MAP: Dict[str, Dict[str, Any]] = {
    "supervisor": {"emoji": "🎯", "pct": 16, "label": "SUPERVISOR"},
    "enrichment": {"emoji": "🔍", "pct": 33, "label": "ENRICHMENT"},
    "analysis": {"emoji": "🧠", "pct": 50, "label": "ANALYSIS"},
    "investigation": {"emoji": "🔎", "pct": 66, "label": "INVESTIGATION"},
    "response": {"emoji": "📋", "pct": 83, "label": "RESPONSE"},
    "communication": {"emoji": "📡", "pct": 100, "label": "COMMUNICATION"},
}

# Workflow node order
WORKFLOW_NODES = [
    "supervisor",
    "enrichment",
    "analysis",
    "investigation",
    "response",
    "communication",
]


def get_agent_config(agent_name: str) -> Dict[str, str]:
    """Get config for a specific agent with fallback"""
    return AGENT_CONFIG.get(
        agent_name,
        {"emoji": "🤖", "color": "#666", "name": agent_name.upper()}
    )


def get_node_progress(node_name: str) -> Dict[str, Any]:
    """Get progress config for a specific node"""
    return NODE_PROGRESS_MAP.get(
        node_name,
        {"emoji": "📌", "pct": 0, "label": node_name.upper()}
    )
