"""
Bento Grid Layout System for SOC Orchestrator
Provides helper functions and classes for building Bento-style grids in Gradio
"""

from enum import Enum
from typing import Callable, Optional
import gradio as gr


class BentoSize(Enum):
    """Bento card size classes matching CSS grid spans"""
    SMALL = "bento-2x1"       # 3 cols, 1 row
    SQUARE = "bento-2x2"      # 3 cols, 2 rows
    TALL = "bento-2x3"        # 3 cols, 3 rows
    MEDIUM = "bento-3x2"      # 4 cols, 2 rows
    WIDE = "bento-4x2"        # 6 cols, 2 rows
    LARGE = "bento-6x2"       # 8 cols, 2 rows
    EXTRA_LARGE = "bento-8x2" # 9 cols, 2 rows
    FULL = "bento-full"       # 12 cols, 1 row
    FULL_TALL = "bento-full-2"  # 12 cols, 2 rows


def create_bento_card(
    title: str,
    icon: str,
    size: BentoSize = BentoSize.SQUARE,
    elem_classes: Optional[list] = None,
    elem_id: Optional[str] = None,
) -> gr.HTML:
    """
    Creates a Bento card header HTML

    Args:
        title: Card title (will be uppercased)
        icon: Emoji icon for the card
        size: BentoSize enum for grid sizing
        elem_classes: Additional CSS classes
        elem_id: Element ID

    Returns:
        HTML string for the card header
    """
    classes = ["bento-card", size.value]
    if elem_classes:
        classes.extend(elem_classes)

    header_html = f"""
    <div class="bento-card-header">
        <div class="bento-card-icon">{icon}</div>
        <span class="bento-card-title">{title.upper()}</span>
    </div>
    """
    return header_html


def wrap_in_bento_card(
    content_html: str,
    title: str,
    icon: str,
    size: BentoSize = BentoSize.SQUARE,
    extra_classes: str = "",
    card_id: str = "",
) -> str:
    """
    Wraps content in a Bento card container with header

    Args:
        content_html: The HTML content to wrap
        title: Card title
        icon: Emoji icon
        size: BentoSize enum
        extra_classes: Additional CSS classes
        card_id: Optional element ID

    Returns:
        Complete Bento card HTML string
    """
    id_attr = f'id="{card_id}"' if card_id else ""

    return f"""
    <div class="bento-card {size.value} {extra_classes}" {id_attr}>
        <div class="bento-card-header">
            <div class="bento-card-icon">{icon}</div>
            <span class="bento-card-title">{title.upper()}</span>
        </div>
        <div class="bento-card-content">
            {content_html}
        </div>
    </div>
    """


def create_bento_grid(content_html: str, grid_class: str = "") -> str:
    """
    Wraps content in a Bento grid container

    Args:
        content_html: HTML content (cards)
        grid_class: Additional class for specific grid type

    Returns:
        Complete grid HTML
    """
    return f"""
    <div class="bento-grid {grid_class}">
        {content_html}
    </div>
    """


def create_investigation_grid() -> dict:
    """
    Returns the grid structure for the Investigation tab

    Layout:
    - Row 1: Agent Orchestration (full width)
    - Row 2: Reasoning Stream (8 cols) + Threat Score (4 cols)
    - Row 3: MITRE (4 cols) + Actions (4 cols) + Enrichment (4 cols)
    """
    return {
        "agent_orchestration": {"size": BentoSize.FULL, "icon": "🧠", "title": "Agent Orchestration"},
        "reasoning_stream": {"size": BentoSize.LARGE, "icon": "💭", "title": "Reasoning Stream"},
        "threat_score": {"size": BentoSize.SQUARE, "icon": "📊", "title": "Threat Score"},
        "mitre": {"size": BentoSize.MEDIUM, "icon": "🎯", "title": "MITRE ATT&CK"},
        "actions": {"size": BentoSize.MEDIUM, "icon": "✅", "title": "Actions"},
        "enrichment": {"size": BentoSize.MEDIUM, "icon": "🔗", "title": "Enrichment"},
    }


def create_memory_grid() -> dict:
    """
    Returns the grid structure for the Memory tab

    Layout:
    - Row 1: Memory Reasoning (8 cols) + Statistics (4 cols)
    - Row 2: Similar Incidents (full width)
    - Row 3: Campaign Detection (full width)
    """
    return {
        "memory_reasoning": {"size": BentoSize.LARGE, "icon": "💭", "title": "Memory Reasoning"},
        "statistics": {"size": BentoSize.SQUARE, "icon": "📊", "title": "Statistics"},
        "similar_incidents": {"size": BentoSize.FULL, "icon": "🔍", "title": "Similar Past Incidents"},
        "campaign_detection": {"size": BentoSize.FULL, "icon": "🚨", "title": "Campaign Detection"},
    }


def create_chat_grid() -> dict:
    """
    Returns the grid structure for the Chat tab

    Layout:
    - Row 1: Chat Interface (full width, flexible height)
    - Row 2: Quick Actions (full width)
    """
    return {
        "chat_interface": {"size": BentoSize.FULL_TALL, "icon": "💬", "title": "AI Assistant"},
        "quick_actions": {"size": BentoSize.FULL, "icon": "⚡", "title": "Quick Actions"},
    }


def create_sidebar_grid() -> dict:
    """
    Returns the grid structure for the Sidebar

    Layout:
    - Alert Input (tall card)
    - MCP Servers (square card)
    """
    return {
        "alert_input": {"size": BentoSize.TALL, "icon": "🎯", "title": "Alert Input"},
        "mcp_servers": {"size": BentoSize.SQUARE, "icon": "⚡", "title": "MCP Servers"},
    }


def get_agent_color(agent_name: str) -> str:
    """
    Returns the CSS color variable for an agent

    Args:
        agent_name: Name of the agent

    Returns:
        CSS variable string
    """
    agent_colors = {
        "supervisor": "var(--agent-supervisor)",
        "enrichment": "var(--agent-enrichment)",
        "analysis": "var(--agent-analysis)",
        "investigation": "var(--agent-investigation)",
        "response": "var(--agent-response)",
        "communication": "var(--agent-communication)",
        "memory": "var(--agent-memory)",
    }
    return agent_colors.get(agent_name.lower(), "var(--text-secondary)")


def get_severity_class(severity: str) -> str:
    """
    Returns the CSS class for a severity level

    Args:
        severity: Severity string (critical, high, medium, low)

    Returns:
        CSS class string
    """
    severity_map = {
        "critical": "critical",
        "high": "high",
        "medium": "medium",
        "low": "low",
        "info": "info",
    }
    return severity_map.get(severity.lower(), "medium")
