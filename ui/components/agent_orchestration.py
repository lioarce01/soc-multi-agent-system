"""
Agent Orchestration Component
Visual pipeline showing agent workflow and status
"""

from typing import Dict, List, Optional


# Agent configuration with icons and colors
AGENT_CONFIG = {
    "supervisor": {"icon": "👁️", "label": "SUP", "color": "var(--agent-supervisor)"},
    "enrichment": {"icon": "🔍", "label": "ENR", "color": "var(--agent-enrichment)"},
    "analysis": {"icon": "📊", "label": "ANA", "color": "var(--agent-analysis)"},
    "investigation": {"icon": "🔬", "label": "INV", "color": "var(--agent-investigation)"},
    "response": {"icon": "🛡️", "label": "RES", "color": "var(--agent-response)"},
    "communication": {"icon": "📡", "label": "COM", "color": "var(--agent-communication)"},
    "memory": {"icon": "🧠", "label": "MEM", "color": "var(--agent-memory)"},
}

# Default agent order in pipeline
DEFAULT_PIPELINE_ORDER = [
    "supervisor",
    "enrichment",
    "analysis",
    "investigation",
    "response",
    "communication",
]


def create_agent_node(
    agent_name: str,
    status: str = "pending",
) -> str:
    """
    Creates a single agent node in the pipeline

    Args:
        agent_name: Name of the agent
        status: Status (pending, active, completed)

    Returns:
        HTML string for agent node
    """
    config = AGENT_CONFIG.get(agent_name.lower(), {
        "icon": "⚙️",
        "label": agent_name[:3].upper(),
        "color": "var(--text-secondary)"
    })

    status_class = status.lower() if status else "pending"

    return f"""
    <div class="agent-node {status_class}" data-agent="{agent_name.lower()}">
        <div class="node-ring">
            <span class="node-icon">{config["icon"]}</span>
        </div>
        <span class="node-label">{config["label"]}</span>
    </div>
    """


def create_flow_connector(active: bool = False) -> str:
    """
    Creates a flow connector between agent nodes

    Args:
        active: Whether the flow is active

    Returns:
        HTML string for connector
    """
    active_class = "active" if active else ""
    return f'<div class="flow-connector {active_class}"></div>'


def create_agent_pipeline(
    agent_states: Optional[Dict[str, str]] = None,
    pipeline_order: Optional[List[str]] = None,
) -> str:
    """
    Creates the full agent pipeline visualization

    Args:
        agent_states: Dict mapping agent name to status (pending, active, completed)
        pipeline_order: List of agent names in order

    Returns:
        HTML string for complete pipeline
    """
    if agent_states is None:
        agent_states = {}

    if pipeline_order is None:
        pipeline_order = DEFAULT_PIPELINE_ORDER

    nodes_html = ""
    previous_completed = True  # Track if previous agent was completed for flow line

    for i, agent in enumerate(pipeline_order):
        # Get status, default to pending
        status = agent_states.get(agent, "pending")

        # Add agent node
        nodes_html += create_agent_node(agent, status)

        # Add connector between nodes (not after last)
        if i < len(pipeline_order) - 1:
            # Flow is active if previous was completed and current is active or completed
            flow_active = previous_completed and status in ("active", "completed")
            nodes_html += create_flow_connector(active=flow_active)

        # Update tracking
        previous_completed = (status == "completed")

    return f"""
    <div class="agent-pipeline">
        {nodes_html}
    </div>
    """


def create_agent_orchestration_card(
    agent_states: Optional[Dict[str, str]] = None,
    current_agent: Optional[str] = None,
) -> str:
    """
    Creates the complete Agent Orchestration Bento card

    Args:
        agent_states: Dict mapping agent name to status
        current_agent: Currently active agent (will override states)

    Returns:
        HTML string for the complete card
    """
    if agent_states is None:
        agent_states = {}

    # If current_agent is provided, set its status to active
    if current_agent:
        # Mark all agents up to current as completed
        for agent in DEFAULT_PIPELINE_ORDER:
            if agent == current_agent.lower():
                agent_states[agent] = "active"
                break
            else:
                agent_states[agent] = "completed"

    pipeline_html = create_agent_pipeline(agent_states)

    return f"""
    <div class="bento-card bento-full" id="agent-orchestration-card">
        <div class="bento-card-header">
            <div class="bento-card-icon">🧠</div>
            <span class="bento-card-title">AGENT ORCHESTRATION</span>
        </div>
        {pipeline_html}
    </div>
    """


def get_agent_status_from_events(events: List[Dict]) -> Dict[str, str]:
    """
    Parses stream events to determine agent statuses

    Args:
        events: List of stream event dicts

    Returns:
        Dict mapping agent name to status
    """
    statuses = {}
    active_agent = None

    for event in events:
        agent = event.get("agent", "").lower()
        if agent in AGENT_CONFIG:
            event_type = event.get("type", "")

            if event_type == "start":
                active_agent = agent
                statuses[agent] = "active"
            elif event_type == "end":
                statuses[agent] = "completed"

    # Set all agents before the active one as completed
    if active_agent:
        for agent in DEFAULT_PIPELINE_ORDER:
            if agent == active_agent:
                break
            if agent not in statuses:
                statuses[agent] = "completed"

    return statuses


def create_minimal_pipeline(current_step: int = 0) -> str:
    """
    Creates a minimal pipeline indicator

    Args:
        current_step: 0-based index of current step

    Returns:
        HTML string for minimal pipeline
    """
    steps = len(DEFAULT_PIPELINE_ORDER)
    dots_html = ""

    for i in range(steps):
        if i < current_step:
            dot_class = "completed"
        elif i == current_step:
            dot_class = "active"
        else:
            dot_class = "pending"

        dots_html += f'<span class="pipeline-dot {dot_class}"></span>'

    return f"""
    <div class="minimal-pipeline" style="display: flex; gap: 8px; align-items: center;">
        {dots_html}
    </div>
    """
