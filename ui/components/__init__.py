"""UI Components - Reusable HTML component generators"""

from ui.components.agent_chat import format_agent_chat_html
from ui.components.status_panel import (
    get_initial_status_compact_html,
    get_status_compact_html,
    get_threat_score_html,
)
from ui.components.results import format_results_html
from ui.components.memory_context import (
    format_similar_incidents_html,
    format_campaign_alert_html,
)

# Bento UI Components
from ui.components.bento_card import (
    create_bento_card,
    create_stat_card,
    create_stat_grid,
    create_action_list,
    create_technique_list,
    create_incident_grid,
    create_stream_message,
    create_empty_state,
)
from ui.components.agent_orchestration import (
    create_agent_pipeline,
    create_agent_orchestration_card,
    get_agent_status_from_events,
    AGENT_CONFIG,
)
from ui.components.mcp_status import (
    create_mcp_servers_list,
    create_mcp_status_card,
    create_compact_mcp_indicator,
)
from ui.components.threat_gauge import (
    create_score_ring,
    create_threat_score_card,
    create_severity_badge,
    create_mini_score,
    get_severity_from_score,
)

__all__ = [
    # Legacy components
    "format_agent_chat_html",
    "get_initial_status_compact_html",
    "get_status_compact_html",
    "get_threat_score_html",
    "format_results_html",
    "format_similar_incidents_html",
    "format_campaign_alert_html",
    # Bento components
    "create_bento_card",
    "create_stat_card",
    "create_stat_grid",
    "create_action_list",
    "create_technique_list",
    "create_incident_grid",
    "create_stream_message",
    "create_empty_state",
    "create_agent_pipeline",
    "create_agent_orchestration_card",
    "get_agent_status_from_events",
    "AGENT_CONFIG",
    "create_mcp_servers_list",
    "create_mcp_status_card",
    "create_compact_mcp_indicator",
    "create_score_ring",
    "create_threat_score_card",
    "create_severity_badge",
    "create_mini_score",
    "get_severity_from_score",
]
