"""
MCP Servers Status Component
Shows connection status for MCP (Model Context Protocol) servers
"""

from typing import Dict, List, Optional


# MCP Server configuration (only actual servers in the project)
MCP_SERVERS = {
    "siem": {"name": "SIEM", "port": "8001", "description": "Security Events"},
    "memory": {"name": "Memory", "port": "8003", "description": "Incident Memory"},
}


def create_server_item(
    server_id: str,
    status: str = "disconnected",
    custom_name: Optional[str] = None,
    custom_port: Optional[str] = None,
) -> str:
    """
    Creates a single MCP server status item

    Args:
        server_id: Server identifier
        status: Connection status (connected, disconnected, connecting)
        custom_name: Override display name
        custom_port: Override port display

    Returns:
        HTML string for server item
    """
    config = MCP_SERVERS.get(server_id, {
        "name": server_id.upper(),
        "port": "----",
        "description": ""
    })

    name = custom_name or config["name"]
    port = custom_port or config["port"]
    status_class = status.lower() if status else "disconnected"

    return f"""
    <div class="server-item {status_class}">
        <span class="server-dot"></span>
        <span class="server-name">{name}</span>
        <span class="server-port">:{port}</span>
    </div>
    """


def create_mcp_servers_list(
    server_statuses: Optional[Dict[str, str]] = None,
) -> str:
    """
    Creates the MCP servers list

    Args:
        server_statuses: Dict mapping server_id to status

    Returns:
        HTML string for servers list
    """
    if server_statuses is None:
        server_statuses = {}

    servers_html = ""
    for server_id in MCP_SERVERS:
        status = server_statuses.get(server_id, "disconnected")
        servers_html += create_server_item(server_id, status)

    return f"""
    <div class="mcp-servers-list">
        {servers_html}
    </div>
    """


def create_mcp_status_card(
    server_statuses: Optional[Dict[str, str]] = None,
    show_connection_lines: bool = False,
    embedded: bool = True,
) -> str:
    """
    Creates the complete MCP Servers Bento card

    Args:
        server_statuses: Dict mapping server_id to status
        show_connection_lines: Whether to show animated connection lines
        embedded: If True, renders without outer card wrapper (for embedding in sidebar)

    Returns:
        HTML string for the complete card
    """
    if server_statuses is None:
        # Default to connected for main servers
        server_statuses = {
            "siem": "connected",
            "memory": "connected",
            "intel": "disconnected",
        }

    servers_list = create_mcp_servers_list(server_statuses)

    connection_lines = ""
    if show_connection_lines:
        connection_lines = """
        <div class="connection-lines">
            <svg class="connection-svg" viewBox="0 0 100 100" style="position: absolute; width: 100%; height: 100%; pointer-events: none; opacity: 0.3;">
                <line class="flow-line" x1="50" y1="0" x2="50" y2="100" stroke="var(--accent)" stroke-width="1" stroke-dasharray="4 2"/>
            </svg>
        </div>
        """

    if embedded:
        # Simplified version for embedding inside another card
        return f"""
        <div id="mcp-status-card">
            <div class="bento-card-header" style="margin-bottom: 12px;">
                <div class="bento-card-icon">⚡</div>
                <span class="bento-card-title">MCP SERVERS</span>
            </div>
            {servers_list}
            {connection_lines}
        </div>
        """
    else:
        # Full standalone card
        return f"""
        <div class="bento-card bento-2x2" id="mcp-status-card">
            <div class="bento-card-header">
                <div class="bento-card-icon">⚡</div>
                <span class="bento-card-title">MCP SERVERS</span>
            </div>
            {servers_list}
            {connection_lines}
        </div>
        """


def create_compact_mcp_indicator(
    connected_count: int,
    total_count: int,
) -> str:
    """
    Creates a compact MCP status indicator

    Args:
        connected_count: Number of connected servers
        total_count: Total number of servers

    Returns:
        HTML string for compact indicator
    """
    status_color = "var(--accent)" if connected_count == total_count else "var(--warning)"

    return f"""
    <div class="mcp-compact" style="display: flex; align-items: center; gap: 8px;">
        <span class="mcp-dot" style="width: 8px; height: 8px; border-radius: 50%; background: {status_color};"></span>
        <span class="mcp-text" style="font-family: var(--font-mono); font-size: var(--text-xs); color: var(--text-secondary);">
            MCP {connected_count}/{total_count}
        </span>
    </div>
    """


def get_mcp_connection_summary(server_statuses: Dict[str, str]) -> Dict[str, int]:
    """
    Gets a summary of MCP connection statuses

    Args:
        server_statuses: Dict mapping server_id to status

    Returns:
        Dict with connected, disconnected, and total counts
    """
    connected = sum(1 for s in server_statuses.values() if s == "connected")
    total = len(server_statuses)

    return {
        "connected": connected,
        "disconnected": total - connected,
        "total": total,
    }
