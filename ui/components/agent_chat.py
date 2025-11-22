"""
Agent Chat Component
Formats agent messages as HTML with distinct styling per agent
"""

import html
from typing import Dict, List, Optional

from ui.config.agents import AGENT_CONFIG
from ui.helpers.html import markdown_to_html


def format_agent_chat_html(
    messages: List[Dict],
    streaming_agent: Optional[str] = None,
    streaming_content: str = "",
    agent_config: Optional[Dict] = None
) -> str:
    """
    Format agent chat messages as HTML with distinct styling per agent

    Args:
        messages: List of chat messages {agent, type, content, tool_name?}
        streaming_agent: Currently streaming agent (for live indicator)
        streaming_content: Current streaming content
        agent_config: Agent configuration with colors and emojis (uses default if None)

    Returns:
        HTML formatted chat
    """
    if not agent_config:
        agent_config = AGENT_CONFIG

    if not messages and not streaming_content:
        return "<div style='color: #666; padding: 20px; text-align: center;'>Waiting for agents to start...</div>"

    html_parts = []

    # Group consecutive messages from same agent
    current_agent = None
    current_group = []

    def render_agent_group(agent: str, group_messages: List[Dict]) -> str:
        """Render a group of messages from the same agent"""
        config = agent_config.get(agent, {"emoji": "🤖", "color": "#666", "name": agent.upper()})
        emoji = config["emoji"]
        color = config["color"]
        name = config["name"]

        # Agent header
        group_html = f"""
        <div style="margin-bottom: 16px; border-left: 3px solid {color}; padding-left: 12px;">
            <div style="display: flex; align-items: center; gap: 8px; margin-bottom: 8px;">
                <span style="font-size: 1.2rem;">{emoji}</span>
                <span style="color: {color}; font-weight: 700; font-size: 0.85rem; letter-spacing: 0.05em;">{name}</span>
            </div>
            <div style="color: #e0e0e0; font-size: 0.85rem; line-height: 1.6;">
        """

        for msg in group_messages:
            msg_type = msg.get("type", "thinking")
            content = msg.get("content", "")
            tool_name = msg.get("tool_name", "")

            if msg_type == "tool_call":
                # Tool call with special styling
                safe_content = html.escape(content) if content else ""
                group_html += f"""
                <div style="background: #1a1a2e; border: 1px solid {color}40; border-radius: 6px; padding: 8px 12px; margin: 6px 0; font-family: 'JetBrains Mono', monospace;">
                    <span style="color: #fbbf24;">🔧</span>
                    <span style="color: {color};">{html.escape(tool_name)}</span>
                    <span style="color: #888;">()</span>
                    {f'<span style="color: #10b981;"> → {safe_content}</span>' if safe_content else '<span style="color: #888;"> calling...</span>'}
                </div>
                """
            elif msg_type == "tool_result":
                # Tool result
                safe_content = html.escape(content)
                group_html += f"""
                <div style="background: #0a1a0a; border: 1px solid #10b98140; border-radius: 6px; padding: 8px 12px; margin: 6px 0;">
                    <span style="color: #10b981;">✓</span>
                    <span style="color: #a0a0a0;">{safe_content}</span>
                </div>
                """
            else:
                # Regular thinking/content - convert markdown to HTML
                formatted_content = markdown_to_html(content)
                group_html += f"<div style='margin: 4px 0;'>{formatted_content}</div>"

        group_html += "</div></div>"
        return group_html

    # Process messages and group by agent
    for msg in messages:
        agent = msg.get("agent", "unknown")
        if agent != current_agent:
            if current_group:
                html_parts.append(render_agent_group(current_agent, current_group))
            current_agent = agent
            current_group = [msg]
        else:
            current_group.append(msg)

    # Render last group
    if current_group:
        html_parts.append(render_agent_group(current_agent, current_group))

    # Add streaming content if active
    if streaming_agent and streaming_content:
        config = agent_config.get(streaming_agent, {"emoji": "🤖", "color": "#666", "name": streaming_agent.upper()})
        emoji = config["emoji"]
        color = config["color"]
        name = config["name"]

        # Convert markdown to HTML for streaming content too
        formatted_content = markdown_to_html(streaming_content)
        html_parts.append(f"""
        <div style="margin-bottom: 16px; border-left: 3px solid {color}; padding-left: 12px;">
            <div style="display: flex; align-items: center; gap: 8px; margin-bottom: 8px;">
                <span style="font-size: 1.2rem;">{emoji}</span>
                <span style="color: {color}; font-weight: 700; font-size: 0.85rem; letter-spacing: 0.05em;">{name}</span>
                <span style="color: #888; font-size: 0.7rem; animation: pulse 1s infinite;">● thinking...</span>
            </div>
            <div style="color: #e0e0e0; font-size: 0.85rem; line-height: 1.6;">
                {formatted_content}<span style="color: {color}; animation: blink 0.5s infinite;">█</span>
            </div>
        </div>
        """)

    # Styles only - no inner scroll container (let #reasoning_panel CSS handle scroll)
    return f"""
    <style>
        @keyframes blink {{ 0%, 50% {{ opacity: 1; }} 51%, 100% {{ opacity: 0; }} }}
        @keyframes pulse {{ 0%, 100% {{ opacity: 1; }} 50% {{ opacity: 0.5; }} }}
    </style>
    <div style="font-family: 'Inter', -apple-system, sans-serif; padding: 16px; background: transparent; border-radius: 8px;">
        {''.join(html_parts)}
    </div>
    """
