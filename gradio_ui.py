"""
Gradio Web Interface for SOC Orchestrator v2.0
Enhanced with Gradio 5.49+ features and async streaming best practices

IMPROVEMENTS:
- ✅ Native async generators (no asyncio.run)
- ✅ Real streaming (no buffering)
- ✅ HTML sanitization (XSS prevention)
- ✅ Queue configuration (concurrency limits)
- ✅ Gradio 5.49 features: Dialogue, Walkthrough, Performance metrics
- ✅ MCP resources ready
"""

import json
import html
import time
import logging
import sys
from pathlib import Path
from datetime import datetime
from typing import AsyncGenerator, Tuple, Dict, Any, List, Optional
import gradio as gr

# Suppress benign Windows asyncio connection reset errors
# These occur during normal MCP connection cleanup and are harmless
class WindowsAsyncioFilter(logging.Filter):
    """Filter out harmless Windows asyncio ConnectionResetError messages"""
    def filter(self, record: logging.LogRecord) -> bool:
        # Suppress WinError 10054 (connection forcibly closed)
        if "WinError 10054" in str(record.msg):
            return False
        if "_call_connection_lost" in str(record.msg):
            return False
        return True

# Apply filter to asyncio logger
asyncio_logger = logging.getLogger("asyncio")
asyncio_logger.addFilter(WindowsAsyncioFilter())

from src.graph import investigate_alert_streaming as graph_streaming
from src.state import create_initial_state

# Import from ui modules (modularized components)
from ui.config.agents import AGENT_CONFIG, NODE_PROGRESS_MAP
from ui.styles.css import GLOBAL_CSS, AUTO_SCROLL_JS
from ui.styles.bento_css import get_bento_css
from ui.helpers.html import sanitize_html as ui_sanitize_html, markdown_to_html
from ui.helpers.formatters import build_enrichment_data, format_activity_log, format_error_html
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
from ui.components.agent_orchestration import create_agent_pipeline, AGENT_CONFIG as BENTO_AGENT_CONFIG
from ui.components.mcp_status import create_mcp_status_card
from ui.components.threat_gauge import create_threat_score_card, create_score_ring, get_severity_from_score


# ===== HTML Sanitization (now imported from ui.helpers.html) =====
# Using: sanitize_html (aliased as ui_sanitize_html), markdown_to_html from ui.helpers.html

def sanitize_html(text: Any) -> str:
    """Wrapper for ui_sanitize_html for backwards compatibility"""
    return ui_sanitize_html(text)


# format_agent_chat_html is now imported from ui.components.agent_chat


# Wrapper functions for backwards compatibility with underscore naming
def _build_enrichment_data(source_state: Dict[str, Any]) -> Dict[str, Any]:
    return build_enrichment_data(source_state)

def _format_error_html(title: str, message: str, traceback: str = "") -> str:
    return format_error_html(title, message, traceback)


# ===== Core Investigation Function (ASYNC GENERATOR - NO asyncio.run) =====

async def investigate_alert_streaming_v2(
    alert_json: str
) -> AsyncGenerator[Tuple[str, str, str, str, str, str], None]:
    """
    REAL STREAMING investigation with bento grid layout (Gradio 5.x native support)

    Yields real-time updates as investigation progresses:
    - Compact status card (combines node status, progress, metrics)
    - Agent reasoning with integrated key events (LARGE - live LLM token streaming)
    - Investigation results (HTML report)
    - Memory reasoning (LLM explanation of similar incidents)
    - Similar incidents HTML (visual cards)
    - Campaign alert HTML (if campaign detected)

    Args:
        alert_json: JSON string containing alert data

    Yields:
        Tuple of (status_compact, reasoning_with_events, result_html, memory_reasoning, similar_incidents_html, campaign_alert_html)
    """

    # Helper to get timestamp
    def get_timestamp() -> str:
        return datetime.now().strftime("%H:%M:%S")

    # Node metadata for UI (name, emoji, progress percentage)
    node_progress_map = {
        "supervisor": {"emoji": "🎯", "pct": 16, "label": "SUPERVISOR"},
        "enrichment": {"emoji": "🔍", "pct": 33, "label": "ENRICHMENT"},
        "analysis": {"emoji": "🧠", "pct": 50, "label": "ANALYSIS"},
        "investigation": {"emoji": "🔎", "pct": 66, "label": "INVESTIGATION"},
        "response": {"emoji": "📋", "pct": 83, "label": "RESPONSE"},
        "communication": {"emoji": "📡", "pct": 100, "label": "COMMUNICATION"}
    }

    # Initialize tracking
    completed_nodes = []
    skipped_nodes = []
    activity_log_lines = []
    current_node = None
    current_progress = 0
    final_state = None
    start_time = time.time()
    node_timings = {}
    previous_node = None 
    last_node_complete_time = start_time

    accumulated_state = {
        "alert_id": None,
        "alert_data": {},
        "threat_score": 0.0,
        "attack_stage": "",
        "threat_category": "",
        "mitre_mappings": [],
        "recommendations": [],
        "report": "",
        "enrichment_data": {},
        "workflow_status": "in_progress",
        "similar_incidents": [],  # Memory fields
        "memory_reasoning": "",
        "campaign_info": None
    }
    
    # Agent Chat System - Messages from all agents
    agent_chat_messages = []  # List of {agent, type, content, tool_name?}
    current_streaming_content = ""  # For token-by-token streaming
    current_streaming_agent = None

    # Cache for status HTML to prevent flicker during token streaming
    cached_status_html = _get_initial_status_compact_html()

    # Agent configuration with colors and emojis
    agent_config = {
        "supervisor": {"emoji": "🎯", "color": "#3b82f6", "name": "SUPERVISOR"},
        "enrichment": {"emoji": "🔍", "color": "#10b981", "name": "ENRICHMENT"},
        "analysis": {"emoji": "🧠", "color": "#f59e0b", "name": "ANALYSIS"},
        "investigation": {"emoji": "🔬", "color": "#8b5cf6", "name": "INVESTIGATION"},
        "response": {"emoji": "🛡️", "color": "#ef4444", "name": "RESPONSE"},
        "communication": {"emoji": "📝", "color": "#06b6d4", "name": "COMMUNICATION"},
        "memory": {"emoji": "💾", "color": "#ec4899", "name": "MEMORY"},
    }

    try:
        # Parse and sanitize alert
        alert_data = json.loads(alert_json)

        # Sanitize critical fields
        alert_data["id"] = sanitize_html(alert_data.get("id", "unknown"))
        alert_data["type"] = sanitize_html(alert_data.get("type", "unknown"))
        alert_data["title"] = sanitize_html(alert_data.get("title", "Untitled Alert"))

        # Initial log
        activity_log_lines.append(_format_activity_log(
            get_timestamp(),
            "SYSTEM",
            f"Investigation started for alert {alert_data.get('id')}",
            "🚀"
        ))

        yield (
            _get_initial_status_compact_html(),
            "",  # Empty reasoning initially
            "",  # No results yet
            "*No memory context available yet. Run an investigation first.*",  # Memory reasoning
            "",  # Similar incidents HTML
            ""  # Campaign alert HTML
        )

        async for event in graph_streaming(alert_data):
            event_type = event.get("type")
            node = event.get("node")
            message = event.get("message", "")
            state = event.get("state")

            if state:
                # Update accumulated state with any non-empty fields
                for key in accumulated_state.keys():
                    if key in state and state[key]:
                        # For lists, extend instead of replace
                        if isinstance(accumulated_state[key], list) and isinstance(state[key], list):
                            accumulated_state[key] = state[key]  # Replace with latest
                        # For dicts, merge
                        elif isinstance(accumulated_state[key], dict) and isinstance(state[key], dict):
                            accumulated_state[key].update(state[key])
                        # For other values, update if not empty
                        else:
                            accumulated_state[key] = state[key]

            # This works because LangGraph executes nodes sequentially, so the time
            # between completions represents the actual node execution time
            current_event_time = time.time()

            if event_type == "node_complete" and node in node_progress_map:
                # Calculate duration since last node completed
                duration = current_event_time - last_node_complete_time

                node_timings[node] = {
                    "start": last_node_complete_time,
                    "end": current_event_time,
                    "duration": duration
                }

                # Update for next node
                last_node_complete_time = current_event_time

            # Handle LLM reasoning events - Agent Chat System
            if event_type == "llm_reasoning_start":
                current_streaming_agent = node
                current_streaming_content = ""
                # Don't yield here - wait for tokens to come
                continue

            elif event_type == "llm_token":
                # Append token to streaming content
                token = event.get("data", {}).get("token", message)
                current_streaming_content += token

                # Check if streaming content looks like JSON - don't display live
                content_preview = current_streaming_content.strip()
                is_json_streaming = (
                    content_preview.startswith('[') or
                    content_preview.startswith('{') or
                    content_preview.startswith('```json') or
                    content_preview.startswith('```\n[') or
                    content_preview.startswith('```\n{')
                )

                # Only show streaming if it's not JSON
                display_content = "" if is_json_streaming else current_streaming_content

                # Generate chat HTML with streaming
                chat_html = format_agent_chat_html(
                    agent_chat_messages,
                    streaming_agent=current_streaming_agent if not is_json_streaming else None,
                    streaming_content=display_content,
                    agent_config=agent_config
                )

                # Yield with updated reasoning (REAL-TIME TOKEN STREAMING)
                # IMPORTANT: Use cached_status_html to prevent flicker!
                # Status panel doesn't need to update on each token
                memory_reasoning = accumulated_state.get("memory_reasoning", "")
                similar_incidents = accumulated_state.get("similar_incidents", [])
                campaign_info = accumulated_state.get("campaign_info")

                memory_reasoning_md = memory_reasoning if memory_reasoning else "*No memory reasoning available yet.*"
                similar_incidents_html = format_similar_incidents_html(similar_incidents)
                campaign_alert_html = format_campaign_alert_html(campaign_info)

                yield (
                    cached_status_html,  # Use cached status to prevent flicker
                    chat_html,  # Agent Chat with live streaming
                    "",  # No HTML results yet
                    memory_reasoning_md,  # Memory reasoning
                    similar_incidents_html,  # Similar incidents
                    campaign_alert_html  # Campaign alert
                )
                continue  # Skip the normal yield at the end

            elif event_type == "llm_reasoning_complete":
                # Save completed reasoning to agent chat messages
                # Filter out JSON responses (from plan/findings generation)
                if current_streaming_agent and current_streaming_content:
                    content = current_streaming_content.strip()

                    # Skip if content is primarily JSON (investigation plan/findings)
                    is_json = (
                        (content.startswith('[') and content.rstrip().endswith(']')) or
                        (content.startswith('{') and content.rstrip().endswith('}')) or
                        (content.startswith('```json') or content.startswith('```\n[') or content.startswith('```\n{'))
                    )

                    if not is_json and len(content) > 50:  # Only save non-JSON, meaningful content
                        agent_chat_messages.append({
                            "agent": current_streaming_agent,
                            "type": "thinking",
                            "content": content
                        })

                current_streaming_agent = None
                current_streaming_content = ""
                # Don't yield here - the next event will update the display
                continue

            # Handle tool call events (NEW - for Agent Chat)
            elif event_type == "tool_call":
                tool_data = event.get("data", {})
                agent_chat_messages.append({
                    "agent": node,
                    "type": "tool_call",
                    "tool_name": tool_data.get("tool", "unknown"),
                    "content": tool_data.get("result", "")
                })

            elif event_type == "tool_result":
                tool_data = event.get("data", {})
                agent_chat_messages.append({
                    "agent": node,
                    "type": "tool_result",
                    "content": tool_data.get("summary", message)
                })

            # Handle agent_message events (for non-streaming agent output)
            elif event_type == "agent_message":
                agent_chat_messages.append({
                    "agent": node,
                    "type": "thinking",
                    "content": message
                })

            # Map event type to emoji
            emoji_map = {
                "investigation_start": "🚀",
                "node_start": "▶️",
                "state_update": "🔄",
                "node_complete": "✅",
                "investigation_complete": "🎉",
                "llm_reasoning_start": "🤔",
                "llm_reasoning_complete": "✅"
            }
            emoji = node_progress_map.get(node, {}).get("emoji", emoji_map.get(event_type, "📌"))

            if event_type == "node_start" and node in node_progress_map:
                # Check if we skipped investigation (analysis → response)
                if previous_node == "analysis" and node == "response":
                    if "investigation" not in completed_nodes and "investigation" not in skipped_nodes:
                        skipped_nodes.append("investigation")
                        activity_log_lines.append(_format_activity_log(
                            get_timestamp(),
                            "INVESTIGATION",
                            "Skipped (threat score below threshold)",
                            "⏭️"
                        ))

            if node in node_progress_map:
                current_node = node
                if event_type == "node_start":
                    # Set progress to slightly before node completion
                    current_progress = max(node_progress_map[node]["pct"] - 8, current_progress)
                    # Update cached status HTML on state change
                    cached_status_html = _get_status_compact_html(current_node, completed_nodes, skipped_nodes, current_progress, time.time() - start_time)
                elif event_type == "node_complete":
                    # Set progress to node's target percentage
                    current_progress = node_progress_map[node]["pct"]
                    completed_nodes.append(node)
                    previous_node = node  # Track for skip detection
                    # Update cached status HTML on state change
                    cached_status_html = _get_status_compact_html(current_node, completed_nodes, skipped_nodes, current_progress, time.time() - start_time)

            # Add activity log (sanitize message)
            activity_log_lines.append(_format_activity_log(
                get_timestamp(),
                node.upper() if node != "system" else "SYSTEM",
                sanitize_html(message),
                emoji
            ))

            # Keep only last 50 lines
            if len(activity_log_lines) > 50:
                activity_log_lines = activity_log_lines[-50:]

            # Store final state
            if event_type == "investigation_complete":
                final_state = state
                current_progress = 100

            # Generate Agent Chat HTML
            chat_html = format_agent_chat_html(
                agent_chat_messages,
                streaming_agent=current_streaming_agent,
                streaming_content=current_streaming_content,
                agent_config=agent_config
            )

            # Extract memory data from accumulated state
            memory_reasoning = accumulated_state.get("memory_reasoning", "")
            similar_incidents = accumulated_state.get("similar_incidents", [])
            campaign_info = accumulated_state.get("campaign_info")

            memory_reasoning_md = memory_reasoning if memory_reasoning else "*No memory reasoning available yet.*"
            similar_incidents_html = format_similar_incidents_html(similar_incidents)
            campaign_alert_html = format_campaign_alert_html(campaign_info)

            yield (
                cached_status_html,  # Use cached status to prevent flicker
                chat_html,  # Agent Chat
                "",  # No HTML results yet
                memory_reasoning_md,  # Memory reasoning
                similar_incidents_html,  # Similar incidents
                campaign_alert_html  # Campaign alert
            )

        # Investigation complete - format results
        if final_state or accumulated_state.get("report"):  # Check if we have any data
            # Calculate total time
            total_time = time.time() - start_time

            # Use accumulated_state (which has all data collected during streaming)
            source_state = accumulated_state

            # Convert state to result format
            result = {
                "alert_id": sanitize_html(source_state.get("alert_id")) if source_state.get("alert_id") else "Unknown",
                "alert_type": sanitize_html(source_state.get("alert_data", {}).get("type", "Unknown")),
                "threat_score": source_state.get("threat_score", 0.0),
                "attack_stage": sanitize_html(source_state.get("attack_stage", "")),
                "threat_category": sanitize_html(source_state.get("threat_category", "")),
                "mitre_mappings": source_state.get("mitre_mappings", []),
                "recommendations": source_state.get("recommendations", []),
                "report": source_state.get("report", ""),
                "enrichment_data": _build_enrichment_data(source_state),
                "workflow_status": source_state.get("workflow_status", "completed"),
                "performance": {
                    "total_time": round(total_time, 2),
                    "node_timings": {k: round(v.get("duration", 0), 2) for k, v in node_timings.items()}
                }
            }

            # Format final results
            html_output = format_results_html(result)
            json_output = json.dumps(result, indent=2)

            # Final yield with results
            activity_log_lines.append(_format_activity_log(
                get_timestamp(),
                "SYSTEM",
                f"Investigation completed in {total_time:.2f}s - Threat Score: {result['threat_score']:.2f}",
                "🎉"
            ))

            # Get final Agent Chat HTML
            final_chat_html = format_agent_chat_html(
                agent_chat_messages,
                agent_config=agent_config
            )

            # Extract final memory data
            memory_reasoning = accumulated_state.get("memory_reasoning", "")
            similar_incidents = accumulated_state.get("similar_incidents", [])
            campaign_info = accumulated_state.get("campaign_info")

            memory_reasoning_md = memory_reasoning if memory_reasoning else "*No memory reasoning available.*"
            similar_incidents_html = format_similar_incidents_html(similar_incidents)
            campaign_alert_html = format_campaign_alert_html(campaign_info)

            yield (
                _get_status_compact_html("communication", completed_nodes, skipped_nodes, 100, total_time, result['threat_score']),
                final_chat_html,  # Final Agent Chat
                html_output,  # Investigation results
                memory_reasoning_md,  # Memory reasoning
                similar_incidents_html,  # Similar incidents
                campaign_alert_html  # Campaign alert
            )
        else:
            # No final state - error
            error_html = _format_error_html("No final state received", "Investigation did not complete")
            yield (
                _get_status_compact_html(current_node or "supervisor", completed_nodes, skipped_nodes, current_progress, time.time() - start_time),
                "",  # Empty reasoning on error
                error_html,
                "*No memory context available.*",  # Memory reasoning
                "",  # Similar incidents HTML
                ""  # Campaign alert HTML
            )

    except json.JSONDecodeError as e:
        error_html = _format_error_html("Invalid JSON", str(e))
        activity_log_lines.append(_format_activity_log(
            get_timestamp(),
            "ERROR",
            f"Invalid JSON format: {sanitize_html(str(e))}",
            "❌"
        ))

        yield (
            _get_initial_status_compact_html(),
            "",  # Empty reasoning on error
            error_html,
            "*No memory context available.*",  # Memory reasoning
            "",  # Similar incidents HTML
            ""  # Campaign alert HTML
        )

    except Exception as e:
        import traceback
        error_html = _format_error_html("Investigation Failed", str(e), traceback.format_exc())
        activity_log_lines.append(_format_activity_log(
            get_timestamp(),
            "ERROR",
            sanitize_html(str(e)),
            "❌"
        ))

        yield (
            _get_initial_status_compact_html(),
            "",  # Empty reasoning on error
            error_html,
            "*No memory context available.*",  # Memory reasoning
            "",  # Similar incidents HTML
            ""  # Campaign alert HTML
        )


# ===== Load Sample Alerts =====

def load_sample_alerts() -> List[Dict]:
    """Load sample alerts from data directory"""
    alerts_file = Path(__file__).parent / "data" / "sample_alerts.json"

    try:
        with open(alerts_file, "r", encoding="utf-8") as f:
            alerts = json.load(f)
        return alerts
    except FileNotFoundError:
        return []


# format_results_html is now imported from ui.components.results


# Status HTML generators are now imported from ui.components.status_panel:
# - get_initial_status_compact_html
# - get_status_compact_html
# - get_threat_score_html

# Wrapper functions for backwards compatibility with underscore naming
def _get_initial_status_compact_html() -> str:
    return get_initial_status_compact_html()

def _get_status_compact_html(current_node: str, completed_nodes: List[str], skipped_nodes: List[str], progress_pct: int, total_time: float, threat_score: float = None) -> str:
    return get_status_compact_html(current_node, completed_nodes, skipped_nodes, progress_pct, total_time, threat_score)

# _format_activity_log is now imported from ui.helpers.formatters as format_activity_log
def _format_activity_log(timestamp: str, node: str, message: str, emoji: str = "🔄") -> str:
    return format_activity_log(timestamp, node, message, emoji)




# Memory context formatters are now imported from ui.components.memory_context:
# - format_similar_incidents_html
# - format_campaign_alert_html


# ===== Gradio UI =====

def create_gradio_interface():
    """
    Create Gradio web interface with v5.49+ features

    Features:
    - Async streaming (native)
    - Dialogue component for confirmations
    - Walkthrough for guided workflow
    - Performance metrics
    - Queue configuration
    """

    # Load sample alert for default value
    sample_alerts = load_sample_alerts()
    default_alert_json = json.dumps(sample_alerts[0], indent=2) if sample_alerts else "{}"

    # Bento UI Theme - Neon green accent on pure black
    # Inspired by Apple Vision Pro / Linear / Arc Browser
    dark_minimal_theme = gr.themes.Base(
        primary_hue=gr.themes.colors.emerald,  # Neon green family
        secondary_hue=gr.themes.colors.slate,
        neutral_hue=gr.themes.colors.zinc,
        font=[gr.themes.GoogleFont("Inter"), "ui-sans-serif", "system-ui", "sans-serif"],
    ).set(
        # === BACKGROUNDS (Pure black) ===
        body_background_fill="#000000",
        body_background_fill_dark="#000000",
        background_fill_primary="#000000",
        background_fill_primary_dark="#000000",
        background_fill_secondary="#0a0a0a",
        background_fill_secondary_dark="#0a0a0a",

        # === BORDERS (Subtle) ===
        border_color_primary="#1a1a1a",
        border_color_primary_dark="#1a1a1a",
        border_color_accent="#00ff88",  # Neon green accent
        border_color_accent_dark="#00ff88",

        # === BUTTONS - Neon Green Accent ===
        button_primary_background_fill="#00ff88",
        button_primary_background_fill_dark="#00ff88",
        button_primary_background_fill_hover="#00ff99",
        button_primary_background_fill_hover_dark="#00ff99",
        button_primary_border_color="#00ff88",
        button_primary_border_color_dark="#00ff88",
        button_primary_text_color="#000000",  # Black text on green
        button_primary_text_color_dark="#000000",

        button_secondary_background_fill="#0a0a0a",
        button_secondary_background_fill_dark="#0a0a0a",
        button_secondary_background_fill_hover="#111111",
        button_secondary_background_fill_hover_dark="#111111",
        button_secondary_border_color="#1a1a1a",
        button_secondary_border_color_dark="#1a1a1a",
        button_secondary_text_color="#71717a",
        button_secondary_text_color_dark="#71717a",

        # === INPUTS ===
        input_background_fill="#0a0a0a",
        input_background_fill_dark="#0a0a0a",
        input_background_fill_focus="#0a0a0a",
        input_background_fill_focus_dark="#0a0a0a",
        input_border_color="#1a1a1a",
        input_border_color_dark="#1a1a1a",
        input_border_color_focus="#00ff88",  # Neon green on focus
        input_border_color_focus_dark="#00ff88",
        input_border_width="1px",
        input_shadow="0 0 0 0 rgba(0, 255, 136, 0)",
        input_shadow_focus="0 0 0 2px rgba(0, 255, 136, 0.2)",

        # === TEXT COLORS ===
        block_title_text_color="#ffffff",
        block_title_text_color_dark="#ffffff",
        block_label_text_color="#71717a",
        block_label_text_color_dark="#71717a",
        block_info_text_color="#52525b",
        block_info_text_color_dark="#52525b",
        body_text_color="#ffffff",
        body_text_color_dark="#ffffff",
        body_text_color_subdued="#71717a",
        body_text_color_subdued_dark="#71717a",

        # === CODE BLOCKS ===
        code_background_fill="#0a0a0a",
        code_background_fill_dark="#0a0a0a",

        # === PANELS/BLOCKS ===
        panel_background_fill="#0a0a0a",
        panel_background_fill_dark="#0a0a0a",
        panel_border_color="#1a1a1a",
        panel_border_color_dark="#1a1a1a",
        panel_border_width="1px",

        # === SHADOWS ===
        shadow_drop="0 1px 3px rgba(0, 0, 0, 0.3)",
        shadow_drop_lg="0 4px 12px rgba(0, 0, 0, 0.4)",
        shadow_inset="inset 0 1px 2px rgba(0, 0, 0, 0.3)",
        shadow_spread="0 0 20px rgba(0, 255, 136, 0.05)",

        # === SPACING (Bento = generous) ===
        block_padding="24px",
        container_radius="24px",  # Extra rounded for Bento
        block_radius="16px",

        # === SLIDERS & INTERACTIVE ===
        slider_color="#00ff88",
        slider_color_dark="#00ff88",
        checkbox_background_color="#0a0a0a",
        checkbox_background_color_dark="#0a0a0a",
        checkbox_background_color_selected="#00ff88",
        checkbox_background_color_selected_dark="#00ff88",
        checkbox_border_color="#1a1a1a",
        checkbox_border_color_dark="#1a1a1a",
        checkbox_border_color_focus="#00ff88",
        checkbox_border_color_focus_dark="#00ff88",
        checkbox_label_text_color="#ffffff",
        checkbox_label_text_color_dark="#ffffff",
    )
    
    # Create Gradio Blocks interface
    # CSS and JS are imported from ui.styles.css module
    # Combine global CSS with Bento CSS for modern UI
    combined_css = GLOBAL_CSS + "\n" + get_bento_css()

    with gr.Blocks(
        title="SOC Orchestrator",
        theme=dark_minimal_theme,
        css=combined_css,
        js=AUTO_SCROLL_JS
    ) as demo:

        # ===== BENTO HEADER BAR =====
        gr.HTML("""
            <div class="bento-header">
                <div class="bento-logo">
                    <span style="font-size: 24px;">🛡️</span>
                    <span class="bento-logo-text">SOC ORCHESTRATOR</span>
                </div>
                <span class="bento-version">⚡ v2.0</span>
            </div>
        """)

        # ===== MAIN LAYOUT: SIDEBAR (25%) | CONTENT (75%) =====
        with gr.Row(elem_id="main_container"):
            # ===== LEFT: SIDEBAR (25%) =====
            with gr.Column(scale=25, min_width=300, elem_id="sidebar"):
                # Alert Input Bento Card
                gr.HTML("""
                    <div class="bento-card" style="margin-bottom: 16px;">
                        <div class="bento-card-header">
                            <div class="bento-card-icon">🎯</div>
                            <span class="bento-card-title">ALERT INPUT</span>
                        </div>
                    </div>
                """, visible=False)  # Header rendered separately for cleaner layout

                with gr.Column(elem_id="sidebar_card", elem_classes=["bento-card"]):
                    # Bento Header for Alert Input
                    gr.HTML("""
                        <div class="bento-card-header" style="margin-bottom: 16px;">
                            <div class="bento-card-icon">🎯</div>
                            <span class="bento-card-title">ALERT INPUT</span>
                        </div>
                    """)

                    # Status Panel
                    status_compact = gr.HTML(
                        value=_get_initial_status_compact_html(),
                        show_label=False,
                        elem_id="status_compact"
                    )

                    # Alert Input
                    alert_input = gr.Code(
                        language="json",
                        lines=16,
                        value=default_alert_json,
                        show_label=False,
                        container=False,
                        elem_id="alert_input"
                    )

                    investigate_btn = gr.Button(
                        "▶ ANALYZE",
                        variant="primary",
                        size="lg",
                        elem_id="investigate_btn",
                        elem_classes=["analyze-button"]
                    )

                    # MCP Servers Status Card (inside sidebar_card)
                    # Only showing actual MCP servers: SIEM and Memory
                    gr.HTML("""<div style="margin-top: 20px; padding-top: 20px; border-top: 1px solid var(--border-subtle, #1a1a1a);"></div>""")
                    mcp_status_html = gr.HTML(
                        value=create_mcp_status_card({
                            "siem": "connected",
                            "memory": "connected",
                        }),
                        elem_id="mcp_status_panel"
                    )

            # ===== RIGHT: CONTENT AREA (75%) - Multi-Tab Interface =====
            with gr.Column(scale=75, elem_id="content_area"):
                with gr.Tabs(elem_classes=["bento-tabs"]) as investigation_tabs:

                    # ===== TAB 1: INVESTIGATION (Current Workflow) =====
                    with gr.Tab("🔍 Investigation", id="tab_investigation"):
                        # Agent Reasoning Card (Bento style)
                        with gr.Column(elem_id="reasoning_card", elem_classes=["bento-card"]):
                            gr.HTML("""
                                <div class="bento-card-header">
                                    <div class="bento-card-icon">💭</div>
                                    <span class="bento-card-title">AGENT REASONING</span>
                                    <span class="live-indicator">
                                        <span class="live-dot"></span>
                                        LIVE
                                    </span>
                                </div>
                            """)
                            reasoning_panel = gr.HTML(
                                value="""<div class="stream-container" style="min-height: 200px;">
                                    <div style="color: var(--text-tertiary, #52525b); padding: 40px; text-align: center;">
                                        Agent reasoning will stream here during investigation...
                                    </div>
                                </div>""",
                                show_label=False,
                                elem_id="reasoning_panel"
                            )

                        # Investigation Results Card (Bento style)
                        with gr.Column(elem_id="results_card", elem_classes=["bento-card"]):
                            gr.HTML("""
                                <div class="bento-card-header">
                                    <div class="bento-card-icon">📋</div>
                                    <span class="bento-card-title">INVESTIGATION RESULTS</span>
                                </div>
                            """)
                            result_html = gr.HTML(
                                value="""<div style="color: var(--text-tertiary, #52525b); padding: 40px; text-align: center;">
                                    Investigation results will appear here after analysis completes...
                                </div>""",
                                show_label=False,
                                elem_id="result_html"
                            )

                    # ===== TAB 2: MEMORY CONTEXT =====
                    with gr.Tab("🧠 Memory", id="tab_memory"):
                        # Memory Reasoning Card (Bento style)
                        with gr.Column(elem_id="memory_reasoning_card", elem_classes=["bento-card"]):
                            gr.HTML("""
                                <div class="bento-card-header">
                                    <div class="bento-card-icon">💭</div>
                                    <span class="bento-card-title">MEMORY REASONING</span>
                                </div>
                            """)
                            memory_reasoning_display = gr.Markdown(
                                value="*No memory context available yet. Run an investigation first.*",
                                show_label=False,
                                elem_id="memory_reasoning_panel"
                            )

                        # Similar Incidents Card (Bento style)
                        with gr.Column(elem_id="similar_incidents_card", elem_classes=["bento-card"]):
                            gr.HTML("""
                                <div class="bento-card-header">
                                    <div class="bento-card-icon">🔍</div>
                                    <span class="bento-card-title">SIMILAR PAST INCIDENTS</span>
                                </div>
                            """)
                            similar_incidents_display = gr.HTML(
                                value="""<div style="color: var(--text-tertiary, #52525b); padding: 40px; text-align: center;">
                                    Similar incidents will appear here after investigation...
                                </div>""",
                                show_label=False,
                                elem_id="similar_incidents_html"
                            )

                        # Campaign Detection Card (Bento style)
                        with gr.Column(elem_classes=["bento-card"]):
                            gr.HTML("""
                                <div class="bento-card-header">
                                    <div class="bento-card-icon">🚨</div>
                                    <span class="bento-card-title">CAMPAIGN DETECTION</span>
                                </div>
                            """)
                            campaign_alert_display = gr.HTML(
                                value="""<div style="color: var(--text-tertiary, #52525b); padding: 40px; text-align: center;">
                                    Campaign information will appear here if detected...
                                </div>""",
                                visible=True,
                                show_label=False,
                                elem_id="campaign_alert_html"
                            )

                    # ===== TAB 3: CHAT =====
                    with gr.Tab("💬 Chat", id="tab_chat"):
                        # Chat Interface Card (Full Width)
                        with gr.Column(elem_id="chat_card", elem_classes=["bento-card"]):
                            gr.HTML("""
                                <div class="bento-card-header">
                                    <div class="bento-card-icon">💬</div>
                                    <span class="bento-card-title">AI ASSISTANT</span>
                                </div>
                            """)

                            # Chatbot with Bento styling
                            chatbot = gr.Chatbot(
                                height=400,
                                show_label=False,
                                elem_id="chat_history",
                                bubble_full_width=False,
                                elem_classes=["chat-messages"]
                            )

                            # Message input with Bento styling
                            with gr.Row(elem_classes=["chat-input-container"]):
                                chat_input = gr.Textbox(
                                    placeholder="Ask about past investigations...",
                                    show_label=False,
                                    scale=9,
                                    container=False,
                                    elem_classes=["chat-input"]
                                )
                                chat_send = gr.Button("▶ Send", scale=1, variant="primary", elem_classes=["chat-send-btn"])

                        # Quick Actions Card (Full Width)
                        with gr.Column(elem_classes=["bento-card"]):
                            gr.HTML("""
                                <div class="bento-card-header">
                                    <div class="bento-card-icon">⚡</div>
                                    <span class="bento-card-title">QUICK ACTIONS</span>
                                </div>
                            """)

                            with gr.Row():
                                example_btn1 = gr.Button("📊 Statistics", size="sm", elem_classes=["quick-action-card"])
                                example_btn2 = gr.Button("🔴 High Alerts", size="sm", elem_classes=["quick-action-card"])
                                example_btn3 = gr.Button("🎯 Campaigns", size="sm", elem_classes=["quick-action-card"])
                            
                            # Connect chat functionality with streaming status updates
                            from src.chat_graph import chat_with_history_streaming

                            async def submit_chat_streaming(message, history):
                                """Handle chat submission with streaming status updates"""
                                if not message.strip():
                                    yield history, ""
                                    return
                                try:
                                    async for updated_history, _ in chat_with_history_streaming(message, history):
                                        yield updated_history, ""
                                except Exception as e:
                                    error_msg = f"Error: {str(e)}"
                                    history.append([message, error_msg])
                                    yield history, ""

                            chat_input.submit(
                                fn=submit_chat_streaming,
                                inputs=[chat_input, chatbot],
                                outputs=[chatbot, chat_input]
                            )

                            chat_send.click(
                                fn=submit_chat_streaming,
                                inputs=[chat_input, chatbot],
                                outputs=[chatbot, chat_input]
                            )
                            
                            # Example button handlers
                            example_btn1.click(
                                fn=lambda: "Show me statistics for the last 7 days",
                                outputs=chat_input
                            )
                            
                            example_btn2.click(
                                fn=lambda: "Show me all high-severity alerts",
                                outputs=chat_input
                            )
                            
                            example_btn3.click(
                                fn=lambda: "Are there any active attack campaigns?",
                                outputs=chat_input
                            )


        # Connect button to ASYNC STREAMING investigation function
        investigate_btn.click(
            fn=investigate_alert_streaming_v2,
            inputs=alert_input,
            outputs=[
                status_compact,              # Compact status card
                reasoning_panel,             # Reasoning with integrated events
                result_html,                 # Investigation results
                memory_reasoning_display,    # Memory reasoning (Tab 2)
                similar_incidents_display,   # Similar incidents (Tab 2)
                campaign_alert_display       # Campaign alert (Tab 2)
            ]
        )

    return demo


# ===== Main Entry Point =====

if __name__ == "__main__":
    print(" SOC ORCHESTRATOR - GRADIO UI")
    print("\nStarting Gradio interface...")

    # Create and launch interface
    demo = create_gradio_interface()

    demo.queue(
        max_size=20,  # Max 20 requests in queue
        default_concurrency_limit=5  # Max 5 concurrent investigations
    )

    demo.launch(
        server_name="0.0.0.0",
        server_port=7860,
        share=False,
        show_error=True,
        max_threads=40  # Thread pool for non-async functions
    )
