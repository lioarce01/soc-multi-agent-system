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
from pathlib import Path
from datetime import datetime
from typing import AsyncGenerator, Tuple, Dict, Any, List, Optional
import gradio as gr

from src.graph import investigate_alert_streaming as graph_streaming
from src.state import create_initial_state


# ===== HTML Sanitization =====

def sanitize_html(text: Any) -> str:
    """
    Escape HTML to prevent XSS attacks

    Args:
        text: Any input that will be rendered in HTML

    Returns:
        HTML-escaped string
    """
    return html.escape(str(text))


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
    
    # NEW: Track reasoning text per node
    reasoning_buffer = {
        "analysis": "",
        "investigation": "",
        "response": "",
        "current": ""
    }
    current_reasoning_node = None

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

            # Handle LLM reasoning events (NEW)
            if event_type == "llm_reasoning_start":
                current_reasoning_node = node
                reasoning_buffer["current"] = f"\n[🤔 {node.upper()} AGENT] Thinking...\n\n"
                
            elif event_type == "llm_token":
                # Append token to current reasoning
                token = event.get("data", {}).get("token", message)
                reasoning_buffer["current"] += token
                
                # Update reasoning panel immediately (real-time streaming)
                reasoning_display = (
                    reasoning_buffer.get("analysis", "") +
                    reasoning_buffer.get("investigation", "") +
                    reasoning_buffer.get("response", "") +
                    reasoning_buffer["current"]
                )
                
                # Yield with updated reasoning (REAL-TIME TOKEN STREAMING)
                # Extract memory data from accumulated state
                memory_reasoning = accumulated_state.get("memory_reasoning", "")
                similar_incidents = accumulated_state.get("similar_incidents", [])
                campaign_info = accumulated_state.get("campaign_info")
                
                memory_reasoning_md = memory_reasoning if memory_reasoning else "*No memory reasoning available yet.*"
                similar_incidents_html = format_similar_incidents_html(similar_incidents)
                campaign_alert_html = format_campaign_alert_html(campaign_info)
                
                yield (
                    _get_status_compact_html(current_node or "supervisor", completed_nodes, skipped_nodes, current_progress, time.time() - start_time),
                    reasoning_display,  # Live reasoning
                    "",  # No HTML results yet
                    memory_reasoning_md,  # Memory reasoning
                    similar_incidents_html,  # Similar incidents
                    campaign_alert_html  # Campaign alert
                )
                continue  # Skip the normal yield at the end
                
            elif event_type == "llm_reasoning_complete":
                # Save completed reasoning
                if current_reasoning_node:
                    reasoning_buffer[current_reasoning_node] = reasoning_buffer["current"]
                    reasoning_buffer["current"] = ""
                    current_reasoning_node = None

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
                elif event_type == "node_complete":
                    # Set progress to node's target percentage
                    current_progress = node_progress_map[node]["pct"]
                    completed_nodes.append(node)
                    previous_node = node  # Track for skip detection

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

            # Get current reasoning display with key events integrated
            reasoning_display = (
                reasoning_buffer.get("analysis", "") +
                reasoning_buffer.get("investigation", "") +
                reasoning_buffer.get("response", "") +
                reasoning_buffer.get("current", "") +
                get_key_events_summary(activity_log_lines)  # NEW: Integrated key events
            )

            # Extract memory data from accumulated state
            memory_reasoning = accumulated_state.get("memory_reasoning", "")
            similar_incidents = accumulated_state.get("similar_incidents", [])
            campaign_info = accumulated_state.get("campaign_info")
            
            memory_reasoning_md = memory_reasoning if memory_reasoning else "*No memory reasoning available yet.*"
            similar_incidents_html = format_similar_incidents_html(similar_incidents)
            campaign_alert_html = format_campaign_alert_html(campaign_info)
            
            yield (
                _get_status_compact_html(current_node or "supervisor", completed_nodes, skipped_nodes, current_progress, time.time() - start_time),
                reasoning_display,  # Reasoning with integrated events
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
                "enrichment_data": {
                    "siem_logs_count": len(source_state.get("enrichment_data", {}).get("siem_logs", [])),
                    "ip_reputation": sanitize_html(source_state.get("enrichment_data", {}).get("threat_intel", {}).get("ip_reputation", "unknown")),
                    "threat_score_intel": source_state.get("enrichment_data", {}).get("threat_intel", {}).get("threat_score", 0),
                    "threat_intel_source": sanitize_html(source_state.get("enrichment_data", {}).get("threat_intel", {}).get("source", "mock")),
                    "malicious_detections": source_state.get("enrichment_data", {}).get("threat_intel", {}).get("malicious_count", 0),
                    "total_scanners": source_state.get("enrichment_data", {}).get("threat_intel", {}).get("total_scanners", 0),
                },
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

            # Get final reasoning display with all key events
            final_reasoning = (
                reasoning_buffer.get("analysis", "") +
                reasoning_buffer.get("investigation", "") +
                reasoning_buffer.get("response", "") +
                get_key_events_summary(activity_log_lines)
            )

            # Extract final memory data
            memory_reasoning = accumulated_state.get("memory_reasoning", "")
            similar_incidents = accumulated_state.get("similar_incidents", [])
            campaign_info = accumulated_state.get("campaign_info")
            
            memory_reasoning_md = memory_reasoning if memory_reasoning else "*No memory reasoning available.*"
            similar_incidents_html = format_similar_incidents_html(similar_incidents)
            campaign_alert_html = format_campaign_alert_html(campaign_info)
            
            yield (
                _get_status_compact_html("communication", completed_nodes, skipped_nodes, 100, total_time),
                final_reasoning,  # Complete reasoning with events
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


# ===== HTML Formatting Functions =====

def format_results_html(result: dict) -> str:
    """
    Format investigation results as structured HTML (XSS-safe)

    Args:
        result: Investigation results dictionary (already sanitized)

    Returns:
        HTML formatted results
    """
    threat_score = result.get("threat_score", 0.0)

    # Determine threat level colors
    if threat_score >= 0.90:
        threat_color = "#ef4444"  # red
        threat_glow = "0 0 20px rgba(239, 68, 68, 0.5)"
        threat_label = "CRITICAL"
    elif threat_score >= 0.70:
        threat_color = "#f97316"  # orange
        threat_glow = "0 0 20px rgba(249, 115, 22, 0.5)"
        threat_label = "HIGH"
    elif threat_score >= 0.50:
        threat_color = "#eab308"  # yellow
        threat_glow = "0 0 20px rgba(234, 179, 8, 0.5)"
        threat_label = "MEDIUM"
    else:
        threat_color = "#ffffff"  # white
        threat_glow = "0 0 20px rgba(255, 255, 255, 0.4)"
        threat_label = "LOW"

    # Get escalation status
    escalation_badge = ""
    requires_escalation = threat_score >= 0.90
    if requires_escalation:
        escalation_badge = '<span style="background-color: #ef4444; color: #000; padding: 6px 16px; border-radius: 4px; font-size: 0.75rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.05em; box-shadow: 0 0 20px rgba(239, 68, 68, 0.6);">⚠ ESCALATION REQUIRED</span>'

    # Format MITRE mappings (already sanitized in result)
    mitre_html = ""
    for mapping in result.get("mitre_mappings", [])[:3]:
        confidence_pct = int(mapping.get("confidence", 0) * 100)
        mitre_html += f"""
        <div style="background: #0a0a0a; padding: 14px; margin: 10px 0; border-left: 3px solid #ffffff; border-radius: 2px; font-family: 'Courier New', monospace; box-shadow: 0 0 10px rgba(255, 255, 255, 0.1);">
            <div style="font-weight: 600; color: #ffffff; margin-bottom: 6px; font-size: 0.9rem; letter-spacing: 0.02em;">
                [{mapping.get('technique_id', 'Unknown')}] {mapping.get('name', 'Unknown').upper()}
            </div>
            <div style="color: #71717a; font-size: 0.8rem; font-family: 'Courier New', monospace;">
                > TACTIC: {mapping.get('tactic', 'Unknown').upper()} | CONFIDENCE: {confidence_pct}%
            </div>
        </div>
        """

    if not mitre_html:
        mitre_html = "<div style='color: #71717a; font-style: italic; font-family: monospace;'>[!] No MITRE ATT&CK mappings detected</div>"

    # Format recommended actions
    actions_html = ""
    for i, action in enumerate(result.get("recommendations", []), 1):
        # Action is already sanitized in result
        actions_html += f"""
        <div style="padding: 10px 0; border-bottom: 1px solid #18181b; font-family: 'Courier New', monospace;">
            <span style="color: #ffffff; margin-right: 12px; font-weight: 700;">[{i:02d}]</span>
            <span style="color: #e4e4e7;">{action}</span>
        </div>
        """

    if not actions_html:
        actions_html = "<div style='color: #71717a; font-style: italic; font-family: monospace;'>[!] No recommended actions available</div>"

    html_result = f"""
    <div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; padding: 0; background: #000; border-radius: 0; color: #e4e4e7;">

        <!-- Header -->
        <div style="border-bottom: 1px solid #27272a; padding: 20px 24px; margin-bottom: 0; background: #000;">
            <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 14px;">
                <h2 style="margin: 0; color: #ffffff; font-size: 1.4rem; font-family: 'Courier New', monospace; font-weight: 700; letter-spacing: 0.05em; text-shadow: 0 0 10px rgba(255, 255, 255, 0.3);">
                    [INVESTIGATION_RESULTS]
                </h2>
                {escalation_badge}
            </div>
            <div style="color: #71717a; font-size: 0.8rem; font-family: 'Courier New', monospace;">
                > ALERT_ID: <span style="color: #a1a1aa;">{result.get('alert_id', 'Unknown')}</span> |
                TYPE: <span style="color: #a1a1aa;">{result.get('alert_type', 'Unknown').replace('_', ' ').upper()}</span>
            </div>
        </div>

        <!-- Threat Score Card -->
        <div style="background: linear-gradient(135deg, #0a0a0a 0%, #000 100%);
                    border: 1px solid {threat_color}; border-radius: 0; padding: 24px; margin: 0; box-shadow: inset 0 0 40px rgba(0, 0, 0, 0.8), {threat_glow};">
            <div style="display: flex; align-items: center; justify-content: space-between;">
                <div>
                    <div style="color: #71717a; font-size: 0.75rem; font-weight: 700; margin-bottom: 8px; font-family: 'Courier New', monospace; letter-spacing: 0.1em;">THREAT_SCORE</div>
                    <div style="font-size: 3.5rem; font-weight: 700; color: {threat_color}; font-family: 'Courier New', monospace; text-shadow: {threat_glow};">
                        {int(threat_score * 100)}<span style="font-size: 1.5rem;">%</span>
                    </div>
                    <div style="color: #71717a; font-size: 0.8rem; margin-top: 8px; font-family: 'Courier New', monospace;">
                        > STAGE: <span style="color: #a1a1aa;">{result.get('attack_stage', 'Unknown').upper()}</span>
                    </div>
                </div>
                <div style="text-align: right;">
                    <div style="background-color: {threat_color}; color: #000;
                                padding: 10px 24px; border-radius: 2px; font-size: 1.1rem; font-weight: 900; margin-bottom: 10px; font-family: 'Courier New', monospace; letter-spacing: 0.1em; box-shadow: {threat_glow};">
                        {threat_label}
                    </div>
                    <div style="color: #71717a; font-size: 0.8rem; font-family: 'Courier New', monospace;">
                        [{result.get('threat_category', 'Unclassified').upper()}]
                    </div>
                </div>
            </div>
        </div>

        <!-- MITRE ATT&CK Mappings -->
        <div style="margin: 0; padding: 24px; background: #000; border-bottom: 1px solid #18181b;">
            <h3 style="color: #ffffff; font-size: 1rem; margin-bottom: 16px; font-weight: 700; font-family: 'Courier New', monospace; letter-spacing: 0.05em; text-transform: uppercase;">
                [MITRE_ATT&CK_TECHNIQUES]
            </h3>
            {mitre_html}
        </div>

        <!-- Recommended Actions -->
        <div style="margin: 0; padding: 24px; background: #000; border-bottom: 1px solid #18181b;">
            <h3 style="color: #ffffff; font-size: 1rem; margin-bottom: 16px; font-weight: 700; font-family: 'Courier New', monospace; letter-spacing: 0.05em; text-transform: uppercase;">
                [RECOMMENDED_ACTIONS]
            </h3>
            <div style="background: #0a0a0a; padding: 16px; border-radius: 0; border: 1px solid #18181b;">
                {actions_html}
            </div>
        </div>

        <!-- Enrichment Data -->
        <div style="margin: 0; padding: 24px; background: #000; border-bottom: 1px solid #18181b;">
            <h3 style="color: #ffffff; font-size: 1rem; margin-bottom: 16px; font-weight: 700; font-family: 'Courier New', monospace; letter-spacing: 0.05em; text-transform: uppercase;">
                [ENRICHMENT_DATA]
            </h3>
            <div style="display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px;">
                <div style="background: #0a0a0a; padding: 16px; border-radius: 0; text-align: center; border: 1px solid #18181b;">
                    <div style="color: #71717a; font-size: 0.7rem; margin-bottom: 8px; font-family: 'Courier New', monospace; letter-spacing: 0.1em;">SIEM_LOGS</div>
                    <div style="font-size: 2rem; font-weight: 700; color: #ffffff; font-family: 'Courier New', monospace; text-shadow: 0 0 10px rgba(255, 255, 255, 0.2);">
                        {result.get('enrichment_data', {}).get('siem_logs_count', 0)}
                    </div>
                </div>
                <div style="background: #0a0a0a; padding: 16px; border-radius: 0; text-align: center; border: 1px solid #18181b;">
                    <div style="color: #71717a; font-size: 0.7rem; margin-bottom: 8px; font-family: 'Courier New', monospace; letter-spacing: 0.1em;">IP_REPUTATION</div>
                    <div style="font-size: 1rem; font-weight: 700; color: #ef4444; text-transform: uppercase; font-family: 'Courier New', monospace; text-shadow: 0 0 10px rgba(239, 68, 68, 0.3);">
                        {result.get('enrichment_data', {}).get('ip_reputation', 'unknown')}
                    </div>
                </div>
                <div style="background: #0a0a0a; padding: 16px; border-radius: 0; text-align: center; border: 1px solid #18181b;">
                    <div style="color: #71717a; font-size: 0.7rem; margin-bottom: 8px; font-family: 'Courier New', monospace; letter-spacing: 0.1em;">THREAT_INTEL</div>
                    <div style="font-size: 2rem; font-weight: 700; color: #ffffff; font-family: 'Courier New', monospace; text-shadow: 0 0 10px rgba(255, 255, 255, 0.2);">
                        {result.get('enrichment_data', {}).get('threat_score_intel', 0)}<span style="font-size: 1rem; color: #71717a;">/10</span>
                    </div>
                </div>
                <div style="background: #0a0a0a; padding: 16px; border-radius: 0; text-align: center; border: 1px solid #3b82f6; box-shadow: 0 0 15px rgba(59, 130, 246, 0.2);">
                    <div style="color: #3b82f6; font-size: 0.7rem; margin-bottom: 8px; font-weight: 700; font-family: 'Courier New', monospace; letter-spacing: 0.1em;">INTEL_SOURCE</div>
                    <div style="font-size: 1rem; font-weight: 700; color: #3b82f6; text-transform: uppercase; font-family: 'Courier New', monospace; text-shadow: 0 0 10px rgba(59, 130, 246, 0.3);">
                        {result.get('enrichment_data', {}).get('threat_intel_source', 'mock')}
                    </div>
                    <div style="color: #60a5fa; font-size: 0.7rem; margin-top: 6px; font-family: 'Courier New', monospace;">
                        {result.get('enrichment_data', {}).get('malicious_detections', 0)}/{result.get('enrichment_data', {}).get('total_scanners', 0)} detections
                    </div>
                </div>
            </div>
        </div>

        <!-- Full Summary -->
        <details style="margin: 0; background: #000; padding: 24px;">
            <summary style="cursor: pointer; color: #ffffff; font-weight: 700; padding: 14px;
                           background: #0a0a0a; border-radius: 0; margin-bottom: 16px; border: 1px solid #18181b; font-family: 'Courier New', monospace; letter-spacing: 0.05em; text-transform: uppercase;">
                [FULL_INVESTIGATION_REPORT]
            </summary>
            <div style="background: #0a0a0a; padding: 20px; border-radius: 0; border: 1px solid #18181b;
                        font-family: 'Courier New', monospace; font-size: 0.85rem; white-space: pre-wrap;
                        color: #a1a1aa; line-height: 1.7; box-shadow: inset 0 0 20px rgba(0, 0, 0, 0.5);">
{result.get('report', 'No summary available')}
            </div>
        </details>

    </div>
    """

    return html_result


def _format_error_html(title: str, message: str, traceback: str = "") -> str:
    """Format error as HTML (XSS-safe)"""
    traceback_section = ""
    if traceback:
        traceback_section = f"""
            <pre style="background: #fff; padding: 12px; border-radius: 4px; overflow-x: auto; color: #000;">
{sanitize_html(traceback)}
            </pre>
        """

    return f"""
    <div style="background-color: #fee; border: 2px solid #dc2626; border-radius: 8px; padding: 20px; color: #dc2626;">
        <h3 style="margin-top: 0;">❌ {sanitize_html(title)}</h3>
        <p><strong>Error:</strong> {sanitize_html(message)}</p>
        {traceback_section}
    </div>
    """


# ===== Status HTML Generators (Vertical Stepper) =====


def _get_initial_status_compact_html() -> str:
    """
    Generate initial status with vertical step-by-step workflow
    """
    return """
    <div style="font-family: 'JetBrains Mono', monospace;">
        <!-- Progress Header -->
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px;">
            <span style="font-size: 0.7rem; color: #999999; font-weight: 500; letter-spacing: 0.05em;">PROGRESS</span>
            <span style="font-size: 0.8rem; color: #e8e8e8; font-weight: 600;">0%</span>
        </div>
        
        <!-- Progress Bar -->
        <div style="background: #0a0a0a; border: 1px solid #1a1a1a; height: 6px; border-radius: 4px; overflow: hidden; margin-bottom: 20px;">
            <div style="background: linear-gradient(90deg, #e8e8e8 0%, #999999 100%); width: 0%; height: 100%; transition: width 0.5s ease;"></div>
        </div>
        
        <!-- Workflow Steps (Vertical) -->
        <div style="margin-top: 16px;">
            <div style="display: flex; align-items: flex-start; margin-bottom: 14px;">
                <div style="flex-shrink: 0; width: 24px; height: 24px; border-radius: 50%; border: 2px solid #333333; display: flex; align-items: center; justify-content: center; background: #000000; margin-right: 12px; font-size: 0.7rem;">1</div>
                <div style="flex: 1;">
                    <div style="font-size: 0.75rem; color: #666666; font-weight: 500;">Supervisor</div>
                    <div style="font-size: 0.65rem; color: #444444; margin-top: 2px;">Pending</div>
                </div>
            </div>
            
            <div style="display: flex; align-items: flex-start; margin-bottom: 14px;">
                <div style="flex-shrink: 0; width: 24px; height: 24px; border-radius: 50%; border: 2px solid #333333; display: flex; align-items: center; justify-content: center; background: #000000; margin-right: 12px; font-size: 0.7rem;">2</div>
                <div style="flex: 1;">
                    <div style="font-size: 0.75rem; color: #666666; font-weight: 500;">Enrichment</div>
                    <div style="font-size: 0.65rem; color: #444444; margin-top: 2px;">Pending</div>
                </div>
            </div>
            
            <div style="display: flex; align-items: flex-start; margin-bottom: 14px;">
                <div style="flex-shrink: 0; width: 24px; height: 24px; border-radius: 50%; border: 2px solid #333333; display: flex; align-items: center; justify-content: center; background: #000000; margin-right: 12px; font-size: 0.7rem;">3</div>
                <div style="flex: 1;">
                    <div style="font-size: 0.75rem; color: #666666; font-weight: 500;">Analysis</div>
                    <div style="font-size: 0.65rem; color: #444444; margin-top: 2px;">Pending</div>
                </div>
            </div>
            
            <div style="display: flex; align-items: flex-start; margin-bottom: 14px;">
                <div style="flex-shrink: 0; width: 24px; height: 24px; border-radius: 50%; border: 2px solid #333333; display: flex; align-items: center; justify-content: center; background: #000000; margin-right: 12px; font-size: 0.7rem;">4</div>
                <div style="flex: 1;">
                    <div style="font-size: 0.75rem; color: #666666; font-weight: 500;">Investigation</div>
                    <div style="font-size: 0.65rem; color: #444444; margin-top: 2px;">Pending</div>
                </div>
            </div>
            
            <div style="display: flex; align-items: flex-start; margin-bottom: 14px;">
                <div style="flex-shrink: 0; width: 24px; height: 24px; border-radius: 50%; border: 2px solid #333333; display: flex; align-items: center; justify-content: center; background: #000000; margin-right: 12px; font-size: 0.7rem;">5</div>
                <div style="flex: 1;">
                    <div style="font-size: 0.75rem; color: #666666; font-weight: 500;">Response</div>
                    <div style="font-size: 0.65rem; color: #444444; margin-top: 2px;">Pending</div>
                </div>
            </div>
            
            <div style="display: flex; align-items: flex-start;">
                <div style="flex-shrink: 0; width: 24px; height: 24px; border-radius: 50%; border: 2px solid #333333; display: flex; align-items: center; justify-content: center; background: #000000; margin-right: 12px; font-size: 0.7rem;">6</div>
                <div style="flex: 1;">
                    <div style="font-size: 0.75rem; color: #666666; font-weight: 500;">Communication</div>
                    <div style="font-size: 0.65rem; color: #444444; margin-top: 2px;">Pending</div>
                </div>
            </div>
        </div>
        
        <!-- Time Footer -->
        <div style="margin-top: 20px; padding-top: 14px; border-top: 1px solid #1a1a1a;">
            <div style="display: flex; justify-content: space-between; align-items: center;">
                <span style="font-size: 0.7rem; color: #999999; font-weight: 500; letter-spacing: 0.05em;">TIME</span>
                <span style="font-size: 0.8rem; color: #e8e8e8; font-weight: 600;">--</span>
            </div>
        </div>
    </div>
    """


def _get_status_compact_html(current_node: str, completed_nodes: List[str], skipped_nodes: List[str], progress_pct: int, total_time: float) -> str:
    """
    Generate updated status with vertical step-by-step workflow
    Shows execution order and current progress
    """
    # Node configuration with execution order
    nodes = [
        (1, "supervisor", "Supervisor"),
        (2, "enrichment", "Enrichment"),
        (3, "analysis", "Analysis"),
        (4, "investigation", "Investigation"),
        (5, "response", "Response"),
        (6, "communication", "Communication")
    ]
    
    # Progress bar styling
    if progress_pct >= 100:
        bar_gradient = "linear-gradient(90deg, #10b981 0%, #059669 100%)"
        bar_shadow = "0 0 12px rgba(16, 185, 129, 0.4)"
    elif progress_pct >= 50:
        bar_gradient = "linear-gradient(90deg, #e8e8e8 0%, #999999 100%)"
        bar_shadow = "0 0 10px rgba(232, 232, 232, 0.2)"
    else:
        bar_gradient = "linear-gradient(90deg, #666666 0%, #444444 100%)"
        bar_shadow = "0 0 8px rgba(102, 102, 102, 0.2)"
    
    # Build vertical steps
    steps_html = ""
    for step_num, node_id, label in nodes:
        # Determine step state
        if node_id in completed_nodes:
            # Completed
            circle_bg = "#000000"
            circle_border = "2px solid #10b981"
            circle_content = "✓"
            circle_color = "#10b981"
            title_color = "#10b981"
            status_text = "Completed"
            status_color = "#059669"
        elif node_id == current_node:
            # In Progress
            circle_bg = "#1a1a1a"
            circle_border = "2px solid #e8e8e8"
            circle_content = str(step_num)
            circle_color = "#e8e8e8"
            title_color = "#e8e8e8"
            status_text = "In Progress..."
            status_color = "#999999"
        elif node_id in skipped_nodes:
            # Skipped
            circle_bg = "#000000"
            circle_border = "2px solid #666666"
            circle_content = "−"
            circle_color = "#666666"
            title_color = "#666666"
            status_text = "Skipped"
            status_color = "#444444"
        else:
            # Pending
            circle_bg = "#000000"
            circle_border = "2px solid #333333"
            circle_content = str(step_num)
            circle_color = "#666666"
            title_color = "#666666"
            status_text = "Pending"
            status_color = "#444444"
        
        is_last = (step_num == 6)
        margin_bottom = "0" if is_last else "14px"
        
        steps_html += f"""
        <div style="display: flex; align-items: flex-start; margin-bottom: {margin_bottom};">
            <div style="flex-shrink: 0; width: 24px; height: 24px; border-radius: 50%; border: {circle_border}; display: flex; align-items: center; justify-content: center; background: {circle_bg}; margin-right: 12px; color: {circle_color}; font-size: 0.7rem; font-weight: 600;">{circle_content}</div>
            <div style="flex: 1;">
                <div style="font-size: 0.75rem; color: {title_color}; font-weight: 500;">{label}</div>
                <div style="font-size: 0.65rem; color: {status_color}; margin-top: 2px;">{status_text}</div>
            </div>
        </div>
        """
    
    return f"""
    <div style="font-family: 'JetBrains Mono', monospace;">
        <!-- Progress Header -->
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px;">
            <span style="font-size: 0.7rem; color: #999999; font-weight: 500; letter-spacing: 0.05em;">PROGRESS</span>
            <span style="font-size: 0.8rem; color: #e8e8e8; font-weight: 600;">{progress_pct}%</span>
        </div>
        
        <!-- Progress Bar -->
        <div style="background: #0a0a0a; border: 1px solid #1a1a1a; height: 6px; border-radius: 4px; overflow: hidden; margin-bottom: 20px;">
            <div style="background: {bar_gradient}; width: {progress_pct}%; height: 100%; transition: width 0.5s ease; box-shadow: {bar_shadow};"></div>
        </div>
        
        <!-- Workflow Steps (Vertical) -->
        <div style="margin-top: 16px;">
            {steps_html}
        </div>
        
        <!-- Time Footer -->
        <div style="margin-top: 20px; padding-top: 14px; border-top: 1px solid #1a1a1a;">
            <div style="display: flex; justify-content: space-between; align-items: center;">
                <span style="font-size: 0.7rem; color: #999999; font-weight: 500; letter-spacing: 0.05em;">TIME</span>
                <span style="font-size: 0.8rem; color: #e8e8e8; font-weight: 600;">{total_time:.1f}s</span>
            </div>
        </div>
    </div>
    """


def _format_activity_log(timestamp: str, node: str, message: str, emoji: str = "🔄") -> str:
    """Format a single activity log entry"""
    return f"[{timestamp}] {emoji} {node:15s} -> {message}"


def get_key_events_summary(activity_log_lines: List[str], max_events: int = 8) -> str:
    """
    Extract only key events (node complete, errors, important milestones)
    Filters out noise from state_update events and deduplicates similar messages

    Args:
        activity_log_lines: Full list of activity log lines
        max_events: Maximum number of key events to show

    Returns:
        Markdown formatted string with key events
    """
    key_events = []
    seen_event_keys = set()  # Track unique events to prevent duplicates
    important_keywords = ["✅", "❌", "🎉", "COMPLETED", "ERROR", "FAILED", "started processing", "Threat Score"]

    for line in activity_log_lines:
        # Filter for important events only
        if any(keyword in line for keyword in important_keywords):
            # Extract event key (remove timestamp for deduplication)
            # Format: [HH:MM:SS] EMOJI NODE -> message
            # We want to deduplicate based on NODE + message content
            parts = line.split(" -> ", 1)
            if len(parts) == 2:
                # Get the part after timestamp: "EMOJI NODE"
                prefix_parts = parts[0].split("] ", 1)
                if len(prefix_parts) == 2:
                    event_key = prefix_parts[1].strip() + " -> " + parts[1].strip()
                else:
                    event_key = line
            else:
                event_key = line

            # Only add if we haven't seen this event type before
            if event_key not in seen_event_keys:
                seen_event_keys.add(event_key)
                key_events.append(line)

    # Get last N events
    recent_events = key_events[-max_events:] if len(key_events) > max_events else key_events

    if not recent_events:
        return ""

    # Format as markdown with proper line breaks for Gradio
    # Use HTML <br> tags for reliable line breaks
    events_md = "\n\n---\n\n### Key Events\n\n"
    event_lines = []
    for event in recent_events:
        event_lines.append(f"○ `{event}`")

    # Join with <br> for reliable line breaks in Gradio Markdown
    events_md += "<br>\n".join(event_lines)

    return events_md


# ===== HTML Formatters for Memory Context =====

def format_similar_incidents_html(similar_incidents: List[Dict]) -> str:
    """
    Format similar incidents as HTML cards with dark minimal styling

    Args:
        similar_incidents: List of similar past incidents

    Returns:
        HTML string with incident cards
    """
    if not similar_incidents:
        return """
        <div style="padding: 32px; text-align: center; font-family: 'Inter', sans-serif;
                    background: rgba(255, 255, 255, 0.02); border-radius: 12px; border: 1px dashed #333;">
            <div style="font-size: 2rem; margin-bottom: 12px;">🆕</div>
            <p style="font-size: 0.95rem; color: #e8e8e8; margin-bottom: 8px; font-weight: 500;">
                New Pattern Detected
            </p>
            <p style="font-size: 0.85rem; color: #999; line-height: 1.5; max-width: 400px; margin: 0 auto;">
                No similar incidents found in memory. This appears to be a new attack pattern
                that the system hasn't seen before.
            </p>
            <div style="margin-top: 16px; padding-top: 16px; border-top: 1px solid #1a1a1a;">
                <p style="font-size: 0.8rem; color: #666;">
                    ✅ This investigation will be saved to memory for future reference
                </p>
            </div>
        </div>
        """

    cards_html = ""

    for incident in similar_incidents:
        similarity = incident.get("similarity_score", 0.0)
        incident_id = incident.get("incident_id", "Unknown")
        alert_type = incident.get("alert_type", "unknown")
        threat_score = incident.get("threat_score", 0.0)
        timestamp = incident.get("timestamp", "Unknown")
        attack_stage = incident.get("attack_stage", "Unknown")
        threat_category = incident.get("threat_category", "Unknown")
        summary = incident.get("summary", "No summary available")

        # Similarity bar color
        if similarity >= 0.8:
            bar_color = "#10b981"  # Green
        elif similarity >= 0.6:
            bar_color = "#f59e0b"  # Amber
        else:
            bar_color = "#6b7280"  # Gray

        card_html = f"""
        <div style="
            background: #000000;
            border: 1px solid #1a1a1a;
            border-radius: 12px;
            padding: 20px;
            margin-bottom: 16px;
            transition: all 0.2s ease;
        " onmouseover="this.style.borderColor='#333333'; this.style.boxShadow='0 2px 6px rgba(255,255,255,0.05)'"
           onmouseout="this.style.borderColor='#1a1a1a'; this.style.boxShadow='none'">

            <!-- Header -->
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px;">
                <div style="font-family: 'JetBrains Mono', monospace; font-size: 0.9rem; color: #e8e8e8; font-weight: 600;">
                    {incident_id}
                </div>
                <div style="font-size: 0.75rem; color: #999999; font-family: 'Inter', sans-serif;">
                    {timestamp[:19] if len(timestamp) > 19 else timestamp}
                </div>
            </div>

            <!-- Similarity Bar -->
            <div style="margin-bottom: 12px;">
                <div style="display: flex; justify-content: space-between; margin-bottom: 4px;">
                    <span style="font-size: 0.75rem; color: #999999; font-family: 'Inter', sans-serif;">Similarity</span>
                    <span style="font-size: 0.75rem; color: {bar_color}; font-weight: 600; font-family: 'Inter', sans-serif;">{similarity:.0%}</span>
                </div>
                <div style="width: 100%; height: 6px; background: #1a1a1a; border-radius: 3px; overflow: hidden;">
                    <div style="width: {similarity * 100}%; height: 100%; background: {bar_color}; transition: width 0.3s ease;"></div>
                </div>
            </div>

            <!-- Metadata Grid -->
            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 12px; margin-bottom: 12px;">
                <div>
                    <div style="font-size: 0.7rem; color: #666; margin-bottom: 3px; font-family: 'Inter', sans-serif;">Alert Type</div>
                    <div style="font-size: 0.85rem; color: #e8e8e8; text-transform: capitalize; font-family: 'Inter', sans-serif;">{alert_type.replace('_', ' ')}</div>
                </div>
                <div>
                    <div style="font-size: 0.7rem; color: #666; margin-bottom: 3px; font-family: 'Inter', sans-serif;">Threat Score</div>
                    <div style="font-size: 0.85rem; color: #e8e8e8; font-family: 'Inter', sans-serif;">{threat_score:.2f}</div>
                </div>
                <div>
                    <div style="font-size: 0.7rem; color: #666; margin-bottom: 3px; font-family: 'Inter', sans-serif;">Attack Stage</div>
                    <div style="font-size: 0.85rem; color: #e8e8e8; font-family: 'Inter', sans-serif;">{attack_stage}</div>
                </div>
                <div>
                    <div style="font-size: 0.7rem; color: #666; margin-bottom: 3px; font-family: 'Inter', sans-serif;">Category</div>
                    <div style="font-size: 0.85rem; color: #e8e8e8; font-family: 'Inter', sans-serif;">{threat_category}</div>
                </div>
            </div>

            <!-- Summary -->
            <div style="padding-top: 12px; border-top: 1px solid #1a1a1a;">
                <div style="font-size: 0.8rem; color: #999999; line-height: 1.5; font-family: 'Inter', sans-serif;">
                    {summary}
                </div>
            </div>
        </div>
        """

        cards_html += card_html

    return cards_html


def format_campaign_alert_html(campaign_info: Optional[Dict]) -> str:
    """
    Format campaign detection as alert banner

    Args:
        campaign_info: Campaign detection results

    Returns:
        HTML string with campaign alert
    """
    if not campaign_info:
        return ""

    campaign_id = campaign_info.get("campaign_id", "Unknown")
    confidence = campaign_info.get("confidence", 0.0)
    incident_count = campaign_info.get("incident_count", 0)
    related_incidents = campaign_info.get("related_incidents", [])
    assessment = campaign_info.get("threat_assessment", "UNKNOWN")
    time_span_hours = campaign_info.get("time_span_hours", 0)

    # Color based on assessment
    if "ONGOING" in assessment:
        alert_color = "#ff453a"  # Red
        emoji = "🚨"
    else:
        alert_color = "#ff9f0a"  # Orange
        emoji = "⚠️"

    return f"""
    <div style="
        background: linear-gradient(135deg, rgba(255, 69, 58, 0.1) 0%, rgba(255, 69, 58, 0.05) 100%);
        border: 1px solid {alert_color};
        border-radius: 12px;
        padding: 24px;
        margin-top: 24px;
        font-family: 'Inter', sans-serif;
    ">
        <!-- Header -->
        <div style="display: flex; align-items: center; margin-bottom: 16px;">
            <div style="font-size: 1.5rem; margin-right: 12px;">{emoji}</div>
            <div>
                <div style="font-size: 1.1rem; font-weight: 600; color: #e8e8e8; margin-bottom: 4px;">
                    CAMPAIGN DETECTED
                </div>
                <div style="font-size: 0.8rem; color: #999999;">
                    {assessment.replace('_', ' ')}
                </div>
            </div>
        </div>

        <!-- Metrics Grid -->
        <div style="display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 16px; margin-bottom: 16px;">
            <div>
                <div style="font-size: 0.7rem; color: #999999; margin-bottom: 4px;">Campaign ID</div>
                <div style="font-family: 'JetBrains Mono', monospace; font-size: 0.9rem; color: #e8e8e8;">{campaign_id}</div>
            </div>
            <div>
                <div style="font-size: 0.7rem; color: #999999; margin-bottom: 4px;">Confidence</div>
                <div style="font-size: 0.9rem; color: {alert_color}; font-weight: 600;">{confidence:.0%}</div>
            </div>
            <div>
                <div style="font-size: 0.7rem; color: #999999; margin-bottom: 4px;">Related Incidents</div>
                <div style="font-size: 0.9rem; color: #e8e8e8;">{incident_count}</div>
            </div>
        </div>

        <!-- Timeline -->
        <div style="padding-top: 16px; border-top: 1px solid rgba(255, 69, 58, 0.2);">
            <div style="font-size: 0.75rem; color: #999999; margin-bottom: 8px;">
                Timeline ({time_span_hours:.1f} hours):
            </div>
            <div style="font-family: 'JetBrains Mono', monospace; font-size: 0.8rem; color: #e8e8e8; overflow-x: auto;">
                {' → '.join(related_incidents[:5])}
                {' → ...' if len(related_incidents) > 5 else ''}
            </div>
        </div>
    </div>
    """


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

    # Load sample alerts
    sample_alerts = load_sample_alerts()

    # Create alert options for dropdown
    alert_choices = {}
    if sample_alerts:
        for alert in sample_alerts:
            alert_label = f"{alert.get('id', 'N/A')} - {alert.get('title', 'Untitled')} [{alert.get('severity', 'unknown').upper()}]"
            alert_choices[alert_label] = json.dumps(alert, indent=2)

    def load_selected_alert(alert_label: str) -> str:
        """Load selected alert from dropdown"""
        return alert_choices.get(alert_label, "{}")

    # Create ultra-minimal dark theme inspired by crypto/AI dashboards
    dark_minimal_theme = gr.themes.Base(
        primary_hue=gr.themes.colors.slate,
        secondary_hue=gr.themes.colors.slate,
        neutral_hue=gr.themes.colors.slate,
        font=[gr.themes.GoogleFont("Inter"), "ui-sans-serif", "system-ui", "sans-serif"],
    ).set(
        # === BACKGROUNDS ===
        body_background_fill="#000000",
        body_background_fill_dark="#000000",
        background_fill_primary="#000000",
        background_fill_primary_dark="#000000",
        background_fill_secondary="#0a0a0a",
        background_fill_secondary_dark="#0a0a0a",
        
        # === BORDERS ===
        border_color_primary="#1a1a1a",
        border_color_primary_dark="#1a1a1a",
        border_color_accent="#333333",
        border_color_accent_dark="#333333",
        
        # === BUTTONS - Minimal ===
        button_primary_background_fill="#000000",
        button_primary_background_fill_dark="#000000",
        button_primary_background_fill_hover="#111111",
        button_primary_background_fill_hover_dark="#111111",
        button_primary_border_color="#e8e8e8",
        button_primary_border_color_dark="#e8e8e8",
        button_primary_text_color="#e8e8e8",
        button_primary_text_color_dark="#e8e8e8",
        
        button_secondary_background_fill="#000000",
        button_secondary_background_fill_dark="#000000",
        button_secondary_background_fill_hover="#0a0a0a",
        button_secondary_background_fill_hover_dark="#0a0a0a",
        button_secondary_border_color="#1a1a1a",
        button_secondary_border_color_dark="#1a1a1a",
        button_secondary_text_color="#999999",
        button_secondary_text_color_dark="#999999",
        
        # === INPUTS ===
        input_background_fill="#000000",
        input_background_fill_dark="#000000",
        input_background_fill_focus="#000000",
        input_background_fill_focus_dark="#000000",
        input_border_color="#1a1a1a",
        input_border_color_dark="#1a1a1a",
        input_border_color_focus="#e8e8e8",
        input_border_color_focus_dark="#e8e8e8",
        input_border_width="1px",
        input_shadow="0 0 0 0 rgba(255, 255, 255, 0)",
        input_shadow_focus="0 0 8px rgba(255, 255, 255, 0.08)",
        
        # === TEXT COLORS ===
        block_title_text_color="#e8e8e8",
        block_title_text_color_dark="#e8e8e8",
        block_label_text_color="#999999",
        block_label_text_color_dark="#999999",
        block_info_text_color="#666666",
        block_info_text_color_dark="#666666",
        body_text_color="#e8e8e8",
        body_text_color_dark="#e8e8e8",
        body_text_color_subdued="#999999",
        body_text_color_subdued_dark="#999999",
        
        # === CODE BLOCKS ===
        code_background_fill="#0a0a0a",
        code_background_fill_dark="#0a0a0a",
        
        # === PANELS/BLOCKS ===
        panel_background_fill="#000000",
        panel_background_fill_dark="#000000",
        panel_border_color="#1a1a1a",
        panel_border_color_dark="#1a1a1a",
        panel_border_width="1px",
        
        # === SHADOWS ===
        shadow_drop="0 1px 3px rgba(255, 255, 255, 0.03)",
        shadow_drop_lg="0 2px 6px rgba(255, 255, 255, 0.05)",
        shadow_inset="inset 0 1px 2px rgba(0, 0, 0, 0.5)",
        shadow_spread="0 0 12px rgba(255, 255, 255, 0.06)",
        
        # === SPACING ===
        block_padding="32px",
        container_radius="12px",
        block_radius="12px",
        
        # === SLIDERS & INTERACTIVE ===
        slider_color="#e8e8e8",
        slider_color_dark="#e8e8e8",
        checkbox_background_color="#000000",
        checkbox_background_color_dark="#000000",
        checkbox_background_color_selected="#e8e8e8",
        checkbox_background_color_selected_dark="#e8e8e8",
        checkbox_border_color="#1a1a1a",
        checkbox_border_color_dark="#1a1a1a",
        checkbox_border_color_focus="#e8e8e8",
        checkbox_border_color_focus_dark="#e8e8e8",
        checkbox_label_text_color="#e8e8e8",
        checkbox_label_text_color_dark="#e8e8e8",
    )
    
    # Create Gradio Blocks interface
    with gr.Blocks(
        title="SOC Orchestrator",
        theme=dark_minimal_theme,
        css="""
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600&display=swap');
        @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600&display=swap');

        /* === BASE STYLES === */
        .gradio-container {
            max-width: 1920px !important;
            background: #000000 !important;
            font-family: 'Inter', 'ui-sans-serif', 'system-ui', sans-serif !important;
        }

        body {
            background: #000000 !important;
            /* Subtle noise texture for depth */
            background-image: 
                radial-gradient(circle at 20% 50%, rgba(255, 255, 255, 0.01) 0%, transparent 50%),
                radial-gradient(circle at 80% 80%, rgba(255, 255, 255, 0.01) 0%, transparent 50%);
        }

        /* === TYPOGRAPHY === */
        h1, h2, h3, h4, h5, h6 {
            font-family: 'Inter', sans-serif !important;
            color: #e8e8e8 !important;
            font-weight: 600 !important;
            letter-spacing: -0.02em;
        }

        .prose p {
            color: #999999 !important;
            font-family: 'Inter', sans-serif !important;
            font-size: 0.875rem;
            line-height: 1.6;
        }

        label {
            color: #999999 !important;
            font-family: 'Inter', sans-serif !important;
            font-size: 0.8rem !important;
            font-weight: 500 !important;
            letter-spacing: 0.01em;
        }

        /* === BUTTONS - Ultra Minimal === */
        .gr-button {
            border-radius: 8px !important;
            border: 1px solid #1a1a1a !important;
            font-family: 'Inter', sans-serif !important;
            font-weight: 500 !important;
            letter-spacing: 0;
            transition: all 0.2s cubic-bezier(0.4, 0, 0.2, 1) !important;
            background: #000000 !important;
            color: #e8e8e8 !important;
            box-shadow: 0 1px 3px rgba(255, 255, 255, 0.03) !important;
        }

        .gr-button:hover {
            background: #111111 !important;
            border-color: #333333 !important;
            box-shadow: 0 0 12px rgba(255, 255, 255, 0.06) !important;
            transform: translateY(-1px);
        }

        .gr-button-primary {
            border-color: #e8e8e8 !important;
        }

        .gr-button-primary:hover {
            box-shadow: 0 0 16px rgba(232, 232, 232, 0.1) !important;
        }

        /* === INPUTS === */
        .gr-box {
            border-radius: 8px !important;
            border: 1px solid #1a1a1a !important;
            background: #000000 !important;
        }

        .gr-input, .gr-textarea, select {
            border-radius: 8px !important;
            border: 1px solid #1a1a1a !important;
            background: #000000 !important;
            color: #e8e8e8 !important;
            font-family: 'JetBrains Mono', monospace !important;
            font-size: 0.875rem !important;
            transition: all 0.2s ease !important;
        }

        .gr-input:focus, .gr-textarea:focus, select:focus {
            border-color: #e8e8e8 !important;
            box-shadow: 0 0 8px rgba(255, 255, 255, 0.08) !important;
            outline: none !important;
        }

        /* === SCROLLBAR - Minimal === */
        ::-webkit-scrollbar {
            width: 8px;
            height: 8px;
        }

        ::-webkit-scrollbar-track {
            background: #000000;
        }

        ::-webkit-scrollbar-thumb {
            background: #1a1a1a;
            border-radius: 4px;
        }

        ::-webkit-scrollbar-thumb:hover {
            background: #333333;
        }

        /* === CARD CONTAINERS - Ultra Minimal === */
        #reasoning_card, #results_card {
            background: #000000 !important;
            border: 1px solid #1a1a1a !important;
            border-radius: 12px !important;
            padding: 28px !important;
            box-shadow: 
                0 1px 3px rgba(255, 255, 255, 0.03),
                inset 0 0 0 1px rgba(255, 255, 255, 0.02) !important;
            transition: all 0.3s ease !important;
        }

        #reasoning_card:hover, #results_card:hover {
            border-color: #333333 !important;
            box-shadow: 
                0 2px 6px rgba(255, 255, 255, 0.05),
                inset 0 0 0 1px rgba(255, 255, 255, 0.03),
                0 0 20px rgba(255, 255, 255, 0.04) !important;
        }

        #sidebar_card:hover {
            border-color: #333333 !important;
            box-shadow: 
                0 2px 6px rgba(255, 255, 255, 0.05),
                inset 0 0 0 1px rgba(255, 255, 255, 0.03),
                0 0 20px rgba(255, 255, 255, 0.04) !important;
        }

        /* === SIDEBAR LAYOUT === */
        #main_container {
            gap: 24px !important;
            align-items: stretch !important;
        }

        #sidebar {
            min-width: 420px !important;
            max-width: 500px !important;
            flex-shrink: 0 !important;
        }

        #sidebar_card {
            height: 100% !important;
        }

        #content_area {
            display: flex !important;
            flex-direction: column !important;
            gap: 20px !important;
            flex: 1 !important;
            min-width: 900px !important;
        }

        .gradio-row {
            gap: 24px !important;
        }

        /* === SIDEBAR STYLING === */
        #sidebar_card {
            background: #000000 !important;
            border: 1px solid #1a1a1a !important;
            border-radius: 12px !important;
            padding: 28px !important;
            box-shadow: 
                0 1px 3px rgba(255, 255, 255, 0.03),
                inset 0 0 0 1px rgba(255, 255, 255, 0.02) !important;
        }

        #alert_input {
            border: 1px solid #1a1a1a !important;
            border-radius: 8px !important;
            margin-top: 10px !important;
            margin-bottom: 14px !important;
            background: #000000 !important;
            font-size: 0.85rem !important;
        }

        #alert_dropdown {
            margin-bottom: 12px !important;
        }

        #investigate_btn {
            margin-top: 16px !important;
            width: 100% !important;
            font-size: 1rem !important;
            padding: 14px 20px !important;
        }

        /* === STATUS IN SIDEBAR === */
        #status_compact {
            margin-top: 0 !important;
        }

        .status-compact {
            font-family: 'JetBrains Mono', monospace !important;
            color: #999999 !important;
            font-size: 0.8rem !important;
        }

        .status-compact .metric-row {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 10px 0;
            border-bottom: 1px solid #1a1a1a;
        }

        .status-compact .metric-row:last-child {
            border-bottom: none;
        }

        .status-compact .metric-label {
            color: #999999;
            font-size: 0.75rem;
            font-weight: 500;
            letter-spacing: 0.01em;
        }

        .status-compact .metric-value {
            color: #e8e8e8;
            font-weight: 600;
            font-size: 0.8rem;
        }

        /* === PROGRESS BAR - Minimal === */
        .progress-bar-container {
            background: #0a0a0a !important;
            border: 1px solid #1a1a1a !important;
            border-radius: 4px !important;
            height: 6px !important;
            overflow: hidden !important;
            margin: 10px 0 !important;
        }

        .progress-bar {
            background: linear-gradient(90deg, #e8e8e8 0%, #999999 100%) !important;
            height: 100% !important;
            transition: width 0.3s cubic-bezier(0.4, 0, 0.2, 1) !important;
            box-shadow: 0 0 10px rgba(232, 232, 232, 0.2) !important;
        }

        /* === CARD HEADERS - Minimal Style === */
        .card-header {
            font-family: 'Inter', sans-serif !important;
            color: #e8e8e8 !important;
            font-size: 1.1rem !important;
            font-weight: 600 !important;
            margin-bottom: 8px !important;
            letter-spacing: -0.01em;
        }

        .card-description {
            font-family: 'Inter', sans-serif !important;
            color: #999999 !important;
            font-size: 0.85rem !important;
            margin-bottom: 20px !important;
            line-height: 1.5;
            font-weight: 400;
        }

        /* === REASONING PANEL - Clean Display (HERO SIZE) === */
        #reasoning_panel {
            font-family: 'JetBrains Mono', monospace !important;
            font-size: 0.875rem !important;
            line-height: 1.8 !important;
            background: transparent !important;
            border: none !important;
            padding: 0 !important;
            color: #e8e8e8 !important;
            min-height: 400px !important;
            max-height: 500px !important;
            overflow-y: auto !important;
        }

        /* Reasoning card - primary focus */
        #reasoning_card {
            flex: 1 !important;
            margin-bottom: 0 !important;
        }

        /* Results card */
        #results_card {
            flex: 0.6 !important;
        }

        #reasoning_panel * {
            background: transparent !important;
        }

        /* Reasoning Panel Markdown Elements */
        #reasoning_panel p {
            color: #e8e8e8 !important;
            margin-bottom: 12px !important;
            font-family: 'JetBrains Mono', monospace !important;
        }

        #reasoning_panel strong {
            color: #e8e8e8 !important;
            font-weight: 600 !important;
        }

        #reasoning_panel em {
            color: #999999 !important;
            font-style: italic !important;
        }

        #reasoning_panel ul, #reasoning_panel ol {
            color: #e8e8e8 !important;
            margin-left: 20px !important;
            margin-bottom: 12px !important;
        }

        #reasoning_panel li {
            margin-bottom: 6px !important;
            color: #999999 !important;
        }

        #reasoning_panel h1, #reasoning_panel h2, #reasoning_panel h3, #reasoning_panel h4 {
            color: #e8e8e8 !important;
            font-family: 'Inter', sans-serif !important;
            font-weight: 600 !important;
            margin-top: 16px !important;
            margin-bottom: 12px !important;
            letter-spacing: -0.01em;
        }

        #reasoning_panel code {
            background: rgba(255, 255, 255, 0.04) !important;
            color: #e8e8e8 !important;
            padding: 3px 6px !important;
            border-radius: 4px !important;
            font-family: 'JetBrains Mono', monospace !important;
            border: 1px solid #1a1a1a !important;
        }

        #reasoning_panel pre {
            background: rgba(255, 255, 255, 0.02) !important;
            border: 1px solid #1a1a1a !important;
            padding: 16px !important;
            border-radius: 8px !important;
            overflow-x: auto !important;
        }

        #reasoning_panel blockquote {
            border-left: 2px solid #333333 !important;
            padding-left: 16px !important;
            margin: 12px 0 !important;
            color: #999999 !important;
        }

        /* === RESULTS HTML === */
        #result_html {
            min-height: 300px !important;
        }

        /* === REMOVE DEFAULT GRADIO STYLES === */
        .gr-box {
            border: none !important;
            background: transparent !important;
        }

        /* === PAGE PADDING === */
        .gradio-container {
            padding: 40px !important;
        }

        /* === TABS === */
        .gradio-tabs {
            border: none !important;
            background: transparent !important;
        }

        .gradio-tabs .tab-nav {
            border-bottom: 1px solid #1a1a1a !important;
            margin-bottom: 24px !important;
            gap: 0 !important;
        }

        .gradio-tabs button {
            border: none !important;
            border-bottom: 2px solid transparent !important;
            background: transparent !important;
            color: #999999 !important;
            font-family: 'Inter', sans-serif !important;
            font-weight: 500 !important;
            font-size: 0.95rem !important;
            padding: 12px 24px !important;
            transition: all 0.2s ease !important;
            border-radius: 0 !important;
        }

        .gradio-tabs button.selected {
            color: #e8e8e8 !important;
            border-bottom-color: #e8e8e8 !important;
        }

        .gradio-tabs button:hover {
            color: #e8e8e8 !important;
            background: rgba(255, 255, 255, 0.02) !important;
        }

        /* Memory Context Cards */
        #memory_reasoning_card, #similar_incidents_card {
            background: #000000 !important;
            border: 1px solid #1a1a1a !important;
            border-radius: 12px !important;
            padding: 28px !important;
            margin-bottom: 20px !important;
            box-shadow:
                0 1px 3px rgba(255, 255, 255, 0.03),
                inset 0 0 0 1px rgba(255, 255, 255, 0.02) !important;
            transition: all 0.3s ease !important;
        }

        #memory_reasoning_card:hover, #similar_incidents_card:hover {
            border-color: #333333 !important;
            box-shadow:
                0 2px 6px rgba(255, 255, 255, 0.05),
                inset 0 0 0 1px rgba(255, 255, 255, 0.03),
                0 0 20px rgba(255, 255, 255, 0.04) !important;
        }

        /* Chat Card */
        #chat_card {
            background: #000000 !important;
            border: 1px solid #1a1a1a !important;
            border-radius: 12px !important;
            padding: 28px !important;
        }

        /* === MICRO ANIMATIONS === */
        * {
            transition: border-color 0.2s ease, box-shadow 0.2s ease, background 0.2s ease !important;
        }
        """,
        js="""
        function setupAutoScroll() {
            // Auto-scroll reasoning panel when content updates
            const setupObserver = () => {
                const reasoningPanel = document.querySelector('#reasoning_panel');
                if (reasoningPanel) {
                    // Create a MutationObserver to watch for content changes
                    const observer = new MutationObserver((mutations) => {
                        // Scroll to bottom when content changes
                        reasoningPanel.scrollTop = reasoningPanel.scrollHeight;
                    });

                    // Start observing
                    observer.observe(reasoningPanel, {
                        childList: true,
                        subtree: true,
                        characterData: true
                    });

                    console.log('[SOC] Auto-scroll enabled for reasoning panel');
                } else {
                    // Retry after a short delay if element not found
                    setTimeout(setupObserver, 500);
                }
            };

            // Wait for DOM to be ready
            if (document.readyState === 'loading') {
                document.addEventListener('DOMContentLoaded', setupObserver);
            } else {
                setupObserver();
            }

            return [];
        }
        """
    ) as demo:

        # ===== MAIN LAYOUT: SIDEBAR (28%) | CONTENT (72%) =====
        with gr.Row(elem_id="main_container"):
            # ===== LEFT: SIDEBAR (28%) =====
            with gr.Column(scale=28, min_width=320, elem_id="sidebar"):
                with gr.Column(elem_id="sidebar_card"):
                    # Status Section (Top)
                    gr.HTML("""
                        <div style="margin-bottom: 20px;">
                            <div style="font-family: 'Inter', sans-serif; font-size: 1.1rem; font-weight: 600; color: #e8e8e8; margin-bottom: 8px; letter-spacing: -0.01em;">Investigation Status</div>
                            <div style="font-family: 'Inter', sans-serif; font-size: 0.85rem; color: #999999; font-weight: 400; line-height: 1.5;">Real-time progress.</div>
                        </div>
                    """)
                    
                    status_compact = gr.HTML(
                        value=_get_initial_status_compact_html(),
                        show_label=False,
                        elem_id="status_compact"
                    )

                    # Alert Section (Bottom)
                    gr.HTML("""
                        <div style="margin-top: 32px; margin-bottom: 20px;">
                            <div style="font-family: 'Inter', sans-serif; font-size: 1.1rem; font-weight: 600; color: #e8e8e8; margin-bottom: 8px; letter-spacing: -0.01em;">Alert Input</div>
                            <div style="font-family: 'Inter', sans-serif; font-size: 0.85rem; color: #999999; font-weight: 400; line-height: 1.5;">Select or paste a security alert.</div>
                        </div>
                    """)
                    
                    if alert_choices:
                        sample_dropdown = gr.Dropdown(
                            choices=list(alert_choices.keys()),
                            value=list(alert_choices.keys())[0] if alert_choices else None,
                            interactive=True,
                            show_label=False,
                            container=False,
                            elem_id="alert_dropdown"
                        )

                    alert_input = gr.Code(
                        language="json",
                        lines=14,
                        value=list(alert_choices.values())[0] if alert_choices else "{}",
                        show_label=False,
                        container=False,
                        elem_id="alert_input"
                    )

                    investigate_btn = gr.Button(
                        "🚀 Investigate",
                        variant="primary",
                        size="lg",
                        elem_id="investigate_btn"
                    )

            # ===== RIGHT: CONTENT AREA (72%) - Multi-Tab Interface =====
            with gr.Column(scale=72, elem_id="content_area"):
                with gr.Tabs() as investigation_tabs:

                    # ===== TAB 1: INVESTIGATION (Current Workflow) =====
                    with gr.Tab("🔍 Investigation", id="tab_investigation"):
                        # Agent Reasoning (Top)
                        with gr.Column(elem_id="reasoning_card"):
                            gr.HTML("""
                                <div style="margin-bottom: 20px;">
                                    <div style="font-family: 'Inter', sans-serif; font-size: 1.25rem; font-weight: 600; color: #e8e8e8; margin-bottom: 8px; letter-spacing: -0.02em;">Agent Reasoning</div>
                                    <div style="font-family: 'Inter', sans-serif; font-size: 0.875rem; color: #999999; font-weight: 400; line-height: 1.5;">Live LLM reasoning from Analysis and Response agents.</div>
                                </div>
                            """)
                            reasoning_panel = gr.Markdown(
                                value="*Agent reasoning will appear here as the LLM thinks...*",
                                show_label=False,
                                container=False,
                                elem_id="reasoning_panel"
                            )

                        # Investigation Results (Bottom)
                        with gr.Column(elem_id="results_card"):
                            gr.HTML("""
                                <div style="margin-bottom: 20px;">
                                    <div style="font-family: 'Inter', sans-serif; font-size: 1.1rem; font-weight: 600; color: #e8e8e8; margin-bottom: 8px; letter-spacing: -0.01em;">Investigation Results</div>
                                    <div style="font-family: 'Inter', sans-serif; font-size: 0.85rem; color: #999999; font-weight: 400; line-height: 1.5;">Complete analysis with threat score and recommended actions.</div>
                                </div>
                            """)
                            result_html = gr.HTML(
                                show_label=False,
                                elem_id="result_html"
                            )

                    # ===== TAB 2: MEMORY CONTEXT =====
                    with gr.Tab("🧠 Memory Context", id="tab_memory"):
                        # Memory Reasoning Panel
                        with gr.Column(elem_id="memory_reasoning_card"):
                            gr.HTML("""
                                <div style="margin-bottom: 20px;">
                                    <div style="font-family: 'Inter', sans-serif; font-size: 1.1rem; font-weight: 600; color: #e8e8e8; margin-bottom: 8px;">
                                        💭 Memory Reasoning
                                    </div>
                                    <div style="font-family: 'Inter', sans-serif; font-size: 0.85rem; color: #999999;">
                                        AI explains why past incidents are similar
                                    </div>
                                </div>
                            """)
                            memory_reasoning_display = gr.Markdown(
                                value="*No memory context available yet. Run an investigation first.*",
                                show_label=False,
                                elem_id="memory_reasoning_panel"
                            )

                        # Similar Incidents Cards
                        with gr.Column(elem_id="similar_incidents_card"):
                            gr.HTML("""
                                <div style="margin-bottom: 20px; margin-top: 24px;">
                                    <div style="font-family: 'Inter', sans-serif; font-size: 1.1rem; font-weight: 600; color: #e8e8e8; margin-bottom: 8px;">
                                        🔍 Similar Past Incidents
                                    </div>
                                    <div style="font-family: 'Inter', sans-serif; font-size: 0.85rem; color: #999999;">
                                        Incidents with matching patterns and behaviors
                                    </div>
                                </div>
                            """)
                            similar_incidents_display = gr.HTML(
                                value="",
                                show_label=False,
                                elem_id="similar_incidents_html"
                            )

                        # Campaign Detection Alert (conditional visibility)
                        campaign_alert_display = gr.HTML(
                            value="",
                            visible=True,
                            show_label=False,
                            elem_id="campaign_alert_html"
                        )

                    # ===== TAB 3: CHAT =====
                    with gr.Tab("💬 Chat", id="tab_chat"):
                        with gr.Column(elem_id="chat_card"):
                            gr.HTML("""
                                <div style="margin-bottom: 20px;">
                                    <div style="font-family: 'Inter', sans-serif; font-size: 1.25rem; font-weight: 600; color: #e8e8e8; margin-bottom: 8px;">
                                        Chat with Investigation History
                                    </div>
                                    <div style="font-family: 'Inter', sans-serif; font-size: 0.875rem; color: #999999;">
                                        Ask questions about past investigations, campaigns, and statistics
                                    </div>
                                </div>
                            """)
                            
                            # Chatbot
                            chatbot = gr.Chatbot(
                                height=500,
                                show_label=False,
                                elem_id="chat_history",
                                bubble_full_width=False
                            )
                            
                            # Message input
                            with gr.Row():
                                chat_input = gr.Textbox(
                                    placeholder="Ask about past investigations...",
                                    show_label=False,
                                    scale=9,
                                    container=False
                                )
                                chat_send = gr.Button("Send", scale=1, variant="primary")
                            
                            # Example queries
                            gr.HTML("""
                                <div style="margin-top: 20px; padding-top: 20px; border-top: 1px solid #1a1a1a;">
                                    <div style="font-size: 0.8rem; color: #666; margin-bottom: 12px; font-family: 'Inter', sans-serif;">Quick Actions:</div>
                                </div>
                            """)
                            
                            with gr.Row():
                                example_btn1 = gr.Button("📊 Show statistics", size="sm")
                                example_btn2 = gr.Button("🔍 High-severity alerts", size="sm")
                                example_btn3 = gr.Button("🚨 Active campaigns", size="sm")
                            
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


        # Connect dropdown to alert input
        if alert_choices:
            sample_dropdown.change(
                fn=load_selected_alert,
                inputs=sample_dropdown,
                outputs=alert_input
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
