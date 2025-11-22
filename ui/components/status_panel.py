"""
Status Panel Component
Vertical stepper workflow with progress tracking and animations
"""

from typing import List, Optional

# Agent colors for visual identity
AGENT_COLORS = {
    "supervisor": "#3b82f6",
    "enrichment": "#10b981",
    "analysis": "#f59e0b",
    "investigation": "#8b5cf6",
    "response": "#ef4444",
    "communication": "#06b6d4",
}


def get_initial_status_compact_html() -> str:
    """
    Generate initial status with vertical step-by-step workflow (Bento style)
    """
    return """
    <div style="font-family: var(--font-mono, 'JetBrains Mono', monospace);">
        <!-- Progress Header -->
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px;">
            <span style="font-size: 0.7rem; color: var(--text-secondary, #71717a); font-weight: 500; letter-spacing: 0.1em;">PROGRESS</span>
            <span style="font-size: 0.8rem; color: var(--text-primary, #ffffff); font-weight: 600;">0%</span>
        </div>

        <!-- Progress Bar (Bento style) -->
        <div style="background: var(--bg-elevated, #111111); border: 1px solid var(--border-subtle, #1a1a1a); height: 6px; border-radius: 9999px; overflow: hidden; margin-bottom: 20px;">
            <div style="background: var(--border-subtle, #1a1a1a); width: 0%; height: 100%; transition: width 0.5s ease; border-radius: 9999px;"></div>
        </div>

        <!-- Workflow Steps (Vertical - Bento) -->
        <div style="margin-top: 16px;">
            <div style="display: flex; align-items: flex-start; margin-bottom: 14px;">
                <div style="flex-shrink: 0; width: 24px; height: 24px; border-radius: 50%; border: 2px solid var(--border-subtle, #1a1a1a); display: flex; align-items: center; justify-content: center; background: var(--bg-surface, #0a0a0a); margin-right: 12px; font-size: 0.7rem; color: var(--text-tertiary, #52525b);">1</div>
                <div style="flex: 1;">
                    <div style="font-size: 0.75rem; color: var(--text-secondary, #71717a); font-weight: 500;">Supervisor</div>
                    <div style="font-size: 0.65rem; color: var(--text-tertiary, #52525b); margin-top: 2px;">Pending</div>
                </div>
            </div>

            <div style="display: flex; align-items: flex-start; margin-bottom: 14px;">
                <div style="flex-shrink: 0; width: 24px; height: 24px; border-radius: 50%; border: 2px solid var(--border-subtle, #1a1a1a); display: flex; align-items: center; justify-content: center; background: var(--bg-surface, #0a0a0a); margin-right: 12px; font-size: 0.7rem; color: var(--text-tertiary, #52525b);">2</div>
                <div style="flex: 1;">
                    <div style="font-size: 0.75rem; color: var(--text-secondary, #71717a); font-weight: 500;">Enrichment</div>
                    <div style="font-size: 0.65rem; color: var(--text-tertiary, #52525b); margin-top: 2px;">Pending</div>
                </div>
            </div>

            <div style="display: flex; align-items: flex-start; margin-bottom: 14px;">
                <div style="flex-shrink: 0; width: 24px; height: 24px; border-radius: 50%; border: 2px solid var(--border-subtle, #1a1a1a); display: flex; align-items: center; justify-content: center; background: var(--bg-surface, #0a0a0a); margin-right: 12px; font-size: 0.7rem; color: var(--text-tertiary, #52525b);">3</div>
                <div style="flex: 1;">
                    <div style="font-size: 0.75rem; color: var(--text-secondary, #71717a); font-weight: 500;">Analysis</div>
                    <div style="font-size: 0.65rem; color: var(--text-tertiary, #52525b); margin-top: 2px;">Pending</div>
                </div>
            </div>

            <div style="display: flex; align-items: flex-start; margin-bottom: 14px;">
                <div style="flex-shrink: 0; width: 24px; height: 24px; border-radius: 50%; border: 2px solid var(--border-subtle, #1a1a1a); display: flex; align-items: center; justify-content: center; background: var(--bg-surface, #0a0a0a); margin-right: 12px; font-size: 0.7rem; color: var(--text-tertiary, #52525b);">4</div>
                <div style="flex: 1;">
                    <div style="font-size: 0.75rem; color: var(--text-secondary, #71717a); font-weight: 500;">Investigation</div>
                    <div style="font-size: 0.65rem; color: var(--text-tertiary, #52525b); margin-top: 2px;">Pending</div>
                </div>
            </div>

            <div style="display: flex; align-items: flex-start; margin-bottom: 14px;">
                <div style="flex-shrink: 0; width: 24px; height: 24px; border-radius: 50%; border: 2px solid var(--border-subtle, #1a1a1a); display: flex; align-items: center; justify-content: center; background: var(--bg-surface, #0a0a0a); margin-right: 12px; font-size: 0.7rem; color: var(--text-tertiary, #52525b);">5</div>
                <div style="flex: 1;">
                    <div style="font-size: 0.75rem; color: var(--text-secondary, #71717a); font-weight: 500;">Response</div>
                    <div style="font-size: 0.65rem; color: var(--text-tertiary, #52525b); margin-top: 2px;">Pending</div>
                </div>
            </div>

            <div style="display: flex; align-items: flex-start;">
                <div style="flex-shrink: 0; width: 24px; height: 24px; border-radius: 50%; border: 2px solid var(--border-subtle, #1a1a1a); display: flex; align-items: center; justify-content: center; background: var(--bg-surface, #0a0a0a); margin-right: 12px; font-size: 0.7rem; color: var(--text-tertiary, #52525b);">6</div>
                <div style="flex: 1;">
                    <div style="font-size: 0.75rem; color: var(--text-secondary, #71717a); font-weight: 500;">Communication</div>
                    <div style="font-size: 0.65rem; color: var(--text-tertiary, #52525b); margin-top: 2px;">Pending</div>
                </div>
            </div>
        </div>

        <!-- Time Footer -->
        <div style="margin-top: 20px; padding-top: 14px; border-top: 1px solid var(--border-subtle, #1a1a1a);">
            <div style="display: flex; justify-content: space-between; align-items: center;">
                <span style="font-size: 0.7rem; color: var(--text-secondary, #71717a); font-weight: 500; letter-spacing: 0.1em;">TIME</span>
                <span style="font-size: 0.8rem; color: var(--text-primary, #ffffff); font-weight: 600;">--</span>
            </div>
        </div>
    </div>
    """


def get_threat_score_html(threat_score: Optional[float], progress_pct: int) -> str:
    """
    Generate threat score display for completed investigations

    Args:
        threat_score: Calculated threat score (0-1)
        progress_pct: Current progress percentage

    Returns:
        HTML string for threat score display
    """
    if threat_score is None or progress_pct < 100:
        return ""

    # Color based on severity
    if threat_score >= 0.7:
        color = "#ef4444"  # Red - High
        label = "HIGH"
    elif threat_score >= 0.4:
        color = "#f59e0b"  # Amber - Medium
        label = "MEDIUM"
    else:
        color = "#10b981"  # Green - Low
        label = "LOW"

    return f"""
    <div style="display: flex; justify-content: space-between; align-items: center; margin-top: 12px;">
        <span style="font-size: 0.7rem; color: #999999; font-weight: 500; letter-spacing: 0.05em;">THREAT</span>
        <div style="display: flex; align-items: center; gap: 8px;">
            <span style="font-size: 0.65rem; color: {color}; font-weight: 600; padding: 2px 6px; background: {color}22; border-radius: 4px;">{label}</span>
            <span style="font-size: 0.8rem; color: {color}; font-weight: 600;">{threat_score:.2f}</span>
        </div>
    </div>
    """


def get_status_compact_html(
    current_node: str,
    completed_nodes: List[str],
    skipped_nodes: List[str],
    progress_pct: int,
    total_time: float,
    threat_score: Optional[float] = None
) -> str:
    """
    Generate updated status with vertical step-by-step workflow
    Shows execution order and current progress with animations

    Args:
        current_node: Currently executing node
        completed_nodes: List of completed node names
        skipped_nodes: List of skipped node names
        progress_pct: Progress percentage (0-100)
        total_time: Total elapsed time in seconds
        threat_score: Optional threat score for completed investigations

    Returns:
        HTML string for status display
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

    # Progress bar styling with Bento neon green accent
    if progress_pct >= 100:
        bar_gradient = "linear-gradient(90deg, #00ff88 0%, #10b981 100%)"  # Neon green
        bar_shadow = "0 0 20px rgba(0, 255, 136, 0.4)"
        bar_animation = "animation: accentGlow 2s ease-in-out infinite;"
    elif progress_pct >= 50:
        bar_gradient = "linear-gradient(90deg, #00ff88 0%, #00cc6a 100%)"  # Neon green
        bar_shadow = "0 0 15px rgba(0, 255, 136, 0.3)"
        bar_animation = ""
    else:
        bar_gradient = "linear-gradient(90deg, #00ff88 0%, #00aa55 100%)"  # Neon green dimmer
        bar_shadow = "0 0 10px rgba(0, 255, 136, 0.2)"
        bar_animation = ""

    # Build vertical steps with enhanced styling
    steps_html = ""
    for step_num, node_id, label in nodes:
        agent_color = AGENT_COLORS.get(node_id, "#666666")

        # Determine step state with agent-specific colors (Bento style)
        if node_id in completed_nodes:
            # Completed - neon green checkmark with agent accent
            circle_style = f"""
                background: linear-gradient(135deg, {agent_color}22 0%, #000000 100%);
                border: 2px solid #00ff88;
                box-shadow: 0 0 12px rgba(0, 255, 136, 0.3);
            """
            circle_content = '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="#00ff88" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>'
            title_color = "#00ff88"
            status_text = "Completed"
            status_color = "#10b981"
            row_animation = ""
        elif node_id == current_node:
            # In Progress - pulsing with agent color
            circle_style = f"""
                background: {agent_color}22;
                border: 2px solid {agent_color};
                box-shadow: 0 0 0 0 {agent_color}66;
                animation: pulse-ring-{node_id} 1.5s ease-in-out infinite;
            """
            circle_content = f'<span style="color: {agent_color}; font-size: 0.75rem; font-weight: 700;">{step_num}</span>'
            title_color = agent_color
            status_text = "In Progress..."
            status_color = agent_color
            row_animation = f"animation: fadeInUp 0.3s ease-out;"
        elif node_id in skipped_nodes:
            # Skipped - dashed border
            circle_style = """
                background: #000000;
                border: 2px dashed #444444;
            """
            circle_content = '<span style="color: #666666; font-size: 0.9rem;">−</span>'
            title_color = "#666666"
            status_text = "Skipped"
            status_color = "#444444"
            row_animation = ""
        else:
            # Pending - dimmed
            circle_style = """
                background: #000000;
                border: 2px solid #333333;
            """
            circle_content = f'<span style="color: #666666; font-size: 0.7rem;">{step_num}</span>'
            title_color = "#666666"
            status_text = "Pending"
            status_color = "#444444"
            row_animation = ""

        is_last = (step_num == 6)
        margin_bottom = "0" if is_last else "14px"

        # Add connecting line for non-last items (Bento neon green)
        connector = ""
        if not is_last:
            next_node = nodes[step_num][1] if step_num < len(nodes) else None
            line_color = "#00ff88" if node_id in completed_nodes else "var(--border-subtle, #1a1a1a)"
            connector = f'<div style="position: absolute; left: 11px; top: 28px; width: 2px; height: 12px; background: {line_color};"></div>'

        steps_html += f"""
        <div style="display: flex; align-items: flex-start; margin-bottom: {margin_bottom}; position: relative; {row_animation}" data-agent="{node_id}">
            <div style="flex-shrink: 0; width: 24px; height: 24px; border-radius: 50%; display: flex; align-items: center; justify-content: center; margin-right: 12px; {circle_style} transition: all 0.3s ease;">
                {circle_content}
            </div>
            {connector}
            <div style="flex: 1;">
                <div style="font-size: 0.75rem; color: {title_color}; font-weight: 500; transition: color 0.3s ease;">{label}</div>
                <div style="font-size: 0.65rem; color: {status_color}; margin-top: 2px; transition: color 0.3s ease;">{status_text}</div>
            </div>
        </div>
        """

    # Note: Keyframe animations are in global CSS (ui/styles/css.py and bento_css.py)
    # This prevents flicker from re-parsing styles on each update

    return f"""
    <div style="font-family: var(--font-mono, 'JetBrains Mono', monospace);">
        <!-- Progress Header -->
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px;">
            <span style="font-size: 0.7rem; color: var(--text-secondary, #71717a); font-weight: 500; letter-spacing: 0.1em;">PROGRESS</span>
            <span style="font-size: 0.8rem; color: var(--text-primary, #ffffff); font-weight: 600;">{progress_pct}%</span>
        </div>

        <!-- Progress Bar with Bento styling -->
        <div style="background: var(--bg-elevated, #111111); border: 1px solid var(--border-subtle, #1a1a1a); height: 6px; border-radius: 9999px; overflow: hidden; margin-bottom: 20px; position: relative;">
            <div style="background: {bar_gradient}; width: {progress_pct}%; height: 100%; transition: width 0.5s cubic-bezier(0.4, 0, 0.2, 1); box-shadow: {bar_shadow}; border-radius: 9999px; {bar_animation}"></div>
        </div>

        <!-- Workflow Steps (Vertical) -->
        <div style="margin-top: 16px;">
            {steps_html}
        </div>

        <!-- Time Footer -->
        <div style="margin-top: 20px; padding-top: 14px; border-top: 1px solid var(--border-subtle, #1a1a1a);">
            <div style="display: flex; justify-content: space-between; align-items: center;">
                <span style="font-size: 0.7rem; color: var(--text-secondary, #71717a); font-weight: 500; letter-spacing: 0.1em;">TIME</span>
                <span style="font-size: 0.8rem; color: var(--text-primary, #ffffff); font-weight: 600;">{total_time:.1f}s</span>
            </div>
            {get_threat_score_html(threat_score, progress_pct)}
        </div>
    </div>
    """
