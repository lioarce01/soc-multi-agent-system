"""
Status Panel Component
Vertical stepper workflow with progress tracking
"""

from typing import List, Optional


def get_initial_status_compact_html() -> str:
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
    Shows execution order and current progress

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
            {get_threat_score_html(threat_score, progress_pct)}
        </div>
    </div>
    """
