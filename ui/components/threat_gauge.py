"""
Threat Score Gauge Component
Circular gauge visualization for threat scores
"""

from typing import Optional, Tuple
import math


def get_severity_from_score(score: float) -> Tuple[str, str]:
    """
    Determines severity level and CSS class from threat score

    Args:
        score: Threat score (0-100 or 0-1)

    Returns:
        Tuple of (severity label, css class)
    """
    # Normalize to 0-100 if needed
    if score <= 1:
        score = score * 100

    if score >= 80:
        return ("CRITICAL", "critical")
    elif score >= 60:
        return ("HIGH", "high")
    elif score >= 40:
        return ("MEDIUM", "medium")
    else:
        return ("LOW", "low")


def create_score_ring(
    score: float,
    size: int = 140,
) -> str:
    """
    Creates the SVG score ring visualization

    Args:
        score: Threat score (0-100 or 0-1)
        size: Ring size in pixels

    Returns:
        HTML string for score ring
    """
    # Normalize score to 0-100
    if score <= 1:
        normalized_score = score * 100
    else:
        normalized_score = min(100, max(0, score))

    # Calculate stroke-dashoffset for progress
    # Circumference = 2 * PI * radius (r=45)
    circumference = 2 * math.pi * 45  # ~283
    offset = circumference - (circumference * normalized_score / 100)

    severity_label, severity_class = get_severity_from_score(normalized_score)
    display_score = int(normalized_score)

    return f"""
    <div class="score-ring" style="width: {size}px; height: {size}px;">
        <svg viewBox="0 0 100 100">
            <circle class="ring-bg" cx="50" cy="50" r="45" />
            <circle
                class="ring-progress {severity_class}"
                cx="50" cy="50" r="45"
                style="stroke-dasharray: {circumference}; stroke-dashoffset: {offset};"
            />
        </svg>
        <span class="score-value">
            {display_score}<span class="score-percent">%</span>
        </span>
    </div>
    """


def create_severity_badge(
    severity: str,
    label: Optional[str] = None,
) -> str:
    """
    Creates a severity badge

    Args:
        severity: Severity level (critical, high, medium, low)
        label: Optional custom label (defaults to severity name)

    Returns:
        HTML string for severity badge
    """
    severity_lower = severity.lower()
    display_label = label or severity.upper()

    # Add warning icon for high/critical
    icon = ""
    if severity_lower in ("critical", "high"):
        icon = "⚠️ "

    return f"""
    <span class="severity-badge {severity_lower}">
        {icon}{display_label}
    </span>
    """


def create_threat_score_card(
    score: float,
    category: Optional[str] = None,
    show_severity: bool = True,
) -> str:
    """
    Creates the complete Threat Score Bento card

    Args:
        score: Threat score (0-100 or 0-1)
        category: Optional attack category label
        show_severity: Whether to show severity badge

    Returns:
        HTML string for the complete card
    """
    # Normalize score
    if score <= 1:
        normalized_score = score * 100
    else:
        normalized_score = score

    severity_label, severity_class = get_severity_from_score(normalized_score)
    score_ring = create_score_ring(normalized_score)

    severity_html = ""
    if show_severity:
        severity_html = create_severity_badge(severity_class, severity_label)

    category_html = ""
    if category:
        category_html = f"""
        <span class="category-label" style="font-size: var(--text-sm); color: var(--text-secondary);">
            {category}
        </span>
        """

    return f"""
    <div class="bento-card bento-3x2" id="threat-score-card">
        <div class="bento-card-header">
            <div class="bento-card-icon">📊</div>
            <span class="bento-card-title">THREAT SCORE</span>
        </div>
        <div class="threat-score-display">
            {score_ring}
            <div class="score-meta" style="display: flex; flex-direction: column; align-items: center; gap: 8px;">
                {severity_html}
                {category_html}
            </div>
        </div>
    </div>
    """


def create_mini_score(
    score: float,
    size: int = 48,
) -> str:
    """
    Creates a mini score indicator

    Args:
        score: Threat score (0-100 or 0-1)
        size: Size in pixels

    Returns:
        HTML string for mini score
    """
    # Normalize score
    if score <= 1:
        normalized_score = score * 100
    else:
        normalized_score = min(100, max(0, score))

    severity_label, severity_class = get_severity_from_score(normalized_score)
    display_score = int(normalized_score)

    # Color map
    color_map = {
        "critical": "var(--danger)",
        "high": "#f97316",
        "medium": "var(--warning)",
        "low": "var(--success)",
    }
    color = color_map.get(severity_class, "var(--text-secondary)")

    return f"""
    <div class="mini-score" style="
        width: {size}px;
        height: {size}px;
        border-radius: 50%;
        border: 3px solid {color};
        display: flex;
        align-items: center;
        justify-content: center;
        font-family: var(--font-display);
        font-size: {size // 3}px;
        font-weight: var(--font-bold);
        color: var(--text-primary);
    ">
        {display_score}
    </div>
    """


def create_horizontal_score_bar(
    score: float,
    width: str = "100%",
    height: int = 8,
) -> str:
    """
    Creates a horizontal score bar

    Args:
        score: Threat score (0-100 or 0-1)
        width: Bar width (CSS value)
        height: Bar height in pixels

    Returns:
        HTML string for score bar
    """
    # Normalize score
    if score <= 1:
        normalized_score = score * 100
    else:
        normalized_score = min(100, max(0, score))

    severity_label, severity_class = get_severity_from_score(normalized_score)

    # Color map
    color_map = {
        "critical": "var(--danger)",
        "high": "#f97316",
        "medium": "var(--warning)",
        "low": "var(--success)",
    }
    color = color_map.get(severity_class, "var(--accent)")

    return f"""
    <div class="score-bar" style="
        width: {width};
        height: {height}px;
        background: var(--border-subtle);
        border-radius: var(--radius-full);
        overflow: hidden;
    ">
        <div class="score-bar-fill" style="
            width: {normalized_score}%;
            height: 100%;
            background: {color};
            border-radius: var(--radius-full);
            transition: width 0.6s ease;
        "></div>
    </div>
    """
