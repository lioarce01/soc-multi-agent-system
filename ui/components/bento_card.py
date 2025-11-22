"""
Bento Card Base Component
Reusable card components for the Bento UI system
"""

from typing import Optional, List, Dict, Any


def create_bento_card(
    title: str,
    icon: str,
    content_html: str,
    size_class: str = "bento-2x2",
    extra_classes: str = "",
    card_id: str = "",
    show_live_indicator: bool = False,
) -> str:
    """
    Creates a complete Bento card with header and content

    Args:
        title: Card title (will be uppercased)
        icon: Emoji icon
        content_html: HTML content for the card body
        size_class: CSS grid size class
        extra_classes: Additional CSS classes
        card_id: Optional element ID
        show_live_indicator: Show LIVE indicator in header

    Returns:
        Complete HTML string for the card
    """
    id_attr = f'id="{card_id}"' if card_id else ""

    live_indicator = ""
    if show_live_indicator:
        live_indicator = """
        <span class="live-indicator">
            <span class="live-dot"></span>
            LIVE
        </span>
        """

    return f"""
    <div class="bento-card {size_class} {extra_classes}" {id_attr}>
        <div class="bento-card-header">
            <div class="bento-card-icon">{icon}</div>
            <span class="bento-card-title">{title.upper()}</span>
            {live_indicator}
        </div>
        <div class="bento-card-content">
            {content_html}
        </div>
    </div>
    """


def create_stat_card(
    label: str,
    value: str,
    variant: str = "default",
) -> str:
    """
    Creates a stat item for stat grids

    Args:
        label: Stat label
        value: Stat value
        variant: Color variant (default, danger, success, accent)

    Returns:
        HTML string for stat item
    """
    variant_class = variant if variant != "default" else ""

    return f"""
    <div class="stat-item {variant_class}">
        <span class="stat-label">{label}</span>
        <span class="stat-value">{value}</span>
    </div>
    """


def create_stat_grid(stats: List[Dict[str, Any]]) -> str:
    """
    Creates a stat grid with multiple stat items

    Args:
        stats: List of stat dicts with keys: label, value, variant (optional)

    Returns:
        HTML string for stat grid
    """
    stat_items = ""
    for stat in stats:
        stat_items += create_stat_card(
            label=stat.get("label", ""),
            value=stat.get("value", ""),
            variant=stat.get("variant", "default"),
        )

    return f"""
    <div class="stat-grid">
        {stat_items}
    </div>
    """


def create_action_item(
    number: int,
    text: str,
    urgent: bool = False,
) -> str:
    """
    Creates an action list item

    Args:
        number: Action number
        text: Action description
        urgent: Whether this is urgent

    Returns:
        HTML string for action item
    """
    urgent_class = "urgent" if urgent else ""

    return f"""
    <div class="action-item {urgent_class}">
        <span class="action-number">{number}</span>
        <span class="action-text">{text}</span>
    </div>
    """


def create_action_list(actions: List[Dict[str, Any]]) -> str:
    """
    Creates an action list

    Args:
        actions: List of action dicts with keys: text, urgent (optional)

    Returns:
        HTML string for action list
    """
    action_items = ""
    for i, action in enumerate(actions, 1):
        action_items += create_action_item(
            number=i,
            text=action.get("text", ""),
            urgent=action.get("urgent", False),
        )

    return f"""
    <div class="action-list">
        {action_items}
    </div>
    """


def create_technique_item(
    technique_id: str,
    confidence: float,
    url: Optional[str] = None,
) -> str:
    """
    Creates a MITRE technique item with confidence bar

    Args:
        technique_id: MITRE technique ID (e.g., T1110.001)
        confidence: Confidence percentage (0-100)
        url: Optional link to MITRE page

    Returns:
        HTML string for technique item
    """
    confidence_pct = min(100, max(0, int(confidence)))

    if url:
        id_html = f'<a href="{url}" target="_blank" class="technique-id">{technique_id}</a>'
    else:
        id_html = f'<span class="technique-id">{technique_id}</span>'

    return f"""
    <div class="technique-item">
        {id_html}
        <div class="technique-bar">
            <div class="bar-fill" style="--confidence: {confidence_pct}%; width: {confidence_pct}%;"></div>
        </div>
        <span class="technique-confidence">{confidence_pct}%</span>
    </div>
    """


def create_technique_list(techniques: List[Dict[str, Any]]) -> str:
    """
    Creates a MITRE technique list

    Args:
        techniques: List of technique dicts with keys: id, confidence, url (optional)

    Returns:
        HTML string for technique list
    """
    technique_items = ""
    for tech in techniques:
        technique_items += create_technique_item(
            technique_id=tech.get("id", ""),
            confidence=tech.get("confidence", 0),
            url=tech.get("url"),
        )

    return f"""
    <div class="technique-list">
        {technique_items}
    </div>
    """


def create_incident_card(
    incident_id: str,
    similarity: float,
    incident_type: str,
    score: float,
    date: str,
) -> str:
    """
    Creates a similar incident card

    Args:
        incident_id: Incident ID
        similarity: Similarity percentage
        incident_type: Type of incident
        score: Threat score
        date: Date string

    Returns:
        HTML string for incident card
    """
    similarity_pct = min(100, max(0, int(similarity)))

    return f"""
    <div class="incident-card">
        <div class="incident-id">{incident_id}</div>
        <div class="similarity-bar">
            <div class="bar-fill" style="--similarity: {similarity_pct}%; width: {similarity_pct}%;"></div>
        </div>
        <div class="incident-meta">
            <div>Type: {incident_type}</div>
            <div>Score: {score:.2f}</div>
            <div>{date}</div>
        </div>
    </div>
    """


def create_incident_grid(incidents: List[Dict[str, Any]]) -> str:
    """
    Creates a grid of incident cards

    Args:
        incidents: List of incident dicts

    Returns:
        HTML string for incident grid
    """
    incident_cards = ""
    for inc in incidents:
        incident_cards += create_incident_card(
            incident_id=inc.get("id", ""),
            similarity=inc.get("similarity", 0),
            incident_type=inc.get("type", ""),
            score=inc.get("score", 0),
            date=inc.get("date", ""),
        )

    return f"""
    <div class="incident-grid">
        {incident_cards}
    </div>
    """


def create_stream_message(
    agent: str,
    text: str,
    tool: Optional[str] = None,
    is_streaming: bool = False,
) -> str:
    """
    Creates a reasoning stream message

    Args:
        agent: Agent name
        text: Message text
        tool: Optional tool being called
        is_streaming: Show typing cursor

    Returns:
        HTML string for stream message
    """
    agent_lower = agent.lower()
    cursor = '<span class="typing-cursor">▌</span>' if is_streaming else ""

    tool_html = ""
    if tool:
        tool_html = f"""
        <span class="tool-chip">
            <span class="tool-icon">🔧</span>
            {tool}
        </span>
        """

    return f"""
    <div class="stream-message">
        <span class="agent-badge {agent_lower}">{agent.upper()}</span>
        {tool_html}
        <span class="message-text">{text}{cursor}</span>
    </div>
    """


def create_empty_state(
    icon: str,
    title: str,
    description: str,
) -> str:
    """
    Creates an empty state placeholder

    Args:
        icon: Emoji icon
        title: Title text
        description: Description text

    Returns:
        HTML string for empty state
    """
    return f"""
    <div class="empty-state" style="text-align: center; padding: 40px 20px; color: var(--text-secondary);">
        <div style="font-size: 48px; margin-bottom: 16px; opacity: 0.5;">{icon}</div>
        <div style="font-size: 16px; font-weight: 500; color: var(--text-primary); margin-bottom: 8px;">{title}</div>
        <div style="font-size: 14px; color: var(--text-tertiary);">{description}</div>
    </div>
    """
