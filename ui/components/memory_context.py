"""
Memory Context Components
Similar incidents and campaign detection display
"""

from typing import Dict, List, Optional


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
