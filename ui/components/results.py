"""
Results Component
Investigation results display with threat score, MITRE mappings, and recommendations
Enhanced with animations for visual impact
"""

from typing import Dict, Any
import html as html_lib


def format_results_html(result: Dict[str, Any]) -> str:
    """
    Format investigation results as structured HTML (XSS-safe)
    With animated threat score and enhanced visual effects

    Args:
        result: Investigation results dictionary (already sanitized)

    Returns:
        HTML formatted results
    """
    threat_score = result.get("threat_score", 0.0)
    threat_score_pct = int(threat_score * 100)

    # Determine threat level colors and animations
    if threat_score >= 0.90:
        threat_color = "#ef4444"  # red
        threat_glow = "0 0 20px rgba(239, 68, 68, 0.5)"
        threat_label = "CRITICAL"
        threat_animation = "animation: threat-critical 1s ease-in-out infinite;"
        shake_class = "animate-shake"
    elif threat_score >= 0.70:
        threat_color = "#f97316"  # orange
        threat_glow = "0 0 20px rgba(249, 115, 22, 0.5)"
        threat_label = "HIGH"
        threat_animation = "animation: threat-high 2s ease-in-out infinite;"
        shake_class = ""
    elif threat_score >= 0.50:
        threat_color = "#eab308"  # yellow
        threat_glow = "0 0 20px rgba(234, 179, 8, 0.5)"
        threat_label = "MEDIUM"
        threat_animation = "animation: threat-medium 2.5s ease-in-out infinite;"
        shake_class = ""
    else:
        threat_color = "#10b981"  # green for low (changed from white)
        threat_glow = "0 0 20px rgba(16, 185, 129, 0.4)"
        threat_label = "LOW"
        threat_animation = "animation: threat-low 3s ease-in-out infinite;"
        shake_class = ""

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

    # Note: JavaScript animations don't work in Gradio's dynamic HTML
    # Using CSS-only animations for threat score display
    html_result = f"""
    <style>
        /* Threat level animations */
        @keyframes threat-low {{
            0%, 100% {{ box-shadow: inset 0 0 40px rgba(0, 0, 0, 0.8), 0 0 10px rgba(16, 185, 129, 0.3); }}
            50% {{ box-shadow: inset 0 0 40px rgba(0, 0, 0, 0.8), 0 0 20px rgba(16, 185, 129, 0.5); }}
        }}
        @keyframes threat-medium {{
            0%, 100% {{ box-shadow: inset 0 0 40px rgba(0, 0, 0, 0.8), 0 0 10px rgba(234, 179, 8, 0.3); }}
            50% {{ box-shadow: inset 0 0 40px rgba(0, 0, 0, 0.8), 0 0 25px rgba(234, 179, 8, 0.6); }}
        }}
        @keyframes threat-high {{
            0%, 100% {{ box-shadow: inset 0 0 40px rgba(0, 0, 0, 0.8), 0 0 15px rgba(249, 115, 22, 0.4); }}
            50% {{ box-shadow: inset 0 0 40px rgba(0, 0, 0, 0.8), 0 0 30px rgba(249, 115, 22, 0.7); }}
        }}
        @keyframes threat-critical {{
            0%, 100% {{
                box-shadow: inset 0 0 40px rgba(0, 0, 0, 0.8), 0 0 20px rgba(239, 68, 68, 0.5);
                transform: scale(1);
            }}
            50% {{
                box-shadow: inset 0 0 40px rgba(0, 0, 0, 0.8), 0 0 40px rgba(239, 68, 68, 0.8);
                transform: scale(1.01);
            }}
        }}
        @keyframes fadeInScale {{
            from {{ transform: scale(0.8); opacity: 0; }}
            to {{ transform: scale(1); opacity: 1; }}
        }}
        @keyframes shake {{
            0%, 100% {{ transform: translateX(0); }}
            10%, 30%, 50%, 70%, 90% {{ transform: translateX(-2px); }}
            20%, 40%, 60%, 80% {{ transform: translateX(2px); }}
        }}
        .animate-shake {{ animation: shake 0.5s ease-in-out; }}
        @keyframes scoreReveal {{
            from {{ opacity: 0; transform: scale(0.8); }}
            to {{ opacity: 1; transform: scale(1); }}
        }}
    </style>
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

        <!-- Threat Score Card with Animation -->
        <div class="{shake_class}" style="background: linear-gradient(135deg, #0a0a0a 0%, #000 100%);
                    border: 1px solid {threat_color}; border-radius: 0; padding: 24px; margin: 0;
                    box-shadow: inset 0 0 40px rgba(0, 0, 0, 0.8), {threat_glow};
                    {threat_animation}">
            <div style="display: flex; align-items: center; justify-content: space-between;">
                <div>
                    <div style="color: #71717a; font-size: 0.75rem; font-weight: 700; margin-bottom: 8px; font-family: 'Courier New', monospace; letter-spacing: 0.1em;">THREAT_SCORE</div>
                    <div style="font-size: 3.5rem; font-weight: 700; color: {threat_color}; font-family: 'Courier New', monospace; text-shadow: {threat_glow}; animation: scoreReveal 0.6s ease-out forwards;">
                        {threat_score_pct}<span style="font-size: 1.5rem;">%</span>
                    </div>
                    <div style="color: #71717a; font-size: 0.8rem; margin-top: 8px; font-family: 'Courier New', monospace;">
                        > STAGE: <span style="color: #a1a1aa;">{result.get('attack_stage', 'Unknown').upper()}</span>
                    </div>
                </div>
                <div style="text-align: right;">
                    <div style="background-color: {threat_color}; color: #000;
                                padding: 10px 24px; border-radius: 2px; font-size: 1.1rem; font-weight: 900; margin-bottom: 10px;
                                font-family: 'Courier New', monospace; letter-spacing: 0.1em; box-shadow: {threat_glow};
                                animation: fadeInScale 0.5s ease-out forwards;">
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
