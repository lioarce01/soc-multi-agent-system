"""
Formatting Helper Functions
Data transformation and error formatting utilities
"""

from typing import Dict, Any
from ui.helpers.html import sanitize_html


def build_enrichment_data(source_state: Dict[str, Any]) -> Dict[str, Any]:
    """
    Build enrichment data with intelligent fallbacks

    If external threat intel (VirusTotal/AbuseIPDB) returns no data,
    falls back to the calculated threat score from the analysis.

    Args:
        source_state: State dictionary with enrichment_data and threat_score

    Returns:
        Processed enrichment data dictionary
    """
    enrichment = source_state.get("enrichment_data", {})
    threat_intel = enrichment.get("threat_intel", {})

    # Get raw values from external threat intel
    raw_reputation = threat_intel.get("ip_reputation") or threat_intel.get("reputation", "")
    raw_score = threat_intel.get("threat_score", 0)
    raw_source = threat_intel.get("source", "")
    raw_malicious = threat_intel.get("malicious_count", 0)
    raw_scanners = threat_intel.get("total_scanners", 0)
    siem_logs = enrichment.get("siem_logs", [])

    # Get calculated threat score from analysis
    calculated_score = source_state.get("threat_score", 0.0)

    # Determine if we have valid external intel
    has_external_intel = (
        raw_reputation and
        raw_reputation.lower() not in ["unknown", "none", ""] and
        raw_source and
        raw_source.lower() not in ["mock", "none", ""]
    )

    if has_external_intel:
        # Use external threat intel data
        ip_reputation = raw_reputation
        threat_score_intel = raw_score
        intel_source = raw_source
        malicious_detections = raw_malicious
        total_scanners = raw_scanners
    else:
        # Fallback to calculated values from analysis
        # Convert threat_score (0-1) to reputation label and 0-10 scale
        if calculated_score >= 0.7:
            ip_reputation = "HIGH RISK"
        elif calculated_score >= 0.4:
            ip_reputation = "MEDIUM"
        else:
            ip_reputation = "LOW"

        threat_score_intel = round(calculated_score * 10, 1)  # Convert to 0-10 scale
        intel_source = "Analysis"
        malicious_detections = int(calculated_score * 10)  # Approximate
        total_scanners = 10

    return {
        "siem_logs_count": len(siem_logs),
        "ip_reputation": sanitize_html(ip_reputation),
        "threat_score_intel": threat_score_intel,
        "threat_intel_source": sanitize_html(intel_source),
        "malicious_detections": malicious_detections,
        "total_scanners": total_scanners,
    }


def format_activity_log(timestamp: str, node: str, message: str, emoji: str = "🔄") -> str:
    """
    Format a single activity log entry

    Args:
        timestamp: Time of the event
        node: Node name (padded to 15 chars)
        message: Log message
        emoji: Optional emoji prefix

    Returns:
        Formatted log line
    """
    return f"[{timestamp}] {emoji} {node:15s} -> {message}"


def format_error_html(title: str, message: str, traceback: str = "") -> str:
    """
    Format error as HTML (XSS-safe)

    Args:
        title: Error title
        message: Error description
        traceback: Optional traceback string

    Returns:
        HTML formatted error display
    """
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
