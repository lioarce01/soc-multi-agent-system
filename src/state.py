"""
LangGraph State Definition for SOC Orchestrator
Defines the central state shared across all agents
"""

from typing import TypedDict, Annotated, List, Optional, Any
from langgraph.graph.message import add_messages
from datetime import datetime


class SecurityAgentState(TypedDict):
    """
    Central state for security alert investigation workflow

    This state is passed between all agents and contains all data
    needed for alert investigation, analysis, and response.
    """

    # ===== Message History =====
    # Uses add_messages reducer to append new messages to the list
    messages: Annotated[list, add_messages]

    # ===== Alert Data (Input) =====
    alert_data: dict  # Raw alert from user
    # Example: {
    #   "id": "ALT-2024-001",
    #   "type": "phishing",
    #   "source_ip": "45.76.123.45",
    #   "description": "...",
    #   "timestamp": "2024-01-15T14:30:00Z"
    # }

    alert_id: str  # Unique alert identifier
    timestamp: str  # Alert timestamp

    # ===== Context Enrichment Phase =====
    enrichment_data: dict  # Data gathered from SIEM, EDR, threat intel
    # Example: {
    #   "siem_logs": [...],
    #   "threat_intel": {...},
    #   "endpoint_data": {...}
    # }

    # ===== Analysis Phase =====
    mitre_mappings: List[dict]  # MITRE ATT&CK techniques matched
    # Example: [
    #   {
    #     "technique_id": "T1566.001",
    #     "name": "Phishing: Spearphishing Attachment",
    #     "confidence": 0.92
    #   }
    # ]

    threat_score: float  # Calculated threat probability (0.0 - 1.0)
    attack_stage: str  # MITRE tactic (e.g., "Initial Access", "Persistence")
    threat_category: str  # High-level category (e.g., "Credential Theft")
    analysis_reasoning: str  # NEW: LLM explanation of threat analysis

    # ===== Investigation Phase (Optional) =====
    investigation_plan: List[str]  # Generated investigation steps
    investigation_findings: dict  # Results from deep investigation
    investigation_reasoning: str  # NEW: LLM explanation of investigation plan and findings

    # ===== Response Phase =====
    recommendations: List[str]  # Remediation recommendations
    remediation_playbook: dict  # Detailed response actions
    response_reasoning: str  # NEW: LLM explanation of recommendations

    # ===== Communication Phase =====
    report: str  # Human-readable investigation report
    notifications_sent: List[dict]  # Track sent notifications

    # ===== Metadata & Control Flow =====
    current_agent: str  # Which agent is currently processing
    workflow_status: str  # "in_progress", "completed", "failed"
    error: Optional[str]  # Error message if workflow fails

    # ===== Additional Context =====
    session_id: str  # Session identifier for tracking
    created_at: str  # When investigation started
    completed_at: Optional[str]  # When investigation finished

    # ===== Memory & Context Engineering =====
    similar_incidents: List[dict]  # Similar past incidents found in memory
    # Example: [
    #   {
    #     "incident_id": "ALT-2024-089",
    #     "similarity_score": 0.87,
    #     "alert_type": "phishing",
    #     "threat_score": 0.82,
    #     "summary": "..."
    #   }
    # ]

    memory_reasoning: str  # LLM explanation of why incidents are similar
    # Example: "I found 2 highly similar incidents because they share the same
    # sender domain and MITRE technique T1566. This pattern suggests a repeated
    # attack campaign targeting the same vulnerability."

    campaign_info: Optional[dict]  # Campaign detection results
    # Example: {
    #   "campaign_id": "CAMPAIGN-A7B3C2F1",
    #   "confidence": 0.82,
    #   "related_incidents": ["ALT-001", "ALT-002", "ALT-003"],
    #   "incident_count": 3,
    #   "threat_assessment": "ONGOING_CAMPAIGN"
    # }

    context_compacted: bool  # Flag indicating if message context was compacted


# Type alias for easier imports
State = SecurityAgentState


def create_initial_state(alert_data: dict) -> SecurityAgentState:
    """
    Create initial state from alert data

    Args:
        alert_data: Raw alert dictionary

    Returns:
        Initialized SecurityAgentState with default values
    """
    now = datetime.utcnow().isoformat()

    return {
        # Messages
        "messages": [],

        # Alert data
        "alert_data": alert_data,
        "alert_id": alert_data.get("id", f"ALT-{now}"),
        "timestamp": alert_data.get("timestamp", now),

        # Enrichment
        "enrichment_data": {},

        # Analysis
        "mitre_mappings": [],
        "threat_score": 0.0,
        "attack_stage": "",
        "threat_category": "",
        "analysis_reasoning": "",  # NEW

        # Investigation
        "investigation_plan": [],
        "investigation_findings": {},
        "investigation_reasoning": "",  # NEW

        # Response
        "recommendations": [],
        "remediation_playbook": {},
        "response_reasoning": "",  # NEW

        # Communication
        "report": "",
        "notifications_sent": [],

        # Metadata
        "current_agent": "supervisor",
        "workflow_status": "in_progress",
        "error": None,
        "session_id": f"session-{now}",
        "created_at": now,
        "completed_at": None,

        # Memory
        "similar_incidents": [],
        "memory_reasoning": "",
        "campaign_info": None,
        "context_compacted": False
    }


def get_state_summary(state: SecurityAgentState) -> dict:
    """
    Get a summary of current state for logging/debugging

    Args:
        state: Current state

    Returns:
        Summary dictionary with key metrics
    """
    return {
        "alert_id": state.get("alert_id", "unknown"),
        "current_agent": state.get("current_agent", "unknown"),
        "workflow_status": state.get("workflow_status", "unknown"),
        "threat_score": state.get("threat_score", 0.0),
        "mitre_techniques_found": len(state.get("mitre_mappings", [])),
        "has_enrichment_data": bool(state.get("enrichment_data", {})),
        "has_recommendations": bool(state.get("recommendations", [])),
        "similar_incidents_found": len(state.get("similar_incidents", [])),
        "campaign_detected": bool(state.get("campaign_info")),
        "context_compacted": state.get("context_compacted", False)
    }
