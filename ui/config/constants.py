"""
UI Constants
Colors, sizing, and other constant values
"""

# Severity color mapping
SEVERITY_COLORS = {
    "CRITICAL": {"bg": "#7f1d1d", "border": "#dc2626", "text": "#fca5a5"},
    "HIGH": {"bg": "#7c2d12", "border": "#ea580c", "text": "#fdba74"},
    "MEDIUM": {"bg": "#713f12", "border": "#ca8a04", "text": "#fde047"},
    "LOW": {"bg": "#14532d", "border": "#16a34a", "text": "#86efac"},
}

# Base color palette
COLORS = {
    # Backgrounds
    "bg_primary": "#000000",
    "bg_secondary": "#0a0a0a",
    "bg_card": "#111111",
    "bg_hover": "#1a1a1a",

    # Borders
    "border_subtle": "#1a1a1a",
    "border_default": "#333333",
    "border_accent": "#444444",

    # Text
    "text_primary": "#e8e8e8",
    "text_secondary": "#999999",
    "text_muted": "#666666",

    # Accents
    "accent_blue": "#3b82f6",
    "accent_green": "#10b981",
    "accent_amber": "#f59e0b",
    "accent_red": "#ef4444",
    "accent_purple": "#8b5cf6",
    "accent_cyan": "#06b6d4",
    "accent_pink": "#ec4899",

    # Status
    "success": "#10b981",
    "warning": "#f59e0b",
    "error": "#ef4444",
    "info": "#3b82f6",
}


def get_severity_color(threat_score: float) -> dict:
    """Get severity colors based on threat score"""
    if threat_score >= 0.85:
        return SEVERITY_COLORS["CRITICAL"]
    elif threat_score >= 0.65:
        return SEVERITY_COLORS["HIGH"]
    elif threat_score >= 0.45:
        return SEVERITY_COLORS["MEDIUM"]
    else:
        return SEVERITY_COLORS["LOW"]


def get_severity_label(threat_score: float) -> str:
    """Get severity label based on threat score"""
    if threat_score >= 0.85:
        return "CRITICAL"
    elif threat_score >= 0.65:
        return "HIGH"
    elif threat_score >= 0.45:
        return "MEDIUM"
    else:
        return "LOW"
