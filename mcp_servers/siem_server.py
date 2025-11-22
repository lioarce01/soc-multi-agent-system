"""
SIEM MCP Server - Mock Security Information and Event Management
Provides security event query tools via MCP protocol (streamable_http)
"""

import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

# Load environment variables from .env
from dotenv import load_dotenv
load_dotenv(Path(__file__).parent.parent / ".env")

from fastmcp import FastMCP
from typing import Dict, List, Optional
from datetime import datetime

from mcp_servers.mock_data import (
    query_siem_events,
    get_ip_reputation,
    get_user_activity,
    search_events_by_query,
    MOCK_SIEM_EVENTS,
    IP_REPUTATION_DB
)

# Try to import real threat intelligence integrations
import os

# Check which providers are configured
USE_VIRUSTOTAL = os.getenv("VIRUSTOTAL_API_KEY") is not None
USE_ABUSEIPDB = os.getenv("ABUSEIPDB_API_KEY") is not None

threat_intel_providers = []

# Initialize VirusTotal if configured
if USE_VIRUSTOTAL:
    try:
        from mcp_servers.integrations.virustotal_integration import get_virustotal_client
        virustotal = get_virustotal_client()
        threat_intel_providers.append(("VirusTotal", virustotal))
        print("✅ VirusTotal integration enabled")
    except Exception as e:
        print(f"⚠️  Failed to initialize VirusTotal: {e}")

# Initialize AbuseIPDB if configured
if USE_ABUSEIPDB:
    try:
        from mcp_servers.integrations.abuseipdb_integration import get_abuseipdb_client
        abuseipdb = get_abuseipdb_client()
        threat_intel_providers.append(("AbuseIPDB", abuseipdb))
        print("✅ AbuseIPDB integration enabled")
    except Exception as e:
        print(f"⚠️  Failed to initialize AbuseIPDB: {e}")

# Display status
print("=" * 60)
if threat_intel_providers:
    print(f"🌐 REAL THREAT INTEL ENABLED ({len(threat_intel_providers)} providers)")
    for name, _ in threat_intel_providers:
        print(f"   - {name}")
else:
    print("📝 USING MOCK THREAT INTEL")
    print("Set VIRUSTOTAL_API_KEY or ABUSEIPDB_API_KEY to use real data")
    print("  - VirusTotal: https://virustotal.com")
    print("  - AbuseIPDB: https://abuseipdb.com")
print("=" * 60)


# ===== Helper Functions for Multi-Provider Intelligence =====

def aggregate_threat_intel(results: List[Dict]) -> Dict:
    """
    Aggregate threat intelligence from multiple providers

    Args:
        results: List of threat intel results from different providers

    Returns:
        Aggregated threat intelligence data
    """
    if not results:
        return {
            "reputation": "unknown",
            "threat_score": 0,
            "source": "none",
            "error": "No threat intel providers returned data"
        }

    # Filter out error results
    valid_results = [r for r in results if r.get("reputation") != "unknown" and not r.get("error")]

    if not valid_results:
        # All providers failed, return first error
        return results[0]

    # Aggregate reputation (take worst case)
    reputations = [r.get("reputation") for r in valid_results]
    if "malicious" in reputations:
        aggregated_reputation = "malicious"
    elif "suspicious" in reputations:
        aggregated_reputation = "suspicious"
    else:
        aggregated_reputation = "clean"

    # Average threat scores
    threat_scores = [r.get("threat_score", 0) for r in valid_results]
    avg_threat_score = sum(threat_scores) / len(threat_scores) if threat_scores else 0

    # Sum malicious counts
    total_malicious = sum(r.get("malicious_count", 0) for r in valid_results)

    # Sum total scanners
    total_scanners = sum(r.get("total_scanners", 0) for r in valid_results)

    # Collect all sources
    sources = [r.get("source") for r in valid_results if r.get("source")]

    # Merge categories
    all_categories = []
    for r in valid_results:
        all_categories.extend(r.get("categories", []))
    unique_categories = list(set(all_categories))

    # Get IP from first result
    ip_address = valid_results[0].get("ip_address")

    return {
        "ip_address": ip_address,
        "reputation": aggregated_reputation,
        "threat_score": round(avg_threat_score, 1),
        "malicious_count": total_malicious,
        "total_scanners": total_scanners,
        "categories": unique_categories,
        "source": " + ".join(sources),  # e.g., "VirusTotal + AbuseIPDB"
        "provider_count": len(valid_results),
        "provider_details": valid_results  # Keep individual results for debugging
    }


# ===== Initialize FastMCP Server =====

mcp_server = FastMCP(
    name="SIEM MCP Server",
    version="1.0.0",
)


# ===== MCP Tools =====

@mcp_server.tool(
    description="Query SIEM (Security Information and Event Management) for security events with filters. Use when you need to search for security events, logs, or incidents. Supports filtering by source IP, destination IP, event type (e.g., failed_login, email_received), username, and time range. Returns list of matching security events with details."
)
async def query_siem(
    source_ip: Optional[str] = None,
    destination_ip: Optional[str] = None,
    event_type: Optional[str] = None,
    user: Optional[str] = None,
    time_range: str = "last_24h",
    limit: int = 100
) -> Dict:
    """
    Query SIEM for security events with filters

    Args:
        source_ip: Filter by source IP address (e.g., "45.76.123.45")
        destination_ip: Filter by destination IP address
        event_type: Filter by event type (e.g., "failed_login", "email_received")
        user: Filter by username (e.g., "john.doe@company.com")
        time_range: Time window (last_1h, last_24h, last_7d)
        limit: Maximum number of events to return

    Returns:
        Dictionary with events list and count
    """
    events = query_siem_events(
        source_ip=source_ip,
        destination_ip=destination_ip,
        event_type=event_type,
        user=user,
        time_range=time_range,
        limit=limit
    )

    return {
        "events": events,
        "count": len(events),
        "time_range": time_range,
        "filters_applied": {
            "source_ip": source_ip,
            "destination_ip": destination_ip,
            "event_type": event_type,
            "user": user
        }
    }


@mcp_server.tool(
    description="Get threat intelligence and reputation data for an IP address from multiple providers. Use when you need to check if an IP address is malicious, suspicious, or has a bad reputation. Returns aggregated threat intelligence including reputation (malicious/suspicious/clean/unknown), threat score, categories, and recommendations. Works with public IP addresses."
)
async def get_threat_intel(ip_address: str) -> Dict:
    """
    Get threat intelligence for an IP address from multiple providers

    Args:
        ip_address: IP address to look up (e.g., "45.76.123.45")

    Returns:
        Aggregated threat intelligence from all configured providers
    """
    # Query all configured threat intel providers
    if threat_intel_providers:
        results = []
        for provider_name, provider in threat_intel_providers:
            try:
                print(f"  [Threat Intel] Querying {provider_name}...")
                result = provider.get_ip_reputation(ip_address)
                results.append(result)
            except Exception as e:
                print(f"  [Threat Intel] {provider_name} failed: {e}")
                results.append({
                    "ip_address": ip_address,
                    "reputation": "unknown",
                    "threat_score": 0,
                    "error": str(e),
                    "source": provider_name
                })

        # Aggregate results from all providers
        aggregated = aggregate_threat_intel(results)

        return {
            "ip_address": ip_address,
            "reputation": aggregated.get("reputation", "unknown"),
            "confidence": 0.9 if aggregated.get("reputation") == "malicious" else 0.5,
            "categories": aggregated.get("categories", []),
            "threat_score": aggregated.get("threat_score", 0),
            "source": aggregated.get("source", "unknown"),
            "malicious_count": aggregated.get("malicious_count", 0),
            "total_scanners": aggregated.get("total_scanners", 0),
            "provider_count": aggregated.get("provider_count", 0),
            "recommendation": _get_ip_recommendation(aggregated)
        }
    else:
        # Fall back to mock data
        reputation_data = get_ip_reputation(ip_address)

        # Convert sources array to source string (mock data uses "sources" plural)
        sources = reputation_data.get("sources", [])
        source_str = " + ".join(sources) if sources else "mock"

        return {
            "ip_address": ip_address,
            "reputation": reputation_data.get("reputation", "unknown"),
            "confidence": reputation_data.get("confidence", 0.5),
            "categories": reputation_data.get("categories", []),
            "threat_score": reputation_data.get("threat_score", 5.0),
            "last_seen": reputation_data.get("last_seen"),
            "source": source_str,
            "malicious_count": reputation_data.get("malicious_count", 0),
            "total_scanners": reputation_data.get("total_scanners", 0),
            "recommendation": _get_ip_recommendation(reputation_data)
        }


@mcp_server.tool(
    description="Get all security events and activity history for a specific user. Use when you need to analyze user behavior, check user activity patterns, or investigate user-related security incidents. Returns user activity summary including total events, event types, unique IPs, last activity timestamp, suspicious activity count, and risk level."
)
async def get_user_events(username: str, time_range: str = "last_7d") -> Dict:
    """
    Get all security events for a specific user

    Args:
        username: Username to look up (e.g., "john.doe@company.com")
        time_range: Time window (last_1h, last_24h, last_7d)

    Returns:
        User activity summary including event count, types, IPs, and suspicious activity
    """
    activity = get_user_activity(username, time_range)

    return {
        "username": username,
        "time_range": time_range,
        "total_events": activity.get("total_events", 0),
        "event_types": activity.get("event_types", []),
        "unique_ips": activity.get("unique_ips", []),
        "last_activity": activity.get("last_activity"),
        "suspicious_activity_count": activity.get("suspicious_activity_count", 0),
        "risk_level": _calculate_user_risk(activity)
    }


@mcp_server.tool(
    description="Search SIEM logs with a query string. Use when you need to search for specific security events using field:value format (e.g., 'source_ip:45.76.123.45', 'user:john.doe@company.com'). Returns matching security events based on the search query."
)
async def search_siem_logs(query: str, limit: int = 50) -> Dict:
    """
    Search SIEM logs with a query string

    Args:
        query: Search query in format "field:value" (e.g., "source_ip:45.76.123.45", "user:john.doe@company.com")
        limit: Maximum events to return

    Returns:
        Matching security events
    """
    events = search_events_by_query(query, limit)

    return {
        "query": query,
        "events": events,
        "count": len(events),
        "limit": limit
    }


@mcp_server.tool(
    description="Find security events related to a specific event based on correlation fields (e.g., source_ip, user). Use when you need to find related incidents, correlate events, or discover patterns. Returns related events and correlation summary within a time window."
)
async def get_related_events(
    event_id: str,
    correlation_fields: List[str] = None,
    time_window_minutes: int = 60
) -> Dict:
    """
    Find events related to a specific event based on correlation fields

    Args:
        event_id: Event ID to find related events for (e.g., "evt-001")
        correlation_fields: Fields to correlate on (default: ["source_ip", "user"])
        time_window_minutes: Time window to search (default: 60 minutes)

    Returns:
        Related events and correlation summary
    """
    if correlation_fields is None:
        correlation_fields = ["source_ip", "user"]

    # Find the original event
    original_event = None
    for event in MOCK_SIEM_EVENTS:
        if event["id"] == event_id:
            original_event = event
            break

    if not original_event:
        return {
            "error": f"Event {event_id} not found",
            "related_events": [],
            "count": 0
        }

    # Find related events
    related_events = []
    for event in MOCK_SIEM_EVENTS:
        if event["id"] == event_id:
            continue  # Skip the original event

        # Check if any correlation field matches
        is_related = False
        for field in correlation_fields:
            if field in original_event and field in event:
                if original_event[field] == event[field]:
                    is_related = True
                    break

        if is_related:
            related_events.append(event)

    return {
        "original_event_id": event_id,
        "correlation_fields": correlation_fields,
        "time_window_minutes": time_window_minutes,
        "related_events": related_events,
        "count": len(related_events),
        "correlation_summary": _build_correlation_summary(original_event, related_events)
    }


@mcp_server.tool(
    description="Get endpoint security data from EDR (Endpoint Detection and Response) system. Use when you need to check endpoint status, running processes, network connections, security tools status, or threats detected on a specific hostname. Returns comprehensive endpoint security information including processes, network connections, and security tool status."
)
async def get_endpoint_data(hostname: str) -> Dict:
    """
    Get endpoint security data (simulated EDR integration)

    Args:
        hostname: Hostname to query (e.g., "WS-015")

    Returns:
        Endpoint security information including running processes, network connections, and security status
    """
    # Simulate endpoint data
    endpoint_data = {
        "hostname": hostname,
        "last_seen": datetime.utcnow().isoformat(),
        "operating_system": "Windows 10 Enterprise",
        "ip_address": "192.168.1.55",
        "running_processes": [
            {"name": "explorer.exe", "pid": 1234, "suspicious": False},
            {"name": "chrome.exe", "pid": 5678, "suspicious": False},
            {"name": "cryptominer.exe", "pid": 9999, "suspicious": True}
        ],
        "network_connections": [
            {
                "remote_ip": "192.0.2.1",
                "remote_port": 8080,
                "protocol": "TCP",
                "state": "ESTABLISHED",
                "suspicious": True
            }
        ],
        "security_tools": {
            "antivirus": {"enabled": True, "up_to_date": True},
            "firewall": {"enabled": True},
            "edr_agent": {"enabled": True, "version": "1.2.3"}
        },
        "threats_detected": 1,
        "last_scan": "2024-01-15T16:00:00Z"
    }

    return endpoint_data


@mcp_server.tool(
    description="Get aggregated alert and event statistics. Use when you need summary metrics, counts by severity or type, trends, or overall statistics about security alerts and events. Returns aggregated statistics including total events, counts by severity, counts by event type, unique IPs, and unique users."
)
async def get_alert_statistics(time_range: str = "last_24h") -> Dict:
    """
    Get aggregated alert statistics

    Args:
        time_range: Time window (last_1h, last_24h, last_7d)

    Returns:
        Statistics about alerts including counts by severity, type, and trends
    """
    # Count events by severity
    severity_counts = {}
    event_type_counts = {}

    for event in MOCK_SIEM_EVENTS:
        severity = event.get("severity", "unknown")
        event_type = event.get("event_type", "unknown")

        severity_counts[severity] = severity_counts.get(severity, 0) + 1
        event_type_counts[event_type] = event_type_counts.get(event_type, 0) + 1

    return {
        "time_range": time_range,
        "total_events": len(MOCK_SIEM_EVENTS),
        "by_severity": severity_counts,
        "by_event_type": event_type_counts,
        "unique_source_ips": len(set(e.get("source_ip") for e in MOCK_SIEM_EVENTS if e.get("source_ip"))),
        "unique_users": len(set(e.get("user") for e in MOCK_SIEM_EVENTS if e.get("user"))),
        "malicious_ips_detected": sum(1 for ip in IP_REPUTATION_DB.values() if ip.get("reputation") == "malicious")
    }


# ===== Helper Functions =====

def _get_ip_recommendation(reputation_data: Dict) -> str:
    """Generate recommendation based on IP reputation"""
    reputation = reputation_data.get("reputation", "unknown")
    threat_score = reputation_data.get("threat_score", 5.0)

    if reputation == "malicious" and threat_score >= 9.0:
        return "IMMEDIATE ACTION: Block this IP at firewall immediately. Known malicious actor."
    elif reputation == "malicious":
        return "HIGH PRIORITY: Investigate and consider blocking this IP. Known threat actor."
    elif reputation == "suspicious":
        return "MONITOR: Add to watchlist and monitor for suspicious activity."
    elif reputation == "clean":
        return "No action required. IP has clean reputation."
    else:
        return "INVESTIGATE: Unknown IP. Gather more intelligence before making decision."


def _calculate_user_risk(activity: Dict) -> str:
    """Calculate user risk level based on activity"""
    suspicious_count = activity.get("suspicious_activity_count", 0)
    total_events = activity.get("total_events", 0)

    if suspicious_count == 0:
        return "low"
    elif suspicious_count >= 3:
        return "critical"
    elif suspicious_count >= 2:
        return "high"
    else:
        return "medium"


def _build_correlation_summary(original_event: Dict, related_events: List[Dict]) -> Dict:
    """Build summary of correlation findings"""
    if not related_events:
        return {"message": "No related events found"}

    # Analyze related events
    same_source_ip = sum(1 for e in related_events if e.get("source_ip") == original_event.get("source_ip"))
    same_user = sum(1 for e in related_events if e.get("user") == original_event.get("user"))
    high_severity = sum(1 for e in related_events if e.get("severity") in ["high", "critical"])

    return {
        "total_related": len(related_events),
        "same_source_ip": same_source_ip,
        "same_user": same_user,
        "high_severity_count": high_severity,
        "assessment": "Possible attack campaign" if len(related_events) >= 3 else "Isolated incident pattern"
    }


# ===== Health Check Endpoint =====

@mcp_server.tool()
async def health_check() -> Dict:
    """
    Health check endpoint for SIEM server

    Returns:
        Server status and statistics
    """
    return {
        "status": "healthy",
        "server": "SIEM MCP Server",
        "version": "1.0.0",
        "transport": "streamable_http",
        "total_events": len(MOCK_SIEM_EVENTS),
        "total_known_ips": len(IP_REPUTATION_DB),
        "timestamp": datetime.utcnow().isoformat()
    }


# ===== Run Server =====

if __name__ == "__main__":
    print("="*60)
    print("SIEM MCP Server")
    print("="*60)
    print(f"Transport: HTTP")
    print(f"Host: 0.0.0.0")
    print(f"Port: 8001")
    print(f"Available Tools:")
    print("  - query_siem()")
    print("  - get_threat_intel()")
    print("  - get_user_events()")
    print("  - search_siem_logs()")
    print("  - get_related_events()")
    print("  - get_endpoint_data()")
    print("  - get_alert_statistics()")
    print("  - health_check()")
    print("="*60)
    print("\nStarting server on http://0.0.0.0:8001...")

    # Run with HTTP transport
    mcp_server.run(transport="http", host="0.0.0.0", port=8001)
