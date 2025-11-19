"""
Mock SIEM data for testing and development
Provides realistic security event data without a real SIEM
"""

from datetime import datetime, timedelta
from typing import List, Dict


# Mock SIEM event database
MOCK_SIEM_EVENTS = [
    # Phishing-related events
    {
        "id": "evt-001",
        "timestamp": "2024-01-15T14:25:00Z",
        "source_ip": "45.76.123.45",
        "destination_ip": "192.168.1.100",
        "event_type": "email_received",
        "severity": "medium",
        "user": "john.doe@company.com",
        "subject": "Invoice #12345",
        "attachment": "invoice.exe",
        "sender": "external@malicious-domain.com",
        "spf_result": "fail",
        "dkim_result": "fail"
    },
    {
        "id": "evt-002",
        "timestamp": "2024-01-15T14:30:00Z",
        "source_ip": "192.168.1.100",
        "destination_ip": "45.76.123.45",
        "event_type": "file_downloaded",
        "severity": "high",
        "user": "john.doe@company.com",
        "filename": "invoice.exe",
        "file_hash": "d41d8cd98f00b204e9800998ecf8427e",
        "file_size": 245760
    },

    # Brute force attack events
    {
        "id": "evt-101",
        "timestamp": "2024-01-15T15:40:00Z",
        "source_ip": "185.220.101.1",
        "destination_ip": "192.168.1.10",
        "event_type": "failed_login",
        "severity": "high",
        "user": "admin",
        "protocol": "SSH",
        "port": 22,
        "attempts": 15,
        "time_window": "5 minutes"
    },
    {
        "id": "evt-102",
        "timestamp": "2024-01-15T15:42:00Z",
        "source_ip": "185.220.101.1",
        "destination_ip": "192.168.1.10",
        "event_type": "failed_login",
        "severity": "high",
        "user": "root",
        "protocol": "SSH",
        "port": 22,
        "attempts": 10,
        "time_window": "3 minutes"
    },

    # Malware/C2 communication
    {
        "id": "evt-201",
        "timestamp": "2024-01-15T16:20:00Z",
        "source_ip": "192.168.1.55",
        "destination_ip": "192.0.2.1",
        "event_type": "suspicious_connection",
        "severity": "critical",
        "user": "jane.smith@company.com",
        "hostname": "WS-015",
        "process": "cryptominer.exe",
        "port": 8080,
        "protocol": "TCP",
        "bytes_sent": 1024000,
        "connection_duration": "3600 seconds"
    },

    # Data exfiltration
    {
        "id": "evt-301",
        "timestamp": "2024-01-15T17:10:00Z",
        "source_ip": "192.168.10.50",
        "destination_ip": "52.218.48.101",
        "event_type": "large_data_transfer",
        "severity": "high",
        "user": "db_service_account",
        "hostname": "DB-PROD-01",
        "bytes_transferred": 5368709120,  # 5GB
        "destination_service": "AWS S3",
        "transfer_duration": "2700 seconds",  # 45 minutes
        "time_of_day": "after_hours"
    },

    # Suspicious login
    {
        "id": "evt-401",
        "timestamp": "2024-01-15T18:00:00Z",
        "source_ip": "93.184.216.34",
        "destination_ip": "192.168.1.20",
        "event_type": "vpn_login",
        "severity": "medium",
        "user": "michael.chen@company.com",
        "geolocation": "Russia",
        "normal_location": "USA",
        "device_type": "unknown",
        "time_of_day": "3am EST"
    }
]


# IP reputation database (mock threat intelligence)
IP_REPUTATION_DB = {
    "45.76.123.45": {
        "reputation": "malicious",
        "confidence": 0.95,
        "categories": ["phishing", "spam", "malware"],
        "last_seen": "2024-01-15T12:00:00Z",
        "sources": ["VirusTotal", "AbuseIPDB"],
        "threat_score": 9.5
    },
    "185.220.101.1": {
        "reputation": "malicious",
        "confidence": 0.90,
        "categories": ["brute_force", "scanner"],
        "last_seen": "2024-01-15T10:00:00Z",
        "sources": ["AbuseIPDB", "Shodan"],
        "threat_score": 8.5
    },
    "192.0.2.1": {
        "reputation": "malicious",
        "confidence": 0.98,
        "categories": ["c2_server", "botnet"],
        "last_seen": "2024-01-15T16:00:00Z",
        "sources": ["VirusTotal", "AlienVault OTX"],
        "threat_score": 10.0
    },
    "52.218.48.101": {
        "reputation": "clean",
        "confidence": 0.85,
        "categories": ["cloud_provider"],
        "last_seen": "2024-01-15T17:00:00Z",
        "sources": ["AWS IP ranges"],
        "threat_score": 2.0
    },
    "93.184.216.34": {
        "reputation": "suspicious",
        "confidence": 0.65,
        "categories": ["proxy", "vpn"],
        "last_seen": "2024-01-15T18:00:00Z",
        "sources": ["MaxMind"],
        "threat_score": 5.5
    }
}


def query_siem_events(
    source_ip: str = None,
    destination_ip: str = None,
    event_type: str = None,
    user: str = None,
    time_range: str = "last_24h",
    limit: int = 100
) -> List[Dict]:
    """
    Query mock SIEM events with filters

    Args:
        source_ip: Filter by source IP
        destination_ip: Filter by destination IP
        event_type: Filter by event type
        user: Filter by user
        time_range: Time window (last_1h, last_24h, last_7d)
        limit: Maximum events to return

    Returns:
        List of matching events
    """
    results = MOCK_SIEM_EVENTS.copy()

    # Apply filters
    if source_ip:
        results = [e for e in results if e.get("source_ip") == source_ip]

    if destination_ip:
        results = [e for e in results if e.get("destination_ip") == destination_ip]

    if event_type:
        results = [e for e in results if e.get("event_type") == event_type]

    if user:
        results = [e for e in results if e.get("user") == user]

    # Sort by timestamp (newest first)
    results.sort(key=lambda x: x.get("timestamp", ""), reverse=True)

    return results[:limit]


def get_ip_reputation(ip_address: str) -> Dict:
    """
    Get IP reputation from mock threat intelligence database

    Args:
        ip_address: IP address to lookup

    Returns:
        Reputation information or default clean response
    """
    return IP_REPUTATION_DB.get(ip_address, {
        "reputation": "unknown",
        "confidence": 0.5,
        "categories": [],
        "last_seen": None,
        "sources": [],
        "threat_score": 5.0
    })


def get_user_activity(username: str, time_range: str = "last_7d") -> Dict:
    """
    Get user activity summary

    Args:
        username: Username to lookup
        time_range: Time window

    Returns:
        User activity summary
    """
    events = query_siem_events(user=username)

    return {
        "username": username,
        "total_events": len(events),
        "event_types": list(set(e.get("event_type") for e in events)),
        "unique_ips": list(set(e.get("source_ip") for e in events if e.get("source_ip"))),
        "last_activity": events[0].get("timestamp") if events else None,
        "suspicious_activity_count": sum(1 for e in events if e.get("severity") in ["high", "critical"])
    }


def search_events_by_query(query: str, limit: int = 50) -> List[Dict]:
    """
    Search SIEM events by query string (simple implementation)

    Args:
        query: Search query (e.g., "source_ip:45.76.123.45")
        limit: Maximum events to return

    Returns:
        Matching events
    """
    # Simple query parser
    if ":" in query:
        field, value = query.split(":", 1)
        field = field.strip()
        value = value.strip()

        if field == "source_ip":
            return query_siem_events(source_ip=value, limit=limit)
        elif field == "user":
            return query_siem_events(user=value, limit=limit)
        elif field == "event_type":
            return query_siem_events(event_type=value, limit=limit)

    # Default: return all events
    return MOCK_SIEM_EVENTS[:limit]
