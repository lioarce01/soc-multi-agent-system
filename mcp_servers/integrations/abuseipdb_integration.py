"""
AbuseIPDB IP Reputation Integration (REAL API)
Free tier: 1000 requests/day (no rate limit per minute)
Get API key: https://abuseipdb.com

Uses the generic HTTPClient for all API calls.
"""

import os
from typing import Dict
from functools import lru_cache

from .http_client import HTTPClient, cache_response


class AbuseIPDBThreatIntel:
    """Real AbuseIPDB API integration for IP reputation"""

    def __init__(self):
        self.api_key = os.getenv("ABUSEIPDB_API_KEY")
        if not self.api_key:
            raise ValueError(
                "ABUSEIPDB_API_KEY not found in environment variables.\n"
                "Get a free API key at https://abuseipdb.com"
            )

        # Initialize HTTP client with AbuseIPDB configuration
        self.client = HTTPClient(
            base_url="https://api.abuseipdb.com/api/v2",
            default_headers={
                "Key": self.api_key,
                "Accept": "application/json"
            },
            timeout=10,
            max_retries=3,
            rate_limit=None,  # Free tier has daily limit but no rate limit per minute
            verbose=True
        )

    @cache_response(ttl_seconds=3600)  # Cache for 1 hour
    def get_ip_reputation(self, ip_address: str) -> Dict:
        """
        Get IP reputation from AbuseIPDB

        Args:
            ip_address: IP to check (e.g., "45.76.123.45")

        Returns:
            Dictionary with reputation data
        """
        print(f"  [AbuseIPDB] Querying IP reputation for {ip_address}...")

        # Make API request using HTTPClient
        response = self.client.get(
            "/check",
            params={
                "ipAddress": ip_address,
                "maxAgeInDays": 90,  # Check reports from last 90 days
                "verbose": True  # Get detailed info
            }
        )

        # Handle errors from HTTPClient
        if response.get("error"):
            status_code = response.get("status_code")

            # 404 = IP not in database (likely clean)
            if status_code == 404:
                print(f"  [AbuseIPDB] {ip_address} not found in database (likely clean)")
                return {
                    "ip_address": ip_address,
                    "reputation": "clean",
                    "threat_score": 0,
                    "malicious_count": 0,
                    "total_scanners": 1,
                    "message": "Not found in AbuseIPDB database",
                    "source": "AbuseIPDB"
                }

            # 429 = Rate limit
            elif status_code == 429:
                print(f"  [AbuseIPDB] Rate limit exceeded (1000/day)")
                return {
                    "ip_address": ip_address,
                    "reputation": "unknown",
                    "threat_score": 0,
                    "error": "Rate limit exceeded",
                    "source": "AbuseIPDB"
                }

            # Other errors
            else:
                print(f"  [AbuseIPDB] API error: {response.get('message', 'Unknown error')}")
                return {
                    "ip_address": ip_address,
                    "reputation": "unknown",
                    "threat_score": 0,
                    "error": response.get("message", "API request failed"),
                    "source": "AbuseIPDB"
                }

        # Parse successful response
        try:
            data = response.get("data", {})

            # AbuseIPDB returns confidence score 0-100
            abuse_score = data.get("abuseConfidenceScore", 0)
            total_reports = data.get("totalReports", 0)
            is_public = data.get("isPublic", True)
            is_whitelisted = data.get("isWhitelisted", False)

            # Normalize abuse score 0-100 to threat score 0-10
            threat_score = abuse_score / 10.0

            # Determine reputation based on abuse score
            if is_whitelisted:
                reputation = "clean"
                threat_score = 0
            elif abuse_score >= 75:
                reputation = "malicious"
            elif abuse_score >= 25:
                reputation = "suspicious"
            else:
                reputation = "clean"

            # Get usage information
            usage_type = data.get("usageType")
            isp = data.get("isp", "Unknown")
            country_code = data.get("countryCode")

            print(f"  [AbuseIPDB] {ip_address}: {reputation} (abuse score: {abuse_score}/100, reports: {total_reports})")

            return {
                "ip_address": ip_address,
                "reputation": reputation,
                "threat_score": round(threat_score, 1),
                "malicious_count": total_reports,
                "total_scanners": 1,  # AbuseIPDB is a single source
                "abuse_confidence_score": abuse_score,
                "is_whitelisted": is_whitelisted,
                "is_public": is_public,
                "usage_type": usage_type,
                "isp": isp,
                "country": country_code,
                "categories": self._parse_categories(data.get("reports", [])),
                "source": "AbuseIPDB"
            }

        except (KeyError, TypeError, AttributeError) as e:
            print(f"  [AbuseIPDB] Failed to parse response: {e}")
            return {
                "ip_address": ip_address,
                "reputation": "unknown",
                "threat_score": 0,
                "error": f"Failed to parse API response: {str(e)}",
                "source": "AbuseIPDB"
            }

    def _parse_categories(self, reports: list) -> list:
        """Parse abuse categories from reports"""
        # AbuseIPDB categories mapping
        category_names = {
            3: "Fraud Orders",
            4: "DDoS Attack",
            5: "FTP Brute-Force",
            6: "Ping of Death",
            7: "Phishing",
            8: "Fraud VoIP",
            9: "Open Proxy",
            10: "Web Spam",
            11: "Email Spam",
            12: "Blog Spam",
            13: "VPN IP",
            14: "Port Scan",
            15: "Hacking",
            16: "SQL Injection",
            17: "Spoofing",
            18: "Brute-Force",
            19: "Bad Web Bot",
            20: "Exploited Host",
            21: "Web App Attack",
            22: "SSH",
            23: "IoT Targeted"
        }

        categories = set()
        for report in reports[:10]:  # Check last 10 reports
            for cat_id in report.get("categories", []):
                if cat_id in category_names:
                    categories.add(category_names[cat_id])

        return list(categories)

    def close(self):
        """Close HTTP client session"""
        self.client.close()


# Singleton instance
_abuseipdb_instance = None

def get_abuseipdb_client():
    """Get singleton AbuseIPDB client"""
    global _abuseipdb_instance
    if _abuseipdb_instance is None:
        _abuseipdb_instance = AbuseIPDBThreatIntel()
    return _abuseipdb_instance


# ===== Testing =====

if __name__ == "__main__":
    # Test the integration
    print("=" * 60)
    print("ABUSEIPDB INTEGRATION TEST (using HTTPClient)")
    print("=" * 60)

    abuse = AbuseIPDBThreatIntel()

    # Test with known IPs
    test_ips = [
        "45.76.123.45",     # Example from sample alerts
        "8.8.8.8",          # Google DNS (should be clean/whitelisted)
        "185.220.101.1",    # Tor exit node
        "103.75.201.2"      # From alert generator
    ]

    for ip in test_ips:
        print(f"\nTesting: {ip}")
        result = abuse.get_ip_reputation(ip)
        print(f"  Reputation: {result['reputation']}")
        print(f"  Threat Score: {result['threat_score']}/10")
        print(f"  Abuse Score: {result.get('abuse_confidence_score', 0)}/100")
        if 'malicious_count' in result:
            print(f"  Total Reports: {result['malicious_count']}")

    abuse.close()

    print("\n" + "=" * 60)
    print("✅ AbuseIPDB tests completed")
    print("=" * 60)
