"""
VirusTotal IP Reputation Integration (REAL API)
Free tier: 500 requests/day
Get API key: https://virustotal.com

Uses the generic HTTPClient for all API calls.
"""

import os
from typing import Dict
from functools import lru_cache

from .http_client import HTTPClient, cache_response


class VirusTotalThreatIntel:
    """Real VirusTotal API integration for IP reputation"""

    def __init__(self):
        self.api_key = os.getenv("VIRUSTOTAL_API_KEY")
        if not self.api_key:
            raise ValueError(
                "VIRUSTOTAL_API_KEY not found in environment variables.\n"
                "Get a free API key at https://virustotal.com"
            )

        # Initialize HTTP client with VirusTotal configuration
        self.client = HTTPClient(
            base_url="https://www.virustotal.com/api/v3",
            default_headers={
                "x-apikey": self.api_key,
                "Accept": "application/json"
            },
            timeout=10,
            max_retries=3,
            rate_limit=4,  # 4 requests per minute (conservative for free tier)
            verbose=True
        )

    @cache_response(ttl_seconds=3600)  # Cache for 1 hour
    def get_ip_reputation(self, ip_address: str) -> Dict:
        """
        Get IP reputation from VirusTotal

        Args:
            ip_address: IP to check (e.g., "45.76.123.45")

        Returns:
            Dictionary with reputation data
        """
        print(f"  [VirusTotal] Querying IP reputation for {ip_address}...")

        # Make API request using HTTPClient
        response = self.client.get(f"/ip_addresses/{ip_address}")

        # Handle errors from HTTPClient
        if response.get("error"):
            status_code = response.get("status_code")

            # 404 = IP not in database (likely clean)
            if status_code == 404:
                print(f"  [VirusTotal] {ip_address} not found in database (likely clean)")
                return {
                    "ip_address": ip_address,
                    "reputation": "clean",
                    "threat_score": 0,
                    "malicious_count": 0,
                    "message": "Not found in VirusTotal database",
                    "source": "VirusTotal"
                }

            # 429 = Rate limit
            elif status_code == 429:
                print(f"  [VirusTotal] Rate limit exceeded (500/day)")
                return {
                    "ip_address": ip_address,
                    "reputation": "unknown",
                    "threat_score": 0,
                    "error": "Rate limit exceeded",
                    "source": "VirusTotal"
                }

            # Other errors
            else:
                print(f"  [VirusTotal] API error: {response.get('message', 'Unknown error')}")
                return {
                    "ip_address": ip_address,
                    "reputation": "unknown",
                    "threat_score": 0,
                    "error": response.get("message", "API request failed"),
                    "source": "VirusTotal"
                }

        # Parse successful response
        try:
            data = response.get("data", {})
            attributes = data.get("attributes", {})

            # Calculate threat score from analysis stats
            stats = attributes.get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            total = sum(stats.values())

            # Threat score 0-10
            if total > 0:
                threat_score = ((malicious * 2 + suspicious) / total) * 10
            else:
                threat_score = 0

            # Determine reputation
            if malicious > 5:
                reputation = "malicious"
            elif malicious > 0 or suspicious > 3:
                reputation = "suspicious"
            else:
                reputation = "clean"

            print(f"  [VirusTotal] {ip_address}: {reputation} (malicious: {malicious}/{total})")

            return {
                "ip_address": ip_address,
                "reputation": reputation,
                "threat_score": round(threat_score, 1),
                "malicious_count": malicious,
                "suspicious_count": suspicious,
                "total_scanners": total,
                "categories": list(attributes.get("categories", {}).values()),
                "country": attributes.get("country"),
                "asn": attributes.get("asn"),
                "as_owner": attributes.get("as_owner"),
                "source": "VirusTotal"
            }

        except (KeyError, TypeError, AttributeError) as e:
            print(f"  [VirusTotal] Failed to parse response: {e}")
            return {
                "ip_address": ip_address,
                "reputation": "unknown",
                "threat_score": 0,
                "error": f"Failed to parse API response: {str(e)}",
                "source": "VirusTotal"
            }

    def get_domain_reputation(self, domain: str) -> Dict:
        """
        Get domain reputation from VirusTotal

        Args:
            domain: Domain to check (e.g., "malicious-domain.com")

        Returns:
            Dictionary with reputation data
        """
        print(f"  [VirusTotal] Querying domain reputation for {domain}...")

        response = self.client.get(f"/domains/{domain}")

        if response.get("error"):
            return {
                "domain": domain,
                "reputation": "unknown",
                "threat_score": 0,
                "error": response.get("message", "API request failed"),
                "source": "VirusTotal"
            }

        try:
            data = response.get("data", {})
            attributes = data.get("attributes", {})

            stats = attributes.get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            total = sum(stats.values())

            if total > 0:
                threat_score = ((malicious * 2 + suspicious) / total) * 10
            else:
                threat_score = 0

            if malicious > 5:
                reputation = "malicious"
            elif malicious > 0:
                reputation = "suspicious"
            else:
                reputation = "clean"

            return {
                "domain": domain,
                "reputation": reputation,
                "threat_score": round(threat_score, 1),
                "malicious_count": malicious,
                "suspicious_count": suspicious,
                "total_scanners": total,
                "categories": list(attributes.get("categories", {}).values()),
                "source": "VirusTotal"
            }

        except (KeyError, TypeError, AttributeError) as e:
            return {
                "domain": domain,
                "reputation": "unknown",
                "threat_score": 0,
                "error": f"Failed to parse API response: {str(e)}",
                "source": "VirusTotal"
            }

    def get_file_reputation(self, file_hash: str) -> Dict:
        """
        Get file reputation from VirusTotal

        Args:
            file_hash: File hash (MD5, SHA1, or SHA256)

        Returns:
            Dictionary with reputation data
        """
        print(f"  [VirusTotal] Querying file reputation for {file_hash}...")

        response = self.client.get(f"/files/{file_hash}")

        if response.get("error"):
            return {
                "file_hash": file_hash,
                "reputation": "unknown",
                "threat_score": 0,
                "error": response.get("message", "API request failed"),
                "source": "VirusTotal"
            }

        try:
            data = response.get("data", {})
            attributes = data.get("attributes", {})

            stats = attributes.get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            total = sum(stats.values())

            if total > 0:
                threat_score = (malicious / total) * 10
            else:
                threat_score = 0

            if malicious > 5:
                reputation = "malicious"
            elif malicious > 0:
                reputation = "suspicious"
            else:
                reputation = "clean"

            return {
                "file_hash": file_hash,
                "reputation": reputation,
                "threat_score": round(threat_score, 1),
                "malicious_count": malicious,
                "total_scanners": total,
                "file_type": attributes.get("type_description"),
                "file_size": attributes.get("size"),
                "first_seen": attributes.get("first_submission_date"),
                "source": "VirusTotal"
            }

        except (KeyError, TypeError, AttributeError) as e:
            return {
                "file_hash": file_hash,
                "reputation": "unknown",
                "threat_score": 0,
                "error": f"Failed to parse API response: {str(e)}",
                "source": "VirusTotal"
            }

    def close(self):
        """Close HTTP client session"""
        self.client.close()


# Singleton instance
_virustotal_instance = None

def get_virustotal_client():
    """Get singleton VirusTotal client"""
    global _virustotal_instance
    if _virustotal_instance is None:
        _virustotal_instance = VirusTotalThreatIntel()
    return _virustotal_instance


# ===== Testing =====

if __name__ == "__main__":
    # Test the integration
    print("=" * 60)
    print("VIRUSTOTAL INTEGRATION TEST (using HTTPClient)")
    print("=" * 60)

    vt = VirusTotalThreatIntel()

    # Test with known IPs
    test_ips = [
        "45.76.123.45",  # Example from sample alerts
        "8.8.8.8",       # Google DNS (should be clean)
        "185.220.101.1"  # Example brute force IP
    ]

    for ip in test_ips:
        print(f"\nTesting: {ip}")
        result = vt.get_ip_reputation(ip)
        print(f"  Reputation: {result['reputation']}")
        print(f"  Threat Score: {result['threat_score']}/10")
        if 'malicious_count' in result:
            print(f"  Detections: {result['malicious_count']}/{result.get('total_scanners', 0)}")

    # Test domain
    print(f"\n\nTesting domain: malicious-domain.com")
    result = vt.get_domain_reputation("malicious-domain.com")
    print(f"  Reputation: {result['reputation']}")

    vt.close()

    print("\n" + "=" * 60)
    print("✅ VirusTotal tests completed")
    print("=" * 60)
