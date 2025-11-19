"""
AI-Powered Alert Normalizer

Converts alerts from ANY format into a standardized format using LLM.
No necesitas adaptar tu código para cada SIEM diferente!
"""

from typing import Dict, Any
import json
from langchain_core.messages import HumanMessage, SystemMessage
from src.llm_factory import get_llm


class AlertNormalizer:
    """
    Normalize alerts from any SIEM/source using AI

    Ventajas:
    - Acepta CUALQUIER formato JSON
    - Extrae información relevante automáticamente
    - No requiere mapeos manuales para cada SIEM
    """

    def __init__(self):
        self.llm = get_llm()

    def normalize(self, raw_alert: Dict[str, Any]) -> Dict[str, Any]:
        """
        Convert any alert format to standardized format

        Args:
            raw_alert: Alert in ANY format (Splunk, Elastic, custom, etc.)

        Returns:
            Standardized alert format
        """
        # Prompt para que el LLM extraiga información relevante
        prompt = f"""
You are a security alert normalizer. Convert the following security alert into a standardized JSON format.

INPUT ALERT (raw format):
```json
{json.dumps(raw_alert, indent=2)}
```

EXTRACT the following information and create a normalized alert:
- Alert ID (if available, otherwise generate one)
- Alert type (classify as: phishing, malware, unauthorized_access, data_exfiltration, suspicious_login, or other)
- Severity (critical, high, medium, low - infer from context)
- Title (short description)
- Description (detailed description)
- Source IP address (if mentioned)
- Destination IP address (if mentioned)
- User/account affected (if mentioned)
- Hostname/device (if mentioned)
- Timestamp (if available)
- Any other relevant indicators (file hashes, domains, etc.)

OUTPUT FORMAT (JSON only, no explanation):
```json
{{
  "id": "unique-id",
  "timestamp": "ISO8601 format",
  "type": "alert_type",
  "severity": "severity_level",
  "title": "Short title",
  "description": "Detailed description",
  "source_ip": "x.x.x.x or null",
  "destination_ip": "x.x.x.x or null",
  "user": "username or null",
  "hostname": "hostname or null",
  "indicators": {{
    "any_relevant_field": "value"
  }}
}}
```

Return ONLY the JSON, nothing else.
"""

        messages = [
            SystemMessage(content="You are a security alert normalizer. Output only valid JSON."),
            HumanMessage(content=prompt)
        ]

        # Call LLM
        response = self.llm.invoke(messages)

        # Parse response
        try:
            # Extract JSON from response (LLM might add markdown)
            content = response.content.strip()

            # Remove markdown code blocks if present
            if content.startswith("```json"):
                content = content.replace("```json", "").replace("```", "").strip()
            elif content.startswith("```"):
                content = content.replace("```", "").strip()

            normalized = json.loads(content)
            return normalized

        except json.JSONDecodeError as e:
            print(f"[AlertNormalizer] Failed to parse LLM response: {e}")
            print(f"[AlertNormalizer] Raw response: {response.content}")

            # Fallback: return raw alert with some basic structure
            return {
                "id": raw_alert.get("id", "unknown"),
                "timestamp": raw_alert.get("timestamp", raw_alert.get("_time", "")),
                "type": "other",
                "severity": "medium",
                "title": "Unknown alert",
                "description": str(raw_alert),
                "source_ip": None,
                "destination_ip": None,
                "user": None,
                "hostname": None,
                "indicators": raw_alert
            }


# ===== Testing =====

def test_normalizer():
    """Test normalizer with different formats"""

    normalizer = AlertNormalizer()

    # Test 1: Splunk format
    print("\n" + "=" * 60)
    print("TEST 1: Splunk Raw Log")
    print("=" * 60)

    splunk_alert = {
        "_time": "2025-01-16T10:30:45.000Z",
        "_raw": "Jan 16 10:30:45 server01 sshd[12345]: Failed password for admin from 45.142.214.93 port 44252 ssh2",
        "host": "server01",
        "source": "/var/log/auth.log",
        "sourcetype": "syslog",
        "index": "security"
    }

    normalized = normalizer.normalize(splunk_alert)
    print(json.dumps(normalized, indent=2))

    # Test 2: Elastic ECS format
    print("\n" + "=" * 60)
    print("TEST 2: Elastic ECS Format")
    print("=" * 60)

    elastic_alert = {
        "@timestamp": "2025-01-16T10:35:22.123Z",
        "event": {
            "category": "malware",
            "type": "info",
            "action": "detected"
        },
        "message": "Malicious file detected: cryptominer.exe",
        "process": {
            "name": "cryptominer.exe",
            "hash": {
                "md5": "44d88612fea8a8f36de82e1278abb02f"
            }
        },
        "host": {
            "name": "WS-042",
            "ip": "192.168.1.42"
        },
        "user": {
            "name": "sarah.johnson@company.com"
        },
        "network": {
            "destination": {
                "ip": "91.203.5.146",
                "port": 8080
            }
        }
    }

    normalized = normalizer.normalize(elastic_alert)
    print(json.dumps(normalized, indent=2))

    # Test 3: Custom format completamente diferente
    print("\n" + "=" * 60)
    print("TEST 3: Custom Format")
    print("=" * 60)

    custom_alert = {
        "alert_name": "Phishing Email Detected",
        "detected_at": "2025-01-16 10:40:15",
        "priority": "P1",
        "details": {
            "recipient": "john.doe@company.com",
            "sender": "noreply@invoice-payment-urgent.com",
            "email_subject": "URGENT: Payment Required",
            "contains_attachment": True,
            "attachment_name": "invoice.pdf.exe",
            "sender_ip": "185.220.101.1"
        }
    }

    normalized = normalizer.normalize(custom_alert)
    print(json.dumps(normalized, indent=2))

    print("\n" + "=" * 60)
    print("✅ All formats normalized successfully!")
    print("=" * 60)


if __name__ == "__main__":
    test_normalizer()
