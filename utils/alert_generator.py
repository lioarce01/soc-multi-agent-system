"""
Realistic Alert Generator for POC/Demo

Generates realistic security alerts based on common attack patterns.
NO requiere SIEM instalado - perfecto para demos y POCs.
"""

import random
from datetime import datetime, timedelta
from typing import Dict, List
import json


class AlertGenerator:
    """Generate realistic security alerts for testing"""

    def __init__(self):
        self.alert_counter = 1000

        # IPs maliciosas reales (de listas públicas)
        self.malicious_ips = [
            "45.142.214.93",   # Conocida por scans
            "185.220.101.1",   # Tor exit node
            "91.203.5.146",    # Botnet C2
            "194.165.16.85",   # Brute force attacks
            "103.75.201.2"     # Phishing campaigns
        ]

        # Dominios sospechosos
        self.malicious_domains = [
            "invoice-payment-urgent.com",
            "microsoft-security-alert.net",
            "paypal-verify-account.info",
            "amazon-security-update.org",
            "dropbox-file-share.xyz"
        ]

        # Hashes de malware reales (de VirusTotal)
        self.malware_hashes = [
            "44d88612fea8a8f36de82e1278abb02f",  # EICAR test
            "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6",  # Generic malware
            "5d41402abc4b2a76b9719d911017c592",  # Cryptominer
        ]

        # Usuarios ficticios pero realistas
        self.users = [
            "john.doe@company.com",
            "sarah.johnson@company.com",
            "mike.wilson@company.com",
            "lisa.anderson@company.com",
            "admin",
            "administrator",
            "root"
        ]

    def generate_phishing_alert(self) -> Dict:
        """Generate a realistic phishing email alert"""
        self.alert_counter += 1

        sender_domain = random.choice(self.malicious_domains)
        user = random.choice(self.users)

        subjects = [
            "URGENT: Verify your account",
            "Your invoice is ready",
            "Security Alert: Unusual Activity Detected",
            "Payment Failed - Action Required",
            "Dropbox: File shared with you"
        ]

        return {
            "id": f"ALT-{datetime.now().year}-{self.alert_counter}",
            "timestamp": (datetime.now() - timedelta(minutes=random.randint(1, 30))).isoformat() + "Z",
            "type": "phishing",
            "severity": random.choice(["high", "critical"]),
            "title": "Suspicious phishing email detected",
            "description": f"User received email with subject '{random.choice(subjects)}' from unknown sender external@{sender_domain}",
            "source_ip": random.choice(self.malicious_ips),
            "destination_ip": f"192.168.{random.randint(1,20)}.{random.randint(1,254)}",
            "user": user,
            "hostname": f"WS-{random.randint(1,50):03d}",
            "indicators": {
                "sender": f"noreply@{sender_domain}",
                "subject": random.choice(subjects),
                "attachment": random.choice(["invoice.exe", "document.pdf.exe", "receipt.docm", None]),
                "attachment_hash": random.choice(self.malware_hashes) if random.random() > 0.3 else None,
                "links": [f"https://{sender_domain}/verify?token=abc123"]
            }
        }

    def generate_brute_force_alert(self) -> Dict:
        """Generate a brute force attack alert"""
        self.alert_counter += 1

        return {
            "id": f"ALT-{datetime.now().year}-{self.alert_counter}",
            "timestamp": (datetime.now() - timedelta(minutes=random.randint(1, 15))).isoformat() + "Z",
            "type": "unauthorized_access",
            "severity": "critical",
            "title": "Multiple failed login attempts",
            "description": f"Failed login attempts: {random.randint(10, 50)} tries in {random.randint(3, 10)} minutes from IP {random.choice(self.malicious_ips)}",
            "source_ip": random.choice(self.malicious_ips),
            "destination_ip": f"192.168.1.{random.randint(1,50)}",
            "user": random.choice(["admin", "administrator", "root", "sa"]),
            "hostname": f"SERVER-{random.randint(1,10):02d}",
            "indicators": {
                "failed_attempts": random.randint(10, 50),
                "time_window": f"{random.randint(3, 10)} minutes",
                "account_targeted": random.choice(["admin", "root", "administrator"]),
                "authentication_method": random.choice(["SSH", "RDP", "Web Console", "API"])
            }
        }

    def generate_malware_alert(self) -> Dict:
        """Generate a malware detection alert"""
        self.alert_counter += 1

        malware_names = [
            "cryptominer.exe",
            "ransomware.dll",
            "trojan_backdoor.exe",
            "keylogger.sys",
            "botnet_agent.bin"
        ]

        c2_servers = self.malicious_ips

        return {
            "id": f"ALT-{datetime.now().year}-{self.alert_counter}",
            "timestamp": (datetime.now() - timedelta(minutes=random.randint(1, 20))).isoformat() + "Z",
            "type": "malware",
            "severity": "critical",
            "title": "Malicious process detected",
            "description": f"Endpoint detected malicious process '{random.choice(malware_names)}' connecting to known C2 server {random.choice(c2_servers)}",
            "source_ip": f"192.168.{random.randint(1,20)}.{random.randint(1,254)}",
            "destination_ip": random.choice(c2_servers),
            "user": random.choice(self.users),
            "hostname": f"WS-{random.randint(1,100):03d}",
            "indicators": {
                "process_name": random.choice(malware_names),
                "process_hash": random.choice(self.malware_hashes),
                "c2_server": f"{random.choice(c2_servers)}:{random.choice([8080, 443, 4444, 1337])}",
                "network_protocol": random.choice(["TCP", "UDP", "HTTP", "HTTPS"]),
                "parent_process": random.choice(["explorer.exe", "svchost.exe", "winlogon.exe"])
            }
        }

    def generate_data_exfiltration_alert(self) -> Dict:
        """Generate a data exfiltration alert"""
        self.alert_counter += 1

        cloud_ips = [
            "52.218.48.101",  # AWS S3
            "142.250.185.78", # Google Drive
            "40.90.189.152"   # Azure Blob
        ]

        return {
            "id": f"ALT-{datetime.now().year}-{self.alert_counter}",
            "timestamp": (datetime.now() - timedelta(minutes=random.randint(1, 45))).isoformat() + "Z",
            "type": "data_exfiltration",
            "severity": random.choice(["high", "critical"]),
            "title": "Unusual data transfer detected",
            "description": f"Large data transfer ({random.randint(1, 10)}GB) to external cloud storage from internal server",
            "source_ip": f"192.168.10.{random.randint(1,100)}",
            "destination_ip": random.choice(cloud_ips),
            "user": random.choice(self.users + ["db_service_account", "backup_service"]),
            "hostname": f"DB-PROD-{random.randint(1,5):02d}",
            "indicators": {
                "bytes_transferred": random.randint(1, 10) * 1073741824,  # GB to bytes
                "destination_service": random.choice(["AWS S3", "Google Drive", "Dropbox", "OneDrive"]),
                "transfer_duration": f"{random.randint(10, 90)} minutes",
                "unusual_time": random.choice(["after business hours", "weekend", "holiday", None])
            }
        }

    def generate_suspicious_login_alert(self) -> Dict:
        """Generate a suspicious login alert"""
        self.alert_counter += 1

        countries = [
            ("Russia", "93.184.216.34"),
            ("China", "218.92.0.107"),
            ("Nigeria", "105.112.98.45"),
            ("Iran", "5.160.247.89"),
            ("North Korea", "175.45.176.1")
        ]

        country, ip = random.choice(countries)

        return {
            "id": f"ALT-{datetime.now().year}-{self.alert_counter}",
            "timestamp": (datetime.now() - timedelta(minutes=random.randint(1, 60))).isoformat() + "Z",
            "type": "suspicious_login",
            "severity": random.choice(["medium", "high"]),
            "title": "Login from unusual location",
            "description": f"User login from geolocation: {country} (normally logs in from USA)",
            "source_ip": ip,
            "destination_ip": f"192.168.1.{random.randint(10,50)}",
            "user": random.choice(self.users),
            "hostname": random.choice(["VPN-GATEWAY", "WEB-APP-01", "API-SERVER"]),
            "indicators": {
                "normal_country": "USA",
                "login_country": country,
                "normal_login_time": "9am-5pm EST",
                "login_time": f"{random.randint(0,5)}am EST",
                "device_type": random.choice(["unknown", "mobile", "desktop"]),
                "new_device": random.random() > 0.5
            }
        }

    def generate_random_alert(self) -> Dict:
        """Generate a random alert of any type"""
        alert_types = [
            self.generate_phishing_alert,
            self.generate_brute_force_alert,
            self.generate_malware_alert,
            self.generate_data_exfiltration_alert,
            self.generate_suspicious_login_alert
        ]

        return random.choice(alert_types)()

    def generate_batch(self, count: int = 10) -> List[Dict]:
        """Generate multiple random alerts"""
        return [self.generate_random_alert() for _ in range(count)]


# ===== CLI Interface =====

def main():
    """Generate alerts from command line"""
    import argparse

    parser = argparse.ArgumentParser(description="Generate realistic security alerts")
    parser.add_argument("--count", type=int, default=1, help="Number of alerts to generate")
    parser.add_argument("--type", choices=["phishing", "brute_force", "malware", "exfiltration", "suspicious_login", "random"],
                       default="random", help="Type of alert to generate")
    parser.add_argument("--output", type=str, help="Output file (JSON)")

    args = parser.parse_args()

    generator = AlertGenerator()

    # Generate alerts
    if args.count == 1:
        if args.type == "phishing":
            alert = generator.generate_phishing_alert()
        elif args.type == "brute_force":
            alert = generator.generate_brute_force_alert()
        elif args.type == "malware":
            alert = generator.generate_malware_alert()
        elif args.type == "exfiltration":
            alert = generator.generate_data_exfiltration_alert()
        elif args.type == "suspicious_login":
            alert = generator.generate_suspicious_login_alert()
        else:
            alert = generator.generate_random_alert()

        alerts = [alert]
    else:
        alerts = generator.generate_batch(args.count)

    # Output
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(alerts, f, indent=2)
        print(f"Generated {len(alerts)} alert(s) → {args.output}")
    else:
        print(json.dumps(alerts, indent=2))


if __name__ == "__main__":
    main()
