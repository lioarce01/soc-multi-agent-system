"""
Standard Remediation Playbooks
Pre-populated playbooks for common security incidents
"""

# Standard playbooks for common threat types
STANDARD_PLAYBOOKS = [
    {
        "name": "phishing_response",
        "content": """# Phishing Incident Response Playbook

## Overview
This playbook outlines the response procedures for phishing email incidents.

## Immediate Actions (0-15 minutes)
1. **Isolate Affected Systems**
   - Disconnect affected user's device from network
   - Revoke active sessions for affected user account
   - Block sender email address at email gateway

2. **Credential Security**
   - Force password reset for affected user account
   - Enable MFA if not already enabled
   - Review account for unauthorized access

3. **Containment**
   - Quarantine malicious email from all mailboxes
   - Block malicious URLs/domains at firewall/proxy
   - Scan affected endpoint for malware

## Investigation (15-60 minutes)
1. **Email Analysis**
   - Extract email headers and metadata
   - Analyze sender reputation and history
   - Check for email authentication failures (SPF/DKIM/DMARC)

2. **Link/Attachment Analysis**
   - Analyze malicious URLs (sandbox if possible)
   - Extract and analyze attachments
   - Check if links lead to credential harvesting pages

3. **User Impact Assessment**
   - Determine if user clicked links or opened attachments
   - Check for credential submission to malicious sites
   - Review user's recent activity for signs of compromise

## Remediation (1-4 hours)
1. **Account Recovery**
   - Reset passwords for all affected accounts
   - Review and revoke suspicious permissions
   - Enable additional security controls

2. **Network Remediation**
   - Update firewall rules to block malicious domains
   - Update email security rules
   - Deploy additional email filtering

3. **Endpoint Remediation**
   - Run full antivirus scan
   - Check for persistence mechanisms
   - Review browser extensions and installed software

## Post-Incident (24-48 hours)
1. **User Education**
   - Provide phishing awareness training
   - Review security best practices
   - Document lessons learned

2. **Monitoring**
   - Monitor affected accounts for suspicious activity
   - Review email logs for similar patterns
   - Check for credential reuse attempts

## MITRE ATT&CK Techniques
- T1566: Phishing
- T1566.001: Spearphishing Attachment
- T1566.002: Spearphishing Link
- T1078: Valid Accounts (if credentials compromised)

## Success Criteria
- All malicious emails quarantined
- Affected accounts secured
- No evidence of credential compromise
- User educated on phishing risks""",
        "metadata": {
            "threat_type": "phishing",
            "attack_stage": "Initial Access",
            "severity": "medium",
            "estimated_time": "2-4 hours"
        }
    },
    {
        "name": "malware_response",
        "content": """# Malware Incident Response Playbook

## Overview
This playbook outlines response procedures for malware detection and infection incidents.

## Immediate Actions (0-15 minutes)
1. **Isolation**
   - Immediately isolate affected endpoint from network
   - Disable network adapters if necessary
   - Block endpoint IP at network perimeter

2. **Initial Assessment**
   - Identify malware type and family
   - Determine infection vector (email, USB, download, etc.)
   - Assess potential data exposure

3. **Containment**
   - Disable affected user account
   - Revoke network access
   - Preserve system state for forensics

## Investigation (15-60 minutes)
1. **Malware Analysis**
   - Extract malware sample for analysis
   - Determine malware capabilities (keylogger, ransomware, backdoor, etc.)
   - Identify command and control (C2) infrastructure

2. **Infection Timeline**
   - Determine initial infection time
   - Map lateral movement within network
   - Identify other potentially affected systems

3. **Impact Assessment**
   - Determine data accessed or exfiltrated
   - Check for credential theft
   - Assess business impact

## Remediation (1-6 hours)
1. **Endpoint Remediation**
   - Run full antivirus/EDR scan
   - Remove malware artifacts
   - Check for persistence mechanisms (registry, scheduled tasks, services)
   - Review installed software and browser extensions

2. **Network Remediation**
   - Block C2 domains and IPs at firewall
   - Update IDS/IPS signatures
   - Review network traffic for anomalies

3. **Credential Security**
   - Reset passwords for all potentially compromised accounts
   - Rotate service account credentials
   - Review and revoke suspicious permissions

4. **Data Recovery**
   - Restore from clean backups if needed
   - Verify backup integrity
   - Document data loss (if any)

## Post-Incident (24-72 hours)
1. **Forensics**
   - Preserve disk images for analysis
   - Analyze network logs
   - Document attack timeline

2. **Prevention**
   - Update endpoint protection rules
   - Deploy additional security controls
   - Review and update security policies

3. **Monitoring**
   - Monitor for re-infection
   - Check for related indicators of compromise
   - Review security logs for similar patterns

## MITRE ATT&CK Techniques
- T1055: Process Injection
- T1071: Application Layer Protocol
- T1059: Command and Scripting Interpreter
- T1562: Impair Defenses
- T1490: Inhibit System Recovery (for ransomware)

## Success Criteria
- Malware completely removed
- No evidence of lateral movement
- All C2 communications blocked
- System restored to clean state""",
        "metadata": {
            "threat_type": "malware",
            "attack_stage": "Execution",
            "severity": "high",
            "estimated_time": "4-6 hours"
        }
    },
    {
        "name": "brute_force_response",
        "content": """# Brute Force Attack Response Playbook

## Overview
This playbook outlines response procedures for brute force authentication attacks.

## Immediate Actions (0-15 minutes)
1. **Block Source IP**
   - Immediately block attacking IP at firewall
   - Add to threat intelligence blacklist
   - Update WAF rules if applicable

2. **Account Protection**
   - Temporarily lock targeted user accounts
   - Enable account lockout policies
   - Review account for unauthorized access

3. **Monitoring**
   - Increase logging for authentication events
   - Set up alerts for repeated failed logins
   - Monitor for successful logins from suspicious IPs

## Investigation (15-60 minutes)
1. **Attack Analysis**
   - Review authentication logs
   - Identify attack pattern and timing
   - Determine if attack was successful

2. **Source Investigation**
   - Check IP reputation and geolocation
   - Review threat intelligence feeds
   - Check for known APT group associations

3. **Impact Assessment**
   - Determine if any accounts were compromised
   - Check for successful logins during attack window
   - Review account activity for suspicious behavior

## Remediation (1-4 hours)
1. **Account Security**
   - Force password reset for targeted accounts
   - Enable MFA for all affected accounts
   - Review and revoke suspicious sessions

2. **Network Security**
   - Implement rate limiting for authentication
   - Deploy CAPTCHA for web-based logins
   - Update firewall rules to block attack patterns

3. **System Hardening**
   - Review and strengthen password policies
   - Enable account lockout after failed attempts
   - Implement IP whitelisting for critical accounts

## Post-Incident (24-48 hours)
1. **Monitoring**
   - Continue monitoring for repeated attacks
   - Check for credential stuffing attempts
   - Review authentication logs for anomalies

2. **Prevention**
   - Deploy additional authentication security
   - Update security awareness training
   - Review and update access control policies

## MITRE ATT&CK Techniques
- T1110: Brute Force
- T1110.001: Password Guessing
- T1110.002: Password Cracking
- T1078: Valid Accounts (if successful)

## Success Criteria
- Attack source blocked
- No accounts compromised
- Additional security controls deployed
- Monitoring enhanced""",
        "metadata": {
            "threat_type": "brute_force",
            "attack_stage": "Credential Access",
            "severity": "medium",
            "estimated_time": "2-4 hours"
        }
    },
    {
        "name": "data_exfiltration_response",
        "content": """# Data Exfiltration Incident Response Playbook

## Overview
This playbook outlines response procedures for suspected or confirmed data exfiltration incidents.

## Immediate Actions (0-15 minutes)
1. **Containment**
   - Immediately isolate affected systems
   - Block outbound connections if possible
   - Preserve network logs and system state

2. **Assessment**
   - Determine scope of potential data loss
   - Identify exfiltration method (HTTP, FTP, cloud storage, etc.)
   - Assess data sensitivity and regulatory impact

3. **Legal/Compliance**
   - Notify legal and compliance teams
   - Determine if breach notification required
   - Preserve evidence for potential investigation

## Investigation (15-120 minutes)
1. **Exfiltration Analysis**
   - Review network traffic logs
   - Identify destination IPs/domains
   - Determine data volume and types exfiltrated

2. **Timeline Reconstruction**
   - Determine when exfiltration began
   - Map data access timeline
   - Identify initial compromise vector

3. **Data Classification**
   - Categorize exfiltrated data (PII, PHI, intellectual property, etc.)
   - Assess regulatory impact (GDPR, HIPAA, etc.)
   - Determine notification requirements

## Remediation (2-8 hours)
1. **Immediate Containment**
   - Block all outbound connections from affected systems
   - Revoke access credentials
   - Isolate compromised accounts

2. **Network Remediation**
   - Block destination IPs/domains at firewall
   - Update DLP rules
   - Implement stricter egress filtering

3. **System Remediation**
   - Remove attacker access
   - Patch exploited vulnerabilities
   - Review and strengthen access controls

4. **Data Protection**
   - Encrypt sensitive data at rest
   - Review data access logs
   - Implement additional data loss prevention controls

## Post-Incident (48-72 hours)
1. **Forensics**
   - Complete forensic analysis
   - Document attack timeline
   - Preserve evidence for legal proceedings

2. **Notification**
   - Notify affected parties if required
   - Report to regulatory bodies if necessary
   - Coordinate with law enforcement if appropriate

3. **Prevention**
   - Deploy advanced DLP solutions
   - Implement data classification and tagging
   - Enhance network monitoring

## MITRE ATT&CK Techniques
- TA0010: Exfiltration
- T1041: Exfiltration Over C2 Channel
- T1048: Exfiltration Over Alternative Protocol
- T1537: Transfer Data to Cloud Account

## Success Criteria
- Exfiltration stopped
- All compromised systems secured
- Regulatory requirements met
- Enhanced monitoring deployed""",
        "metadata": {
            "threat_type": "data_exfiltration",
            "attack_stage": "Exfiltration",
            "severity": "critical",
            "estimated_time": "6-8 hours"
        }
    },
    {
        "name": "privilege_escalation_response",
        "content": """# Privilege Escalation Incident Response Playbook

## Overview
This playbook outlines response procedures for privilege escalation incidents.

## Immediate Actions (0-15 minutes)
1. **Account Revocation**
   - Immediately revoke elevated privileges
   - Disable compromised accounts
   - Lock affected user accounts

2. **System Isolation**
   - Isolate affected systems from network
   - Preserve system state for forensics
   - Block lateral movement paths

3. **Assessment**
   - Determine scope of privilege escalation
   - Identify exploited vulnerability or misconfiguration
   - Assess potential data access

## Investigation (15-60 minutes)
1. **Escalation Analysis**
   - Review authentication and authorization logs
   - Identify method of privilege escalation
   - Determine timeline of escalation

2. **Impact Assessment**
   - Determine what systems/data were accessed
   - Check for additional compromised accounts
   - Assess potential for lateral movement

3. **Vulnerability Identification**
   - Identify exploited vulnerability
   - Check for similar misconfigurations
   - Review access control policies

## Remediation (1-6 hours)
1. **Access Control**
   - Revoke all elevated privileges
   - Reset passwords for affected accounts
   - Review and update access control policies

2. **System Remediation**
   - Patch exploited vulnerabilities
   - Fix misconfigurations
   - Remove unauthorized access

3. **Security Hardening**
   - Implement principle of least privilege
   - Enable privilege access management (PAM)
   - Deploy additional access monitoring

## Post-Incident (24-48 hours)
1. **Forensics**
   - Complete forensic analysis
   - Document attack timeline
   - Preserve evidence

2. **Prevention**
   - Review and update access control policies
   - Deploy privilege access management
   - Enhance monitoring and alerting

3. **Monitoring**
   - Monitor for repeated escalation attempts
   - Review access logs for anomalies
   - Check for related security events

## MITRE ATT&CK Techniques
- T1078: Valid Accounts
- T1134: Access Token Manipulation
- T1548: Abuse Elevation Control Mechanism
- T1068: Exploitation for Privilege Escalation

## Success Criteria
- All elevated privileges revoked
- Vulnerabilities patched
- Access controls strengthened
- Monitoring enhanced""",
        "metadata": {
            "threat_type": "privilege_escalation",
            "attack_stage": "Privilege Escalation",
            "severity": "high",
            "estimated_time": "4-6 hours"
        }
    }
]


async def initialize_playbooks(memory_manager) -> int:
    """
    Initialize standard playbooks in the knowledge base
    
    Args:
        memory_manager: MemoryManager instance
    
    Returns:
        Number of playbooks initialized
    """
    count = 0
    
    for playbook in STANDARD_PLAYBOOKS:
        try:
            await memory_manager.save_playbook(
                playbook_name=playbook["name"],
                playbook_content=playbook["content"],
                metadata=playbook["metadata"]
            )
            count += 1
            print(f"[PLAYBOOKS] ✅ Initialized playbook: {playbook['name']}")
        except Exception as e:
            print(f"[PLAYBOOKS] ⚠️  Failed to initialize playbook {playbook['name']}: {e}")
    
    print(f"[PLAYBOOKS] ✅ Initialized {count}/{len(STANDARD_PLAYBOOKS)} playbooks")
    return count

