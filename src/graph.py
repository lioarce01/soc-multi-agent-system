"""
LangGraph Workflow for Security Alert Investigation (Non-Streaming)
Main investigation workflow with structured, complete results
"""

from typing import Dict, Any, List
from langgraph.graph import StateGraph, END
from langchain_core.messages import HumanMessage, AIMessage

from src.state import SecurityAgentState, create_initial_state
from src.config import Config


# ===== Node Functions =====

async def supervisor_node(state: SecurityAgentState) -> Dict[str, Any]:
    """
    Supervisor - Routes workflow and searches memory for similar incidents
    """
    print(f"\n[SUPERVISOR] Processing alert: {state['alert_id']}")

    # Search memory for similar past incidents
    similar_incidents = []
    memory_reasoning = ""

    try:
        from src.memory.manager import get_memory_manager

        memory_manager = get_memory_manager()
        similar_incidents = await memory_manager.find_similar_incidents(
            current_alert=state["alert_data"],
            k=3,
            min_similarity=0.7
        )

        if similar_incidents:
            print(f"[SUPERVISOR] 🔍 Found {len(similar_incidents)} similar past incidents:")
            for incident in similar_incidents:
                print(f"  - {incident['incident_id']}: {incident['similarity_score']:.0%} similar ({incident['alert_type']})")

            # Generate LLM reasoning about similarities
            try:
                from src.llm_factory import get_llm
                import json

                llm = get_llm()

                reasoning_prompt = f"""You are a SOC analyst reviewing past security incidents.

Current alert being investigated:
{json.dumps(state["alert_data"], indent=2)}

Similar past incidents found in memory:
{json.dumps(similar_incidents, indent=2)}

Explain in 3-4 concise sentences:
1. Why these past incidents are similar to the current alert
2. What common patterns or indicators you notice
3. How this historical context will help the current investigation

Focus on actionable insights. Be specific about shared attributes like IPs, attack techniques, or behaviors."""

                print(f"[SUPERVISOR] 💭 Generating memory reasoning with LLM...")
                response = await llm.ainvoke(reasoning_prompt)
                memory_reasoning = response.content

                print(f"[SUPERVISOR] ✅ Memory reasoning generated")

            except Exception as llm_error:
                print(f"[SUPERVISOR] ⚠️  Could not generate memory reasoning: {llm_error}")
                memory_reasoning = f"Found {len(similar_incidents)} similar past incidents, but could not generate detailed reasoning."

    except Exception as e:
        print(f"[SUPERVISOR] ⚠️  Error searching memory: {e}")
        print(f"[SUPERVISOR] Continuing without memory context")

    # Campaign Detection: If 3+ similar incidents found, detect campaign
    campaign_info = None
    if len(similar_incidents) >= 3:
        try:
            from datetime import datetime, timedelta
            
            # Get all incident IDs (including current)
            incident_ids = [inc["incident_id"] for inc in similar_incidents]
            incident_ids.append(state["alert_id"])
            
            # Calculate time span
            timestamps = []
            for inc in similar_incidents:
                try:
                    ts = inc.get("timestamp", "")
                    if ts:
                        timestamps.append(datetime.fromisoformat(ts.replace("Z", "+00:00")))
                except:
                    pass
            
            if timestamps:
                time_span = (max(timestamps) - min(timestamps)).total_seconds() / 3600  # hours
            else:
                time_span = 24.0  # Default
            
            # Calculate confidence based on similarity scores
            avg_similarity = sum(inc["similarity_score"] for inc in similar_incidents) / len(similar_incidents)
            confidence = min(0.95, avg_similarity * 1.1)  # Boost confidence slightly
            
            # Determine threat assessment
            if time_span < 24:
                assessment = "ONGOING_CAMPAIGN"
            else:
                assessment = "MULTI_WAVE_CAMPAIGN"
            
            campaign_info = {
                "campaign_id": f"CAMPAIGN-{state['alert_id'][-8:].upper()}",
                "confidence": confidence,
                "incident_count": len(incident_ids),
                "related_incidents": incident_ids,
                "time_span_hours": time_span,
                "threat_assessment": assessment,
                "average_similarity": avg_similarity
            }
            
            print(f"[SUPERVISOR] 🚨 CAMPAIGN DETECTED: {campaign_info['campaign_id']} ({len(incident_ids)} incidents, {confidence:.0%} confidence)")
            
        except Exception as campaign_error:
            print(f"[SUPERVISOR] ⚠️  Error detecting campaign: {campaign_error}")

    return {
        "current_agent": "supervisor",
        "similar_incidents": similar_incidents,
        "memory_reasoning": memory_reasoning,
        "campaign_info": campaign_info,
        "messages": [AIMessage(content=f"Supervisor received alert {state['alert_id']}. Found {len(similar_incidents)} similar past incidents.")]
    }


async def enrichment_node(state: SecurityAgentState) -> Dict[str, Any]:
    """
    Context Enrichment Agent - Gather data from SIEM, EDR, Threat Intel
    Uses MCP tools to query external systems
    """
    print(f"\n[ENRICHMENT] Gathering context for alert {state['alert_id']}")

    alert_data = state["alert_data"]
    enrichment_data = {}

    try:
        # Import MCP integration functions
        from src.mcp_integration import (
            get_siem_events,
            get_ip_threat_intel,
            get_user_security_events,
            get_endpoint_security_data
        )

        # 1. Query SIEM for related events
        print(f"  [MCP] Querying SIEM for events from {alert_data.get('source_ip')}")
        siem_result = await get_siem_events(
            source_ip=alert_data.get("source_ip"),
            event_type=alert_data.get("type"),
            user=alert_data.get("user"),
            time_range="last_24h",
            limit=50
        )

        # Validate result type (MCP tools can return strings on error)
        if isinstance(siem_result, dict):
            enrichment_data["siem_logs"] = siem_result.get("events", [])
            print(f"  [MCP] Found {len(enrichment_data['siem_logs'])} SIEM events")
        else:
            print(f"  [MCP] SIEM query returned invalid type: {type(siem_result).__name__}")
            enrichment_data["siem_logs"] = []

        # 2. Get threat intelligence for IP (smart selection of public IP)
        # Choose the IP to query: prefer public IPs over private IPs
        def is_private_ip(ip: str) -> bool:
            """Check if IP is private (RFC 1918)"""
            if not ip:
                return True
            try:
                parts = ip.split('.')
                if len(parts) != 4:
                    return True
                first = int(parts[0])
                second = int(parts[1])
                # Private ranges: 10.x.x.x, 172.16-31.x.x, 192.168.x.x
                if first == 10:
                    return True
                if first == 172 and 16 <= second <= 31:
                    return True
                if first == 192 and second == 168:
                    return True
                return False
            except:
                return True

        # Select best IP to query
        source_ip = alert_data.get("source_ip")
        dest_ip = alert_data.get("destination_ip")

        ip_to_query = None
        if source_ip and not is_private_ip(source_ip):
            ip_to_query = source_ip
        elif dest_ip and not is_private_ip(dest_ip):
            ip_to_query = dest_ip
        elif source_ip:
            ip_to_query = source_ip  # Try anyway

        if ip_to_query:
            print(f"  [MCP] Getting threat intel for {ip_to_query}")
            threat_intel_result = await get_ip_threat_intel(ip_to_query)

            if isinstance(threat_intel_result, dict):
                enrichment_data["threat_intel"] = {
                    "ip_address": threat_intel_result.get("ip_address"),
                    "ip_reputation": threat_intel_result.get("reputation"),
                    "threat_score": threat_intel_result.get("threat_score"),
                    "categories": threat_intel_result.get("categories", []),
                    "first_seen": threat_intel_result.get("first_seen"),
                    "last_seen": threat_intel_result.get("last_seen"),
                    "recommendation": threat_intel_result.get("recommendation"),
                    "source": threat_intel_result.get("source", "unknown"),
                    "malicious_count": threat_intel_result.get("malicious_count", 0),
                    "total_scanners": threat_intel_result.get("total_scanners", 0)
                }
                print(f"  [MCP] IP Reputation: {threat_intel_result.get('reputation')}")
            else:
                print(f"  [MCP] Threat intel query returned invalid type: {type(threat_intel_result).__name__}")
                enrichment_data["threat_intel"] = {}

        # 3. Get user activity history
        if alert_data.get("user"):
            print(f"  [MCP] Getting user events for {alert_data.get('user')}")
            user_result = await get_user_security_events(
                username=alert_data.get("user"),
                time_range="last_7d"
            )

            if isinstance(user_result, dict):
                enrichment_data["user_activity"] = user_result
                print(f"  [MCP] User has {user_result.get('event_count', 0)} security events in last 7 days")
            else:
                print(f"  [MCP] User events query returned invalid type: {type(user_result).__name__}")
                enrichment_data["user_activity"] = {}

        # 4. Get endpoint security data
        if alert_data.get("hostname"):
            print(f"  [MCP] Getting endpoint data for {alert_data.get('hostname')}")
            endpoint_result = await get_endpoint_security_data(alert_data.get("hostname"))

            if isinstance(endpoint_result, dict):
                enrichment_data["endpoint_data"] = endpoint_result
                print(f"  [MCP] Endpoint status: {endpoint_result.get('status', 'unknown')}")
            else:
                print(f"  [MCP] Endpoint query returned invalid type: {type(endpoint_result).__name__}")
                enrichment_data["endpoint_data"] = {}

        message = (
            f"Enrichment completed via MCP: "
            f"gathered {len(enrichment_data.get('siem_logs', []))} SIEM events, "
            f"threat intel for {alert_data.get('source_ip')}, "
            f"user activity for {alert_data.get('user')}"
        )

    except Exception as e:
        # Fallback to simulated data if MCP fails
        print(f"  [WARNING] MCP enrichment failed: {str(e)}")
        print(f"  [WARNING] Using simulated enrichment data as fallback")

        enrichment_data = {
            "siem_logs": [
                {
                    "timestamp": alert_data.get("timestamp"),
                    "source_ip": alert_data.get("source_ip"),
                    "event_count": 15,
                    "related_events": ["failed_login", "port_scan"],
                    "note": "SIMULATED DATA - MCP connection failed"
                }
            ],
            "threat_intel": {
                "ip_reputation": "unknown",
                "threat_score": 0.5,
                "categories": ["unknown"],
                "note": "SIMULATED DATA - MCP connection failed"
            },
            "endpoint_data": {
                "hostname": alert_data.get("hostname", "unknown"),
                "status": "unknown",
                "note": "SIMULATED DATA - MCP connection failed"
            }
        }

        message = f"Enrichment completed with simulated data (MCP unavailable: {str(e)})"

    return {
        "current_agent": "enrichment",
        "enrichment_data": enrichment_data,
        "messages": [AIMessage(content=message)]
    }


async def analysis_node(state: SecurityAgentState) -> Dict[str, Any]:
    """
    Behavioral Analysis Agent - Map to MITRE ATT&CK and calculate threat score
    NOW WITH VISIBLE LLM REASONING
    Uses MITRE RAG with Chroma DB to find matching techniques + LLM for analysis reasoning
    """
    print(f"\n[ANALYSIS] Analyzing threat patterns for alert {state['alert_id']}")

    alert_data = state["alert_data"]
    enrichment_data = state.get("enrichment_data", {})

    try:
        # Import MITRE RAG
        from src.intelligence.mitre_attack import map_alert_to_techniques

        # Use MITRE RAG to map alert to techniques
        print(f"  [MITRE RAG] Mapping alert to MITRE ATT&CK techniques...")
        mitre_mappings = map_alert_to_techniques(alert_data)

        print(f"  [MITRE RAG] Found {len(mitre_mappings)} matching techniques")
        for technique in mitre_mappings[:3]:  # Show top 3
            print(f"    - {technique['technique_id']}: {technique['name']} (confidence: {technique['confidence']:.2%})")

        # Calculate threat score based on MITRE matches
        if mitre_mappings:
            # Base score on highest confidence match
            max_confidence = max(t['confidence'] for t in mitre_mappings)

            # Calculate weighted average of top 3 techniques
            top_techniques = sorted(mitre_mappings, key=lambda x: x['confidence'], reverse=True)[:3]
            weighted_score = sum(t['confidence'] for t in top_techniques) / len(top_techniques)

            # Combine max and weighted (70% weighted, 30% max)
            threat_score = (weighted_score * 0.7) + (max_confidence * 0.3)

            # Determine attack stage and category from top technique
            top_technique = top_techniques[0]
            attack_stage = top_technique.get('tactic', 'Unknown')

            # Derive threat category from tactic
            tactic_to_category = {
                'Initial Access': 'Initial Compromise',
                'Execution': 'Malware Execution',
                'Persistence': 'System Persistence',
                'Privilege Escalation': 'Privilege Abuse',
                'Defense Evasion': 'Detection Evasion',
                'Credential Access': 'Credential Theft',
                'Discovery': 'Reconnaissance',
                'Lateral Movement': 'Network Propagation',
                'Collection': 'Data Harvesting',
                'Command and Control': 'C2 Communication',
                'Exfiltration': 'Data Theft',
                'Impact': 'System Impact'
            }
            threat_category = tactic_to_category.get(attack_stage, 'Suspicious Activity')

        else:
            # No MITRE matches found - use baseline
            print(f"  [MITRE RAG] No techniques matched - using baseline assessment")
            threat_score = 0.50  # Baseline for unknown threats
            attack_stage = "Unknown"
            threat_category = "Unclassified Threat"

        # Adjust score based on enrichment data
        threat_intel = enrichment_data.get("threat_intel", {})

        # IP reputation adjustment with scaled bonus
        ip_reputation = threat_intel.get("ip_reputation", "unknown")
        ti_score = threat_intel.get("threat_score", 0)

        if ip_reputation == "malicious":
            # Base bonus for malicious IP
            bonus = 0.20

            # Scale bonus based on threat intel score (0-10 scale)
            # If very high confidence (>6.0), add extra weight
            if ti_score >= 6.0:
                bonus += 0.30  # Very high confidence (6.0-10.0)
                print(f"  [ANALYSIS] Increasing threat score +{bonus:.2f} (malicious IP, very high confidence: {ti_score}/10)")
            elif ti_score >= 4.0:
                bonus += 0.20  # High confidence (4.0-5.9)
                print(f"  [ANALYSIS] Increasing threat score +{bonus:.2f} (malicious IP, high confidence: {ti_score}/10)")
            elif ti_score >= 2.0:
                bonus += 0.10  # Medium confidence (2.0-3.9)
                print(f"  [ANALYSIS] Increasing threat score +{bonus:.2f} (malicious IP, medium confidence: {ti_score}/10)")
            else:
                print(f"  [ANALYSIS] Increasing threat score +{bonus:.2f} (malicious IP detected)")

            threat_score = min(1.0, threat_score + bonus)

        elif ip_reputation == "suspicious":
            bonus = 0.10 if ti_score >= 3.0 else 0.08
            print(f"  [ANALYSIS] Increasing threat score +{bonus:.2f} (suspicious IP detected)")
            threat_score = min(1.0, threat_score + bonus)

        # SIEM event count adjustment (if available)
        siem_logs = enrichment_data.get("siem_logs", [])
        if len(siem_logs) > 10:
            print(f"  [ANALYSIS] Increasing threat score +0.05 (multiple related events: {len(siem_logs)})")
            threat_score = min(1.0, threat_score + 0.05)

        print(f"  [ANALYSIS] Final threat score: {threat_score:.2f}")
        
        # NEW: Generate LLM reasoning to explain the analysis
        reasoning_text = ""
        try:
            from src.llm_factory import get_llm
            from langchain_core.messages import SystemMessage, HumanMessage

            llm = get_llm(temperature=0.3, streaming=True)

            # Build context for LLM
            mitre_summary = "\n".join([
                f"- {m['technique_id']}: {m['name']} (Confidence: {m['confidence']:.0%})"
                for m in mitre_mappings[:3]
            ]) if mitre_mappings else "No MITRE techniques identified"

            prompt = f"""You are a cybersecurity threat analyst. Analyze this security alert and explain your reasoning step-by-step.

ALERT DETAILS:
- Type: {alert_data.get('type', 'Unknown')}
- Source IP: {alert_data.get('source_ip', 'Unknown')}
- User: {alert_data.get('user', 'Unknown')}
- Hostname: {alert_data.get('hostname', 'Unknown')}

ENRICHMENT DATA:
- SIEM Events: {len(siem_logs)} related events in last 24h
- IP Reputation: {threat_intel.get('ip_reputation', 'unknown')}
- Threat Score: {threat_intel.get('threat_score', 0)}/10
- Categories: {', '.join(threat_intel.get('categories', [])[:3])}

MITRE ATT&CK MAPPINGS (from RAG):
{mitre_summary}

CALCULATED THREAT SCORE: {threat_score:.2f}/1.00

TASK: Provide a step-by-step analysis explaining:
1. What patterns you observe in the data
2. Why you believe this matches the MITRE techniques identified
3. Your reasoning for the threat severity level
4. Key indicators that influenced your decision

Be concise but thorough. Think like a SOC analyst explaining to a colleague."""

            messages = [
                SystemMessage(content="You are an expert cybersecurity analyst. Explain your reasoning clearly."),
                HumanMessage(content=prompt)
            ]

            # Stream LLM reasoning
            print(f"  [ANALYSIS LLM] Generating reasoning...")
            
            async for chunk in llm.astream(messages):
                if chunk.content:
                    reasoning_text += chunk.content

            print(f"  [ANALYSIS LLM] Reasoning complete ({len(reasoning_text)} chars)")

        except Exception as e:
            print(f"  [WARNING] LLM reasoning failed: {e}")
            reasoning_text = f"Analysis reasoning unavailable (LLM error: {str(e)})"

    except Exception as e:
        # Fallback if MITRE RAG fails
        print(f"  [WARNING] MITRE RAG failed: {str(e)}")
        print(f"  [WARNING] Using fallback hardcoded mapping")

        # Fallback to simple hardcoded mapping
        alert_type = alert_data.get("type", "").lower()
        reasoning_text = f"Analysis completed with fallback rules (MITRE RAG unavailable: {str(e)})"

        if "phishing" in alert_type:
            mitre_mappings = [{
                "technique_id": "T1566.001",
                "name": "Phishing: Spearphishing Attachment",
                "tactic": "Initial Access",
                "confidence": 0.92
            }]
            threat_score = 0.85
            attack_stage = "Initial Access"
            threat_category = "Credential Theft"
        elif "brute" in alert_type or "unauthorized" in alert_type:
            mitre_mappings = [{
                "technique_id": "T1110.001",
                "name": "Brute Force: Password Guessing",
                "tactic": "Credential Access",
                "confidence": 0.88
            }]
            threat_score = 0.75
            attack_stage = "Credential Access"
            threat_category = "Account Compromise"
        elif "malware" in alert_type:
            mitre_mappings = [{
                "technique_id": "T1071.001",
                "name": "Application Layer Protocol: Web Protocols",
                "tactic": "Command and Control",
                "confidence": 0.90
            }]
            threat_score = 0.95
            attack_stage = "Command and Control"
            threat_category = "Malware Execution"
        else:
            mitre_mappings = []
            threat_score = 0.60
            attack_stage = "Unknown"
            threat_category = "Suspicious Activity"

    return {
        "current_agent": "analysis",
        "mitre_mappings": mitre_mappings,
        "threat_score": threat_score,
        "attack_stage": attack_stage,
        "threat_category": threat_category,
        "analysis_reasoning": reasoning_text,  # NEW FIELD: LLM explanation
        "messages": [AIMessage(content=f"Analysis completed with LLM reasoning: {len(mitre_mappings)} MITRE techniques found, threat score: {threat_score:.2f}")]
    }


async def investigation_node(state: SecurityAgentState) -> Dict[str, Any]:
    """
    Deep Investigation Agent - Generate investigation plan and findings using LLM
    Only triggered for high-severity alerts
    NOW WITH LLM-POWERED INVESTIGATION PLAN AND FINDINGS
    """
    print(f"\n[INVESTIGATION] Deep investigation for alert {state['alert_id']}")

    threat_score = state.get("threat_score", 0.0)

    # Only investigate if threat score is high
    if threat_score < 0.60:
        return {
            "current_agent": "investigation",
            "investigation_plan": ["Skip deep investigation - low threat score"],
            "investigation_findings": {"skipped": True, "reason": "Low threat score"},
            "messages": [AIMessage(content="Investigation skipped: threat score below threshold")]
        }

    alert_data = state.get("alert_data", {})
    enrichment_data = state.get("enrichment_data", {})
    mitre_mappings = state.get("mitre_mappings", [])
    attack_stage = state.get("attack_stage", "Unknown")
    threat_category = state.get("threat_category", "Unknown")

    # Initialize reasoning (will be populated by LLM)
    investigation_reasoning = ""

    try:
        from src.llm_factory import get_llm
        from langchain_core.messages import SystemMessage, HumanMessage
        import json

        llm = get_llm(temperature=0.4, streaming=True)

        # Build context for investigation
        mitre_summary = "\n".join([
            f"- {m['technique_id']}: {m['name']} (Confidence: {m['confidence']:.0%})"
            for m in mitre_mappings[:5]
        ]) if mitre_mappings else "No MITRE techniques identified"

        threat_intel = enrichment_data.get("threat_intel", {})
        siem_logs = enrichment_data.get("siem_logs", [])

        # Step 1: Generate investigation plan using LLM
        print(f"  [INVESTIGATION LLM] Generating investigation plan...")
        
        plan_prompt = f"""You are a Senior SOC Investigator. Based on this security alert, generate a detailed investigation plan.

ALERT CONTEXT:
- Alert ID: {state.get('alert_id', 'Unknown')}
- Type: {alert_data.get('type', 'Unknown')}
- Source IP: {alert_data.get('source_ip', 'Unknown')}
- Destination IP: {alert_data.get('destination_ip', 'Unknown')}
- User: {alert_data.get('user', 'Unknown')}
- Hostname: {alert_data.get('hostname', 'Unknown')}
- Threat Score: {threat_score:.2f}/1.00
- Attack Stage: {attack_stage}
- Threat Category: {threat_category}

MITRE ATT&CK TECHNIQUES:
{mitre_summary}

THREAT INTELLIGENCE:
- IP Reputation: {threat_intel.get('ip_reputation', 'unknown')}
- Threat Score: {threat_intel.get('threat_score', 0)}/10
- Categories: {', '.join(threat_intel.get('categories', [])[:5])}
- SIEM Events: {len(siem_logs)} related events

TASK: Generate a focused investigation plan with 4-6 specific, actionable steps.
Each step should be:
1. Specific and actionable (e.g., "Query SIEM for failed logins from IP X in last 24h")
2. Relevant to the threat type and MITRE techniques
3. Prioritized by potential impact

Format your response as a JSON array of investigation steps:
["Step 1 description", "Step 2 description", ...]

Example format:
["Check user's recent login history for suspicious patterns", "Review network traffic logs for connections to/from source IP", "Scan endpoint for malware artifacts and suspicious processes", "Query threat intel for additional indicators related to this IP"]

Return ONLY the JSON array, no additional text."""

        plan_messages = [
            SystemMessage(content="You are an expert SOC investigator. Generate precise, actionable investigation plans. Return only valid JSON arrays."),
            HumanMessage(content=plan_prompt)
        ]

        plan_response = ""
        async for chunk in llm.astream(plan_messages):
            if chunk.content:
                plan_response += chunk.content

        print(f"  [INVESTIGATION LLM] Plan generated ({len(plan_response)} chars)")

        # Parse investigation plan
        try:
            # Clean response (remove markdown code blocks if present)
            plan_text = plan_response.strip()
            if plan_text.startswith("```"):
                plan_text = plan_text.split("```")[1]
                if plan_text.startswith("json"):
                    plan_text = plan_text[4:]
            plan_text = plan_text.strip()
            
            investigation_plan = json.loads(plan_text)
            if not isinstance(investigation_plan, list):
                investigation_plan = [str(investigation_plan)]
        except json.JSONDecodeError as e:
            print(f"  [WARNING] Failed to parse plan JSON: {e}")
            print(f"  [WARNING] Raw response: {plan_response[:200]}")
            # Fallback: extract steps from text
            investigation_plan = [
                "Check user's recent login history",
                "Review network traffic to/from source IP",
                "Scan endpoint for malware artifacts",
                "Check similar alerts in past 7 days"
            ]

        # Step 2: Generate investigation findings using LLM
        print(f"  [INVESTIGATION LLM] Generating investigation findings...")

        findings_prompt = f"""Based on the investigation plan and alert context, generate realistic investigation findings.

INVESTIGATION PLAN:
{json.dumps(investigation_plan, indent=2)}

ALERT CONTEXT:
- Alert ID: {state.get('alert_id', 'Unknown')}
- Type: {alert_data.get('type', 'Unknown')}
- Source IP: {alert_data.get('source_ip', 'Unknown')}
- User: {alert_data.get('user', 'Unknown')}
- Threat Score: {threat_score:.2f}/1.00
- MITRE Techniques: {', '.join([m['technique_id'] for m in mitre_mappings[:3]])}

TASK: Generate realistic investigation findings as a JSON object. Include:
- user_history: recent_logins (int), failed_attempts (int), unusual_locations (array)
- network_traffic: total_bytes (int), suspicious_domains (array), c2_indicators (bool)
- endpoint_scan: malware_found (bool), files_quarantined (array), registry_changes (int)
- historical_alerts: similar_alerts (int), same_ip (int)

Make findings consistent with the threat score and alert type. If threat_score > 0.8, findings should show more severe indicators.

Return ONLY valid JSON, no additional text.
Example format:
{{
  "user_history": {{"recent_logins": 25, "failed_attempts": 3, "unusual_locations": ["Russia"]}},
  "network_traffic": {{"total_bytes": 1048576, "suspicious_domains": ["malicious-site.com"], "c2_indicators": true}},
  "endpoint_scan": {{"malware_found": true, "files_quarantined": ["invoice.exe"], "registry_changes": 5}},
  "historical_alerts": {{"similar_alerts": 2, "same_ip": 1}}
}}"""

        findings_messages = [
            SystemMessage(content="You are a SOC investigator reporting findings. Generate realistic, structured investigation results. Return only valid JSON."),
            HumanMessage(content=findings_prompt)
        ]

        findings_response = ""
        async for chunk in llm.astream(findings_messages):
            if chunk.content:
                findings_response += chunk.content

        print(f"  [INVESTIGATION LLM] Findings generated ({len(findings_response)} chars)")

        # Parse investigation findings
        try:
            # Clean response
            findings_text = findings_response.strip()
            if findings_text.startswith("```"):
                findings_text = findings_text.split("```")[1]
                if findings_text.startswith("json"):
                    findings_text = findings_text[4:]
            findings_text = findings_text.strip()
            
            investigation_findings = json.loads(findings_text)
        except json.JSONDecodeError as e:
            print(f"  [WARNING] Failed to parse findings JSON: {e}")
            print(f"  [WARNING] Raw response: {findings_response[:200]}")
            # Fallback findings
            investigation_findings = {
                "user_history": {
                    "recent_logins": 25,
                    "failed_attempts": 3,
                    "unusual_locations": ["Unknown"]
                },
                "network_traffic": {
                    "total_bytes": 0,
                    "suspicious_domains": [],
                    "c2_indicators": False
                },
                "endpoint_scan": {
                    "malware_found": False,
                    "files_quarantined": [],
                    "registry_changes": 0
                },
                "historical_alerts": {
                    "similar_alerts": 0,
                    "same_ip": 0
                }
            }

        print(f"  [INVESTIGATION] Plan: {len(investigation_plan)} steps")
        print(f"  [INVESTIGATION] Findings: {len(investigation_findings)} categories")

        # Step 3: Generate investigation reasoning using LLM
        print(f"  [INVESTIGATION LLM] Generating investigation reasoning...")
        
        reasoning_prompt = f"""You are a Senior SOC Investigator. Explain your investigation approach and findings.

INVESTIGATION PLAN:
{json.dumps(investigation_plan, indent=2)}

INVESTIGATION FINDINGS:
{json.dumps(investigation_findings, indent=2)}

ALERT CONTEXT:
- Alert ID: {state.get('alert_id', 'Unknown')}
- Type: {alert_data.get('type', 'Unknown')}
- Threat Score: {threat_score:.2f}/1.00
- Attack Stage: {attack_stage}
- MITRE Techniques: {', '.join([m['technique_id'] for m in mitre_mappings[:3]])}

TASK: Provide a clear, step-by-step explanation of:
1. Why you chose this investigation plan (what indicators led to these specific steps)
2. What the findings reveal about the threat (interpretation of the data collected)
3. How the findings relate to the threat score and MITRE techniques
4. Key insights or concerns discovered during the investigation

IMPORTANT: 
- Focus ONLY on explaining the investigation process and findings
- DO NOT provide recommendations or next steps (that's handled by the Response Agent)
- DO NOT suggest remediation actions
- Just explain what you investigated and what you found

Be concise but thorough. Think like a SOC analyst explaining to a colleague why you investigated this way and what you discovered."""

        reasoning_messages = [
            SystemMessage(content="You are an expert SOC investigator. Explain your investigation reasoning clearly and concisely. Focus on explaining what you investigated and what you found - do NOT provide recommendations or next steps."),
            HumanMessage(content=reasoning_prompt)
        ]

        investigation_reasoning = ""
        async for chunk in llm.astream(reasoning_messages):
            if chunk.content:
                investigation_reasoning += chunk.content

        print(f"  [INVESTIGATION LLM] Reasoning complete ({len(investigation_reasoning)} chars)")

    except Exception as e:
        print(f"  [WARNING] LLM investigation failed: {e}")
        # Fallback to hardcoded plan
        investigation_plan = [
            "Check user's recent login history",
            "Review network traffic to/from source IP",
            "Scan endpoint for malware artifacts",
            "Check similar alerts in past 7 days"
        ]
        investigation_findings = {
            "user_history": {
                "recent_logins": 25,
                "failed_attempts": 3,
                "unusual_locations": ["Unknown"]
            },
            "network_traffic": {
                "total_bytes": 0,
                "suspicious_domains": [],
                "c2_indicators": False
            },
            "endpoint_scan": {
                "malware_found": False,
                "files_quarantined": [],
                "registry_changes": 0
            },
            "historical_alerts": {
                "similar_alerts": 0,
                "same_ip": 0
            }
        }
        investigation_reasoning = f"Investigation reasoning unavailable (LLM error: {str(e)})"

    return {
        "current_agent": "investigation",
        "investigation_plan": investigation_plan,
        "investigation_findings": investigation_findings,
        "investigation_reasoning": investigation_reasoning,  # NEW FIELD: LLM explanation
        "messages": [AIMessage(content=f"Investigation completed: {len(investigation_plan)} steps executed")]
    }


async def response_node(state: SecurityAgentState) -> Dict[str, Any]:
    """
    Response Orchestration Agent - Generate remediation playbook using AI
    NOW WITH TOKEN-BY-TOKEN STREAMING
    Creates contextual, specific recommendations based on threat intelligence
    """
    print(f"\n[RESPONSE] Generating AI-powered response playbook for alert {state['alert_id']}")

    threat_score = state.get("threat_score", 0.0)
    attack_stage = state.get("attack_stage", "Unknown")
    threat_category = state.get("threat_category", "Unknown")
    mitre_mappings = state.get("mitre_mappings", [])
    alert_data = state.get("alert_data", {})
    enrichment_data = state.get("enrichment_data", {})

    # Determine severity based on threat score
    if threat_score >= 0.85:
        severity = "CRITICAL"
    elif threat_score >= 0.65:  # Lowered from 0.70
        severity = "HIGH"
    elif threat_score >= 0.45:
        severity = "MEDIUM"
    else:
        severity = "LOW"

    # Try to generate AI recommendations
    try:
        from src.llm_factory import get_llm
        from langchain_core.messages import HumanMessage, SystemMessage

        llm = get_llm(streaming=True)  # ✅ Enable streaming

        # Build context for LLM
        threat_intel = enrichment_data.get("threat_intel", {})

        # MITRE techniques summary
        mitre_summary = "\n".join([
            f"- {m['technique_id']}: {m['name']} (Tactic: {m.get('tactic', 'Unknown')})"
            for m in mitre_mappings[:3]
        ]) if mitre_mappings else "No MITRE techniques identified"

        # Threat intel summary
        ti_summary = f"""
IP Reputation: {threat_intel.get('ip_reputation', 'unknown')}
Threat Score: {threat_intel.get('threat_score', 0)}/10
Source: {threat_intel.get('source', 'unknown')}
Detections: {threat_intel.get('malicious_count', 0)}/{threat_intel.get('total_scanners', 0)}
Categories: {', '.join(threat_intel.get('categories', [])[:5])}
"""

        prompt = f"""You are a cybersecurity incident response expert. Generate specific, actionable remediation steps for this security alert.

ALERT DETAILS:
- Alert Type: {alert_data.get('type', 'Unknown')}
- Severity: {severity}
- Threat Score: {threat_score:.2f}/1.00
- Attack Stage: {attack_stage}
- Threat Category: {threat_category}

AFFECTED ASSETS:
- User: {alert_data.get('user', 'Unknown')}
- Hostname: {alert_data.get('hostname', 'Unknown')}
- Source IP: {alert_data.get('source_ip', 'Unknown')}
- Destination IP: {alert_data.get('destination_ip', 'Unknown')}

MITRE ATT&CK MAPPINGS:
{mitre_summary}

THREAT INTELLIGENCE:
{ti_summary}

TASK: Generate {5 if severity in ['CRITICAL', 'HIGH'] else 4} specific remediation actions in order of priority.

REQUIREMENTS:
1. Start with most critical/immediate actions first
2. For {severity} severity alerts, use prefixes:
   - CRITICAL/HIGH: "IMMEDIATE:" or "URGENT:" for time-sensitive actions
   - MEDIUM/LOW: No prefix needed
3. Be specific to the attack type and MITRE techniques
4. Include technical details (which logs to check, what to block, where to isolate)
5. Consider the actual IPs, user, and hostname in your recommendations
6. Each action should be ONE clear sentence

FORMAT: Return ONLY a numbered list, one action per line. No extra text.

Example for brute force:
1. IMMEDIATE: Isolate endpoint {alert_data.get('hostname', 'WS-XXX')} from network to prevent lateral movement
2. IMMEDIATE: Force password reset for user {alert_data.get('user', 'user@company.com')} across all systems
3. URGENT: Block source IP {alert_data.get('source_ip', 'X.X.X.X')} at perimeter firewall and update threat intel feeds
4. Review authentication logs for the last 24 hours for other affected accounts
5. Enable MFA for affected user and review account permissions

Now generate recommendations for THIS alert:"""

        messages = [
            SystemMessage(content="You are a cybersecurity incident response expert. Be specific and actionable."),
            HumanMessage(content=prompt)
        ]

        print(f"  [RESPONSE] Streaming LLM recommendations...")
        
        # Stream response token by token
        recommendations_text = ""
        async for chunk in llm.astream(messages):
            if chunk.content:
                recommendations_text += chunk.content
                # Tokens will be captured by astream_events()

        print(f"  [RESPONSE] Streaming complete ({len(recommendations_text)} chars)")
        
        recommendations_text = recommendations_text.strip()

        # Extract numbered list
        recommendations = []
        for line in recommendations_text.split('\n'):
            line = line.strip()
            # Remove numbering (1., 2., etc.)
            if line and (line[0].isdigit() or line.startswith('-')):
                # Remove leading numbers and punctuation
                cleaned = line.lstrip('0123456789.-) ').strip()
                if cleaned:
                    recommendations.append(cleaned)

        print(f"  [RESPONSE] Generated {len(recommendations)} AI recommendations")

    except Exception as e:
        print(f"  [WARNING] AI recommendation generation failed: {e}")
        print(f"  [WARNING] Falling back to rule-based recommendations")

        # Fallback to hardcoded recommendations
        recommendations_text = f"Using rule-based recommendations (LLM unavailable: {str(e)})"
        
        if threat_score >= 0.90:
            recommendations = [
                "IMMEDIATE: Isolate affected endpoint from network",
                "IMMEDIATE: Reset user credentials",
                "URGENT: Block source IP at firewall",
                "Conduct full endpoint forensics",
                "Notify security leadership immediately"
            ]
        elif threat_score >= 0.70:
            recommendations = [
                "Isolate affected endpoint",
                "Reset user password",
                "Block source IP temporarily",
                "Review related logs for 24 hours",
                "Notify security team"
            ]
        else:
            recommendations = [
                "Monitor user activity for 24 hours",
                "Review endpoint logs",
                "Add source IP to watchlist",
                "Document in incident tracking system"
            ]

    # Build remediation playbook
    remediation_playbook = {
        "severity": severity,
        "estimated_time": "15 minutes" if severity == "CRITICAL" else "30 minutes" if severity == "HIGH" else "1 hour"
    }

    # Categorize actions by urgency
    immediate_actions = []
    follow_up_actions = []

    for i, rec in enumerate(recommendations, 1):
        action_item = {"action": rec, "priority": i}

        if "IMMEDIATE" in rec or "URGENT" in rec:
            immediate_actions.append(action_item)
        else:
            follow_up_actions.append(action_item)

    remediation_playbook["immediate_actions"] = immediate_actions if immediate_actions else [{"action": recommendations[0], "priority": 1}]
    remediation_playbook["follow_up_actions"] = follow_up_actions if follow_up_actions else []

    # Add MITRE-specific mitigations
    if mitre_mappings:
        remediation_playbook["mitre_techniques"] = [
            {
                "technique_id": m['technique_id'],
                "name": m['name'],
                "tactic": m.get('tactic', 'Unknown')
            }
            for m in mitre_mappings[:3]
        ]

    return {
        "current_agent": "response",
        "recommendations": recommendations,
        "remediation_playbook": remediation_playbook,
        "response_reasoning": recommendations_text,  # NEW FIELD: Full streamed text
        "messages": [AIMessage(content=f"Response playbook generated with streaming: {len(recommendations)} recommendations")]
    }


async def communication_node(state: SecurityAgentState) -> Dict[str, Any]:
    """
    Communication Agent - Generate human-readable report
    Creates final investigation report
    """
    print(f"\n[COMMUNICATION] Generating report for alert {state['alert_id']}")

    alert_data = state["alert_data"]
    threat_score = state.get("threat_score", 0.0)
    attack_stage = state.get("attack_stage", "Unknown")
    mitre_mappings = state.get("mitre_mappings", [])
    recommendations = state.get("recommendations", [])

    # Generate structured report
    report = f"""
SECURITY ALERT INVESTIGATION REPORT
=====================================

Alert ID: {state['alert_id']}
Timestamp: {state['timestamp']}
Alert Type: {alert_data.get('type', 'Unknown')}

THREAT ASSESSMENT
-----------------
Threat Score: {threat_score:.2f} / 1.00
Attack Stage: {attack_stage}
Threat Category: {state.get('threat_category', 'Unknown')}

MITRE ATT&CK MAPPINGS
---------------------
"""

    if mitre_mappings:
        for mapping in mitre_mappings:
            report += f"- {mapping['technique_id']}: {mapping['name']} (Confidence: {mapping['confidence']:.0%})\n"
    else:
        report += "- No MITRE techniques identified\n"

    report += f"""
RECOMMENDATIONS
---------------
"""
    for i, rec in enumerate(recommendations, 1):
        report += f"{i}. {rec}\n"

    report += f"""
INVESTIGATION STATUS
--------------------
Status: {state.get('workflow_status', 'completed')}
Investigated By: SOC Orchestrator AI
Session: {state.get('session_id', 'unknown')}
"""

    # Simulate notification sending
    notifications_sent = [
        {
            "channel": "slack",
            "recipient": "#security-alerts",
            "sent_at": state['timestamp'],
            "status": "success"
        }
    ]

    return {
        "current_agent": "communication",
        "report": report,
        "notifications_sent": notifications_sent,
        "workflow_status": "completed",
        "messages": [AIMessage(content="Investigation report generated and notifications sent")]
    }


async def memory_save_node(state: SecurityAgentState) -> Dict[str, Any]:
    """
    Memory Save - Save investigation to long-term memory and detect campaigns
    """
    print(f"\n[MEMORY] Saving investigation results...")

    try:
        from src.memory.manager import get_memory_manager

        memory_manager = get_memory_manager()

        # Save incident to memory
        incident_id = await memory_manager.save_incident(
            user_id="default_user",  # In production: get from authentication context
            incident_data=dict(state)
        )

        print(f"[MEMORY] ✅ Investigation saved: {incident_id}")

        # TODO: Check for campaign detection (Phase 2)
        # campaign_info = await campaign_detector.check_for_campaign(...)

        return {
            "current_agent": "memory_save",
            "messages": [AIMessage(content=f"Investigation {incident_id} saved to memory")]
        }

    except Exception as e:
        print(f"[MEMORY] ⚠️  Error saving to memory: {e}")
        print(f"[MEMORY] Investigation completed without memory persistence")

        return {
            "current_agent": "memory_save",
            "error": f"Memory save failed: {str(e)}",
            "messages": [AIMessage(content="Memory save failed, but investigation completed successfully")]
        }


# ===== Conditional Edges =====

def should_investigate(state: SecurityAgentState) -> str:
    """
    Decide whether to perform deep investigation based on threat score
    """
    threat_score = state.get("threat_score", 0.0)

    if threat_score >= 0.60:
        return "investigate"
    else:
        return "skip_investigation"


# ===== Build Graph =====

def create_investigation_graph() -> StateGraph:
    """
    Create the main investigation workflow graph (non-streaming)

    Workflow:
    1. Supervisor receives alert
    2. Enrichment gathers context
    3. Analysis maps MITRE and scores threat
    4. Investigation (conditional - only if high threat)
    5. Response generates playbook
    6. Communication creates report
    """

    # Initialize graph
    workflow = StateGraph(SecurityAgentState)

    # Add nodes
    workflow.add_node("supervisor", supervisor_node)
    workflow.add_node("enrichment", enrichment_node)
    workflow.add_node("analysis", analysis_node)
    workflow.add_node("investigation", investigation_node)
    workflow.add_node("response", response_node)
    workflow.add_node("communication", communication_node)
    workflow.add_node("memory_save", memory_save_node)

    # Define edges (workflow flow)
    workflow.set_entry_point("supervisor")
    workflow.add_edge("supervisor", "enrichment")
    workflow.add_edge("enrichment", "analysis")

    # Conditional edge: investigate only if high threat
    workflow.add_conditional_edges(
        "analysis",
        should_investigate,
        {
            "investigate": "investigation",
            "skip_investigation": "response"
        }
    )

    workflow.add_edge("investigation", "response")
    workflow.add_edge("response", "communication")
    workflow.add_edge("communication", "memory_save")
    workflow.add_edge("memory_save", END)

    # Compile graph
    app = workflow.compile()

    return app


# ===== Compiled Graph for LangGraph Studio =====

# Create and export compiled graph instance for langgraph dev
graph = create_investigation_graph()


# ===== Execution Function =====

async def investigate_alert(alert_data: Dict[str, Any]) -> SecurityAgentState:
    """
    Main entry point for alert investigation (non-streaming)

    Args:
        alert_data: Raw alert dictionary

    Returns:
        Complete SecurityAgentState with all investigation results
    """
    # Create initial state
    initial_state = create_initial_state(alert_data)

    # Create graph
    graph = create_investigation_graph()

    # Execute workflow (non-streaming - returns complete result)
    print(f"\n{'='*60}")
    print(f"STARTING INVESTIGATION: {initial_state['alert_id']}")
    print(f"{'='*60}")

    final_state = await graph.ainvoke(initial_state)

    print(f"\n{'='*60}")
    print(f"INVESTIGATION COMPLETED")
    print(f"{'='*60}")
    print(f"Threat Score: {final_state.get('threat_score', 0.0):.2f}")
    print(f"Status: {final_state.get('workflow_status', 'unknown')}")

    return final_state


async def investigate_alert_streaming(alert_data: Dict[str, Any]):
    """
    Streaming version of alert investigation with LLM token streaming support
    Uses astream_events() to capture granular events including LLM tokens
    
    Args:
        alert_data: Raw alert dictionary

    Yields:
        Dict with event information:
        {
            "type": "node_start" | "node_complete" | "state_update" | "llm_token" | "llm_reasoning_start" | "llm_reasoning_complete" | "final",
            "node": str,  # Current node name
            "message": str,  # Human-readable message (for llm_token: the actual token)
            "data": dict,  # Additional event data
            "state": SecurityAgentState  # Current state snapshot
        }
    """
    from datetime import datetime

    # Create initial state
    initial_state = create_initial_state(alert_data)

    # Create graph
    graph = create_investigation_graph()

    alert_id = initial_state['alert_id']

    # Yield start event
    yield {
        "type": "investigation_start",
        "node": "system",
        "message": f"Starting investigation for alert {alert_id}",
        "data": {"alert_id": alert_id},
        "state": initial_state
    }

    # Track current node and state
    current_node = None
    prev_state = initial_state.copy()
    current_state = initial_state.copy()

    # Use astream_events for fine-grained streaming
    # This captures LLM tokens, chain events, and more
    try:
        async for event in graph.astream_events(initial_state, version="v2"):
            event_type = event.get("event")
            event_name = event.get("name", "")
            event_data = event.get("data", {})

            # Handle different event types
            if event_type == "on_chain_start":
                # Node started
                # Check if this is a main node (not a subchain)
                if event_name in ["supervisor", "enrichment", "analysis", "investigation", "response", "communication"]:
                    current_node = event_name
                    
                    yield {
                        "type": "node_start",
                        "node": current_node,
                        "message": f"Node {current_node.upper()} started processing",
                        "data": {},
                        "state": prev_state
                    }

            elif event_type == "on_chain_end":
                # Node completed
                if event_name in ["supervisor", "enrichment", "analysis", "investigation", "response", "communication"]:
                    output = event_data.get("output", {})
                    
                    # Update state with output
                    if isinstance(output, dict):
                        current_state = {**prev_state, **output}
                    else:
                        current_state = prev_state
                    
                    # Extract meaningful events from state changes
                    events = _extract_node_events(event_name, prev_state, current_state)
                    
                    # Yield each sub-event
                    for sub_event in events:
                        yield {
                            "type": "state_update",
                            "node": event_name,
                            "message": sub_event["message"],
                            "data": sub_event.get("data", {}),
                            "state": current_state
                        }

                    yield {
                        "type": "node_complete",
                        "node": event_name,
                        "message": f"Node {event_name.upper()} completed",
                        "data": {},
                        "state": current_state
                    }

                    prev_state = current_state.copy()

            elif event_type == "on_chat_model_start":
                # LLM invocation started
                yield {
                    "type": "llm_reasoning_start",
                    "node": current_node or "unknown",
                    "message": f"[{(current_node or 'unknown').upper()}] 🤔 Thinking...",
                    "data": {},
                    "state": prev_state
                }

            elif event_type == "on_chat_model_stream":
                # LLM token streamed! This is the KEY event
                chunk = event_data.get("chunk", {})
                
                # Extract token content
                token = ""
                if hasattr(chunk, 'content'):
                    token = chunk.content
                elif isinstance(chunk, dict) and 'content' in chunk:
                    token = chunk['content']
                elif isinstance(chunk, str):
                    token = chunk

                if token:
                    yield {
                        "type": "llm_token",
                        "node": current_node or "unknown",
                        "message": token,  # Individual token
                        "data": {"token": token},
                        "state": prev_state
                    }

            elif event_type == "on_chat_model_end":
                # LLM invocation completed
                yield {
                    "type": "llm_reasoning_complete",
                    "node": current_node or "unknown",
                    "message": f"[{(current_node or 'unknown').upper()}] ✅ Reasoning complete",
                    "data": {},
                    "state": prev_state
                }

    except Exception as e:
        # If astream_events fails, yield error event
        yield {
            "type": "error",
            "node": current_node or "system",
            "message": f"Streaming error: {str(e)}",
            "data": {"error": str(e)},
            "state": prev_state
        }

    # Yield final event
    yield {
        "type": "investigation_complete",
        "node": "system",
        "message": f"Investigation completed - Threat Score: {current_state.get('threat_score', 0.0):.2f}",
        "data": {
            "threat_score": current_state.get("threat_score", 0.0),
            "mitre_techniques": len(current_state.get("mitre_mappings", [])),
            "recommendations": len(current_state.get("recommendations", []))
        },
        "state": current_state
    }


def _extract_node_events(node_name: str, prev_state: Dict, current_state: Dict) -> List[Dict]:
    """
    Extract meaningful events from state changes for a specific node

    Args:
        node_name: Name of the node that just executed
        prev_state: State before node execution
        current_state: State after node execution

    Returns:
        List of event dictionaries with messages and data
    """
    events = []

    if node_name == "supervisor":
        # Supervisor routes the workflow
        events.append({
            "message": f"Alert {current_state.get('alert_id')} received and routed to enrichment",
            "data": {"alert_type": current_state.get('alert_data', {}).get('type', 'unknown')}
        })

    elif node_name == "enrichment":
        # Check what data was enriched
        enrichment = current_state.get("enrichment_data", {})

        # SIEM logs
        siem_logs = enrichment.get("siem_logs", [])
        if siem_logs:
            events.append({
                "message": f"Found {len(siem_logs)} related events in SIEM",
                "data": {"siem_event_count": len(siem_logs)}
            })
        else:
            events.append({
                "message": "No related events found in SIEM",
                "data": {"siem_event_count": 0}
            })

        # Threat intel
        threat_intel = enrichment.get("threat_intel", {})
        if threat_intel:
            reputation = threat_intel.get("ip_reputation", "unknown")
            confidence = threat_intel.get("confidence", 0)
            events.append({
                "message": f"Threat Intel: IP reputation = {reputation.upper()} (confidence: {confidence}/10)",
                "data": {"reputation": reputation, "confidence": confidence}
            })

        # User events
        user_events = enrichment.get("user_events", {})
        if user_events:
            event_count = user_events.get("event_count", 0)
            events.append({
                "message": f"User has {event_count} security events in last 7 days",
                "data": {"user_event_count": event_count}
            })

        # Endpoint data
        endpoint_data = enrichment.get("endpoint_data", {})
        if endpoint_data:
            hostname = endpoint_data.get("hostname", "unknown")
            status = endpoint_data.get("endpoint_status", "unknown")
            events.append({
                "message": f"Endpoint {hostname}: status = {status}",
                "data": {"hostname": hostname, "status": status}
            })

    elif node_name == "analysis":
        # Check MITRE mappings
        mitre_mappings = current_state.get("mitre_mappings", [])
        if mitre_mappings:
            events.append({
                "message": f"Mapped to {len(mitre_mappings)} MITRE ATT&CK technique(s)",
                "data": {"technique_count": len(mitre_mappings)}
            })

            # Show each technique
            for mapping in mitre_mappings[:3]:  # Show first 3
                technique_id = mapping.get("technique_id", "unknown")
                technique_name = mapping.get("name", "unknown")
                confidence = mapping.get("confidence", 0.0)
                events.append({
                    "message": f"  -> {technique_id}: {technique_name} (confidence: {confidence:.1%})",
                    "data": {"technique": technique_id, "name": technique_name, "confidence": confidence}
                })

        # Threat score
        threat_score = current_state.get("threat_score", 0.0)
        prev_score = prev_state.get("threat_score", 0.0)
        if threat_score != prev_score:
            events.append({
                "message": f"Threat score calculated: {threat_score:.2f}/1.00",
                "data": {"threat_score": threat_score}
            })

        # Attack stage
        attack_stage = current_state.get("attack_stage", "")
        if attack_stage:
            events.append({
                "message": f"Attack stage: {attack_stage}",
                "data": {"attack_stage": attack_stage}
            })

    elif node_name == "investigation":
        # Investigation findings
        findings = current_state.get("investigation_findings", {})
        if findings:
            events.append({
                "message": f"Deep investigation completed with {len(findings)} findings",
                "data": {"finding_count": len(findings)}
            })

    elif node_name == "response":
        # Recommendations
        recommendations = current_state.get("recommendations", [])
        if recommendations:
            events.append({
                "message": f"Generated {len(recommendations)} remediation recommendation(s)",
                "data": {"recommendation_count": len(recommendations)}
            })

            # Show first few recommendations
            for i, rec in enumerate(recommendations[:2], 1):
                events.append({
                    "message": f"  {i}. {rec[:80]}{'...' if len(rec) > 80 else ''}",
                    "data": {"recommendation": rec}
                })

    elif node_name == "communication":
        # Report generation
        report = current_state.get("report", "")
        if report:
            events.append({
                "message": f"Investigation report generated ({len(report)} characters)",
                "data": {"report_length": len(report)}
            })

    return events


# ===== Example Usage =====

if __name__ == "__main__":
    import asyncio
    import json
    from pathlib import Path

    # Load sample alert
    data_dir = Path(__file__).parent.parent / "data"
    with open(data_dir / "sample_alerts.json", "r") as f:
        alerts = json.load(f)

    # Test with first alert
    sample_alert = alerts[0]

    # Run investigation
    result = asyncio.run(investigate_alert(sample_alert))

    # Print report
    print("\n" + "="*60)
    print("FINAL REPORT")
    print("="*60)
    print(result.get("report", "No report generated"))
