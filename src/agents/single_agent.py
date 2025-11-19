"""
Single ReAct Agent for Security Investigation
Uses Reasoning + Acting pattern with MCP tools
"""

from typing import Dict, Any, List
from langchain_core.messages import SystemMessage, HumanMessage, AIMessage
from langchain_core.tools import BaseTool
from langchain.agents import create_agent

from src.config import Config
from src.mcp_integration import MCPClientManager
from src.llm_factory import get_llm


# ===== System Prompts =====

SECURITY_ANALYST_SYSTEM_PROMPT = """You are a Senior Security Analyst in a Security Operations Center (SOC).

Your role is to investigate security alerts using available tools and your security expertise.

**Investigation Approach:**
1. Gather context about the alert (query SIEM, check threat intel, examine endpoints)
2. Analyze the data to understand the threat
3. Map to MITRE ATT&CK framework
4. Calculate threat severity
5. Provide remediation recommendations

**Available Tools:**
You have access to MCP tools for:
- Querying SIEM for security events
- Getting threat intelligence on IPs
- Retrieving user activity
- Getting endpoint security data
- Searching logs
- Finding related events

**Guidelines:**
- Always gather evidence before drawing conclusions
- Use multiple data sources to corroborate findings
- Reference specific events, IPs, timestamps in your analysis
- Map findings to MITRE ATT&CK techniques when applicable
- Provide actionable recommendations based on severity
- Be thorough but efficient - SOC analysts need quick answers

**Response Format:**
1. Initial Assessment (what we know from the alert)
2. Evidence Gathering (use tools to collect data)
3. Analysis (what the evidence tells us)
4. MITRE Mapping (relevant ATT&CK techniques)
5. Threat Score (0.0-1.0 with justification)
6. Recommendations (specific actions to take)

Think step-by-step and use the available tools to build a complete picture.
"""


# ===== ReAct Agent Factory =====

async def create_security_agent(tools: List[BaseTool] = None) -> Any:
    """
    Create a ReAct agent for security investigation

    Args:
        tools: Optional list of tools (if None, will load from MCP)

    Returns:
        Compiled ReAct agent
    """
    # Initialize LLM (provider determined by LLM_PROVIDER env var)
    llm = get_llm(
        temperature=0.1,  # Low temperature for factual analysis
        streaming=False   # Non-streaming for structured investigation
    )

    # Get tools if not provided
    if tools is None:
        mcp_manager = MCPClientManager()
        tools = await mcp_manager.get_tools()

    # Create agent using LangChain 1.0 API
    # Migrated from langgraph.prebuilt.create_react_agent (deprecated)
    # New API uses LangGraph internally with improved features
    agent = create_agent(
        model=llm,
        tools=tools,
        system_prompt=SECURITY_ANALYST_SYSTEM_PROMPT
    )

    return agent


# ===== Investigation Functions =====

async def investigate_with_agent(alert_data: Dict[str, Any], tools: List[BaseTool] = None) -> Dict[str, Any]:
    """
    Investigate alert using ReAct agent

    Args:
        alert_data: Alert information to investigate
        tools: Optional list of tools

    Returns:
        Investigation results including analysis, findings, and recommendations
    """
    # Create agent
    agent = await create_security_agent(tools)

    # Build investigation prompt
    investigation_prompt = _build_investigation_prompt(alert_data)

    # Execute agent
    print(f"\n[AGENT] Starting investigation for alert: {alert_data.get('id', 'unknown')}")
    print(f"[AGENT] Prompt: {investigation_prompt[:200]}...")

    result = await agent.ainvoke({
        "messages": [HumanMessage(content=investigation_prompt)]
    })

    # Extract response
    messages = result.get("messages", [])
    if messages:
        final_message = messages[-1]
        response_text = final_message.content if hasattr(final_message, 'content') else str(final_message)

        return {
            "success": True,
            "investigation_text": response_text,
            "messages": messages,
            "alert_id": alert_data.get("id", "unknown")
        }
    else:
        return {
            "success": False,
            "error": "No response from agent",
            "alert_id": alert_data.get("id", "unknown")
        }


async def analyze_threat_with_agent(
    alert_data: Dict[str, Any],
    enrichment_data: Dict[str, Any],
    tools: List[BaseTool] = None
) -> Dict[str, Any]:
    """
    Analyze threat using ReAct agent with enrichment context

    Args:
        alert_data: Original alert
        enrichment_data: Gathered context data
        tools: Optional tools

    Returns:
        Threat analysis including MITRE mappings and threat score
    """
    agent = await create_security_agent(tools)

    # Build analysis prompt
    prompt = f"""Analyze this security threat:

ALERT:
{_format_alert_data(alert_data)}

ENRICHMENT DATA:
{_format_enrichment_data(enrichment_data)}

Provide:
1. MITRE ATT&CK technique mappings (technique ID, name, confidence)
2. Threat score (0.0-1.0) with justification
3. Attack stage (Initial Access, Persistence, etc.)
4. Threat category

Be specific and reference the evidence.
"""

    result = await agent.ainvoke({
        "messages": [HumanMessage(content=prompt)]
    })

    messages = result.get("messages", [])
    if messages:
        return {
            "success": True,
            "analysis": messages[-1].content,
            "messages": messages
        }
    else:
        return {"success": False, "error": "No analysis generated"}


async def get_remediation_with_agent(
    alert_data: Dict[str, Any],
    threat_score: float,
    mitre_techniques: List[str],
    tools: List[BaseTool] = None
) -> Dict[str, Any]:
    """
    Get remediation recommendations using ReAct agent

    Args:
        alert_data: Alert information
        threat_score: Calculated threat score
        mitre_techniques: Identified MITRE techniques
        tools: Optional tools

    Returns:
        Remediation recommendations and playbook
    """
    agent = await create_security_agent(tools)

    prompt = f"""Generate remediation recommendations:

ALERT: {alert_data.get('type', 'unknown')} from {alert_data.get('source_ip', 'unknown')}
THREAT SCORE: {threat_score:.2f} / 1.00
MITRE TECHNIQUES: {', '.join(mitre_techniques)}

Provide:
1. Immediate actions (ordered by priority)
2. Follow-up actions
3. Long-term preventive measures
4. Estimated response time

Be specific and actionable.
"""

    result = await agent.ainvoke({
        "messages": [HumanMessage(content=prompt)]
    })

    messages = result.get("messages", [])
    if messages:
        return {
            "success": True,
            "recommendations": messages[-1].content,
            "messages": messages
        }
    else:
        return {"success": False, "error": "No recommendations generated"}


# ===== Helper Functions =====

def _build_investigation_prompt(alert_data: Dict[str, Any]) -> str:
    """Build investigation prompt from alert data"""
    prompt_parts = [
        "Investigate this security alert:",
        "",
        "ALERT DETAILS:",
        f"ID: {alert_data.get('id', 'unknown')}",
        f"Type: {alert_data.get('type', 'unknown')}",
        f"Timestamp: {alert_data.get('timestamp', 'unknown')}",
    ]

    if alert_data.get('source_ip'):
        prompt_parts.append(f"Source IP: {alert_data['source_ip']}")

    if alert_data.get('destination_ip'):
        prompt_parts.append(f"Destination IP: {alert_data['destination_ip']}")

    if alert_data.get('user'):
        prompt_parts.append(f"User: {alert_data['user']}")

    if alert_data.get('description'):
        prompt_parts.append(f"Description: {alert_data['description']}")

    prompt_parts.extend([
        "",
        "Use available tools to:",
        "1. Gather evidence from SIEM",
        "2. Check threat intelligence for IPs",
        "3. Review user activity if applicable",
        "4. Check endpoint data if hostname/IP available",
        "5. Find related events",
        "",
        "Then provide a complete security analysis with MITRE mapping and recommendations."
    ])

    return "\n".join(prompt_parts)


def _format_alert_data(alert_data: Dict[str, Any]) -> str:
    """Format alert data for prompt"""
    lines = []
    for key, value in alert_data.items():
        lines.append(f"  {key}: {value}")
    return "\n".join(lines)


def _format_enrichment_data(enrichment_data: Dict[str, Any]) -> str:
    """Format enrichment data for prompt"""
    if not enrichment_data:
        return "  No enrichment data available"

    lines = []

    # SIEM logs
    siem_logs = enrichment_data.get("siem_logs", [])
    if siem_logs:
        lines.append("SIEM Logs:")
        for log in siem_logs[:3]:  # First 3
            lines.append(f"  - {log.get('timestamp')}: {log.get('event_count')} events")

    # Threat intel
    threat_intel = enrichment_data.get("threat_intel", {})
    if threat_intel:
        lines.append("\nThreat Intelligence:")
        lines.append(f"  Reputation: {threat_intel.get('ip_reputation', 'unknown')}")
        lines.append(f"  Confidence: {threat_intel.get('confidence', 0):.0%}")

    # Endpoint data
    endpoint_data = enrichment_data.get("endpoint_data", {})
    if endpoint_data:
        lines.append("\nEndpoint Data:")
        lines.append(f"  Hostname: {endpoint_data.get('hostname', 'unknown')}")
        lines.append(f"  User: {endpoint_data.get('user', 'unknown')}")

    return "\n".join(lines) if lines else "  No enrichment data"


# ===== Testing =====

async def test_security_agent():
    """Test the ReAct security agent"""
    print("\n" + "="*60)
    print("SECURITY AGENT TEST")
    print("="*60)

    # Sample alert
    sample_alert = {
        "id": "TEST-001",
        "type": "phishing",
        "timestamp": "2024-01-15T14:30:00Z",
        "source_ip": "45.76.123.45",
        "user": "john.doe@company.com",
        "description": "Suspicious email with executable attachment"
    }

    try:
        # Initialize MCP tools
        mcp_manager = MCPClientManager()
        await mcp_manager.initialize()
        tools = await mcp_manager.get_tools()

        # Investigate
        result = await investigate_with_agent(sample_alert, tools)

        if result.get("success"):
            print("\n[SUCCESS] Investigation completed")
            print("\n" + "-"*60)
            print("INVESTIGATION REPORT:")
            print("-"*60)
            print(result.get("investigation_text", "No report"))
        else:
            print(f"\n[FAILED] {result.get('error', 'Unknown error')}")

    except Exception as e:
        print(f"\n[ERROR] Agent test failed: {str(e)}")
        raise


if __name__ == "__main__":
    import asyncio

    # Run test
    asyncio.run(test_security_agent())
