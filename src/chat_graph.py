"""
LangGraph Chat Workflow for Q&A Interface (Streaming Mode)
Token-by-token streaming for conversational interactions
"""

from typing import Dict, Any, AsyncGenerator
from langgraph.graph import StateGraph, END
from langchain_core.messages import HumanMessage, AIMessage, SystemMessage

from src.state import SecurityAgentState
from src.config import Config
from src.llm_factory import get_llm


# ===== Chat-Specific State =====

class ChatState(SecurityAgentState):
    """
    Extended state for chat interface
    Includes conversation history and context from investigation
    """
    pass


# ===== System Prompt =====

SECURITY_ANALYST_PROMPT = """You are a Senior Security Analyst AI assistant in a Security Operations Center (SOC).

Your role is to help analysts understand security alerts, investigations, and threat intelligence.

**Available Context:**
- Alert Data: Information about the current security alert
- Enrichment Data: SIEM logs, threat intelligence, endpoint data
- MITRE Mappings: ATT&CK techniques identified
- Threat Score: Calculated risk probability
- Investigation Findings: Results from deep investigation
- Recommendations: Suggested remediation actions

**Guidelines:**
1. Provide clear, concise explanations
2. Reference specific data from the investigation when answering
3. Use security industry terminology appropriately
4. Suggest follow-up actions when relevant
5. Be direct and actionable - SOC analysts need quick answers
6. If you don't have enough context, ask clarifying questions

**Response Style:**
- Short paragraphs (2-3 sentences max)
- Use bullet points for lists
- Include specific values/metrics from investigation
- Highlight critical items with CAPS for urgency

Answer the analyst's question based on the investigation context provided.
"""


# ===== Node Functions =====

async def chat_agent_node(state: ChatState) -> Dict[str, Any]:
    """
    Chat agent that answers questions about the investigation
    Streams responses token-by-token
    """
    # Get last user message
    messages = state.get("messages", [])
    if not messages:
        return {
            "messages": [AIMessage(content="No messages to process")]
        }

    last_message = messages[-1]
    if not isinstance(last_message, HumanMessage):
        return {
            "messages": [AIMessage(content="Expected a user question")]
        }

    # Build context from investigation state
    context_parts = []

    # Alert context
    alert_data = state.get("alert_data", {})
    if alert_data:
        context_parts.append(f"**Alert ID:** {state.get('alert_id', 'Unknown')}")
        context_parts.append(f"**Alert Type:** {alert_data.get('type', 'Unknown')}")
        context_parts.append(f"**Source IP:** {alert_data.get('source_ip', 'Unknown')}")
        context_parts.append(f"**User:** {alert_data.get('user', 'Unknown')}")

    # Threat assessment context
    threat_score = state.get("threat_score", 0.0)
    if threat_score > 0:
        context_parts.append(f"**Threat Score:** {threat_score:.2f} / 1.00")
        context_parts.append(f"**Attack Stage:** {state.get('attack_stage', 'Unknown')}")
        context_parts.append(f"**Category:** {state.get('threat_category', 'Unknown')}")

    # MITRE context
    mitre_mappings = state.get("mitre_mappings", [])
    if mitre_mappings:
        context_parts.append("\n**MITRE ATT&CK Techniques:**")
        for mapping in mitre_mappings[:3]:  # Top 3
            context_parts.append(
                f"- {mapping['technique_id']}: {mapping['name']} "
                f"(Confidence: {mapping['confidence']:.0%})"
            )

    # Enrichment data context
    enrichment_data = state.get("enrichment_data", {})
    if enrichment_data:
        threat_intel = enrichment_data.get("threat_intel", {})
        if threat_intel:
            context_parts.append(
                f"\n**Threat Intel:** IP reputation = {threat_intel.get('reputation', 'unknown')}, "
                f"confidence = {threat_intel.get('confidence', 0):.0%}"
            )

    # Recommendations context
    recommendations = state.get("recommendations", [])
    if recommendations:
        context_parts.append(f"\n**Recommendations:** {len(recommendations)} actions suggested")

    # Build context message
    context_text = "\n".join(context_parts)

    # Build messages for LLM
    llm_messages = [
        SystemMessage(content=SECURITY_ANALYST_PROMPT),
        SystemMessage(content=f"\n**INVESTIGATION CONTEXT:**\n{context_text}\n")
    ]

    # Add conversation history (last 5 messages for context)
    conversation_history = messages[-6:-1] if len(messages) > 1 else []
    llm_messages.extend(conversation_history)

    # Add current question
    llm_messages.append(last_message)

    # Initialize LLM (will use streaming)
    llm = get_llm(
        temperature=0.7,
        streaming=True  # Enable streaming
    )

    # Generate response (non-streaming for now, will be converted to streaming in invoke)
    response = await llm.ainvoke(llm_messages)

    return {
        "messages": [response],
        "current_agent": "chat"
    }


# ===== Build Chat Graph =====

def create_chat_graph() -> StateGraph:
    """
    Create streaming chat workflow graph

    Simple workflow:
    1. Receive user question
    2. Generate answer with investigation context
    3. Stream response token-by-token
    """
    workflow = StateGraph(ChatState)

    # Add chat agent node
    workflow.add_node("chat_agent", chat_agent_node)

    # Simple linear flow
    workflow.set_entry_point("chat_agent")
    workflow.add_edge("chat_agent", END)

    # Compile graph
    app = workflow.compile()

    return app


# ===== Compiled Graph for LangGraph Studio =====

# Create and export compiled graph instance for langgraph dev
graph = create_chat_graph()


# ===== Streaming Execution =====

async def chat_with_streaming(
    question: str,
    investigation_state: SecurityAgentState
) -> AsyncGenerator[str, None]:
    """
    Chat with streaming responses (token-by-token)

    Args:
        question: User's question
        investigation_state: Current investigation state for context

    Yields:
        Tokens of the response as they're generated
    """
    # Create chat state from investigation state
    chat_state = dict(investigation_state)

    # Add user question to messages
    existing_messages = chat_state.get("messages", [])
    chat_state["messages"] = existing_messages + [HumanMessage(content=question)]

    # Initialize LLM with streaming
    llm = get_llm(
        temperature=0.7,
        streaming=True
    )

    # Build context (same as in chat_agent_node)
    context_parts = []
    alert_data = chat_state.get("alert_data", {})
    if alert_data:
        context_parts.append(f"**Alert ID:** {chat_state.get('alert_id', 'Unknown')}")
        context_parts.append(f"**Alert Type:** {alert_data.get('type', 'Unknown')}")

    threat_score = chat_state.get("threat_score", 0.0)
    if threat_score > 0:
        context_parts.append(f"**Threat Score:** {threat_score:.2f}")

    mitre_mappings = chat_state.get("mitre_mappings", [])
    if mitre_mappings:
        context_parts.append("\n**MITRE Techniques:**")
        for mapping in mitre_mappings[:3]:
            context_parts.append(f"- {mapping['technique_id']}: {mapping['name']}")

    context_text = "\n".join(context_parts)

    # Build messages
    messages = [
        SystemMessage(content=SECURITY_ANALYST_PROMPT),
        SystemMessage(content=f"\n**INVESTIGATION CONTEXT:**\n{context_text}\n"),
        HumanMessage(content=question)
    ]

    # Stream response
    async for chunk in llm.astream(messages):
        if chunk.content:
            yield chunk.content


async def chat_without_streaming(
    question: str,
    investigation_state: SecurityAgentState
) -> str:
    """
    Chat without streaming (complete response at once)
    Useful for testing or batch processing

    Args:
        question: User's question
        investigation_state: Current investigation state for context

    Returns:
        Complete response text
    """
    # Create chat state
    chat_state = dict(investigation_state)
    chat_state["messages"] = chat_state.get("messages", []) + [HumanMessage(content=question)]

    # Create graph
    graph = create_chat_graph()

    # Execute
    result = await graph.ainvoke(chat_state)

    # Extract response
    messages = result.get("messages", [])
    if messages:
        last_message = messages[-1]
        if isinstance(last_message, AIMessage):
            return last_message.content

    return "No response generated"


async def chat_with_history(
    message: str,
    history: list
) -> tuple:
    """
    Chat function for Gradio that queries historical investigations
    
    Args:
        message: User message
        history: Chat history [[user, bot], ...]
    
    Returns:
        Tuple of (updated_history, "")
    """
    from src.memory.manager import get_memory_manager
    from src.llm_factory import get_llm
    import json
    import re
    
    # Initialize memory manager and LLM
    memory_manager = get_memory_manager()
    llm = get_llm(temperature=0.7)
    
    # Convert history to messages format
    messages = []
    for user_msg, bot_msg in history:
        messages.append(HumanMessage(content=user_msg))
        messages.append(AIMessage(content=bot_msg))
    
    # Add current message
    messages.append(HumanMessage(content=message))
    
    # Classify intent
    intent_prompt = f"""Classify this user query into one of these categories:

Query: "{message}"

Categories:
- search_incidents: User wants to search/filter past incidents
- get_statistics: User wants aggregated metrics/stats
- explain_incident: User wants details about a specific incident
- find_campaigns: User wants to know about campaigns
- general: General question about the system

Return only the category name."""
    
    try:
        intent_response = await llm.ainvoke(intent_prompt)
        intent = intent_response.content.strip().lower()
    except:
        intent = "general"
    
    # Search memory based on intent
    search_results = []
    
    if intent == "search_incidents":
        # Semantic search in incident database
        try:
            similar = await memory_manager.find_similar_incidents(
                current_alert={"description": message},
                k=5,
                min_similarity=0.3
            )
            search_results = similar
        except Exception as e:
            print(f"[CHAT] Error searching incidents: {e}")
    
    elif intent == "get_statistics":
        # Get stats
        try:
            # Extract time range from message (default: 7 days)
            time_range = 168  # hours
            if "last week" in message.lower() or "7 days" in message.lower():
                time_range = 168
            elif "last 24 hours" in message.lower() or "today" in message.lower():
                time_range = 24
            elif "last month" in message.lower() or "30 days" in message.lower():
                time_range = 720
            
            stats = await memory_manager.get_statistics(
                user_id="default_user",
                time_range_hours=time_range
            )
            search_results = [stats]
        except Exception as e:
            print(f"[CHAT] Error getting statistics: {e}")
    
    elif intent == "explain_incident":
        # Extract incident ID from query
        match = re.search(r'ALT-[\d-]+', message.upper())
        if match:
            incident_id = match.group(0)
            try:
                incident = await memory_manager.get_incident_by_id(
                    user_id="default_user",
                    incident_id=incident_id
                )
                if incident:
                    search_results = [incident]
            except Exception as e:
                print(f"[CHAT] Error retrieving incident: {e}")
    
    elif intent == "find_campaigns":
        # Get all incidents and look for patterns
        try:
            all_incidents = await memory_manager.get_all_incidents(
                user_id="default_user",
                limit=50
            )
            search_results = all_incidents
        except Exception as e:
            print(f"[CHAT] Error finding campaigns: {e}")
    
    # Generate response
    response_prompt = f"""You are a helpful SOC assistant answering questions about past security investigations.

User Query: "{message}"

Search Results:
{json.dumps(search_results, indent=2, default=str)}

Generate a helpful, concise response (3-5 sentences). Include specific details from the search results.
If no results found, explain that politely."""
    
    try:
        response = await llm.ainvoke(response_prompt)
        bot_response = response.content
    except Exception as e:
        bot_response = f"I encountered an error processing your query: {str(e)}"
    
    # Update history
    history.append([message, bot_response])
    
    return history, ""


# ===== Example Usage =====

if __name__ == "__main__":
    import asyncio
    import json
    from pathlib import Path
    from src.graph import investigate_alert

    async def test_chat():
        """Test streaming chat interface"""
        # First, run an investigation to get context
        data_dir = Path(__file__).parent.parent / "data"
        with open(data_dir / "sample_alerts.json", "r") as f:
            alerts = json.load(f)

        sample_alert = alerts[0]

        print("Running investigation to build context...")
        investigation_result = await investigate_alert(sample_alert)

        print("\n" + "="*60)
        print("CHAT INTERFACE TEST (Streaming Mode)")
        print("="*60)

        # Test questions
        questions = [
            "Why is this threat scored so high?",
            "What MITRE techniques were identified?",
            "What should I do first to remediate this?",
            "Is this IP address known to be malicious?"
        ]

        for question in questions:
            print(f"\nAnalyst: {question}")
            print("SOC AI: ", end="", flush=True)

            # Stream response
            async for token in chat_with_streaming(question, investigation_result):
                print(token, end="", flush=True)

            print("\n")

    # Run test
    asyncio.run(test_chat())
