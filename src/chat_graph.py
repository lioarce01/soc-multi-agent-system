"""
LangGraph Chat Workflow for Q&A Interface (Streaming Mode)
Token-by-token streaming for conversational interactions
"""

from typing import Dict, Any, AsyncGenerator, List, Optional
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
    Chat function for Gradio that uses an agent to infer and call MCP tools
    
    Args:
        message: User message
        history: Chat history [[user, bot], ...]
    
    Returns:
        Tuple of (updated_history, "")
    """
    from src.mcp_integration import MCPClientManager
    from src.llm_factory import get_llm
    from langchain.agents import create_agent
    from langchain_core.messages import HumanMessage, AIMessage
    
    try:
        # Initialize MCP client and get memory tools
        mcp_manager = MCPClientManager()
        try:
            await mcp_manager.initialize()
        except Exception as init_error:
            print(f"[CHAT AGENT] ⚠️  MCP initialization failed: {init_error}")
            print(f"[CHAT AGENT] Make sure Memory MCP server is running on port 8003")
            return _fallback_chat_response(message, history, str(init_error))
        
        # Get all tools from MCP - agent will infer which to use based on descriptions
        try:
            all_tools = await mcp_manager.get_tools()
        except Exception as tools_error:
            print(f"[CHAT AGENT] ⚠️  Failed to get tools: {tools_error}")
            return _fallback_chat_response(message, history, str(tools_error))
        
        if not all_tools:
            print(f"[CHAT AGENT] ⚠️  No tools available from MCP servers")
            print(f"[CHAT AGENT] Check that Memory MCP server (port 8003) and SIEM MCP server (port 8001) are running")
            return _fallback_chat_response(message, history, "No tools available")
        
        # Log all tools received for debugging
        print(f"[CHAT AGENT] 📋 Received {len(all_tools)} tools from MCP:")
        for tool in all_tools:
            tool_name = getattr(tool, 'name', 'NO_NAME')
            tool_desc = getattr(tool, 'description', 'NO_DESC')[:50] if hasattr(tool, 'description') else 'NO_DESC'
            print(f"  - {tool_name}: {tool_desc}...")
        
        # Filter out invalid tools (like 'default_api' or tools without proper schemas)
        valid_tools = []
        invalid_tool_names = []
        invalid_tool_reasons = {}
        
        for tool in all_tools:
            try:
                tool_name = getattr(tool, 'name', None)
                
                # Validate tool has required attributes
                if not tool_name or tool_name == '':
                    invalid_tool_names.append("unnamed_tool")
                    invalid_tool_reasons["unnamed_tool"] = "No name attribute"
                    continue
                
                # Skip invalid tool names (more comprehensive list)
                invalid_names = ['default_api', '', 'api', 'default', 'tool', 'function']
                if tool_name in invalid_names or tool_name.startswith('_') or tool_name.startswith('__'):
                    invalid_tool_names.append(tool_name)
                    invalid_tool_reasons[tool_name] = f"Invalid name pattern"
                    continue
                
                # Validate tool has a callable or invoke method
                if not (hasattr(tool, 'invoke') or hasattr(tool, 'ainvoke') or hasattr(tool, '__call__')):
                    invalid_tool_names.append(tool_name)
                    invalid_tool_reasons[tool_name] = "No invoke/ainvoke method"
                    continue
                
                # Additional validation: check if tool has description (helps with agent selection)
                if not hasattr(tool, 'description') or not tool.description:
                    print(f"[CHAT AGENT] ⚠️  Warning: Tool {tool_name} has no description")
                
                valid_tools.append(tool)
            except Exception as tool_error:
                tool_name = getattr(tool, 'name', 'unknown')
                print(f"[CHAT AGENT] ⚠️  Error validating tool {tool_name}: {tool_error}")
                invalid_tool_names.append(tool_name)
                invalid_tool_reasons[tool_name] = str(tool_error)
        
        if invalid_tool_names:
            print(f"[CHAT AGENT] ⚠️  Filtered out {len(invalid_tool_names)} invalid tools:")
            for name in invalid_tool_names:
                reason = invalid_tool_reasons.get(name, "Unknown reason")
                print(f"    - {name}: {reason}")
        
        if not valid_tools:
            print(f"[CHAT AGENT] ⚠️  No valid tools available after filtering")
            return _fallback_chat_response(message, history, "No valid tools available")
        
        print(f"[CHAT AGENT] ✅ Using {len(valid_tools)} valid tools:")
        for tool in valid_tools:
            print(f"    - {tool.name}")
        
        # Create system prompt for chat agent (generic, no hardcoded tool names)
        chat_system_prompt = """You are a helpful SOC assistant that answers questions about past security investigations.

You have access to tools that can help you search, analyze, and retrieve information about past security incidents and investigations.

IMPORTANT TOOL USAGE GUIDELINES:
- For STATISTICS, SUMMARIES, COUNTS, or AGGREGATED DATA: Use get_investigation_statistics tool
  - This tool supports filtering by alert_type (e.g., 'malware', 'phishing', 'brute_force')
  - Examples: "malware statistics" → use get_investigation_statistics(alert_type='malware')
  - Examples: "phishing stats" → use get_investigation_statistics(alert_type='phishing')
  - Examples: "statistics for the last 7 days" → use get_investigation_statistics(time_range_hours=168)

- For FINDING INDIVIDUAL INCIDENTS: Use search_incidents tool
  - Use when user wants to see specific incidents, not aggregated data

- For SPECIFIC INCIDENT DETAILS: Use explain_incident tool
  - Use when user mentions a specific incident ID (e.g., ALT-2024-001)

- For CAMPAIGN DETECTION: Use find_campaigns tool
  - Use when user asks about coordinated attacks or campaigns

When a user asks a question:
1. Review the available tools and their descriptions carefully
2. Select the most appropriate tool(s) based on the user's query
3. Use the tool(s) to gather the necessary information
4. Provide a clear, helpful response based on the results

Be concise and specific. Include relevant details from the tool results. If a user asks for statistics about a specific alert type, use get_investigation_statistics with the alert_type parameter."""
        
        # Create agent with MCP tools using langchain.agents
        # Agent will automatically discover and use appropriate tools based on descriptions
        llm = get_llm(temperature=0.7)
        
        # Optionally use LLM tool selector middleware for better performance with many tools
        # This pre-filters tools before the main agent sees them
        # NOTE: Disabled for now due to 'default_api' selection issue
        # The middleware seems to be selecting tools that don't exist in valid_tool_names
        middleware = []
        
        # Only use tool selector if we have many tools AND we're confident in tool names
        # For now, let's skip it to avoid the 'default_api' issue
        use_tool_selector = False  # Disabled until we fix the 'default_api' issue
        
        if use_tool_selector and len(valid_tools) > 5:
            try:
                from langchain.agents.middleware import LLMToolSelectorMiddleware
                # Use a cheaper/faster model for tool selection if available
                selector_llm = get_llm(temperature=0.0)  # Lower temp for selection
                middleware.append(
                    LLMToolSelectorMiddleware(
                        model=selector_llm,
                        max_tools=10,  # Limit to most relevant tools
                    )
                )
                print(f"[CHAT AGENT] Using tool selector middleware ({len(valid_tools)} tools available)")
            except ImportError:
                print(f"[CHAT AGENT] LLMToolSelectorMiddleware not available, using all {len(valid_tools)} tools")
        else:
            print(f"[CHAT AGENT] Using all {len(valid_tools)} tools directly (tool selector disabled)")
        
        # Create agent - middleware is passed only if available
        if middleware:
            agent = create_agent(
                model=llm,
                tools=valid_tools,
                system_prompt=chat_system_prompt,
                middleware=middleware
            )
        else:
            agent = create_agent(
                model=llm,
                tools=valid_tools,
                system_prompt=chat_system_prompt
            )
        
        # Convert history to messages
        messages = []
        for user_msg, bot_msg in history:
            messages.append(HumanMessage(content=user_msg))
            messages.append(AIMessage(content=bot_msg))
        
        # Add current user message
        messages.append(HumanMessage(content=message))
        
        # Run agent - it will infer which tool to use
        print(f"[CHAT AGENT] Processing query: {message[:50]}...")
        result = await agent.ainvoke({"messages": messages})
        
        # Extract agent response
        agent_messages = result.get("messages", [])
        if agent_messages:
            last_message = agent_messages[-1]
            if hasattr(last_message, 'content'):
                bot_response = last_message.content
            else:
                bot_response = str(last_message)
        else:
            bot_response = "I couldn't generate a response. Please try again."
        
        # Update history
        history.append([message, bot_response])
        
        return history, ""
        
    except Exception as e:
        import traceback
        print(f"[CHAT AGENT] ⚠️  Error: {e}")
        print(f"[CHAT AGENT] Traceback: {traceback.format_exc()}")
        # Fallback to simple response
        return _fallback_chat_response(message, history, str(e))


def _fallback_chat_response(message: str, history: list, error_detail: str = None) -> tuple:
    """
    Fallback chat response when MCP tools are unavailable

    Args:
        message: User message
        history: Chat history
        error_detail: Optional error details for better diagnostics

    Returns:
        Tuple of (updated_history, "")
    """
    error_msg = error_detail or "MCP connection failed"

    # Provide helpful error message with instructions
    bot_response = f"""I'm sorry, but the investigation history tools are currently unavailable.

**Error:** {error_msg}

**To fix this:**
1. Make sure the Memory MCP server is running:
   ```bash
   cd mcp_servers
   python memory_server.py
   ```
   The server should start on http://localhost:8003

2. Also ensure the SIEM MCP server is running (port 8001) if you want to use investigation features.

3. Check that the servers are accessible and not blocked by firewall.

Once the servers are running, please try your question again."""

    history.append([message, bot_response])
    return history, ""


async def chat_with_history_streaming(
    message: str,
    history: list
) -> AsyncGenerator[tuple, None]:
    """
    Chat function with streaming status updates for Gradio
    Yields intermediate status messages while processing

    Args:
        message: User message
        history: Chat history [[user, bot], ...]

    Yields:
        Tuple of (updated_history, "")
    """
    from src.mcp_integration import MCPClientManager
    from src.llm_factory import get_llm
    from langchain.agents import create_agent
    from langchain_core.messages import HumanMessage, AIMessage

    # Helper to create status message
    def make_status(status_text: str) -> list:
        """Create history with status message"""
        return history + [[message, f"*{status_text}*"]]

    try:
        # Status: Connecting
        yield make_status("🔌 Connecting to memory database..."), ""

        # Initialize MCP client and get memory tools
        mcp_manager = MCPClientManager()
        try:
            await mcp_manager.initialize()
        except Exception as init_error:
            print(f"[CHAT AGENT] ⚠️  MCP initialization failed: {init_error}")
            result, _ = _fallback_chat_response(message, history, str(init_error))
            yield result, ""
            return

        # Status: Getting tools
        yield make_status("🛠️ Loading analysis tools..."), ""

        # Get all tools from MCP
        try:
            all_tools = await mcp_manager.get_tools()
        except Exception as tools_error:
            print(f"[CHAT AGENT] ⚠️  Failed to get tools: {tools_error}")
            result, _ = _fallback_chat_response(message, history, str(tools_error))
            yield result, ""
            return

        if not all_tools:
            print(f"[CHAT AGENT] ⚠️  No tools available from MCP servers")
            result, _ = _fallback_chat_response(message, history, "No tools available")
            yield result, ""
            return

        # Log all tools received for debugging
        print(f"[CHAT AGENT] 📋 Received {len(all_tools)} tools from MCP:")
        for tool in all_tools:
            tool_name = getattr(tool, 'name', 'NO_NAME')
            tool_desc = getattr(tool, 'description', 'NO_DESC')[:50] if hasattr(tool, 'description') else 'NO_DESC'
            print(f"  - {tool_name}: {tool_desc}...")

        # Filter out invalid tools
        valid_tools = []
        invalid_tool_names = []
        invalid_tool_reasons = {}

        for tool in all_tools:
            try:
                tool_name = getattr(tool, 'name', None)

                if not tool_name or tool_name == '':
                    invalid_tool_names.append("unnamed_tool")
                    invalid_tool_reasons["unnamed_tool"] = "No name attribute"
                    continue

                invalid_names = ['default_api', '', 'api', 'default', 'tool', 'function']
                if tool_name in invalid_names or tool_name.startswith('_') or tool_name.startswith('__'):
                    invalid_tool_names.append(tool_name)
                    invalid_tool_reasons[tool_name] = f"Invalid name pattern"
                    continue

                if not (hasattr(tool, 'invoke') or hasattr(tool, 'ainvoke') or hasattr(tool, '__call__')):
                    invalid_tool_names.append(tool_name)
                    invalid_tool_reasons[tool_name] = "No invoke/ainvoke method"
                    continue

                if not hasattr(tool, 'description') or not tool.description:
                    print(f"[CHAT AGENT] ⚠️  Warning: Tool {tool_name} has no description")

                valid_tools.append(tool)
            except Exception as tool_error:
                tool_name = getattr(tool, 'name', 'unknown')
                print(f"[CHAT AGENT] ⚠️  Error validating tool {tool_name}: {tool_error}")
                invalid_tool_names.append(tool_name)
                invalid_tool_reasons[tool_name] = str(tool_error)

        if invalid_tool_names:
            print(f"[CHAT AGENT] ⚠️  Filtered out {len(invalid_tool_names)} invalid tools:")
            for name in invalid_tool_names:
                reason = invalid_tool_reasons.get(name, "Unknown reason")
                print(f"    - {name}: {reason}")

        if not valid_tools:
            print(f"[CHAT AGENT] ⚠️  No valid tools available after filtering")
            result, _ = _fallback_chat_response(message, history, "No valid tools available")
            yield result, ""
            return

        print(f"[CHAT AGENT] ✅ Using {len(valid_tools)} valid tools:")
        for tool in valid_tools:
            print(f"    - {tool.name}")

        # Status: Analyzing query
        yield make_status("🔍 Analyzing your question..."), ""

        # Create system prompt
        chat_system_prompt = """You are a helpful SOC assistant that answers questions about past security investigations.

You have access to tools that can help you search, analyze, and retrieve information about past security incidents and investigations.

IMPORTANT TOOL USAGE GUIDELINES:
- For STATISTICS, SUMMARIES, COUNTS, or AGGREGATED DATA: Use get_investigation_statistics tool
  - This tool supports filtering by alert_type (e.g., 'malware', 'phishing', 'brute_force')
  - Examples: "malware statistics" → use get_investigation_statistics(alert_type='malware')
  - Examples: "phishing stats" → use get_investigation_statistics(alert_type='phishing')
  - Examples: "statistics for the last 7 days" → use get_investigation_statistics(time_range_hours=168)

- For FINDING INDIVIDUAL INCIDENTS: Use search_incidents tool
  - Use when user wants to see specific incidents, not aggregated data

- For SPECIFIC INCIDENT DETAILS: Use explain_incident tool
  - Use when user mentions a specific incident ID (e.g., ALT-2024-001)

- For CAMPAIGN DETECTION: Use find_campaigns tool
  - Use when user asks about coordinated attacks or campaigns

When a user asks a question:
1. Review the available tools and their descriptions carefully
2. Select the most appropriate tool(s) based on the user's query
3. Use the tool(s) to gather the necessary information
4. Provide a clear, helpful response based on the results

Be concise and specific. Include relevant details from the tool results. If a user asks for statistics about a specific alert type, use get_investigation_statistics with the alert_type parameter."""

        # Create agent
        llm = get_llm(temperature=0.7)
        middleware = []
        use_tool_selector = False

        if use_tool_selector and len(valid_tools) > 5:
            try:
                from langchain.agents.middleware import LLMToolSelectorMiddleware
                selector_llm = get_llm(temperature=0.0)
                middleware.append(
                    LLMToolSelectorMiddleware(
                        model=selector_llm,
                        max_tools=10,
                    )
                )
                print(f"[CHAT AGENT] Using tool selector middleware ({len(valid_tools)} tools available)")
            except ImportError:
                print(f"[CHAT AGENT] LLMToolSelectorMiddleware not available, using all {len(valid_tools)} tools")
        else:
            print(f"[CHAT AGENT] Using all {len(valid_tools)} tools directly (tool selector disabled)")

        if middleware:
            agent = create_agent(
                model=llm,
                tools=valid_tools,
                system_prompt=chat_system_prompt,
                middleware=middleware
            )
        else:
            agent = create_agent(
                model=llm,
                tools=valid_tools,
                system_prompt=chat_system_prompt
            )

        # Convert history to messages
        messages = []
        for user_msg, bot_msg in history:
            messages.append(HumanMessage(content=user_msg))
            messages.append(AIMessage(content=bot_msg))
        messages.append(HumanMessage(content=message))

        # Status: Searching
        yield make_status("📊 Searching incident database..."), ""

        # Run agent
        print(f"[CHAT AGENT] Processing query: {message[:50]}...")

        # Status: Processing
        yield make_status("🤔 Processing results..."), ""

        result = await agent.ainvoke({"messages": messages})

        # Extract agent response
        agent_messages = result.get("messages", [])
        if agent_messages:
            last_message = agent_messages[-1]
            if hasattr(last_message, 'content'):
                bot_response = last_message.content
            else:
                bot_response = str(last_message)
        else:
            bot_response = "I couldn't generate a response. Please try again."

        # Final response
        final_history = history + [[message, bot_response]]
        yield final_history, ""

    except Exception as e:
        import traceback
        print(f"[CHAT AGENT] ⚠️  Error: {e}")
        print(f"[CHAT AGENT] Traceback: {traceback.format_exc()}")
        result, _ = _fallback_chat_response(message, history, str(e))
        yield result, ""


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
