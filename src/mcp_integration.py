"""
MCP Integration - Client setup for connecting to MCP servers
Initializes connections to SIEM and Threat Intel MCP servers via streamable_http
"""

import json
import os
from typing import List, Dict, Any, Optional
from langchain_mcp_adapters.client import MultiServerMCPClient
from langchain_core.tools import BaseTool

from src.config import Config


# ===== MCP Server Configuration =====

def get_mcp_server_config() -> Dict[str, Dict[str, Any]]:
    """
    Get MCP server configuration based on environment

    Returns:
        Configuration dictionary for all MCP servers
    """
    # Check if running in Docker
    is_docker = os.getenv("DOCKER_ENV", "false").lower() == "true"

    if is_docker:
        # Docker environment - use container names
        return {
            "siem": {
                "transport": "streamable_http",
                "url": "http://siem-mcp:8001/mcp",
                "headers": {
                    "Authorization": f"Bearer {Config.SIEM_API_KEY}" if Config.SIEM_API_KEY else ""
                }
            },
            "threat_intel": {
                "transport": "streamable_http",
                "url": "http://threat-intel-mcp:8002/mcp"
            }
        }
    else:
        # Development environment - use localhost
        return {
            "siem": {
                "transport": "streamable_http",
                "url": "http://localhost:8001/mcp",
                "headers": {
                    "Authorization": f"Bearer {Config.SIEM_API_KEY}" if Config.SIEM_API_KEY else ""
                }
            },
            # Note: Only SIEM server for now, will add threat_intel later
            # "threat_intel": {
            #     "transport": "streamable_http",
            #     "url": "http://localhost:8002/mcp"
            # }
        }


# ===== MCP Client Manager =====

class MCPClientManager:
    """
    Manages MCP client connections and tool access
    Singleton pattern to ensure single client instance
    """

    _instance: Optional['MCPClientManager'] = None
    _client: Optional[MultiServerMCPClient] = None
    _tools: Optional[List[BaseTool]] = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    async def initialize(self) -> None:
        """
        Initialize MCP client and load tools from all servers
        """
        if self._client is not None:
            print("[MCP] Client already initialized")
            return

        print("[MCP] Initializing MCP client...")

        # Get server configuration
        server_config = get_mcp_server_config()

        print(f"[MCP] Connecting to {len(server_config)} MCP servers:")
        for name, config in server_config.items():
            print(f"  - {name}: {config['url']}")

        # Initialize multi-server client
        self._client = MultiServerMCPClient(server_config)

        # Load tools from all servers
        try:
            self._tools = await self._client.get_tools()
            print(f"[MCP] Successfully loaded {len(self._tools)} tools:")
            for tool in self._tools:
                print(f"  - {tool.name}: {tool.description[:60]}...")

        except Exception as e:
            print(f"[MCP] ERROR: Failed to load tools: {str(e)}")
            print(f"[MCP] Make sure MCP servers are running:")
            for name, config in server_config.items():
                print(f"  - {name}: {config['url']}")
            raise

    async def get_tools(self) -> List[BaseTool]:
        """
        Get all available MCP tools

        Returns:
            List of LangChain tools from all MCP servers
        """
        if self._tools is None:
            await self.initialize()

        return self._tools or []

    async def get_tool_by_name(self, tool_name: str) -> Optional[BaseTool]:
        """
        Get a specific tool by name

        Args:
            tool_name: Name of the tool to retrieve

        Returns:
            The tool if found, None otherwise
        """
        tools = await self.get_tools()

        for tool in tools:
            if tool.name == tool_name:
                return tool

        return None

    async def invoke_tool(self, tool_name: str, **kwargs) -> Any:
        """
        Invoke a specific MCP tool by name

        Args:
            tool_name: Name of the tool to invoke
            **kwargs: Tool arguments

        Returns:
            Tool execution result (automatically parses JSON strings)
        """
        tool = await self.get_tool_by_name(tool_name)

        if tool is None:
            raise ValueError(f"Tool '{tool_name}' not found")

        result = await tool.ainvoke(kwargs)

        # MCP tools may return JSON as string - parse it automatically
        if isinstance(result, str):
            try:
                parsed = json.loads(result)
                print(f"[MCP] Parsed JSON string response from '{tool_name}'")
                return parsed
            except json.JSONDecodeError:
                # Not JSON, return as-is
                print(f"[MCP] Tool '{tool_name}' returned non-JSON string")
                return result

        return result

    async def close(self) -> None:
        """
        Close MCP client connections
        """
        if self._client:
            # Note: langchain-mcp-adapters may not have explicit close method
            # This is a placeholder for future cleanup if needed
            print("[MCP] Closing client connections...")
            self._client = None
            self._tools = None

    def get_tool_list(self) -> List[Dict[str, str]]:
        """
        Get simplified list of available tools

        Returns:
            List of dictionaries with tool name and description
        """
        if self._tools is None:
            return []

        return [
            {
                "name": tool.name,
                "description": tool.description
            }
            for tool in self._tools
        ]


# ===== Convenience Functions =====

async def initialize_mcp_tools() -> List[BaseTool]:
    """
    Initialize MCP client and return all available tools
    Convenience function for quick setup

    Returns:
        List of all MCP tools
    """
    manager = MCPClientManager()
    await manager.initialize()
    return await manager.get_tools()


async def get_siem_events(
    source_ip: Optional[str] = None,
    event_type: Optional[str] = None,
    user: Optional[str] = None,
    time_range: str = "last_24h",
    limit: int = 100
) -> Dict[str, Any]:
    """
    Query SIEM for events (convenience wrapper)

    Args:
        source_ip: Filter by source IP
        event_type: Filter by event type
        user: Filter by user
        time_range: Time window
        limit: Max events to return

    Returns:
        SIEM query results
    """
    manager = MCPClientManager()
    return await manager.invoke_tool(
        "query_siem",
        source_ip=source_ip,
        event_type=event_type,
        user=user,
        time_range=time_range,
        limit=limit
    )


async def get_ip_threat_intel(ip_address: str) -> Dict[str, Any]:
    """
    Get threat intelligence for IP address (convenience wrapper)

    Args:
        ip_address: IP to look up

    Returns:
        Threat intelligence data
    """
    manager = MCPClientManager()
    return await manager.invoke_tool("get_threat_intel", ip_address=ip_address)


async def get_user_security_events(username: str, time_range: str = "last_7d") -> Dict[str, Any]:
    """
    Get user security events (convenience wrapper)

    Args:
        username: Username to look up
        time_range: Time window

    Returns:
        User activity data
    """
    manager = MCPClientManager()
    return await manager.invoke_tool("get_user_events", username=username, time_range=time_range)


async def get_endpoint_security_data(hostname: str) -> Dict[str, Any]:
    """
    Get endpoint security data (convenience wrapper)

    Args:
        hostname: Hostname to query

    Returns:
        Endpoint security information
    """
    manager = MCPClientManager()
    return await manager.invoke_tool("get_endpoint_data", hostname=hostname)


async def check_mcp_health() -> Dict[str, Any]:
    """
    Check MCP server health

    Returns:
        Health status of MCP servers
    """
    manager = MCPClientManager()
    return await manager.invoke_tool("health_check")


# ===== Testing =====

async def test_mcp_connection():
    """
    Test MCP connection and tool availability
    """
    print("\n" + "="*60)
    print("MCP CONNECTION TEST")
    print("="*60)

    try:
        # Initialize
        manager = MCPClientManager()
        await manager.initialize()

        # List tools
        print("\nAvailable Tools:")
        print("-" * 60)
        tool_list = manager.get_tool_list()
        for tool_info in tool_list:
            print(f"\n{tool_info['name']}:")
            print(f"  {tool_info['description']}")

        # Test health check
        print("\n" + "="*60)
        print("HEALTH CHECK")
        print("="*60)
        health = await check_mcp_health()
        print(f"Status: {health.get('status', 'unknown')}")
        print(f"Server: {health.get('server', 'unknown')}")
        print(f"Total Events: {health.get('total_events', 0)}")

        # Test SIEM query
        print("\n" + "="*60)
        print("TEST SIEM QUERY")
        print("="*60)
        events = await get_siem_events(event_type="failed_login", limit=5)
        print(f"Found {events.get('count', 0)} events")
        for event in events.get('events', [])[:2]:
            print(f"  - {event.get('timestamp')}: {event.get('event_type')} from {event.get('source_ip')}")

        # Test threat intel
        print("\n" + "="*60)
        print("TEST THREAT INTEL")
        print("="*60)
        threat_info = await get_ip_threat_intel("45.76.123.45")
        print(f"IP: {threat_info.get('ip_address')}")
        print(f"Reputation: {threat_info.get('reputation')}")
        print(f"Threat Score: {threat_info.get('threat_score')}")
        print(f"Recommendation: {threat_info.get('recommendation')}")

        print("\n" + "="*60)
        print("ALL TESTS PASSED")
        print("="*60)

    except Exception as e:
        print(f"\n[ERROR] MCP connection test failed: {str(e)}")
        print("\nTroubleshooting:")
        print("1. Make sure SIEM MCP server is running:")
        print("   cd mcp_servers")
        print("   mcp_servers\\venv\\Scripts\\activate")
        print("   python siem_server.py")
        print("\n2. Check that port 8001 is not in use")
        print("\n3. Verify streamable_http transport is configured correctly")
        raise


if __name__ == "__main__":
    import asyncio

    # Run test
    asyncio.run(test_mcp_connection())
