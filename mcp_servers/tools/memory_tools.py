"""
Memory MCP Tools
Tool definitions for memory/incident search operations
"""

import logging
from typing import Dict, Optional, Any
from datetime import datetime

from fastmcp import FastMCP
from mcp_servers.core.memory_manager import IsolatedMemoryManager

logger = logging.getLogger("memory_mcp_server.tools")


def register_memory_tools(mcp_server: FastMCP, memory_manager: IsolatedMemoryManager):
    """
    Register memory-related tools with the MCP server

    Args:
        mcp_server: FastMCP server instance
        memory_manager: IsolatedMemoryManager instance
    """

    @mcp_server.tool(
        description="Search past security investigations using semantic search. Use when user asks to find, search, or look for incidents, alerts, or investigations. Use get_investigation_statistics for statistics and summaries - this tool is for finding individual incidents. Supports filtering by alert type (phishing, malware, brute_force) and by severity using min_threat_score (0.7 for high severity, 0.5 for medium). If only alert_type is provided, use that as the search query. Returns list of matching incidents with similarity scores, threat scores, and metadata."
    )
    async def search_incidents(
        query: Optional[str] = None,
        alert_type: Optional[str] = None,
        min_threat_score: Optional[float] = None,
        limit: int = 10
    ) -> Dict[str, Any]:
        """
        Search past investigations using semantic search

        Args:
            query: Optional search query text (e.g., "phishing emails", "malware detection")
            alert_type: Optional filter by alert type (e.g., "phishing", "malware", "brute_force")
            min_threat_score: Optional minimum threat score filter (0.0-1.0). Use 0.7 for high severity, 0.5 for medium.
            limit: Maximum number of results to return (default: 10)

        Returns:
            Dictionary with list of matching incidents and metadata
        """
        # If query is not provided, use alert_type as query, or default to generic search
        if not query:
            if alert_type:
                query = alert_type
                logger.debug(f"No query provided, using alert_type '{alert_type}' as search query")
            else:
                query = "security incident"
                logger.debug(f"No query or alert_type provided, using default query: 'security incident'")

        logger.info(f"Tool invoked: search_incidents(query='{query[:50]}...', alert_type={alert_type}, min_threat_score={min_threat_score}, limit={limit})")

        try:
            if memory_manager.incident_db is None:
                logger.warning("Memory DB not initialized, returning empty results")
                return {
                    "incidents": [],
                    "count": 0,
                    "error": "Memory database not initialized. Please check server logs."
                }

            # Build search query
            search_query = query
            if alert_type and alert_type != query:
                search_query = f"{query} {alert_type}"
                logger.debug(f"Applied alert_type filter: {alert_type}")

            # Call isolated memory manager
            results = await memory_manager.find_similar_incidents(
                query=search_query,
                k=limit,
                min_similarity=0.3
            )

            # Filter by alert type if specified
            if alert_type:
                before_filter = len(results)
                results = [r for r in results if r.get("alert_type") == alert_type]
                logger.debug(f"Filtered results: {before_filter} -> {len(results)} after alert_type filter")

            # Filter by minimum threat score (severity) if specified
            if min_threat_score is not None:
                before_filter = len(results)
                results = [r for r in results if r.get("threat_score", 0.0) >= min_threat_score]
                logger.debug(f"Filtered results: {before_filter} -> {len(results)} after min_threat_score filter ({min_threat_score})")

            logger.info(f"search_incidents completed: found {len(results)} incidents")

            # Build filters dict for response
            filters = {}
            if alert_type:
                filters["alert_type"] = alert_type
            if min_threat_score is not None:
                filters["min_threat_score"] = min_threat_score
                filters["severity"] = "high" if min_threat_score >= 0.7 else "medium" if min_threat_score >= 0.5 else "low"

            return {
                "incidents": results,
                "count": len(results),
                "query": query,
                "filters": filters if filters else None
            }
        except Exception as e:
            logger.error(f"Error in search_incidents tool: {e}", exc_info=True)
            return {
                "error": str(e),
                "incidents": [],
                "count": 0
            }

    @mcp_server.tool(
        description="Get aggregated statistics and summary metrics about past security investigations. Use when user asks for statistics, summaries, counts, averages, trends, or aggregated data about incidents. IMPORTANT: This tool can filter by alert type - use alert_type parameter (e.g., 'malware', 'phishing', 'brute_force') to get statistics for specific attack types. Supports time range filtering (hours). Returns total incidents, average threat score, alert type distribution, attack stage distribution, and high severity counts."
    )
    async def get_investigation_statistics(
        time_range_hours: int = 168,
        alert_type: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Get aggregated statistics about past investigations

        Args:
            time_range_hours: Time range in hours (default: 168 = 7 days)
            alert_type: Optional filter by alert type (e.g., "phishing", "malware")

        Returns:
            Dictionary with statistics (total incidents, average threat score, etc.)
        """
        logger.info(f"Tool invoked: get_investigation_statistics(time_range_hours={time_range_hours}, alert_type={alert_type})")

        try:
            stats = await memory_manager.get_statistics(
                time_range_hours=time_range_hours,
                alert_type=alert_type
            )

            filter_msg = f" (filtered by alert_type='{alert_type}')" if alert_type else ""
            logger.info(f"get_investigation_statistics completed: {stats.get('total_incidents', 0)} incidents{filter_msg}")

            return {
                "statistics": stats,
                "time_range_hours": time_range_hours,
                "alert_type_filter": alert_type
            }
        except Exception as e:
            logger.error(f"Error in get_investigation_statistics tool: {e}", exc_info=True)
            return {
                "error": str(e),
                "statistics": {
                    "total_incidents": 0,
                    "error": str(e)
                }
            }

    @mcp_server.tool(
        description="Get detailed information about a specific security incident by its ID. Use when user asks about a specific incident, mentions an incident ID (format: ALT-YYYY-XXX), or wants detailed explanation of a particular investigation. Requires the incident_id parameter. Returns comprehensive incident details including threat score, attack stage, threat category, source IP, timestamp, and summary."
    )
    async def explain_incident(
        incident_id: str
    ) -> Dict[str, Any]:
        """
        Get detailed information about a specific incident

        Args:
            incident_id: Incident identifier (e.g., "ALT-2024-001", "ALT-2024-089")

        Returns:
            Dictionary with detailed incident information
        """
        logger.info(f"Tool invoked: explain_incident(incident_id={incident_id})")

        try:
            incident = await memory_manager.get_incident_by_id(incident_id)

            if incident:
                logger.info(f"explain_incident completed: found incident {incident_id}")
                return {
                    "incident": incident,
                    "found": True,
                    "incident_id": incident_id
                }
            else:
                logger.warning(f"explain_incident: incident {incident_id} not found")
                return {
                    "incident": None,
                    "found": False,
                    "incident_id": incident_id,
                    "message": "Incident not found"
                }
        except Exception as e:
            logger.error(f"Error in explain_incident tool: {e}", exc_info=True)
            return {
                "error": str(e),
                "incident": None,
                "found": False,
                "incident_id": incident_id
            }

    @mcp_server.tool(
        description="Find detected coordinated attack campaigns within a time window. Use when user asks about campaigns, coordinated attacks, multiple related incidents, or patterns of attacks. Identifies groups of related security incidents that may be part of the same attack campaign. Returns campaign information including campaign ID, confidence score, related incident IDs, time span, threat assessment, and source IPs."
    )
    async def find_campaigns(
        time_window_hours: int = 48
    ) -> Dict[str, Any]:
        """
        Find detected attack campaigns within a time window

        Args:
            time_window_hours: Time window in hours to search for campaigns (default: 48)

        Returns:
            Dictionary with list of detected campaigns and metadata
        """
        logger.info(f"Tool invoked: find_campaigns(time_window_hours={time_window_hours})")

        try:
            if memory_manager.incident_db is None:
                logger.warning("Memory DB not initialized, cannot find campaigns")
                return {
                    "campaigns": [],
                    "count": 0,
                    "time_window_hours": time_window_hours,
                    "error": "Memory database not initialized. Please check server logs."
                }

            campaigns = await memory_manager.find_campaigns(time_window_hours=time_window_hours)

            logger.info(f"find_campaigns completed: found {len(campaigns)} campaigns")

            return {
                "campaigns": campaigns,
                "count": len(campaigns),
                "time_window_hours": time_window_hours
            }
        except Exception as e:
            logger.error(f"Error in find_campaigns tool: {e}", exc_info=True)
            return {
                "error": str(e),
                "campaigns": [],
                "count": 0
            }

    @mcp_server.tool(
        description="Save a completed security investigation to the memory database. Use after an investigation is complete to store it for future reference and semantic search. Returns the incident_id if saved successfully, or None if duplicate/failed."
    )
    async def save_incident(
        incident_data: str
    ) -> Dict[str, Any]:
        """
        Save a completed investigation to memory

        Args:
            incident_data: JSON string containing incident data with fields:
                - alert_id: Unique identifier
                - alert_data: Original alert information
                - threat_score: Calculated threat score (0-1)
                - attack_stage: MITRE ATT&CK stage
                - threat_category: Category of threat
                - mitre_mappings: List of MITRE techniques
                - report: Investigation report text

        Returns:
            Dictionary with save status and incident_id
        """
        import json as json_module
        import re

        logger.info(f"Tool invoked: save_incident")

        try:
            # Parse JSON input
            if isinstance(incident_data, str):
                # Clean control characters that break JSON parsing
                # Replace problematic control chars but preserve valid JSON escapes
                cleaned_data = incident_data

                # Remove or replace control characters (except valid JSON whitespace)
                # This handles newlines, tabs, etc. that aren't properly escaped
                cleaned_data = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f]', '', cleaned_data)

                try:
                    data = json_module.loads(cleaned_data)
                except json_module.JSONDecodeError as json_err:
                    # Try with strict=False as fallback
                    logger.warning(f"Standard JSON parse failed, trying lenient mode: {json_err}")
                    try:
                        data = json_module.loads(cleaned_data, strict=False)
                    except json_module.JSONDecodeError:
                        # Last resort: try to extract key fields manually
                        logger.error(f"JSON parsing failed completely. Data preview: {incident_data[:500]}...")
                        raise
            else:
                data = incident_data

            if memory_manager.incident_db is None:
                logger.warning("Memory DB not initialized, cannot save incident")
                return {
                    "success": False,
                    "error": "Memory database not initialized",
                    "incident_id": None
                }

            incident_id = await memory_manager.save_incident(data)

            if incident_id:
                logger.info(f"save_incident completed: saved {incident_id}")
                return {
                    "success": True,
                    "incident_id": incident_id,
                    "message": f"Incident {incident_id} saved successfully"
                }
            else:
                logger.warning(f"save_incident: duplicate or failed")
                return {
                    "success": False,
                    "incident_id": None,
                    "message": "Incident already exists or save failed"
                }
        except Exception as e:
            logger.error(f"Error in save_incident tool: {e}", exc_info=True)
            return {
                "success": False,
                "error": str(e),
                "incident_id": None
            }

    @mcp_server.tool()
    async def health_check() -> Dict[str, Any]:
        """
        Health check endpoint for Memory & Chat server

        Returns:
            Server status and information
        """
        logger.debug("Tool invoked: health_check()")

        # Check initialization status
        db_initialized = memory_manager.incident_db is not None
        embeddings_initialized = memory_manager.embeddings is not None

        # Determine status
        if db_initialized and embeddings_initialized:
            status = "healthy"
        elif not db_initialized and not embeddings_initialized:
            status = "unavailable"
        else:
            status = "degraded"

        health_status = {
            "status": status,
            "server": "Memory & Chat MCP Server",
            "version": "1.0.0",
            "transport": "streamable_http",
            "tools_available": [
                "search_incidents",
                "get_investigation_statistics",
                "explain_incident",
                "find_campaigns",
                "save_incident"
            ],
            "memory_manager_initialized": db_initialized,
            "embeddings_initialized": embeddings_initialized,
            "persist_directory": memory_manager.persist_directory,
            "timestamp": datetime.utcnow().isoformat()
        }

        if not db_initialized:
            logger.warning("Health check: Memory manager not initialized")
            health_status["error"] = "Memory database not initialized. Check server startup logs for initialization errors."
            health_status["troubleshooting"] = [
                "1. Check that dependencies are installed: pip install langchain-community chromadb sentence-transformers",
                "2. Verify the persist_directory exists and is writable",
                "3. Check server startup logs for initialization errors",
                "4. Ensure the MCP server venv has all required packages"
            ]

        logger.info(f"Health check completed: status={status}")

        return health_status
