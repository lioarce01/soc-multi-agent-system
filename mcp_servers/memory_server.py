"""
Memory & Chat MCP Server - Isolated Implementation
Exposes investigation history query tools via MCP protocol (streamable_http)
This server is isolated from the main LangGraph application
"""

import sys
from pathlib import Path

# Add parent directory to path for imports (only for data access)
sys.path.insert(0, str(Path(__file__).parent.parent))

# Load environment variables from .env
from dotenv import load_dotenv
load_dotenv(Path(__file__).parent.parent / ".env")

from fastmcp import FastMCP
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
import json
import os
import logging

# ===== Logging Configuration =====
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger("memory_mcp_server")

# ===== Isolated Memory Manager Implementation =====

class IsolatedMemoryManager:
    """
    Isolated memory manager for MCP server
    Uses Chroma vector DB directly without LangGraph dependencies
    """

    def __init__(self, persist_directory: str = None):
        """Initialize isolated memory manager"""
        self.incident_db = None
        self.embeddings = None

        # Use absolute path to project root's data/memory directory
        # This ensures we read from the same location regardless of working directory
        if persist_directory is None:
            project_root = Path(__file__).parent.parent
            persist_directory = str(project_root / "data" / "memory")

        self.persist_directory = persist_directory
        
        try:
            logger.info(f"Initializing memory manager with directory: {persist_directory}")
            
            # Check dependencies - try new packages first, fallback to deprecated ones
            try:
                # Try new non-deprecated packages first
                try:
                    from langchain_chroma import Chroma
                    from langchain_huggingface import HuggingFaceEmbeddings
                    logger.debug("Using langchain-chroma and langchain-huggingface (recommended)")
                except ImportError:
                    # Fallback to deprecated packages (still work but will show warnings)
                    from langchain_community.vectorstores import Chroma
                    from langchain_community.embeddings import HuggingFaceEmbeddings
                    logger.warning("Using deprecated langchain-community packages. Install langchain-chroma and langchain-huggingface for better compatibility.")
                
                from langchain_core.documents import Document
                logger.debug("Successfully imported required libraries")
            except ImportError as import_error:
                logger.error(f"Missing required dependencies: {import_error}")
                logger.error("Please install: langchain-chroma langchain-huggingface chromadb sentence-transformers")
                logger.error("Or fallback: langchain-community chromadb sentence-transformers")
                raise
            
            # Create directory if it doesn't exist
            try:
                os.makedirs(persist_directory, exist_ok=True)
                os.makedirs(f"{persist_directory}/incidents", exist_ok=True)
                logger.debug(f"Created directories: {persist_directory}")
            except Exception as dir_error:
                logger.error(f"Failed to create directories: {dir_error}")
                raise
            
            # Initialize embeddings
            try:
                logger.info("Loading HuggingFace embeddings model...")
                self.embeddings = HuggingFaceEmbeddings(
                    model_name="sentence-transformers/all-MiniLM-L6-v2"
                )
                logger.debug("Embeddings model loaded successfully")
            except Exception as embed_error:
                logger.error(f"Failed to load embeddings model: {embed_error}", exc_info=True)
                raise
            
            # Initialize Chroma vector store
            try:
                logger.info("Initializing Chroma vector database...")
                self.incident_db = Chroma(
                    collection_name="past_incidents",
                    embedding_function=self.embeddings,
                    persist_directory=f"{persist_directory}/incidents"
                )
                logger.debug("Chroma database initialized successfully")
                
                # Test the database connection
                try:
                    # Try a simple query to verify it works
                    test_results = self.incident_db.similarity_search("test", k=1)
                    logger.debug(f"Database connection test successful (found {len(test_results)} test results)")
                except Exception as test_error:
                    logger.warning(f"Database connection test failed, but continuing: {test_error}")
                
            except Exception as chroma_error:
                logger.error(f"Failed to initialize Chroma database: {chroma_error}", exc_info=True)
                raise
            
            logger.info(f"✅ Memory manager initialized successfully: {persist_directory}")
            logger.info(f"   Collection: past_incidents")
            logger.info(f"   Embeddings: sentence-transformers/all-MiniLM-L6-v2")
            
        except Exception as e:
            logger.error(f"❌ Failed to initialize memory manager: {e}", exc_info=True)
            logger.error("Memory features will be unavailable until this is fixed")
            self.incident_db = None
            self.embeddings = None
    
    async def find_similar_incidents(
        self,
        query: str,
        k: int = 10,
        min_similarity: float = 0.3
    ) -> List[Dict[str, Any]]:
        """Find similar incidents using semantic search"""
        logger.debug(f"find_similar_incidents called: query='{query[:50]}...', k={k}, min_similarity={min_similarity}")
        
        # Check if database is initialized
        if self.incident_db is None:
            logger.warning("Memory DB not initialized, returning empty results")
            logger.warning(f"  incident_db: {self.incident_db}")
            logger.warning(f"  embeddings: {self.embeddings is not None}")
            logger.warning(f"  persist_directory: {self.persist_directory}")
            logger.warning(f"  self instance ID: {id(self)}")
            return []
        
        # Log database instance info for debugging
        logger.debug(f"Database instance check - ID: {id(self.incident_db)}, Type: {type(self.incident_db).__name__}")
        
        # Verify database connection is still valid
        try:
            # Quick check to ensure database is accessible
            _ = self.incident_db._collection  # Access internal collection to verify connection
        except Exception as conn_error:
            logger.error(f"Database connection lost: {conn_error}", exc_info=True)
            logger.warning("Attempting to reinitialize database...")
            # Try to reinitialize
            try:
                from langchain_community.vectorstores import Chroma
                self.incident_db = Chroma(
                    collection_name="past_incidents",
                    embedding_function=self.embeddings,
                    persist_directory=f"{self.persist_directory}/incidents"
                )
                logger.info("Database reinitialized successfully")
            except Exception as reinit_error:
                logger.error(f"Failed to reinitialize database: {reinit_error}")
                return []
        
        try:
            logger.info(f"Searching for similar incidents: query='{query[:100]}'")
            results = self.incident_db.similarity_search_with_score(query, k=k)
            logger.debug(f"Found {len(results)} raw results from vector search")
            
            similar_incidents = []
            for doc, score in results:
                # Convert distance to similarity
                similarity = 1.0 / (1.0 + score)
                
                if similarity >= min_similarity:
                    incident_id = doc.metadata.get("incident_id", "Unknown")
                    similar_incidents.append({
                        "incident_id": incident_id,
                        "similarity_score": round(similarity, 3),
                        "alert_type": doc.metadata.get("alert_type", "unknown"),
                        "threat_score": doc.metadata.get("threat_score", 0.0),
                        "attack_stage": doc.metadata.get("attack_stage", "Unknown"),
                        "threat_category": doc.metadata.get("threat_category", "Unknown"),
                        "timestamp": doc.metadata.get("timestamp", "Unknown"),
                        "source_ip": doc.metadata.get("source_ip", "Unknown"),
                        "summary": doc.page_content[:200] + "..." if len(doc.page_content) > 200 else doc.page_content
                    })
                    logger.debug(f"Added incident {incident_id} with similarity {similarity:.3f}")
            
            logger.info(f"Returning {len(similar_incidents)} similar incidents (filtered by min_similarity={min_similarity})")
            return similar_incidents
        except Exception as e:
            logger.error(f"Error searching incidents: {e}", exc_info=True)
            return []
    
    async def get_statistics(
        self,
        time_range_hours: int = 168,
        alert_type: Optional[str] = None
    ) -> Dict[str, Any]:
        """Get aggregated statistics, optionally filtered by alert_type"""
        logger.debug(f"get_statistics called: time_range_hours={time_range_hours}, alert_type={alert_type}")
        
        # Check if database is initialized
        if self.incident_db is None:
            logger.warning("Memory DB not initialized, returning empty statistics")
            logger.warning(f"  incident_db: {self.incident_db}")
            logger.warning(f"  embeddings: {self.embeddings is not None}")
            logger.warning(f"  persist_directory: {self.persist_directory}")
            return {
                "total_incidents": 0,
                "time_range_hours": time_range_hours,
                "average_threat_score": 0.0,
                "alert_types": {},
                "attack_stages": {},
                "high_severity_count": 0
            }
        
        try:
            logger.info(f"Calculating statistics for time range: {time_range_hours} hours")
            # Get all incidents from vector store (limited search)
            # Note: Chroma doesn't have a direct "get all" method, so we use a broad search
            results = self.incident_db.similarity_search("security incident", k=1000)
            logger.debug(f"Retrieved {len(results)} incidents from vector store")
            
            # Filter by time range
            cutoff_time = datetime.now() - timedelta(hours=time_range_hours)
            recent_incidents = []
            
            for doc in results:
                try:
                    timestamp_str = doc.metadata.get("timestamp", "")
                    if timestamp_str:
                        incident_time = datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
                        if incident_time.tzinfo:
                            incident_time = incident_time.replace(tzinfo=None)

                        if incident_time >= cutoff_time:
                            incident_alert_type = doc.metadata.get("alert_type", "unknown")

                            # Filter by alert_type if specified (BEFORE aggregation)
                            if alert_type and incident_alert_type != alert_type:
                                continue

                            recent_incidents.append({
                                "threat_score": doc.metadata.get("threat_score", 0.0),
                                "alert_type": incident_alert_type,
                                "attack_stage": doc.metadata.get("attack_stage", "Unknown")
                            })
                except:
                    continue
            
            if not recent_incidents:
                filter_msg = f" with alert_type='{alert_type}'" if alert_type else ""
                logger.info(f"No incidents found in time range {time_range_hours} hours{filter_msg}")
                return {
                    "total_incidents": 0,
                    "time_range_hours": time_range_hours,
                    "alert_type_filter": alert_type,
                    "average_threat_score": 0.0,
                    "alert_types": {},
                    "attack_stages": {},
                    "high_severity_count": 0
                }
            
            logger.debug(f"Processing {len(recent_incidents)} recent incidents for statistics")
            
            # Calculate statistics
            total = len(recent_incidents)
            threat_scores = [inc.get("threat_score", 0.0) for inc in recent_incidents]
            avg_threat_score = sum(threat_scores) / len(threat_scores) if threat_scores else 0.0
            
            # Alert type distribution
            alert_types = {}
            for inc in recent_incidents:
                alert_type = inc.get("alert_type", "unknown")
                alert_types[alert_type] = alert_types.get(alert_type, 0) + 1
            
            # Attack stage distribution
            attack_stages = {}
            for inc in recent_incidents:
                stage = inc.get("attack_stage", "Unknown")
                attack_stages[stage] = attack_stages.get(stage, 0) + 1
            
            # High severity count
            high_severity = sum(1 for score in threat_scores if score >= 0.7)
            
            stats = {
                "total_incidents": total,
                "time_range_hours": time_range_hours,
                "alert_type_filter": alert_type,
                "average_threat_score": round(avg_threat_score, 3),
                "alert_types": alert_types,
                "attack_stages": attack_stages,
                "high_severity_count": high_severity,
                "high_severity_percentage": round(high_severity / total * 100, 1) if total > 0 else 0
            }
            
            logger.info(f"Statistics calculated: {total} incidents, avg_threat={avg_threat_score:.3f}, high_severity={high_severity}")
            logger.debug(f"Alert types: {alert_types}, Attack stages: {attack_stages}")
            
            return stats
        except Exception as e:
            logger.error(f"Error getting statistics: {e}", exc_info=True)
            return {
                "total_incidents": 0,
                "error": str(e)
            }
    
    async def get_incident_by_id(
        self,
        incident_id: str
    ) -> Optional[Dict[str, Any]]:
        """Get specific incident by ID"""
        logger.debug(f"get_incident_by_id called: incident_id={incident_id}")
        
        if not self.incident_db:
            logger.warning("Memory DB not initialized, cannot retrieve incident")
            return None
        
        try:
            logger.info(f"Retrieving incident: {incident_id}")
            # Search for incident with specific ID in metadata
            results = self.incident_db.similarity_search_with_score(
                f"incident {incident_id}",
                k=10
            )
            logger.debug(f"Found {len(results)} potential matches for incident {incident_id}")
            
            for doc, score in results:
                if doc.metadata.get("incident_id") == incident_id:
                    logger.info(f"Found incident {incident_id} with similarity score {score:.3f}")
                    incident_data = {
                        "incident_id": doc.metadata.get("incident_id"),
                        "timestamp": doc.metadata.get("timestamp"),
                        "alert_type": doc.metadata.get("alert_type"),
                        "threat_score": doc.metadata.get("threat_score", 0.0),
                        "attack_stage": doc.metadata.get("attack_stage"),
                        "threat_category": doc.metadata.get("threat_category"),
                        "source_ip": doc.metadata.get("source_ip"),
                        "summary": doc.page_content
                    }
                    return incident_data
            
            logger.warning(f"Incident {incident_id} not found in database")
            return None
        except Exception as e:
            logger.error(f"Error retrieving incident {incident_id}: {e}", exc_info=True)
            return None
    
    async def find_campaigns(
        self,
        time_window_hours: int = 48
    ) -> List[Dict[str, Any]]:
        """Find campaigns by analyzing incident patterns"""
        logger.debug(f"find_campaigns called: time_window_hours={time_window_hours}")
        
        if self.incident_db is None:
            logger.warning("Memory DB not initialized, cannot find campaigns")
            logger.warning(f"  incident_db: {self.incident_db}")
            logger.warning(f"  embeddings: {self.embeddings is not None}")
            logger.warning(f"  persist_directory: {self.persist_directory}")
            return []
        
        try:
            logger.info(f"Searching for campaigns in time window: {time_window_hours} hours")
            # Get recent incidents
            results = self.incident_db.similarity_search("security incident", k=100)
            logger.debug(f"Retrieved {len(results)} incidents for campaign analysis")
            
            # Group by similar characteristics
            incidents_by_ip = {}
            incidents_by_technique = {}
            
            cutoff_time = datetime.now() - timedelta(hours=time_window_hours)
            
            for doc in results:
                try:
                    timestamp_str = doc.metadata.get("timestamp", "")
                    if timestamp_str:
                        incident_time = datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
                        if incident_time.tzinfo:
                            incident_time = incident_time.replace(tzinfo=None)
                        
                        if incident_time < cutoff_time:
                            continue
                    
                    source_ip = doc.metadata.get("source_ip")
                    incident_id = doc.metadata.get("incident_id", "Unknown")
                    
                    if source_ip and source_ip != "Unknown":
                        if source_ip not in incidents_by_ip:
                            incidents_by_ip[source_ip] = []
                        incidents_by_ip[source_ip].append({
                            "incident_id": incident_id,
                            "timestamp": timestamp_str,
                            "threat_score": doc.metadata.get("threat_score", 0.0)
                        })
                except:
                    continue
            
            # Detect campaigns (3+ incidents from same IP or similar pattern)
            campaigns = []
            for ip, incidents in incidents_by_ip.items():
                if len(incidents) >= 3:
                    campaign_id = f"CAMPAIGN-{ip.replace('.', '')[-8:].upper()}"
                    timestamps = [inc["timestamp"] for inc in incidents if inc["timestamp"]]
                    
                    time_span = 0.0
                    if timestamps:
                        try:
                            times = [datetime.fromisoformat(ts.replace("Z", "+00:00")) for ts in timestamps]
                            if times:
                                time_span = (max(times) - min(times)).total_seconds() / 3600
                        except:
                            pass
                    
                    campaign_data = {
                        "campaign_id": campaign_id,
                        "confidence": min(0.95, 0.6 + (len(incidents) - 3) * 0.1),
                        "incident_count": len(incidents),
                        "related_incidents": [inc["incident_id"] for inc in incidents],
                        "time_span_hours": round(time_span, 1),
                        "threat_assessment": "ONGOING_CAMPAIGN" if time_span < 24 else "MULTI_WAVE_CAMPAIGN",
                        "source_ip": ip
                    }
                    campaigns.append(campaign_data)
                    logger.info(f"Detected campaign {campaign_id}: {len(incidents)} incidents from IP {ip}, confidence={campaign_data['confidence']:.2f}")
            
            logger.info(f"Found {len(campaigns)} campaigns in time window {time_window_hours} hours")
            return campaigns
        except Exception as e:
            logger.error(f"Error finding campaigns: {e}", exc_info=True)
            return []


# ===== Initialize Memory Manager =====

logger.info("=" * 60)
logger.info("🧠 Memory & Chat MCP Server")
logger.info("=" * 60)
logger.info("Initializing memory manager...")

memory_manager = IsolatedMemoryManager()

# Check if initialization was successful
if memory_manager.incident_db is None:
    logger.error("=" * 60)
    logger.error("⚠️  WARNING: Memory database not initialized!")
    logger.error("Memory features (search, statistics, campaigns) will not work.")
    logger.error("Check the error messages above for details.")
    logger.error("=" * 60)
else:
    logger.info("=" * 60)
    logger.info("✅ Memory manager ready")
    logger.info(f"   Database instance: {type(memory_manager.incident_db).__name__}")
    logger.info(f"   Database ID: {id(memory_manager.incident_db)}")
    logger.info(f"   Embeddings ID: {id(memory_manager.embeddings)}")
    logger.info("=" * 60)

# ===== Initialize FastMCP Server =====

mcp_server = FastMCP(
    name="Memory & Chat MCP Server",
    version="1.0.0"
)


# ===== MCP Tools =====

@mcp_server.tool(
    description="Search past security investigations using semantic search. Use when user asks to find, search, or look for incidents, alerts, or investigations. Use get_investigation_statistics for statistics and summaries - this tool is for finding individual incidents. Supports filtering by alert type (phishing, malware, brute_force). If only alert_type is provided, use that as the search query. Returns list of matching incidents with similarity scores, threat scores, and metadata."
)
async def search_incidents(
    query: Optional[str] = None,
    alert_type: Optional[str] = None,
    limit: int = 10
) -> Dict[str, Any]:
    """
    Search past investigations using semantic search
    
    Args:
        query: Optional search query text (e.g., "phishing emails", "malware detection"). If not provided, alert_type will be used as the query.
        alert_type: Optional filter by alert type (e.g., "phishing", "malware", "brute_force"). Can also be used as the search query if query is not provided.
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
    
    logger.info(f"Tool invoked: search_incidents(query='{query[:50]}...', alert_type={alert_type}, limit={limit})")
    
    # Debug: Check memory manager state
    logger.debug(f"Memory manager check - incident_db: {memory_manager.incident_db is not None}")
    logger.debug(f"Memory manager check - embeddings: {memory_manager.embeddings is not None}")
    logger.debug(f"Memory manager check - instance ID: {id(memory_manager)}")
    if memory_manager.incident_db is not None:
        logger.debug(f"Memory manager check - DB type: {type(memory_manager.incident_db).__name__}")
        logger.debug(f"Memory manager check - DB ID: {id(memory_manager.incident_db)}")
    
    try:
        # Check if database is initialized
        if memory_manager.incident_db is None:
            logger.warning("Memory DB not initialized, returning empty results")
            logger.warning(f"  incident_db: {memory_manager.incident_db}")
            logger.warning(f"  embeddings: {memory_manager.embeddings is not None}")
            logger.warning(f"  persist_directory: {memory_manager.persist_directory}")
            logger.warning(f"  memory_manager instance ID: {id(memory_manager)}")
            return {
                "incidents": [],
                "count": 0,
                "error": "Memory database not initialized. Please check server logs."
            }
        
        # Verify database connection is still valid
        try:
            _ = memory_manager.incident_db._collection  # Access internal collection to verify connection
            logger.debug(f"Database connection verified for search_incidents (collection name: {memory_manager.incident_db._collection.name})")
        except Exception as conn_error:
            logger.error(f"Database connection lost in search_incidents: {conn_error}", exc_info=True)
            logger.warning("Attempting to reinitialize database in search_incidents...")
            # Try to reinitialize
            try:
                from langchain_chroma import Chroma
                from langchain_huggingface import HuggingFaceEmbeddings
                memory_manager.embeddings = HuggingFaceEmbeddings(model_name="sentence-transformers/all-MiniLM-L6-v2")
                memory_manager.incident_db = Chroma(
                    collection_name="past_incidents",
                    embedding_function=memory_manager.embeddings,
                    persist_directory=f"{memory_manager.persist_directory}/incidents"
                )
                logger.info("Database reinitialized successfully in search_incidents.")
            except Exception as reinit_error:
                logger.error(f"Failed to reinitialize database in search_incidents: {reinit_error}", exc_info=True)
                return {
                    "incidents": [],
                    "count": 0,
                    "error": f"Memory database reinitialization failed: {reinit_error}"
                }
        
        # Build search query
        search_query = query
        if alert_type and alert_type != query:
            # If alert_type is different from query, append it to refine search
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
        
        logger.info(f"search_incidents completed: found {len(results)} incidents")
        
        return {
            "incidents": results,
            "count": len(results),
            "query": query,
            "filters": {"alert_type": alert_type} if alert_type else None
        }
    except Exception as e:
        logger.error(f"Error in search_incidents tool: {e}", exc_info=True)
        return {
            "error": str(e),
            "incidents": [],
            "count": 0
        }


@mcp_server.tool(
    description="Get aggregated statistics and summary metrics about past security investigations. Use when user asks for statistics, summaries, counts, averages, trends, or aggregated data about incidents. IMPORTANT: This tool can filter by alert type - use alert_type parameter (e.g., 'malware', 'phishing', 'brute_force') to get statistics for specific attack types. Supports time range filtering (hours). Returns total incidents, average threat score, alert type distribution, attack stage distribution, and high severity counts. Examples: 'malware statistics', 'phishing stats', 'statistics for brute force attacks'."
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
    logger.debug(f"Memory manager instance check - DB: {memory_manager.incident_db is not None}, ID: {id(memory_manager)}")
    
    try:
        # Pass alert_type to get_statistics for PROPER filtering BEFORE aggregation
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
    
    # Debug: Check memory manager state
    logger.debug(f"Memory manager check - incident_db: {memory_manager.incident_db is not None}")
    logger.debug(f"Memory manager check - embeddings: {memory_manager.embeddings is not None}")
    logger.debug(f"Memory manager check - instance ID: {id(memory_manager)}")
    if memory_manager.incident_db is not None:
        logger.debug(f"Memory manager check - DB type: {type(memory_manager.incident_db).__name__}")
        logger.debug(f"Memory manager check - DB ID: {id(memory_manager.incident_db)}")
    
    try:
        # Check if database is initialized
        if memory_manager.incident_db is None:
            logger.warning("Memory DB not initialized, cannot find campaigns")
            logger.warning(f"  incident_db: {memory_manager.incident_db}")
            logger.warning(f"  embeddings: {memory_manager.embeddings is not None}")
            logger.warning(f"  persist_directory: {memory_manager.persist_directory}")
            logger.warning(f"  memory_manager instance ID: {id(memory_manager)}")
            return {
                "campaigns": [],
                "count": 0,
                "time_window_hours": time_window_hours,
                "error": "Memory database not initialized. Please check server logs."
            }
        
        # Verify database connection is still valid
        try:
            _ = memory_manager.incident_db._collection  # Access internal collection to verify connection
            logger.debug(f"Database connection verified for find_campaigns (collection name: {memory_manager.incident_db._collection.name})")
        except Exception as conn_error:
            logger.error(f"Database connection lost in find_campaigns: {conn_error}", exc_info=True)
            logger.warning("Attempting to reinitialize database in find_campaigns...")
            # Try to reinitialize
            try:
                from langchain_chroma import Chroma
                from langchain_huggingface import HuggingFaceEmbeddings
                memory_manager.embeddings = HuggingFaceEmbeddings(model_name="sentence-transformers/all-MiniLM-L6-v2")
                memory_manager.incident_db = Chroma(
                    collection_name="past_incidents",
                    embedding_function=memory_manager.embeddings,
                    persist_directory=f"{memory_manager.persist_directory}/incidents"
                )
                logger.info("Database reinitialized successfully in find_campaigns.")
            except Exception as reinit_error:
                logger.error(f"Failed to reinitialize database in find_campaigns: {reinit_error}", exc_info=True)
                return {
                    "campaigns": [],
                    "count": 0,
                    "time_window_hours": time_window_hours,
                    "error": f"Memory database reinitialization failed: {reinit_error}"
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
            "find_campaigns"
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
    
    logger.info(f"Health check completed: status={status}, db={'initialized' if db_initialized else 'NOT initialized'}, embeddings={'initialized' if embeddings_initialized else 'NOT initialized'}")
    
    return health_status


# ===== Run Server =====

if __name__ == "__main__":
    logger.info("="*60)
    logger.info("Memory & Chat MCP Server")
    logger.info("="*60)
    logger.info(f"Transport: HTTP")
    logger.info(f"Host: 0.0.0.0")
    logger.info(f"Port: 8003")
    logger.info(f"Available Tools:")
    logger.info("  - search_incidents()")
    logger.info("  - get_investigation_statistics()")
    logger.info("  - explain_incident()")
    logger.info("  - find_campaigns()")
    logger.info("  - health_check()")
    logger.info("="*60)
    
    # Final status check before starting server
    if memory_manager.incident_db is None:
        logger.error("="*60)
        logger.error("⚠️  CRITICAL: Memory database failed to initialize!")
        logger.error("="*60)
        logger.error("The server will start, but memory features will not work.")
        logger.error("")
        logger.error("To fix this:")
        logger.error("1. Install missing dependencies:")
        logger.error("   pip install langchain-community chromadb sentence-transformers")
        logger.error("")
        logger.error("2. Check the error messages above for specific issues")
        logger.error("")
        logger.error("3. Verify the data directory is writable:")
        logger.error(f"   Directory: {memory_manager.persist_directory}")
        logger.error("="*60)
    else:
        logger.info("✅ Server ready - Memory database initialized")
        logger.info("="*60)
    
    logger.info("\nStarting server on http://0.0.0.0:8003...")
    logger.info("Use the health_check() tool to verify initialization status")
    
    # Run with HTTP transport
    mcp_server.run(transport="http", host="0.0.0.0", port=8003)
