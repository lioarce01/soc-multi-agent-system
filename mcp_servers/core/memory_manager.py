"""
Isolated Memory Manager for MCP Servers
Uses Chroma vector DB for semantic search on past incidents
"""

import os
import logging
from pathlib import Path
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta

logger = logging.getLogger("memory_mcp_server.core")


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
            project_root = Path(__file__).parent.parent.parent
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
                # Import here to use the correct class
                try:
                    from langchain_huggingface import HuggingFaceEmbeddings
                except ImportError:
                    from langchain_community.embeddings import HuggingFaceEmbeddings

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
                try:
                    from langchain_chroma import Chroma
                except ImportError:
                    from langchain_community.vectorstores import Chroma

                self.incident_db = Chroma(
                    collection_name="past_incidents",
                    embedding_function=self.embeddings,
                    persist_directory=f"{persist_directory}/incidents"
                )
                logger.debug("Chroma database initialized successfully")

                # Test the database connection
                try:
                    test_results = self.incident_db.similarity_search("test", k=1)
                    logger.debug(f"Database connection test successful (found {len(test_results)} test results)")
                except Exception as test_error:
                    logger.warning(f"Database connection test failed, but continuing: {test_error}")

            except Exception as chroma_error:
                logger.error(f"Failed to initialize Chroma database: {chroma_error}", exc_info=True)
                raise

            logger.info(f"Memory manager initialized successfully: {persist_directory}")
            logger.info(f"   Collection: past_incidents")
            logger.info(f"   Embeddings: sentence-transformers/all-MiniLM-L6-v2")

        except Exception as e:
            logger.error(f"Failed to initialize memory manager: {e}", exc_info=True)
            logger.error("Memory features will be unavailable until this is fixed")
            self.incident_db = None
            self.embeddings = None

    def _reinitialize_db(self) -> bool:
        """Attempt to reinitialize the database connection"""
        try:
            try:
                from langchain_chroma import Chroma
                from langchain_huggingface import HuggingFaceEmbeddings
            except ImportError:
                from langchain_community.vectorstores import Chroma
                from langchain_community.embeddings import HuggingFaceEmbeddings

            self.embeddings = HuggingFaceEmbeddings(
                model_name="sentence-transformers/all-MiniLM-L6-v2"
            )
            self.incident_db = Chroma(
                collection_name="past_incidents",
                embedding_function=self.embeddings,
                persist_directory=f"{self.persist_directory}/incidents"
            )
            logger.info("Database reinitialized successfully")
            return True
        except Exception as reinit_error:
            logger.error(f"Failed to reinitialize database: {reinit_error}")
            return False

    def _verify_connection(self) -> bool:
        """Verify database connection is still valid"""
        try:
            _ = self.incident_db._collection
            return True
        except Exception as conn_error:
            logger.error(f"Database connection lost: {conn_error}", exc_info=True)
            logger.warning("Attempting to reinitialize database...")
            return self._reinitialize_db()

    def _collection_is_empty(self) -> bool:
        """Check if the collection has any documents"""
        try:
            collection = self.incident_db._collection
            count = collection.count()
            logger.debug(f"Collection document count: {count}")
            return count == 0
        except Exception as e:
            logger.warning(f"Could not check collection count: {e}")
            return True  # Assume empty if we can't check

    async def find_similar_incidents(
        self,
        query: str,
        k: int = 10,
        min_similarity: float = 0.3
    ) -> List[Dict[str, Any]]:
        """Find similar incidents using semantic search"""
        logger.debug(f"find_similar_incidents called: query='{query[:50]}...', k={k}, min_similarity={min_similarity}")

        if self.incident_db is None:
            logger.warning("Memory DB not initialized, returning empty results")
            return []

        if not self._verify_connection():
            return []

        try:
            # Check if collection is empty before searching
            if self._collection_is_empty():
                logger.info("Collection is empty, no incidents to search")
                return []

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

        if self.incident_db is None:
            logger.warning("Memory DB not initialized, returning empty statistics")
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

            # Check if collection is empty before searching
            if self._collection_is_empty():
                filter_msg = f" with alert_type='{alert_type}'" if alert_type else ""
                logger.info(f"Collection is empty, no incidents to analyze{filter_msg}")
                return {
                    "total_incidents": 0,
                    "time_range_hours": time_range_hours,
                    "alert_type_filter": alert_type,
                    "average_threat_score": 0.0,
                    "alert_types": {},
                    "attack_stages": {},
                    "high_severity_count": 0,
                    "message": "No incidents found in database. Run some investigations first."
                }

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
                except Exception:
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
                inc_alert_type = inc.get("alert_type", "unknown")
                alert_types[inc_alert_type] = alert_types.get(inc_alert_type, 0) + 1

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
            # Check if collection is empty before searching
            if self._collection_is_empty():
                logger.info(f"Collection is empty, incident {incident_id} not found")
                return None

            logger.info(f"Retrieving incident: {incident_id}")
            results = self.incident_db.similarity_search_with_score(
                f"incident {incident_id}",
                k=10
            )
            logger.debug(f"Found {len(results)} potential matches for incident {incident_id}")

            for doc, score in results:
                if doc.metadata.get("incident_id") == incident_id:
                    logger.info(f"Found incident {incident_id} with similarity score {score:.3f}")
                    return {
                        "incident_id": doc.metadata.get("incident_id"),
                        "timestamp": doc.metadata.get("timestamp"),
                        "alert_type": doc.metadata.get("alert_type"),
                        "threat_score": doc.metadata.get("threat_score", 0.0),
                        "attack_stage": doc.metadata.get("attack_stage"),
                        "threat_category": doc.metadata.get("threat_category"),
                        "source_ip": doc.metadata.get("source_ip"),
                        "summary": doc.page_content
                    }

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
            return []

        try:
            logger.info(f"Searching for campaigns in time window: {time_window_hours} hours")

            # Check if collection is empty before searching
            if self._collection_is_empty():
                logger.info("Collection is empty, no incidents to analyze for campaigns")
                return []

            results = self.incident_db.similarity_search("security incident", k=100)
            logger.debug(f"Retrieved {len(results)} incidents for campaign analysis")

            # Group by similar characteristics
            incidents_by_ip = {}
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
                except Exception:
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
                        except Exception:
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
                    logger.info(f"Detected campaign {campaign_id}: {len(incidents)} incidents from IP {ip}")

            logger.info(f"Found {len(campaigns)} campaigns in time window {time_window_hours} hours")
            return campaigns
        except Exception as e:
            logger.error(f"Error finding campaigns: {e}", exc_info=True)
            return []

    async def save_incident(
        self,
        incident_data: Dict[str, Any]
    ) -> Optional[str]:
        """
        Save an incident to the vector database

        Args:
            incident_data: Incident data including alert_id, alert_data, threat_score, etc.

        Returns:
            incident_id if saved successfully, None if duplicate or failed
        """
        if self.incident_db is None:
            logger.warning("Memory DB not initialized, cannot save incident")
            return None

        try:
            from langchain_core.documents import Document
        except ImportError:
            logger.error("langchain_core not available")
            return None

        incident_id = incident_data.get("alert_id", "UNKNOWN")
        timestamp = incident_data.get("timestamp", datetime.now().isoformat())

        # Extract alert data
        alert_data = incident_data.get("alert_data", {})
        alert_type = alert_data.get("type", "unknown")
        alert_description = alert_data.get("description", "")

        # Extract MITRE techniques
        mitre_mappings = incident_data.get("mitre_mappings", [])
        mitre_names = [m.get("name", "Unknown") for m in mitre_mappings]

        logger.info(f"Saving incident: {incident_id}")

        # Check for duplicate
        try:
            existing = self.incident_db._collection.get(
                where={"incident_id": incident_id}
            )
            if existing and existing.get("ids") and len(existing["ids"]) > 0:
                logger.warning(f"Incident {incident_id} already exists, skipping")
                return None
        except Exception as dedup_error:
            logger.warning(f"Dedup check failed: {dedup_error}")

        # Build document content
        content_parts = [
            f"Alert Type: {alert_type}",
            f"Description: {alert_description}",
            f"Attack Stage: {incident_data.get('attack_stage', 'Unknown')}",
            f"Threat Category: {incident_data.get('threat_category', 'Unknown')}",
            f"MITRE Techniques: {', '.join(mitre_names)}",
            f"Threat Score: {incident_data.get('threat_score', 0.0):.2f}",
        ]

        report = incident_data.get("report", "")
        if report:
            content_parts.append(f"Report: {report[:500]}")

        document = Document(
            page_content="\n".join(content_parts),
            metadata={
                "incident_id": incident_id,
                "timestamp": timestamp,
                "alert_type": alert_type,
                "threat_score": incident_data.get("threat_score", 0.0),
                "attack_stage": incident_data.get("attack_stage", "Unknown"),
                "threat_category": incident_data.get("threat_category", "Unknown"),
                "source_ip": alert_data.get("source_ip", "Unknown"),
            }
        )

        try:
            self.incident_db.add_documents([document])
            logger.info(f"Saved incident {incident_id} successfully")
            return incident_id
        except Exception as save_error:
            logger.error(f"Failed to save incident: {save_error}", exc_info=True)
            return None
