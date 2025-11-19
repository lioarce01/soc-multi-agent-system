"""
Memory Manager for Context Engineering
Handles long-term incident storage and semantic search
"""

from typing import Dict, Any, List, Optional
from datetime import datetime
import json
import os

from langgraph.store.memory import InMemoryStore
from langchain_community.vectorstores import Chroma
from langchain_community.embeddings import HuggingFaceEmbeddings
from langchain_core.documents import Document


class MemoryManager:
    """
    Three-tier memory system for security investigations

    1. Short-term: LangGraph State (handled by workflow)
    2. Long-term: LangGraph Store (this class)
    3. Semantic: Chroma Vector DB (this class)
    """

    def __init__(self, persist_directory: str = "./data/memory"):
        """
        Initialize memory manager

        Args:
            persist_directory: Where to persist memory data
        """
        # Create directory if it doesn't exist
        os.makedirs(persist_directory, exist_ok=True)
        os.makedirs(f"{persist_directory}/incidents", exist_ok=True)
        os.makedirs(f"{persist_directory}/playbooks", exist_ok=True)

        # Long-term structured storage (LangGraph Store)
        self.store = InMemoryStore()

        # Embeddings for semantic search (same as MITRE RAG)
        self.embeddings = HuggingFaceEmbeddings(
            model_name="sentence-transformers/all-MiniLM-L6-v2"
        )

        # Semantic vector stores
        self.incident_db = Chroma(
            collection_name="past_incidents",
            embedding_function=self.embeddings,
            persist_directory=f"{persist_directory}/incidents"
        )

        self.playbook_db = Chroma(
            collection_name="remediation_playbooks",
            embedding_function=self.embeddings,
            persist_directory=f"{persist_directory}/playbooks"
        )

        print(f"[MEMORY] Memory Manager initialized")
        print(f"  - LangGraph Store: In-memory")
        print(f"  - Vector DB: {persist_directory}")
        print(f"  - Embeddings: sentence-transformers/all-MiniLM-L6-v2")


    async def save_incident(
        self,
        user_id: str,
        incident_data: Dict[str, Any]
    ) -> str:
        """
        Save completed investigation to long-term memory

        Args:
            user_id: User/organization identifier
            incident_data: Complete investigation result

        Returns:
            incident_id: Unique identifier for saved incident
        """
        incident_id = incident_data.get("alert_id", "UNKNOWN")
        timestamp = incident_data.get("timestamp") or incident_data.get("created_at") or datetime.now().isoformat()

        # Extract alert data safely
        alert_data = incident_data.get("alert_data", {})
        alert_type = alert_data.get("type", "unknown")
        alert_description = alert_data.get("description", "")

        # Extract MITRE techniques
        mitre_mappings = incident_data.get("mitre_mappings", [])
        mitre_technique_ids = [
            m.get("technique_id", "Unknown")
            for m in mitre_mappings
        ]
        mitre_technique_names = [
            m.get("name", "Unknown")
            for m in mitre_mappings
        ]

        # 1. Store structured data in LangGraph Store
        await self.store.aput(
            namespace=(user_id, "incidents"),
            key=incident_id,
            value={
                "timestamp": timestamp,
                "alert_type": alert_type,
                "threat_score": incident_data.get("threat_score", 0.0),
                "attack_stage": incident_data.get("attack_stage", "Unknown"),
                "mitre_techniques": mitre_technique_ids,
                "threat_category": incident_data.get("threat_category", "Unknown"),
                "remediation_actions": incident_data.get("recommendations", []),
                "outcome": "investigated",  # Could be: resolved, escalated, false_positive
                "source_ip": alert_data.get("source_ip"),
                "destination_ip": alert_data.get("destination_ip"),
                "workflow_status": incident_data.get("workflow_status", "completed"),
            }
        )

        # 2. Index in vector store for semantic search
        report_text = incident_data.get("report", "")
        analysis_reasoning = incident_data.get("analysis_reasoning", "")
        investigation_findings = incident_data.get("investigation_findings", {})

        # Build searchable content
        content_parts = [
            f"Alert Type: {alert_type}",
            f"Description: {alert_description}",
            f"Attack Stage: {incident_data.get('attack_stage', 'Unknown')}",
            f"Threat Category: {incident_data.get('threat_category', 'Unknown')}",
            f"MITRE Techniques: {', '.join(mitre_technique_names)}",
            f"Threat Score: {incident_data.get('threat_score', 0.0):.2f}",
        ]

        # Add analysis reasoning if available
        if analysis_reasoning:
            content_parts.append(f"Analysis: {analysis_reasoning[:300]}")

        # Add investigation findings if available
        if investigation_findings:
            root_cause = investigation_findings.get("root_cause", "")
            if root_cause:
                content_parts.append(f"Root Cause: {root_cause}")

        # Add report excerpt
        if report_text:
            content_parts.append(f"Report: {report_text[:500]}")

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

        self.incident_db.add_documents([document])

        print(f"[MEMORY] ✅ Saved incident: {incident_id}")
        print(f"  - Timestamp: {timestamp}")
        print(f"  - Alert Type: {alert_type}")
        print(f"  - Threat Score: {incident_data.get('threat_score', 0.0):.2f}")
        print(f"  - MITRE Techniques: {len(mitre_mappings)}")

        return incident_id


    async def find_similar_incidents(
        self,
        current_alert: Dict[str, Any],
        k: int = 3,
        min_similarity: float = 0.6
    ) -> List[Dict[str, Any]]:
        """
        Find similar past incidents using semantic search

        Args:
            current_alert: Current alert being investigated
            k: Number of similar incidents to retrieve
            min_similarity: Minimum similarity score (0-1)

        Returns:
            List of similar incidents with metadata
        """
        # Build query from current alert
        query_parts = [
            f"Alert Type: {current_alert.get('type', 'unknown')}",
            f"Description: {current_alert.get('description', '')}",
        ]

        if current_alert.get("source_ip"):
            query_parts.append(f"Source IP: {current_alert['source_ip']}")

        if current_alert.get("destination_ip"):
            query_parts.append(f"Destination IP: {current_alert['destination_ip']}")

        query = "\n".join(query_parts)

        # Search vector store
        try:
            results = self.incident_db.similarity_search_with_score(
                query,
                k=k
            )
        except Exception as e:
            print(f"[MEMORY] ⚠️  Error searching incidents: {e}")
            return []

        # Filter by similarity and format
        similar_incidents = []
        for doc, score in results:
            # Convert distance to similarity (lower distance = higher similarity)
            # Chroma uses L2 distance, so we need to convert
            similarity = 1.0 / (1.0 + score)  # Normalize distance to 0-1 similarity

            if similarity >= min_similarity:
                similar_incidents.append({
                    "incident_id": doc.metadata.get("incident_id", "Unknown"),
                    "similarity_score": round(similarity, 3),
                    "alert_type": doc.metadata.get("alert_type", "unknown"),
                    "threat_score": doc.metadata.get("threat_score", 0.0),
                    "attack_stage": doc.metadata.get("attack_stage", "Unknown"),
                    "threat_category": doc.metadata.get("threat_category", "Unknown"),
                    "timestamp": doc.metadata.get("timestamp", "Unknown"),
                    "source_ip": doc.metadata.get("source_ip", "Unknown"),
                    "summary": doc.page_content[:200] + "..."  # First 200 chars
                })

        if similar_incidents:
            print(f"[MEMORY] 🔍 Found {len(similar_incidents)} similar past incidents:")
            for incident in similar_incidents:
                print(f"  - {incident['incident_id']}: {incident['similarity_score']:.0%} similar ({incident['alert_type']})")
        else:
            print(f"[MEMORY] ℹ️  No similar incidents found (threshold: {min_similarity:.0%})")

        return similar_incidents


    async def get_incident_by_id(
        self,
        user_id: str,
        incident_id: str
    ) -> Optional[Dict[str, Any]]:
        """
        Retrieve specific incident from long-term storage

        Args:
            user_id: User/organization identifier
            incident_id: Incident identifier

        Returns:
            Incident data or None if not found
        """
        try:
            incident = await self.store.aget(
                namespace=(user_id, "incidents"),
                key=incident_id
            )
            if incident:
                print(f"[MEMORY] Retrieved incident: {incident_id}")
                return incident.value
            else:
                print(f"[MEMORY] Incident not found: {incident_id}")
                return None
        except Exception as e:
            print(f"[MEMORY] ⚠️  Error retrieving incident {incident_id}: {e}")
            return None


    async def get_all_incidents(
        self,
        user_id: str,
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        """
        Retrieve all incidents for a user

        Args:
            user_id: User/organization identifier
            limit: Maximum number of incidents to return

        Returns:
            List of incidents
        """
        try:
            # Search namespace for all incidents
            # Note: asearch takes namespace_prefix as positional argument
            incidents = await self.store.asearch(
                (user_id, "incidents")  # Positional, not keyword
            )

            results = []
            for item in incidents[:limit]:
                results.append({
                    "incident_id": item.key,
                    **item.value
                })

            print(f"[MEMORY] Retrieved {len(results)} incidents for user {user_id}")
            return results

        except Exception as e:
            print(f"[MEMORY] ⚠️  Error retrieving incidents: {e}")
            return []


    async def save_playbook(
        self,
        playbook_name: str,
        playbook_content: str,
        metadata: Dict[str, Any]
    ):
        """
        Save remediation playbook to knowledge base

        Args:
            playbook_name: Unique playbook identifier
            playbook_content: Full playbook text
            metadata: Additional metadata (threat_type, severity, etc.)
        """
        document = Document(
            page_content=playbook_content,
            metadata={
                "playbook_name": playbook_name,
                "timestamp": datetime.now().isoformat(),
                **metadata
            }
        )

        self.playbook_db.add_documents([document])
        print(f"[MEMORY] 📋 Saved playbook: {playbook_name}")


    async def get_relevant_playbook(
        self,
        threat_type: str,
        attack_stage: str = None
    ) -> Optional[Dict[str, Any]]:
        """
        Retrieve relevant remediation playbook from knowledge base

        Args:
            threat_type: Type of threat (phishing, malware, etc.)
            attack_stage: MITRE ATT&CK attack stage

        Returns:
            Relevant playbook or None
        """
        query = f"Threat Type: {threat_type}"
        if attack_stage:
            query += f"\nAttack Stage: {attack_stage}"

        try:
            results = self.playbook_db.similarity_search(query, k=1)

            if results:
                playbook = results[0]
                print(f"[MEMORY] 📋 Retrieved playbook: {playbook.metadata.get('playbook_name', 'Unknown')}")
                return {
                    "name": playbook.metadata.get("playbook_name", "Unknown"),
                    "content": playbook.page_content,
                    "metadata": playbook.metadata
                }
            else:
                print(f"[MEMORY] ℹ️  No playbook found for: {threat_type}")
                return None

        except Exception as e:
            print(f"[MEMORY] ⚠️  Error retrieving playbook: {e}")
            return None


    async def get_statistics(
        self,
        user_id: str,
        time_range_hours: int = 168  # Default: last 7 days
    ) -> Dict[str, Any]:
        """
        Get aggregated statistics about past incidents

        Args:
            user_id: User/organization identifier
            time_range_hours: Time range in hours

        Returns:
            Statistics dictionary
        """
        incidents = await self.get_all_incidents(user_id)

        # Filter by time range
        cutoff_time = datetime.now().timestamp() - (time_range_hours * 3600)
        recent_incidents = []

        for incident in incidents:
            try:
                incident_time = datetime.fromisoformat(incident["timestamp"]).timestamp()
                if incident_time >= cutoff_time:
                    recent_incidents.append(incident)
            except:
                continue

        # Calculate statistics
        total_incidents = len(recent_incidents)

        if total_incidents == 0:
            return {
                "total_incidents": 0,
                "time_range_hours": time_range_hours,
                "average_threat_score": 0.0,
                "alert_types": {},
                "attack_stages": {},
                "high_severity_count": 0
            }

        # Average threat score
        threat_scores = [inc.get("threat_score", 0.0) for inc in recent_incidents]
        avg_threat_score = sum(threat_scores) / len(threat_scores) if threat_scores else 0.0

        # Alert type distribution
        alert_types = {}
        for incident in recent_incidents:
            alert_type = incident.get("alert_type", "unknown")
            alert_types[alert_type] = alert_types.get(alert_type, 0) + 1

        # Attack stage distribution
        attack_stages = {}
        for incident in recent_incidents:
            stage = incident.get("attack_stage", "Unknown")
            attack_stages[stage] = attack_stages.get(stage, 0) + 1

        # High severity count (threat score >= 0.7)
        high_severity = sum(1 for score in threat_scores if score >= 0.7)

        stats = {
            "total_incidents": total_incidents,
            "time_range_hours": time_range_hours,
            "average_threat_score": round(avg_threat_score, 3),
            "alert_types": alert_types,
            "attack_stages": attack_stages,
            "high_severity_count": high_severity,
            "high_severity_percentage": round(high_severity / total_incidents * 100, 1) if total_incidents > 0 else 0
        }

        print(f"[MEMORY] 📊 Statistics for last {time_range_hours}h:")
        print(f"  - Total Incidents: {total_incidents}")
        print(f"  - Average Threat Score: {avg_threat_score:.2f}")
        print(f"  - High Severity: {high_severity} ({stats['high_severity_percentage']}%)")

        return stats


# Global instance (singleton pattern)
_memory_manager: Optional[MemoryManager] = None


def get_memory_manager() -> MemoryManager:
    """Get or create global Memory Manager instance"""
    global _memory_manager

    if _memory_manager is None:
        _memory_manager = MemoryManager()

    return _memory_manager
