"""
Memory Manager for Context Engineering

Architecture:
- Incidents: Handled by LangGraph agents via MCP Memory Server tools
- Playbooks: Stored locally in ChromaDB
- LangGraph Store: In-memory for session data

Note: Incident save/search operations are performed by agents using MCP tools
(save_incident, search_incidents). This class only handles playbooks locally.
"""

from typing import Dict, Any, List, Optional
from datetime import datetime
import json
import os

from langgraph.store.memory import InMemoryStore
from langchain_core.documents import Document

# Try to use newer packages first, fallback to deprecated ones
try:
    from langchain_chroma import Chroma
    from langchain_huggingface import HuggingFaceEmbeddings
    print("[MEMORY] Using langchain-chroma and langchain-huggingface (recommended)")
except ImportError:
    # Fallback to deprecated packages
    from langchain_community.vectorstores import Chroma
    from langchain_community.embeddings import HuggingFaceEmbeddings
    print("[MEMORY] ⚠️  Using deprecated langchain-community packages.")


class MemoryManager:
    """
    Memory system for security investigations

    Architecture:
    - Incidents: Handled by agents via MCP Memory Server tools
    - Playbooks: Local ChromaDB (this class)
    - Session data: LangGraph Store (this class)

    Note: For incidents, agents use MCP tools:
    - save_incident: Save completed investigation
    - search_incidents: Find similar past incidents
    - get_investigation_statistics: Get aggregated stats
    """

    def __init__(self, persist_directory: str = "./data/memory"):
        """
        Initialize memory manager

        Args:
            persist_directory: Where to persist memory data
        """
        self.persist_directory = persist_directory

        # Create directory for playbooks
        os.makedirs(persist_directory, exist_ok=True)
        os.makedirs(f"{persist_directory}/playbooks", exist_ok=True)

        # Session storage (LangGraph Store)
        self.store = InMemoryStore()

        # Embeddings for playbook search
        try:
            print(f"[MEMORY] Loading embeddings model...")
            self.embeddings = HuggingFaceEmbeddings(
                model_name="sentence-transformers/all-MiniLM-L6-v2"
            )
            print(f"[MEMORY] ✅ Embeddings loaded")
        except Exception as embed_error:
            print(f"[MEMORY] ❌ Failed to load embeddings: {embed_error}")
            self.embeddings = None
            self.playbook_db = None
            return

        # Playbook database (local)
        try:
            self.playbook_db = Chroma(
                collection_name="remediation_playbooks",
                embedding_function=self.embeddings,
                persist_directory=f"{persist_directory}/playbooks"
            )
            print(f"[MEMORY] ✅ Playbook database initialized")
        except Exception as chroma_error:
            print(f"[MEMORY] ❌ Failed to initialize playbook database: {chroma_error}")
            self.playbook_db = None

        print(f"[MEMORY] Memory Manager initialization complete")
        print(f"  - Session Store: In-memory (LangGraph)")
        print(f"  - Incidents: Via agents using MCP tools")
        print(f"  - Playbooks: Local ChromaDB")
        print(f"  - Playbook DB: {'✅ Ready' if self.playbook_db else '❌ Failed'}")


    async def save_incident_to_session(
        self,
        user_id: str,
        incident_data: Dict[str, Any]
    ) -> str:
        """
        Save incident to session store (in-memory)
        Note: For persistent storage, agents use MCP save_incident tool

        Args:
            user_id: User/organization identifier
            incident_data: Investigation result

        Returns:
            incident_id
        """
        incident_id = incident_data.get("alert_id", "UNKNOWN")
        timestamp = incident_data.get("timestamp", datetime.now().isoformat())
        alert_data = incident_data.get("alert_data", {})

        await self.store.aput(
            namespace=(user_id, "incidents"),
            key=incident_id,
            value={
                "timestamp": timestamp,
                "alert_type": alert_data.get("type", "unknown"),
                "threat_score": incident_data.get("threat_score", 0.0),
                "attack_stage": incident_data.get("attack_stage", "Unknown"),
                "workflow_status": incident_data.get("workflow_status", "completed"),
            }
        )

        print(f"[MEMORY] 📝 Incident {incident_id} saved to session store")
        return incident_id


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
        # Note: Playbooks will be initialized on-demand or can be initialized manually
        # See src/memory/playbooks.py for initialization function

    return _memory_manager
