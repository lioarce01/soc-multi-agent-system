"""
Campaign Detector for Context Engineering
Detects coordinated attack campaigns across multiple alerts
"""

from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
from collections import Counter


class CampaignDetector:
    """
    Detect coordinated attack campaigns across multiple security incidents
    
    Campaigns are detected based on:
    - MITRE technique overlap
    - Source IP correlation
    - Temporal proximity (within time window)
    - Similar threat scores
    """

    def __init__(self, time_window_hours: int = 48):
        """
        Initialize campaign detector
        
        Args:
            time_window_hours: Time window in hours for campaign correlation (default: 48h)
        """
        self.time_window = timedelta(hours=time_window_hours)
        self.campaigns: Dict[str, Dict[str, Any]] = {}
        print(f"[CAMPAIGN DETECTOR] Initialized with {time_window_hours}h time window")

    async def check_for_campaign(
        self,
        memory_manager,
        current_incident: Dict[str, Any],
        user_id: str
    ) -> Optional[Dict[str, Any]]:
        """
        Check if current incident is part of a coordinated campaign
        
        Args:
            memory_manager: MemoryManager instance for querying past incidents
            current_incident: Current incident data (full state dict)
            user_id: User/organization identifier
        
        Returns:
            Campaign info dict if campaign detected, None otherwise
        """
        try:
            # Get all recent incidents within time window
            all_incidents = await memory_manager.get_all_incidents(
                user_id=user_id,
                limit=100  # Check last 100 incidents
            )
            
            if len(all_incidents) < 2:
                # Need at least 2 incidents (current + 1 past) for campaign
                return None
            
            # Extract current incident details
            current_alert_data = current_incident.get("alert_data", {})
            current_source_ip = current_alert_data.get("source_ip")
            current_mitre_techniques = [
                m.get("technique_id", "") 
                for m in current_incident.get("mitre_mappings", [])
            ]
            current_timestamp = current_incident.get("timestamp") or current_incident.get("created_at")
            current_threat_score = current_incident.get("threat_score", 0.0)
            
            # Parse current timestamp
            try:
                if isinstance(current_timestamp, str):
                    # Handle ISO format with or without timezone
                    current_time = datetime.fromisoformat(current_timestamp.replace("Z", "+00:00"))
                    if current_time.tzinfo:
                        current_time = current_time.replace(tzinfo=None)
                else:
                    current_time = datetime.now()
            except:
                current_time = datetime.now()
            
            # Filter incidents within time window
            related_incidents = []
            for incident in all_incidents:
                # Skip if same incident
                if incident.get("incident_id") == current_incident.get("alert_id"):
                    continue
                
                # Check temporal proximity
                incident_timestamp = incident.get("timestamp", "")
                try:
                    if isinstance(incident_timestamp, str):
                        incident_time = datetime.fromisoformat(incident_timestamp.replace("Z", "+00:00"))
                        if incident_time.tzinfo:
                            incident_time = incident_time.replace(tzinfo=None)
                    else:
                        continue
                    
                    time_diff = abs((current_time - incident_time).total_seconds() / 3600)  # hours
                    if time_diff > self.time_window.total_seconds() / 3600:
                        continue  # Outside time window
                except:
                    continue
                
                related_incidents.append(incident)
            
            # Need at least 2 related incidents (3 total including current) for campaign
            if len(related_incidents) < 2:
                return None
            
            # Calculate campaign score
            campaign_score = self._calculate_campaign_score(
                current_incident=current_incident,
                related_incidents=related_incidents,
                current_source_ip=current_source_ip,
                current_mitre_techniques=current_mitre_techniques
            )
            
            # Campaign threshold: 0.6 (60% confidence)
            if campaign_score < 0.6:
                return None
            
            # Generate campaign info
            campaign_id = f"CAMPAIGN-{current_incident.get('alert_id', 'UNKNOWN')[-8:].upper()}"
            
            # Collect all related incident IDs
            related_incident_ids = [inc.get("incident_id", "Unknown") for inc in related_incidents]
            related_incident_ids.append(current_incident.get("alert_id", "Unknown"))
            
            # Calculate time span
            timestamps = []
            for inc in related_incidents:
                ts = inc.get("timestamp", "")
                if ts:
                    try:
                        t = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                        if t.tzinfo:
                            t = t.replace(tzinfo=None)
                        timestamps.append(t)
                    except:
                        pass
            
            if timestamps:
                timestamps.append(current_time)
                time_span_hours = (max(timestamps) - min(timestamps)).total_seconds() / 3600
            else:
                time_span_hours = 0.0
            
            # Determine threat assessment
            if time_span_hours < 24:
                threat_assessment = "ONGOING_CAMPAIGN"
            elif time_span_hours < 48:
                threat_assessment = "RECENT_CAMPAIGN"
            else:
                threat_assessment = "MULTI_WAVE_CAMPAIGN"
            
            campaign_info = {
                "campaign_id": campaign_id,
                "confidence": round(campaign_score, 3),
                "incident_count": len(related_incident_ids),
                "related_incidents": related_incident_ids,
                "time_span_hours": round(time_span_hours, 1),
                "threat_assessment": threat_assessment,
                "average_similarity": round(campaign_score, 3),  # Use campaign score as similarity proxy
                "detected_at": datetime.now().isoformat()
            }
            
            print(f"[CAMPAIGN DETECTOR] 🚨 CAMPAIGN DETECTED: {campaign_id}")
            print(f"  - Confidence: {campaign_score:.0%}")
            print(f"  - Related Incidents: {len(related_incident_ids)}")
            print(f"  - Time Span: {time_span_hours:.1f} hours")
            print(f"  - Assessment: {threat_assessment}")
            
            return campaign_info
            
        except Exception as e:
            print(f"[CAMPAIGN DETECTOR] ⚠️  Error detecting campaign: {e}")
            import traceback
            traceback.print_exc()
            return None

    def _calculate_campaign_score(
        self,
        current_incident: Dict[str, Any],
        related_incidents: List[Dict[str, Any]],
        current_source_ip: Optional[str],
        current_mitre_techniques: List[str]
    ) -> float:
        """
        Calculate campaign likelihood score (0-1)
        
        Scoring factors:
        - Number of related incidents (max 0.3)
        - MITRE technique overlap (max 0.4)
        - IP correlation (max 0.2)
        - Temporal clustering (max 0.1)
        
        Args:
            current_incident: Current incident data
            related_incidents: List of related past incidents
            current_source_ip: Source IP of current incident
            current_mitre_techniques: List of MITRE technique IDs for current incident
        
        Returns:
            Campaign score (0.0 - 1.0)
        """
        if not related_incidents:
            return 0.0
        
        score = 0.0
        
        # Factor 1: Number of related incidents (max 0.3)
        # More incidents = higher confidence
        incident_count = len(related_incidents)
        if incident_count >= 5:
            score += 0.3  # 5+ incidents = max score
        elif incident_count >= 3:
            score += 0.25  # 3-4 incidents = high score
        elif incident_count >= 2:
            score += 0.15  # 2 incidents = moderate score
        
        # Factor 2: MITRE technique overlap (max 0.4)
        # Check how many related incidents share MITRE techniques
        mitre_overlap_count = 0
        for incident in related_incidents:
            incident_mitre = incident.get("mitre_techniques", [])
            if isinstance(incident_mitre, list):
                # Check if any techniques overlap
                if any(tech in incident_mitre for tech in current_mitre_techniques if tech):
                    mitre_overlap_count += 1
        
        if mitre_overlap_count > 0:
            overlap_ratio = mitre_overlap_count / len(related_incidents)
            score += 0.4 * overlap_ratio  # Weighted by overlap ratio
        
        # Factor 3: IP correlation (max 0.2)
        # Check if same source IP appears in multiple incidents
        if current_source_ip:
            ip_match_count = 0
            for incident in related_incidents:
                # Try to get source IP from incident
                # Incidents stored in LangGraph Store may have different structure
                incident_source_ip = None
                
                # Try different possible fields
                if isinstance(incident, dict):
                    # Check if incident has alert_data nested
                    if "source_ip" in incident:
                        incident_source_ip = incident.get("source_ip")
                    elif "alert_data" in incident and isinstance(incident["alert_data"], dict):
                        incident_source_ip = incident["alert_data"].get("source_ip")
                
                if incident_source_ip and incident_source_ip == current_source_ip:
                    ip_match_count += 1
            
            if ip_match_count > 0:
                ip_ratio = ip_match_count / len(related_incidents)
                score += 0.2 * min(ip_ratio, 1.0)  # Cap at 0.2
        
        # Factor 4: Temporal clustering (max 0.1)
        # Incidents clustered in shorter time = higher score
        try:
            current_timestamp = current_incident.get("timestamp") or current_incident.get("created_at")
            if isinstance(current_timestamp, str):
                current_time = datetime.fromisoformat(current_timestamp.replace("Z", "+00:00"))
                if current_time.tzinfo:
                    current_time = current_time.replace(tzinfo=None)
            else:
                current_time = datetime.now()
            
            timestamps = [current_time]
            for incident in related_incidents:
                ts = incident.get("timestamp", "")
                if ts:
                    try:
                        t = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                        if t.tzinfo:
                            t = t.replace(tzinfo=None)
                        timestamps.append(t)
                    except:
                        pass
            
            if len(timestamps) > 1:
                time_span_hours = (max(timestamps) - min(timestamps)).total_seconds() / 3600
                # Shorter time span = higher score
                if time_span_hours < 12:
                    score += 0.1  # Very tight clustering
                elif time_span_hours < 24:
                    score += 0.07  # Tight clustering
                elif time_span_hours < 48:
                    score += 0.04  # Moderate clustering
        except:
            pass  # Skip temporal factor if error
        
        # Cap score at 1.0
        return min(score, 1.0)

