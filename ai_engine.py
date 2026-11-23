import time
from datetime import datetime
from typing import List, Dict, Any, Tuple
from collections import deque

class AIAnomalyDetector:
    """
    Local AI Anomaly Detection Engine for FileShield.
    Evaluates behavioral patterns across temporal windows without external APIs.
    Identifies:
      - Rapid burst modifications (Ransomware / automated tamper)
      - Critical resource compromise
      - Off-hours anomalous operations
      - Correlated multi-target modifications
    """

    def __init__(self, time_window_seconds: float = 30.0):
        self.time_window = time_window_seconds
        # In-memory sliding window of recent events for behavioral context
        self.recent_events = deque()

    def _cleanup_old_events(self, current_time: float):
        """Remove events outside the analysis time window."""
        while self.recent_events and (current_time - self.recent_events[0]["timestamp_epoch"]) > self.time_window:
            self.recent_events.popleft()

    def analyze(self, current_event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyzes a single event in the context of recent behavioral history.
        Returns:
          {
            "is_anomaly": bool,
            "risk_score": int (0-100),
            "risk_level": "LOW" | "MEDIUM" | "HIGH" | "CRITICAL",
            "reasons": List[str]
          }
        """
        now_epoch = time.time()
        self._cleanup_old_events(now_epoch)

        file_name = current_event.get("file_name", "")
        criticality = current_event.get("criticality", "MEDIUM").upper()
        event_type = current_event.get("event_type", "MODIFY").upper()
        integrity_status = current_event.get("integrity_status", "VIOLATED").upper()
        
        # Check event timestamp or parse it
        try:
            event_dt = datetime.fromisoformat(current_event.get("timestamp", datetime.now().isoformat()))
        except Exception:
            event_dt = datetime.now()

        reasons: List[str] = []
        base_score = 0.0

        # ---------------------------------------------------------
        # Factor 1: Baseline Integrity Violation
        # ---------------------------------------------------------
        if integrity_status == "VIOLATED":
            base_score += 25
            reasons.append(f"SHA-256 digital fingerprint mismatch against trusted baseline")
        elif integrity_status == "DELETED":
            base_score += 30
            reasons.append(f"Protected asset was completely removed from file system")

        # ---------------------------------------------------------
        # Factor 2: Criticality Weight
        # ---------------------------------------------------------
        if criticality == "CRITICAL":
            base_score += 25
            reasons.append(f"Critical mission asset targeted ({file_name})")
        elif criticality == "HIGH":
            base_score += 15
            reasons.append(f"High sensitivity tier asset affected ({file_name})")
        elif criticality == "MEDIUM":
            base_score += 5

        # ---------------------------------------------------------
        # Factor 3: Temporal / Off-Hours Anomaly
        # Typical office hours: 07:00 to 21:00
        # Off-hours: 21:00 to 07:00
        # ---------------------------------------------------------
        hour = event_dt.hour
        is_off_hours = hour < 7 or hour >= 21
        # If simulated off-hours flag is passed
        if current_event.get("simulated_off_hours", False) or is_off_hours:
            base_score += 15
            formatted_time = event_dt.strftime("%I:%M %p")
            reasons.append(f"Activity occurred during abnormal operational hours ({formatted_time})")

        # ---------------------------------------------------------
        # Factor 4: Rapid Burst & Multi-Target Velocity (Ransomware Heuristic)
        # ---------------------------------------------------------
        recent_window_events = list(self.recent_events)
        recent_count = len(recent_window_events)
        
        # Count distinct files affected in recent window
        recent_files = {e["file_name"] for e in recent_window_events}
        recent_files.add(file_name)

        if recent_count >= 2:
            time_span = now_epoch - recent_window_events[0]["timestamp_epoch"]
            time_span = max(0.5, time_span) # avoid divide by zero
            velocity = (recent_count + 1) / time_span  # events per second
            
            if velocity >= 0.5 or (recent_count + 1 >= 3 and time_span <= 10.0):
                burst_score = min(35, int(velocity * 12) + (len(recent_files) * 8))
                base_score += burst_score
                reasons.append(f"Rapid burst detected: {recent_count + 1} events across {len(recent_files)} files in {time_span:.1f}s")
            elif len(recent_files) > 1:
                base_score += 10
                reasons.append(f"Coordinated activity targeting {len(recent_files)} distinct files within {time_span:.1f}s")

        # ---------------------------------------------------------
        # Factor 5: Dangerous Action Combinations
        # ---------------------------------------------------------
        if event_type == "DELETE" and criticality in ["CRITICAL", "HIGH"]:
            base_score += 15
            reasons.append(f"Severe unauthorized deletion of key infrastructure file")

        # Normalize score between 5 and 99 (or 100)
        risk_score = min(100, max(5, int(base_score)))

        # Determine Anomaly Flag & Level
        is_anomaly = risk_score >= 60 or (recent_count >= 2 and len(recent_files) >= 2)
        
        if risk_score >= 85:
            risk_level = "CRITICAL"
        elif risk_score >= 60:
            risk_level = "HIGH"
        elif risk_score >= 35:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"

        # Record this event into the sliding window
        self.recent_events.append({
            "timestamp_epoch": now_epoch,
            "file_name": file_name,
            "criticality": criticality,
            "event_type": event_type,
            "risk_score": risk_score
        })

        return {
            "is_anomaly": is_anomaly,
            "risk_score": risk_score,
            "risk_level": risk_level,
            "reasons": reasons
        }

    def reset(self):
        """Clears recent events sliding window."""
        self.recent_events.clear()

# Global singleton AI detector instance
ai_engine = AIAnomalyDetector()

