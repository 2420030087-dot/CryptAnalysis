from typing import Dict, Any

class SeverityRulesEngine:
    """
    Evaluates rule-based severity for file events based on:
    - File Criticality (CRITICAL, HIGH, MEDIUM, LOW)
    - Event Type (DELETE, MODIFY, CREATE, RENAME)
    - Integrity Status (VIOLATED, DELETED, SAFE, CREATED)
    """

    @staticmethod
    def evaluate(event_type: str, criticality: str, integrity_status: str, file_name: str = "") -> str:
        event_type = event_type.upper()
        criticality = criticality.upper()
        integrity_status = integrity_status.upper()
        file_name_lower = file_name.lower()

        # If hash matched and file is safe
        if integrity_status in ["SAFE", "INTACT"]:
            return "INFORMATIONAL"

        # Check for dangerous or ransom extensions
        suspicious_exts = [".encrypted", ".locked", ".ransom", ".crypt", ".payme"]
        if any(file_name_lower.endswith(ext) for ext in suspicious_exts):
            return "CRITICAL"

        # Rule evaluation matrix
        if event_type == "DELETE":
            if criticality == "CRITICAL":
                return "CRITICAL"
            elif criticality == "HIGH":
                return "HIGH"
            elif criticality == "MEDIUM":
                return "MEDIUM"
            else:
                return "LOW"

        elif event_type == "MODIFY":
            if integrity_status == "VIOLATED":
                if criticality == "CRITICAL":
                    return "CRITICAL"
                elif criticality == "HIGH":
                    return "HIGH"
                elif criticality == "MEDIUM":
                    return "MEDIUM"
                else:
                    return "LOW"
            return "LOW"

        elif event_type == "CREATE":
            if file_name_lower.endswith((".exe", ".sh", ".bat", ".ps1", ".vbs", ".cmd")):
                return "HIGH"
            if criticality in ["CRITICAL", "HIGH"]:
                return "MEDIUM"
            return "LOW"

        elif event_type == "RENAME":
            if criticality in ["CRITICAL", "HIGH"]:
                return "HIGH"
            return "MEDIUM"

        return "LOW"
