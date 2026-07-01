from pydantic import BaseModel
from typing import List

class ThreatTriple(BaseModel):
    source_entity: str      # e.g., "Threat Actor X"
    source_type: str        # e.g., "Threat Actor", "IP Address"
    relationship: str       # e.g., "UTILIZES", "EXPLOITS", "SCANS"
    target_entity: str      # e.g., "Malware Y", "Vulnerability Z"
    target_type: str        # e.g., "Malware", "Vulnerability", "Host"

class ThreatIntelReport(BaseModel):
    report_name: str
    triples: List[ThreatTriple]