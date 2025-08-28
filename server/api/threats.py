"""
API endpoints for managing threats in the CyberGuard System.
Handles threat analysis, reporting, and statistics.
"""

from fastapi import APIRouter, Depends, HTTPException
from typing import List, Dict, Any
from ..core.database import get_database
from ..core.threat_detection import ThreatDetectionEngine

router = APIRouter()

async def get_threat_engine() -> ThreatDetectionEngine:
    """Get threat detection engine instance."""
    database = await get_database()
    return ThreatDetectionEngine(database)

@router.post("/analyze", response_model=Dict[str, Any])
async def analyze_threat(event_data: Dict[str, Any], threat_engine: ThreatDetectionEngine = Depends(get_threat_engine)):
    """Analyze a threat based on event data."""
    result = await threat_engine.analyze_threat(event_data)
    return result

@router.get("/stats", response_model=Dict[str, Any])
async def get_threat_stats(threat_engine: ThreatDetectionEngine = Depends(get_threat_engine)):
    """Get threat statistics."""
    stats = await threat_engine.get_stats()
    return stats

@router.get("/signatures", response_model=List[Dict[str, Any]])
async def get_threat_signatures(threat_engine: ThreatDetectionEngine = Depends(get_threat_engine)):
    """Get all threat signatures."""
    return list(threat_engine.threat_signatures.values())
