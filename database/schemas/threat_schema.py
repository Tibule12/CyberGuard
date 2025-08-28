"""
Database schemas for CyberGuard threat intelligence.
Defines MongoDB document structures for threat data.
"""

from datetime import datetime
from typing import Dict, List, Optional, Any
from pydantic import BaseModel, Field

class ThreatSignature(BaseModel):
    """Schema for threat signatures."""
    signature: str = Field(..., description="Unique signature identifier")
    threat_type: str = Field(..., description="Type of threat (malware, virus, etc.)")
    severity: str = Field(..., description="Severity level (low, medium, high, critical)")
    description: str = Field(..., description="Description of the threat")
    indicators: List[str] = Field(..., description="List of threat indicators")
    mitigation: List[str] = Field(..., description="Mitigation steps")
    references: List[str] = Field([], description="Reference URLs")
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    is_active: bool = Field(True, description="Whether the signature is active")

class ClientEvent(BaseModel):
    """Schema for client security events."""
    event_id: str = Field(..., description="Unique event identifier")
    client_id: str = Field(..., description="Client identifier")
    event_type: str = Field(..., description="Type of event (process, network, file, etc.)")
    timestamp: datetime = Field(..., description="Event timestamp")
    data: Dict[str, Any] = Field(..., description="Event data")
    threat_level: str = Field("unknown", description="Detected threat level")
    analysis_result: Optional[Dict[str, Any]] = Field(None, description="Analysis results")
    analyzed_at: Optional[datetime] = Field(None, description="When analysis was performed")

class ThreatAnalysisResult(BaseModel):
    """Schema for threat analysis results."""
    analysis_id: str = Field(..., description="Unique analysis identifier")
    event_id: str = Field(..., description="Related event identifier")
    threat_level: str = Field(..., description="Final threat level assessment")
    confidence: float = Field(..., description="Confidence score (0.0-1.0)")
    signatures_matched: List[str] = Field([], description="Matched threat signatures")
    behavioral_analysis: Dict[str, Any] = Field({}, description="Behavioral analysis results")
    recommendations: List[str] = Field([], description="Security recommendations")
    created_at: datetime = Field(default_factory=datetime.utcnow)

class ClientInfo(BaseModel):
    """Schema for client information."""
    client_id: str = Field(..., description="Unique client identifier")
    platform: str = Field(..., description="Operating system platform")
    version: str = Field(..., description="Client version")
    system_info: Dict[str, Any] = Field(..., description="System information")
    registered_at: datetime = Field(default_factory=datetime.utcnow)
    last_heartbeat: datetime = Field(default_factory=datetime.utcnow)
    is_active: bool = Field(True, description="Whether client is active")
    threat_count: int = Field(0, description="Number of threats detected")
    last_scan: Optional[datetime] = Field(None, description="Last scan timestamp")

class SystemScan(BaseModel):
    """Schema for system scan results."""
    scan_id: str = Field(..., description="Unique scan identifier")
    client_id: str = Field(..., description="Client identifier")
    scan_type: str = Field(..., description="Type of scan (full, quick, custom)")
    start_time: datetime = Field(..., description="Scan start time")
    end_time: datetime = Field(..., description="Scan end time")
    results: Dict[str, Any] = Field(..., description="Scan results")
    threats_detected: int = Field(0, description="Number of threats detected")
    status: str = Field("completed", description="Scan status")

class UserAccount(BaseModel):
    """Schema for user accounts."""
    username: str = Field(..., description="Unique username")
    email: str = Field(..., description="User email address")
    password_hash: str = Field(..., description="Hashed password")
    roles: List[str] = Field(["user"], description="User roles")
    is_active: bool = Field(True, description="Whether account is active")
    created_at: datetime = Field(default_factory=datetime.utcnow)
    last_login: Optional[datetime] = Field(None, description="Last login timestamp")
    preferences: Dict[str, Any] = Field({}, description="User preferences")

class SystemSettings(BaseModel):
    """Schema for system settings."""
    setting_key: str = Field(..., description="Setting key")
    setting_value: Any = Field(..., description="Setting value")
    description: str = Field("", description="Setting description")
    is_editable: bool = Field(True, description="Whether setting can be edited")
    category: str = Field("general", description="Setting category")
    updated_at: datetime = Field(default_factory=datetime.utcnow)

class ThreatIntelligenceFeed(BaseModel):
    """Schema for threat intelligence feeds."""
    feed_name: str = Field(..., description="Feed name")
    feed_url: str = Field(..., description="Feed URL")
    feed_type: str = Field(..., description="Feed type (malware, ioc, etc.)")
    last_update: datetime = Field(..., description="Last update time")
    update_interval: int = Field(3600, description="Update interval in seconds")
    is_active: bool = Field(True, description="Whether feed is active")
    signatures_count: int = Field(0, description="Number of signatures from this feed")

# Collection name constants
THREATS_COLLECTION = "threats"
EVENTS_COLLECTION = "events"
ANALYSIS_COLLECTION = "analysis"
CLIENTS_COLLECTION = "clients"
SCANS_COLLECTION = "scans"
USERS_COLLECTION = "users"
SETTINGS_COLLECTION = "settings"
FEEDS_COLLECTION = "feeds"

# Index definitions (for MongoDB optimization)
INDEXES = {
    THREATS_COLLECTION: [
        [("signature", 1), ("is_active", 1)],
        [("threat_type", 1)],
        [("severity", 1)]
    ],
    EVENTS_COLLECTION: [
        [("client_id", 1), ("timestamp", -1)],
        [("event_type", 1)],
        [("threat_level", 1)]
    ],
    CLIENTS_COLLECTION: [
        [("client_id", 1)],
        [("platform", 1)],
        [("is_active", 1), ("last_heartbeat", -1)]
    ],
    USERS_COLLECTION: [
        [("username", 1)],
        [("email", 1)],
        [("is_active", 1)]
    ]
}

def create_sample_threat_signatures() -> List[Dict[str, Any]]:
    """Create sample threat signatures for initial database setup."""
    return [
        {
            "signature": "MALWARE_WIN32_EXAMPLE",
            "threat_type": "malware",
            "severity": "high",
            "description": "Example Windows malware signature",
            "indicators": ["*.exe", "specific_hash_value", "suspicious_process_name"],
            "mitigation": ["Run antivirus scan", "Isolate system", "Update definitions"],
            "references": ["https://example.com/threat-info"],
            "created_at": datetime.utcnow(),
            "updated_at": datetime.utcnow(),
            "is_active": True
        },
        {
            "signature": "PHISHING_EMAIL_EXAMPLE",
            "threat_type": "phishing",
            "severity": "medium",
            "description": "Example phishing email pattern",
            "indicators": ["suspicious_domain", "fake_login_page", "urgent_action_required"],
            "mitigation": ["Delete email", "Report as spam", "Verify with legitimate source"],
            "references": ["https://example.com/phishing-info"],
            "created_at": datetime.utcnow(),
            "updated_at": datetime.utcnow(),
            "is_active": True
        }
    ]
