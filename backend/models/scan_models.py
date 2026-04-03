from pydantic import BaseModel
from typing import Optional, List, Any
from datetime import datetime


class ScanRequest(BaseModel):
    content: str
    input_type: str = "email"   # email | url | attachment_base64
    filename: Optional[str] = None
    source: str = "paste"       # paste | extension


class SignalResult(BaseModel):
    name: str
    score: int                  # 0-100
    severity: str               # red | yellow | green | neutral
    detail: str


class AttackChainNode(BaseModel):
    stage: str                  # email | url | payload
    value: str
    verdict: str
    score: int


class ScanResult(BaseModel):
    id: str
    verdict: str
    score: int
    reasons: List[str]
    signals: List[SignalResult]
    explanation: str
    chain: Optional[List[AttackChainNode]] = None
    campaign_id: Optional[str] = None
    ai_generated_score: Optional[int] = None
    timestamp: datetime


class StatsResponse(BaseModel):
    total_scanned: int
    threats_detected: int
    suspicious_detected: int
    detection_rate: float
    daily_trend: List[dict]
    top_threat_types: List[dict]
    recent_scans: List[dict]


class FeedbackRequest(BaseModel):
    scan_id: str
    correction: str             # false_positive | false_negative
