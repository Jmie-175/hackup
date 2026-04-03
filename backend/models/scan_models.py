from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime


class ScanRequest(BaseModel):
    content: str
    input_type: str = "email"       # email | url | attachment_base64
    filename: Optional[str] = None
    source: str = "paste"           # paste | extension
    attachments: Optional[List[dict]] = None  # attachment metadata from Gmail DOM


class SignalResult(BaseModel):
    name: str
    score: int                      # 0-100
    severity: str                   # red | yellow | green | neutral
    detail: str


class AttackChainNode(BaseModel):
    stage: str
    value: str
    verdict: str
    score: int


class AttachmentResult(BaseModel):
    filename: str
    risk_score: int
    verdict: str                    # clean | suspicious | malicious
    file_type: str
    signals: List[SignalResult]
    macro_detected: bool = False
    js_detected: bool = False
    extension_spoofed: bool = False


class PhishingClassification(BaseModel):
    attack_type: str                # credential_harvest | bec | spear_phish |
                                    # malware_delivery | social_engineering |
                                    # ai_generated | unknown
    attack_type_label: str          # human-readable label
    attack_type_description: str    # one-sentence description
    confidence: int                 # 0-100
    target_brand: Optional[str] = None
    target_persona: Optional[str] = None   # "CEO", "IT dept", "customer" etc.


class ScanResult(BaseModel):
    id: str
    verdict: str
    score: int
    reasons: List[str]
    signals: List[SignalResult]
    explanation: str
    classification: Optional[PhishingClassification] = None
    attachments: Optional[List[AttachmentResult]] = None
    chain: Optional[List[AttackChainNode]] = None
    campaign_id: Optional[str] = None
    ai_generated_score: Optional[int] = None
    urls_found: Optional[List[str]] = None
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
    correction: str
