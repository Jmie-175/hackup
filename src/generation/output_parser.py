
"""
Pydantic output parser for ChatGroq JSON responses.
"""
import json
import re
from pydantic import BaseModel, Field, field_validator
from langchain_core.output_parsers import PydanticOutputParser


class FeatureScores(BaseModel):
    urgency_language: float = Field(default=0.0, ge=0.0, le=1.0)
    domain_suspicious: float = Field(default=0.0, ge=0.0, le=1.0)
    sender_mismatch: float = Field(default=0.0, ge=0.0, le=1.0)
    attachment_risk: float = Field(default=0.0, ge=0.0, le=1.0)
    ai_generated: float = Field(default=0.0, ge=0.0, le=1.0)


class PhishingVerdict(BaseModel):
    verdict: str = Field(..., description="PHISHING | LEGITIMATE | UNCERTAIN")
    confidence: float = Field(..., ge=0.0, le=1.0)
    risk_score: int = Field(..., ge=0, le=100)
    reasoning: str = Field(...)
    indicators: list[str] = Field(default_factory=list)
    mitigation: str = Field(default="")
    features: FeatureScores = Field(default_factory=FeatureScores)

    @field_validator("verdict")
    @classmethod
    def normalise_verdict(cls, v: str) -> str:
        return v.upper().strip()


def get_parser() -> PydanticOutputParser:
    return PydanticOutputParser(pydantic_object=PhishingVerdict)


def _extract_json_block(text: str) -> str:
    match = re.search(r"\{[\s\S]*\}", text)
    return match.group(0) if match else text


def safe_parse(raw: str) -> PhishingVerdict:
    parser = get_parser()
    try:
        return parser.parse(raw)
    except Exception:
        pass
    try:
        data = json.loads(_extract_json_block(raw))
        return PhishingVerdict(**data)
    except Exception:
        return PhishingVerdict(
            verdict="UNCERTAIN",
            confidence=0.5,
            risk_score=50,
            reasoning=f"Parse error -- raw output: {raw[:400]}",
            indicators=["parse_error"],
            mitigation="Review the email manually with caution.",
        )
