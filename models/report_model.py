from pydantic import BaseModel
from typing import Optional, List


class QRScanResult(BaseModel):
    extracted_text: str


class DomainAnalysis(BaseModel):
    domain: str
    available: bool
    safe: bool
    whois: dict


class URLClassificationRequest(BaseModel):
    url: str


class URLClassificationResponse(BaseModel):
    url: str
    label: str  # e.g., "phishing" or "benign"
    probability: float


class ForensicReport(BaseModel):
    url: str
    qr_text: Optional[str]
    analysis: DomainAnalysis
    ml_result: Optional[URLClassificationResponse]
    generated_at: str
