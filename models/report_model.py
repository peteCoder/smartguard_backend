from pydantic import BaseModel
from typing import Optional, List, Union, Any, Dict, Literal

class WhoisInfo(BaseModel):
    domain_name: Optional[str]
    registrar: Optional[str]
    name_servers: Optional[List[str]]
    status: Optional[Union[List[str], str]]
    emails: Optional[Union[List[str], str]]
    owner: Optional[str]
    organization: Optional[str]
    creation_date: Optional[str]
    expiry_date: Optional[str]
    age_days: Optional[int]
    error: Optional[str]

class PhishingPredictionResponse(BaseModel):
    domain: str
    tld: str
    is_phishing: bool
    confidence: float
    features_used: Dict[str, Union[str, int, float]]
    whois: WhoisInfo
    deceptive_pattern_detected: Optional[bool]
    warning: Optional[str]
    risk_score: Optional[float]
    risk_level: Optional[str]

class QRScanResult(BaseModel):
    extracted_text: str


class ExternalCheckResult(BaseModel):
    safe: Optional[bool]  # True, False, or None (error)
    details: Optional[List[Dict[str, Any]]] = []
    error: Optional[str] = None


class URLScanCheckResult(BaseModel):
    safe: Optional[bool]
    verdict: Optional[str]
    tags: Optional[List[str]]
    score: Optional[int]
    screenshot: Optional[str]
    error: Optional[str] = None

class DomainAnalysis(BaseModel):
    domain: str
    is_ip: bool
    has_https: bool
    is_shortened: bool
    tld: str
    typosquatting_score: float
    domain_age_days: Optional[int]
    safe: bool
    whois: WhoisInfo
    external_google_safe_check: ExternalCheckResult
    external_urlscan_check: URLScanCheckResult

class DomainPredictFeatures(BaseModel):
    has_https: bool
    is_shortened: bool
    typosquatting_score: float
    domain_age_days: int
    tld: str
    domain_length: int


class InvalidExtractedError:
    extracted_text: str



class URLClassificationRequest(BaseModel):
    url: str


class URLClassificationResponse(BaseModel):
    url: str
    label: str
    probability: float


class ForensicReport(BaseModel):
    url: str
    qr_text: Optional[str]
    analysis: DomainAnalysis
    ml_result: Optional[URLClassificationResponse]
    generated_at: str
