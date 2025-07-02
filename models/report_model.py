from pydantic import BaseModel
from typing import Optional, List, Union, Any, Dict


class WhoisInfo(BaseModel):
    domain_name: Optional[str]
    registrar: Optional[str]
    name_servers: Optional[Union[str, List[str]]]
    status: Optional[Union[str, List[str]]]
    emails: Optional[Union[str, List[str]]]
    owner: Optional[str]
    organization: Optional[str]
    creation_date: Optional[str]
    expiry_date: Optional[str]
    age_days: Optional[int]
    error: Optional[str] = None


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


class InvalidExtractedError:
    extracted_text: str



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
