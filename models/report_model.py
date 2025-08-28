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
