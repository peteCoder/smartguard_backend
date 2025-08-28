from urllib.parse import urlparse
import numpy as np
import tldextract
import whois
from datetime import datetime, timezone
import socket

import tldextract
from difflib import SequenceMatcher

from .constants import ( 
    BRAND_TRUSTED_TLDS,
    BRAND_TARGETS,
    SHORTENERS,
    SUSPICIOUS_KEYWORDS,
    SUSPICIOUS_TLDS,
)

from sklearn.preprocessing import LabelEncoder


def safe_label_encode(label: str, encoder: LabelEncoder) -> int:
    if label in encoder.classes_:
        return int(encoder.transform([label])[0])
    else:
        return -1  # Or some other default value

def improved_typosquatting_score(domain: str, threshold: float = 0.6) -> tuple[float, bool]:
    """
    Returns a similarity score between 0 and 1,
    and a boolean flag indicating whether it’s likely typosquatting.
    """

    BRANDS = BRAND_TARGETS
    ext = tldextract.extract(domain)
    main_part = ext.domain.lower()
    
    max_score = 0.0
    for brand in BRANDS:
        similarity = SequenceMatcher(None, main_part, brand).ratio()
        if similarity > max_score:
            max_score = similarity

    return round(max_score, 2), max_score >= threshold


# facebook.net rather facebook.com
def is_brand_misused_with_tld(domain: str) -> int:
    ext = tldextract.extract(domain)
    main_domain = ext.domain.lower()
    tld = ext.suffix.lower()

    for brand, trusted_tlds in BRAND_TRUSTED_TLDS.items():
        if brand in main_domain and tld not in trusted_tlds:
            return 1  # Suspicious
    return 0  # Not suspicious

def get_whois_info(domain: str):
    try:
        w = whois.whois(domain)
        creation = w.creation_date
        expiry = w.expiration_date

        if isinstance(creation, list):
            creation = creation[0]

        if isinstance(expiry, list):
            expiry = expiry[0]
        
        if creation and creation.tzinfo is None:
            creation = creation.replace(tzinfo=timezone.utc)
        if expiry and expiry.tzinfo is None:
            expiry = expiry.replace(tzinfo=timezone.utc)
        
        age_days = (datetime.now(timezone.utc) - creation).days if creation else None

        return {
            "domain_name": w.domain_name,
            "registrar": w.registrar,
            "name_servers": w.name_servers,
            "status": w.status,
            "emails": w.emails,
            "owner": w.name,
            "organization": w.org,
            "creation_date": str(creation) if creation else None,
            "expiry_date": str(expiry) if expiry else None,
            "age_days": age_days,
            "error": None,
        }
    except Exception as e:
        print(e)
        return {
            "domain_name": None,
            "registrar": None,
            "name_servers": None,
            "status": None,
            "emails": None,
            "owner": None,
            "organization": None,
            "creation_date": None,
            "expiry_date": None,
            "age_days": None,
            "error": str(e),
        }


def is_potentially_deceptive(domain: str) -> bool:
    suspicious_keywords = SUSPICIOUS_KEYWORDS
    brand_targets = BRAND_TARGETS

    ext = tldextract.extract(domain)
    main_domain = ext.domain.lower()
    full_domain = domain.lower()

    # 1. If it's an exact match with a real brand domain, do not flag
    if main_domain in brand_targets and ext.suffix in {"com", "net", "org"}:
        return False  # It's probably a real brand

    # 2. If the main domain contains a brand name or keyword + some other text, flag as deceptive
    for brand in brand_targets:
        if brand in main_domain and main_domain != brand:
            return True

    for keyword in suspicious_keywords:
        if keyword in main_domain:
            return True

    return False


def is_potentially_deceptive_flag(domain: str) -> int:
    return int(is_potentially_deceptive(domain))


# Is Shortened
def is_shortened(domain: str) -> bool:
    shorteners = SHORTENERS
    return any(s in domain for s in shorteners)


def domain_length(domain):
    return len(domain)


def num_digits(domain):
    return sum(c.isdigit() for c in domain)


def num_hyphens(domain):
    return domain.count('-')


def has_https(domain):
    """
        Returns 1 if domain starts with https://  
        although not a safety signal since many sites 
        have https:// regardless if they are phishing or not
        This is just to tell the users if his input contains 
        https:// or is merely http://
    """
    return 1 if domain.startswith('https://') else 0


def num_subdomains(domain):
    ext = tldextract.extract(domain)
    if ext.subdomain:
        return len(ext.subdomain.split('.'))
    return 0


def get_tld(domain):
    ext = tldextract.extract(domain)
    return ext.suffix


def is_suspicious_tld(tld):
    return 1 if tld in SUSPICIOUS_TLDS else 0


def is_ip_address(domain: str) -> bool:
    try:
        socket.inet_aton(domain)
        return True
    except socket.error:
        return False


def normalize_domain(raw: str) -> str:
    parsed = urlparse(raw if raw.startswith("http") else "http://" + raw)
    return parsed.netloc.lower()









