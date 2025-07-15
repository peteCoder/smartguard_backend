import re
import socket
from urllib.parse import urlparse
import whois
from datetime import datetime, timezone
import tldextract
from utils.safe_browsing import (
    check_url_safety_google, 
    scan_url_with_urlscan
)

# Detect IP-based URLs
def is_ip_address(domain: str) -> bool:
    try:
        socket.inet_aton(domain)
        return True
    except socket.error:
        return False

# Check for HTTPS
def has_https(domain: str) -> bool:
    return domain.startswith("https://")

# Check for known shorteners
def is_shortened(domain: str) -> bool:
    shorteners = [
        "bit.ly", 
        "tinyurl.com", 
        "t.co", 
        "goo.gl", 
        "is.gd", 
        "buff.ly",
    ]
    return any(s in domain for s in shorteners)

# Basic typosquatting score (placeholder logic)
def typosquatting_score(domain: str) -> float:
    suspicious_keywords = ["login", "verify", "secure", "account"]
    score = sum([1 for word in suspicious_keywords if word in domain.lower()])
    return round(min(score / len(suspicious_keywords), 1.0), 2)

# WHOIS lookup & domain age
def get_whois_info(domain: str):
    try:
        w = whois.whois(domain)

        creation = w.creation_date
        expiry = w.expiration_date

        # Handle list cases
        if isinstance(creation, list): creation = creation[0]
        if isinstance(expiry, list): expiry = expiry[0]

        # Fix timezone mismatch
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
            "age_days": age_days
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
            "error": str(e)
        }


# Main analysis
def analyze_url(url: str):
    parsed = urlparse(url)
    hostname = parsed.netloc or parsed.path  
    # handle urls like "example.com"
    ext = tldextract.extract(hostname)
    domain_name = f"{ext.domain}.{ext.suffix}"

    whois_info = get_whois_info(domain_name)

    age_days = whois_info.get("age_days")
    typo_score = typosquatting_score(domain_name)

    is_safe = (
        age_days is not None and 
        age_days > 180 and 
        typo_score < 0.5
    )

    result = {
        "domain": domain_name,
        "is_ip": is_ip_address(hostname),
        "has_https": has_https(url),
        "is_shortened": is_shortened(url),
        "tld": ext.suffix,
        "typosquatting_score": typo_score,
        "domain_age_days": age_days,
        "safe": is_safe,
        "whois": whois_info,
    }

    google_check = check_url_safety_google(url)
    urlscan_check = scan_url_with_urlscan(url)
 

    result["external_urlscan_check"] = urlscan_check
    result["external_google_safe_check"] = google_check



    return result






