import re
import socket
from urllib.parse import urlparse
import whois
from datetime import datetime, timezone
import tldextract



def is_ip_address(domain: str) -> bool:
    try:
        socket.inet_aton(domain)
        return True
    except socket.error:
        return False

def is_shortened(domain: str) -> bool:
    shorteners = [
        "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "buff.ly", "ow.ly", "rebrand.ly",
        "adf.ly", "shorte.st", "cutt.ly", "v.gd", "tr.im", "cli.gs", "bl.ink", "tiny.cc",
        "soo.gd", "qr.ae", "chilp.it", "x.co", "yourls.org", "u.to", "lnkd.in", "rb.gy",
        "short.io", "short.cm", "1url.com", "linktr.ee", "s.id", "hyperurl.co", "gg.gg"
    ]
    return any(s in domain for s in shorteners)

def domain_length(domain: str):
    return len(domain)

def num_digits(domain: str):
    return sum(c.isdigit() for c in domain)

def num_hyphens(domain: str):
    return domain.count('-')

def has_https(domain: str):
    return 1 if domain.startswith('https://') else 0

def num_subdomains(domain: str):
    ext = tldextract.extract(domain)
    if ext.subdomain:
        return len(ext.subdomain.split('.'))
    return 0

def get_tld(domain: str):
    ext = tldextract.extract(domain)
    return ext.suffix

SUSPICIOUS_TLDS = {'tk', 'ml', 'ga', 'cf', 'gq'}

def is_suspicious_tld(tld):
    return 1 if tld in SUSPICIOUS_TLDS else 0

def typosquatting_score(domain: str) -> float:
    suspicious_keywords = ["login", "verify", "secure", "account"]
    score = sum([1 for word in suspicious_keywords if word in domain.lower()])
    return round(min(score / len(suspicious_keywords), 1.0), 2)


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


def analyse_domain_for_ml(domain: str):
    tld = get_tld(domain)
    whois_info = get_whois_info(domain)

    return {
        "domain": domain,
        "domain_length": domain_length(domain),
        "num_digits": num_digits(domain),
        "num_hyphens": num_hyphens(domain),
        "has_https": has_https(domain),
        "num_subdomains": num_subdomains(domain),
        "tld": tld,
        "is_suspicious_tld": is_suspicious_tld(tld),
        "typosquatting_score": typosquatting_score(domain),
        "domain_age_days": whois_info["age_days"] if whois_info["age_days"] is not None else 0,
        "whois": whois_info  
    }










