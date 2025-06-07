
def analyze_url(domain: str):
    # For now we just fake check
    return {
        "domain": domain,
        "available": True,
        "safe": True,
        "whois": {
            "registrar": "Fake Registrar Inc.",
            "creation_date": "2020-01-01",
            "expiry_date": "2025-01-01"
        }
    }


