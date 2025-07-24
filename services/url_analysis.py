from helpers import (
    get_tld, get_whois_info,
    normalize_domain, domain_length, num_digits,
    num_hyphens, num_subdomains, has_https,
    is_suspicious_tld,typosquatting_score,
    is_shortened,
    improved_typosquatting_score,
    is_potentially_deceptive_flag,
    is_brand_misused_with_tld,
)


def analyse_domain_for_ml(domain: str):
    tld = get_tld(domain)
    whois_info = get_whois_info(domain)

    domain = normalize_domain(domain)

    typo_score, is_typosquatting = improved_typosquatting_score(domain)

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
        "whois": whois_info,

        # Additional Features
        "is_shortened": is_shortened(domain),
        "is_potentially_deceptive_flag": is_potentially_deceptive_flag(domain),
        "is_brand_misused_with_tld": is_brand_misused_with_tld(domain),
        "typo_score": typo_score,
        "is_typosquatting": is_typosquatting,

    }










