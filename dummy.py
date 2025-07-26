from config import settings
from urllib.parse import urlparse
import numpy as np
import pandas as pd

from datetime import datetime

# -------------------------------
# CONFIGURATION
# -------------------------------

INPUT_FILE = 'DataDomainCSVProto.csv'  # change to your file name
OUTPUT_FILE = 'DomainAccurateDataCSVType.csv'


from helpers import (
    domain_length,
    is_suspicious_tld,
    normalize_domain,
    typosquatting_score,
    get_tld,
    num_subdomains,
    has_https,
    num_hyphens,
    num_digits,
    is_shortened,
    improved_typosquatting_score,
    is_potentially_deceptive_flag,
    is_brand_misused_with_tld,
)

def main():
    # print(f'Loading file: {INPUT_FILE}')
    if INPUT_FILE.endswith('.xlsx'):
        df = pd.read_excel(INPUT_FILE)
    else:
        df = pd.read_csv(INPUT_FILE)

    # print(f'Loaded {len(df)} rows.')

    # Ensure column is named 'domain'
    if 'domain' not in df.columns:
        # print(f'Could not find a "domain" column. Found: {df.columns.tolist()}')
        return

    df['domain'] = df['domain'].apply(normalize_domain)

    # Generate features
    df['domain_length'] = df['domain'].apply(domain_length)
    df['num_digits'] = df['domain'].apply(num_digits)
    df['num_hyphens'] = df['domain'].apply(num_hyphens)
    df['has_https'] = df['domain'].apply(has_https)
    df['num_subdomains'] = df['domain'].apply(num_subdomains)
    df['tld'] = df['domain'].apply(get_tld)
    df['is_suspicious_tld'] = df['tld'].apply(is_suspicious_tld)
    
    # Not Additional
    df["typosquatting_score"] = df["domain"].apply(typosquatting_score)
    
    # Additional
    df["is_shortened"] = df["domain"].apply(is_shortened)
    df["is_brand_misused_with_tld"] = df["domain"].apply(is_brand_misused_with_tld)
    df["is_potentially_deceptive_flag"] = df["domain"].apply(is_potentially_deceptive_flag)

    # Add both typo score and flag
    df[["typo_score", "is_typosquatting"]] = df["domain"].apply(
        lambda d: improved_typosquatting_score(d)
    ).apply(pd.Series)

    # Not Additional
    df["typosquatting_score"] = df["domain"].apply(typosquatting_score)

    # print('✅ Features added:')
    # print(df.head())

    # Save to CSV
    df.to_csv(OUTPUT_FILE, index=False)
    # print(f'📁 Saved to {OUTPUT_FILE}')


if __name__ == '__main__':
    main()

# print("Working as expected!")


