from config import settings

# import uvicorn
# from fastapi import FastAPI, Query, Body, Header, Cookie, Form, File, UploadFile
# from fastapi.responses import Response, JSONResponse, RedirectResponse
# from enum import Enum
# from pydantic import BaseModel
# from typing import Annotated
# from uuid import UUID
# from datetime import datetime, date, timedelta, time



# app = FastAPI(debug=True)


# class ModelName(str, Enum):
#     alexnet = "alexnet"
#     resnet = "resnet"
#     lenet = "lenet"

# class Product(BaseModel):
#     name: str
#     price: float | int
#     description: str


# @app.post("/product")
# async def add_product(product: Product, q: str | None = Query(default="This is the default", min_length=10)):
#     print(product.name)
#     p = product.model_dump()
#     if q:
#         p.update({"q": q})
#     return p


# @app.get("/models/{model_name}")
# async def get_model(model_name: ModelName):
#     if model_name is ModelName.alexnet:
#         return {"model_name": model_name, "message": "Deep Learning FTW!"}

#     if model_name.value:
#         return {"model_name": model_name, "message": "LeCNN all the images"}
#     return {"model_name": model_name, "message": "Have some residuals"}


# @app.get("/")
# async def main_home():
#     return {"message": "Welcome Home Now!"}

# @app.get("/items/{item_id}")
# async def main_home(item_id: int):
#     return {"message": f"Your item id is {item_id}"}



# @app.put("/items/{item_id}")
# async def read_items(
#     item_id: UUID,
#     start_datetime: Annotated[datetime, Body()],
#     end_datetime: Annotated[datetime, Body()],
#     process_after: Annotated[timedelta, Body()],
#     repeat_at: Annotated[time | None, Body()] = None,
# ):
#     start_process = start_datetime + process_after
#     duration = end_datetime - start_process
#     return {
#         "item_id": item_id,
#         "start_datetime": start_datetime,
#         "end_datetime": end_datetime,
#         "process_after": process_after,
#         "repeat_at": repeat_at,
#         "start_process": start_process,
#         "duration": duration,
#     }



# # @app.get("/items/")
# # async def read_items(x_token: Annotated[list[str] | None, Header()] = None):
# #     return {"X-Token": x_token}


# class CommonHeaders(BaseModel):
#     host: str
#     save_data: bool
#     if_modified_since: str | None = None
#     traceparent: str | None = None
#     x_tag: list[str] = []


# @app.get("/items/", response_model=CommonHeaders, response_model_exclude_none=True, response_model_exclude_defaults=True)
# async def read_items(
#     headers: Annotated[CommonHeaders, Header(convert_underscores=False)],
# ):
    
#     headers.model_dump()    
    
#     return headers

# @app.get("/portal", response_model=BaseModel)
# async def get_portal(teleport: bool = False) -> Response:
#     if teleport:
#         return RedirectResponse(url="https://www.youtube.com/watch?v=dQw4w9WgXcQ")
#     return JSONResponse(content={"message": "Here's your interdimensional portal."})

# # if __name__ == "__main__":
# #     uvicorn.run(app, host="127.0.0.1", port=5000)


# class FormCredentials(BaseModel):
#     username: str
#     password: str
#     model_config = {"extra": "forbid"}


# @app.post('/login')
# def login_page(data: Annotated[FormCredentials, Form()]):
#     return data

# @app.post('/uploadfile/')
# def upload_file(file: Annotated[bytes, File()]):
#     return {"file_size": len(file)}


# @app.post('/uploadfile-another/')
# def upload_another_file(file: UploadFile):
#     return {"file_name": file.filename}



# import requests
# import zipfile
# import io

# url = "http://s3-us-west-1.amazonaws.com/umbrella-static/top-1m.csv.zip"
# response = requests.get(url)

# with zipfile.ZipFile(io.BytesIO(response.content)) as z:
#     with z.open("top-1m.csv") as f:
#         lines = f.read().decode("utf-8").splitlines()

# # Parse CSV: each line is like "1,google.com"
# domains = [line.split(',')[1] for line in lines]
# print(domains[:1000])


# url = "http://s3-us-west-1.amazonaws.com/umbrella-static/top-1m.csv.zip"

# # Local path to save the downloaded ZIP
# output_path = "top-1m.csv.zip"

# try:
#     print("Downloading...")
#     response = requests.get(url)
#     response.raise_for_status()  # Raise an error for bad status

#     # Save to file
#     with open(output_path, "wb") as f:
#         f.write(response.content)

#     print(f"Downloaded and saved as: {output_path}")
# except requests.RequestException as e:
#     print(f"Failed to download: {e}")

import numpy as np
import pandas as pd
import tldextract
import whois
from datetime import datetime

# -------------------------------
# CONFIGURATION
# -------------------------------

INPUT_FILE = 'DataDomainCSVProto.csv'  # change to your file name
OUTPUT_FILE = 'DomainAccurateDataCSVType.csv'

# -------------------------------
# FEATURE FUNCTIONS
# -------------------------------


def domain_length(domain):
    return len(domain)

def num_digits(domain):
    return sum(c.isdigit() for c in domain)

def num_hyphens(domain):
    return domain.count('-')

def has_https(domain):
    return 1 if domain.startswith('https://') else 0

def num_subdomains(domain):
    ext = tldextract.extract(domain)
    if ext.subdomain:
        return len(ext.subdomain.split('.'))
    return 0

def get_tld(domain):
    ext = tldextract.extract(domain)
    return ext.suffix

# Optional suspicious TLD flag
SUSPICIOUS_TLDS = {'tk', 'ml', 'ga', 'cf', 'gq'}  # add more if needed

def is_suspicious_tld(tld):
    return 1 if tld in SUSPICIOUS_TLDS else 0

def typosquatting_score(domain: str) -> float:
    suspicious_keywords = ["login", "verify", "secure", "account"]
    score = sum([1 for word in suspicious_keywords if word in domain.lower()])
    return round(min(score / len(suspicious_keywords), 1.0), 2)

from datetime import datetime, timezone
import requests


# Generate age based on is_phishing label
def generate_age(is_phishing):
    if is_phishing == 1:
        return np.random.randint(1, 180)  # phishing domains are often new
    else:
        return np.random.randint(1000, 5000)  # safe domains are older


# def get_domain_age_days(domain) -> int:
#     try:
#         w = whois.whois(domain)

#         creation = w.creation_date
#         expiry = w.expiration_date

#         # Handle list cases
#         if isinstance(creation, list): creation = creation[0]
#         if isinstance(expiry, list): expiry = expiry[0]

#         # Fix timezone mismatch
#         if creation and creation.tzinfo is None:
#             creation = creation.replace(tzinfo=timezone.utc)
#         if expiry and expiry.tzinfo is None:
#             expiry = expiry.replace(tzinfo=timezone.utc)

#         age_days = (datetime.now(timezone.utc) - creation).days if creation else None

#         return age_days
#     except Exception as e:
#         print(e)
#         return 0


# def get_domain_age_days(domain):
#     api_key = settings.WHOIS_API_KEY
#     url = "https://www.whoisxmlapi.com/whoisserver/WhoisService"
#     params = {
#         "apiKey": api_key,
#         "domainName": domain,
#         "outputFormat": "JSON"
#     }
#     try:
#         response = requests.get(url, params=params, timeout=10)
#         data = response.json()
#         created_date = data['WhoisRecord']['createdDate']
#         created_dt = datetime.strptime(created_date, "%Y-%m-%dT%H:%M:%SZ")
#         age_days = (datetime.now() - created_dt).days
#         return age_days
#     except Exception as e:
#         print(f"WHOIS failed for {domain}: {e}")
#         return None


# def get_domain_age_days(domain):
#     try:
#         # Strip prefixes if needed
#         if domain.startswith('https://'):
#             domain = domain.replace('https://', '')
#         elif domain.startswith('http://'):
#             domain = domain.replace('http://', '')

#         w = whois.whois(domain)
#         created = w.creation_date

#         # Some registrars return a list of creation dates — pick the first
#         if isinstance(created, list):
#             created = created[0]

#         if created is None:
#             return None

#         # Calculate age in days
#         age_days = (datetime.now() - created).days
#         return age_days

#     except Exception as e:
#         print(f"WHOIS failed for {domain}: {e}")
#         return None

# -------------------------------
# MAIN PIPELINE
# -------------------------------

def main():
    print(f'Loading file: {INPUT_FILE}')
    if INPUT_FILE.endswith('.xlsx'):
        df = pd.read_excel(INPUT_FILE)
    else:
        df = pd.read_csv(INPUT_FILE)

    print(f'Loaded {len(df)} rows.')

    # Ensure column is named 'domain'
    if 'domain' not in df.columns:
        print(f'Could not find a "domain" column. Found: {df.columns.tolist()}')
        return

    df['domain'] = df['domain'].astype(str)

    # Generate features
    df['domain_length'] = df['domain'].apply(domain_length)
    df['num_digits'] = df['domain'].apply(num_digits)
    df['num_hyphens'] = df['domain'].apply(num_hyphens)
    df['has_https'] = df['domain'].apply(has_https)
    df['num_subdomains'] = df['domain'].apply(num_subdomains)
    df['tld'] = df['domain'].apply(get_tld)
    df['is_suspicious_tld'] = df['tld'].apply(is_suspicious_tld)
    # df['domain_age_days'] = df['domain'].apply(get_domain_age_days)
    # df["domain_age_days"] = df["is_phishing"].apply(generate_age)
    df["typosquatting_score"] = df["domain"].apply(typosquatting_score)

    print('✅ Features added:')
    print(df.head())

    # Save to CSV
    df.to_csv(OUTPUT_FILE, index=False)
    print(f'📁 Saved to {OUTPUT_FILE}')

if __name__ == '__main__':
    main()

print("Working as expected!")


