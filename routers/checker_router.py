from fastapi import APIRouter, UploadFile, File, Query, Response
from services import qr_extration, url_analysis
from models import report_model
from typing import Union
from config import env
from weasyprint import HTML
from datetime import datetime, timezone
import whois
from utils.predict_ml import machine_learning_prediction

from services.url_analysis import is_shortened, typosquatting_score  # Import your helpers
from helpers import (
    is_ip_address
)

router = APIRouter()


# Main analysis
def analyze_url(url: str):
    result = machine_learning_prediction(url)
    return result


@router.get("/")
async def api_home():
    return {"message": "API is working"}

@router.post("/scan-qr")
async def scan_qr(file: UploadFile = File(...)):
    result = await qr_extration.extract_qr_from_file(file)
    return {"extracted_text": result}


@router.post("/extract-qr")
async def extract_qr(file: UploadFile = File(...)):
    qr_text = qr_extration.extract_qr_code(file)
    if qr_text:
        analysis_result = analyze_url(qr_text)
        return analysis_result
    else:
        return {"extracted_text": "Please enter a valid QR Code."}


@router.get("/check-domain")
def check_domain(domain: str = Query(..., example="https://example.com")):
    analysis_result = analyze_url(domain)
    return analysis_result

@router.post("/generate-report")
def generate_pdf_report(data: report_model.PhishingPredictionResponse):
    input_dict = data.model_dump()

    # Extract WHOIS info safely
    whois = input_dict.get("whois", {})

    # Additional features needed by the template
    extra_fields = {
        "is_ip": is_ip_address(data.domain),
        "has_https": data.features_used.get("has_https", 0),
        "is_shortened": is_shortened(data.domain),
        "typosquatting_score": data.features_used.get("typosquatting_score", 0),
        "domain_age_days": whois.get("age_days"),
        "safe": not data.is_phishing  # Invert to match "Safe: Yes/No"
    }

    # Merge everything for the template
    context = {
        **input_dict,
        **extra_fields,
        "date": datetime.now().strftime("%Y-%m-%d %H:%M UTC")
    }

    print("Print Context: ", context)

    template = env.get_template("report.html")
    rendered_html = template.render(**context)
    pdf = HTML(string=rendered_html).write_pdf()

    return Response(
        content=pdf,
        media_type="application/pdf",
        headers={"Content-Disposition": f"inline; filename=smartguard_{data.domain}_report.pdf"}
    )

@router.get("/predict-ml")
def predict_ml_result(domain: str = Query(..., example="https://example.com")):
    data = machine_learning_prediction(domain)
    return data




