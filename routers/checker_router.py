from fastapi import APIRouter, UploadFile, File, Query, Response
from services import qr_extration, url_analysis
from models import report_model
from typing import Union
from config import env
from weasyprint import HTML

from datetime import datetime


router = APIRouter()

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
        analysis_result = url_analysis.analyze_url(qr_text)
        return analysis_result
    else:
        return {"extracted_text": "Please enter a valid QR Code."}
    


# @router.get("/check-domain", response_model=report_model.DomainAnalysis)
@router.get("/check-domain")
def check_domain(domain: str = Query(..., example="https://example.com")):
    analysis_result = url_analysis.analyze_url(domain)
    return analysis_result






@router.post("/generate-report", response_class=Response)
async def generate_pdf_report(data: report_model.DomainAnalysis):
    """
    Generates a PDF report from the phishing scan result.
    """

    print(data)

    template = env.get_template("report.html")

    # Convert Pydantic model to dictionary for rendering
    data_dict = data.model_dump()
    print(data_dict)
    rendered_html = template.render(**data.model_dump(), date=datetime.now().strftime("%Y-%m-%d %H:%M UTC"))

    # Generate the PDF
    pdf = HTML(string=rendered_html).write_pdf()

    # print(pdf)

    # Return the PDF as response
    return Response(
        content=pdf,
        media_type="application/pdf",
        headers={"Content-Disposition": f"inline; filename=smartguard_{data.domain}_report.pdf"}
    )
