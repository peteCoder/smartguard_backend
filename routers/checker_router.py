from fastapi import APIRouter, UploadFile, File, Query
from services import qr_extration, url_analysis
from models import report_model

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
        return {"extracted_text": qr_text}
    else:
        return {"extracted_text": "No QR code found"}


@router.get("/check-domain")
def check_domain(domain: str = Query(..., example="example.com")):
    analysis_result = url_analysis.analyze_url(domain)
    return analysis_result




