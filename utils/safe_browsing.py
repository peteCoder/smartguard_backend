import requests
from config import settings
import time



# GOOGLE SAFE BROWSING API
GOOGLE_API_URL = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={settings.GOOGLE_SAFE_BROWSING_API_KEY}"

def check_url_safety_google(url: str):
    payload = {
        "client": {
            "clientId": "smartguard",
            "clientVersion": "1.0.0"
        },
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }

    try:
        response = requests.post(GOOGLE_API_URL, json=payload, timeout=5)
        response.raise_for_status()
        
        data = response.json()

        print("DATA: ", data)
        print(response.status_code)

        print(data.get("matches"))

        if data.get("matches"):
            return {
                "safe": False,
                "details": data["matches"]
            }
        else:
            return {
                "safe": True,
                "details": []
            }

    except Exception as e:
        print(e)
        return {
            "safe": None,
            "error": str(e)
        }


# URL SCANNER TOOL from https://urlscan.io/
URL_SCANNER_API_KEY = settings.URL_SCANNER_API_KEY
HEADERS = {
    "API-Key": URL_SCANNER_API_KEY,
    "Content-Type": "application/json"
}

SCAN_URL = "https://urlscan.io/api/v1/scan/"
RESULT_URL = "https://urlscan.io/api/v1/result/"

def scan_url_with_urlscan(target_url: str):
    # Normalize URL
    if not target_url.startswith("http"):
        target_url = "http://" + target_url

    try:
        # Submit URL for scanning
        submission_response = requests.post(
            SCAN_URL,
            headers=HEADERS,
            json={"url": target_url},
            timeout=10
        )
        submission_response.raise_for_status()
        scan_data = submission_response.json()
        scan_id = scan_data.get("uuid")

        if not scan_id:
            return {"safe": None, "error": "No scan ID returned from URLScan"}

        # Poll for result
        for _ in range(10):  # Try up to 10 times with a 2s delay
            time.sleep(2)
            result_response = requests.get(f"{RESULT_URL}{scan_id}/", timeout=10)
            if result_response.status_code == 200:
                result_data = result_response.json()
                verdict_info = result_data.get("verdicts", {}).get("overall", {})

                malicious = verdict_info.get("malicious", False)
                tags = verdict_info.get("tags", [])
                score = verdict_info.get("score")
                categories = verdict_info.get("categories", [])
                verdict = categories[0] if categories else "unknown"

                screenshot_url = f"https://urlscan.io/screenshots/{scan_id}.png"

                return {
                    "safe": not malicious,
                    "verdict": verdict,
                    "tags": tags,
                    "score": score,
                    "screenshot": screenshot_url,
                    "error": None
                }

        return {"safe": None, "error": "Scan result not ready after retries"}

    except Exception as e:
        return {"safe": None, "error": str(e)}









