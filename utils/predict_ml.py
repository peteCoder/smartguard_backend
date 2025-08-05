import joblib
import numpy as np
import pandas as pd

from services.url_analysis import analyse_domain_for_ml
from config import BASE_DIR
from helpers import (
    is_potentially_deceptive,
    safe_label_encode  # now included
)

# Load trained model and label encoder
PHISHING_MODEL_PATH = BASE_DIR / "utils" / "phishing_model.pkl"
LABEL_ENCODER_PATH = BASE_DIR / "utils" / "label_encoder.pkl"

model = joblib.load(PHISHING_MODEL_PATH)
label_encoder = joblib.load(LABEL_ENCODER_PATH)


def machine_learning_prediction(domain: str):
    FEATURES = [
        "domain_length",
        "num_digits",
        "num_hyphens",
        "has_https",
        "num_subdomains",
        "tld",
        "is_suspicious_tld",
        "typosquatting_score",
        "is_shortened",
        "is_brand_misused_with_tld",
        "is_potentially_deceptive_flag",
        "typo_score",
        "is_typosquatting"
    ]

    full_features = analyse_domain_for_ml(domain)

    try:
        # Prepare features for model
        model_features = {k: full_features[k] for k in FEATURES}
        model_features["tld"] = safe_label_encode(model_features["tld"], label_encoder)

        df = pd.DataFrame([model_features])
        prediction = int(model.predict(df)[0])
        prob = float(model.predict_proba(df)[0][prediction])

        # Heuristics
        deceptive = is_potentially_deceptive(domain)
        whois_age = full_features.get("whois", {}).get("age_days")

        warnings = []
        if prob < 0.75:
            warnings.append("⚠️ Low confidence in prediction.")
        if not whois_age:
            warnings.append("⚠️ Domain age is unknown or very recent.")
        if deceptive and not full_features["is_typosquatting"]:
            warnings.append("⚠️ Domain name may imitate trusted brands.")

        # Risk scoring
        risk_score = round((1 - prob) * 0.5 + deceptive * 0.3 + (not whois_age) * 0.2, 2)
        risk_level = "high" if risk_score > 0.7 else "medium" if risk_score > 0.4 else "low"

        return {
            "domain": full_features["domain"],
            "tld": full_features["tld"],
            "is_phishing": bool(prediction),
            "confidence": round(prob, 3),
            "features_used": {
                k: int(v) if isinstance(v, (np.integer, bool)) else v
                for k, v in model_features.items()
            },
            "whois": full_features.get("whois"),
            "deceptive_pattern_detected": deceptive,
            "warning": " ".join(warnings) if warnings else None,
            "risk_score": risk_score,
            "risk_level": risk_level
        }

    except Exception as e:
        return {"error": str(e)}




















