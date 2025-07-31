import joblib
import numpy as np
import pandas as pd

from services.url_analysis import analyse_domain_for_ml
from config import BASE_DIR

from helpers import (
    is_potentially_deceptive,
)

# Retrieving the location of the model
PHISHING_MODEL_PATH = BASE_DIR / "utils" / "phishing_model.pkl"
LABEL_ENCODED_PATH = BASE_DIR / "utils" / "label_encoder.pkl"

# print("BASE_DIR: ", BASE_DIR)
# print("PHISHING_MODEL_PATH: ", PHISHING_MODEL_PATH)
# print("LABEL_ENCODED_PATH: ", LABEL_ENCODED_PATH)

# Load your trained model and label encoder
model = joblib.load(PHISHING_MODEL_PATH)
label_encoder = joblib.load(LABEL_ENCODED_PATH)



def machine_learning_prediction(domain: str):
    ML_FEATURES = [
        "domain_length",
        "num_digits",
        "num_hyphens",
        "has_https",
        "num_subdomains",
        "tld",
        "is_suspicious_tld",
        "typosquatting_score",

        # Other Features
        "is_shortened",
        "is_brand_misused_with_tld",
        "is_potentially_deceptive_flag",
        
        "typo_score",
        "is_typosquatting"

    ]

    full_features = analyse_domain_for_ml(domain)

    try:
        features_for_model = {k: full_features[k] for k in ML_FEATURES}
        features_for_model["tld"] = label_encoder.transform([features_for_model["tld"]])[0]
        df = pd.DataFrame([features_for_model])

        prediction = int(model.predict(df)[0])
        prob = float(model.predict_proba(df)[0][prediction])

        # Additional heuristics
        warning_msgs = []
        deceptive = is_potentially_deceptive(domain)

        if prob < 0.75:
            warning_msgs.append("⚠️ Model is not confident in its prediction. Proceed with caution.")

        if not full_features.get("whois", {}).get("age_days"):
            warning_msgs.append("⚠️ Domain age could not be determined. May indicate a newly created domain.")

        if deceptive:
            warning_msgs.append("⚠️ Domain name may imitate trusted brands. Possible phishing attempt.")

        # Optional: Risk score (simple example)
        risk_score = round((1 - prob) * 0.5 + deceptive * 0.3 + (not full_features.get("whois", {}).get("age_days")) * 0.2, 2)
        risk_level = "high" if risk_score > 0.7 else "medium" if risk_score > 0.4 else "low"

        return {
            "domain": full_features["domain"],
            "tld": full_features["tld"],
            "is_phishing": bool(prediction),
            "confidence": round(prob, 3),
            "features_used": {
                k: (int(v) if isinstance(v, (np.integer, bool)) else v)
                for k, v in features_for_model.items()
            },
            "whois": full_features.get("whois"),
            "deceptive_pattern_detected": deceptive,
            "warning": " ".join(warning_msgs) if warning_msgs else None,
            "risk_score": risk_score,
            "risk_level": risk_level
        }

    except Exception as e:
        return {"error": str(e)}





















