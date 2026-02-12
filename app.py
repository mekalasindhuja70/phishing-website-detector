import streamlit as st
import pandas as pd
import joblib
import tldextract
import requests
import math
from urllib.parse import urlparse

# -------------------- CONFIG --------------------
st.set_page_config(page_title="Phishing Website Detector", page_icon="🔒", layout="centered")

st.title("🔒 Advanced Phishing Website Detector")
st.write("Enter a website URL below to check if it is legitimate or a phishing site.")

# 🔐 Add your Google Safe Browsing API key here
GOOGLE_API_KEY = "YOUR_GOOGLE_SAFE_BROWSING_API_KEY"

# -------------------- LOAD MODEL --------------------
obj = joblib.load("phish_model.pkl")

if isinstance(obj, dict):
    model = obj.get("model")
    model_features = obj.get("features")
else:
    model = obj
    model_features = None

if model is None:
    st.error("Model failed to load.")
    st.stop()

# -------------------- CONSTANTS --------------------
SUSPICIOUS_KEYWORDS = [
    "login", "verify", "update", "secure",
    "account", "bank", "confirm", "signin",
    "reset", "password"
]

SUSPICIOUS_TLDS = ["tk", "ml", "ga", "cf", "gq"]

KNOWN_BRANDS = [
    "paypal", "amazon", "google",
    "facebook", "instagram", "bank"
]

# -------------------- HELPER FUNCTIONS --------------------

def calculate_entropy(s):
    if len(s) == 0:
        return 0
    prob = [float(s.count(c)) / len(s) for c in dict.fromkeys(list(s))]
    return -sum([p * math.log2(p) for p in prob])

def base_url_features(url):
    parsed = urlparse(url if "://" in url else "http://" + url)
    ext = tldextract.extract(url)
    s = url.lower()

    features = {}

    features['url_len'] = len(s)
    features['hostname_len'] = len(parsed.hostname or '')
    features['path_len'] = len(parsed.path or '')
    features['query_len'] = len(parsed.query or '')
    features['count_dots'] = s.count('.')
    features['count_hyphen'] = s.count('-')
    features['count_at'] = s.count('@')
    features['count_equal'] = s.count('=')
    features['count_slash'] = s.count('/')
    features['is_https'] = int(parsed.scheme == 'https')
    features['count_digits'] = sum(ch.isdigit() for ch in s)
    features['count_letters'] = sum(ch.isalpha() for ch in s)
    features['digits_to_len'] = features['count_digits'] / (features['url_len'] + 1)
    features['letters_to_len'] = features['count_letters'] / (features['url_len'] + 1)

    # IP detection
    hostname = parsed.hostname or ""
    features['has_ip'] = int(
        hostname.replace('.', '').isdigit() and hostname.count('.') == 3
    )

    # Subdomain count
    features['subdomain_parts'] = ext.subdomain.count('.') + 1 if ext.subdomain else 0

    return features

def enhanced_features(url):
    parsed = urlparse(url if "://" in url else "http://" + url)
    ext = tldextract.extract(url)
    s = url.lower()

    features = base_url_features(url)

    # Suspicious keywords
    features["has_suspicious_keyword"] = int(
        any(k in s for k in SUSPICIOUS_KEYWORDS)
    )

    # Suspicious TLD
    features["suspicious_tld"] = int(ext.suffix in SUSPICIOUS_TLDS)

    # Brand misuse
    features["brand_in_domain"] = int(
        any(b in ext.domain for b in KNOWN_BRANDS)
    )

    # URL entropy
    features["url_entropy"] = calculate_entropy(s)

    # Double slash redirect trick
    features["double_slash_path"] = int("//" in parsed.path)

    # Suspicious file extension
    features["has_executable"] = int(
        any(extn in s for extn in [".exe", ".zip", ".scr"])
    )

    return features

def check_google_safe_browsing(url):
    if GOOGLE_API_KEY == "YOUR_GOOGLE_SAFE_BROWSING_API_KEY":
        return False  # Skip if no key added

    endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_API_KEY}"

    payload = {
        "client": {
            "clientId": "phishing-detector",
            "clientVersion": "1.0"
        },
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }

    try:
        response = requests.post(endpoint, json=payload)
        result = response.json()
        return "matches" in result
    except:
        return False

# -------------------- UI --------------------
url_input = st.text_input("🔗 Enter Website URL", placeholder="https://example.com")

if st.button("Predict"):

    if not url_input.strip():
        st.warning("Please enter a URL.")
    else:
        try:
            feat_dict = enhanced_features(url_input)
            X = pd.DataFrame([feat_dict])

            if model_features:
                for col in model_features:
                    if col not in X.columns:
                        X[col] = 0
                X = X[model_features]

            pred = model.predict(X)[0]
            prob = None
            if hasattr(model, "predict_proba"):
                prob = float(model.predict_proba(X)[0][1])

            # Google Safe Browsing Check
            is_blacklisted = check_google_safe_browsing(url_input)

            st.divider()
            st.subheader("🔍 Analysis Results")

            if is_blacklisted:
                st.error("🚨 Google Safe Browsing: URL is reported as dangerous!")
            else:
                st.success("✅ Google Safe Browsing: No threats detected")

            # Hybrid Decision Logic
            final_prediction = "Legitimate"

            if is_blacklisted:
                final_prediction = "Phishing"
            elif prob and prob > 0.7:
                final_prediction = "Phishing"
            elif pred == 1:
                final_prediction = "Phishing"

            if final_prediction == "Phishing":
                st.error(f"🚨 Final Verdict: PHISHING (ML prob={prob:.2f})")
            else:
                st.success(f"✅ Final Verdict: LEGITIMATE (ML prob={prob:.2f})")

        except Exception as e:
            st.error(f"Error processing URL: {e}")
