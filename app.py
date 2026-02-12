import streamlit as st
import pandas as pd
import joblib
import tldextract
import requests
import math
import matplotlib.pyplot as plt
from urllib.parse import urlparse

# -------------------- CONFIG --------------------
st.set_page_config(page_title="Advanced Phishing Detector", page_icon="🔒", layout="centered")

st.title("🔒 Advanced Hybrid Phishing Website Detector")
st.write("Machine Learning + Heuristics + Google Safe Browsing")

# 🔐 ADD YOUR API KEY HERE
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
    "login","verify","update","secure","account",
    "bank","confirm","signin","reset","password"
]

SUSPICIOUS_TLDS = ["tk","ml","ga","cf","gq"]

KNOWN_BRANDS = [
    "paypal","amazon","google","facebook",
    "instagram","bank"
]

# -------------------- HELPER FUNCTIONS --------------------
def calculate_entropy(s):
    if len(s) == 0:
        return 0
    prob = [float(s.count(c))/len(s) for c in dict.fromkeys(list(s))]
    return -sum([p * math.log2(p) for p in prob])

def extract_features(url):
    parsed = urlparse(url if "://" in url else "http://" + url)
    ext = tldextract.extract(url)
    s = url.lower()
    hostname = parsed.hostname or ""

    features = {}

    features['url_len'] = len(s)
    features['hostname_len'] = len(hostname)
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
    features['digits_to_len'] = features['count_digits']/(features['url_len']+1)
    features['letters_to_len'] = features['count_letters']/(features['url_len']+1)

    # IP detection
    features['has_ip'] = int(hostname.replace('.','').isdigit() and hostname.count('.') == 3)

    # Subdomain count
    features['subdomain_parts'] = ext.subdomain.count('.')+1 if ext.subdomain else 0

    # Suspicious keyword
    features['has_suspicious_keyword'] = int(any(k in s for k in SUSPICIOUS_KEYWORDS))

    # Suspicious TLD
    features['suspicious_tld'] = int(ext.suffix in SUSPICIOUS_TLDS)

    # Brand misuse
    features['brand_in_domain'] = int(any(b in ext.domain for b in KNOWN_BRANDS))

    # Entropy
    features['url_entropy'] = calculate_entropy(s)

    # Double slash trick
    features['double_slash_path'] = int("//" in parsed.path)

    # Executable file
    features['has_executable'] = int(any(extn in s for extn in [".exe",".zip",".scr"]))

    return features

def check_google_safe_browsing(url):
    if GOOGLE_API_KEY == "YOUR_GOOGLE_SAFE_BROWSING_API_KEY":
        return False

    endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_API_KEY}"

    payload = {
        "client": {"clientId":"phishing-detector","clientVersion":"1.0"},
        "threatInfo":{
            "threatTypes":["MALWARE","SOCIAL_ENGINEERING"],
            "platformTypes":["ANY_PLATFORM"],
            "threatEntryTypes":["URL"],
            "threatEntries":[{"url":url}]
        }
    }

    try:
        response = requests.post(endpoint,json=payload)
        result = response.json()
        return "matches" in result
    except:
        return False

# -------------------- UI INPUT --------------------
url_input = st.text_input("🔗 Enter Website URL", placeholder="https://example.com")

if st.button("Analyze URL"):

    if not url_input.strip():
        st.warning("Please enter a valid URL.")
    else:
        try:
            feat_dict = extract_features(url_input)
            X = pd.DataFrame([feat_dict])

            if model_features:
                for col in model_features:
                    if col not in X.columns:
                        X[col] = 0
                X = X[model_features]

            pred = model.predict(X)[0]
            prob = None
            if hasattr(model,"predict_proba"):
                prob = float(model.predict_proba(X)[0][1])

            # Google Safe Browsing
            is_blacklisted = check_google_safe_browsing(url_input)

            st.divider()
            st.subheader("🔍 Security Analysis")

            # -------------------- PROBABILITY GRAPH --------------------
            if prob is not None:
                st.subheader("📊 ML Risk Probability")

                st.progress(int(prob*100))

                if prob < 0.3:
                    st.success(f"🟢 Low Risk ({prob:.2f})")
                elif prob < 0.7:
                    st.warning(f"🟡 Medium Risk ({prob:.2f})")
                else:
                    st.error(f"🔴 High Risk ({prob:.2f})")

                fig, ax = plt.subplots()
                ax.bar(["Legitimate","Phishing"], [1-prob, prob])
                ax.set_ylim([0,1])
                ax.set_ylabel("Probability")
                st.pyplot(fig)

            # -------------------- GOOGLE SAFE BROWSING --------------------
            if is_blacklisted:
                st.error("🚨 Google Safe Browsing: Reported as Dangerous")
            else:
                st.success("✅ Google Safe Browsing: No Threat Found")

            # -------------------- FINAL DECISION --------------------
            final_prediction = "Legitimate"

            if is_blacklisted:
                final_prediction = "Phishing"
            elif prob and prob > 0.7:
                final_prediction = "Phishing"
            elif pred == 1:
                final_prediction = "Phishing"

            st.divider()
            st.subheader("🛡 Final Verdict")

            if final_prediction == "Phishing":
                st.error("🚨 PHISHING WEBSITE DETECTED")
            else:
                st.success("✅ Website Appears Legitimate")

            # -------------------- FEATURE IMPORTANCE --------------------
            if hasattr(model,"feature_importances_"):
                st.divider()
                st.subheader("📈 Feature Importance")

                importance_df = pd.DataFrame({
                    "Feature": X.columns,
                    "Importance": model.feature_importances_
                }).sort_values(by="Importance", ascending=False).head(10)

                fig2, ax2 = plt.subplots()
                ax2.barh(importance_df["Feature"], importance_df["Importance"])
                ax2.invert_yaxis()
                st.pyplot(fig2)

        except Exception as e:
            st.error(f"Error: {e}")
