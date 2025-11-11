import streamlit as st
import pandas as pd
import joblib
from urllib.parse import urlparse
import tldextract
import re

st.set_page_config(page_title="Phishing Website Detector", page_icon="🔒", layout="centered")

st.title("🔒 Phishing Website Detector")
st.write("Enter a website URL below to check if it is legitimate or a phishing site.")

# --- Load model robustly (handles both dict and direct model pickle) ---
obj = joblib.load("phish_model.pkl")
if isinstance(obj, dict):
    model = obj.get("model")
    model_features = obj.get("features")  # list of feature column names used during training
else:
    # older style: model saved directly
    model = obj
    model_features = None

# If model failed to load, stop early
if model is None:
    st.error("Model failed to load. Please re-upload phish_model.pkl (it should contain the trained model).")
    st.stop()

# --- The feature extractor used to *match training* (full lexical features) ---
def url_features_for_model(url):
    parsed = urlparse(url if "://" in url else "http://" + url)
    ext = tldextract.extract(url)
    domain = ext.domain or ""
    suffix = ext.suffix or ""
    subdomain = ext.subdomain or ""
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
    features['has_ip'] = int(bool(parsed.hostname and all(ch.isdigit() or ch=='.' for ch in (parsed.hostname or '').replace(':','').split(':')[0].split('.')) and len((parsed.hostname or '').split('.'))==4))
    features['is_https'] = int(parsed.scheme == 'https')
    features['subdomain_parts'] = subdomain.count('.') + 1 if subdomain else 0
    features['domain_len'] = len(domain)
    features['suffix_len'] = len(suffix)
    features['count_digits'] = sum(ch.isdigit() for ch in s)
    features['count_letters'] = sum(ch.isalpha() for ch in s)
    features['digits_to_len'] = features['count_digits'] / (features['url_len'] + 1)
    features['letters_to_len'] = features['count_letters'] / (features['url_len'] + 1)
    return features

# --- Input box and prediction ---
url_input = st.text_input("🔗 Enter Website URL", placeholder="e.g., https://example.com")

if st.button("Predict"):
    if not url_input.strip():
        st.warning("Please enter a URL.")
    else:
        try:
            # Build feature dict and DataFrame
            feat_dict = url_features_for_model(url_input)
            X = pd.DataFrame([feat_dict])

            # If we have the model_features list saved with the model, ensure column order & missing cols
            if model_features:
                # ensure all expected columns exist; add missing with zeros
                for c in model_features:
                    if c not in X.columns:
                        X[c] = 0
                # Keep only model_features in the right order
                X = X[model_features]
            else:
                # If we don't have model_features, assume X columns match
                pass

            # Predict
            pred = model.predict(X)[0]
            prob = None
            if hasattr(model, "predict_proba"):
                prob = float(model.predict_proba(X)[0, 1])

            # Show results
            if pred == 1:
                if prob is None:
                    st.error("🚨 Predicted: Phishing")
                else:
                    st.error(f"🚨 Predicted: Phishing (prob={prob:.2f})")
            else:
                if prob is None:
                    st.success("✅ Predicted: Legitimate")
                else:
                    st.success(f"✅ Predicted: Legitimate (prob={prob:.2f})")

        except Exception as e:
            st.error(f"An error occurred while processing the URL: {e}")
