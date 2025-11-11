import streamlit as st
import pandas as pd
import joblib
import tldextract
import re

# Load the saved model
model = joblib.load("phish_model.pkl")

st.set_page_config(page_title="Phishing Website Detector", page_icon="🔒", layout="centered")

# Title and description
st.title("🔒 Phishing Website Detector")
st.write("Enter a website URL below to check if it is legitimate or a phishing site.")

# Function to extract features from URL
def extract_features(url):
    domain_info = tldextract.extract(url)
    domain = domain_info.domain
    subdomain = domain_info.subdomain
    suffix = domain_info.suffix

    features = {
        "url_length": len(url),
        "num_dots": url.count("."),
        "has_https": 1 if "https" in url else 0,
        "num_digits": sum(c.isdigit() for c in url),
        "num_special_chars": len(re.findall(r"[^A-Za-z0-9]", url)),
        "domain_length": len(domain),
    }
    return pd.DataFrame([features])

# Input box for user
url_input = st.text_input("🔗 Enter Website URL", placeholder="e.g., http://example.com")

# Predict button
if st.button("Predict"):
    if url_input.strip() == "":
        st.warning("⚠️ Please enter a URL before predicting.")
    else:
        try:
            features = extract_features(url_input)
            prediction = model.predict(features)[0]
            if prediction == 1:
                st.error("🚨 This website is likely **Phishing**!")
            else:
                st.success("✅ This website looks **Legitimate**.")
        except Exception as e:
            st.error(f"An error occurred while processing the URL: {e}")
