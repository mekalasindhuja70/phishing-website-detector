# 🔒 Advanced Hybrid Phishing Website Detector

An AI-powered Hybrid Phishing Detection System that combines:

- 🌲 Random Forest Machine Learning Model
- 🌐 Advanced URL Feature Engineering
- 🛡 Google Safe Browsing API
- 📊 Risk Probability Visualization (Streamlit)

This system detects whether a website URL is **Legitimate or Phishing** using both machine learning and real-time threat intelligence.

---

## 🚀 Project Overview

Phishing attacks are one of the most common cybersecurity threats. This project builds a hybrid detection system that:

1. Extracts intelligent features from URLs
2. Uses a trained Random Forest classifier to predict phishing probability
3. Cross-verifies with Google Safe Browsing API
4. Produces a final security verdict

The goal is to improve detection reliability by combining AI with real-world threat intelligence.

---

## 🌲 Machine Learning Model

### Algorithm Used:
RandomForestClassifier

### Model Configuration:

RandomForestClassifier(
    n_estimators=200,
    class_weight='balanced',
    random_state=42
)

### Why Random Forest?

- Handles structured/tabular data effectively
- Captures non-linear feature relationships
- Reduces overfitting using ensemble learning
- Provides feature importance for explainability
- Performs well in cybersecurity classification tasks

### Handling Class Imbalance

The dataset had imbalance between legitimate and phishing URLs.

To address this:

class_weight = 'balanced'

This ensures phishing samples are not ignored and improves detection sensitivity.

---

## 🔍 Feature Engineering

The model extracts multiple intelligent features from the URL:

### URL-Based Features
- URL length
- Hostname length
- Path length
- Query length
- Number of dots
- Number of hyphens
- Number of special characters
- HTTPS presence
- Digit-to-length ratio
- Letter-to-length ratio

### Security-Oriented Features
- Suspicious keywords (login, verify, update, bank, etc.)
- Suspicious TLD detection (.tk, .ml, .ga, etc.)
- Brand impersonation detection
- IP address in URL
- Double slash in path
- Executable file detection (.exe, .zip, .scr)
- URL entropy (randomness detection)

These features help detect phishing characteristics effectively.

---

## 🛡 Hybrid Detection Logic

Final decision is based on:

1. ML model prediction
2. ML probability score
3. Google Safe Browsing API result

If:
- URL is blacklisted → Marked as Phishing
- Probability > 0.7 → Marked as Phishing
- Model predicts phishing → Marked as Phishing

This layered approach increases detection reliability.

---

## 📊 Output Visualization

The system displays:

- Risk probability progress bar
- Probability comparison graph (Legitimate vs Phishing)
- Final security verdict
- Feature importance chart (Top 10 features)

---

## 🛠 Technologies Used

- Python
- Streamlit
- Scikit-learn
- Pandas
- Matplotlib
- Joblib
- TLDExtract
- Requests
- Google Safe Browsing API

---

