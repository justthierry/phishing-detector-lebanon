# detector.py — Lebanese Phishing URL Detector Agent
#  Agentic AI applied to cybersecurity in Lebanon

import re
import numpy as np
import pandas as pd
from urllib.parse import urlparse
from scipy.stats import entropy as scipy_entropy
from sklearn.ensemble import RandomForestClassifier
import pickle
import sys

# ── Tool 1: Feature Extractor ──────────────────────────────────────────
def extract_features(url):
    features = {}
    features['url_length'] = len(url)
    features['num_dots'] = url.count('.')
    features['has_https'] = 1 if url.startswith('https') else 0
    features['has_ip'] = 1 if re.search(r'\d+\.\d+\.\d+\.\d+', url) else 0
    features['num_slashes'] = url.count('/')
    features['has_at'] = 1 if '@' in url else 0
    features['num_subdomains'] = len(urlparse(url).netloc.split('.')) - 2
    suspicious_words = ['login', 'verify', 'secure', 'account', 'update', 'confirm']
    features['has_suspicious'] = 1 if any(w in url.lower() for w in suspicious_words) else 0
    counts = [url.count(c) for c in set(url)]
    features['url_entropy'] = scipy_entropy(counts)
    features['num_digits'] = sum(c.isdigit() for c in url)
    return features

# ── Tool 2: Risk Explainer ─────────────────────────────────────────────
def explain_risk(features):
    reasons = []
    if features['url_entropy'] > 3.5:
        reasons.append(f"  ✗ High URL entropy (randomness score: {features['url_entropy']:.2f})")
    if features['url_length'] > 75:
        reasons.append(f"  ✗ URL is unusually long ({features['url_length']} characters)")
    if features['has_https'] == 0:
        reasons.append("  ✗ No HTTPS detected")
    if features['has_at'] == 1:
        reasons.append("  ✗ Contains @ symbol (classic phishing trick)")
    if features['has_suspicious'] == 1:
        reasons.append("  ✗ Contains suspicious words (login/verify/secure/account)")
    if features['has_ip'] == 1:
        reasons.append("  ✗ Contains raw IP address instead of domain name")
    if features['num_dots'] > 4:
        reasons.append(f"  ✗ Too many dots ({features['num_dots']}) — possible subdomain abuse")
    return reasons

# ── Agent ──────────────────────────────────────────────────────────────
def run_agent(model, url):
    print(f"\nAnalyzing: {url}\n")

    # Step 1 — extract features (Tool 1)
    features = extract_features(url)
    X = pd.DataFrame([features])

    # Step 2 — classify (Tool 2)
    prob = model.predict_proba(X)[0][1]
    prediction = model.predict(X)[0]

    # Step 3 — explain
    reasons = explain_risk(features)

    # Step 4 — output verdict
    if prediction == 1:
        print(f"⚠️  PHISHING DETECTED (Confidence: {prob*100:.0f}%)\n")
        if reasons:
            print("Risk factors identified:")
            for r in reasons:
                print(r)
    else:
        print(f"✅  URL APPEARS SAFE (Confidence: {(1-prob)*100:.0f}%)\n")
        if reasons:
            print("Minor risk factors (low concern):")
            for r in reasons:
                print(r)

    print("\n🇱🇧 Protecting Lebanese users from phishing attacks.\n")

# ── Main ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    # Load model
    try:
        with open('rf_model.pkl', 'rb') as f:
            model = pickle.load(f)
    except FileNotFoundError:
        print("❌ Model not found. Run the notebook first to train and save the model.")
        sys.exit(1)

    print("=" * 55)
    print("   🔍 Lebanese Phishing URL Detector")
    print("   Lebanon ranks 132nd in global cybersecurity.")
    print("   This tool helps protect Lebanese users online.")
    print("=" * 55)

    while True:
        url = input("\nEnter a URL to check (or 'quit' to exit): ").strip()
        if url.lower() == 'quit':
            print("Stay safe online! 🇱🇧")
            break
        if not url:
            continue
        run_agent(model, url)