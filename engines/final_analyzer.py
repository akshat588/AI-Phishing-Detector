import joblib

from email_analyzer import (
    analyze_email,
    get_email_score
)

from url_analyzer import (
    analyze_url
)

from sender_analyzer import (
    analyze_sender
)

from threat_engine import (
    calculate_threat_score
)

# ==========================
# Load ML Model
# ==========================

model = joblib.load("saved_model.pkl")
vectorizer = joblib.load("vectorizer.pkl")

print("=" * 50)
print("PHISHEYE AI - FINAL ANALYZER")
print("=" * 50)

email = input("\nEnter Email Content:\n\n")

url = input("\nEnter URL:\n\n")

sender = input("\nEnter Sender Email:\n\n")

# ==========================
# Email Analysis
# ==========================

email_result = analyze_email(email)

email_score = get_email_score(email_result)

# ==========================
# URL Analysis
# ==========================

url_score, url_findings = analyze_url(url)

# ==========================
# Sender Analysis
# ==========================

sender_score, sender_findings = analyze_sender(sender)

# ==========================
# ML Prediction
# ==========================

email_vector = vectorizer.transform([email])

prediction = model.predict(email_vector)

probability = model.predict_proba(email_vector)

ml_confidence = round(
    max(probability[0]) * 100,
    2
)

if prediction[0] == 1:
    ml_verdict = "⚠ PHISHING DETECTED"
else:
    ml_verdict = "✓ SAFE MESSAGE"

# ==========================
# Final Threat Score
# ==========================

final_score = calculate_threat_score(
    email_score,
    url_score,
    sender_score,
    ml_confidence
)

# ==========================
# Severity
# ==========================

if final_score >= 90:
    severity = "🚨 CRITICAL"

elif final_score >= 70:
    severity = "🔴 HIGH"

elif final_score >= 40:
    severity = "🟠 MEDIUM"

else:
    severity = "🟢 LOW"

# ==========================
# Final Report
# ==========================

print("\n")
print("=" * 50)
print("PHISHEYE AI REPORT")
print("=" * 50)

print("\nML Verdict:", ml_verdict)
print("ML Confidence:", ml_confidence, "%")

print("\nEmail Score:", email_score)
print("URL Score:", url_score)
print("Sender Score:", sender_score)

print("\nFinal Threat Score:", final_score)
print("Severity:", severity)

print("\nURL Findings:")

if url_findings:
    for item in url_findings:
        print("•", item)

print("\nSender Findings:")

if sender_findings:
    for item in sender_findings:
        print("•", item)