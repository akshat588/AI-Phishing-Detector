import joblib

# ==========================
# Load ML Model
# ==========================

model = joblib.load("saved_model.pkl")
vectorizer = joblib.load("vectorizer.pkl")


# ==========================
# Threat DNA Engine
# ==========================

def analyze_email(email_text):

    email_text = email_text.lower()

    threat_dna = {
        "Credential Theft": 0,
        "Urgency": 0,
        "Fear Tactics": 0,
        "Financial Fraud": 0,
        "Social Engineering": 0
    }

    credential_words = [
        "password",
        "otp",
        "verify",
        "login",
        "credentials"
    ]

    urgency_words = [
        "urgent",
        "immediately",
        "today",
        "now",
        "asap"
    ]

    fear_words = [
        "suspended",
        "blocked",
        "warning",
        "terminated",
        "legal action"
    ]

    financial_words = [
        "bank",
        "account",
        "payment",
        "transaction",
        "credit card"
    ]

    social_words = [
        "click here",
        "dear customer",
        "claim reward",
        "special offer"
    ]

    # Credential Theft
    for word in credential_words:
        if word in email_text:
            threat_dna["Credential Theft"] += 20

    # Urgency
    for word in urgency_words:
        if word in email_text:
            threat_dna["Urgency"] += 20

    # Fear Tactics
    for word in fear_words:
        if word in email_text:
            threat_dna["Fear Tactics"] += 20

    # Financial Fraud
    for word in financial_words:
        if word in email_text:
            threat_dna["Financial Fraud"] += 20

    # Social Engineering
    for word in social_words:
        if word in email_text:
            threat_dna["Social Engineering"] += 20

    return threat_dna


# ==========================
# User Input
# ==========================

email = input("Paste suspicious email:\n\n")


# ==========================
# ML Prediction
# ==========================

email_vector = vectorizer.transform([email])

prediction = model.predict(email_vector)

probability = model.predict_proba(email_vector)

confidence = round(max(probability[0]) * 100, 2)


# ==========================
# Threat DNA Analysis
# ==========================

result = analyze_email(email)

overall_score = min(sum(result.values()), 100)


# ==========================
# Risk Classification
# ==========================

if overall_score >= 90:
    risk_level = "🚨 CRITICAL"

elif overall_score >= 70:
    risk_level = "🔴 HIGH"

elif overall_score >= 40:
    risk_level = "🟠 MEDIUM"

else:
    risk_level = "🟢 LOW"


# ==========================
# PHISHEYE REPORT
# ==========================

print("\n")
print("=" * 50)
print("            PHISHEYE AI REPORT")
print("=" * 50)

print(f"\nML Confidence: {confidence}%")

if prediction[0] == 1:
    print("⚠ PHISHING DETECTED")
else:
    print("✓ SAFE MESSAGE")


# ==========================
# Threat DNA
# ==========================

print("\n========== THREAT DNA ==========\n")

for threat, score in result.items():

    bars = "█" * (score // 10)
    empty = "░" * (10 - (score // 10))

    print(f"{threat:<20} {bars}{empty} {score}%")

print("\nOverall Threat Score:", overall_score, "%")
print("Risk Level:", risk_level)


# ==========================
# AI Security Analyst
# ==========================

print("\n========== AI SECURITY ANALYST ==========\n")

if result["Credential Theft"] > 0:
    print("• Credential harvesting indicators detected.")

if result["Urgency"] > 0:
    print("• Urgency manipulation detected.")

if result["Fear Tactics"] > 0:
    print("• Fear tactics detected.")

if result["Financial Fraud"] > 0:
    print("• Financial fraud indicators detected.")

if result["Social Engineering"] > 0:
    print("• Social engineering indicators detected.")


# ==========================
# Recommendations
# ==========================

print("\nRecommendation:\n")

if overall_score >= 90:

    print("🚨 Quarantine this email immediately.")
    print("🚨 Block sender.")
    print("🚨 Do NOT click links.")
    print("🚨 Report to security team.")

elif overall_score >= 70:

    print("⚠ High-risk phishing indicators detected.")
    print("⚠ Verify sender independently.")
    print("⚠ Avoid opening attachments.")

elif overall_score >= 40:

    print("⚠ Suspicious email.")
    print("⚠ Exercise caution.")
    print("⚠ Verify authenticity before responding.")

else:

    print("✓ Low risk email.")