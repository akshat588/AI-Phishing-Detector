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

    # Credential Theft Detection
    for word in credential_words:
        if word in email_text:
            threat_dna["Credential Theft"] += 20

    # Urgency Detection
    for word in urgency_words:
        if word in email_text:
            threat_dna["Urgency"] += 20

    # Fear Tactics Detection
    for word in fear_words:
        if word in email_text:
            threat_dna["Fear Tactics"] += 20

    # Financial Fraud Detection
    for word in financial_words:
        if word in email_text:
            threat_dna["Financial Fraud"] += 20

    # Social Engineering Detection
    for word in social_words:
        if word in email_text:
            threat_dna["Social Engineering"] += 20

    return threat_dna


# -------------------------
# User Input
# -------------------------

email = input("Paste suspicious email:\n")

result = analyze_email(email)

# -------------------------
# Calculate Overall Score
# -------------------------

overall_score = sum(result.values()) // len(result)

# -------------------------
# Risk Classification
# -------------------------

if overall_score >= 70:
    risk_level = "🔴 HIGH RISK"

elif overall_score >= 40:
    risk_level = "🟠 MEDIUM RISK"

else:
    risk_level = "🟢 LOW RISK"

# -------------------------
# Display Results
# -------------------------

print("\n========== THREAT DNA ==========\n")

for threat, score in result.items():

    bars = "█" * (score // 10)
    empty = "░" * (10 - (score // 10))

    print(f"{threat:<20} {bars}{empty} {score}%")

print("\n================================")

print(f"\nOverall Threat Score: {overall_score}%")

print(f"Risk Level: {risk_level}")
print("\n========== AI SECURITY ANALYST ==========\n")

if result["Credential Theft"] > 0:
    print("• Credential harvesting indicators detected.")

if result["Urgency"] > 0:
    print("• Urgency-based manipulation detected.")

if result["Fear Tactics"] > 0:
    print("• Fear tactics detected.")

if result["Financial Fraud"] > 0:
    print("• Financial fraud indicators detected.")

if result["Social Engineering"] > 0:
    print("• Social engineering patterns detected.")

print("\nRecommendation:")

if overall_score >= 70:
    print("⚠ Do NOT interact with this email.")
    print("⚠ Quarantine immediately.")
elif overall_score >= 40:
    print("⚠ Verify sender before taking action.")
else:
    print("✓ Low risk email.")