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


def get_email_score(threat_dna):

    score = min(sum(threat_dna.values()), 100)

    return score


def get_risk_level(score):

    if score >= 90:
        return "🚨 CRITICAL"

    elif score >= 70:
        return "🔴 HIGH"

    elif score >= 40:
        return "🟠 MEDIUM"

    else:
        return "🟢 LOW"


# ==========================
# TEST MODE
# ==========================

if __name__ == "__main__":

    email = input("Paste suspicious email:\n\n")

    result = analyze_email(email)

    score = get_email_score(result)

    risk_level = get_risk_level(score)

    print("\n========== EMAIL ANALYZER ==========\n")

    for threat, value in result.items():

        bars = "█" * (value // 10)
        empty = "░" * (10 - (value // 10))

        print(f"{threat:<20} {bars}{empty} {value}%")

    print("\nOverall Score:", score)
    print("Risk Level:", risk_level)

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