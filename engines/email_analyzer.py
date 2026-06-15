def analyze_email(email_text):

    email_text = email_text.lower()

    threat_dna = {
        "Credential Theft": 0,
        "Urgency": 0,
        "Fear Tactics": 0,
        "Financial Fraud": 0,
        "Social Engineering": 0
    }

    # Credential Theft
    credential_words = {
        "password": 30,
        "otp": 30,
        "verify": 20,
        "login": 20,
        "credentials": 30
    }

# Urgency
    urgency_words = {
        "urgent": 30,
        "immediately": 25,
        "asap": 20,
        "today": 10,
        "now": 10
    }

    fear_words = {
        "suspended": 30,
        "blocked": 25,
        "warning": 15,
        "terminated": 25,
        "legal action": 35
    }

    financial_words = {
        "payment": 20,
        "transaction": 20,
        "credit card": 30,
        "debit card": 30,
        "refund": 20,
        "upi": 25,
        "wallet": 20,
        "money transfer": 30,
        "banking": 20,
        "bank account": 30
    }

    social_words = {
        "click here": 30,
        "claim reward": 35,
        "special offer": 20,
        "free gift": 30,
        "winner": 25,
        "congratulations": 15,
        "limited offer": 25
    }

    # Credential Theft
    for word, score in credential_words.items():
        if word in email_text:
            threat_dna["Credential Theft"] += score
            

    # Urgency
    for word, score in urgency_words.items():
        if word in email_text:
            threat_dna["Urgency"] += score
            
    # Fear Tactics
    for word, score in fear_words.items():
        if word in email_text:
            threat_dna["Fear Tactics"] += score

    # Financial Fraud
    for word, score in financial_words.items():
        if word in email_text:
            threat_dna["Financial Fraud"] += score

    # Social Engineering
    for word, score in social_words.items():
        if word in email_text:
            threat_dna["Social Engineering"] += score
            
    for key in threat_dna:
        
            threat_dna[key] = min(threat_dna[key], 100)



    return threat_dna


def get_email_score(threat_dna):

    score = round(
        (
            threat_dna["Credential Theft"] * 0.35 +
            threat_dna["Urgency"] * 0.20 +
            threat_dna["Fear Tactics"] * 0.20 +
            threat_dna["Financial Fraud"] * 0.15 +
            threat_dna["Social Engineering"] * 0.10
        ),
        2
    )
    score = min(score * 1.8, 100)

    score = min(score, 100)
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