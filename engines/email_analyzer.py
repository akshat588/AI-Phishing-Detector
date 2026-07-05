import re
from engines.explanation_engine import generate_ai_explanation
from engines.ai_intelligence_engine import generate_ai_intelligence
from services.ai_pipeline import build_ai_pipeline


def analyze_email(email_text):

    email_text = email_text.lower()

    threat_dna = {
        "Credential Theft": 0,
        "Urgency": 0,
        "Fear Tactics": 0,
        "Financial Fraud": 0,
        "Social Engineering": 0,
        "Brand Impersonation": 0,
        "Multiple URLs": 0,
        "Suspicious Attachment": 0,
        "Header Intelligence": 0,
    }

    # Credential Theft
    credential_words = {
        "password": 30,
        "otp": 30,
        "verify": 20,
        "login": 20,
        "credentials": 30,
    }

    # Urgency
    urgency_words = {
        "urgent": 30,
        "immediately": 25,
        "asap": 20,
        "today": 10,
        "now": 10,
    }

    fear_words = {
        "suspended": 30,
        "blocked": 25,
        "warning": 15,
        "terminated": 25,
        "legal action": 35,
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
        "bank account": 30,
    }

    social_words = {
        "click here": 30,
        "claim reward": 35,
        "special offer": 20,
        "free gift": 30,
        "winner": 25,
        "congratulations": 15,
        "limited offer": 25,
    }

    brand_words = {
        "sbi": 20,
        "state bank of india": 30,
        "hdfc": 20,
        "icici": 20,
        "axis bank": 20,
        "kotak": 20,
        "phonepe": 20,
        "google pay": 20,
        "gpay": 20,
        "paytm": 20,
        "bhim": 20,
        "npci": 20,
        "aadhaar": 20,
        "digilocker": 20,
        "income tax": 20,
        "epfo": 20,
        "amazon": 15,
        "flipkart": 15,
        "myntra": 15,
        "netflix": 15,
        "microsoft": 20,
        "google": 20,
    }

    credential_patterns = {
        "verify your account": 35,
        "confirm your account": 35,
        "verify your identity": 40,
        "confirm your identity": 40,
        "login to continue": 35,
        "sign in to continue": 35,
        "reset your password": 35,
        "update your password": 35,
        "confirm your otp": 40,
        "verify your otp": 40,
        "update your kyc": 40,
        "complete your kyc": 40,
        "click below to verify": 35,
        "validate your account": 35,
        "secure your account": 35,
        "unlock your account": 35,
        "your account will be suspended": 45,
        "your account has been suspended": 45,
        "avoid account suspension": 40,
        "verify immediately": 30,
        "action required": 25,
    }

    attachment_extensions = {
        ".exe": 45,
        ".scr": 45,
        ".bat": 40,
        ".cmd": 40,
        ".js": 35,
        ".vbs": 40,
        ".jar": 40,
        ".ps1": 40,
        ".hta": 40,
        ".zip": 20,
        ".rar": 20,
        ".7z": 20,
        ".iso": 30,
        ".img": 30,
        ".xlsm": 35,
        ".docm": 35,
        ".pptm": 30,
    }
    header_patterns = {
        "reply-to:": 15,
        "return-path:": 15,
        "received:": 10,
        "message-id:": 10,
        "x-originating-ip": 25,
        "x-mailer": 10,
        "mime-version": 5,
        "content-type": 5,
        "authentication-results": 20,
    }

    # Brand Impersonation

    for word, score in brand_words.items():
        if word in email_text:
            threat_dna["Brand Impersonation"] += score

    # Multiple URL Detection

    urls = re.findall(r"(https?://\S+|www\.\S+)", email_text)

    if len(urls) >= 2:

        threat_dna["Multiple URLs"] = min(len(urls) * 20, 100)

    # Credential Request Pattern Detection

    for pattern, score in credential_patterns.items():

        if pattern in email_text:

            threat_dna["Credential Theft"] = min(
                threat_dna["Credential Theft"] + score, 100
            )

    # Suspicious Attachment Detection

    for extension, score in attachment_extensions.items():

        if extension in email_text:

            threat_dna["Suspicious Attachment"] = max(
                threat_dna["Suspicious Attachment"], score
            )

    # Double Extension Detection

    if re.search(r"\.[a-z0-9]{2,5}\.(exe|scr|bat|cmd|js|vbs)", email_text):

        threat_dna["Suspicious Attachment"] = 100

    # Header Intelligence

    for header, score in header_patterns.items():

        if header in email_text:

            threat_dna["Header Intelligence"] += score

    # Reply-To mismatch heuristic

    if "reply-to:" in email_text and "from:" in email_text:

        threat_dna["Header Intelligence"] += 20

    # Too many Received headers

    received_count = email_text.count("received:")

    if received_count >= 5:

        threat_dna["Header Intelligence"] += 25

    threat_dna["Header Intelligence"] = min(threat_dna["Header Intelligence"], 100)

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
            threat_dna["Credential Theft"] * 0.23
            + threat_dna["Urgency"] * 0.12
            + threat_dna["Fear Tactics"] * 0.12
            + threat_dna["Financial Fraud"] * 0.12
            + threat_dna["Social Engineering"] * 0.08
            + threat_dna["Brand Impersonation"] * 0.10
            + threat_dna["Multiple URLs"] * 0.09
            + threat_dna["Suspicious Attachment"] * 0.08
            + threat_dna["Header Intelligence"] * 0.06
        ),
        2,
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


def generate_ai_explanation(threat_dna, score):

    reasons = []

    recommendations = []

    confidence = min(100, round(score + 5))

    if threat_dna["Credential Theft"] >= 30:
        reasons.append("Credential harvesting language detected.")
        recommendations.append("Never share passwords, OTPs or banking credentials.")

    if threat_dna["Brand Impersonation"] >= 20:
        reasons.append("Trusted brand names are being impersonated.")
        recommendations.append("Verify the sender using official websites.")

    if threat_dna["Multiple URLs"] > 0:
        reasons.append("Multiple URLs found in the email.")
        recommendations.append("Avoid clicking embedded links.")

    if threat_dna["Suspicious Attachment"] > 0:
        reasons.append("Suspicious attachment detected.")
        recommendations.append("Do not open unexpected attachments.")

    if threat_dna["Header Intelligence"] > 0:
        reasons.append("Email header indicators appear suspicious.")
        recommendations.append("Verify sender authenticity before responding.")

    if threat_dna["Urgency"] >= 20:
        reasons.append("Urgency tactics are being used.")
        recommendations.append("Take time to verify before acting.")

    if threat_dna["Fear Tactics"] >= 20:
        reasons.append("Fear-based language detected.")
        recommendations.append("Do not react immediately to threatening messages.")

    if threat_dna["Financial Fraud"] >= 20:
        reasons.append("Financial fraud indicators detected.")
        recommendations.append("Verify all payment requests independently.")

    if threat_dna["Social Engineering"] >= 20:
        reasons.append("Social engineering techniques identified.")
        recommendations.append(
            "Be cautious of offers, rewards and unexpected requests."
        )

    if not reasons:
        reasons.append("No major phishing indicators detected.")

    risk_level = get_email_risk_level(score)

    ai_report = generate_ai_intelligence(
        score=score,
        risk_level=risk_level,
        findings=reasons,
        threat_dna=threat_dna,
        ml_confidence=confidence,
    )

    return {
        "confidence": confidence,
        "reasons": reasons,
        "recommendations": recommendations,
        "shared_ai": unified_ai_explanation(
            analyzer_name="Email Analyzer",
            risk_level=risk_level,
            score=confidence,
            findings=reasons,
            recommendations=recommendations,
        ),
        "ai_intelligence": ai_report,
    }


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
    ai = generate_ai_explanation(result, score)

    print(f"Confidence : {ai['confidence']}%")

    print("\nReasons:")

    for reason in ai["reasons"]:
        print(f"✔ {reason}")

    print("\nRecommendations:")

    for recommendation in ai["recommendations"]:
        print(f"• {recommendation}")
