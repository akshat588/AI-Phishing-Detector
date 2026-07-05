import re
from engines.explanation_engine import generate_ai_explanation as unified_ai_explanation
from services.ai_pipeline import build_ai_pipeline


def analyze_sms(text):

    text = text.lower()

    threat_dna = {
        "OTP Scam": 0,
        "Banking Scam": 0,
        "Courier Scam": 0,
        "Electricity Scam": 0,
        "Refund Scam": 0,
        "Reward Scam": 0,
        "Government Impersonation": 0,
    }

    patterns = {
        "OTP Scam": {
            "otp": 30,
            "one time password": 30,
            "verification code": 25,
            "verify otp": 35,
            "security code": 20,
        },
        "Banking Scam": {
            "bank account": 30,
            "account blocked": 35,
            "debit card": 25,
            "credit card": 25,
            "kyc": 35,
            "net banking": 25,
            "upi pin": 35,
            "bank": 15,
        },
        "Courier Scam": {
            "parcel": 30,
            "courier": 30,
            "shipment": 25,
            "delivery": 20,
            "tracking": 20,
        },
        "Electricity Scam": {
            "electricity": 35,
            "power supply": 30,
            "bill overdue": 35,
            "disconnect": 30,
            "electric bill": 30,
        },
        "Refund Scam": {
            "refund": 30,
            "cashback": 25,
            "return money": 30,
            "reverse payment": 35,
        },
        "Reward Scam": {
            "reward": 30,
            "winner": 30,
            "lottery": 35,
            "gift": 25,
            "congratulations": 20,
            "prize": 30,
        },
        "Government Impersonation": {
            "aadhaar": 30,
            "digilocker": 30,
            "income tax": 30,
            "epfo": 30,
            "npci": 25,
        },
    }

    findings = []

    for category, keywords in patterns.items():

        for keyword, score in keywords.items():

            if keyword in text:

                threat_dna[category] += score

        threat_dna[category] = min(threat_dna[category], 100)

        if threat_dna[category] > 0:

            findings.append(category)

    score = round(sum(threat_dna.values()) / len(threat_dna))

    score = min(score, 100)

    return score, threat_dna, findings


def get_sms_risk_level(score):

    if score >= 90:
        return "🚨 CRITICAL"

    elif score >= 70:
        return "🔴 HIGH"

    elif score >= 40:
        return "🟠 MEDIUM"

    else:
        return "🟢 LOW"


def generate_sms_ai_explanation(threat_dna, score):

    confidence = min(score + 5, 100)

    reasons = []

    recommendations = []

    if threat_dna["OTP Scam"] > 0:

        reasons.append("OTP-related scam indicators detected.")

        recommendations.append("Never share OTPs with anyone.")

    if threat_dna["Banking Scam"] > 0:

        reasons.append("Bank impersonation indicators detected.")

        recommendations.append("Contact your bank through official channels only.")

    if threat_dna["Courier Scam"] > 0:

        reasons.append("Suspicious courier or parcel message detected.")

        recommendations.append(
            "Verify parcel information using the official courier website."
        )

    if threat_dna["Electricity Scam"] > 0:

        reasons.append("Electricity bill fraud indicators detected.")

        recommendations.append(
            "Pay bills only through official electricity provider portals."
        )

    if threat_dna["Refund Scam"] > 0:

        reasons.append("Refund or cashback scam indicators detected.")

        recommendations.append("Do not click refund links received in SMS messages.")

    if threat_dna["Reward Scam"] > 0:

        reasons.append("Lottery or reward scam detected.")

        recommendations.append(
            "Ignore messages promising prizes or unexpected rewards."
        )

    if threat_dna["Government Impersonation"] > 0:

        reasons.append("Government authority impersonation detected.")

        recommendations.append(
            "Verify government communications through official websites."
        )

    if not reasons:

        reasons.append("No significant SMS scam indicators detected.")

        recommendations.append("Remain cautious with unknown SMS messages.")

    return {
        "confidence": confidence,
        "reasons": reasons,
        "recommendations": recommendations,
        "shared_ai": unified_ai_explanation(
            analyzer_name="SMS Analyzer",
            risk_level=get_sms_risk_level(score),
            score=confidence,
            findings=reasons,
            recommendations=recommendations,
        ),
    }
