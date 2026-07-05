import re
from engines.explanation_engine import generate_ai_explanation as unified_ai_explanation
from services.ai_pipeline import build_ai_pipeline


def analyze_upi(content):

    text = content.lower()

    threat_dna = {
        "Invalid UPI ID": 0,
        "Collect Request": 0,
        "Refund Scam": 0,
        "Cashback Scam": 0,
        "Fake Merchant": 0,
        "Payment Request": 0,
    }

    findings = []

    # =====================================
    # UPI ID Detection
    # =====================================

    upi_pattern = r"[a-zA-Z0-9.\-_]{2,}@[a-zA-Z]{2,}"

    upi_ids = re.findall(upi_pattern, text)

    if upi_ids:

        findings.append("UPI ID detected.")

    # =====================================
    # Invalid UPI IDs
    # =====================================

    for upi in upi_ids:

        if len(upi.split("@")[0]) < 3:

            threat_dna["Invalid UPI ID"] += 30

            findings.append(f"Suspicious UPI ID: {upi}")

    # =====================================
    # Collect Request
    # =====================================

    collect_words = [
        "collect request",
        "approve payment",
        "request money",
        "accept collect",
    ]

    for word in collect_words:

        if word in text:

            threat_dna["Collect Request"] += 35

            findings.append("Collect request detected.")

    # =====================================
    # Refund Scam
    # =====================================

    refund_words = ["refund", "refund amount", "claim refund", "refund pending"]

    for word in refund_words:

        if word in text:

            threat_dna["Refund Scam"] += 25

            findings.append("Refund scam indicator detected.")

    # =====================================
    # Cashback Scam
    # =====================================

    cashback_words = ["cashback", "reward", "gift", "bonus"]

    for word in cashback_words:

        if word in text:

            threat_dna["Cashback Scam"] += 20

            findings.append("Cashback scam indicator detected.")

    # =====================================
    # Fake Merchant
    # =====================================

    fake_words = [
        "customer care",
        "support executive",
        "verification payment",
        "pay to verify",
    ]

    for word in fake_words:

        if word in text:

            threat_dna["Fake Merchant"] += 30

            findings.append("Suspicious merchant behaviour detected.")

    # =====================================
    # Payment Request
    # =====================================

    payment_words = ["pay now", "send money", "complete payment", "payment pending"]

    for word in payment_words:

        if word in text:

            threat_dna["Payment Request"] += 20

            findings.append("Payment request detected.")

    for key in threat_dna:

        threat_dna[key] = min(threat_dna[key], 100)

    score = round(sum(threat_dna.values()) / len(threat_dna))

    return score, threat_dna, findings


def get_upi_risk_level(score):

    if score >= 90:

        return "🚨 CRITICAL"

    elif score >= 70:

        return "🔴 HIGH"

    elif score >= 40:

        return "🟠 MEDIUM"

    else:

        return "🟢 LOW"


def generate_upi_ai_explanation(threat_dna, score):

    confidence = min(score + 5, 100)

    reasons = []

    recommendations = []

    if threat_dna["Invalid UPI ID"] > 0:

        reasons.append("Suspicious UPI ID detected.")

        recommendations.append("Verify the UPI ID before making payments.")

    if threat_dna["Collect Request"] > 0:

        reasons.append("Collect request scam detected.")

        recommendations.append("Never approve collect requests from unknown users.")

    if threat_dna["Refund Scam"] > 0:

        reasons.append("Refund scam indicators detected.")

        recommendations.append("Refunds never require you to send money first.")

    if threat_dna["Cashback Scam"] > 0:

        reasons.append("Cashback scam detected.")

        recommendations.append("Verify cashback offers through official apps.")

    if threat_dna["Fake Merchant"] > 0:

        reasons.append("Suspicious merchant detected.")

        recommendations.append("Confirm merchant identity before payment.")

    if threat_dna["Payment Request"] > 0:

        reasons.append("Unexpected payment request detected.")

        recommendations.append("Do not send money without verification.")

    if not reasons:

        reasons.append("No significant UPI fraud indicators detected.")

        recommendations.append("Continue using trusted UPI applications.")

    return {
        "confidence": confidence,
        "reasons": reasons,
        "recommendations": recommendations,
        "shared_ai": unified_ai_explanation(
            analyzer_name="UPI Analyzer",
            risk_level=get_upi_risk_level(score),
            score=confidence,
            findings=reasons,
            recommendations=recommendations,
        ),
    }
