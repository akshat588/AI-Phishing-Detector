import re
from engines.explanation_engine import generate_ai_explanation as unified_ai_explanation
from services.ai_pipeline import build_ai_pipeline


def analyze_whatsapp(text):

    text = text.lower()

    threat_dna = {
        "Fake Job Scam": 0,
        "Telegram Scam": 0,
        "Investment Scam": 0,
        "APK Download Scam": 0,
        "Lottery Scam": 0,
        "Crypto Scam": 0,
        "Impersonation": 0,
    }

    patterns = {
        "Fake Job Scam": {
            "work from home": 35,
            "part time": 30,
            "earn daily": 30,
            "salary": 20,
            "hr recruiter": 35,
            "interview": 15,
            "vacancy": 20,
            "job offer": 30,
            "registration fee": 40,
        },
        "Telegram Scam": {
            "telegram": 35,
            "join telegram": 40,
            "telegram group": 35,
            "contact on telegram": 40,
        },
        "Investment Scam": {
            "investment": 30,
            "profit": 25,
            "guaranteed return": 40,
            "double your money": 40,
            "high returns": 35,
            "trading": 20,
        },
        "APK Download Scam": {
            ".apk": 45,
            "download apk": 45,
            "install app": 35,
            "unknown app": 40,
            "update app": 20,
        },
        "Lottery Scam": {
            "winner": 30,
            "lottery": 35,
            "reward": 25,
            "gift": 20,
            "prize": 30,
            "congratulations": 20,
        },
        "Crypto Scam": {
            "bitcoin": 25,
            "crypto": 30,
            "usdt": 30,
            "binance": 20,
            "wallet": 20,
        },
        "Impersonation": {
            "bank manager": 30,
            "customer care": 25,
            "technical support": 25,
            "government": 25,
            "police": 30,
            "income tax": 30,
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


def get_whatsapp_risk_level(score):

    if score >= 90:
        return "🚨 CRITICAL"

    elif score >= 70:
        return "🔴 HIGH"

    elif score >= 40:
        return "🟠 MEDIUM"

    else:
        return "🟢 LOW"


def generate_whatsapp_ai_explanation(threat_dna, score):

    confidence = min(score + 5, 100)

    reasons = []

    recommendations = []

    if threat_dna["Fake Job Scam"] > 0:

        reasons.append("Fake job recruitment indicators detected.")

        recommendations.append(
            "Verify job offers on the company's official careers page."
        )

    if threat_dna["Telegram Scam"] > 0:

        reasons.append("Conversation is attempting to move to Telegram.")

        recommendations.append(
            "Avoid continuing recruitment or financial discussions on Telegram."
        )

    if threat_dna["Investment Scam"] > 0:

        reasons.append("Investment fraud indicators detected.")

        recommendations.append(
            "Be cautious of guaranteed profit or quick-return schemes."
        )

    if threat_dna["APK Download Scam"] > 0:

        reasons.append("APK download request detected.")

        recommendations.append("Install apps only from trusted app stores.")

    if threat_dna["Lottery Scam"] > 0:

        reasons.append("Lottery or prize scam detected.")

        recommendations.append("Ignore messages claiming unexpected prizes.")

    if threat_dna["Crypto Scam"] > 0:

        reasons.append("Cryptocurrency scam indicators detected.")

        recommendations.append(
            "Verify crypto investment opportunities through trusted sources."
        )

    if threat_dna["Impersonation"] > 0:

        reasons.append("Authority impersonation detected.")

        recommendations.append("Verify the sender independently before taking action.")

    if not reasons:

        reasons.append("No significant WhatsApp scam indicators detected.")

        recommendations.append("Stay cautious when interacting with unknown contacts.")

    return {
        "confidence": confidence,
        "reasons": reasons,
        "recommendations": recommendations,
        "shared_ai": unified_ai_explanation(
            analyzer_name="WhatsApp Analyzer",
            risk_level=get_whatsapp_risk_level(score),
            score=confidence,
            findings=reasons,
            recommendations=recommendations,
        ),
    }
