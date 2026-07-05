from engines.explanation_engine import generate_ai_explanation as unified_ai_explanation
from services.ai_pipeline import build_ai_pipeline

"""
TrustLens AI
Fake Job Detection Engine
"""

JOB_SCAM_KEYWORDS = {
    "registration fee": 30,
    "training fee": 30,
    "security deposit": 35,
    "processing fee": 30,
    "pay before joining": 40,
    "earn ₹50000": 40,
    "earn rs 50000": 40,
    "work from home": 15,
    "no interview": 25,
    "immediate joining": 20,
    "limited seats": 15,
    "100% selection": 30,
    "whatsapp only": 20,
    "telegram": 20,
}


def analyze_job_offer(job_text):

    text = job_text.lower()

    threat_dna = {
        "Registration Fee": 0,
        "Unrealistic Salary": 0,
        "Fake Recruiter": 0,
        "Urgency": 0,
        "Company Information": 0,
        "Grammar Quality": 0,
    }

    findings = []

    # ======================================
    # Existing Keyword Detection
    # ======================================

    for keyword, weight in JOB_SCAM_KEYWORDS.items():

        if keyword in text:

            findings.append(f"⚠ Suspicious phrase detected: {keyword}")

            threat_dna["Registration Fee"] += weight

    # ======================================
    # Unrealistic Salary
    # ======================================

    salary_patterns = [
        "earn ₹50000",
        "earn rs 50000",
        "earn ₹100000",
        "earn rs 100000",
        "₹5000/day",
        "₹10000/day",
        "2 lakh",
        "3 lakh",
        "5 lakh",
    ]

    for pattern in salary_patterns:

        if pattern.lower() in text:

            threat_dna["Unrealistic Salary"] += 35

            findings.append("⚠ Unrealistic salary promise detected")

            break

    # ======================================
    # Fake Recruiter
    # ======================================

    recruiter_keywords = [
        "telegram",
        "whatsapp",
        "@gmail.com",
        "@yahoo.com",
        "@outlook.com",
    ]

    for keyword in recruiter_keywords:

        if keyword in text:

            threat_dna["Fake Recruiter"] += 25

            findings.append(f"⚠ Suspicious recruiter contact: {keyword}")

    # ======================================
    # Urgency
    # ======================================

    urgency_words = [
        "apply now",
        "join today",
        "limited seats",
        "urgent hiring",
        "immediate joining",
        "last chance",
    ]

    for word in urgency_words:

        if word in text:

            threat_dna["Urgency"] += 20

            findings.append(f"⚠ Urgency tactic detected: {word}")

    # ======================================
    # Company Information
    # ======================================

    company_red_flags = [
        "company confidential",
        "company hidden",
        "employer not disclosed",
    ]

    for item in company_red_flags:

        if item in text:

            threat_dna["Company Information"] += 30

            findings.append("⚠ Company information missing")

            break

    # ======================================
    # Grammar Quality
    # ======================================

    if text.count("!!!"):

        threat_dna["Grammar Quality"] += 15

        findings.append("⚠ Excessive exclamation marks")

    if text.isupper():

        threat_dna["Grammar Quality"] += 20

        findings.append("⚠ Entire message is uppercase")

    for key in threat_dna:

        threat_dna[key] = min(threat_dna[key], 100)

    score = round(sum(threat_dna.values()) / len(threat_dna))

    return score, threat_dna, findings


def get_job_risk_level(score):

    if score >= 90:
        return "🚨 CRITICAL"

    elif score >= 70:
        return "🔴 HIGH"

    elif score >= 40:
        return "🟠 MEDIUM"

    else:
        return "🟢 LOW"


def generate_job_ai_explanation(threat_dna, score):

    confidence = min(score + 5, 100)

    reasons = []

    recommendations = []

    if threat_dna["Registration Fee"] > 0:

        reasons.append("Registration or processing fee requested.")

        recommendations.append("Never pay money before joining a company.")

    if threat_dna["Unrealistic Salary"] > 0:

        reasons.append("Unrealistic salary promise detected.")

        recommendations.append("Compare salary with market standards.")

    if threat_dna["Fake Recruiter"] > 0:

        reasons.append("Recruiter uses unofficial contact channels.")

        recommendations.append("Verify recruiter through the official company website.")

    if threat_dna["Urgency"] > 0:

        reasons.append("Artificial urgency detected.")

        recommendations.append("Avoid making rushed decisions.")

    if threat_dna["Company Information"] > 0:

        reasons.append("Company details are hidden or missing.")

        recommendations.append("Research the company before applying.")

    if threat_dna["Grammar Quality"] > 0:

        reasons.append("Poor writing quality is suspicious.")

        recommendations.append("Review the job posting carefully.")

    if not reasons:

        reasons.append("No significant fake job indicators detected.")

        recommendations.append("Continue verifying the employer before applying.")

    return {
        "confidence": confidence,
        "reasons": reasons,
        "recommendations": recommendations,
        "shared_ai": unified_ai_explanation(
            analyzer_name="Fake Job Detector",
            risk_level=get_job_risk_level(score),
            score=confidence,
            findings=reasons,
            recommendations=recommendations,
        ),
    }
