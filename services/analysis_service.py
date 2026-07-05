import re
from engines.sms_analyzer import (
    analyze_sms,
    get_sms_risk_level,
    generate_sms_ai_explanation,
)
from engines.whatsapp_analyzer import (
    analyze_whatsapp,
    get_whatsapp_risk_level,
    generate_whatsapp_ai_explanation,
)

from engines.email_analyzer import analyze_email, get_email_score
from engines.url_analyzer import analyze_url
from engines.sender_analyzer import analyze_sender
from engines.upi_analyzer import analyze_upi
from engines.digital_trust_engine import calculate_digital_trust_score


def analyze_content(
    content="",
    sender="",
    source="email",
):
    """
    Shared TrustLens AI analysis pipeline.

    This function can be reused by:
    - Email Analyzer
    - SMS Analyzer
    - WhatsApp Analyzer
    - Fake Job Detector
    - Fake Website Detector
    """

    # -------------------------
    # Email Analysis
    # -------------------------

    threat_dna = analyze_email(content)

    email_score = get_email_score(threat_dna)

    # -------------------------
    # Source Specific Analysis
    # -------------------------

    source_score = 0
    source_dna = {}
    source_findings = []

    if source == "sms":

        source_score, source_dna, source_findings = analyze_sms(content)
        source_ai = generate_sms_ai_explanation(
            source_dna,
            source_score,
        )

        source_risk = get_sms_risk_level(
            source_score,
        )

    elif source == "whatsapp":

        source_score, source_dna, source_findings = analyze_whatsapp(content)

        source_ai = generate_whatsapp_ai_explanation(
            source_dna,
            source_score,
        )

        source_risk = get_whatsapp_risk_level(
            source_score,
        )

    # -------------------------
    # Merge Threat DNA
    # -------------------------

    combined_threat_dna = dict(threat_dna)

    combined_threat_dna.update(source_dna)

    # -------------------------
    # URL Detection
    # -------------------------

    found = re.findall(r'https?://[^\s<>"]+', content)

    url = found[0] if found else ""

    url_score, url_findings = analyze_url(url)

    # -------------------------
    # Sender Analysis
    # -------------------------

    if sender:

        sender_score, sender_findings = analyze_sender(sender)

    else:

        sender_score = 0
        sender_findings = []

    # -------------------------
    # UPI Analysis
    # -------------------------

    upi_score, upi_threat_dna, upi_findings = analyze_upi(content)

    # -------------------------
    # Digital Trust
    # -------------------------

    trust = calculate_digital_trust_score(
        email_score=max(email_score, source_score),
        url_score=url_score,
        sender_score=sender_score,
        upi_score=upi_score,
    )

    return {
        "threat_dna": combined_threat_dna,
        "email_score": email_score,
        "url_score": url_score,
        "sender_score": sender_score,
        "sender_findings": sender_findings,
        "url_findings": url_findings,
        "upi_score": upi_score,
        "upi_findings": upi_findings,
        "digital_trust_score": trust["trust_score"],
        "digital_trust_level": trust["trust_level"],
        "source_findings": source_findings,
        "source_ai": source_ai,
        "source_risk": source_risk,
        "shared_ai": source_ai.get("shared_ai", {}),
    }
