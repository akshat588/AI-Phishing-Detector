"""
TrustLens AI
Unified AI Intelligence Engine

This engine combines:
- AI Threat Summary
- Attack Chain Detection
- Confidence Engine
- MITRE ATT&CK Mapping

Every analyzer (Email, URL, SMS, WhatsApp, QR, UPI, Fake Job)
should use this engine.
"""

from engines.ai_threat_summary import generate_ai_threat_summary
from engines.attack_chain_detector import detect_attack_chain
from engines.confidence_engine import calculate_confidence
from engines.mitre_mapper import map_to_mitre


def generate_ai_intelligence(
    score,
    risk_level,
    findings,
    threat_dna,
    ml_confidence=0,
):
    """
    Generate complete AI Intelligence Report.
    """

    # -----------------------------------------
    # Threat Summary
    # -----------------------------------------

    summary = generate_ai_threat_summary(
        score=score,
        risk_level=risk_level,
        findings=findings,
        threat_dna=threat_dna,
    )

    # -----------------------------------------
    # Attack Chain
    # -----------------------------------------

    attack_chain = detect_attack_chain(threat_dna)

    # -----------------------------------------
    # MITRE Mapping
    # -----------------------------------------

    mitre = map_to_mitre(threat_dna)

    # -----------------------------------------
    # Confidence
    # -----------------------------------------

    confidence = calculate_confidence(
        ml_confidence=ml_confidence,
        threat_score=score,
        attack_chain_confidence=attack_chain["confidence"],
        findings_count=len(findings),
    )

    # -----------------------------------------
    # Overall Verdict
    # -----------------------------------------

    if score >= 90:

        verdict = "CRITICAL THREAT"

    elif score >= 70:

        verdict = "HIGH RISK"

    elif score >= 40:

        verdict = "MEDIUM RISK"

    else:

        verdict = "LOW RISK"

    return {
        "summary": summary,
        "attack_chain": attack_chain,
        "confidence": confidence,
        "mitre": mitre,
        "verdict": verdict,
    }
