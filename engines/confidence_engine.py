"""
TrustLens AI
Unified AI Confidence Engine

Calculates a single confidence score by combining:
- ML confidence
- Rule-based confidence
- Threat Intelligence
- Attack Chain confidence
"""


def calculate_confidence(
    ml_confidence=0,
    threat_score=0,
    attack_chain_confidence=0,
    findings_count=0,
):
    components = {}

    # ------------------------------------
    # ML Component
    # ------------------------------------

    ml_component = min(max(ml_confidence, 0), 100)

    components["Machine Learning"] = ml_component

    # ------------------------------------
    # Rule-Based Component
    # ------------------------------------

    rule_component = min(threat_score, 100)

    components["Rule Engine"] = rule_component

    # ------------------------------------
    # Attack Chain Component
    # ------------------------------------

    attack_component = min(
        attack_chain_confidence,
        100,
    )

    components["Attack Chain"] = attack_component

    # ------------------------------------
    # Evidence Component
    # ------------------------------------

    evidence_component = min(
        findings_count * 8,
        100,
    )

    components["Evidence"] = evidence_component

    # ------------------------------------
    # Final Confidence
    # ------------------------------------

    confidence = (
        ml_component * 0.35
        + rule_component * 0.35
        + attack_component * 0.20
        + evidence_component * 0.10
    )

    confidence = round(min(confidence, 100), 2)

    # ------------------------------------
    # Confidence Level
    # ------------------------------------

    if confidence >= 90:

        level = "VERY HIGH"

    elif confidence >= 75:

        level = "HIGH"

    elif confidence >= 50:

        level = "MEDIUM"

    elif confidence >= 25:

        level = "LOW"

    else:

        level = "VERY LOW"

    return {
        "confidence": confidence,
        "level": level,
        "components": components,
    }
