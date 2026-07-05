"""
TrustLens AI
Central AI Intelligence Pipeline

All analyzers should call this service instead of
building AI reports independently.

Supported analyzers:
- Email
- URL
- SMS
- WhatsApp
- QR
- UPI
- Fake Job
- Future analyzers
"""

from engines.ai_intelligence_engine import generate_ai_intelligence
from engines.explanation_engine import generate_ai_explanation


def build_ai_pipeline(
    analyzer_name,
    score,
    risk_level,
    findings,
    threat_dna,
    recommendations,
    ml_confidence=0,
):
    """
    Returns one standardized AI response object.
    """

    shared_ai = generate_ai_explanation(
        analyzer_name=analyzer_name,
        risk_level=risk_level,
        score=score,
        findings=findings,
        recommendations=recommendations,
    )

    intelligence = generate_ai_intelligence(
        score=score,
        risk_level=risk_level,
        findings=findings,
        threat_dna=threat_dna,
        ml_confidence=ml_confidence,
    )

    return {
        "shared_ai": shared_ai,
        "ai_intelligence": intelligence,
    }
