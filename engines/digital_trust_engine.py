"""
TrustLens AI
Digital Trust Score Engine
"""


def calculate_digital_trust_score(
    email_score=0,
    url_score=0,
    sender_score=0,
    qr_score=0,
    upi_score=0,
):
    """
    Calculates an overall Digital Trust Score.

    Higher = More trustworthy
    Lower = More suspicious
    """

    risk_score = (
        email_score * 0.35
        + url_score * 0.25
        + sender_score * 0.15
        + qr_score * 0.10
        + upi_score * 0.15
    )

    trust_score = max(0, 100 - round(risk_score))

    if trust_score >= 85:
        level = "Trusted"

    elif trust_score >= 65:
        level = "Mostly Trusted"

    elif trust_score >= 45:
        level = "Use Caution"

    elif trust_score >= 25:
        level = "High Risk"

    else:
        level = "Do Not Trust"

    return {
        "trust_score": trust_score,
        "trust_level": level,
    }
