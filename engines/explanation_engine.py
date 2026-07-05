"""
Unified Explainable AI Engine

Every analyzer should use this file instead of generating
its own explanation independently.

Standard API:

generate_ai_explanation(
    analyzer_name,
    risk_level,
    score,
    findings,
    recommendations=None
)

Returns:
{
    "title": "...",
    "summary": "...",
    "risk_level": "...",
    "score": ...,
    "threat_dna": [...],
    "recommendations": [...]
}
"""

DEFAULT_RECOMMENDATIONS = {
    "LOW": ["No immediate action required.", "Continue monitoring."],
    "MEDIUM": ["Verify the detected content.", "Avoid sharing sensitive information."],
    "HIGH": [
        "Do not interact with the detected content.",
        "Report the incident if applicable.",
        "Verify through official channels.",
    ],
    "CRITICAL": [
        "Stop immediately.",
        "Do not click or respond.",
        "Report to your security team.",
        "Block the source if possible.",
    ],
}


def generate_ai_explanation(
    analyzer_name, risk_level, score, findings, recommendations=None
):
    if recommendations is None:
        recommendations = DEFAULT_RECOMMENDATIONS.get(risk_level.upper(), [])

    summary = (
        f"The {analyzer_name} detected "
        f"{len(findings)} significant indicator(s). "
        f"Overall risk has been classified as "
        f"{risk_level.upper()} with a confidence score of {score}%."
    )

    return {
        "title": f"{analyzer_name} Security Assessment",
        "summary": summary,
        "risk_level": risk_level.upper(),
        "score": score,
        "threat_dna": findings,
        "recommendations": recommendations,
    }
