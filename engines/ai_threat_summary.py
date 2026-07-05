"""
TrustLens AI
AI Threat Summary Engine

This engine converts technical findings into
human-readable security analyst summaries.
"""


def generate_ai_threat_summary(
    score,
    risk_level,
    findings,
    threat_dna,
):
    summary = []

    # ----------------------------------
    # Executive Summary
    # ----------------------------------

    if score >= 90:

        executive = (
            "Critical threat detected. "
            "The analyzed content contains multiple high-confidence "
            "indicators of phishing, impersonation or malicious activity."
        )

    elif score >= 70:

        executive = (
            "High-risk activity detected. "
            "Several strong threat indicators were identified."
        )

    elif score >= 40:

        executive = (
            "Moderate-risk content detected. " "Further verification is recommended."
        )

    else:

        executive = (
            "No major threat indicators detected. "
            "Continue exercising standard caution."
        )

    # ----------------------------------
    # Finding Summary
    # ----------------------------------

    if findings:

        summary.append(f"{len(findings)} security indicator(s) detected.")

    else:

        summary.append("No suspicious indicators identified.")

    # ----------------------------------
    # Threat DNA Summary
    # ----------------------------------

    for key, value in threat_dna.items():

        if value >= 20:

            summary.append(f"{key} indicators contributed significantly.")

    # ----------------------------------
    # Overall Verdict
    # ----------------------------------

    if risk_level == "CRITICAL":

        verdict = "Immediate action recommended."

    elif risk_level == "HIGH":

        verdict = "User interaction should be avoided."

    elif risk_level == "MEDIUM":

        verdict = "Manual verification is recommended."

    else:

        verdict = "Minimal security concerns detected."

    return {
        "executive_summary": executive,
        "technical_summary": summary,
        "verdict": verdict,
        "risk_level": risk_level,
        "score": score,
    }
