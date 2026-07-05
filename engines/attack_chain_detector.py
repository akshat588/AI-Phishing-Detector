"""
TrustLens AI
Attack Chain Detection Engine

Maps detected indicators into a probable attacker workflow.
This is inspired by real-world phishing and social engineering attacks.
"""


def detect_attack_chain(threat_dna):

    attack_chain = []

    attack_stage = "Unknown"

    confidence = 0

    # ------------------------------------
    # Initial Access
    # ------------------------------------

    if (
        threat_dna.get("Brand Impersonation", 0) > 0
        or threat_dna.get("Credential Theft", 0) > 0
    ):

        attack_chain.append(
            {
                "stage": "Initial Access",
                "description": "Victim is lured using impersonation or credential harvesting.",
            }
        )

        confidence += 20

    # ------------------------------------
    # Social Engineering
    # ------------------------------------

    if (
        threat_dna.get("Urgency", 0) > 0
        or threat_dna.get("Fear Tactics", 0) > 0
        or threat_dna.get("Social Engineering", 0) > 0
    ):

        attack_chain.append(
            {
                "stage": "Manipulation",
                "description": "Psychological pressure is used to influence the victim.",
            }
        )

        confidence += 20

    # ------------------------------------
    # Credential Collection
    # ------------------------------------

    if threat_dna.get("Credential Theft", 0) >= 20:

        attack_chain.append(
            {
                "stage": "Credential Collection",
                "description": "Attack attempts to obtain usernames, passwords or OTPs.",
            }
        )

        confidence += 25

    # ------------------------------------
    # Financial Fraud
    # ------------------------------------

    if threat_dna.get("Financial Fraud", 0) >= 20:

        attack_chain.append(
            {
                "stage": "Financial Exploitation",
                "description": "Victim may be redirected to unauthorized financial transactions.",
            }
        )

        confidence += 20

    # ------------------------------------
    # Malware Delivery
    # ------------------------------------

    if (
        threat_dna.get("Executable Download", 0) > 0
        or threat_dna.get("Malware Indicators", 0) > 0
    ):

        attack_chain.append(
            {
                "stage": "Malware Delivery",
                "description": "The attacker attempts to deliver malicious software.",
            }
        )

        confidence += 15

    # ------------------------------------
    # Determine Overall Attack Stage
    # ------------------------------------

    if confidence >= 80:

        attack_stage = "Complete Attack Chain"

    elif confidence >= 60:

        attack_stage = "Highly Probable"

    elif confidence >= 40:

        attack_stage = "Partial Attack Chain"

    elif confidence >= 20:

        attack_stage = "Early Attack Indicators"

    else:

        attack_stage = "No Attack Chain Detected"

    confidence = min(confidence, 100)

    return {
        "stage": attack_stage,
        "confidence": confidence,
        "chain": attack_chain,
    }
