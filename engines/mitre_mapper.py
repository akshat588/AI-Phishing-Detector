"""
TrustLens AI
MITRE ATT&CK Mapping Engine

Maps detected indicators to MITRE ATT&CK tactics
and techniques.

Reference:
https://attack.mitre.org/
"""

MITRE_DATABASE = {
    "Credential Theft": {
        "tactic": "Credential Access",
        "technique": "T1056 - Input Capture",
        "description": "Attempts to steal usernames, passwords or authentication data.",
    },
    "Brand Impersonation": {
        "tactic": "Initial Access",
        "technique": "T1566 - Phishing",
        "description": "Impersonation of trusted organizations to deceive victims.",
    },
    "Social Engineering": {
        "tactic": "Initial Access",
        "technique": "T1566.002 - Spearphishing Link",
        "description": "Victim is manipulated into opening malicious links.",
    },
    "Urgency": {
        "tactic": "Initial Access",
        "technique": "T1566",
        "description": "Urgency used to influence victim decisions.",
    },
    "Fear Tactics": {
        "tactic": "Initial Access",
        "technique": "T1566",
        "description": "Fear is used to increase success of phishing.",
    },
    "Financial Fraud": {
        "tactic": "Impact",
        "technique": "T1657",
        "description": "Financial fraud or payment redirection.",
    },
    "Executable Download": {
        "tactic": "Execution",
        "technique": "T1204",
        "description": "Execution through user interaction.",
    },
    "Malware Indicators": {
        "tactic": "Execution",
        "technique": "T1204",
        "description": "Malicious payload delivery.",
    },
    "Suspicious TLD": {
        "tactic": "Resource Development",
        "technique": "T1583",
        "description": "Suspicious infrastructure registration.",
    },
    "Punycode": {
        "tactic": "Initial Access",
        "technique": "T1583",
        "description": "Look-alike domain registration.",
    },
    "IP Address": {
        "tactic": "Command and Control",
        "technique": "T1071",
        "description": "Direct IP communication.",
    },
    "Redirect": {
        "tactic": "Defense Evasion",
        "technique": "T1036",
        "description": "Redirects used to hide malicious destination.",
    },
}


def map_to_mitre(threat_dna):
    """
    Converts Threat DNA into MITRE ATT&CK techniques.

    Returns:
    {
        tactics,
        techniques,
        mappings
    }
    """

    tactics = []

    techniques = []

    mappings = []

    for indicator, score in threat_dna.items():

        if score <= 0:
            continue

        if indicator not in MITRE_DATABASE:
            continue

        data = MITRE_DATABASE[indicator]

        tactics.append(data["tactic"])

        techniques.append(data["technique"])

        mappings.append(
            {
                "indicator": indicator,
                "tactic": data["tactic"],
                "technique": data["technique"],
                "description": data["description"],
                "score": score,
            }
        )

    tactics = sorted(set(tactics))

    techniques = sorted(set(techniques))

    return {"tactics": tactics, "techniques": techniques, "mappings": mappings}
