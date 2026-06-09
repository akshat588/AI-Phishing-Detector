def analyze_sender(sender):

    sender = sender.lower()

    risk_score = 0
    findings = []

    free_email_domains = [
        "gmail.com",
        "yahoo.com",
        "outlook.com",
        "hotmail.com"
    ]

    suspicious_keywords = [
        "security",
        "verify",
        "update",
        "support",
        "login"
    ]

    # Extract Domain

    if "@" in sender:
        domain = sender.split("@")[1]
    else:
        domain = sender

    # Free Email Abuse

    for free_domain in free_email_domains:
        if domain == free_domain:
            risk_score += 30
            findings.append("Free email provider used")

    # Brand Impersonation

    if "amaz0n" in domain:
        risk_score += 40
        findings.append("Possible Amazon impersonation")

    if "paypa1" in domain:
        risk_score += 40
        findings.append("Possible PayPal impersonation")

    if "go0gle" in domain:
        risk_score += 40
        findings.append("Possible Google impersonation")

    # Suspicious Keywords

    for keyword in suspicious_keywords:
        if keyword in domain:
            risk_score += 10
            findings.append(
                f"Suspicious keyword: {keyword}"
            )

    risk_score = min(risk_score, 100)

    return risk_score, findings


def get_sender_risk_level(score):

    if score >= 90:
        return "🚨 CRITICAL"

    elif score >= 70:
        return "🔴 HIGH"

    elif score >= 40:
        return "🟠 MEDIUM"

    else:
        return "🟢 LOW"


# ==========================
# TEST MODE
# ==========================

if __name__ == "__main__":

    sender = input("Enter sender email:\n\n")

    score, findings = analyze_sender(sender)

    risk_level = get_sender_risk_level(score)

    print("\n" + "=" * 50)
    print("SENDER INTELLIGENCE REPORT")
    print("=" * 50)

    print(f"\nRisk Score: {score}%")
    print(f"Risk Level: {risk_level}")

    print("\nFindings:\n")

    if findings:
        for item in findings:
            print("•", item)
    else:
        print("✓ No suspicious indicators found.")