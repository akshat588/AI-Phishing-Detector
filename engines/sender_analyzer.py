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

    # Extract domain

    if "@" in sender:
        domain = sender.split("@")[1]
    else:
        domain = sender

    # Free Email Abuse

    for free_domain in free_email_domains:
        if free_domain == domain:
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
            findings.append(f"Suspicious keyword: {keyword}")

    risk_score = min(risk_score, 100)

    if risk_score >= 90:
        risk_level = "🚨 CRITICAL"
    elif risk_score >= 70:
        risk_level = "🔴 HIGH"
    elif risk_score >= 40:
        risk_level = "🟠 MEDIUM"
    else:
        risk_level = "🟢 LOW"

    return risk_score, risk_level, findings


sender = input("Enter sender email:\n\n")

score, risk_level, findings = analyze_sender(sender)

print("\n" + "=" * 50)
print("       SENDER INTELLIGENCE REPORT")
print("=" * 50)

print(f"\nRisk Score: {score}%")
print(f"Risk Level: {risk_level}")

print("\nFindings:\n")

if findings:
    for item in findings:
        print("•", item)
else:
    print("✓ No suspicious indicators found.")