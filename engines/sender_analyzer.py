def analyze_sender(sender):

    sender = sender.lower().strip()

    risk_score = 0
    findings = []

    if "@" in sender:
        domain = sender.split("@")[1]
    else:
        domain = sender

    # Free Email Providers

    free_email_domains = ["gmail.com", "yahoo.com", "outlook.com", "hotmail.com"]

    if domain in free_email_domains:
        risk_score += 20
        findings.append("Free email provider used")

    # Disposable Email Providers

    disposable_domains = [
        "mailinator.com",
        "10minutemail.com",
        "guerrillamail.com",
        "tempmail.com",
        "yopmail.com",
    ]

    if domain in disposable_domains:
        risk_score += 35
        findings.append("Disposable email provider detected")

    sender_text = sender.replace("@", "-")

    # Brand Detection

    brands = [
        "amazon",
        "google",
        "paypal",
        "microsoft",
        "facebook",
        "instagram",
        "netflix",
        "sbi",
        "hdfc",
        "icici",
        "paytm",
    ]

    for brand in brands:

        if brand in sender_text:

            risk_score += 15

            findings.append(f"Brand reference detected: {brand.upper()}")

    # Typosquatting Detection

    typo_patterns = {"amaz0n": "Amazon", "go0gle": "Google", "paypa1": "PayPal"}

    for typo, brand in typo_patterns.items():

        if typo in sender_text:

            risk_score += 40

            findings.append(f"Possible {brand} typosquatting")

    # Suspicious Keywords

    suspicious_keywords = [
        "security",
        "verify",
        "login",
        "update",
        "support",
        "alert",
        "reset",
        "unlock",
    ]

    for keyword in suspicious_keywords:

        if keyword in sender_text:

            risk_score += 10

            findings.append(f"Suspicious keyword detected: {keyword}")

    # Suspicious TLD Detection

    suspicious_tlds = [".xyz", ".top", ".click", ".tk", ".cf", ".ml", ".gq"]

    for tld in suspicious_tlds:

        if domain.endswith(tld):

            risk_score += 25

            findings.append(f"Suspicious TLD detected: {tld}")

    return min(risk_score, 100), findings


def get_sender_risk_level(score):

    if score >= 90:
        return "🚨 CRITICAL"

    elif score >= 70:
        return "🔴 HIGH"

    elif score >= 40:
        return "🟠 MEDIUM"

    else:
        return "🟢 LOW"
