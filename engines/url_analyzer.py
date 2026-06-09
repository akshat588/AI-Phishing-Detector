def analyze_url(url):

    url = url.lower()

    risk_score = 0
    findings = []

    suspicious_keywords = [
        "login",
        "verify",
        "secure",
        "update",
        "bank",
        "account"
    ]

    shorteners = [
        "bit.ly",
        "tinyurl.com",
        "goo.gl"
    ]

    # URL Shortener Detection
    for shortener in shorteners:
        if shortener in url:
            risk_score += 30
            findings.append("URL shortener detected")

    # Suspicious Keywords
    for keyword in suspicious_keywords:
        if keyword in url:
            risk_score += 10
            findings.append(
                f"Suspicious keyword detected: {keyword}"
            )

    # HTTP Detection
    if url.startswith("http://"):
        risk_score += 20
        findings.append("Uses insecure HTTP")

    # IP Address Detection
    domain = (
        url.replace("http://", "")
        .replace("https://", "")
        .split("/")[0]
    )

    if domain.replace(".", "").isdigit():
        risk_score += 40
        findings.append("IP address URL detected")

    # Typosquatting Detection

    if "amaz0n" in url:
        risk_score += 40
        findings.append(
            "Possible Amazon typosquatting"
        )

    if "go0gle" in url:
        risk_score += 40
        findings.append(
            "Possible Google typosquatting"
        )

    if "paypa1" in url:
        risk_score += 40
        findings.append(
            "Possible PayPal typosquatting"
        )

    if "micr0soft" in url:
        risk_score += 40
        findings.append(
            "Possible Microsoft typosquatting"
        )

    if "faceb00k" in url:
        risk_score += 40
        findings.append(
            "Possible Facebook typosquatting"
        )

    risk_score = min(risk_score, 100)

    return risk_score, findings


def get_url_risk_level(score):

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

    url = input("Enter URL:\n\n")

    score, findings = analyze_url(url)

    risk_level = get_url_risk_level(score)

    print("\n" + "=" * 50)
    print("URL INTELLIGENCE REPORT")
    print("=" * 50)

    print(f"\nRisk Score: {score}%")
    print(f"Risk Level: {risk_level}")

    print("\nFindings:\n")

    if findings:
        for item in findings:
            print("•", item)
    else:
        print("✓ No suspicious indicators found.")