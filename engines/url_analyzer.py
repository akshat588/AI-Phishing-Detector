def analyze_url(url):

    url = url.lower()

    risk_score = 0
    findings = []

    suspicious_keywords = ["login", "verify", "secure", "update", "bank", "account"]

    shorteners = ["bit.ly", "tinyurl.com", "goo.gl"]

    # URL Shortener Detection

    for shortener in shorteners:

        if shortener in url:

            risk_score += 30

            findings.append("URL shortener detected")

    # Suspicious Keywords

    for keyword in suspicious_keywords:

        if keyword in url:

            risk_score += 10

            findings.append(f"Suspicious keyword detected: {keyword}")

    # HTTP Detection

    if url.startswith("http://"):

        risk_score += 20

        findings.append("Uses insecure HTTP")

    # IP Address Detection

    domain = url.replace("http://", "").replace("https://", "").split("/")[0]

    if domain.replace(".", "").isdigit():

        risk_score += 40

        findings.append("IP address URL detected")

    # Suspicious TLD Detection

    suspicious_tlds = [".xyz", ".top", ".click", ".tk", ".cf", ".ml", ".gq"]

    for tld in suspicious_tlds:

        if domain.endswith(tld):

            risk_score += 25

            findings.append(f"Suspicious TLD detected: {tld}")

    # Hyphen Abuse Detection

    if domain.count("-") >= 2:

        risk_score += 15

        findings.append("Excessive hyphen usage detected")

    # Long URL Detection

    if len(url) > 75:

        risk_score += 10

        findings.append("Unusually long URL detected")

    # Multiple Subdomain Detection

    domain_parts = domain.split(".")

    if len(domain_parts) > 3:

        risk_score += 20

        findings.append("Multiple subdomains detected")

    # Brand Abuse Detection

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

        if brand in domain:

            risk_score += 15

            findings.append(f"Brand reference detected: {brand.upper()}")

    # Typosquatting Detection

    if "amaz0n" in url:
        risk_score += 40
        findings.append("Possible Amazon typosquatting")

    if "go0gle" in url:
        risk_score += 40
        findings.append("Possible Google typosquatting")

    if "paypa1" in url:
        risk_score += 40
        findings.append("Possible PayPal typosquatting")

    if "micr0soft" in url:
        risk_score += 40
        findings.append("Possible Microsoft typosquatting")

    if "faceb00k" in url:
        risk_score += 40
        findings.append("Possible Facebook typosquatting")

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
