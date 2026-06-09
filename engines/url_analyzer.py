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

    known_brands = [
        "amazon",
        "google",
        "paypal",
        "microsoft",
        "facebook"
    ]

    # ==========================
    # URL Shortener Detection
    # ==========================

    for shortener in shorteners:
        if shortener in url:
            risk_score += 30
            findings.append("URL shortener detected")

    # ==========================
    # Suspicious Keywords
    # ==========================

    for keyword in suspicious_keywords:
        if keyword in url:
            risk_score += 10
            findings.append(f"Suspicious keyword detected: {keyword}")

    # ==========================
    # HTTP Detection
    # ==========================

    if url.startswith("http://"):
        risk_score += 20
        findings.append("Uses insecure HTTP")

    # ==========================
    # IP Address Detection
    # ==========================

    domain = (
        url.replace("http://", "")
        .replace("https://", "")
        .split("/")[0]
    )

    if domain.replace(".", "").isdigit():
        risk_score += 40
        findings.append("IP address URL detected")

    # ==========================
    # Typosquatting Detection
    # ==========================

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

    # ==========================
    # Final Risk Score
    # ==========================

    risk_score = min(risk_score, 100)

    # ==========================
    # Risk Level
    # ==========================

    if risk_score >= 90:
        risk_level = "🚨 CRITICAL"

    elif risk_score >= 70:
        risk_level = "🔴 HIGH"

    elif risk_score >= 40:
        risk_level = "🟠 MEDIUM"

    else:
        risk_level = "🟢 LOW"

    return risk_score, risk_level, findings


# ==========================
# User Input
# ==========================

url = input("Enter URL:\n\n")

score, risk_level, findings = analyze_url(url)

# ==========================
# URL Intelligence Report
# ==========================

print("\n")
print("=" * 50)
print("         URL INTELLIGENCE REPORT")
print("=" * 50)

print(f"\nRisk Score: {score}%")
print(f"Risk Level: {risk_level}")

print("\nFindings:\n")

if findings:
    for item in findings:
        print("•", item)
else:
    print("✓ No suspicious indicators found.")

# ==========================
# Recommendation
# ==========================

print("\nRecommendation:\n")

if score >= 90:

    print("🚨 Do NOT visit this URL.")
    print("🚨 Possible phishing attack.")
    print("🚨 Block immediately.")

elif score >= 70:

    print("⚠ High-risk URL.")
    print("⚠ Verify destination before visiting.")

elif score >= 40:

    print("⚠ Suspicious URL.")
    print("⚠ Exercise caution.")

else:

    print("✓ Low risk URL.")