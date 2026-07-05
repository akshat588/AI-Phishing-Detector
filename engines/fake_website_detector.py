import re
from urllib.parse import urlparse

SUSPICIOUS_TLDS = {
    ".xyz",
    ".top",
    ".click",
    ".shop",
    ".live",
    ".online",
    ".site",
    ".icu",
    ".buzz",
    ".work",
    ".cam",
    ".gq",
    ".cf",
    ".ml",
    ".tk",
}

BRANDS = [
    "amazon",
    "google",
    "paypal",
    "microsoft",
    "apple",
    "netflix",
    "facebook",
    "instagram",
    "whatsapp",
    "telegram",
    "sbi",
    "hdfc",
    "icici",
    "axis",
    "kotak",
    "yono",
    "phonepe",
    "gpay",
    "paytm",
]

SUSPICIOUS_WORDS = [
    "login",
    "signin",
    "verify",
    "verification",
    "secure",
    "security",
    "account",
    "update",
    "banking",
    "wallet",
    "confirm",
    "password",
    "otp",
    "authenticate",
]


def _is_ip(host):
    pattern = r"^\d{1,3}(\.\d{1,3}){3}$"
    return bool(re.match(pattern, host))


import math


def calculate_entropy(text):
    """
    Calculate Shannon entropy to detect random-looking domains.
    """

    if not text:
        return 0

    probability = [text.count(c) / len(text) for c in dict.fromkeys(text)]

    return -sum(p * math.log2(p) for p in probability)


def contains_unicode_homograph(text):
    """
    Detect possible Unicode homograph attacks.
    """

    for ch in text:
        if ord(ch) > 127:
            return True

    return False


def analyze_fake_website(url):
    """
    Detect fake/phishing website characteristics.

    Returns:
    {
        score,
        findings,
        threat_dna,
        recommendations
    }
    """

    score = 0
    findings = []
    recommendations = []
    threat_dna = {}

    if not url:
        return {
            "score": 0,
            "findings": [],
            "threat_dna": {},
            "recommendations": [],
        }

    parsed = urlparse(url)

    host = parsed.netloc.lower()
    unicode_attack = contains_unicode_homograph(host)
    entropy = calculate_entropy(host)
    path = parsed.path.lower()

    # --------------------------
    # Double Extension
    # --------------------------

    dangerous_extensions = [
        ".exe",
        ".zip",
        ".rar",
        ".scr",
        ".bat",
    ]

    for ext in dangerous_extensions:

        if ext in lower_url:

            score += 15

            findings.append(f"Suspicious file extension detected ({ext}).")

            threat_dna["Dangerous Extension"] = 15

            recommendations.append(
                "Avoid downloading executable files from unknown websites."
            )

            break

    # --------------------------
    # Brand impersonation
    # --------------------------

    brand_hits = []

    for brand in BRANDS:

        if brand in host or brand in path:
            brand_hits.append(brand)

    if brand_hits:

        score += 20

        findings.append(
            f"Brand-related keywords detected: {', '.join(sorted(set(brand_hits)))}"
        )

        threat_dna["Brand Impersonation"] = 20

        recommendations.append("Verify that the website belongs to the official brand.")

    # --------------------------
    # Suspicious page keywords
    # --------------------------

    keyword_hits = []

    lower_url = url.lower()

    for word in SUSPICIOUS_WORDS:

        if word in lower_url:
            keyword_hits.append(word)

    if keyword_hits:

        pts = min(20, len(keyword_hits) * 3)

        score += pts

        findings.append(
            "Sensitive page keywords found: " + ", ".join(sorted(set(keyword_hits)))
        )

        threat_dna["Credential Harvesting"] = pts

        recommendations.append(
            "Avoid entering credentials unless you verify the domain."
        )

    # --------------------------
    # IP Address
    # --------------------------

    if _is_ip(host):

        score += 15

        findings.append("Website uses an IP address instead of a domain.")

        threat_dna["IP Hosted"] = 15

        recommendations.append("Avoid websites using raw IP addresses.")

    # --------------------------
    # Hyphen abuse
    # --------------------------

    hyphen_count = host.count("-")

    if hyphen_count >= 2:

        pts = min(10, hyphen_count * 2)

        score += pts

        findings.append("Multiple hyphens detected in domain.")

        threat_dna["Hyphen Abuse"] = pts

    # --------------------------
    # Multiple subdomains
    # --------------------------

    dots = host.count(".")

    if dots >= 3:

        score += 10

        findings.append("Large number of subdomains detected.")

        threat_dna["Subdomain Abuse"] = 10

    # --------------------------
    # Suspicious TLD
    # --------------------------

    for tld in SUSPICIOUS_TLDS:

        if host.endswith(tld):

            score += 15

            findings.append(f"Suspicious top-level domain detected ({tld}).")

            threat_dna["Suspicious TLD"] = 15

            break

    # --------------------------
    # Long URL
    # --------------------------

    if len(url) > 80:

        score += 10

        findings.append("Unusually long URL detected.")

        threat_dna["Long URL"] = 10

    # --------------------------
    # Encoded URL Detection
    # --------------------------

    encoded_patterns = [
        "%20",
        "%2F",
        "%3A",
        "%3D",
        "%40",
        "%25",
    ]

    encoded_count = sum(url.lower().count(p) for p in encoded_patterns)

    if encoded_count >= 2:

        pts = min(15, encoded_count * 3)

        score += pts

        findings.append("Encoded URL detected.")

        threat_dna["Encoded URL"] = pts

        recommendations.append(
            "Encoded URLs are commonly used to hide malicious destinations."
        )

    # --------------------------
    # Excessive Digits
    # --------------------------

    digit_count = sum(c.isdigit() for c in host)

    if digit_count >= 5:

        score += 10

        findings.append("Large number of digits detected in domain.")

        threat_dna["Numeric Domain"] = 10

        recommendations.append("Domains with many numbers are often suspicious.")

    # --------------------------
    # Suspicious Port
    # --------------------------

    if ":" in parsed.netloc:

        try:

            port = parsed.port

            if port not in [80, 443]:

                score += 10

                findings.append(f"Suspicious port detected ({port}).")

                threat_dna["Suspicious Port"] = 10

                recommendations.append(
                    "Verify why the website is using a non-standard port."
                )

        except Exception:
            pass

    # --------------------------
    # Random-looking domain
    # --------------------------

    if entropy > 3.8:

        score += 15

        findings.append("Random-looking domain detected.")

        threat_dna["Domain Randomness"] = 15

        recommendations.append(
            "Random domains are frequently used in phishing campaigns."
        )

    # --------------------------
    # Unicode Homograph Attack
    # --------------------------

    if unicode_attack:

        score += 25

        findings.append("Possible Unicode homograph attack detected.")

        threat_dna["Homograph Attack"] = 25

        recommendations.append(
            "Avoid domains containing non-ASCII characters unless verified."
        )

    # --------------------------
    # Recommendations
    # --------------------------

    if score >= 60:

        recommendations.append("Do not enter passwords, OTPs or banking details.")

        recommendations.append("Verify the website using the official domain.")

    elif score >= 30:

        recommendations.append(
            "Proceed only after verifying the legitimacy of the website."
        )

    if not findings:

        findings.append("No obvious fake website indicators detected.")

    score = min(score, 100)

    return {
        "score": score,
        "findings": findings,
        "threat_dna": threat_dna,
        "recommendations": recommendations,
    }
