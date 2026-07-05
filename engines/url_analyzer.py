import re
from engines.explanation_engine import generate_ai_explanation as unified_ai_explanation
from engines.fake_website_detector import analyze_fake_website
from engines.malware_link_detector import analyze_malware_link
from engines.domain_intelligence import analyze_domain
from engines.ssl_intelligence import analyze_ssl
from engines.reputation_engine import check_reputation
from services.ai_pipeline import build_ai_pipeline


def analyze_url(url):

    url = url.lower()

    risk_score = 0
    findings = []

    suspicious_keywords = ["login", "verify", "secure", "update", "bank", "account"]

    shorteners = ["bit.ly", "tinyurl.com", "goo.gl"]

    login_paths = [
        "/login",
        "/signin",
        "/sign-in",
        "/authenticate",
        "/auth",
        "/verify",
        "/account/login",
        "/user/login",
        "/session",
        "/portal/login",
        "/webscr",
        "/securelogin",
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

            findings.append(f"Suspicious keyword detected: {keyword}")

    # Login Page Detection

    for path in login_paths:

        if path in url:

            risk_score += 20

            findings.append(f"Login page detected: {path}")

            break

    # HTTP Detection

    if url.startswith("http://"):

        risk_score += 20

        findings.append("Uses insecure HTTP")

    # IP Address Detection

    domain = url.replace("http://", "").replace("https://", "").split("/")[0]

    # Number Heavy Domain Detection

    digit_count = sum(c.isdigit() for c in domain)

    if digit_count >= 4:

        risk_score += 20

        findings.append("Number-heavy domain detected")

    if domain.replace(".", "").isdigit():

        risk_score += 40

        findings.append("IP address URL detected")

    # Suspicious Query Parameter Detection

    suspicious_parameters = [
        "redirect",
        "redirect_uri",
        "return",
        "returnurl",
        "continue",
        "next",
        "url",
        "token",
        "session",
        "sessionid",
        "password",
        "passwd",
        "otp",
        "verify",
        "login",
        "auth",
        "email",
        "userid",
        "account",
    ]

    for parameter in suspicious_parameters:

        if f"{parameter}=" in url:

            risk_score += 10

            findings.append(f"Suspicious query parameter detected: {parameter}")

    # Encoded URL Detection

    if "%2f" in url or "%3a" in url or "%40" in url:

        risk_score += 15

        findings.append("Encoded URL detected")

    # '@' Symbol Abuse

    if "@" in url:

        risk_score += 25

        findings.append("Suspicious '@' symbol detected")

    # Excessive Parameters

    if url.count("=") >= 4:

        risk_score += 15

        findings.append("Multiple query parameters detected")

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

        findings.append("Long URL detected")

    if len(url) > 150:

        risk_score += 15

        findings.append("Extremely long URL detected")

    # Multiple Subdomain Detection

    domain_parts = domain.split(".")

    # Excessive Dot Detection

    if domain.count(".") >= 4:

        risk_score += 15

        findings.append("Excessive dots in domain")

    # Consecutive Hyphens

    if "--" in domain:

        risk_score += 20

        findings.append("Consecutive hyphens detected")

    # Long Domain Name

    if len(domain) >= 35:

        risk_score += 15

        findings.append("Unusually long domain name")

    # Random Domain Detection

    if re.search(r"[a-z]{6,}[0-9]{4,}", domain):

        risk_score += 25

        findings.append("Random-looking domain detected")

    # Hexadecimal Hostname

    if re.search(r"[a-f0-9]{12,}", domain):

        risk_score += 25

        findings.append("Hexadecimal-style hostname detected")

    # Mixed Letters and Digits

    if re.search(r"[a-z]+[0-9]+[a-z]+", domain):

        risk_score += 15

        findings.append("Mixed letters and digits in domain")

    # Entire URL Length

    if len(url) >= 180:

        risk_score += 20

        findings.append("Extremely long URL")

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

    # =====================================
    # Advanced Typosquatting Detection
    # =====================================

    typosquatting_patterns = {
        "amazon": ["amaz0n", "arnazon", "amazonn", "amaz0nn"],
        "google": ["go0gle", "g00gle", "goog1e", "googlle"],
        "paypal": ["paypa1", "paypaal", "pay-pal"],
        "microsoft": ["micr0soft", "micorosft", "microsoft-login"],
        "facebook": ["faceb00k", "faceboook", "facebook-login"],
        "instagram": ["instagrarn", "insta-login", "instagram-secure"],
        "netflix": ["netf1ix", "netflix-login", "netflix-secure"],
        "sbi": ["sbi-login", "sbi-verify", "sbibank-login"],
        "hdfc": ["hdfcbank-login", "hdfc-secure", "hdfc-verify"],
        "icici": ["icici-login", "icici-secure"],
        "paytm": ["paytm-login", "paytm-secure", "paytm-verify"],
    }

    for brand, variants in typosquatting_patterns.items():

        for variant in variants:

            if variant in domain:

                risk_score += 35

                findings.append(f"Possible {brand.upper()} typosquatting detected")

                break

    risk_score = min(risk_score, 100)

    # =====================================================
    # Advanced Threat Intelligence
    # =====================================================

    fake_site = analyze_fake_website(url)

    malware = analyze_malware_link(url)

    domain = analyze_domain(url)

    ssl = analyze_ssl(url)

    reputation = check_reputation(url)

    # Merge findings
    findings.extend(fake_site["findings"])
    findings.extend(malware["findings"])
    findings.extend(domain["findings"])
    findings.extend(ssl["findings"])
    findings.extend(reputation["findings"])

    # Remove duplicate findings
    findings = list(dict.fromkeys(findings))

    # Increase URL score based on intelligence modules
    risk_score = max(
        risk_score,
        fake_site["score"],
        malware["score"],
        domain["score"],
        ssl["score"],
        reputation["score"],
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


def generate_url_ai_explanation(score, findings):

    confidence = min(100, score + 5)

    recommendations = []

    for finding in findings:

        finding_lower = finding.lower()

        if "shortener" in finding_lower:
            recommendations.append("Expand shortened URLs before opening them.")

        elif "login" in finding_lower:
            recommendations.append(
                "Verify the login page through the official website."
            )

        elif "http" in finding_lower:
            recommendations.append("Avoid submitting sensitive information over HTTP.")

        elif "ip address" in finding_lower:
            recommendations.append("Avoid URLs that use raw IP addresses.")

        elif "attachment" in finding_lower:
            recommendations.append("Avoid downloading unexpected files.")

        elif "typosquatting" in finding_lower:
            recommendations.append("Check the spelling of the domain carefully.")

        elif "query parameter" in finding_lower:
            recommendations.append("Inspect URL parameters before opening.")

        elif "subdomain" in finding_lower:
            recommendations.append("Verify the real registered domain.")

        elif "random" in finding_lower:
            recommendations.append(
                "Random-looking domains are commonly used in phishing."
            )

        elif "hexadecimal" in finding_lower:
            recommendations.append(
                "Hexadecimal hostnames should be treated as suspicious."
            )

    recommendations = list(dict.fromkeys(recommendations))

    if not recommendations:

        recommendations.append("No major security recommendations.")

    return {
        "confidence": confidence,
        "reasons": findings,
        "recommendations": recommendations,
        "shared_ai": unified_ai_explanation(
            analyzer_name="URL Analyzer",
            risk_level=get_url_risk_level(score),
            score=confidence,
            findings=findings,
            recommendations=recommendations,
        ),
    }
