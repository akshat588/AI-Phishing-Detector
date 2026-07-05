import math
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


def _calculate_entropy(text):
    """
    Shannon entropy.
    Higher entropy often indicates randomly generated domains.
    """

    if not text:
        return 0

    entropy = 0

    for char in set(text):

        probability = text.count(char) / len(text)

        entropy -= probability * math.log2(probability)

    return entropy


def _is_ip(host):

    pattern = r"^\d{1,3}(\.\d{1,3}){3}$"

    return bool(re.match(pattern, host))


# ======================================================
# Future WHOIS placeholders
# ======================================================


def check_whois(domain):
    """
    Future upgrade.
    """
    return None


def check_domain_age(domain):
    """
    Future upgrade.
    """
    return None


def check_registrar(domain):
    """
    Future upgrade.
    """
    return None


# ======================================================
# Main Analysis
# ======================================================


def analyze_domain(url):

    score = 0

    findings = []

    recommendations = []

    threat_dna = {}

    if not url:

        return {
            "score": 0,
            "findings": [],
            "recommendations": [],
            "threat_dna": {},
        }

    parsed = urlparse(url)

    host = parsed.netloc.lower()

    # -----------------------------------------
    # IP Address
    # -----------------------------------------

    if _is_ip(host):

        score += 25

        findings.append("Website uses an IP address instead of a domain.")

        threat_dna["IP Address"] = 25

    # -----------------------------------------
    # Suspicious TLD
    # -----------------------------------------

    for tld in SUSPICIOUS_TLDS:

        if host.endswith(tld):

            score += 20

            findings.append(f"Suspicious TLD detected ({tld}).")

            threat_dna["Suspicious TLD"] = 20

            break

    # -----------------------------------------
    # Domain Length
    # -----------------------------------------

    if len(host) > 35:

        score += 10

        findings.append("Very long domain name.")

        threat_dna["Long Domain"] = 10

    # -----------------------------------------
    # Multiple Subdomains
    # -----------------------------------------

    dots = host.count(".")

    if dots >= 3:

        score += 10

        findings.append("Multiple nested subdomains detected.")

        threat_dna["Subdomain Abuse"] = 10

    # -----------------------------------------
    # Hyphen Abuse
    # -----------------------------------------

    hyphens = host.count("-")

    if hyphens >= 2:

        pts = min(10, hyphens * 2)

        score += pts

        findings.append("Multiple hyphens detected.")

        threat_dna["Hyphen Abuse"] = pts

    # -----------------------------------------
    # Punycode
    # -----------------------------------------

    if "xn--" in host:

        score += 20

        findings.append("Internationalized (punycode) domain detected.")

        threat_dna["Punycode"] = 20

    # -----------------------------------------
    # High Entropy
    # -----------------------------------------

    entropy = _calculate_entropy(host)

    if entropy > 3.8:

        score += 15

        findings.append("Random-looking domain detected.")

        threat_dna["High Entropy"] = 15

    # -----------------------------------------
    # Numeric Domain
    # -----------------------------------------

    digits = sum(c.isdigit() for c in host)

    if digits >= 5:

        score += 8

        findings.append("Domain contains many numeric characters.")

        threat_dna["Numeric Domain"] = 8

    # -----------------------------------------
    # Recommendations
    # -----------------------------------------

    if score >= 60:

        recommendations.append("Avoid interacting with this domain.")

        recommendations.append("Verify ownership before visiting.")

    elif score >= 30:

        recommendations.append("Inspect the domain carefully before trusting it.")

    if not findings:

        findings.append("No suspicious domain characteristics detected.")

    score = min(score, 100)

    return {
        "score": score,
        "findings": findings,
        "recommendations": recommendations,
        "threat_dna": threat_dna,
        "entropy": round(entropy, 2),
        "domain": host,
    }
