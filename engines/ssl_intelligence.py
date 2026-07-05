from urllib.parse import urlparse

# =====================================================
# Future SSL Functions
# =====================================================


def certificate_expiry(domain):
    """
    Future implementation.
    """
    return None


def issuer(domain):
    """
    Future implementation.
    """
    return None


def self_signed(domain):
    """
    Future implementation.
    """
    return None


# =====================================================
# SSL Intelligence
# =====================================================


def analyze_ssl(url):

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

    scheme = parsed.scheme.lower()

    host = parsed.netloc

    # ---------------------------------
    # HTTPS
    # ---------------------------------

    if scheme == "https":

        findings.append("HTTPS encryption detected.")

        threat_dna["HTTPS"] = 0

    # ---------------------------------
    # HTTP
    # ---------------------------------

    elif scheme == "http":

        score += 30

        findings.append("Website uses unsecured HTTP.")

        threat_dna["HTTP"] = 30

        recommendations.append("Avoid submitting sensitive information over HTTP.")

    # ---------------------------------
    # Invalid Scheme
    # ---------------------------------

    else:

        score += 20

        findings.append("Unknown or unsupported URL scheme.")

        threat_dna["Invalid Scheme"] = 20

    # ---------------------------------
    # Missing Host
    # ---------------------------------

    if not host:

        score += 20

        findings.append("No valid hostname detected.")

        threat_dna["Missing Host"] = 20

    # ---------------------------------
    # Suspicious Ports
    # ---------------------------------

    if ":" in host:

        try:

            port = int(host.split(":")[-1])

            if port not in [80, 443]:

                score += 10

                findings.append(f"Non-standard port detected ({port}).")

                threat_dna["Port"] = 10

        except:

            pass

    # ---------------------------------
    # Recommendations
    # ---------------------------------

    if score >= 60:

        recommendations.append("Avoid interacting with this website.")

        recommendations.append("Verify SSL certificate before continuing.")

    elif score >= 30:

        recommendations.append("Proceed only if the website is trusted.")

    if not recommendations:

        recommendations.append("SSL configuration appears acceptable.")

    score = min(score, 100)

    return {
        "score": score,
        "findings": findings,
        "recommendations": recommendations,
        "threat_dna": threat_dna,
    }
