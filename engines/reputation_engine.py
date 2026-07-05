from urllib.parse import urlparse

# ==========================================================
# Local Threat Intelligence Database
# (Offline Demo Dataset)
# ==========================================================

LOCAL_BAD_DOMAINS = {
    "phishing-test.com",
    "fake-paypal-login.com",
    "secure-amazon-login.xyz",
    "verify-account-now.top",
    "bank-update.click",
    "paypal-security.xyz",
    "amazon-verification.top",
    "google-security-login.xyz",
    "microsoft-support.click",
    "icloud-security.xyz",
    "apple-id-login.top",
    "netflix-verify.xyz",
    "facebook-security.click",
    "instagram-security.xyz",
    "whatsapp-update.top",
    "telegram-security.xyz",
    "upi-payment-security.xyz",
    "secure-sbi-login.xyz",
    "secure-hdfc-login.xyz",
    "secure-icici-login.xyz",
    "axis-bank-update.xyz",
    "fakebanking.top",
    "otp-verification.click",
    "freegift.xyz",
    "lottery-winner.top",
    "reward-center.xyz",
    "wallet-verification.click",
    "crypto-airdrop.xyz",
    "investment-profit.top",
    "claim-prize.click",
}

SUSPICIOUS_KEYWORDS = [
    "login",
    "verify",
    "secure",
    "bank",
    "account",
    "update",
    "otp",
    "reward",
    "gift",
    "wallet",
    "crypto",
    "payment",
]


def check_reputation(url):

    score = 0

    findings = []

    recommendations = []

    parsed = urlparse(url)

    domain = parsed.netloc.lower()

    full_url = url.lower()

    reputation = "SAFE"

    # ---------------------------------------
    # Known malicious domains
    # ---------------------------------------

    if domain in LOCAL_BAD_DOMAINS:

        score = 100

        reputation = "MALICIOUS"

        findings.append("Domain exists in the local threat intelligence database.")

        recommendations.append("Block this domain immediately.")

    # ---------------------------------------
    # Suspicious keywords
    # ---------------------------------------

    else:

        hits = []

        for keyword in SUSPICIOUS_KEYWORDS:

            if keyword in full_url:

                hits.append(keyword)

        if hits:

            score += min(40, len(hits) * 8)

            findings.append(
                "Suspicious reputation keywords detected: "
                + ", ".join(sorted(set(hits)))
            )

    # ---------------------------------------
    # Reputation Level
    # ---------------------------------------

    if reputation != "MALICIOUS":

        if score >= 60:

            reputation = "MALICIOUS"

        elif score >= 30:

            reputation = "SUSPICIOUS"

        else:

            reputation = "SAFE"

    # ---------------------------------------
    # Recommendations
    # ---------------------------------------

    if reputation == "SAFE":

        recommendations.append("No known reputation issues detected.")

    elif reputation == "SUSPICIOUS":

        recommendations.append("Verify this website before interacting.")

    elif reputation == "MALICIOUS":

        recommendations.append("Avoid visiting this website.")

    return {
        "score": score,
        "reputation": reputation,
        "findings": findings,
        "recommendations": recommendations,
    }
