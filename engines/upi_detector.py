def analyze_upi(email):

    email = email.lower()

    score = 0

    findings = []

    upi_keywords = [

        "upi",
        "paytm",
        "phonepe",
        "google pay",
        "gpay",
        "bhim",
        "reward",
        "cashback",
        "refund",
        "kyc",
        "account frozen",
        "bank verification",
        "verify account",
        "otp",
        "payment received",
        "payment failed",
        "click to claim"

    ]

    for keyword in upi_keywords:

        if keyword in email:

            score += 10

            findings.append(
                f"Detected keyword: {keyword}"
            )

    if score > 100:
        score = 100

    return score, findings