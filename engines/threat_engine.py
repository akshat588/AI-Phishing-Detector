def calculate_threat_score(
    email_score,
    url_score,
    sender_score,
    ml_confidence
):
    final_score = (
        email_score +
        url_score +
        sender_score +
        ml_confidence
    ) / 4

    return round(final_score, 2)