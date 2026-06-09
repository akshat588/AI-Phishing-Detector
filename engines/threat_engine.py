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


email_score = float(input("Email Score: "))
url_score = float(input("URL Score: "))
sender_score = float(input("Sender Score: "))
ml_confidence = float(input("ML Confidence: "))

final_score = calculate_threat_score(
    email_score,
    url_score,
    sender_score,
    ml_confidence
)

# Risk Classification

if final_score >= 90:
    severity = "🚨 CRITICAL"

elif final_score >= 70:
    severity = "🔴 HIGH"

elif final_score >= 40:
    severity = "🟠 MEDIUM"

else:
    severity = "🟢 LOW"

print("\n========== THREAT ENGINE ==========\n")

print("Final Threat Score:", final_score)
print("Severity:", severity)