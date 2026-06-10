from flask import Flask, render_template, request
import joblib

from engines.email_analyzer import (
    analyze_email,
    get_email_score
)

from engines.url_analyzer import (
    analyze_url
)

from engines.sender_analyzer import (
    analyze_sender
)

from engines.threat_engine import (
    calculate_threat_score
)

app = Flask(__name__)

# ==========================
# Load ML Model
# ==========================

model = joblib.load("saved_model.pkl")
vectorizer = joblib.load("vectorizer.pkl")


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/analyze", methods=["POST"])
def analyze():

    email = request.form.get("email")
    url = request.form.get("url")
    sender = request.form.get("sender")

    threat_dna = analyze_email(email)

    email_score = get_email_score(
        threat_dna
    )

    url_score, url_findings = analyze_url(
        url
    )

    sender_score, sender_findings = analyze_sender(
        sender
    )

    email_vector = vectorizer.transform(
        [email]
    )

    prediction = model.predict(
        email_vector
    )

    probability = model.predict_proba(
        email_vector
    )

    ml_confidence = round(
        max(probability[0]) * 100,
        2
    )

    if prediction[0] == 1:
        ml_verdict = "⚠ PHISHING DETECTED"
    else:
        ml_verdict = "✓ SAFE MESSAGE"

    final_score = calculate_threat_score(
        email_score,
        url_score,
        sender_score,
        ml_confidence
    )

    if final_score >= 90:
        severity = "🚨 CRITICAL"

    elif final_score >= 70:
        severity = "🔴 HIGH"

    elif final_score >= 40:
        severity = "🟠 MEDIUM"

    else:
        severity = "🟢 LOW"

    # ==========================
    # AI Security Analyst
    # ==========================

    analyst_findings = []

    if threat_dna["Credential Theft"] > 0:
        analyst_findings.append(
            "Credential theft indicators detected."
        )

    if threat_dna["Urgency"] > 0:
        analyst_findings.append(
            "Urgency manipulation detected."
        )

    if threat_dna["Fear Tactics"] > 0:
        analyst_findings.append(
            "Fear tactics detected."
        )

    if threat_dna["Financial Fraud"] > 0:
        analyst_findings.append(
            "Financial fraud language detected."
        )

    if threat_dna["Social Engineering"] > 0:
        analyst_findings.append(
            "Social engineering indicators detected."
        )

    if final_score >= 70:
        analyst_summary = (
            "This email appears to be a high-risk phishing attempt."
        )

    elif final_score >= 40:
        analyst_summary = (
            "This email contains multiple suspicious indicators."
        )

    else:
        analyst_summary = (
            "This email appears relatively safe."
        )

    return render_template(
        "result.html",

        final_score=final_score,
        email_score=email_score,
        url_score=url_score,
        sender_score=sender_score,

        ml_confidence=ml_confidence,
        ml_verdict=ml_verdict,
        severity=severity,

        threat_dna=threat_dna,

        analyst_summary=analyst_summary,
        analyst_findings=analyst_findings,

        url_findings=url_findings,
        sender_findings=sender_findings
    )


if __name__ == "__main__":
    app.run(debug=True)