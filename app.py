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

    # ==========================
    # Email Analysis
    # ==========================

    threat_dna = analyze_email(email)

    email_score = get_email_score(
        threat_dna
    )

    # ==========================
    # URL Analysis
    # ==========================

    url_score, url_findings = analyze_url(
        url
    )

    # ==========================
    # Sender Analysis
    # ==========================

    sender_score, sender_findings = analyze_sender(
        sender
    )

    # ==========================
    # ML Prediction
    # ==========================

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

    # ==========================
    # Final Threat Score
    # ==========================

    final_score = calculate_threat_score(
        email_score,
        url_score,
        sender_score,
        ml_confidence
    )

    # ==========================
    # Severity
    # ==========================

    if final_score >= 90:
        severity = "🚨 CRITICAL"

    elif final_score >= 70:
        severity = "🔴 HIGH"

    elif final_score >= 40:
        severity = "🟠 MEDIUM"

    else:
        severity = "🟢 LOW"

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

        url_findings=url_findings,
        sender_findings=sender_findings
    )


if __name__ == "__main__":
    app.run(debug=True)