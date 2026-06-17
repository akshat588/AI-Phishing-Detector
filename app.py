import re
import email
import time
from reportlab.pdfgen import canvas
import io
from engines.upi_detector import (
    analyze_upi
)

from flask import Flask, render_template, request, send_file
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

app = Flask(__name__)
latest_report = {}

# ==========================
# Load ML Model
# ==========================

model = joblib.load("saved_model.pkl")
vectorizer = joblib.load("vectorizer.pkl")


@app.route("/")
def home():
    return render_template("index.html")

@app.route("/email-analyzer")
def email_analyzer():
    return render_template("email_analyzer.html")
@app.route("/url-analyzer")
def url_analyzer():
    return render_template("url_analyzer.html")
@app.route("/sender-analyzer")
def sender_analyzer():
    return render_template("sender_analyzer.html")
@app.route("/upi-analyzer")
def upi_analyzer():
    return render_template("upi_analyzer.html")
@app.route("/analyze", methods=["POST"])
def analyze():

    
    global latest_report
    
    start_time = time.time()
    
    
    
    email = request.form.get("email_content") 
    url = request.form.get("url", "")

    if not url and email:
        urls = re.findall(
        r'https?://[^\s]+',
        email
    )

    if urls:
        url = urls[0]
    sender = request.form.get("sender", "")

    # ==========================
    # Email Analysis
    # ==========================

    threat_dna = analyze_email(email)

    email_score = get_email_score(
        threat_dna
    )

    # ==========================
    # UPI Analysis
    # ==========================

    upi_score, upi_findings = analyze_upi(
        email
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
    email_lower = email.lower()

    # ==========================
    # Brand Impersonation Detection
    # ==========================

    brands = [
        "sbi",
        "hdfc",
        "icici",
        "axis",
        "paytm",
        "amazon",
        "google",
        "microsoft"
    ]

    for brand in brands:

        if brand in email_lower:

            sender_findings.append(
                f"⚠ Brand Impersonation Detected: {brand.upper()}"
            )

            sender_score += 20

    # ==========================
    # ML Prediction
    # ==========================

    if email and email.strip():
        

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

    else:

        prediction = [0]
        ml_confidence = 0
        ml_verdict = "URL / Sender Analysis Only"
        
    # ==========================
    # Weighted Threat Score
    # ==========================

    final_score = round(

        email_score * 0.45 +

        url_score * 0.25 +

        sender_score * 0.15 +

        ml_confidence * 0.15,

        2
    )

    
    # ==========================
    # Attack Classification
    # ==========================

    attack_types = []

    if threat_dna["Credential Theft"] > 30:
        attack_types.append("Credential Theft")

    if threat_dna["Financial Fraud"] > 30:
        attack_types.append("Financial Fraud")

    if threat_dna["Social Engineering"] > 30:
        attack_types.append("Social Engineering")

    if threat_dna["Fear Tactics"] > 30:
        attack_types.append("Fear Tactics")

    if threat_dna["Urgency"] > 30:
        attack_types.append("Urgency Manipulation")

    if len(attack_types) == 0:
        attack_types.append("General Phishing")

    # ==========================
    # AI Security Analyst
    # ==========================

    analyst_findings = []

    if threat_dna["Credential Theft"] > 0:
        analyst_findings.append(
            "🔐 Credential Theft"
        )

    if threat_dna["Urgency"] > 0:
        analyst_findings.append(
            "⏰ Urgency manipulation."
        )

    if threat_dna["Fear Tactics"] > 0:
        analyst_findings.append(
            "🚨 Fear tactics."
        )

    if threat_dna["Financial Fraud"] > 0:
        analyst_findings.append(
            "💰 Financial fraud."
        )

    if threat_dna["Social Engineering"] > 0:
        analyst_findings.append(
            "🎭 Social engineering."
        )
    # ==========================
    # ML Boost
    # ==========================

    if prediction[0] == 1:
        final_score += 20

    final_score = round(final_score, 2)
    
    # ==========================
    # Severity
    # ==========================

    if final_score >= 85:
        severity = "🚨 CRITICAL"

    elif final_score >= 65:
        severity = "🔴 HIGH"

    elif final_score >= 35:
        severity = "🟠 MEDIUM"

    else:
        severity = "🟢 LOW"

    # ==========================
    # Analyst Summary
    # ==========================

    if final_score >= 70:

        analyst_summary = (
            "This email appears to be a high-risk phishing attempt. Immediate caution is advised."
        )

    elif final_score >= 40:

        analyst_summary = (
            "This email contains multiple suspicious indicators and should be verified before interaction."
        )

    else:

        analyst_summary = (
            "This email appears relatively safe, but basic caution is still recommended."
        )

    # ==========================
    # Render Dashboard
    # ==========================
    
    indicators_found = (

    len(analyst_findings)

    + len(url_findings)

    + len(sender_findings)

    + len(upi_findings)

)
    
    analysis_time = round(
        time.time() - start_time,
        2
    )
    

    latest_report = {
        "score": final_score,
        "severity": severity,
        "verdict": ml_verdict,
        "summary": analyst_summary,
        "time": analysis_time
    }
    if indicators_found >= 12:
        detection_status = "🔴 HIGH ACTIVITY"

    elif indicators_found >= 5:
        detection_status = "🟡 SUSPICIOUS"

    else:
        detection_status = "🟢 NORMAL"
    return render_template(

        "result.html",
        indicators_found=indicators_found,
        detection_status=detection_status,

        analysis_time=analysis_time,

        final_score=final_score,

        email_score=email_score,

        url_score=url_score,

        sender_score=sender_score,

        upi_score=upi_score,

        upi_findings=upi_findings,

        ml_confidence=ml_confidence,

        ml_verdict=ml_verdict,

        severity=severity,

        attack_types=attack_types,

        threat_dna=threat_dna,

        analyst_summary=analyst_summary,

        analyst_findings=analyst_findings,

        url_findings=url_findings,

        sender_findings=sender_findings

    )
    
@app.route("/download-report")
def download_report():

    buffer = io.BytesIO()

    pdf = canvas.Canvas(buffer)

    pdf.setTitle("PhishEye AI Report")

    pdf.drawString(
        100,
        800,
        "PhishEye AI Security Report"
    )

    pdf.drawString(
        100,
        760,
        f"Threat Score: {latest_report.get('score')}"
    )

    pdf.drawString(
        100,
        730,
        f"Severity: {latest_report.get('severity')}"
    )

    pdf.drawString(
        100,
        700,
        f"ML Verdict: {latest_report.get('verdict')}"
    )

    pdf.drawString(
        100,
        670,
        f"Analysis Time: {latest_report.get('time')} sec"
    )

    pdf.drawString(
        100,
        640,
        "AI Analyst Summary:"
    )

    pdf.drawString(
        100,
        610,
        latest_report.get("summary", "")
    )

    pdf.save()

    buffer.seek(0)

    return send_file(
        buffer,
        as_attachment=True,
        download_name="PhishEye_Report.pdf",
        mimetype="application/pdf"
    )


if __name__ == "__main__":
    app.run(debug=True)