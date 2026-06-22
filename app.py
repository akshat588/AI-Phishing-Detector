import os
import re
import time
import io

from flask import Flask, render_template, request, send_file, jsonify
import joblib

from engines.email_analyzer import analyze_email, get_email_score
from engines.url_analyzer import analyze_url
from engines.sender_analyzer import analyze_sender
from engines.upi_detector import analyze_upi
from engines.qr_analyzer import analyze_qr

try:
    from reportlab.pdfgen import canvas
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False

app = Flask(__name__)
latest_report = {}

# ==========================
# Load ML Model
# ==========================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
model = joblib.load(os.path.join(BASE_DIR, "saved_model.pkl"))
vectorizer = joblib.load(os.path.join(BASE_DIR, "vectorizer.pkl"))


# ==========================
# Page Routes
# ==========================

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/email-analyzer")
def email_analyzer_page():
    return render_template("email_analyzer.html")

@app.route("/url-analyzer")
def url_analyzer_page():
    return render_template("url_analyzer.html")

@app.route("/sender-analyzer")
def sender_analyzer_page():
    return render_template("sender_analyzer.html")

@app.route("/upi-analyzer")
def upi_analyzer_page():
    return render_template("upi_analyzer.html")

@app.route("/qr-analyzer")
def qr_analyzer_page():
    return render_template("qr_analyzer.html")


# ==========================
# Analysis Routes
# ==========================

@app.route("/analyze", methods=["POST"])
def analyze():
    """Main analysis route — handles email, URL, and sender together."""
    global latest_report
    start_time = time.time()

    email_content = request.form.get("email_content", "").strip()
    url = request.form.get("url", "").strip()
    sender = request.form.get("sender", "").strip()

    # Auto-extract URL from email body if not provided
    if not url and email_content:
        found = re.findall(r'https?://[^\s<>"]+', email_content)
        if found:
            url = found[0]

    # --- Email Analysis ---
    threat_dna = analyze_email(email_content)
    email_score = get_email_score(threat_dna)

    # --- URL Analysis ---
    url_score, url_findings = analyze_url(url)

    # --- Sender Analysis ---
    sender_score, sender_findings = analyze_sender(sender)

    # --- UPI Analysis ---
    upi_score, upi_findings = analyze_upi(email_content)

    # --- Brand Impersonation ---
    brands = ["sbi", "hdfc", "icici", "axis", "paytm", "amazon", "google", "microsoft"]
    for brand in brands:
        if brand in email_content.lower():
            sender_findings.append(f"🚨 Brand impersonation detected: {brand.upper()}")
            sender_score = min(sender_score + 20, 100)

    # --- ML Prediction ---
    if email_content:
        email_vector = vectorizer.transform([email_content])
        prediction = model.predict(email_vector)
        probability = model.predict_proba(email_vector)
        ml_confidence = round(max(probability[0]) * 100, 2)
        ml_verdict = "⚠ PHISHING DETECTED" if prediction[0] == 1 else "✓ SAFE EMAIL"
    else:
        prediction = [0]
        ml_confidence = 0
        ml_verdict = "URL / Sender Analysis Only"

    # --- Weighted Threat Score ---
    final_score = round(
        email_score * 0.40 +
        url_score * 0.25 +
        sender_score * 0.15 +
        ml_confidence * 0.20,
        2
    )

    # ML boost
    if prediction[0] == 1:
        final_score = min(final_score + 15, 100)

    final_score = round(final_score, 2)

    # --- Attack Classification ---
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
    if not attack_types:
        attack_types.append("General Phishing" if final_score > 30 else "No Threat Detected")

    # --- Analyst Findings ---
    analyst_findings = []
    if threat_dna["Credential Theft"] > 0:
        analyst_findings.append("🔐 Credential theft indicators present")
    if threat_dna["Urgency"] > 0:
        analyst_findings.append("⏰ Urgency manipulation detected")
    if threat_dna["Fear Tactics"] > 0:
        analyst_findings.append("🚨 Fear tactics present")
    if threat_dna["Financial Fraud"] > 0:
        analyst_findings.append("💰 Financial fraud indicators")
    if threat_dna["Social Engineering"] > 0:
        analyst_findings.append("🎭 Social engineering attempt")

    # --- Severity ---
    if final_score >= 85:
        severity = "🚨 CRITICAL"
    elif final_score >= 65:
        severity = "🔴 HIGH"
    elif final_score >= 35:
        severity = "🟠 MEDIUM"
    else:
        severity = "🟢 LOW"

    # --- Analyst Summary ---
    if final_score >= 70:
        analyst_summary = "This message shows strong signs of a phishing attack. Do not click any links or provide any information."
    elif final_score >= 40:
        analyst_summary = "Multiple suspicious indicators were found. Verify this message through official channels before taking any action."
    else:
        analyst_summary = "This message appears relatively safe. Standard caution is still recommended."

    # --- Detection Status ---
    indicators_found = len(analyst_findings) + len(url_findings) + len(sender_findings) + len(upi_findings)
    if indicators_found >= 10:
        detection_status = "🔴 HIGH ACTIVITY"
    elif indicators_found >= 4:
        detection_status = "🟡 SUSPICIOUS"
    else:
        detection_status = "🟢 NORMAL"

    analysis_time = round(time.time() - start_time, 3)

    latest_report = {
        "score": final_score,
        "severity": severity,
        "verdict": ml_verdict,
        "summary": analyst_summary,
        "time": analysis_time,
    }

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
        sender_findings=sender_findings,
    )


@app.route("/analyze-url", methods=["POST"])
def analyze_url_only():
    url = request.form.get("url", "").strip()
    score, findings = analyze_url(url)
    if score >= 65:
        severity = "🔴 HIGH"
    elif score >= 35:
        severity = "🟠 MEDIUM"
    else:
        severity = "🟢 LOW"
    return render_template("url_result.html", url=url, score=score, findings=findings, severity=severity)


@app.route("/analyze-sender", methods=["POST"])
def analyze_sender_only():
    sender = request.form.get("sender", "").strip()
    score, findings = analyze_sender(sender)
    if score >= 65:
        severity = "🔴 HIGH"
    elif score >= 35:
        severity = "🟠 MEDIUM"
    else:
        severity = "🟢 LOW"
    return render_template("sender_result.html", sender=sender, score=score, findings=findings, severity=severity)


@app.route("/analyze-upi", methods=["POST"])
def analyze_upi_only():
    text = request.form.get("upi_text", "").strip()
    score, findings = analyze_upi(text)
    if score >= 50:
        severity = "🔴 HIGH"
    elif score >= 25:
        severity = "🟠 MEDIUM"
    else:
        severity = "🟢 LOW"
    return render_template("upi_result.html", score=score, findings=findings, severity=severity)


@app.route("/analyze-qr", methods=["POST"])
def analyze_qr_code():
    start_time = time.time()

    file = request.files.get("qr_image")

    if not file or file.filename == "":
        return render_template(
            "qr_result.html",
            success=False,
            error="No file uploaded."
        )

    upload_path = os.path.join(
        BASE_DIR,
        "static",
        "uploaded_qr.png"
    )

    file.save(upload_path)

    result = analyze_qr(upload_path)

    if not result["success"]:
        return render_template(
            "qr_result.html",
            success=False,
            error=result["message"]
        )
    qr_data = result["url"]

    url_score = result["score"]

    url_findings = result["findings"]

    final_score = url_score

    if final_score >= 80:
        severity = "🚨 CRITICAL"

    elif final_score >= 60:
        severity = "🔴 HIGH"

    elif final_score >= 35:
        severity = "🟠 MEDIUM"

    else:
        severity = "🟢 LOW"

    attack_types = []

    qr_lower = qr_data.lower()

    if "http" in qr_lower:
        attack_types.append("Phishing URL")

    if "bit.ly" in qr_lower:
        attack_types.append("Shortened URL")

    if "tinyurl" in qr_lower:
        attack_types.append("Shortened URL")

    if "upi://" in qr_lower:
        attack_types.append("UPI Payment Request")

    if not attack_types:
        attack_types.append("Unknown Threat")

    if final_score >= 60:

        analyst_summary = (
            "QR code contains a highly suspicious URL."
        )

    elif final_score >= 35:

        analyst_summary = (
            "QR code contains suspicious indicators."
        )

    else:

        analyst_summary = (
            "QR code appears relatively safe."
        )

    analysis_time = round(
        time.time() - start_time,
        2
    )

    return render_template(
        "qr_result.html",
        success=True,
        qr_data=qr_data,
        final_score=final_score,
        url_score=url_score,
        url_findings=url_findings,
        severity=severity,
        attack_types=attack_types,
        analyst_summary=analyst_summary,
        analysis_time=analysis_time
    )


# ==========================
# PDF Report Download
# ==========================

@app.route("/download-report")
def download_report():
    if not REPORTLAB_AVAILABLE:
        return "ReportLab not installed. Run: pip install reportlab", 500

    if not latest_report:
        return "No report available. Run an analysis first.", 400

    buffer = io.BytesIO()
    pdf = canvas.Canvas(buffer)
    pdf.setTitle("PhishEye AI Security Report")

    # Header
    pdf.setFont("Helvetica-Bold", 18)
    pdf.drawString(72, 780, "PhishEye AI — Security Report")
    pdf.setFont("Helvetica", 11)
    pdf.drawString(72, 755, f"Threat Score:   {latest_report.get('score', 'N/A')} / 100")
    pdf.drawString(72, 735, f"Severity:       {latest_report.get('severity', 'N/A')}")
    pdf.drawString(72, 715, f"ML Verdict:     {latest_report.get('verdict', 'N/A')}")
    pdf.drawString(72, 695, f"Analysis Time:  {latest_report.get('time', 'N/A')} sec")
    pdf.drawString(72, 665, "AI Analyst Summary:")
    pdf.setFont("Helvetica", 10)
    pdf.drawString(72, 645, latest_report.get("summary", ""))
    pdf.save()
    buffer.seek(0)

    return send_file(
        buffer,
        as_attachment=True,
        download_name="PhishEye_Report.pdf",
        mimetype="application/pdf",
    )


if __name__ == "__main__":
    app.run(debug=True)