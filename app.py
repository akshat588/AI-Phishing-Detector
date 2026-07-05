from engines.ai_analyst import get_ai_intelligence
import os
import re
import time
import io
from engines.dashboard_manager import (
    update_dashboard,
    get_dashboard,
    update_threat_type,
    update_brand,
    update_tld,
    add_hunting_record,
)
from flask import (
    Flask,
    render_template,
    request,
    send_file,
    jsonify,
    send_from_directory,
)
import csv
import json
import joblib
from datetime import datetime
from engines.email_analyzer import analyze_email, get_email_score
from engines.url_analyzer import (
    analyze_url,
    generate_url_ai_explanation,
)
from engines.job_analyzer import (
    analyze_job_offer,
    get_job_risk_level,
    generate_job_ai_explanation,
)
from engines.sender_analyzer import analyze_sender
from engines.upi_analyzer import (
    analyze_upi,
    get_upi_risk_level,
    generate_upi_ai_explanation,
)
from engines.qr_analyzer import analyze_qr
from engines.digital_trust_engine import calculate_digital_trust_score
from services.analysis_service import analyze_content
from dataset_generator.generator import generator
from dataset_generator.validator import validator
from dataset_generator.feature_extractor import feature_extractor
from dataset_generator.exporter import exporter
from engines.ai_intelligence_engine import generate_ai_intelligence

import tempfile
import os

try:
    from reportlab.pdfgen import canvas

    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False

app = Flask(__name__)
latest_report = {}

import os
import json

SCAN_HISTORY_FILE = "data/scan_history.json"

os.makedirs("data", exist_ok=True)

if not os.path.exists(SCAN_HISTORY_FILE):
    with open(SCAN_HISTORY_FILE, "w") as f:
        json.dump([], f)

# ==========================
# Load ML Model
# ==========================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
model = joblib.load(os.path.join(BASE_DIR, "saved_model.pkl"))
vectorizer = joblib.load(os.path.join(BASE_DIR, "vectorizer.pkl"))

# ==========================
# Scan History Helper
# ==========================

SCAN_HISTORY_FILE = os.path.join(BASE_DIR, "data", "scan_history.json")


def save_scan_history(analyzer, score, risk, verdict):
    """Save every completed scan to scan_history.json."""

    scan = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "analyzer": analyzer,
        "score": score,
        "risk": risk,
        "verdict": verdict,
    }

    try:
        if os.path.exists(SCAN_HISTORY_FILE):
            with open(SCAN_HISTORY_FILE, "r", encoding="utf-8") as f:
                history = json.load(f)
        else:
            history = []

        history.append(scan)

        with open(SCAN_HISTORY_FILE, "w", encoding="utf-8") as f:
            json.dump(history, f, indent=4)

    except Exception as e:
        print(f"Error saving scan history: {e}")


# ==========================
# Page Routes
# ==========================


@app.route("/dashboard")
def dashboard():

    dashboard = get_dashboard()

    analyst = get_ai_intelligence()

    return render_template("dashboard.html", dashboard=dashboard, analyst=analyst)


@app.route("/")
def home():

    dashboard = get_dashboard()

    return render_template("index.html", dashboard=dashboard)


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


@app.route("/sms-analyzer")
def sms_analyzer_page():
    return render_template("sms_analyzer.html")


@app.route("/whatsapp-analyzer")
def whatsapp_analyzer_page():
    return render_template("whatsapp_analyzer.html")


# =====================================================
# Analyze WhatsApp Message
# =====================================================


@app.route("/analyze-whatsapp", methods=["POST"])
def analyze_whatsapp():

    whatsapp_content = request.form.get("whatsapp_content", "").strip()

    result = analyze_content(
        content=whatsapp_content,
        source="whatsapp",
    )

    save_scan_history(
        analyzer="WhatsApp Analyzer",
        score=result["email_score"],
        risk=result["source_risk"],
        verdict=result["source_risk"],
    )

    return render_template(
        "whatsapp_result.html",
        content=whatsapp_content,
        final_score=result["email_score"],
        email_score=result["email_score"],
        url_score=result["url_score"],
        sender_score=result["sender_score"],
        upi_score=result["upi_score"],
        digital_trust_score=result["digital_trust_score"],
        digital_trust_level=result["digital_trust_level"],
        threat_dna=result["threat_dna"],
        url_findings=result["url_findings"],
        sender_findings=result["sender_findings"],
        upi_findings=result["upi_findings"],
        source_findings=result["source_findings"],
        source_ai=result["source_ai"],
        source_risk=result["source_risk"],
        indicators_found=len(result["source_findings"]),
        detection_status="WhatsApp Analysis",
        analysis_time=0,
        ml_confidence=0,
        ml_verdict="WhatsApp Analysis",
        severity=result["source_risk"],
        attack_types=[],
        analyst_summary="WhatsApp message analyzed using TrustLens AI.",
        analyst_findings=[],
    )


@app.route("/job-detector")
def job_detector_page():
    return render_template("job_detector.html")


# =====================================================
# Analyze Fake Job
# =====================================================


@app.route("/analyze-job", methods=["POST"])
def analyze_job():

    job_text = request.form.get("job_text", "").strip()

    score, threat_dna, findings = analyze_job_offer(job_text)

    risk_level = get_job_risk_level(score)

    job_ai = generate_job_ai_explanation(
        threat_dna,
        score,
    )

    save_scan_history(
        analyzer="Fake Job Detector",
        score=score,
        risk=risk_level,
        verdict=risk_level,
    )

    return render_template(
        "job_result.html",
        job_text=job_text,
        score=score,
        risk_level=risk_level,
        threat_dna=threat_dna,
        findings=findings,
        job_ai=job_ai,
    )


@app.route("/scan-center")
def scan_center():
    return render_template("scan_center.html")


@app.route("/scan-history")
def scan_history():

    try:
        with open(SCAN_HISTORY_FILE, "r", encoding="utf-8") as f:
            history = json.load(f)
    except:
        history = []

    history = sorted(
        history,
        key=lambda x: x.get("timestamp", ""),
        reverse=True,
    )

    total_scans = len(history)

    critical_count = sum(1 for scan in history if "CRITICAL" in scan.get("risk", ""))

    high_count = sum(1 for scan in history if "HIGH" in scan.get("risk", ""))

    safe_count = sum(1 for scan in history if "SAFE" in scan.get("verdict", "").upper())

    return render_template(
        "scan_history.html",
        history=history,
        total_scans=total_scans,
        critical_count=critical_count,
        high_count=high_count,
        safe_count=safe_count,
    )


@app.route("/threat-hunting")
def threat_hunting():

    dashboard = get_dashboard()

    records = dashboard.get("hunting_data", [])

    search_query = request.args.get("search", "").lower()

    if search_query:

        filtered_records = []

        for record in records:

            searchable_text = (str(record)).lower()

            if search_query in searchable_text:

                filtered_records.append(record)

        records = filtered_records

    return render_template(
        "threat_hunting.html", records=records, search_query=search_query
    )


# ==========================
# Analysis Routes
# ==========================
@app.route("/scan-email", methods=["POST"])
def scan_email():

    email_content = request.form.get("email_content")

    return render_template(
        "components/loading.html",
        email_content=email_content,
    )


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
    upi_score, upi_threat_dna, upi_findings = analyze_upi(email_content)

    # --- Brand Impersonation ---

    brands = ["sbi", "hdfc", "icici", "axis", "amazon", "google", "microsoft", "paypal"]

    brand_map = {
        "amazon": "Amazon",
        "google": "Google",
        "microsoft": "Microsoft",
        "paypal": "PayPal",
        "sbi": "SBI",
        "hdfc": "HDFC",
        "icici": "ICICI",
        "axis": "Axis",
    }

    for brand in brands:

        if brand in email_content.lower():

            sender_findings.append(f"🚨 Brand impersonation detected: {brand.upper()}")

            sender_score = min(sender_score + 20, 100)

            update_brand(brand_map[brand])

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
        email_score * 0.40
        + url_score * 0.25
        + sender_score * 0.15
        + ml_confidence * 0.20,
        2,
    )

    # ML boost
    if prediction[0] == 1:
        final_score = min(final_score + 15, 100)

    final_score = round(final_score, 2)

    # ==========================
    # Digital Trust Score
    # ==========================

    trust_result = calculate_digital_trust_score(
        email_score=email_score,
        url_score=url_score,
        sender_score=sender_score,
        upi_score=upi_score,
    )

    digital_trust_score = trust_result["trust_score"]
    digital_trust_level = trust_result["trust_level"]

    print("Digital Trust Score:", digital_trust_score)
    print("Digital Trust Level:", digital_trust_level)

    # --- Attack Classification ---
    attack_types = []
    if threat_dna["Credential Theft"] > 30:
        attack_types.append("Credential Theft")
        update_threat_type("Credential Theft")
    if threat_dna["Financial Fraud"] > 30:
        attack_types.append("Financial Fraud")
        update_threat_type("Financial Fraud")
    if threat_dna["Social Engineering"] > 30:
        attack_types.append("Social Engineering")
        update_threat_type("Social Engineering")
    if threat_dna["Fear Tactics"] > 30:
        attack_types.append("Fear Tactics")
        update_threat_type("Fear Tactics")
    if threat_dna["Urgency"] > 30:
        attack_types.append("Urgency")
        update_threat_type("Urgency")
    if not attack_types:
        attack_types.append(
            "General Phishing" if final_score > 30 else "No Threat Detected"
        )

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

    # ==========================
    # AI Intelligence Report
    # ==========================

    ai_intelligence = generate_ai_intelligence(
        score=final_score,
        risk_level=severity.replace("🚨 ", "")
        .replace("🔴 ", "")
        .replace("🟠 ", "")
        .replace("🟢 ", ""),
        findings=analyst_findings + url_findings + sender_findings + upi_findings,
        threat_dna=threat_dna,
        ml_confidence=ml_confidence,
    )

    # --- Detection Status ---
    indicators_found = (
        len(analyst_findings)
        + len(url_findings)
        + len(sender_findings)
        + len(upi_findings)
    )
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

    print("Adding hunting record...")
    add_hunting_record(
        {
            "type": "Email",
            "severity": severity,
            "score": final_score,
            "threats": attack_types,
        }
    )

    update_dashboard(
        analyzer="Email Analyzer",
        score=final_score,
        severity=severity,
    )

    # Save scan to TrustLens Scan History

    save_scan_history(
        analyzer="Email Analyzer",
        score=final_score,
        risk=severity,
        verdict=prediction,
    )
    return render_template(
        "result.html",
        indicators_found=indicators_found,
        detection_status=detection_status,
        analysis_time=analysis_time,
        final_score=final_score,
        digital_trust_score=digital_trust_score,
        digital_trust_level=digital_trust_level,
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
        ai_intelligence=ai_intelligence,
    )


@app.route("/analyze-sms", methods=["POST"])
def analyze_sms():

    sms_content = request.form.get("sms_content", "").strip()

    result = analyze_content(content=sms_content, source="sms")

    save_scan_history(
        analyzer="SMS Analyzer",
        score=result["email_score"],
        risk=result["source_risk"],
        verdict=result["source_risk"],
    )

    return render_template(
        "sms_result.html",
        final_score=result["email_score"],
        email_score=result["email_score"],
        url_score=result["url_score"],
        sender_score=result["sender_score"],
        upi_score=result["upi_score"],
        digital_trust_score=result["digital_trust_score"],
        digital_trust_level=result["digital_trust_level"],
        threat_dna=result["threat_dna"],
        url_findings=result["url_findings"],
        sender_findings=result["sender_findings"],
        upi_findings=result["upi_findings"],
        indicators_found=0,
        detection_status="SMS Analysis",
        analysis_time=0,
        ml_confidence=0,
        ml_verdict="SMS Analysis",
        severity="🟢 LOW",
        attack_types=[],
        analyst_summary="SMS analyzed using TrustLens AI.",
        analyst_findings=[],
        source_findings=result["source_findings"],
        shared_ai=result["source_ai"],
    )


@app.route("/analyze-url", methods=["POST"])
def analyze_url_only():

    url = request.form.get("url", "").strip()

    # Existing URL analysis
    score, findings = analyze_url(url)

    # New Threat Intelligence
    from engines.threat_intelligence import analyze_threat_intelligence

    intelligence = analyze_threat_intelligence(url)

    url_ai = generate_url_ai_explanation(score, findings)

    tlds = [".xyz", ".top", ".click", ".shop", ".live", ".online"]

    for tld in tlds:
        if tld in url.lower():
            update_tld(tld)

    if intelligence["overall_score"] >= 85:
        severity = "🚨 CRITICAL"
    elif intelligence["overall_score"] >= 65:
        severity = "🔴 HIGH"
    elif intelligence["overall_score"] >= 35:
        severity = "🟠 MEDIUM"
    else:
        severity = "🟢 LOW"

    update_dashboard(
        analyzer="URL Analyzer",
        score=intelligence["overall_score"],
        severity=severity,
    )
    save_scan_history(
        analyzer="URL Analyzer",
        score=score,
        risk=severity,
        verdict=severity,
    )

    return render_template(
        "url_result.html",
        url=url,
        score=intelligence["overall_score"],
        findings=intelligence["findings"],
        severity=severity,
        url_ai=url_ai,
        intelligence=intelligence,
    )


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

    update_dashboard(analyzer="Sender Analyzer", score=score, severity=severity)
    return render_template(
        "sender_result.html",
        sender=sender,
        score=score,
        findings=findings,
        severity=severity,
    )


@app.route("/analyze-upi", methods=["POST"])
def analyze_upi_only():

    text = request.form.get("upi_text", "").strip()

    score, threat_dna, findings = analyze_upi(text)

    risk_level = get_upi_risk_level(score)

    ai = generate_upi_ai_explanation(
        threat_dna,
        score,
    )

    update_dashboard(
        analyzer="UPI Analyzer",
        score=score,
        severity=risk_level,
    )

    save_scan_history(
        analyzer="UPI Analyzer",
        score=score,
        risk=risk_level,
        verdict=risk_level,
    )

    return render_template(
        "upi_result.html",
        text=text,
        score=score,
        risk_level=risk_level,
        findings=findings,
        threat_dna=threat_dna,
        ai=ai,
    )


@app.route("/analyze-qr", methods=["POST"])
def analyze_qr_code():

    start_time = time.time()

    file = request.files.get("qr_image")

    if not file or file.filename == "":

        return render_template(
            "qr_result.html",
            success=False,
            error="No file uploaded.",
        )

    upload_path = os.path.join(
        BASE_DIR,
        "static",
        "uploaded_qr.png",
    )

    file.save(upload_path)

    result = analyze_qr(upload_path)

    if not result["success"]:

        return render_template(
            "qr_result.html",
            success=False,
            error=result["message"],
        )

    qr_data = result["decoded_data"]

    qr_type = result["qr_type"]

    score = result["score"]

    confidence = result["confidence"]

    findings = result["findings"]

    threat_dna = result["threat_dna"]

    recommendations = result["recommendations"]

    # ---------------------------------------
    # Dashboard Analytics
    # ---------------------------------------

    tlds = [".xyz", ".top", ".click", ".shop", ".live", ".online"]

    for tld in tlds:

        if tld in qr_data.lower():

            update_tld(tld)

    # ---------------------------------------
    # Severity
    # ---------------------------------------

    if score >= 80:

        severity = "🚨 CRITICAL"

    elif score >= 60:

        severity = "🔴 HIGH"

    elif score >= 35:

        severity = "🟠 MEDIUM"

    else:

        severity = "🟢 LOW"

    # ---------------------------------------
    # Attack Types
    # ---------------------------------------

    attack_types = []

    if qr_type == "URL":

        attack_types.append("Malicious URL")

    elif qr_type == "UPI Payment":

        attack_types.append("UPI Payment Request")

    elif qr_type == "Wi-Fi":

        attack_types.append("Network Configuration")

    elif qr_type == "Cryptocurrency":

        attack_types.append("Crypto Wallet")

    elif qr_type == "SMS":

        attack_types.append("SMS Payload")

    elif qr_type == "Contact Card":

        attack_types.append("Contact Information")

    elif qr_type == "Email":

        attack_types.append("Email Payload")

    elif qr_type == "Phone Number":

        attack_types.append("Phone Number")

    else:

        attack_types.append("Plain Text")

    # ---------------------------------------
    # AI Summary
    # ---------------------------------------

    if score >= 80:

        analyst_summary = "The QR code contains multiple high-risk indicators."

    elif score >= 60:

        analyst_summary = "The QR code contains suspicious characteristics."

    elif score >= 35:

        analyst_summary = "Exercise caution before using this QR code."

    else:

        analyst_summary = "No major threats were detected."

    analysis_time = round(
        time.time() - start_time,
        2,
    )

    update_dashboard(
        analyzer="QR Analyzer",
        score=score,
        severity=severity,
    )

    save_scan_history(
        analyzer="QR Analyzer",
        score=result["score"],
        risk=get_qr_risk_level(result["score"]),
        verdict=result["qr_type"],
    )

    return render_template(
        "qr_result.html",
        success=True,
        qr_data=qr_data,
        qr_type=qr_type,
        confidence=confidence,
        threat_dna=threat_dna,
        recommendations=recommendations,
        findings=findings,
        final_score=score,
        severity=severity,
        attack_types=attack_types,
        analyst_summary=analyst_summary,
        analysis_time=analysis_time,
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

    # ======================
    # HEADER
    # ======================

    pdf.setFont("Helvetica-Bold", 22)
    pdf.drawString(50, 800, "🛡 PHISHEYE AI")

    pdf.setFont("Helvetica-Bold", 14)
    pdf.drawString(50, 775, "Cyber Threat Intelligence Report")

    pdf.line(50, 765, 550, 765)

    # ======================
    # THREAT OVERVIEW
    # ======================

    pdf.setFont("Helvetica-Bold", 16)
    pdf.drawString(50, 730, "Threat Overview")

    pdf.setFont("Helvetica", 12)

    pdf.drawString(70, 705, f"Threat Score: {latest_report.get('score', 'N/A')} / 100")

    pdf.drawString(70, 685, f"Severity: {latest_report.get('severity', 'N/A')}")

    pdf.drawString(70, 665, f"Verdict: {latest_report.get('verdict', 'N/A')}")

    pdf.drawString(70, 645, f"Analysis Time: {latest_report.get('time', 'N/A')} sec")

    # ======================
    # AI ANALYST SUMMARY
    # ======================

    pdf.setFont("Helvetica-Bold", 16)
    pdf.drawString(50, 600, "AI Security Analyst")

    pdf.setFont("Helvetica", 11)

    summary = latest_report.get("summary", "No analyst summary available.")

    pdf.drawString(70, 575, summary)

    # ======================
    # THREAT INDICATORS
    # ======================

    pdf.setFont("Helvetica-Bold", 16)
    pdf.drawString(50, 530, "Threat Indicators")

    pdf.setFont("Helvetica", 11)

    pdf.drawString(70, 505, "• Credential Theft Indicators")

    pdf.drawString(70, 485, "• Brand Impersonation Detection")

    pdf.drawString(70, 465, "• Social Engineering Signals")

    pdf.drawString(70, 445, "• Suspicious URL Intelligence")

    # ======================
    # RECOMMENDED ACTIONS
    # ======================

    pdf.setFont("Helvetica-Bold", 16)
    pdf.drawString(50, 390, "Recommended Actions")

    pdf.setFont("Helvetica", 11)

    pdf.drawString(70, 365, "✓ Do not click suspicious links")

    pdf.drawString(70, 345, "✓ Verify sender authenticity")

    pdf.drawString(70, 325, "✓ Enable Multi-Factor Authentication")

    pdf.drawString(70, 305, "✓ Report suspicious activity")

    # ======================
    # FOOTER
    # ======================

    pdf.line(50, 220, 550, 220)

    pdf.setFont("Helvetica-Oblique", 10)

    pdf.drawString(50, 200, "Generated by PhishEye AI Threat Intelligence Platform")

    pdf.drawString(50, 185, "Confidential Security Report")

    pdf.save()

    buffer.seek(0)

    return send_file(
        buffer,
        as_attachment=True,
        download_name="PhishEye_AI_Report.pdf",
        mimetype="application/pdf",
    )


@app.route("/export-json")
def export_json():

    dashboard = get_dashboard()

    return jsonify(dashboard)


@app.route("/export-csv")
def export_csv():

    dashboard = get_dashboard()

    csv_file = io.StringIO()

    writer = csv.writer(csv_file)

    writer.writerow(["Type", "Severity", "Score", "Threats"])

    for record in dashboard.get("hunting_data", []):

        writer.writerow(
            [
                record.get("type"),
                record.get("severity"),
                record.get("score"),
                ",".join(record.get("threats", [])),
            ]
        )

    output = io.BytesIO()

    output.write(csv_file.getvalue().encode())

    output.seek(0)

    return send_file(
        output,
        as_attachment=True,
        download_name="Threat_Report.csv",
        mimetype="text/csv",
    )


# =====================================================
# Dataset Generator Page
# =====================================================


@app.route("/dataset-generator")
def dataset_generator():

    history_file = "data/history.json"

    history = []

    if os.path.exists(history_file):

        try:

            with open(history_file, "r") as f:
                history = json.load(f)

        except:
            history = []

    return render_template("dataset_generator.html", history=history)


# =====================================================
# Generate Dataset
# =====================================================


@app.route("/generate-dataset", methods=["POST"])
def generate_dataset():

    dataset_type = request.form.get("dataset_type", "email").lower()
    category = request.form.get("category")
    records = int(request.form.get("records", 100))
    export_format = request.form.get("export", "csv").lower()
    balanced = request.form.get("balanced")

    if balanced == "yes":
        dataframe = generator.generate_balanced_dataset(
            dataset_type, records_per_category=records
        )

    elif category:
        dataframe = generator.generate_dataset(dataset_type, category, records)

    else:
        dataframe = generator.generate_full_dataset(dataset_type, records)

    dataframe = validator.validate(dataframe)
    dataframe = feature_extractor.extract(dataframe)

    result = exporter.export(dataframe, dataset_type, export_format)

    preview = dataframe.head(10).to_dict(orient="records")

    summary = exporter.summary(dataframe)

    # ===========================
    # Dataset Quality
    # ===========================

    duplicates = dataframe.duplicated().sum()
    missing = dataframe.isnull().sum().sum()

    quality = 100
    quality -= duplicates * 2
    quality -= missing

    if quality < 0:
        quality = 0

    quality = round(quality)

    # ===========================
    # Save Generation History
    # ===========================

    history_file = "data/history.json"

    os.makedirs("data", exist_ok=True)

    history = []

    if os.path.exists(history_file):
        try:
            with open(history_file, "r") as f:
                history = json.load(f)
        except:
            history = []

    history.insert(
        0,
        {
            "timestamp": datetime.now().strftime("%d-%m-%Y %H:%M"),
            "dataset_type": dataset_type.upper(),
            "records": len(dataframe),
            "category": category if category else "ALL",
            "format": export_format.upper(),
            "filename": os.path.basename(result["dataset_file"]),
            "status": "Completed",
        },
    )

    history = history[:20]

    with open(history_file, "w") as f:
        json.dump(history, f, indent=4)

    return render_template(
        "dataset_generator.html",
        generated=True,
        preview=preview,
        summary=summary,
        result=result,
        history=history,
        quality=quality,
    )


# =====================================================
# Download Dataset
# =====================================================


@app.route("/download-dataset/<path:filename>")
def download_dataset(filename):

    directory = os.path.dirname(filename)

    file = os.path.basename(filename)

    return send_from_directory(directory, file, as_attachment=True)


print("=" * 60)
print("TRUSTLENS AI - NEW APP IS RUNNING")
print(__file__)
print("=" * 60)
if __name__ == "__main__":
    app.run(debug=True)
