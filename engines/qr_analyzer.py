import cv2

from engines.url_analyzer import analyze_url
from engines.upi_analyzer import analyze_upi
from engines.explanation_engine import generate_ai_explanation as unified_ai_explanation
from services.ai_pipeline import build_ai_pipeline


def detect_qr_type(data):

    text = data.strip()

    if text.startswith(("http://", "https://")):
        return "URL"

    elif text.startswith("upi://"):
        return "UPI Payment"

    elif text.startswith("WIFI:"):
        return "Wi-Fi"

    elif text.startswith("BEGIN:VCARD"):
        return "Contact Card"

    elif text.startswith("mailto:"):
        return "Email"

    elif text.startswith("tel:"):
        return "Phone Number"

    elif text.startswith("SMSTO:"):
        return "SMS"

    elif text.startswith(("bitcoin:", "ethereum:", "usdt:", "binance:")):
        return "Cryptocurrency"

    return "Plain Text"


def analyze_qr(image_path):

    try:

        detector = cv2.QRCodeDetector()

        image = cv2.imread(image_path)

        if image is None:

            return {
                "success": False,
                "message": "Unable to read image.",
                "decoded_data": "",
                "qr_type": "Unknown",
                "score": 0,
                "findings": [],
                "threat_dna": {},
                "recommendations": [],
            }

        data, bbox, _ = detector.detectAndDecode(image)

        if not data:

            return {
                "success": False,
                "message": "No QR code detected.",
                "decoded_data": "",
                "qr_type": "Unknown",
                "score": 0,
                "findings": [],
                "threat_dna": {},
                "recommendations": [],
            }

        qr_type = detect_qr_type(data)

        findings = []
        recommendations = []
        threat_dna = {}

        score = 0

        # ======================================
        # URL QR
        # ======================================

        if qr_type == "URL":

            score, findings = analyze_url(data)

            threat_dna["URL Threat"] = score

            recommendations.append("Verify the website before opening it.")

        # ======================================
        # UPI QR
        # ======================================

        elif qr_type == "UPI Payment":

            upi_score, upi_findings = analyze_upi(data)

            score = upi_score

            findings = upi_findings

            threat_dna["UPI Risk"] = upi_score

            recommendations.append("Verify the merchant before making payment.")

        # ======================================
        # Wi-Fi QR
        # ======================================

        elif qr_type == "Wi-Fi":

            score = 20

            findings.append("Wi-Fi QR detected.")

            threat_dna["Wi-Fi"] = 20

            recommendations.append("Connect only if you trust the network.")

        # ======================================
        # Contact Card
        # ======================================

        elif qr_type == "Contact Card":

            score = 10

            findings.append("vCard contact detected.")

            threat_dna["Contact"] = 10

            recommendations.append("Verify contact details before saving.")

        # ======================================
        # Email QR
        # ======================================

        elif qr_type == "Email":

            score = 15

            findings.append("Email QR detected.")

            threat_dna["Email"] = 15

            recommendations.append(
                "Confirm the email address before sending information."
            )

        # ======================================
        # Phone QR
        # ======================================

        elif qr_type == "Phone Number":

            score = 10

            findings.append("Phone number QR detected.")

            threat_dna["Phone"] = 10

            recommendations.append("Verify the phone number before calling.")

        # ======================================
        # SMS QR
        # ======================================

        elif qr_type == "SMS":

            score = 25

            findings.append("SMS QR detected.")

            threat_dna["SMS"] = 25

            recommendations.append("Review the SMS content before sending.")

        # ======================================
        # Cryptocurrency
        # ======================================

        elif qr_type == "Cryptocurrency":

            score = 35

            findings.append("Cryptocurrency wallet detected.")

            threat_dna["Crypto"] = 35

            recommendations.append(
                "Verify wallet addresses carefully before transferring funds."
            )

        # ======================================
        # Plain Text
        # ======================================

        else:

            score = 5

            findings.append("Plain text QR detected.")

            threat_dna["Plain Text"] = 5

            recommendations.append("Review the QR content before acting on it.")

        score = min(score, 100)

        confidence = min(score + 5, 100)

        return {
            "success": True,
            "message": "QR code decoded successfully.",
            "decoded_data": data,
            "qr_type": qr_type,
            "score": score,
            "confidence": confidence,
            "findings": findings,
            "threat_dna": threat_dna,
            "recommendations": recommendations,
            "shared_ai": unified_ai_explanation(
                analyzer_name="QR Analyzer",
                risk_level=(
                    "CRITICAL"
                    if score >= 90
                    else "HIGH" if score >= 70 else "MEDIUM" if score >= 40 else "LOW"
                ),
                score=confidence,
                findings=findings,
                recommendations=recommendations,
            ),
        }

    except Exception as e:

        return {
            "success": False,
            "message": str(e),
            "decoded_data": "",
            "qr_type": "Unknown",
            "score": 0,
            "confidence": 0,
            "findings": [],
            "threat_dna": {},
            "recommendations": [],
        }
