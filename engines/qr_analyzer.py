import cv2

from engines.url_analyzer import analyze_url


def analyze_qr(image_path):

    try:

        detector = cv2.QRCodeDetector()

        image = cv2.imread(image_path)

        data, bbox, _ = detector.detectAndDecode(image)

        if not data:

            return {
                "success": False,
                "message": "No QR code detected.",
                "url": "",
                "score": 0,
                "findings": []
            }

        url_score, url_findings = analyze_url(data)

        return {
            "success": True,
            "message": "QR code decoded successfully.",
            "url": data,
            "score": url_score,
            "findings": url_findings
        }

    except Exception as e:

        return {
            "success": False,
            "message": str(e),
            "url": "",
            "score": 0,
            "findings": []
        }