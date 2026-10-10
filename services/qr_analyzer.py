"""
Digital Guardian - QR Analyzer

Analyzes QR-code payloads before the user opens them.
"""

from urllib.parse import urlparse


def analyze_qr_payload(payload):
    """
    Analyze the content extracted from a QR code.

    Returns:
        dict: QR security analysis
    """

    payload = (payload or "").strip()

    result = {
        "payload": payload,
        "payload_type": "Unknown",
        "url": None,
        "indicators": []
    }

    # ---------------------------------------------------------
    # Empty payload
    # ---------------------------------------------------------

    if not payload:
        result["payload_type"] = "Empty"

        result["indicators"].append(
            "QR code contained no readable data"
        )

        return result

    # ---------------------------------------------------------
    # URL detection
    # ---------------------------------------------------------

    if payload.startswith(("http://", "https://")):

        result["payload_type"] = "URL"
        result["url"] = payload

        parsed = urlparse(payload)

        hostname = parsed.hostname or ""

        # -----------------------------------------------------
        # Non-HTTPS URL
        # -----------------------------------------------------

        if parsed.scheme.lower() == "http":

            result["indicators"].append(
                "QR code points to a non-HTTPS URL"
            )

        # -----------------------------------------------------
        # Direct IP address
        # -----------------------------------------------------

        if hostname.replace(".", "").isdigit():

            result["indicators"].append(
                "QR code points directly to an IP address"
            )

        # -----------------------------------------------------
        # @ symbol in URL
        # -----------------------------------------------------

        if "@" in payload:

            result["indicators"].append(
                "URL contains an '@' character that may hide the real destination"
            )

        # -----------------------------------------------------
        # Suspicious keywords
        # -----------------------------------------------------

        suspicious_keywords = [
            "login",
            "verify",
            "verification",
            "password",
            "otp",
            "reward",
            "prize",
            "winner",
            "claim",
            "urgent",
            "bank",
            "payment",
            "wallet",
            "account"
        ]

        lower_url = payload.lower()

        detected_keywords = [
            keyword
            for keyword in suspicious_keywords
            if keyword in lower_url
        ]

        if detected_keywords:

            result["indicators"].append(
                "Suspicious keywords detected in QR destination"
            )

    # ---------------------------------------------------------
    # Non-URL QR content
    # ---------------------------------------------------------

    else:

        result["payload_type"] = "Text"

        lower_payload = payload.lower()

        suspicious_keywords = [
            "otp",
            "password",
            "verify",
            "login",
            "payment",
            "bank",
            "prize",
            "winner",
            "urgent"
        ]

        if any(
            keyword in lower_payload
            for keyword in suspicious_keywords
        ):

            result["indicators"].append(
                "Potentially sensitive or suspicious instructions detected"
            )

    return result
