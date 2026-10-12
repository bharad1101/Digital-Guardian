"""
Digital Guardian - QR payload analysis (Guardian Lens).

Classifies a decoded QR payload and runs the shared threat engine on it.
URL payloads are additionally inspected with the passive URL analyzer.
Nothing is ever opened automatically.
"""

from __future__ import annotations

from services.threat_engine import analyze_threat

# Structural QR payload types (ISO/IEC 18004 / common de-facto formats).
TYPE_URL = "URL"
TYPE_WIFI = "WiFi"
TYPE_EMAIL = "Email"
TYPE_PHONE = "Phone"
TYPE_SMS = "SMS"
TYPE_GEO = "Location"
TYPE_CONTACT = "Contact"
TYPE_OTPAUTH = "OTP Auth"
TYPE_TEXT = "Text"
TYPE_UNKNOWN = "Unknown"
TYPE_EMPTY = "Empty"

DANGEROUS_SCHEMES = ("javascript:", "data:", "file:", "intent:", "content://")


def classify_payload(payload: str) -> str:
    p = payload.strip()
    if not p:
        return TYPE_EMPTY
    low = p.lower()
    if low.startswith(DANGEROUS_SCHEMES):
        return TYPE_UNKNOWN
    if low.startswith(("http://", "https://")):
        return TYPE_URL
    if low.startswith("wifi:"):
        return TYPE_WIFI
    if low.startswith("mailto:"):
        return TYPE_EMAIL
    if low.startswith(("tel:", "callto:")):
        return TYPE_PHONE
    if low.startswith(("smsto:", "sms:")):
        return TYPE_SMS
    if low.startswith("geo:"):
        return TYPE_GEO
    if low.startswith("begin:vcard"):
        return TYPE_CONTACT
    if low.startswith("otpauth:"):
        return TYPE_OTPAUTH
    return TYPE_TEXT


def _parse_wifi(payload: str) -> dict:
    info = {"ssid": None, "security": None, "hidden": False}
    for chunk in payload[len("WIFI:"):].split(";"):
        if ":" not in chunk:
            continue
        key, _, value = chunk.partition(":")
        key = key.upper()
        if key == "S":
            info["ssid"] = value
        elif key == "T":
            info["security"] = value or "nopass"
        elif key == "H":
            info["hidden"] = value.lower() in ("true", "1")
    return info


def analyze_qr(payload: str) -> dict:
    """Return a complete analysis for a decoded QR payload."""
    payload = (payload or "").strip()
    payload_type = classify_payload(payload)

    if not payload:
        return {
            "payload": "",
            "payload_type": TYPE_EMPTY,
            "payload_url": None,
            "url_report": None,
            "risk_score": 0,
            "rule_score": 0,
            "threat_level": "SAFE",
            "threat_type": "No Data",
            "scam_category": "None",
            "ml_prediction": "UNKNOWN",
            "ml_spam_probability": 0.0,
            "ml_available": False,
            "indicators": ["QR code contained no readable data"],
            "recommendations": ["Re-scan the QR code or enter the payload manually."],
            "manipulation": [],
            "urls": [],
            "evidence": [],
            "explanation": "The QR code did not contain decodable data.",
            "uncertainty": None,
        }

    channel = "URL" if payload_type == TYPE_URL else "Message"
    base = analyze_threat(payload, channel=channel)

    indicators = list(base["indicators"])
    recommendations = list(base["recommendations"])
    payload_url = payload if payload_type == TYPE_URL else None
    url_report = None

    def add(message: str) -> None:
        if message not in indicators:
            indicators.append(message)

    if payload_type == TYPE_URL:
        url_report = base["url_reports"][0] if base["url_reports"] else None
        if not base["url_reports"]:
            from services.url_analyzer import analyze_url

            url_report = analyze_url(payload)

    elif payload_type == TYPE_WIFI:
        wifi = _parse_wifi(payload)
        add(f"QR code configures Wi-Fi access for network '{wifi['ssid'] or 'unknown'}'")
        if wifi["security"] in (None, "", "nopass"):
            add("Wi-Fi network is open (no password) and may be untrusted")
            recommendations.append(
                "Avoid connecting to unknown open Wi-Fi networks found via QR codes."
            )
        else:
            add(f"Wi-Fi network uses {wifi['security']} encryption")

    elif payload_type == TYPE_EMAIL:
        add("QR code opens a pre-filled email (mailto)")
        recommendations.append("Verify the recipient address before sending any email.")

    elif payload_type == TYPE_PHONE:
        add("QR code initiates a phone call")
        recommendations.append("Confirm the phone number is legitimate before calling.")

    elif payload_type == TYPE_SMS:
        add("QR code opens a pre-filled SMS message")
        recommendations.append(
            "Do not send SMS codes or payment instructions to unverified numbers."
        )

    elif payload_type == TYPE_OTPAUTH:
        add("QR code adds a two-factor authentication account")
        recommendations.append(
            "Only scan 2FA provisioning codes from services you are actively setting up."
        )

    elif payload_type == TYPE_GEO:
        add("QR code points to a geographic location")
    elif payload_type == TYPE_CONTACT:
        add("QR code contains a contact card (vCard)")
    else:
        # Plain text or an unusual/unsafe scheme.
        if payload.lower().startswith(DANGEROUS_SCHEMES):
            add("QR code uses a non-web scheme that can execute or embed content")
            recommendations.append(
                "Do not open QR payloads using javascript:, data: or intent: schemes."
            )

    result = dict(base)
    result.update({
        "payload": payload,
        "payload_type": payload_type,
        "payload_url": payload_url,
        "url_report": url_report,
        "indicators": indicators,
        "recommendations": recommendations,
    })
    return result
