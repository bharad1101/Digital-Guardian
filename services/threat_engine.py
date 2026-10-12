"""
Digital Guardian - Threat analysis engine.

Combines two sources of evidence:

1. A deterministic, rule-based indicator engine (explainable, auditable).
2. A machine-learning spam classifier (see services/ml_service.py).

Scoring method (documented and deterministic)
---------------------------------------------
  * Each rule signal contributes a fixed number of *rule points* and a
    human readable indicator. Signals are additive and each distinct
    indicator is counted once.
  * ``rule_score`` = min(sum of rule points, 100).
  * ``risk_score`` = round(0.65 * rule_score + 0.35 * ml_spam_probability)
    with documented safety overrides for high-confidence ML spam and for
    explicit credential-theft patterns.
  * ``risk_score`` is always clamped to the 0-100 range and mapped to a
    threat level:

        <= 20  SAFE
        <= 40  LOW_RISK
        <= 60  SUSPICIOUS
        <= 80  HIGH_RISK
         > 80  CRITICAL

The engine never declares content "safe" as a guarantee: low scores carry
an explicit uncertainty note.
"""

from __future__ import annotations

import re

from services.ml_service import predict as ml_predict
from services.url_analyzer import analyze_url

URL_REGEX = re.compile(r"(?:https?://|www\.)[^\s<>\"')]+", re.IGNORECASE)

RISK_LEVELS = [
    (20, "SAFE"),
    (40, "LOW_RISK"),
    (60, "SUSPICIOUS"),
    (80, "HIGH_RISK"),
    (100, "CRITICAL"),
]

LEVEL_LABELS = {
    "SAFE": "Safe",
    "LOW_RISK": "Low Risk",
    "SUSPICIOUS": "Suspicious",
    "HIGH_RISK": "High Risk",
    "CRITICAL": "Critical",
}


def score_to_level(score: int) -> str:
    for threshold, level in RISK_LEVELS:
        if score <= threshold:
            return level
    return "CRITICAL"


def normalize_level(value) -> str:
    """Normalise a stored level to canonical form (tolerant of legacy values)."""
    if not value:
        return ""
    return str(value).strip().replace(" ", "_").upper()


def level_label(value) -> str:
    """Human-readable label for any stored/legacy level value."""
    key = normalize_level(value)
    return LEVEL_LABELS.get(key, value or "Unknown")


RULES = {
    "urgency": (
        8,
        [
            "urgent", "immediately", "act now", "verify now", "within 24 hours",
            "last chance", "hurry", "expires", "suspended", "blocked",
            "right now", "limited time", "final notice", "act fast",
        ],
        "Urgency or deadline pressure language detected",
        "Urgency",
    ),
    "credentials": (
        30,
        ["otp", "password", "upi pin", "pin number", "cvv", "card number",
         "bank details", "account number", "debit card", "credit card",
         "one time password", "security code"],
        "Requests sensitive credentials (OTP, PIN, password, card data)",
        "Credential Theft",
    ),
    "bank": (
        15,
        ["bank", "sbi", "hdfc", "icici", "axis bank", "account blocked",
         "account suspended", "kyc", "bank account", "netbanking",
         "banking services"],
        "Possible banking / authority impersonation",
        "Authority Impersonation",
    ),
    "payment": (
        15,
        ["upi", "scan qr", "send money", "transfer money", "processing fee",
         "registration fee", "refund", "pay now", "payment link", "send ₹",
         "send rs", "gift card", "wire transfer", "crypto wallet"],
        "Financial or payment request detected",
        None,
    ),
    "job": (
        20,
        ["job offer", "selected for job", "registration fee", "work from home",
         "earn money", "guaranteed salary", "interview fee",
         "hiring immediately", "easy income", "part time job"],
        "Possible fake job / employment opportunity",
        "Greed",
    ),
    "prize": (
        20,
        ["you won", "winner", "lottery", "free prize", "claim reward",
         "cash prize", "congratulations", "lucky winner", "claim prize"],
        "Prize or lottery bait detected",
        "Reward / Greed",
    ),
    "fear": (
        12,
        ["police", "legal action", "arrest", "account closed", "disconnected",
         "penalty", "fine", "case registered", "warrant", "court notice"],
        "Fear-based manipulation detected",
        "Fear",
    ),
    "reward": (
        8,
        ["free money", "cash reward", "bonus", "free gift", "reward",
         "earn instantly", "double your money"],
        "Reward-based manipulation detected",
        "Reward / Greed",
    ),
    "secrecy": (
        10,
        ["do not tell", "keep this confidential", "don't tell anyone",
         "between us", "secret"],
        "Request for secrecy detected",
        "Isolation",
    ),
}

CHANNEL_PHRASES = {
    "email": (
        15,
        ["dear customer", "verify your account", "account suspended",
         "click below", "confirm identity", "security alert",
         "unusual activity", "dear user"],
        "Common phishing email pattern detected",
        "Email Phishing",
    ),
    "call": (
        20,
        ["calling from your bank", "share the otp", "customer care",
         "remote access", "download app", "screen sharing",
         "install application", "share your screen", "anydesk", "teamviewer"],
        "Suspicious call / remote-access behaviour detected",
        "Voice Fraud",
    ),
    "whatsapp": (
        12,
        ["whatsapp support", "verify whatsapp", "whatsapp account",
         "account banned", "whatsapp team"],
        "Possible WhatsApp impersonation detected",
        None,
    ),
}


def extract_urls(text: str) -> list[str]:
    return URL_REGEX.findall(text or "")


def _signal(model_score_category: str, points: int, indicator: str) -> dict:
    return {"points": points, "indicator": indicator, "category": model_score_category}


def analyze_threat(content: str, channel: str = "Message") -> dict:
    """Run the full hybrid analysis on text / a URL / a message."""
    text = (content or "").strip()
    lower = text.lower()
    channel_key = (channel or "Message").lower()

    rule_points = 0
    indicators: list[str] = []
    manipulation: list[str] = []
    scam_category = "None"
    threat_type = "No Major Threat Detected"
    evidence: list[dict] = []

    def add_indicator(message: str) -> None:
        if message not in indicators:
            indicators.append(message)

    def add_manipulation(name: str) -> None:
        if name not in manipulation:
            manipulation.append(name)

    # ---------------------------------------------------------------- rules
    for key, (points, terms, message, category) in RULES.items():
        matched = [t for t in terms if t in lower]
        if matched:
            rule_points += points
            add_indicator(message)
            evidence.append({
                "type": "rule",
                "code": key,
                "detail": message,
                "matched_terms": matched[:5],
            })
            if category in {"Urgency", "Authority Impersonation", "Fear",
                            "Reward / Greed", "Isolation", "Greed"}:
                add_manipulation(category)
            if key == "credentials":
                scam_category = "Credential Theft"
                threat_type = "Phishing / Fraud"
            elif key == "bank" and scam_category == "None":
                scam_category = "Bank / KYC Scam"
                threat_type = "Financial Fraud"
            elif key == "payment" and scam_category == "None":
                scam_category = "Payment / UPI Scam"
                threat_type = "Financial Fraud"
            elif key == "job":
                scam_category = "Job Scam"
                threat_type = "Fraud"
            elif key == "prize":
                scam_category = "Lottery / Prize Scam"
                threat_type = "Fraud"

    # Channel-specific phrasing.
    phrase_rule = CHANNEL_PHRASES.get(channel_key)
    if phrase_rule:
        points, terms, message, cat = phrase_rule
        matched = [t for t in terms if t in lower]
        if matched:
            rule_points += points
            add_indicator(message)
            evidence.append({
                "type": "rule",
                "code": f"channel:{channel_key}",
                "detail": message,
                "matched_terms": matched[:5],
            })
            if cat and scam_category == "None":
                scam_category = cat
                threat_type = cat

    if channel_key == "whatsapp" and "forwarded" in lower:
        rule_points += 5
        add_indicator("Forwarded WhatsApp content detected")
        evidence.append({"type": "rule", "code": "whatsapp_forwarded",
                         "detail": "Forwarded WhatsApp content"})

    # ---------------------------------------------------------------- URLs
    urls = extract_urls(text)
    url_reports = []
    if urls:
        rule_points += 10
        add_indicator("Contains one or more links")
        for url in urls[:5]:
            report = analyze_url(url)
            url_reports.append(report)
            rule_points += report["risk_points"]
            for message in report["indicators"]:
                add_indicator(f"Link: {message}")
            if report["risk_points"] >= 20 and scam_category == "None":
                scam_category = "Suspicious Link"
                threat_type = "Malicious URL"
            evidence.append({
                "type": "url",
                "url": url,
                "risk_points": report["risk_points"],
                "indicators": report["indicators"],
                "passive_only": True,
            })

    # URL-only channel (single URL submitted directly).
    if channel_key == "url" and not urls and text:
        report = analyze_url(text)
        url_reports.append(report)
        rule_points += report["risk_points"]
        for message in report["indicators"]:
            add_indicator(f"Link: {message}")
        if report["risk_points"] >= 20:
            scam_category = "Suspicious Link"
            threat_type = "Malicious URL"
        evidence.append({"type": "url", "url": text,
                         "risk_points": report["risk_points"],
                         "indicators": report["indicators"], "passive_only": True})
        urls = [text]

    rule_score = min(rule_points, 100)

    # ---------------------------------------------------------------- ML
    ml = ml_predict(content)
    ml_prob = ml["spam_probability"] if ml["available"] else 0.0
    if ml["available"]:
        evidence.append({
            "type": "ml",
            "detail": f"Classifier prediction: {ml['prediction']} "
                      f"({ml_prob:.1f}% spam probability)",
            "spam_probability": ml_prob,
        })

    risk_score = round(0.65 * rule_score + 0.35 * ml_prob)

    if ml.get("available"):
        if ml_prob >= 95:
            risk_score = max(risk_score, 70)
        elif ml_prob >= 85:
            risk_score = max(risk_score, 65)

    if any(term in lower for term in ("otp", "password", "cvv", "upi pin", "pin number")):
        risk_score = max(risk_score, 75)
        if any(term in lower for term in ("bank", "sbi", "hdfc", "icici", "axis", "account")):
            risk_score = max(risk_score, 85)

    risk_score = min(max(risk_score, 0), 100)
    threat_level = score_to_level(risk_score)

    if threat_level == "SAFE":
        threat_type = "No Major Threat Detected"
        scam_category = "None"

    # ---------------------------------------------------------- explanations
    recommendations = _recommendations_for(threat_level, url_reports)
    explanation, uncertainty = _build_explanation(
        threat_level, rule_score, ml, indicators, url_reports
    )

    return {
        "risk_score": risk_score,
        "rule_score": rule_score,
        "threat_level": threat_level,
        "threat_type": threat_type,
        "scam_category": scam_category,
        "ml_prediction": ml["prediction"],
        "ml_spam_probability": ml["spam_probability"],
        "ml_available": ml["available"],
        "indicators": indicators,
        "recommendations": recommendations,
        "manipulation": manipulation,
        "urls": urls,
        "url_reports": url_reports,
        "evidence": evidence,
        "explanation": explanation,
        "uncertainty": uncertainty,
    }


def _recommendations_for(threat_level: str, url_reports: list[dict]) -> list[str]:
    base = {
        "CRITICAL": [
            "Do not respond, click links, share OTP/PIN/passwords, or send money.",
            "Verify the sender through an official channel you look up yourself.",
            "If you already shared credentials, change them and contact your bank immediately.",
        ],
        "HIGH_RISK": [
            "Avoid interacting with this content until the sender and any links are independently verified.",
            "Do not enter passwords or payment details on pages reached from this message.",
        ],
        "SUSPICIOUS": [
            "Proceed carefully and verify the source before sharing personal information or paying.",
            "Treat unexpected requests as untrusted until confirmed.",
        ],
        "LOW_RISK": [
            "Some potentially suspicious characteristics were detected. Verify the sender if the request was unexpected.",
        ],
        "SAFE": [
            "No major threat indicators were detected. Continue following normal cybersecurity precautions.",
            "Never share OTPs, PINs or passwords even if a message appears legitimate.",
        ],
    }[threat_level]

    recs = list(base)
    if any(r["is_shortener"] for r in url_reports):
        recs.append("Expand shortened links with a preview tool before opening them.")
    if any(r["is_ip_literal"] for r in url_reports):
        recs.append("Be cautious of links that point to raw IP addresses instead of named websites.")
    return recs


def _build_explanation(threat_level, rule_score, ml, indicators, url_reports):
    parts = [f"Rule-based evidence produced a score of {rule_score}/100."]

    if ml["available"]:
        parts.append(
            f"The spam classifier predicted '{ml['prediction']}' with "
            f"{ml['spam_probability']:.1f}% spam probability."
        )
    else:
        parts.append(
            "The spam classifier was unavailable, so this assessment relies on "
            "rule-based evidence only."
        )

    if url_reports:
        worst = max(url_reports, key=lambda r: r["risk_points"])
        if worst["risk_points"]:
            parts.append(
                f"The most suspicious link ({worst['hostname'] or worst['url']}) "
                f"contributed {worst['risk_points']} risk points."
            )
        else:
            parts.append("The included link(s) showed no strong structural risk signals.")

    if not indicators:
        parts.append("No known fraud indicators were found in this content.")

    if threat_level in {"SAFE", "LOW_RISK"}:
        uncertainty = (
            "A low score is not a guarantee of safety. New scams may avoid known "
            "patterns, and automated analysis cannot detect every threat."
        )
    elif ml["available"]:
        uncertainty = (
            "The spam classifier is a general SMS model and may be less accurate "
            "on other languages or message types. Always verify independently."
        )
    else:
        uncertainty = (
            "Because the machine-learning model was unavailable, this assessment "
            "may under- or over-estimate risk."
        )

    return " ".join(parts), uncertainty
