import os
import re
import joblib


MODEL_FILE = "ml/spam_model.pkl"


# =========================================================
# LOAD TRAINED ML MODEL
# =========================================================

if os.path.exists(MODEL_FILE):

    ml_model = joblib.load(
        MODEL_FILE
    )

else:

    ml_model = None


# =========================================================
# MACHINE LEARNING PREDICTION
# =========================================================

def get_ml_prediction(text):

    if ml_model is None:

        return {
            "prediction": "UNKNOWN",
            "spam_probability": 0.0
        }


    prediction = ml_model.predict(
        [text]
    )[0]


    probabilities = ml_model.predict_proba(
        [text]
    )[0]


    classes = ml_model.classes_


    probability_map = dict(
        zip(
            classes,
            probabilities
        )
    )


    spam_probability = float(
        probability_map.get(
            "spam",
            0
        ) * 100
    )


    return {
        "prediction": str(
            prediction
        ).upper(),

        "spam_probability": round(
            spam_probability,
            2
        )
    }


# =========================================================
# MAIN HYBRID THREAT ENGINE
# =========================================================

def analyze_threat(content, channel):

    text = content.lower().strip()

    rule_score = 0

    indicators = []

    manipulation = []

    scam_category = "Unknown"

    threat_type = "Safe / Low Risk"


    # =====================================================
    # MACHINE LEARNING ANALYSIS
    # =====================================================

    ml_result = get_ml_prediction(
        content
    )


    ml_prediction = ml_result[
        "prediction"
    ]


    ml_spam_probability = ml_result[
        "spam_probability"
    ]


    # =====================================================
    # URGENCY DETECTION
    # =====================================================

    urgency_words = [
        "urgent",
        "immediately",
        "act now",
        "verify now",
        "today",
        "within 24 hours",
        "last chance",
        "hurry",
        "expires",
        "suspended",
        "blocked",
        "right now",
        "limited time"
    ]


    if any(
        word in text
        for word in urgency_words
    ):

        rule_score += 8

        indicators.append(
            "Urgency language detected"
        )

        manipulation.append(
            "Urgency"
        )


    # =====================================================
    # SENSITIVE INFORMATION DETECTION
    # =====================================================

    sensitive_words = [
        "otp",
        "password",
        "upi pin",
        "pin number",
        "cvv",
        "card number",
        "bank details",
        "account number",
        "debit card",
        "credit card"
    ]


    for word in sensitive_words:

        if word in text:

            rule_score += 30

            indicators.append(
                f"Requests sensitive information: {word}"
            )

            scam_category = (
                "Credential Theft"
            )

            threat_type = (
                "Phishing / Fraud"
            )

            break


    # =====================================================
    # BANK / KYC IMPERSONATION
    # =====================================================

    bank_words = [
        "bank",
        "sbi",
        "hdfc",
        "icici",
        "axis bank",
        "account blocked",
        "account suspended",
        "kyc",
        "bank account",
        "banking services"
    ]


    if any(
        word in text
        for word in bank_words
    ):

        rule_score += 15

        indicators.append(
            "Possible banking impersonation detected"
        )

        manipulation.append(
            "Authority Impersonation"
        )

        scam_category = (
            "Bank / KYC Scam"
        )

        threat_type = (
            "Financial Fraud"
        )


    # =====================================================
    # PAYMENT / UPI SCAM
    # =====================================================

    payment_words = [
        "upi",
        "scan qr",
        "payment",
        "send money",
        "transfer money",
        "processing fee",
        "registration fee",
        "refund",
        "pay now",
        "payment link",
        "send ₹",
        "send rs"
    ]


    if any(
        word in text
        for word in payment_words
    ):

        rule_score += 15

        indicators.append(
            "Financial or payment request detected"
        )

        if scam_category == "Unknown":

            scam_category = (
                "Payment / UPI Scam"
            )

        threat_type = (
            "Financial Fraud"
        )


    # =====================================================
    # JOB SCAM DETECTION
    # =====================================================

    job_words = [
        "job offer",
        "selected for job",
        "registration fee",
        "work from home",
        "earn money",
        "guaranteed salary",
        "interview fee",
        "hiring immediately",
        "easy income"
    ]


    if any(
        word in text
        for word in job_words
    ):

        rule_score += 20

        indicators.append(
            "Possible fake job opportunity detected"
        )

        scam_category = (
            "Job Scam"
        )

        threat_type = (
            "Fraud"
        )


    # =====================================================
    # LOTTERY / PRIZE SCAM
    # =====================================================

    prize_words = [
        "you won",
        "winner",
        "lottery",
        "free prize",
        "claim reward",
        "cash prize",
        "congratulations",
        "lucky winner",
        "claim prize"
    ]


    if any(
        word in text
        for word in prize_words
    ):

        rule_score += 20

        indicators.append(
            "Prize or lottery bait detected"
        )

        scam_category = (
            "Lottery / Prize Scam"
        )

        threat_type = (
            "Fraud"
        )


    # =====================================================
    # FEAR MANIPULATION
    # =====================================================

    fear_words = [
        "police",
        "legal action",
        "arrest",
        "account closed",
        "disconnected",
        "penalty",
        "fine",
        "blocked",
        "case registered",
        "warrant"
    ]


    if any(
        word in text
        for word in fear_words
    ):

        rule_score += 12

        indicators.append(
            "Fear-based manipulation detected"
        )

        manipulation.append(
            "Fear"
        )


    # =====================================================
    # REWARD / GREED MANIPULATION
    # =====================================================

    reward_words = [
        "free money",
        "cash reward",
        "bonus",
        "free gift",
        "reward",
        "prize",
        "earn instantly"
    ]


    if any(
        word in text
        for word in reward_words
    ):

        rule_score += 8

        indicators.append(
            "Reward-based manipulation detected"
        )

        manipulation.append(
            "Reward / Greed"
        )


    # =====================================================
    # URL DETECTION
    # =====================================================

    urls = re.findall(
        r"https?://[^\s]+|www\.[^\s]+",
        text
    )


    if urls:

        rule_score += 10

        indicators.append(
            "Contains one or more links"
        )


    suspicious_url_terms = [
        "login",
        "verify",
        "secure",
        "update",
        "free",
        "bonus",
        "wallet",
        "bank",
        "kyc",
        "account",
        "claim"
    ]


    for url in urls:

        if any(
            term in url
            for term in suspicious_url_terms
        ):

            rule_score += 10

            indicators.append(
                "Suspicious URL characteristics detected"
            )

            break


    # =====================================================
    # WHATSAPP ANALYSIS
    # =====================================================

    if channel.lower() == "whatsapp":

        if "forwarded" in text:

            rule_score += 5

            indicators.append(
                "Forwarded WhatsApp content detected"
            )


        whatsapp_terms = [
            "whatsapp support",
            "verify whatsapp",
            "whatsapp account",
            "account banned"
        ]


        if any(
            term in text
            for term in whatsapp_terms
        ):

            rule_score += 12

            indicators.append(
                "Possible WhatsApp impersonation detected"
            )


    # =====================================================
    # EMAIL PHISHING
    # =====================================================

    if channel.lower() == "email":

        email_phrases = [
            "dear customer",
            "verify your account",
            "account suspended",
            "click below",
            "confirm identity",
            "security alert",
            "unusual activity"
        ]


        if any(
            phrase in text
            for phrase in email_phrases
        ):

            rule_score += 15

            indicators.append(
                "Common phishing email pattern detected"
            )

            threat_type = (
                "Email Phishing"
            )


    # =====================================================
    # CALL TRANSCRIPT ANALYSIS
    # =====================================================

    if channel.lower() == "call":

        call_phrases = [
            "calling from your bank",
            "share the otp",
            "customer care",
            "remote access",
            "download app",
            "screen sharing",
            "install application",
            "share your screen"
        ]


        if any(
            phrase in text
            for phrase in call_phrases
        ):

            rule_score += 20

            indicators.append(
                "Suspicious call behaviour detected"
            )

            scam_category = (
                "Call Impersonation Scam"
            )

            threat_type = (
                "Voice Fraud"
            )


    # =====================================================
    # URL-ONLY CHANNEL
    # =====================================================

    if channel.lower() == "url":

        if urls:

            if len(text) < 200:

                rule_score += 5


        suspicious_domains = [
            ".xyz",
            ".top",
            ".click",
            ".loan",
            ".work",
            ".support"
        ]


        if any(
            domain in text
            for domain in suspicious_domains
        ):

            rule_score += 15

            indicators.append(
                "Potentially suspicious domain extension detected"
            )

            scam_category = (
                "Suspicious Website"
            )

            threat_type = (
                "Possible Phishing URL"
            )


    # =====================================================
    # LIMIT RULE SCORE
    # =====================================================

    rule_score = min(
        rule_score,
        100
    )


    # =====================================================
    # HYBRID AI RISK SCORE
    # =====================================================

    hybrid_score = round(

        (
            rule_score * 0.65
        )

        +

        (
            ml_spam_probability * 0.35
        )

    )


    # =====================================================
    # SAFETY OVERRIDES
    # =====================================================

    if ml_spam_probability >= 85:

        hybrid_score = max(
            hybrid_score,
            65
        )


    if ml_spam_probability >= 95:

        hybrid_score = max(
            hybrid_score,
            70
        )


    credential_terms = [
        "otp",
        "password",
        "cvv",
        "upi pin"
    ]


    if any(
        word in text
        for word in credential_terms
    ):

        hybrid_score = max(
            hybrid_score,
            75
        )


    if (
        any(word in text for word in credential_terms)
        and
        any(word in text for word in bank_words)
    ):

        hybrid_score = max(
            hybrid_score,
            85
        )


    hybrid_score = min(
        hybrid_score,
        100
    )


    # =====================================================
    # THREAT LEVEL
    # =====================================================

    if hybrid_score <= 20:

        threat_level = "SAFE"

    elif hybrid_score <= 40:

        threat_level = "LOW RISK"

    elif hybrid_score <= 60:

        threat_level = "SUSPICIOUS"

    elif hybrid_score <= 80:

        threat_level = "HIGH RISK"

    else:

        threat_level = "CRITICAL"


    # =====================================================
    # SAFE DEFAULT
    # =====================================================

    if hybrid_score <= 20:

        threat_type = (
            "No Major Threat Detected"
        )

        scam_category = (
            "None"
        )


        if not indicators:

            indicators.append(
                "No major fraud indicators were detected"
            )


    # =====================================================
    # ADD ML EXPLANATION
    # =====================================================

    if ml_prediction == "SPAM":

        indicators.append(
            "Machine learning model classified this content as spam"
        )


    elif ml_prediction == "HAM":

        indicators.append(
            "Machine learning model classified this content as normal"
        )


    # =====================================================
    # REMOVE DUPLICATES
    # =====================================================

    manipulation = list(
        dict.fromkeys(
            manipulation
        )
    )


    indicators = list(
        dict.fromkeys(
            indicators
        )
    )


    # =====================================================
    # SECURITY RECOMMENDATION
    # =====================================================

    if threat_level == "CRITICAL":

        recommendation = (
            "Do not respond, click links, share credentials, "
            "send money, or provide OTP/PIN information. "
            "Verify the sender through an official channel."
        )


    elif threat_level == "HIGH RISK":

        recommendation = (
            "Avoid interacting with this content until the "
            "sender, link, phone number, or request has been "
            "independently verified."
        )


    elif threat_level == "SUSPICIOUS":

        recommendation = (
            "Proceed carefully and verify the source before "
            "sharing personal information or making any payment."
        )


    elif threat_level == "LOW RISK":

        recommendation = (
            "Some potentially suspicious characteristics were detected. "
            "Verify the sender if the request is unexpected."
        )


    else:

        recommendation = (
            "No major threat was detected. Continue following "
            "normal cybersecurity precautions."
        )


    # =====================================================
    # RETURN COMPLETE ANALYSIS
    # =====================================================

    return {

        "risk_score": hybrid_score,

        "rule_score": rule_score,

        "ml_prediction": ml_prediction,

        "ml_spam_probability": ml_spam_probability,

        "threat_level": threat_level,

        "threat_type": threat_type,

        "scam_category": scam_category,

        "indicators": indicators,

        "manipulation": manipulation,

        "recommendation": recommendation,

        "urls": urls
    }
