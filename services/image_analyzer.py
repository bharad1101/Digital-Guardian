"""
Digital Guardian - Image / screenshot analysis.

Pipeline:
  1. Validate the uploaded file (type, size, dimensions).
  2. Optionally decode a QR code contained in the image. The web client
     decodes QR codes in the browser (jsQR) and passes the payload here;
     the server also tries server-side decoding when the optional ``pyzbar``
     dependency is installed.
  3. Extract text with OCR (pytesseract + the tesseract binary) when
     available.
  4. Analyse whatever text/payload was recovered with the shared engines.

The result always states which sources ran, which were unavailable, and
the limitations of the assessment. Images are never written to disk.
"""

from __future__ import annotations

import io
import logging

from services.qr_analyzer import analyze_qr
from services.threat_engine import analyze_threat, extract_urls

logger = logging.getLogger(__name__)

MAX_DIMENSION_FALLBACK = 8000


# --------------------------------------------------------------- capabilities

def ocr_available() -> bool:
    try:
        import pytesseract

        pytesseract.get_tesseract_version()
        return True
    except Exception:
        return False


def server_qr_available() -> bool:
    try:
        import pyzbar.pyzbar  # noqa: F401

        return True
    except Exception:
        return False


def _decode_qr_server(image) -> tuple[str | None, str]:
    """Attempt server-side QR decode. Returns (payload, status)."""
    try:
        from pyzbar.pyzbar import decode as zbar_decode

        decoded = zbar_decode(image)
        for item in decoded:
            if item.type == "QRCODE":
                return item.data.decode("utf-8", "replace"), "decoded"
        return None, "no_qr_detected"
    except Exception as exc:
        return None, f"unavailable: {exc}"


def ocr_image(image, lang: str = "eng", max_chars: int = 4000) -> tuple[str | None, str]:
    """Run OCR. Returns (text, status)."""
    try:
        import pytesseract

        text = pytesseract.image_to_string(image, lang=lang)
        text = (text or "").strip()
        return text[:max_chars], "decoded"
    except Exception as exc:
        return None, f"unavailable: {exc}"


# --------------------------------------------------------------- validation

def load_and_validate(data: bytes, allowed_exts, max_bytes: int, max_dimension: int):
    """Return (image, error). Image is a PIL RGB image."""
    from PIL import Image

    if not data:
        return None, "Empty file."
    if len(data) > max_bytes:
        return None, f"File is larger than the {max_bytes // 1024} KB limit."

    try:
        image = Image.open(io.BytesIO(data))
        image.verify()
        # verify() consumes the file; reopen for use.
        image = Image.open(io.BytesIO(data))
    except Exception:
        return None, "File is not a readable image."

    width, height = image.size
    if width * height == 0:
        return None, "Image has zero dimensions."
    if max(width, height) > (max_dimension or MAX_DIMENSION_FALLBACK):
        return None, (
            f"Image is too large ({width}x{height}); maximum dimension is "
            f"{max_dimension}px."
        )

    if image.mode not in ("RGB", "L"):
        image = image.convert("RGB")
    return image, None


# --------------------------------------------------------------- orchestration

def analyze_image(data: bytes, filename: str = "", allowed_exts=None,
                  max_bytes: int = 8 * 1024 * 1024, max_dimension: int = 8000,
                  client_qr_payload: str | None = None,
                  ocr_enabled: bool = True, ocr_lang: str = "eng",
                  ocr_max_chars: int = 4000) -> dict:
    allowed_exts = allowed_exts or {"png", "jpg", "jpeg", "gif", "bmp", "webp", "tiff"}

    sources = {
        "qr": {"ran": False, "status": "not_attempted", "source": None},
        "ocr": {"ran": False, "status": "not_attempted", "source": None},
    }
    limitations: list[str] = []

    image, error = load_and_validate(data, allowed_exts, max_bytes, max_dimension)
    if error:
        return {"success": False, "error": error}

    width, height = image.size

    # -- QR -------------------------------------------------------------
    qr_payload = None
    if client_qr_payload and client_qr_payload.strip():
        qr_payload = client_qr_payload.strip()
        sources["qr"] = {"ran": True, "status": "decoded", "source": "client"}
    elif server_qr_available():
        payload, status = _decode_qr_server(image)
        sources["qr"] = {"ran": True, "status": status, "source": "server"}
        qr_payload = payload
    else:
        sources["qr"] = {"ran": False,
                         "status": "unavailable (server QR decoding not installed)",
                         "source": None}
        limitations.append(
            "Server-side QR decoding is unavailable in this environment; "
            "QR codes in images are decoded in the browser where supported."
        )

    # -- OCR ------------------------------------------------------------
    ocr_text = None
    if ocr_enabled and ocr_available():
        ocr_text, status = ocr_image(image, lang=ocr_lang, max_chars=ocr_max_chars)
        sources["ocr"] = {"ran": True, "status": status, "source": "pytesseract"}
        if not ocr_text:
            limitations.append("OCR ran but found no readable text in the image.")
    else:
        sources["ocr"] = {"ran": False,
                          "status": "unavailable (tesseract not installed)",
                          "source": None}
        limitations.append(
            "OCR is unavailable in this environment, so text embedded in the "
            "image could not be extracted."
        )

    # -- Analyse recovered content --------------------------------------
    analysis = None
    analysed_kind = None
    if qr_payload:
        analysis = analyze_qr(qr_payload)
        analysed_kind = "qr"
    elif ocr_text:
        urls = extract_urls(ocr_text)
        # Prefer QR/URL analysis when the OCR text is essentially one URL.
        if urls and (len(urls) == 1 and len(ocr_text) <= len(urls[0]) + 40):
            analysis = analyze_qr(urls[0])
            analysed_kind = "url"
        else:
            analysis = analyze_threat(ocr_text, channel="Message")
            analysis["recommendations"] = analysis.get("recommendations", [])
            analysed_kind = "text"

    if analysis is None:
        analysis = {
            "risk_score": 0,
            "rule_score": 0,
            "threat_level": "SAFE",
            "threat_type": "No Content Analysed",
            "scam_category": "None",
            "ml_prediction": "UNKNOWN",
            "ml_spam_probability": 0.0,
            "ml_available": False,
            "indicators": [],
            "recommendations": [
                "No readable text or QR code was found. Try a clearer image."
            ],
            "manipulation": [],
            "urls": [],
            "evidence": [],
            "explanation": "No analysable content was recovered from the image.",
            "uncertainty": None,
        }
        indicators = list(analysis["indicators"])
    else:
        indicators = list(analysis.get("indicators", []))

    indicators.extend(f"Limitation: {note}" for note in limitations)
    if ocr_text and analysed_kind == "text":
        indicators.append("Findings derived from OCR text extracted from the image")
    if qr_payload:
        indicators.append("Findings derived from a QR code decoded from the image")

    result = dict(analysis)
    result.update({
        "input_type": "image",
        "width": width,
        "height": height,
        "filename": filename,
        "sources": sources,
        "limitations": limitations,
        "qr_payload": qr_payload,
        "ocr_text": ocr_text,
        "analysed_kind": analysed_kind,
        "indicators": indicators,
    })
    return {"success": True, "result": result}
