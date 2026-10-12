"""
Digital Guardian - Machine learning service.

Loads the trained SMS-spam classifier (a scikit-learn Pipeline of
TfidfVectorizer + LogisticRegression) once at import time and exposes a
small prediction API.

If the model file is missing or fails to load, the service degrades
gracefully: it reports ``available = False`` and a neutral prediction so
the rest of the analysis engine can continue with rule-based evidence.
The application never pretends the model ran when it did not.
"""

from __future__ import annotations

import logging
import os
import threading

logger = logging.getLogger(__name__)

_lock = threading.Lock()
_model = None
_model_path: str | None = None
_load_attempted = False
_load_error: str | None = None

MAX_INPUT_CHARS = 10_000


def _resolve_path() -> str:
    from pathlib import Path

    from flask import current_app

    try:
        return current_app.config["ML_MODEL_PATH"]
    except Exception:  # outside application context
        base = Path(__file__).resolve().parent.parent
        return os.getenv("ML_MODEL_PATH", str(base / "ml" / "spam_model.pkl"))


def load_model(force: bool = False):
    """Load (and cache) the model. Safe to call repeatedly."""
    global _model, _model_path, _load_attempted, _load_error

    with _lock:
        if _load_attempted and not force:
            return _model

        _load_attempted = True
        _model_path = _resolve_path()

        if not os.path.exists(_model_path):
            _model = None
            _load_error = f"Model file not found at {_model_path}"
            logger.warning("ML model unavailable: %s", _load_error)
            return _model

        try:
            import joblib

            _model = joblib.load(_model_path)
            _load_error = None
            logger.info("ML model loaded from %s", _model_path)
        except Exception as exc:  # pragma: no cover - defensive
            _model = None
            _load_error = str(exc)
            logger.exception("Failed to load ML model")

        return _model


def model_status() -> dict:
    """Report model availability and metadata without predicting."""
    model = load_model()
    classes = []
    if model is not None:
        try:
            classes = [str(c) for c in getattr(model, "classes_", [])]
        except Exception:
            classes = []
    return {
        "available": model is not None,
        "path": _model_path,
        "error": _load_error,
        "classes": classes,
        "type": type(model).__name__ if model is not None else None,
    }


def predict(text: str) -> dict:
    """Return the model prediction for a piece of text.

    Always returns a dict with the keys ``prediction``, ``spam_probability``
    and ``available``. ``prediction`` is one of "SPAM", "HAM" or "UNKNOWN".
    """
    model = load_model()

    if model is None:
        return {
            "available": False,
            "prediction": "UNKNOWN",
            "spam_probability": 0.0,
        }

    cleaned = (text or "").strip()
    if not cleaned:
        return {
            "available": True,
            "prediction": "HAM",
            "spam_probability": 0.0,
        }

    cleaned = cleaned[:MAX_INPUT_CHARS]

    try:
        prediction = str(model.predict([cleaned])[0]).upper()

        spam_probability = 0.0
        proba = getattr(model, "predict_proba", None)
        if callable(proba):
            probabilities = proba([cleaned])[0]
            classes = [str(c) for c in getattr(model, "classes_", [])]
            mapping = dict(zip(classes, probabilities))
            spam_probability = float(mapping.get("spam", 0.0)) * 100.0

        return {
            "available": True,
            "prediction": prediction,
            "spam_probability": round(spam_probability, 2),
        }
    except Exception as exc:  # pragma: no cover - defensive
        logger.exception("ML prediction failed")
        return {
            "available": False,
            "prediction": "UNKNOWN",
            "spam_probability": 0.0,
            "error": str(exc),
        }
