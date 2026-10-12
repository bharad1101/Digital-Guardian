"""
Digital Guardian - URL analysis.

This module performs *passive* URL inspection: it parses and normalises a
URL and reports structural risk signals without contacting the network.
It also contains a hardened SSRF-guarded fetch helper for optional remote
inspection (disabled unless ENABLE_REMOTE_URL_INSPECTION is set).

Security notes:
  * User-supplied URLs are treated as untrusted input.
  * The SSRF guard validates *every* resolved address with the ipaddress
    module (not a string check) and re-validates after each redirect.
  * Remote inspection is off by default; passive analysis is always safe.
"""

from __future__ import annotations

import ipaddress
import logging
import re
import socket
from urllib.parse import parse_qs, unquote, urlparse

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------- constants

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "shorturl.at", "tiny.cc", "rb.gy", "shorte.st",
    "adf.ly", "bl.ink", "lnkd.in", "s.id", "v.gd", "clck.ru", "surl.li",
}

SUSPICIOUS_TLDS = {
    ".xyz", ".top", ".click", ".loan", ".work", ".support", ".gq", ".tk",
    ".ml", ".cf", ".ga", ".buzz", ".rest", ".zip", ".mov", ".country",
    ".kim", ".science", ".party", ".review", ".stream",
}

SUSPICIOUS_PATH_TERMS = {
    "login", "signin", "verify", "verification", "secure", "update", "confirm",
    "account", "bank", "kyc", "wallet", "password", "credential", "otp",
    "claim", "reward", "prize", "winner", "gift", "bonus", "refund", "invoice",
    "payment", "pay", "unlock", "recover", "suspend", "urgent", "free",
}

BRAND_TERMS = {
    "paypal", "apple", "google", "microsoft", "amazon", "netflix", "facebook",
    "instagram", "whatsapp", "sbi", "hdfc", "icici", "axis", "netbanking",
    "binance", "coinbase", "metamask", "dhl", "fedex", "irs", "hmrc",
}

NON_WEB_SCHEMES = {
    "javascript", "data", "file", "ftp", "tel", "sms", "mailto", "intent",
    "market", "content", "blob",
}

UNUSUAL_PORT_RISK = {21, 22, 23, 25, 445, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080, 8443}


def _is_ip_literal(host: str) -> bool:
    if not host:
        return False
    candidate = host.strip("[]")
    try:
        ipaddress.ip_address(candidate)
        return True
    except ValueError:
        return False


def _ip_kind(host: str) -> str:
    """Classify an IP literal: public / private / loopback / link_local / reserved / metadata."""
    try:
        ip = ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return "hostname"

    if ip.is_loopback:
        return "loopback"
    if ip.is_link_local:
        return "link_local"
    if ip.is_private:
        return "private"
    if ip.is_reserved or ip.is_multicast or ip.is_unspecified:
        return "reserved"
    return "public"


def is_public_ip(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
        return False
    if ip.is_multicast or ip.is_unspecified:
        return False
    # AWS/GCP/Azure metadata endpoint
    if str(ip) == "169.254.169.254":
        return False
    return True


def analyze_url(raw_url: str) -> dict:
    """Passive structural analysis of a URL. Never performs network I/O."""
    result = {
        "url": raw_url,
        "valid": False,
        "scheme": None,
        "hostname": None,
        "port": None,
        "path": None,
        "is_https": False,
        "is_ip_literal": False,
        "ip_kind": None,
        "has_userinfo": False,
        "has_punycode": False,
        "is_shortener": False,
        "shortener_name": None,
        "tld": None,
        "suspicious_keywords": [],
        "brand_impersonation": [],
        "indicators": [],
        "risk_points": 0,
        "passive_only": True,
        "note": None,
    }

    url = (raw_url or "").strip()
    if not url:
        result["indicators"].append("Empty URL")
        return result

    # Add a scheme if the user pasted a bare host.
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.\-]*:", url):
        url = "http://" + url

    try:
        parsed = urlparse(url)
    except ValueError:
        result["indicators"].append("URL could not be parsed")
        return result

    scheme = (parsed.scheme or "").lower()
    hostname = (parsed.hostname or "").lower()
    result.update(
        scheme=scheme,
        hostname=hostname,
        port=parsed.port,
        path=parsed.path,
        is_https=scheme == "https",
        valid=bool(hostname),
    )

    def add(points, message):
        result["risk_points"] += points
        if message not in result["indicators"]:
            result["indicators"].append(message)

    # -- Non web schemes -------------------------------------------------
    if scheme in NON_WEB_SCHEMES:
        add(15, f"Non-web URL scheme detected: {scheme}")
        result["note"] = f"scheme '{scheme}' does not open a normal webpage"
        return result

    if scheme not in {"http", "https"}:
        add(10, f"Unusual URL scheme: {scheme or 'none'}")

    if not hostname:
        add(20, "URL has no valid hostname")
        return result

    # -- IP literal destination -----------------------------------------
    if _is_ip_literal(hostname):
        result["is_ip_literal"] = True
        kind = _ip_kind(hostname)
        result["ip_kind"] = kind
        if kind == "public":
            add(20, "URL points directly to an IP address instead of a domain name")
        else:
            add(35, f"URL points to a non-public IP address ({kind})")

    # -- Userinfo component (user:pass@host) -----------------------------
    if parsed.username or parsed.password or "@" in (parsed.netloc or ""):
        result["has_userinfo"] = True
        add(25, "URL contains a user-information ('@') component that can mask the real host")

    # -- Punycode / IDN --------------------------------------------------
    if hostname.startswith("xn--") or "xn--" in hostname:
        result["has_punycode"] = True
        add(20, "Hostname uses punycode (xn--) and may imitate another brand")

    # -- Port ------------------------------------------------------------
    if parsed.port and parsed.port not in (80, 443):
        if parsed.port in UNUSUAL_PORT_RISK:
            add(12, f"Connection to a non-standard port ({parsed.port})")
        else:
            add(6, f"URL specifies a non-standard port ({parsed.port})")

    # -- HTTPS -----------------------------------------------------------
    if scheme == "http":
        add(8, "URL does not use HTTPS")

    # -- Shortener -------------------------------------------------------
    bare = hostname[4:] if hostname.startswith("www.") else hostname
    if bare in SHORTENERS:
        result["is_shortener"] = True
        result["shortener_name"] = bare
        add(15, f"URL is a link shortener ({bare}); the final destination is hidden")

    # -- TLD -------------------------------------------------------------
    parts = bare.split(".")
    tld = "." + parts[-1] if len(parts) > 1 else None
    result["tld"] = tld
    if tld in SUSPICIOUS_TLDS:
        add(12, f"Hostname uses a frequently abused top-level domain ({tld})")

    # -- Excessive length / hyphens / digits -----------------------------
    if len(url) > 120:
        add(6, "Unusually long URL")
    if bare.count("-") >= 4:
        add(10, "Hostname contains an excessive number of hyphens")
    if sum(c.isdigit() for c in bare) >= 5:
        add(8, "Hostname contains an unusual number of digits")

    # -- Suspicious keywords in path/query -------------------------------
    haystack = unquote(parsed.path or "").lower() + " " + unquote(parsed.query or "").lower()
    found = sorted({term for term in SUSPICIOUS_PATH_TERMS if term in haystack})
    if found:
        result["suspicious_keywords"] = found
        add(10, "URL path or query contains account/credential/payment bait terms")

    # Brand appearing in a subdomain of an unrelated domain is a classic trick.
    registrable = ".".join(parts[-2:]) if len(parts) >= 2 else bare
    brand_hits = sorted({b for b in BRAND_TERMS if b in bare and b not in registrable})
    if brand_hits:
        result["brand_impersonation"] = brand_hits
        add(18, "A well-known brand name appears in a subdomain of an unrelated domain")

    if result["is_ip_literal"]:
        result["note"] = "Destination is an IP address; the owner and certificate cannot be verified"
    elif result["is_shortener"]:
        result["note"] = "Shortened links must be expanded before the real destination is known"

    result["risk_points"] = min(result["risk_points"], 100)
    return result


# ---------------------------------------------------------------- SSRF guard

class SSRFError(Exception):
    """Raised when a URL fails the SSRF safety check."""


def _resolve(host: str, port: int) -> list[str]:
    try:
        infos = socket.getaddrinfo(host, port or None, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise SSRFError(f"DNS resolution failed for {host}: {exc}") from exc
    return sorted({info[4][0] for info in infos})


def assert_url_is_safe(url: str) -> str:
    """Validate a URL is safe for outbound requests. Raises SSRFError."""
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise SSRFError("Only http/https URLs may be fetched")

    host = parsed.hostname
    if not host:
        raise SSRFError("URL has no hostname")

    port = parsed.port or (443 if parsed.scheme == "https" else 80)

    if _is_ip_literal(host):
        if not is_public_ip(host.strip("[]")):
            raise SSRFError(f"Refusing to fetch non-public address {host}")
        return host

    addresses = _resolve(host, port)
    if not addresses:
        raise SSRFError("Host did not resolve to any address")
    for addr in addresses:
        if not is_public_ip(addr):
            raise SSRFError(f"Host resolves to a non-public address ({addr})")
    return host


def safe_remote_fetch(url: str, timeout: int = 5, max_bytes: int = 512 * 1024,
                      max_redirects: int = 3) -> dict:
    """Fetch a URL with SSRF protections. Only call when explicitly enabled.

    Returns a dict describing the outcome. Never raises for ordinary
    network failures -- callers get a descriptive error field instead.
    """
    import http.client

    outcome = {"url": url, "final_url": url, "status": None, "content_type": None,
               "server": None, "redirects": [], "error": None}
    current = url
    seen = 0

    try:
        while seen <= max_redirects:
            host = assert_url_is_safe(current)
            parsed = urlparse(current)
            port = parsed.port
            conn_cls = (
                http.client.HTTPSConnection if parsed.scheme == "https"
                else http.client.HTTPConnection
            )
            conn = conn_cls(host, port, timeout=timeout)
            path = parsed.path or "/"
            if parsed.query:
                path += "?" + parsed.query
            # Prevent connection to a different host than validated.
            conn.request("GET", path, headers={"User-Agent": "DigitalGuardian/1.0",
                                               "Accept": "text/html,*/*"})
            response = conn.getresponse()

            if response.status in (301, 302, 303, 307, 308):
                location = response.getheader("Location")
                conn.close()
                if not location:
                    outcome["error"] = "Redirect without Location header"
                    return outcome
                from urllib.parse import urljoin

                current = urljoin(current, location)
                outcome["redirects"].append(current)
                seen += 1
                continue

            body = response.read(max_bytes)
            outcome.update(
                status=response.status,
                content_type=response.getheader("Content-Type"),
                server=response.getheader("Server"),
                final_url=current,
            )
            if b"<title" in body[:4096].lower():
                match = re.search(rb"<title[^>]*>(.*?)</title>", body, re.IGNORECASE | re.DOTALL)
                if match:
                    outcome["title"] = match.group(1).decode("utf-8", "replace").strip()[:200]
            conn.close()
            return outcome

        outcome["error"] = "Too many redirects"
        return outcome
    except SSRFError as exc:
        outcome["error"] = str(exc)
        return outcome
    except Exception as exc:  # pragma: no cover - network dependent
        logger.warning("Remote fetch failed for %s: %s", url, exc)
        outcome["error"] = f"Request failed: {exc}"
        return outcome
