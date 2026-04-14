from urllib.parse import urlparse
import ipaddress
import re

from flask import Flask, jsonify, render_template, request


app = Flask(__name__)

SUSPICIOUS_KEYWORDS = {
    "account",
    "bank",
    "billing",
    "confirm",
    "free",
    "gift",
    "login",
    "password",
    "paypal",
    "secure",
    "signin",
    "update",
    "verify",
    "wallet",
}

COMMON_BRANDS = {
    "amazon",
    "apple",
    "facebook",
    "google",
    "instagram",
    "microsoft",
    "netflix",
    "paypal",
    "whatsapp",
}


def normalize_url(raw_url):
    value = raw_url.strip()
    if value and not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", value):
        value = f"http://{value}"
    return value


def is_ip_address(hostname):
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


def detect_phishing(raw_url):
    url = normalize_url(raw_url)
    parsed = urlparse(url)
    hostname = (parsed.hostname or "").lower()
    path_and_query = f"{parsed.path}?{parsed.query}".lower()
    full_text = url.lower()
    findings = []
    score = 0

    if not parsed.scheme or not hostname:
        return {
            "status": "Invalid URL",
            "score": 100,
            "level": "high",
            "domain": "Unknown",
            "findings": [
                {
                    "label": "Invalid format",
                    "detail": "Enter a complete URL or domain name, such as https://example.com.",
                    "risk": "high",
                }
            ],
        }

    if parsed.scheme != "https":
        score += 25
        findings.append(
            {
                "label": "HTTPS check failed",
                "detail": "The URL does not use HTTPS. Login and payment pages should encrypt traffic.",
                "risk": "high",
            }
        )
    else:
        findings.append(
            {
                "label": "HTTPS present",
                "detail": "The URL uses HTTPS, which is expected for sensitive pages.",
                "risk": "safe",
            }
        )

    if len(url) > 120:
        score += 25
        findings.append(
            {
                "label": "Very long URL",
                "detail": f"This URL has {len(url)} characters. Phishing links often hide clues inside long URLs.",
                "risk": "high",
            }
        )
    elif len(url) > 75:
        score += 12
        findings.append(
            {
                "label": "Long URL",
                "detail": f"This URL has {len(url)} characters. Review it carefully before opening.",
                "risk": "medium",
            }
        )
    else:
        findings.append(
            {
                "label": "URL length looks normal",
                "detail": f"This URL has {len(url)} characters.",
                "risk": "safe",
            }
        )

    if is_ip_address(hostname):
        score += 30
        findings.append(
            {
                "label": "Suspicious domain",
                "detail": "The link uses an IP address instead of a readable domain name.",
                "risk": "high",
            }
        )

    if "@" in parsed.netloc:
        score += 30
        findings.append(
            {
                "label": "Redirect trick",
                "detail": "The @ symbol can hide the real destination in a URL.",
                "risk": "high",
            }
        )

    labels = hostname.split(".")
    if len(labels) >= 5:
        score += 15
        findings.append(
            {
                "label": "Too many subdomains",
                "detail": "The domain has many sections, which can be used to imitate a trusted site.",
                "risk": "medium",
            }
        )

    if hostname.count("-") >= 2:
        score += 10
        findings.append(
            {
                "label": "Many hyphens in domain",
                "detail": "Attackers sometimes use hyphens to create lookalike domains.",
                "risk": "medium",
            }
        )

    if "xn--" in hostname:
        score += 25
        findings.append(
            {
                "label": "Punycode domain",
                "detail": "This domain may contain characters that visually imitate another website.",
                "risk": "high",
            }
        )

    keyword_hits = sorted(keyword for keyword in SUSPICIOUS_KEYWORDS if keyword in path_and_query)
    if keyword_hits:
        score += min(20, len(keyword_hits) * 5)
        findings.append(
            {
                "label": "Suspicious words",
                "detail": f"Found terms often used in phishing links: {', '.join(keyword_hits[:5])}.",
                "risk": "medium",
            }
        )

    brand_hits = sorted(brand for brand in COMMON_BRANDS if brand in hostname)
    if brand_hits and not any(hostname.endswith(f"{brand}.com") for brand in brand_hits):
        score += 20
        findings.append(
            {
                "label": "Possible brand impersonation",
                "detail": f"The domain mentions {', '.join(brand_hits[:3])} but is not the official .com domain.",
                "risk": "high",
            }
        )

    if not findings:
        findings.append(
            {
                "label": "No obvious warning signs",
                "detail": "This rule-based scan did not find common phishing patterns.",
                "risk": "safe",
            }
        )

    score = min(score, 100)
    if score >= 60:
        status = "Likely Phishing"
        level = "high"
    elif score >= 30:
        status = "Suspicious"
        level = "medium"
    else:
        status = "Likely Safe"
        level = "safe"

    return {
        "status": status,
        "score": score,
        "level": level,
        "domain": hostname,
        "findings": findings,
    }


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/check", methods=["POST"])
def check_url():
    data = request.get_json(silent=True) or {}
    url = data.get("url", "")
    if not url.strip():
        return jsonify({"error": "Please enter a URL to scan."}), 400
    return jsonify(detect_phishing(url))


if __name__ == "__main__":
    app.run(debug=True)
