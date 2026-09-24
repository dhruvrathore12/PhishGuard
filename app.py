import re
import difflib
from urllib.parse import urlparse
from flask import Flask, request, jsonify, render_template

app = Flask(__name__)

SUSPICIOUS_TLDS = {
    "tk", "ml", "ga", "cf", "gq", "xyz", "top", "work", "click",
    "loan", "win", "review", "gdn", "zip", "country"
}

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "cutt.ly", "rb.gy", "shorturl.at"
}

BRAND_DOMAINS = {
    "paypal.com", "google.com", "microsoft.com", "apple.com",
    "amazon.com", "facebook.com", "instagram.com", "netflix.com",
    "bankofamerica.com", "chase.com", "wellsfargo.com", "linkedin.com",
    "outlook.com", "whatsapp.com", "dropbox.com"
}

URL_SUSPICIOUS_KEYWORDS = [
    "login", "verify", "secure", "account", "update", "confirm",
    "signin", "banking", "webscr", "suspended", "unlock", "reset",
    "password", "billing", "invoice"
]

EMAIL_URGENCY_KEYWORDS = [
    "urgent", "immediately", "verify your account", "suspended",
    "act now", "limited time", "click here", "confirm your identity",
    "winner", "congratulations", "you have won", "claim your prize",
    "unusual activity", "restricted", "expire", "final notice"
]

EMAIL_SENSITIVE_REQUESTS = [
    "password", "social security", "ssn", "credit card", "cvv",
    "otp", "one time password", "pin number", "bank account", "routing number"
]

GENERIC_GREETINGS = [
    "dear customer", "dear user", "dear valued customer",
    "dear account holder", "dear member", "dear sir/madam"
]

def is_ip_address(host: str) -> bool:
    return bool(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", host))

def domain_similarity_flag(domain: str):
    core = domain.lower().split(":")[0]
    for brand in BRAND_DOMAINS:
        if core == brand:
            return None
        ratio = difflib.SequenceMatcher(None, core, brand).ratio()
        if 0.75 <= ratio < 1.0:
            return brand
    return None

def analyze_url(raw_url: str):
    flags = []
    score = 0

    url = raw_url.strip()
    if not re.match(r"^https?://", url, re.IGNORECASE):
        url_for_parse = "http://" + url
    else:
        url_for_parse = url

    parsed = urlparse(url_for_parse)
    host = parsed.netloc.lower()
    host_no_port = host.split(":")[0]

    if not url.lower().startswith("https://"):
        flags.append("Connection is not secured with HTTPS")
        score += 10

    if is_ip_address(host_no_port):
        flags.append("Uses a raw IP address instead of a domain name")
        score += 25

    if "@" in url:
        flags.append("Contains '@' symbol which can hide the real destination")
        score += 25

    if host_no_port in URL_SHORTENERS:
        flags.append("Uses a URL shortening service, real destination is hidden")
        score += 15

    subdomain_count = max(host_no_port.count("."), 0)
    if subdomain_count >= 3:
        flags.append("Unusually high number of subdomains")
        score += 15

    if host_no_port.count("-") >= 2:
        flags.append("Domain contains multiple hyphens, common in fake domains")
        score += 10

    tld = host_no_port.split(".")[-1] if "." in host_no_port else ""
    if tld in SUSPICIOUS_TLDS:
        flags.append(f"Uses a high-risk top-level domain (.{tld})")
        score += 15

    lowered_url = url.lower()
    found_keywords = [kw for kw in URL_SUSPICIOUS_KEYWORDS if kw in lowered_url]
    if found_keywords:
        flags.append(f"Contains suspicious keyword(s): {', '.join(found_keywords[:4])}")
        score += 10

    lookalike = domain_similarity_flag(host_no_port)
    if lookalike:
        flags.append(f"Domain closely resembles trusted brand '{lookalike}' (possible typosquat)")
        score += 30

    if len(url) > 90:
        flags.append("URL is unusually long, often used to obscure malicious links")
        score += 10

    score = min(score, 100)
    risk = "High" if score >= 50 else "Medium" if score >= 25 else "Low"

    return {
        "input": raw_url,
        "risk_level": risk,
        "risk_score": score,
        "flags": flags if flags else ["No obvious red flags detected"],
        "domain_analyzed": host_no_port,
    }

def analyze_email(sender: str, subject: str, body: str):
    flags = []
    score = 0

    sender = sender.strip()
    subject = subject or ""
    body = body or ""
    full_text = f"{subject}\n{body}".lower()

    match = re.search(r"@([\w\.-]+)", sender)
    sender_domain = match.group(1).lower() if match else ""

    if sender and not match:
        flags.append("Sender address is not a valid email format")
        score += 15

    if sender_domain:
        lookalike = domain_similarity_flag(sender_domain)
        if lookalike:
            flags.append(f"Sender domain mimics trusted brand '{lookalike}'")
            score += 30

        tld = sender_domain.split(".")[-1] if "." in sender_domain else ""
        if tld in SUSPICIOUS_TLDS:
            flags.append(f"Sender domain uses a high-risk TLD (.{tld})")
            score += 15

    found_urgency = [kw for kw in EMAIL_URGENCY_KEYWORDS if kw in full_text]
    if found_urgency:
        flags.append(f"Uses urgency/pressure tactics: {', '.join(found_urgency[:3])}")
        score += 20

    found_sensitive = [kw for kw in EMAIL_SENSITIVE_REQUESTS if kw in full_text]
    if found_sensitive:
        flags.append(f"Requests sensitive information: {', '.join(found_sensitive[:3])}")
        score += 25

    if any(greet in full_text for greet in GENERIC_GREETINGS):
        flags.append("Uses a generic greeting instead of your real name")
        score += 10

    urls_found = re.findall(r"https?://[^\s\)\]]+", body)
    risky_links = 0
    for u in urls_found:
        result = analyze_url(u)
        if result["risk_score"] >= 25:
            risky_links += 1
    if risky_links:
        flags.append(f"Contains {risky_links} suspicious link(s) in the body")
        score += 20

    if body.count("!") >= 3 or re.search(r"\b[A-Z]{6,}\b", body):
        flags.append("Excessive urgency formatting (caps/exclamation marks)")
        score += 10

    score = min(score, 100)
    risk = "High" if score >= 50 else "Medium" if score >= 25 else "Low"

    return {
        "sender": sender,
        "sender_domain": sender_domain,
        "risk_level": risk,
        "risk_score": score,
        "flags": flags if flags else ["No obvious red flags detected"],
        "links_scanned": len(urls_found),
    }

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/check-url", methods=["POST"])
def check_url():
    data = request.get_json(force=True)
    url = (data or {}).get("url", "").strip()
    if not url:
        return jsonify({"error": "Please provide a URL"}), 400
    return jsonify(analyze_url(url))

@app.route("/api/check-email", methods=["POST"])
def check_email():
    data = request.get_json(force=True)
    sender = (data or {}).get("sender", "").strip()
    subject = (data or {}).get("subject", "").strip()
    body = (data or {}).get("body", "").strip()
    if not sender and not body:
        return jsonify({"error": "Please provide at least a sender email or message body"}), 400
    return jsonify(analyze_email(sender, subject, body))

if __name__ == "__main__":
    app.run(debug=True, port=5000)
