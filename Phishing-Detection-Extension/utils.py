import re
from urllib.parse import urlparse

ABUSE_TLDS = {"tk", "ml", "ga", "cf", "gq", "xyz", "top", "work", "click", "link"}

def check_url_features(url):
    score = 10

    if not url.startswith("https"):
        score -= 3

    if len(url) > 100:
        score -= 2

    if "@" in url:
        score -= 3

    domain = urlparse(url).netloc.lower()

    if re.match(r"^\d+\.\d+\.\d+\.\d+", domain):
        score -= 4

    tld = domain.split(".")[-1]
    if tld in ABUSE_TLDS:
        score -= 2

    subdomain_depth = max(0, domain.count(".") - 1)
    if subdomain_depth >= 3:
        score -= 2

    return max(0, min(score, 10))


def classify(score):
    if score >= 8:
        return "Safe"
    elif score >= 5:
        return "Suspicious"
    else:
        return "Phishing"
