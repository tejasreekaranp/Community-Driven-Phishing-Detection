from urllib.parse import urlparse
import re
import math

COMMON_TLDS = {"com", "org", "net", "edu", "gov", "io", "co"}

PHISHING_KEYWORDS = [
    "login", "signin", "verify", "secure", "account", "update",
    "banking", "paypal", "amazon", "apple", "google", "microsoft",
    "password", "confirm", "billing", "support", "service",
    "ebay", "netflix", "wallet", "alert", "suspended"
]

TRUSTED_DOMAINS = {
    "google.com", "youtube.com", "facebook.com", "twitter.com",
    "microsoft.com", "apple.com", "amazon.com", "paypal.com",
    "github.com", "linkedin.com", "instagram.com", "wikipedia.org"
}

def _entropy(s):
    if not s:
        return 0
    prob = [s.count(c) / len(s) for c in set(s)]
    return -sum(p * math.log2(p) for p in prob)

def extract_features(url):
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower().lstrip("www.")
        path = parsed.path
        query = parsed.query
        full = url.lower()

        features = []

        # ── 1. IP address as host (strong phishing signal) ──────────────
        features.append(1 if re.match(r"^\d+\.\d+\.\d+\.\d+(:\d+)?$", domain) else 0)

        # ── 2. URL total length ──────────────────────────────────────────
        features.append(min(len(url) / 200, 1.0))

        # ── 3. @ symbol in URL ──────────────────────────────────────────
        features.append(1 if "@" in url else 0)

        # ── 4. Hyphen in domain (not subdomain) ─────────────────────────
        main_domain = domain.split(".")[-2] if domain.count(".") >= 1 else domain
        features.append(1 if "-" in main_domain else 0)

        # ── 5. Phishing keyword presence ────────────────────────────────
        keyword_hits = sum(1 for k in PHISHING_KEYWORDS if k in full)
        features.append(min(keyword_hits / 3, 1.0))

        # ── 6. Digit ratio in full URL ──────────────────────────────────
        digits = sum(c.isdigit() for c in url)
        features.append(digits / (len(url) + 1))

        # ── 7. Path length ───────────────────────────────────────────────
        features.append(min(len(path) / 100, 1.0))

        # ── 8. Domain length ─────────────────────────────────────────────
        features.append(min(len(domain) / 50, 1.0))

        # ── 9. TLD is common/trusted ─────────────────────────────────────
        tld = domain.split(".")[-1] if "." in domain else ""
        features.append(1 if tld in COMMON_TLDS else 0)

        # ── 10. Number of subdomains ─────────────────────────────────────
        subdomain_count = max(0, domain.count(".") - 1)
        features.append(min(subdomain_count / 3, 1.0))

        # ── 11. HTTPS protocol ───────────────────────────────────────────
        features.append(1 if parsed.scheme == "https" else 0)

        # ── 12. Double slash in path (redirect trick) ────────────────────
        features.append(1 if "//" in path else 0)

        # ── 13. Suspicious TLD (known high-abuse) ────────────────────────
        ABUSE_TLDS = {"tk", "ml", "ga", "cf", "gq", "xyz", "top", "work", "click", "link"}
        features.append(1 if tld in ABUSE_TLDS else 0)

        # ── 14. Number count in domain ───────────────────────────────────
        digit_in_domain = sum(c.isdigit() for c in domain)
        features.append(min(digit_in_domain / 10, 1.0))

        # ── 15. Domain entropy (random-looking = phishing) ───────────────
        features.append(_entropy(main_domain) / 4.5)

        # ── 16. Query string length ──────────────────────────────────────
        features.append(min(len(query) / 100, 1.0))

        # ── 17. Number of query parameters ──────────────────────────────
        param_count = len(query.split("&")) if query else 0
        features.append(min(param_count / 10, 1.0))

        # ── 18. Hex-encoded characters (%xx) in URL ──────────────────────
        hex_count = len(re.findall(r"%[0-9a-fA-F]{2}", url))
        features.append(min(hex_count / 5, 1.0))

        # ── 19. URL contains trusted brand in subdomain or path ──────────
        # e.g. paypal.fake.com or fake.com/paypal/login
        brand_in_subdomain = any(b.split(".")[0] in domain.replace(b, "") for b in TRUSTED_DOMAINS)
        features.append(1 if brand_in_subdomain else 0)

        # ── 20. Dot count in domain ──────────────────────────────────────
        features.append(min(domain.count(".") / 5, 1.0))

        # ── 21. Hyphen count in full domain ─────────────────────────────
        features.append(min(domain.count("-") / 5, 1.0))

        # ── 22. Path depth (number of slashes) ───────────────────────────
        depth = path.count("/")
        features.append(min(depth / 8, 1.0))

        return features

    except Exception:
        return [0.0] * 22
