from urllib.parse import urlparse
import math
import re


def extract_domain_features(url):
    """
    Standalone domain-level feature extractor.
    Can be combined with features.py for richer signals.
    """
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower().lstrip("www.")

        if not domain:
            return [0.0] * 6

        features = []

        # 1. Domain length (normalized)
        features.append(min(len(domain) / 50, 1.0))

        # 2. Number of dots
        features.append(min(domain.count(".") / 5, 1.0))

        # 3. Number of hyphens
        features.append(min(domain.count("-") / 5, 1.0))

        # 4. Digit ratio
        digits = sum(c.isdigit() for c in domain)
        features.append(digits / (len(domain) + 1))

        # 5. Entropy (higher = more random = more suspicious)
        if len(domain) > 0:
            prob = [domain.count(c) / len(domain) for c in set(domain)]
            entropy = -sum(p * math.log2(p) for p in prob)
            features.append(min(entropy / 4.5, 1.0))
        else:
            features.append(0.0)

        # 6. Consonant ratio (high consonant ratio = gibberish domain)
        vowels = set("aeiou")
        alpha = [c for c in domain if c.isalpha()]
        if alpha:
            consonant_ratio = sum(1 for c in alpha if c not in vowels) / len(alpha)
        else:
            consonant_ratio = 0.0
        features.append(consonant_ratio)

        return features

    except Exception:
        return [0.0] * 6
