import whois
from datetime import datetime
from urllib.parse import urlparse
import signal


def _timeout_handler(signum, frame):
    raise TimeoutError("WHOIS timed out")


def get_domain_age(url, timeout_seconds=4):
    """
    Returns domain age in days, or 0 if unknown/failed.
    Has a hard timeout to prevent hanging the Flask request.
    """
    try:
        domain = urlparse(url).netloc.lower().lstrip("www.")
        if not domain:
            return 0

        # Set a signal-based timeout (Unix only)
        try:
            signal.signal(signal.SIGALRM, _timeout_handler)
            signal.alarm(timeout_seconds)
        except (AttributeError, OSError):
            pass  # Windows doesn't support SIGALRM — just proceed without timeout

        try:
            w = whois.whois(domain)
        finally:
            try:
                signal.alarm(0)  # Cancel alarm
            except (AttributeError, OSError):
                pass

        creation_date = w.creation_date

        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        if creation_date and isinstance(creation_date, datetime):
            age = (datetime.now() - creation_date).days
            return max(0, age)

    except Exception:
        pass

    return 0
