from datetime import datetime, timezone
from urllib.parse import urlparse
import requests

USER_AGENT = "WebShield/1.0 (+authorized-security-header-audit)"

def validate_url(url):
    if not url or any(ch.isspace() for ch in url):
        raise ValueError("Provide a valid URL without spaces.")
    parsed = urlparse(url)
    if parsed.scheme.lower() not in ("http", "https") or not parsed.hostname:
        raise ValueError("Only valid http:// and https:// URLs are supported.")
    if parsed.username or parsed.password:
        raise ValueError("URLs containing embedded credentials are not supported.")
    return url

def scan_url(url, timeout=10):
    """Send one ordinary GET request. Only scan systems you own or have permission to assess."""
    url = validate_url(url)
    try:
        response = requests.get(url, timeout=timeout, allow_redirects=True,
            headers={"User-Agent": USER_AGENT, "Accept": "text/html,*/*;q=0.8"})
    except requests.exceptions.Timeout as exc:
        raise RuntimeError(f"Request timed out after {timeout} seconds.") from exc
    except requests.exceptions.SSLError as exc:
        raise RuntimeError("TLS certificate verification failed; TLS verification remains enabled.") from exc
    except requests.exceptions.RequestException as exc:
        raise RuntimeError(f"Could not reach target: {exc}") from exc
    final_url = response.url
    return {
        "requested_url": url, "final_url": final_url,
        "status_code": response.status_code,
        "is_https": urlparse(final_url).scheme.lower() == "https",
        "checked_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "headers": dict(response.headers)
    }
