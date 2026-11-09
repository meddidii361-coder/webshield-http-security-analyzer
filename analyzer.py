from urllib.parse import urlparse

def _get(headers, name):
    for key, value in headers.items():
        if key.lower() == name.lower():
            return str(value).strip()
    return None

def analyze_headers(headers, final_url):
    https = urlparse(final_url).scheme.lower() == "https"
    results = []
    csp = _get(headers, "Content-Security-Policy")
    if not csp:
        results.append(dict(header="Content-Security-Policy", status="FAIL", weight=25,
            summary="Missing.", recommendation="Deploy a restrictive policy tailored to the application's resources."))
    elif any(x in csp.lower() for x in ("'unsafe-inline'", "'unsafe-eval'", "*")):
        results.append(dict(header="Content-Security-Policy", status="WARN", weight=25,
            summary="Present, but contains potentially broad or unsafe source expressions.",
            recommendation="Review sources; avoid unsafe-inline, unsafe-eval, and broad wildcards where possible."))
    else:
        results.append(dict(header="Content-Security-Policy", status="PASS", weight=25,
            summary="Present; basic checks found no obvious unsafe expressions.",
            recommendation="Review the policy against the application's actual resource requirements."))

    hsts = _get(headers, "Strict-Transport-Security")
    if not https:
        results.append(dict(header="Strict-Transport-Security", status="INFO", weight=0,
            summary="Not assessed because the final URL is not HTTPS.",
            recommendation="Serve the site over HTTPS; HSTS is meaningful only over secure connections."))
    elif not hsts:
        results.append(dict(header="Strict-Transport-Security", status="FAIL", weight=20,
            summary="Missing on an HTTPS response.",
            recommendation="Consider an appropriate max-age; validate subdomains before using includeSubDomains."))
    else:
        max_age = 0
        for part in hsts.lower().split(";"):
            if part.strip().startswith("max-age="):
                try: max_age = int(part.strip().split("=", 1)[1])
                except ValueError: pass
        status = "PASS" if max_age >= 15552000 else "WARN"
        summary = "Present with max-age of at least 180 days." if status == "PASS" else "Present, but max-age is missing, invalid, or shorter than 180 days."
        results.append(dict(header="Strict-Transport-Security", status=status, weight=20,
            summary=summary, recommendation="Review max-age and deployment scope."))

    xcto = _get(headers, "X-Content-Type-Options")
    ok = bool(xcto and xcto.lower() == "nosniff")
    results.append(dict(header="X-Content-Type-Options", status="PASS" if ok else "FAIL", weight=10,
        summary="Set to nosniff." if ok else "Missing or not set to nosniff.",
        recommendation="Set X-Content-Type-Options: nosniff."))

    xfo = _get(headers, "X-Frame-Options")
    frame_ancestors = bool(csp and "frame-ancestors" in csp.lower())
    if (xfo and xfo.upper() in ("DENY", "SAMEORIGIN")) or frame_ancestors:
        status, summary = "PASS", "Clickjacking framing control found."
    elif xfo:
        status, summary = "WARN", f"Present with value '{xfo}'; review it."
    else:
        status, summary = "FAIL", "No X-Frame-Options or CSP frame-ancestors directive found."
    results.append(dict(header="X-Frame-Options / CSP frame-ancestors", status=status, weight=15,
        summary=summary, recommendation="Use a suitable X-Frame-Options value or CSP frame-ancestors directive."))

    ref = _get(headers, "Referrer-Policy")
    safe = {"no-referrer", "same-origin", "strict-origin", "strict-origin-when-cross-origin", "no-referrer-when-downgrade"}
    status = "PASS" if ref and ref.lower() in safe else ("WARN" if ref else "FAIL")
    summary = f"Present with value '{ref}'." if ref else "Missing."
    if ref and status == "WARN": summary += " Review information leakage implications."
    results.append(dict(header="Referrer-Policy", status=status, weight=10, summary=summary,
        recommendation="Consider strict-origin-when-cross-origin or a stricter policy suitable for the application."))

    permissions = _get(headers, "Permissions-Policy")
    results.append(dict(header="Permissions-Policy", status="PASS" if permissions else "FAIL", weight=10,
        summary="Present." if permissions else "Missing.",
        recommendation="Define a policy that disables browser features the application does not need."))
    return results

def calculate_score(results):
    applicable = [x for x in results if x["weight"] > 0]
    total = sum(x["weight"] for x in applicable)
    earned = sum(x["weight"] if x["status"] == "PASS" else x["weight"] * 0.5 if x["status"] == "WARN" else 0 for x in applicable)
    score = round(earned / total * 100) if total else 0
    rating = "GOOD" if score >= 85 else "NEEDS IMPROVEMENT" if score >= 60 else "WEAK"
    return {"score": score, "rating": rating, "earned_weight": round(earned, 1), "total_weight": total}
