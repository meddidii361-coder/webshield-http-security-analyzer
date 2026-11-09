import json
from pathlib import Path

DISCLAIMER = ("This is a limited HTTP security-header configuration review, not a penetration test. "
              "A missing header does not by itself prove exploitability.")

def _data(response, results, score):
    return {"tool": "WebShield", "version": "1.0.0", "target": response["requested_url"],
        "final_url": response["final_url"], "http_status": response["status_code"],
        "https": response["is_https"], "checked_at": response["checked_at"],
        "score": score, "checks": results, "disclaimer": DISCLAIMER}

def save_json_report(response, results, score, path):
    path = Path(path); path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(_data(response, results, score), indent=2), encoding="utf-8")
    return path

def save_text_report(response, results, score, path):
    path = Path(path); path.parent.mkdir(parents=True, exist_ok=True)
    lines = ["WEBSHIELD - HTTP SECURITY HEADERS REPORT", "=" * 48,
        f"Target: {response['requested_url']}", f"Final URL: {response['final_url']}",
        f"HTTP status: {response['status_code']}", f"HTTPS: {response['is_https']}",
        f"Checked at: {response['checked_at']}", "",
        f"Score: {score['score']}/100 ({score['rating']})", "", "FINDINGS", "-" * 48]
    for item in results:
        lines += [f"[{item['status']}] {item['header']}", f"  Finding: {item['summary']}",
                  f"  Recommendation: {item['recommendation']}", ""]
    lines += ["DISCLAIMER", DISCLAIMER, ""]
    path.write_text("\n".join(lines), encoding="utf-8")
    return path
