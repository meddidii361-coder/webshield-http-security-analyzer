import argparse
import sys
from pathlib import Path
from scanner import scan_url
from analyzer import analyze_headers, calculate_score
from reporter import save_json_report, save_text_report

def main():
    parser = argparse.ArgumentParser(description="Analyze HTTP security headers on a website you own or are authorized to assess.")
    parser.add_argument("url", help="Target URL, e.g. https://example.com")
    parser.add_argument("--timeout", type=int, default=10)
    parser.add_argument("--format", choices=["text", "json", "both"], default="both")
    parser.add_argument("--output-dir", default="reports")
    args = parser.parse_args()
    if not 1 <= args.timeout <= 60:
        parser.error("--timeout must be between 1 and 60 seconds")
    try:
        data = scan_url(args.url, args.timeout)
    except (ValueError, RuntimeError) as exc:
        print(f"[!] Scan failed: {exc}", file=sys.stderr)
        return 1
    results = analyze_headers(data["headers"], data["final_url"])
    score = calculate_score(results)
    print("\n" + "=" * 60 + "\n                 WEBSHIELD\n       HTTP SECURITY HEADERS ANALYZER\n" + "=" * 60)
    print(f"Target: {data['requested_url']}\nFinal URL: {data['final_url']}\nHTTP status: {data['status_code']}\nHTTPS: {data['is_https']}\n")
    for item in results:
        marker = {"PASS": "[+]", "WARN": "[!]", "FAIL": "[-]", "INFO": "[i]"}[item["status"]]
        print(f"{marker} {item['header']}: {item['summary']}")
    print(f"\nScore: {score['score']}/100 — {score['rating']}")
    print("Note: This is a configuration review, not a penetration test.")
    out = Path(args.output_dir)
    out.mkdir(parents=True, exist_ok=True)
    if args.format in ("text", "both"):
        print(f"[+] Text report: {save_text_report(data, results, score, out / 'webshield_report.txt')}")
    if args.format in ("json", "both"):
        print(f"[+] JSON report: {save_json_report(data, results, score, out / 'webshield_report.json')}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
