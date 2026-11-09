import unittest
from analyzer import analyze_headers, calculate_score
from scanner import validate_url

class AnalyzerTests(unittest.TestCase):
    def test_all_headers_present(self):
        headers = {
            "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Permissions-Policy": "camera=(), microphone=()",
        }
        score = calculate_score(analyze_headers(headers, "https://example.test"))
        self.assertEqual(score["score"], 100)

    def test_missing_headers_fail(self):
        results = analyze_headers({}, "https://example.test")
        self.assertTrue(any(x["status"] == "FAIL" for x in results))

    def test_hsts_not_applicable_over_http(self):
        results = analyze_headers({}, "http://example.test")
        hsts = next(x for x in results if x["header"] == "Strict-Transport-Security")
        self.assertEqual(hsts["status"], "INFO")
        self.assertEqual(hsts["weight"], 0)

    def test_weak_csp_warns(self):
        results = analyze_headers({"Content-Security-Policy": "default-src * 'unsafe-inline'"}, "https://example.test")
        csp = next(x for x in results if x["header"] == "Content-Security-Policy")
        self.assertEqual(csp["status"], "WARN")

    def test_rejects_unsupported_scheme(self):
        with self.assertRaises(ValueError):
            validate_url("ftp://example.test")

if __name__ == "__main__":
    unittest.main()
