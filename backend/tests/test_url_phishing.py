import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from engines.url_analyser import analyse_url
from scoring.risk_engine import compute_score

TEST_CASES = [
    # 1. Lookalike Domain
    ("https://paypa1.com/login", ["Lookalike domain", "Suspicious keywords"]),
    ("https://faceb00k-verification.net", ["Lookalike domain", "Suspicious keywords"]),
    ("https://micr0soft-support.org", ["Lookalike domain", "Suspicious keywords"]),
    
    # 2. Subdomain Tricks
    ("https://paypal.com.security-update.xyz/login", ["Brand impersonation (URL)", "Subdomain depth"]),
    ("https://secure.facebook.login-alerts.co", ["Brand impersonation (URL)", "Suspicious keywords"]),

    # 3. IP Address
    ("http://192.168.1.100/login", ["IP as hostname", "Suspicious keywords"]),
    ("http://103.21.244.5/bank", ["IP as hostname"]),

    # 4. URL Shorteners
    ("https://bit.ly/3FakeLogin", ["URL shortener", "Suspicious keywords"]),
    ("https://short.ly/update-info", ["URL shortener", "Suspicious keywords"]),

    # 5. Suspicious Keywords (Domain)
    ("https://secure-login-alert.com/update-account", ["Suspicious keywords"]),
    ("https://account-suspended-warning.com", ["Suspicious keywords"]),

    # 6. Fake HTTPS + Misleading Domain
    ("https://paypal-secure-login.com", ["Brand impersonation (URL)", "Suspicious keywords"]),
    ("https://amazon-authentication.net", ["Brand impersonation (URL)", "Suspicious keywords"]),

    # 7. Excessively Long URLs
    ("https://secure-login-paypal-user-account-update-confirmation.com/session/verify", ["Excessive URL length", "Brand impersonation (URL)"]),

    # 8. Special Characters / Encoding
    ("https://paypal.com%00.evil.com/login", ["Obfuscation / Encoding"]),
    ("https://google.com@malicious-site.net", ["Obfuscation / Encoding"]),
    
    # Safe URLs (Should score low/safe and not trigger brand spoofing)
    ("https://www.paypal.com", []),
    ("https://www.amazon.in", []),
    ("https://accounts.google.com", ["Suspicious keywords"]), # "account"
    ("https://www.microsoft.com", []),
]

if __name__ == "__main__":
    failed = 0
    for url, expected_signals in TEST_CASES:
        signals = analyse_url(url)
        signal_names = [s.name for s in signals if s.score > 0]
        score = compute_score(signals)
        
        print(f"URL: {url}")
        print(f"Score: {score} -> {'[HIGH]' if score >= 75 else '[LOW]'}  Detected: {signal_names}")
        
        # Check if all expected signals are present
        missing = [exp for exp in expected_signals if exp not in signal_names]
        if missing:
            print(f"❌ FAILED. Missing expected signals: {missing}")
            failed += 1
        elif url.startswith("https://www.") and score >= 35 and url != "https://accounts.google.com":
            print(f"❌ FAILED. Safe URL scored too high: {score}")
            failed += 1
        else:
            print("✅ PASS")
        print("-" * 60)

    if failed == 0:
        print("[ALL TESTS PASSED]")
        sys.exit(0)
    else:
        print(f"[{failed} TESTS FAILED]")
        sys.exit(1)
