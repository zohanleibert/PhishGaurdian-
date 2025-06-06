import re
import argparse

# Define suspicious patterns and keywords
SUSPICIOUS_KEYWORDS = [
    "login", "verify", "secure", "update", "account", "banking",
    "paypal", "signin", "confirm", "webscr", "ebay"
]

def is_suspicious(url):
    score = 0
    reasons = []

    if "@" in url:
        score += 1
        reasons.append("Contains '@' symbol")

    if url.count("-") >= 2:
        score += 1
        reasons.append("Contains multiple hyphens")

    if url.startswith("http://"):
        score += 1
        reasons.append("Uses insecure HTTP")

    if any(keyword in url.lower() for keyword in SUSPICIOUS_KEYWORDS):
        score += 1
        reasons.append("Contains phishing-related keywords")

    if url.count(".") > 3:
        score += 1
        reasons.append("Too many subdomains")

    if len(url) > 75:
        score += 1
        reasons.append("URL is unusually long")

    return score, reasons

def main():
    parser = argparse.ArgumentParser(description="Phishing URL Detector")
    parser.add_argument("--url", required=True, help="URL to check")
    args = parser.parse_args()
    
    url = args.url.strip()
    score, reasons = is_suspicious(url)

    print("\nURL:", url)
    if score >= 2:
        print("Result: ⚠️ Suspicious (Potential Phishing Link)")
    else:
        print("Result: ✅ Safe")

    if reasons:
        print("Reasons:")
        for reason in reasons:
            print(" -", reaso
