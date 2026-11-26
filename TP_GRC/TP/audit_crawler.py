
from playwright.sync_api import sync_playwright
from urllib.parse import urlparse
import json
from datetime import datetime, timezone

# Website to audit
TARGET_URL = "https://example.com"

# Extract website domain
target_domain = urlparse(TARGET_URL).hostname

# Store evidence
requests_evidence = []

with sync_playwright() as p:

    # Launch Chromium
    browser = p.chromium.launch(headless=False)

    context = browser.new_context()

    page = context.new_page()

    # Observe every HTTP request
    def capture_request(request):

        request_domain = urlparse(request.url).hostname

        # Classify first-party / third-party
        if request_domain == target_domain:
            request_type = "First-party"
        else:
            request_type = "Third-party"

        evidence = {
            "url": request.url,
            "method": request.method,
            "domain": request_domain,
            "type": request_type
        }

        requests_evidence.append(evidence)

    # Register listener BEFORE visiting website
    page.on("request", capture_request)

    # Visit website
    page.goto(TARGET_URL, wait_until="networkidle", timeout=60000)

    # Wait for additional activity
    page.wait_for_timeout(3000)

    # Collect cookies
    cookies = context.cookies()

    cookies_evidence = []

    for cookie in cookies:

        expiry = cookie["expires"]

        if expiry == -1:
            expiry_date = "Session cookie"
        else:
            expiry_date = datetime.fromtimestamp(
                expiry, timezone.utc
            ).isoformat()

        cookies_evidence.append({
            "name": cookie["name"],
            "domain": cookie["domain"],
            "expiry": expiry_date
        })

    # Count requests
    total_requests = len(requests_evidence)

    first_party = sum(
        1 for r in requests_evidence
        if r["type"] == "First-party"
    )

    third_party = sum(
        1 for r in requests_evidence
        if r["type"] == "Third-party"
    )

    # Prepare audit report
    report = {
        "website": TARGET_URL,
        "audit_date": datetime.now(timezone.utc).isoformat(),
        "total_requests": total_requests,
        "first_party_requests": first_party,
        "third_party_requests": third_party,
        "requests": requests_evidence,
        "cookies": cookies_evidence
    }

    # Export evidence
    with open("audit_evidence.json", "w", encoding="utf-8") as file:
        json.dump(report, file, indent=4, ensure_ascii=False)

    print("\n===== AUDIT REPORT =====")
    print("Website:", TARGET_URL)
    print("Total requests:", total_requests)
    print("First-party:", first_party)
    print("Third-party:", third_party)
    print("Cookies:", len(cookies_evidence))
    print("Evidence exported to audit_evidence.json")

    browser.close()
