# URLGuard Mini

Check a URL for phishing signs and get a risk score. Backend only, Node.js CLI.

Parses the URL, checks for insecure HTTP, IP in URL, @ symbol, punycode, long URL, suspicious TLD, suspicious keywords, and many subdomains, then saves a structured report to `url_report.json`.

## Features

- Built in URL parsing, no manual splitting
- Phishing checks for IP, @ symbol, punycode, suspicious TLD, and keywords
- Scoring system, 0 to 100, mapped to LOW, MEDIUM, HIGH, CRITICAL
- Line by line reasons for SOC triage
- Handles invalid URLs and missing args without crashing
- No printing inside helpers, only `main()` prints

## Project Structure

- `url_guard.js` - Main checker
- `url_report.json` - Generated output, gitignored

## How to Run

No dependencies. Node.js only.

```bash
node url_guard.js https://google.com
node url_guard.js http://192.168.1.1/login
node url_guard.js https://paypal-secure-login.verify-free.xyz/login
node url_guard.js https://google.com@evil.com/login
node url_guard.js http://[2001:db8::1]/login
node url_guard.js not-a-url
node url_guard.js
