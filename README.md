# OAuth Account Merge Vulnerability Detector

A Python tool that automatically detects OAuth account merge vulnerability surfaces — the class of vulnerability that produced a **Critical Hall of Fame finding on Remitly** and a **P2 finding on Blockchain.com**.

## What is an OAuth Account Merge Vulnerability?

When a platform allows both:
1. Email/password registration (without enforcing email verification)
2. OAuth login (Google, Facebook, Apple)

An attacker can **pre-register** a victim's email address before the victim ever signs up. When the victim later signs in with Google OAuth using that same email, the platform merges both into one account — giving the attacker access to the victim's account.

## Real-World Findings

| Platform | Severity | Status |
|----------|----------|--------|
| Remitly | Critical | Hall of Fame (#3912792) |
| Blockchain.com | P2 | Pending (#a7a32471) |

## Installation
```bash
Download the file
```
```bash
pip3 install requests beautifulsoup4 --break-system-packages
```

## Usage

```bash
# Basic scan
python3 oauth_merger_detector.py --target https://example.com --email test@gmail.com

# Verbose output
python3 oauth_merger_detector.py --target https://example.com --email test@gmail.com --verbose

# Save JSON report
python3 oauth_merger_detector.py --target https://example.com --email test@gmail.com --output report.json
```

## What It Detects

- OAuth providers on the target (Google, Facebook, Apple, GitHub)
- Registration endpoints (GET and POST)
- Whether email verification is enforced
- Account linking endpoints
- Scores severity: CRITICAL / HIGH / MEDIUM / LOW

## Manual Testing Checklist

When the tool reports HIGH or CRITICAL, verify manually:

1. Register with `victim@gmail.com` + password — skip email verification
2. In incognito, sign in with Google OAuth using same `victim@gmail.com`
3. Compare User-ID / Customer-ID across both sessions
4. If same ID → **confirmed account merge vulnerability**
5. Change password from victim session → check if attacker session persists
6. If attacker session survives password reset → escalated severity

## Author

**Rishu Raj Singh** | [Patliputra Anveshan Labs](https://anveshanlabs.in)  
HackerOne: [rishusec](https://hackerone.com/rishusec) | Medium: [@rishuraj2666](https://medium.com/@rishuraj2666)

## License

MIT
