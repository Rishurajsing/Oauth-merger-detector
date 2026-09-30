#!/usr/bin/env python3
"""
OAuth Account Merge Vulnerability Detector
By Rishu Raj Singh | Patliputra Anveshan Labs
anveshanlabs.in

Detects if a target website is vulnerable to OAuth account merge attacks.
Tests for the vulnerability class that led to Critical severity finding on Remitly
and P2 finding on Blockchain.com.

Usage:
    python3 oauth_merger_detector.py --target https://example.com
    python3 oauth_merger_detector.py --target https://example.com --email test@gmail.com --verbose
    python3 oauth_merger_detector.py --target https://example.com --output report.json
"""

import requests
import argparse
import json
import re
import sys
import time
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
import warnings
warnings.filterwarnings("ignore")

# ─────────────────────────────────────────────
# COLORS FOR OUTPUT
# ─────────────────────────────────────────────
class Color:
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    BLUE    = "\033[94m"
    CYAN    = "\033[96m"
    WHITE   = "\033[97m"
    RESET   = "\033[0m"
    BOLD    = "\033[1m"

def info(msg):    print(f"{Color.CYAN}[*]{Color.RESET} {msg}")
def success(msg): print(f"{Color.GREEN}[+]{Color.RESET} {msg}")
def warning(msg): print(f"{Color.YELLOW}[!]{Color.RESET} {msg}")
def error(msg):   print(f"{Color.RED}[-]{Color.RESET} {msg}")
def finding(msg): print(f"{Color.RED}{Color.BOLD}[FINDING]{Color.RESET} {msg}")
def header(msg):  print(f"\n{Color.BLUE}{Color.BOLD}{'='*60}{Color.RESET}\n{Color.BLUE}{Color.BOLD}{msg}{Color.RESET}\n{Color.BLUE}{Color.BOLD}{'='*60}{Color.RESET}")

# ─────────────────────────────────────────────
# OAUTH ENDPOINT PATTERNS
# ─────────────────────────────────────────────
OAUTH_PATTERNS = {
    "google": [
        "/auth/google",
        "/oauth/google",
        "/login/google",
        "/signin/google",
        "/auth/google/callback",
        "/oauth2/google",
        "/sso/google",
        "/api/auth/google",
        "/accounts/google",
        "/connect/google",
    ],
    "facebook": [
        "/auth/facebook",
        "/oauth/facebook",
        "/login/facebook",
    ],
    "apple": [
        "/auth/apple",
        "/oauth/apple",
        "/login/apple",
    ],
    "github": [
        "/auth/github",
        "/oauth/github",
        "/login/github",
    ]
}

# Strings that indicate OAuth buttons in HTML
OAUTH_BUTTON_PATTERNS = [
    "sign in with google",
    "login with google",
    "continue with google",
    "google sign in",
    "sign up with google",
    "accounts.google.com",
    "googleapis.com/auth",
    "oauth2/auth",
    "openid connect",
    "social login",
    "sign in with apple",
    "continue with facebook",
]

# Registration endpoint patterns
REGISTER_PATTERNS = [
    "/register",
    "/signup",
    "/sign-up",
    "/create-account",
    "/join",
    "/auth/register",
    "/api/register",
    "/api/signup",
    "/api/auth/register",
    "/api/v1/register",
    "/api/v1/signup",
    "/api/v2/register",
    "/users/register",
    "/account/register",
    "/accounts/register",
]

# Login endpoint patterns
LOGIN_PATTERNS = [
    "/login",
    "/signin",
    "/sign-in",
    "/auth/login",
    "/api/login",
    "/api/signin",
    "/api/auth/login",
    "/api/v1/login",
    "/api/v1/signin",
    "/users/login",
    "/account/login",
    "/accounts/login",
]

# ─────────────────────────────────────────────
# MAIN DETECTOR CLASS
# ─────────────────────────────────────────────
class OAuthMergeDetector:
    def __init__(self, target_url, test_email=None, verbose=False):
        self.target = target_url.rstrip("/")
        self.test_email = test_email or f"oauthtest_{int(time.time())}@gmail.com"
        self.verbose = verbose
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:120.0) Gecko/20100101 Firefox/120.0",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
        })
        self.results = {
            "target": self.target,
            "oauth_detected": False,
            "oauth_providers": [],
            "oauth_endpoints": [],
            "register_endpoint": None,
            "login_endpoint": None,
            "email_verification_required": None,
            "unverified_account_persists": None,
            "merge_surface_detected": False,
            "vulnerability_indicators": [],
            "recommendations": [],
            "severity": None,
        }

    # ─────────────────────────────────────────────
    # STEP 1: FETCH AND ANALYZE TARGET PAGE
    # ─────────────────────────────────────────────
    def analyze_homepage(self):
        header("STEP 1: Analyzing Target Homepage")
        try:
            resp = self.session.get(self.target, timeout=15, verify=False)
            info(f"Status: {resp.status_code} | Size: {len(resp.content)} bytes")

            soup = BeautifulSoup(resp.text, "html.parser")
            page_text = resp.text.lower()

            # Check for OAuth buttons/links
            for pattern in OAUTH_BUTTON_PATTERNS:
                if pattern.lower() in page_text:
                    if "google" in pattern:
                        if "Google" not in self.results["oauth_providers"]:
                            self.results["oauth_providers"].append("Google")
                    if "apple" in pattern:
                        if "Apple" not in self.results["oauth_providers"]:
                            self.results["oauth_providers"].append("Apple")
                    if "facebook" in pattern:
                        if "Facebook" not in self.results["oauth_providers"]:
                            self.results["oauth_providers"].append("Facebook")

            if self.results["oauth_providers"]:
                self.results["oauth_detected"] = True
                success(f"OAuth providers detected: {', '.join(self.results['oauth_providers'])}")
            else:
                warning("No OAuth providers detected on homepage")

            links = [a.get("href", "") for a in soup.find_all("a", href=True)]
            return links

        except Exception as e:
            error(f"Failed to fetch homepage: {e}")
            return []

    # ─────────────────────────────────────────────
    # STEP 2: DISCOVER OAUTH ENDPOINTS
    # ─────────────────────────────────────────────
    def discover_oauth_endpoints(self):
        header("STEP 2: Discovering OAuth Endpoints")
        found_endpoints = []

        for provider, paths in OAUTH_PATTERNS.items():
            for path in paths:
                url = urljoin(self.target, path)
                try:
                    resp = self.session.get(url, timeout=8, verify=False, allow_redirects=False)
                    status = resp.status_code

                    if status in [200, 302, 301, 303, 307, 308, 403]:
                        location = resp.headers.get("Location", "")
                        # Only count as real OAuth if redirect goes to actual OAuth provider domain
                        oauth_domains = [
                            "accounts.google.com", "google.com/o/oauth",
                            "facebook.com/dialog", "appleid.apple.com",
                            "github.com/login/oauth"
                        ]
                        is_real_oauth = any(d in location.lower() for d in oauth_domains)

                        if status == 200 or is_real_oauth:
                            found_endpoints.append({
                                "provider": provider,
                                "url": url,
                                "status": status
                            })
                            success(f"Found: {url} [{status}]")

                            if is_real_oauth:
                                finding(f"Confirmed {provider.title()} OAuth redirect: {url} → {location[:80]}")
                                if provider.title() not in self.results["oauth_providers"]:
                                    self.results["oauth_providers"].append(provider.title())
                                self.results["oauth_detected"] = True

                except Exception:
                    pass

        self.results["oauth_endpoints"] = found_endpoints
        if not found_endpoints:
            warning("No OAuth endpoints found via path discovery")
        else:
            info(f"Total OAuth endpoints found: {len(found_endpoints)}")

    # ─────────────────────────────────────────────
    # STEP 3: DISCOVER REGISTRATION ENDPOINT
    # ─────────────────────────────────────────────
    def discover_register_endpoint(self):
        header("STEP 3: Discovering Registration Endpoint")

        for path in REGISTER_PATTERNS:
            url = urljoin(self.target, path)
            try:
                resp = self.session.get(url, timeout=8, verify=False, allow_redirects=True)
                if resp.status_code in [200, 201]:
                    page_text = resp.text.lower()
                    if any(k in page_text for k in ["password", "email", "register", "sign up", "create"]):
                        self.results["register_endpoint"] = url
                        success(f"Registration endpoint found: {url}")
                        return url
            except Exception:
                pass

        # Try API registration endpoints with POST
        api_register_paths = [
            "/api/register",
            "/api/signup",
            "/api/v1/register",
            "/api/v1/users",
            "/api/auth/register",
            "/api/v1/auth/register",
        ]

        for path in api_register_paths:
            url = urljoin(self.target, path)
            try:
                resp = self.session.post(
                    url,
                    json={"email": "test@test.com", "password": "Test123!"},
                    timeout=8,
                    verify=False
                )
                if resp.status_code not in [404, 429, 403, 503]:
                    self.results["register_endpoint"] = url
                    success(f"API registration endpoint found: {url} [{resp.status_code}]")
                    return url
            except Exception:
                pass

        warning("Registration endpoint not automatically discovered")
        return None

    # ─────────────────────────────────────────────
    # STEP 4: TEST REGISTRATION WITH UNVERIFIED EMAIL
    # ─────────────────────────────────────────────
    def test_unverified_registration(self):
        header("STEP 4: Testing Unverified Email Registration")

        if not self.results["register_endpoint"]:
            warning("Skipping — no registration endpoint found")
            return False

        url = self.results["register_endpoint"]
        test_password = "TestPassword123!@#"

        payloads = [
            {"email": self.test_email, "password": test_password},
            {"email": self.test_email, "password": test_password, "confirmPassword": test_password},
            {"email": self.test_email, "password": test_password, "username": "testuser123"},
            {"emailAddress": self.test_email, "password": test_password},
            {"user": {"email": self.test_email, "password": test_password}},
        ]

        for payload in payloads:
            try:
                resp = self.session.post(
                    url,
                    json=payload,
                    timeout=10,
                    verify=False,
                    headers={"Content-Type": "application/json"}
                )

                if self.verbose:
                    info(f"Registration attempt: {resp.status_code} | Response: {resp.text[:200]}")

                if resp.status_code in [200, 201]:
                    resp_text = resp.text.lower()
                    if any(k in resp_text for k in ["verify", "verification", "confirm your email", "check your email"]):
                        self.results["email_verification_required"] = True
                        warning("Email verification required after registration")
                        self.results["vulnerability_indicators"].append(
                            "Registration requires email verification — check if unverified accounts persist and can be merged via OAuth"
                        )
                    else:
                        self.results["email_verification_required"] = False
                        finding("Registration succeeded WITHOUT email verification requirement!")
                        self.results["vulnerability_indicators"].append(
                            "Registration does not require email verification — high risk of account merge vulnerability"
                        )

                    success(f"Registration response: {resp.status_code}")
                    return True

                elif resp.status_code == 409:
                    warning("Email already exists (409) — account exists check working")

            except Exception as e:
                if self.verbose:
                    error(f"Registration attempt failed: {e}")

        warning("Could not complete automated registration test")
        return False

    # ─────────────────────────────────────────────
    # STEP 5: CHECK FOR MERGE SURFACE INDICATORS
    # ─────────────────────────────────────────────
    def check_merge_surface(self):
        header("STEP 5: Checking for Account Merge Surface Indicators")

        indicators_found = 0

        # Indicator 1: Both OAuth AND email/password login exist
        if self.results["oauth_detected"] and self.results["register_endpoint"]:
            indicators_found += 1
            finding("INDICATOR 1: Platform supports BOTH OAuth AND email/password registration")
            self.results["vulnerability_indicators"].append(
                "Platform supports multiple authentication methods (OAuth + email/password) — primary condition for account merge vulnerability"
            )

        # Indicator 2: Check if login page shows "forgot password"
        for path in LOGIN_PATTERNS:
            url = urljoin(self.target, path)
            try:
                resp = self.session.get(url, timeout=8, verify=False)
                if resp.status_code == 200:
                    self.results["login_endpoint"] = url
                    page_text = resp.text.lower()

                    if "forgot password" in page_text or "reset password" in page_text:
                        indicators_found += 1
                        success(f"INDICATOR 2: Login page has 'forgot password' — email/password accounts confirmed")

                    has_oauth_on_login = any(p in page_text for p in OAUTH_BUTTON_PATTERNS)
                    if has_oauth_on_login:
                        indicators_found += 1
                        finding(f"INDICATOR 3: Login page has BOTH email/password AND OAuth options")
                        self.results["vulnerability_indicators"].append(
                            "Login page offers both email/password and OAuth — merge surface confirmed"
                        )
                    break
            except Exception:
                pass

        # Indicator 3: Check for "link accounts" or "connect" functionality
        # Only count 200 responses with relevant content — 301/302 redirects are generic and not meaningful
        connect_paths = ["/account/connect", "/settings/connections", "/profile/social", "/auth/link"]
        for path in connect_paths:
            url = urljoin(self.target, path)
            try:
                resp = self.session.get(url, timeout=5, verify=False, allow_redirects=True)
                if resp.status_code == 200:
                    page_text = resp.text.lower()
                    # Must have a form AND linking-specific keywords — avoids generic page matches
                    has_form = "<form" in page_text
                    has_link_keywords = any(k in page_text for k in ["link account", "connect account", "link social", "connect google", "link google", "add google"])
                    if has_form and has_link_keywords:
                        indicators_found += 1
                        success(f"INDICATOR 4: Account linking endpoint found: {url}")
                        self.results["vulnerability_indicators"].append(
                            f"Account linking endpoint exists at {url} — test for improper merge authorization"
                        )
            except Exception:
                pass

        # Indicator 4: No email verification required
        if self.results["email_verification_required"] is False:
            indicators_found += 2
            finding("INDICATOR 5: No email verification required — critical merge surface condition")

        if indicators_found >= 2:
            self.results["merge_surface_detected"] = True
            finding(f"MERGE SURFACE DETECTED — {indicators_found} indicators found!")
        elif indicators_found == 1:
            warning(f"Possible merge surface — {indicators_found} indicator found, manual testing required")
        else:
            info("No strong merge surface indicators found")

        return indicators_found

    # ─────────────────────────────────────────────
    # STEP 6: GENERATE REPORT
    # ─────────────────────────────────────────────
    def generate_report(self):
        header("FINAL REPORT")

        if self.results["merge_surface_detected"] and not self.results["email_verification_required"]:
            self.results["severity"] = "CRITICAL"
            severity_color = Color.RED
        elif self.results["merge_surface_detected"]:
            self.results["severity"] = "HIGH"
            severity_color = Color.RED
        elif self.results["oauth_detected"] and self.results["register_endpoint"]:
            self.results["severity"] = "MEDIUM - REQUIRES MANUAL TESTING"
            severity_color = Color.YELLOW
        else:
            self.results["severity"] = "LOW - LIMITED SURFACE DETECTED"
            severity_color = Color.GREEN

        if self.results["merge_surface_detected"]:
            self.results["recommendations"] = [
                "Require email verification BEFORE allowing account creation that can be merged via OAuth",
                "When OAuth targets existing email, require existing account owner approval before merge",
                "Send notification to account owner when new login method is linked",
                "Bind device-verification tokens to specific session that initiated the request",
                "Audit all OAuth callback handlers for improper account merging logic",
                "Ensure password change invalidates ALL sessions across independently provisioned accounts",
            ]

        print(f"\n{'─'*60}")
        print(f"  Target:          {self.results['target']}")
        print(f"  OAuth Detected:  {'YES' if self.results['oauth_detected'] else 'NO'}")
        print(f"  OAuth Providers: {', '.join(self.results['oauth_providers']) or 'None'}")
        print(f"  Register EP:     {self.results['register_endpoint'] or 'Not found'}")
        print(f"  Email Verify:    {self.results['email_verification_required']}")
        print(f"  Merge Surface:   {'YES' if self.results['merge_surface_detected'] else 'NO'}")
        print(f"  Severity:        {severity_color}{self.results['severity']}{Color.RESET}")
        print(f"{'─'*60}")

        if self.results["vulnerability_indicators"]:
            print(f"\n{Color.RED}{Color.BOLD}Vulnerability Indicators:{Color.RESET}")
            for i, indicator in enumerate(self.results["vulnerability_indicators"], 1):
                print(f"  {i}. {indicator}")

        if self.results["recommendations"]:
            print(f"\n{Color.CYAN}{Color.BOLD}Recommendations:{Color.RESET}")
            for i, rec in enumerate(self.results["recommendations"], 1):
                print(f"  {i}. {rec}")

        print(f"\n{Color.YELLOW}Manual Testing Required:{Color.RESET}")
        print(f"  1. Register with victim@gmail.com + password (do NOT verify email)")
        print(f"  2. Sign in with Google OAuth using same victim@gmail.com")
        print(f"  3. Check if Customer-ID / User-ID is identical across both sessions")
        print(f"  4. If same ID → CONFIRMED account merge vulnerability")
        print(f"  5. Change password from victim session → check if attacker session persists")
        print(f"  6. If attacker session survives password reset → Blockchain.com class finding")
        print(f"  7. Check if second wallet/account provisioned → P1/P2 severity")

        print(f"\n{Color.GREEN}Tool by Rishu Raj Singh | Patliputra Anveshan Labs{Color.RESET}")
        print(f"{Color.GREEN}anveshanlabs.in | HackerOne: rishusec | medium.com/@rishuraj2666{Color.RESET}\n")

        return self.results

    # ─────────────────────────────────────────────
    # RUN ALL STEPS
    # ─────────────────────────────────────────────
    def run(self):
        print(f"""
\033[92m\033[1m
 ██████╗  █████╗ ██╗
 ██╔══██╗██╔══██╗██║
 ██████╔╝███████║██║
 ██╔═══╝ ██╔══██║██║
 ██║     ██║  ██║███████╗
 ╚═╝     ╚═╝  ╚═╝╚══════╝
\033[0m
\033[96mOAuth Account Merge Vulnerability Detector v1.0\033[0m
\033[96mBy Rishu Raj Singh | Patliputra Anveshan Labs\033[0m
\033[96manveshanlabs.in\033[0m

Target: \033[93m{self.target}\033[0m
Email:  \033[93m{self.test_email}\033[0m

\033[93mBased on real findings:\033[0m
  - Critical finding on Remitly (Hall of Fame, #3912792)
  - P2 finding on Blockchain.com (#a7a32471, pending)
""")

        self.analyze_homepage()
        self.discover_oauth_endpoints()
        self.discover_register_endpoint()
        self.test_unverified_registration()
        self.check_merge_surface()
        return self.generate_report()


# ─────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="OAuth Account Merge Vulnerability Detector | Patliputra Anveshan Labs",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 oauth_merger_detector.py --target https://example.com
  python3 oauth_merger_detector.py --target https://remitly.com --email test@gmail.com --verbose
  python3 oauth_merger_detector.py --target https://example.com --output report.json

Real-world findings this tool is based on:
  - Remitly Critical OAuth merge (HackerOne #3912792, Hall of Fame)
  - Blockchain.com dual-wallet provisioning (Bugcrowd P2, pending)

Tool by Rishu Raj Singh | Patliputra Anveshan Labs | anveshanlabs.in
        """
    )
    parser.add_argument("--target", required=True, help="Target URL (e.g. https://example.com)")
    parser.add_argument("--email", help="Test Gmail address you control (for manual OAuth step)")
    parser.add_argument("--verbose", action="store_true", help="Verbose output")
    parser.add_argument("--output", help="Save results to JSON file")

    args = parser.parse_args()

    detector = OAuthMergeDetector(
        target_url=args.target,
        test_email=args.email,
        verbose=args.verbose
    )

    results = detector.run()

    if args.output:
        with open(args.output, "w") as f:
            json.dump(results, f, indent=2)
        success(f"Results saved to {args.output}")


if __name__ == "__main__":
    main()
