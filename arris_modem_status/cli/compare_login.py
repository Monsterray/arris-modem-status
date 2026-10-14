"""Compare a browser login HAR offline without emitting credentials or making requests."""

import argparse
import base64
import json
import sys
from getpass import getpass
from http.cookies import SimpleCookie
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from arris_modem_status.client.auth import HNAPAuthenticator


def _response(entry: dict[str, Any]) -> dict[str, Any]:
    content = entry.get("response", {}).get("content", {})
    text = content.get("text", "")
    if content.get("encoding") == "base64":
        text = base64.b64decode(text, validate=True).decode("utf-8")
    data = json.loads(text)
    response = data.get("LoginResponse", {})
    if not isinstance(response, dict):
        raise ValueError("Unexpected login response shape")
    return response


def _headers(entry: dict[str, Any]) -> dict[str, str]:
    return {header["name"].lower(): header["value"] for header in entry["request"].get("headers", [])}


def compare_login(har: dict[str, Any], password: str, algorithm: str) -> dict[str, Any]:
    """Return only comparisons from the last complete login flow, never raw HAR values."""
    challenge_entry = None
    flow = None
    for entry in har["log"]["entries"]:
        request = entry["request"]
        if request.get("method") != "POST" or urlsplit(request.get("url", "")).path.rstrip("/") != "/HNAP1":
            continue
        try:
            login = json.loads(request.get("postData", {}).get("text", "")).get("Login", {})
        except (ValueError, AttributeError):
            continue
        if login.get("Action") == "request":
            challenge_entry = entry
        elif login.get("Action") == "login" and challenge_entry is not None:
            if urlsplit(request["url"]).netloc != urlsplit(challenge_entry["request"]["url"]).netloc:
                continue
            flow = (challenge_entry, entry, login)
    if flow is None:
        raise ValueError("No complete HNAP challenge/login pair found; capture one successful browser login")

    challenge_entry, login_entry, login = flow
    challenge = _response(challenge_entry)
    result = _response(login_entry).get("LoginResult")
    auth = HNAPAuthenticator(login["Username"], password, hmac_algorithm=algorithm)

    def token_matches(entry: dict[str, Any]) -> bool:
        token = _headers(entry).get("hnap_auth", "")
        try:
            timestamp = int(token.rsplit(" ", 1)[1])
        except (ValueError, IndexError):
            return False
        return token == auth.generate_auth_token("Login", timestamp)

    challenge_token_matches = token_matches(challenge_entry)
    login_password = auth.compute_credentials(challenge["Challenge"], challenge["PublicKey"])
    cookies = SimpleCookie()
    cookies.load(_headers(login_entry).get("cookie", ""))
    values = {name: cookie.value for name, cookie in cookies.items()}
    values.update({cookie["name"]: cookie["value"] for cookie in login_entry["request"].get("cookies", [])})
    return {
        "algorithm": algorithm,
        "browser_login_succeeded": isinstance(result, str) and result.upper() in {"SUCCESS", "OK", "TRUE"},
        "checks": {
            "challenge_signature_matches": challenge_token_matches,
            "password_matches_browser_login_hash": login.get("LoginPassword") == login_password,
            "login_signature_matches": token_matches(login_entry),
            "uid_cookie_matches": values.get("uid") == challenge.get("Cookie") and bool(challenge.get("Cookie")),
            "private_key_cookie_matches": values.get("PrivateKey") == auth.private_key,
            "private_login_selects_password_field": login.get("PrivateLogin") == "LoginPassword",
        },
    }


def main() -> int:
    """Read a local HAR and prompt for the password; print a redacted comparison only."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--har", required=True, type=Path)
    parser.add_argument("--hmac-algorithm", required=True, choices=("md5", "sha256"))
    args = parser.parse_args()
    try:
        har = json.loads(args.har.read_text(encoding="utf-8"))
        report = compare_login(har, getpass("Modem password (local comparison only): "), args.hmac_algorithm)
    except (OSError, ValueError, KeyError, TypeError, AttributeError, EOFError):
        print("Comparison failed: HAR is unreadable, incomplete, or missing required login fields.", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130
    print(json.dumps(report, indent=2))
    return 0 if report["browser_login_succeeded"] and all(report["checks"].values()) else 1


if __name__ == "__main__":
    sys.exit(main())
