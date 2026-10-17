"""Read Flint 2 GL.iNet and LuCI status over certificate-pinned HTTPS."""

import argparse
import hashlib
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urljoin, urlsplit

from passlib.hash import md5_crypt, sha256_crypt, sha512_crypt

from arris_modem_status.http_compatibility import create_arris_compatible_session
from scripts.flint2_credentials import (
    DATA_DIR,
    SafeError,
    load_profile,
    normalize_fingerprint,
    private_write,
    validate_url,
)

GL_READS = (("system", "get_info"), ("system", "get_status"))
LUCI_READS = (("system", "board"), ("system", "info"), ("network.interface", "dump"), ("luci-rpc", "getNetworkDevices"))
LOGIN_BUNDLE_SHA256 = "bb2f6ef79c8fc95f6fc18bdf4d43883aea318d8b39a29d549583acbb079a235d"
APP_BUNDLE_SHA256 = "7f932af072e305dbeca23bd33a941fa4cd1e556c46421bf9aebc5fb479162e3a"
SENSITIVE = re.compile(
    r"pass|secret|token|session|cookie|credential|authorization|private|(?:^|_)key|^sid$|hash|nonce|salt", re.I
)


class UnsupportedError(SafeError):
    """An optional status method is not installed on this firmware."""


def redact(value, secrets=()):
    """Remove credential-shaped fields and exact in-memory secrets before writing data."""
    if isinstance(value, dict):
        return {
            str(key): "<redacted>" if SENSITIVE.search(str(key)) else redact(item, secrets)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [redact(item, secrets) for item in value]
    if isinstance(value, str):
        for secret in secrets:
            if secret:
                value = value.replace(secret, "<redacted>")
    return value


def login_hash(password, username, challenge):
    """Match the observed public GUI: Unix-crypt followed by SHA-256, without guessing."""
    if not password.isascii():
        raise SafeError(
            "This GUI firmware's non-ASCII password hashing is unsupported; no login was attempted. LuCI/SSH remain separate options."
        )
    if not isinstance(challenge, dict) or set(challenge) - {"alg", "salt", "nonce", "hash-method"}:
        raise SafeError("Unrecognized GUI challenge fields; inspect the firmware before attempting login.")
    alg = str(challenge.get("alg", ""))
    salt, nonce = challenge.get("salt"), challenge.get("nonce")
    if alg not in ("1", "5", "6") or not isinstance(salt, str) or not re.fullmatch(r"[./A-Za-z0-9]{1,16}", salt):
        raise SafeError("Unsupported GUI password-hash settings; no login was attempted.")
    if alg == "1" and len(salt) > 8:
        raise SafeError("Invalid MD5-crypt salt; no login was attempted.")
    if not isinstance(nonce, str) or not 1 <= len(nonce) <= 256 or challenge.get("hash-method", "sha256") != "sha256":
        raise SafeError("Unsupported GUI challenge variant; no login was attempted.")
    handler = {"1": md5_crypt, "5": sha256_crypt, "6": sha512_crypt}[alg]
    options = {"salt": salt}
    if alg != "1":
        options["rounds"] = 5000
    cipher = handler.using(**options).hash(password)
    return hashlib.sha256(f"{username}:{cipher}:{nonce}".encode()).hexdigest(), cipher


def luci_environment(html):
    """Parse LuCI's JSON bootstrap object without executing JavaScript."""
    match = re.search(r"new\s+LuCI\s*\(\s*", html)
    if match:
        try:
            value, _ = json.JSONDecoder().raw_decode(html[match.end() :])
            if isinstance(value, dict):
                return value
        except ValueError:
            pass
    raise SafeError("LuCI did not expose its expected bootstrap metadata; stopped.")


class Collector:
    """One pinned session with a fixed allowlist and one explicit authentication attempt."""

    def __init__(self, profile):
        self.profile = profile
        self.origin = validate_url(profile["url"])
        self.session = create_arris_compatible_session(relaxed_http=False, network_interface=profile.get("interface"))
        self.session.get_adapter(self.origin).poolmanager.connection_pool_kw["assert_fingerprint"] = (
            normalize_fingerprint(profile["fingerprint"])
        )
        self.session.headers.update({"Origin": self.origin, "Referer": self.origin + "/"})
        self.next_id = 0
        self.secrets = [profile["password"]]
        self.login_attempted = False
        self.sid = None
        self.rpc_path = None

    def close(self):
        """Close sockets and discard cookies and session material."""
        self.session.cookies.clear()
        self.session.close()
        self.sid = None
        self.secrets.clear()

    def request(self, method, path, **kwargs):
        """Never follow redirects, use proxies, or replay a credential request."""
        url = urljoin(self.origin + "/", path)
        if (urlsplit(url).scheme, urlsplit(url).netloc) != (urlsplit(self.origin).scheme, urlsplit(self.origin).netloc):
            raise SafeError("Cross-origin router requests are forbidden.")
        timeout = kwargs.pop("timeout", (5, 20))
        return self.session.request(method, url, timeout=timeout, allow_redirects=False, **kwargs)

    def rpc(self, path, method, params, ubus=False, timeout=(5, 20)):
        """Validate JSON-RPC IDs and statuses without exposing remote error bodies."""
        self.next_id += 1
        response = self.request(
            "POST",
            path,
            json={"jsonrpc": "2.0", "id": self.next_id, "method": method, "params": params},
            timeout=timeout,
        )
        if response.status_code != 200:
            raise SafeError(f"Router API returned HTTP {response.status_code}; stopped without retrying.")
        try:
            data = response.json()
        except ValueError as error:
            raise SafeError("Router API returned invalid JSON; stopped.") from error
        if not isinstance(data, dict) or data.get("id") != self.next_id:
            raise SafeError("Router API response ID or shape did not match the request.")
        if data.get("error"):
            code = data["error"].get("code") if isinstance(data["error"], dict) else None
            if code == -32601:
                raise UnsupportedError("Status method is unavailable on this firmware.")
            raise SafeError("Router API denied or failed the request; stopped without reauthentication.")
        if "result" not in data:
            raise SafeError("Router API response has no result.")
        result = data["result"]
        if ubus:
            if not isinstance(result, list) or not result:
                raise SafeError("Invalid ubus response.")
            if result[0] in (3, 4):
                raise UnsupportedError("Status method is unavailable on this firmware.")
            if result[0] != 0:
                raise SafeError("LuCI denied or failed the status request; stopped without reauthentication.")
            return result[1] if len(result) > 1 else {}
        return result

    def authenticate_gui(self):
        """Check observed public UI bundles, then perform a single challenge/login flow."""
        if self.login_attempted:
            raise SafeError("A login was already attempted on this client.")
        self.login_attempted = True
        page = self.request("GET", "/")
        if page.status_code != 200:
            raise SafeError("GUI public page is unavailable; no credential POST was made.")
        # Binding these verified artifacts prevents treating another firmware's login as this protocol.
        for path, expected in (
            ("/js/app.bfe03abe.js", APP_BUNDLE_SHA256),
            ("/views/gl-sdk4-ui-login.common.js", LOGIN_BUNDLE_SHA256),
        ):
            response = self.request("GET", path)
            if response.status_code != 200 or hashlib.sha256(response.content).hexdigest() != expected:
                raise SafeError("GUI login assets differ from the verified firmware; inspect them before login.")
        challenge = self.rpc("/rpc", "challenge", {"username": self.profile["username"]})
        digest, cipher = login_hash(self.profile["password"], self.profile["username"], challenge)
        self.secrets.extend([digest, cipher])
        result = self.rpc("/rpc", "login", {"username": self.profile["username"], "hash": digest})
        sid = result.get("sid") if isinstance(result, dict) else None
        if not isinstance(sid, str) or not re.fullmatch(r"[A-Za-z0-9_-]{16,256}", sid):
            raise SafeError("GUI authentication failed or returned an unknown session; stopped.")
        self.sid = sid
        self.secrets.append(sid)
        self.session.headers["Admin-Token"] = sid
        self.session.cookies.set("Admin-Token", sid, domain=urlsplit(self.origin).hostname, path="/")
        self.rpc_path = "/rpc"

    def authenticate_luci(self):
        """Use LuCI's actual form, cookie, and advertised ubus path; never try another login."""
        if self.login_attempted:
            raise SafeError("A login was already attempted on this client.")
        self.login_attempted = True
        page = self.request("GET", "/cgi-bin/luci/")
        if page.status_code not in (200, 403) or "luci_password" not in page.text:
            raise SafeError("Expected LuCI login form was not found; no credential POST was made.")
        response = self.request(
            "POST",
            "/cgi-bin/luci/",
            data={"luci_username": self.profile["username"], "luci_password": self.profile["password"]},
        )
        if response.status_code in (302, 303):
            response = self.request("GET", response.headers.get("Location", "/cgi-bin/luci/"))
        if (
            response.status_code != 200
            or 'name="luci_password"' in response.text
            or "name='luci_password'" in response.text
        ):
            raise SafeError("LuCI authentication failed; stopped after one credential POST.")
        environment = luci_environment(response.text)
        sid = environment.get("sessionid") or environment.get("ubus_rpc_session")
        if not sid:
            sid = next(
                (cookie.value for cookie in self.session.cookies if cookie.name in ("sysauth_https", "sysauth")), None
            )
        if not isinstance(sid, str) or not re.fullmatch(r"[0-9a-f]{32}", sid):
            raise SafeError("LuCI session metadata is unsupported; stopped.")
        path = environment.get("ubuspath")
        if path not in ("/ubus", "/ubus/", "/cgi-bin/luci/admin/ubus", "/cgi-bin/luci/admin/ubus/"):
            raise SafeError("LuCI advertised an unsupported RPC path; stopped.")
        self.sid, self.rpc_path = sid, path
        self.secrets.append(sid)
        token = environment.get("token")
        if isinstance(token, str) and token:
            self.secrets.append(token)
            self.session.headers["X-LuCI-Token"] = token

    def read(self, module, method):
        """Permit only the reviewed status reads for the authenticated interface."""
        allowed = GL_READS if self.profile["profile"] == "gui" else LUCI_READS
        if not self.sid or (module, method) not in allowed:
            raise SafeError("Only authenticated, allowlisted status reads are permitted.")
        return self.rpc(self.rpc_path, "call", [self.sid, module, method, {}], ubus=self.profile["profile"] == "luci")

    def collect(self):
        """Collect a finite snapshot, marking only missing optional methods as unavailable."""
        if self.profile["profile"] == "gui":
            self.authenticate_gui()
            methods = GL_READS
        else:
            self.authenticate_luci()
            methods = LUCI_READS
        results = {}
        for module, method in methods:
            try:
                results[f"{module}.{method}"] = self.read(module, method)
            except UnsupportedError:
                results[f"{module}.{method}"] = {"unavailable": True}
        return redact(
            {
                "schema_version": 1,
                "collected_utc": datetime.now(timezone.utc).isoformat(),
                "source": self.profile["profile"],
                "origin": self.origin,
                "data": results,
            },
            self.secrets,
        )


def main(argv=None):
    """Collect one profile's status and write only a private, redacted snapshot."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("profile", choices=("gui", "luci"))
    parser.add_argument("--output-dir", type=Path, default=DATA_DIR)
    args = parser.parse_args(argv)
    client = None
    try:
        client = Collector(load_profile(args.profile))
        report = client.collect()
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
        path = args.output_dir / f"{args.profile}-{stamp}.json"
        private_write(path, json.dumps(report, ensure_ascii=False, indent=2).encode())
        print(f"Saved private {args.profile} snapshot: {path}")
        return 0
    except KeyboardInterrupt:
        print("Stopped.", file=sys.stderr)
        return 130
    except Exception as error:
        print(
            (
                str(error)
                if isinstance(error, SafeError)
                else f"Collection failed ({type(error).__name__}); no credentials or remote response bodies printed."
            ),
            file=sys.stderr,
        )
        return 1
    finally:
        if client:
            client.close()


if __name__ == "__main__":
    raise SystemExit(main())
