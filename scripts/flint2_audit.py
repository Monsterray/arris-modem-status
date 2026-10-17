"""Capture installed UCI settings through LuCI using only list/read/get operations."""

import json
import re
import sys
from datetime import datetime, timezone
from urllib.parse import urlsplit, urlunsplit

from scripts.flint2_collect import LUCI_READS, SENSITIVE, Collector, UnsupportedError, redact
from scripts.flint2_credentials import DATA_DIR, SafeError, load_profile, private_write

EXTRA_SECRET = re.compile(r"psk|preshared|^pin$|community|client_secret|access_code", re.I)
AUTH_FLAGS = {"passwordauth", "rootpasswordauth", "rootlogin"}
FLAG_VALUES = {"0", "1", "on", "off", "yes", "no", "true", "false", "enabled", "disabled"}


def sanitize(value, secrets=()):
    """Keep auth-policy flags while removing credentials before any disk/output write."""
    if isinstance(value, dict):
        result = {}
        for key, item in value.items():
            flag = key.lower() in AUTH_FLAGS and isinstance(item, (str, bool, int)) and str(item).lower() in FLAG_VALUES
            if not flag and (SENSITIVE.search(key) or EXTRA_SECRET.search(key)):
                result[key] = "<redacted>"
            else:
                result[key] = sanitize(item, secrets)
        return result
    if isinstance(value, list):
        return [sanitize(item, secrets) for item in value]
    if isinstance(value, str):
        value = redact(value, secrets)
        if "://" in value:
            try:
                parsed = urlsplit(value)
                if parsed.username is not None or parsed.password is not None:
                    return "<redacted URL credentials>"
                if parsed.query or parsed.fragment:
                    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "<redacted>", ""))
            except ValueError:
                return "<redacted malformed URL>"
    return value


def capture(client):
    """Use one session; no shell commands, configuration writes, or active tests."""
    client.authenticate_luci()
    report = {
        "schema_version": 1,
        "collected_utc": datetime.now(timezone.utc).isoformat(),
        "source": "luci-readonly-audit",
        "status": {},
        "metadata": {},
        "configuration": {},
        "unavailable": {},
        "complete": False,
    }

    def read(module, method, arguments):
        return client.rpc(client.rpc_path, "call", [client.sid, module, method, arguments], ubus=True)

    try:
        for module, method in LUCI_READS:
            try:
                report["status"][f"{module}.{method}"] = sanitize(client.read(module, method), client.secrets)
            except UnsupportedError:
                report["unavailable"][f"{module}.{method}"] = "Not installed or unsupported"
        listing = read("file", "list", {"path": "/etc/config"})
        entries = listing.get("entries") if isinstance(listing, dict) else None
        if not isinstance(entries, list) or len(entries) > 256:
            raise SafeError("Configuration inventory has an unsupported shape or exceeds its limit.")
        names = sorted(
            {
                item["name"]
                for item in entries
                if isinstance(item, dict)
                and item.get("type") == "file"
                and isinstance(item.get("name"), str)
                and re.fullmatch(r"[A-Za-z0-9_-]{1,64}", item["name"])
            }
        )
        if not names:
            raise SafeError("No supported configuration files were listed.")
        report["inventory"] = names
        for name in names:
            try:
                report["configuration"][name] = sanitize(read("uci", "get", {"config": name}), client.secrets)
            except UnsupportedError:
                report["unavailable"][name] = "Empty, unsupported, or unavailable configuration"
        for path in ("/etc/glversion", "/etc/openwrt_release"):
            try:
                report["metadata"][path] = sanitize(read("file", "read", {"path": path}), client.secrets)
            except SafeError:
                report["unavailable"][path] = "Metadata unavailable; no further file reads attempted"
                break
        report["complete"] = True
    except SafeError as error:
        report["stopped"] = str(error)
    return report


def main():
    """Save only a private, sanitized report; never display raw settings or errors."""
    client = None
    try:
        client = Collector(load_profile("luci"))
        report = capture(client)
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
        path = DATA_DIR / f"settings-{stamp}.json"
        private_write(path, json.dumps(report, ensure_ascii=False, indent=2).encode())
        print(f"Saved private read-only settings capture: {path}")
        print(f"Captured {len(report['configuration'])} configurations; complete={report['complete']}.")
        if not report["complete"]:
            print(report.get("stopped", "Capture incomplete."), file=sys.stderr)
        return 0 if report["complete"] else 1
    except KeyboardInterrupt:
        print("Stopped.", file=sys.stderr)
        return 130
    except Exception as error:
        print(
            str(error) if isinstance(error, SafeError) else f"Read-only audit stopped ({type(error).__name__}).",
            file=sys.stderr,
        )
        return 1
    finally:
        if client:
            client.close()


if __name__ == "__main__":
    raise SystemExit(main())
