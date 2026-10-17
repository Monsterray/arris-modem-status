"""Encrypted Flint 2 credentials; the encryption key stays in macOS Keychain."""

import argparse
import base64
import getpass
import hashlib
import hmac
import ipaddress
import json
import os
import re
import socket
import ssl
import stat
import sys
import tempfile
import uuid
from pathlib import Path
from urllib.parse import urlsplit

from cryptography.fernet import Fernet, InvalidToken

from arris_modem_status.http_compatibility import get_interface_socket_option

ROOT = Path(__file__).resolve().parents[1]
SECRET_DIR = ROOT / ".secrets" / "flint2"
DATA_DIR = ROOT / "router-data"
SERVICE = "com.monsterray.flint2.collector"
PROFILES = ("gui", "luci", "ssh")


class SafeError(Exception):
    """An error whose message contains no credentials or remote response bodies."""


def keychain():
    """Select the native backend explicitly; never fall back to a plaintext keyring."""
    if sys.platform != "darwin":
        raise SafeError("This credential store requires macOS Keychain.")
    from keyring.backends.macOS import Keyring

    return Keyring()


def private_directory(path):
    """Create a private directory, refusing symlinks or an existing unsafe directory."""
    path = Path(path)
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077:
        raise SafeError("Private directories must be owned by you, real directories, and mode 700.")
    return path


def private_write(path, data, replace=False):
    """Write atomically with mode 600 without following an existing destination symlink."""
    path = Path(path)
    private_directory(path.parent)
    if path.exists() or path.is_symlink():
        if not replace or path.is_symlink() or not path.is_file():
            raise SafeError("Destination already exists; choose another name or explicitly replace a regular file.")
    fd, temporary = tempfile.mkstemp(prefix=".flint2-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
        if replace:
            os.replace(temporary, path)
        else:
            os.link(temporary, path)  # Fails atomically if another writer created the destination.
            os.unlink(temporary)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def private_read(path):
    """Read only a small, owner-only regular file through a non-following descriptor."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as handle:
        info = os.fstat(handle.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077:
            raise SafeError("Credential files must be owned by you, regular files, and mode 600.")
        if info.st_size > 65536:
            raise SafeError("Credential file is too large.")
        return handle.read()


def validate_url(url):
    """Accept an HTTPS origin on a literal private IPv4 address; no credentials in URLs."""
    parsed = urlsplit(url)
    try:
        address = ipaddress.IPv4Address(parsed.hostname or "")
        port = parsed.port or 443
    except ValueError as error:
        raise SafeError("Use an HTTPS URL with the router's private IPv4 address.") from error
    networks = ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
    if (
        parsed.scheme != "https"
        or not any(address in ipaddress.IPv4Network(network) for network in networks)
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in ("", "/")
        or parsed.query
        or parsed.fragment
        or not 1 <= port <= 65535
    ):
        raise SafeError("Use only an HTTPS origin at the router's private IPv4 address.")
    return f"https://{address}" + (f":{port}" if port != 443 else "")


def normalize_fingerprint(value):
    """Validate a SHA-256 certificate fingerprint copied from a trusted source."""
    value = value.replace(":", "").lower()
    if not re.fullmatch(r"[0-9a-f]{64}", value):
        raise SafeError("The HTTPS fingerprint must be a SHA-256 certificate fingerprint (64 hex digits).")
    return value


def connect_socket(host, port, interface=None):
    """Open one bounded TCP connection, optionally bound to the physical LAN interface."""
    connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    connection.settimeout(10)
    try:
        if interface:
            connection.setsockopt(*get_interface_socket_option(interface))
        connection.connect((host, port))
        return connection
    except BaseException:
        connection.close()
        raise


def ssh_fingerprint(key):
    """Return the OpenSSH SHA-256 public host-key fingerprint."""
    return "SHA256:" + base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode().rstrip("=")


def probe(url, interface=None, ssh=False, port=22):
    """Observe a public key without authenticating; observations are not automatic trust."""
    parsed = urlsplit(validate_url(url))
    if ssh:
        import paramiko

        with connect_socket(parsed.hostname, port, interface) as connection:
            transport = paramiko.Transport(connection)
            try:
                transport.start_client(timeout=10)
                return {
                    "host": parsed.hostname,
                    "port": port,
                    "ssh_host_key_sha256": ssh_fingerprint(transport.get_remote_server_key()),
                }
            finally:
                transport.close()
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE  # Public observation only; no HTTP request or credential is sent.
    with (
        connect_socket(parsed.hostname, parsed.port or 443, interface) as connection,
        context.wrap_socket(connection, server_hostname=parsed.hostname) as tls,
    ):
        return {"url": url, "certificate_sha256": hashlib.sha256(tls.getpeercert(binary_form=True)).hexdigest()}


def save_profile(profile, settings, password, directory=SECRET_DIR, replace=False):
    """Encrypt credentials using a fresh random key stored only in native Keychain."""
    if profile not in PROFILES or not password:
        raise SafeError("Choose a supported profile and a nonempty password.")
    private_directory(Path(directory).parent)
    private_directory(directory)
    path = Path(directory) / f"{profile}.enc"
    if path.exists() and not replace:
        raise SafeError("Profile exists; use --replace only when intentionally updating its credentials.")
    old_id = None
    if replace and path.exists():
        old_id = json.loads(private_read(path)).get("key_id")
    key = Fernet.generate_key()
    key_id = str(uuid.uuid4())
    content = dict(settings, profile=profile, password=password)
    token = Fernet(key).encrypt(json.dumps(content, ensure_ascii=False).encode("utf-8"))
    backend = keychain()
    backend.set_password(SERVICE, key_id, key.decode())
    try:
        envelope = json.dumps({"version": 1, "key_id": key_id, "ciphertext": token.decode()}).encode()
        private_write(path, envelope, replace=replace)
    except BaseException:
        backend.delete_password(SERVICE, key_id)
        raise
    if old_id and old_id != key_id:
        backend.delete_password(SERVICE, old_id)
    return path


def load_profile(profile, directory=SECRET_DIR):
    """Decrypt in memory; bind each encrypted file to its intended profile."""
    if profile not in PROFILES:
        raise SafeError("Unsupported credential profile.")
    try:
        private_directory(Path(directory).parent)
        private_directory(directory)
        envelope = json.loads(private_read(Path(directory) / f"{profile}.enc"))
        if envelope.get("version") != 1:
            raise SafeError("Unsupported credential format.")
        key_id = str(uuid.UUID(envelope["key_id"]))
        key = keychain().get_password(SERVICE, key_id)
        if not key:
            raise SafeError("The matching encryption key is missing or unavailable in macOS Keychain.")
        data = json.loads(Fernet(key.encode()).decrypt(envelope["ciphertext"].encode()))
        if data.get("profile") != profile or not isinstance(data.get("password"), str) or not data["password"]:
            raise SafeError("Credential profile does not match its file.")
        data["url"] = validate_url(data["url"])
        return data
    except (InvalidToken, ValueError, KeyError, TypeError) as error:
        raise SafeError("Credential file is damaged, incompatible, or failed authentication.") from error


def main(argv=None):
    """Create credentials through a hidden prompt or inspect public fingerprints."""
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    observe = sub.add_parser("probe", help="Observe a certificate/SSH public key; never logs in")
    observe.add_argument("--url", default="https://192.168.8.1")
    observe.add_argument("--interface", default="en0")
    observe.add_argument("--ssh", action="store_true")
    observe.add_argument("--ssh-port", type=int, default=22)
    store = sub.add_parser("store", help="Prompt locally; encrypt the password without a plaintext file")
    store.add_argument("profile", choices=PROFILES)
    store.add_argument("--url")
    store.add_argument("--username", default="root")
    store.add_argument(
        "--fingerprint", help="Verified HTTPS certificate SHA256 or SSH host-key SHA256; prompts if omitted"
    )
    store.add_argument("--interface", default="en0")
    store.add_argument("--ssh-port", type=int, default=22)
    store.add_argument("--replace", action="store_true")
    args = parser.parse_args(argv)
    try:
        if args.command == "probe":
            print(json.dumps(probe(args.url, args.interface, args.ssh, args.ssh_port), indent=2))
            print("Verify this fingerprint independently before storing credentials.", file=sys.stderr)
            return 0
        if not sys.stdin.isatty():
            raise SafeError("Run store in your Terminal so the password can be entered through a hidden prompt.")
        url = validate_url(
            args.url or ("https://192.168.8.1:8443" if args.profile == "luci" else "https://192.168.8.1")
        )
        fingerprint = args.fingerprint
        if fingerprint is None:
            observed = probe(url, args.interface, args.profile == "ssh", args.ssh_port)
            observed_pin = observed["ssh_host_key_sha256" if args.profile == "ssh" else "certificate_sha256"]
            print(f"Observed public fingerprint: {observed_pin}")
            fingerprint = input(
                "Verify independently in your browser or trusted SSH record, then paste the verified fingerprint: "
            ).strip()
            comparison = fingerprint if args.profile == "ssh" else normalize_fingerprint(fingerprint)
            if not hmac.compare_digest(comparison, observed_pin):
                raise SafeError("Verified fingerprint does not match the observed server; nothing was stored.")
        if args.profile == "ssh":
            if not re.fullmatch(r"SHA256:[A-Za-z0-9+/]{43}", fingerprint) or not 1 <= args.ssh_port <= 65535:
                raise SafeError("Use a verified OpenSSH SHA256 fingerprint and a valid SSH port.")
        else:
            fingerprint = normalize_fingerprint(fingerprint)
        password = getpass.getpass(f"{args.profile} password (hidden): ")
        confirmation = getpass.getpass("Repeat password (hidden): ")
        if password != confirmation:
            raise SafeError("Passwords do not match; nothing was stored.")
        if args.profile == "gui" and not password.isascii():
            raise SafeError("This GUI firmware's non-ASCII hashing is unsupported; use LuCI/SSH for that password.")
        settings = {
            "url": url,
            "username": args.username,
            "fingerprint": fingerprint,
            "interface": args.interface,
            "ssh_port": args.ssh_port,
        }
        path = save_profile(args.profile, settings, password, replace=args.replace)
        print(f"Encrypted profile saved: {path}")
        return 0
    except KeyboardInterrupt:
        print("Stopped.", file=sys.stderr)
        return 130
    except Exception as error:
        print(
            (
                str(error)
                if isinstance(error, SafeError)
                else f"Credential operation failed ({type(error).__name__}); no secret details printed."
            ),
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
