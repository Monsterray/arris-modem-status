"""Password input must preserve punctuation, Unicode, and significant spaces."""

import hashlib
import hmac
from unittest.mock import MagicMock, Mock

import pytest

from arris_modem_status.cli.args import create_parser
from arris_modem_status.cli.main import create_client
from arris_modem_status.cli.monitor import main
from arris_modem_status.client.auth import HNAPAuthenticator

PASSWORD = "  $@! 'quotes' \"double\" \\ `literal` $(literal) café🔒  "


@pytest.mark.parametrize("source", ["argument", "environment", "file"])
def test_cli_preserves_password(source, tmp_path, monkeypatch):
    """All CLI credential sources must pass the original string to the client."""
    argv = []
    if source == "argument":
        argv = ["--password", PASSWORD]
    elif source == "environment":
        monkeypatch.setenv("ARRIS_PW", PASSWORD)
    else:
        path = tmp_path / "password"
        path.write_text(PASSWORD + "\n", encoding="utf-8")
        argv = ["--password-file", str(path)]
    factory = Mock()
    create_client(create_parser().parse_args(argv), factory)
    assert factory.call_args.kwargs["password"] == PASSWORD


@pytest.mark.parametrize("source", ["prompt", "file"])
def test_monitor_preserves_password(source, tmp_path, monkeypatch):
    """Conservative monitoring must not expand or trim password characters."""
    factory = MagicMock()
    monkeypatch.setattr("arris_modem_status.cli.monitor.ArrisModemStatusClient", factory)
    monkeypatch.setattr("arris_modem_status.cli.monitor.poll", Mock())
    argv = ["--hmac-algorithm", "md5"]
    if source == "prompt":
        monkeypatch.setattr("arris_modem_status.cli.monitor.getpass", lambda _: PASSWORD)
    else:
        path = tmp_path / "password"
        path.write_text(PASSWORD + "\n", encoding="utf-8")
        argv += ["--password-file", str(path)]
    assert main(argv) == 0
    assert factory.call_args.kwargs["password"] == PASSWORD


@pytest.mark.parametrize("algorithm", ["md5", "sha256"])
def test_hnap_hashes_exact_utf8_password(algorithm):
    """Hash the supplied Unicode text without normalization or shell evaluation."""
    auth = HNAPAuthenticator("admin", PASSWORD, hmac_algorithm=algorithm)
    key = hmac.new(("public" + PASSWORD).encode("utf-8"), b"challenge", getattr(hashlib, algorithm))
    expected_key = key.hexdigest().upper()
    expected_login = hmac.new(expected_key.encode(), b"challenge", getattr(hashlib, algorithm)).hexdigest().upper()
    assert auth.compute_credentials("challenge", "public") == expected_login
    assert auth.private_key == expected_key
