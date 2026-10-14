"""Regressions for the remaining transport and firmware compatibility issues."""

import hashlib
import hmac
import json as jsonlib
from unittest.mock import Mock

import pytest
import requests

from arris_modem_status.client.auth import HNAPAuthenticator
from arris_modem_status.client.http import HNAPRequestHandler
from arris_modem_status.exceptions import ArrisHTTPError
from arris_modem_status.http_compatibility import ArrisCompatibleHTTPAdapter


def test_md5_login_sends_browser_session_cookies(mock_modem_responses, monkeypatch):
    """The modem browser sends both cookies before the second login POST."""
    from arris_modem_status import ArrisModemStatusClient

    with ArrisModemStatusClient(password="test", hmac_algorithm="md5", max_retries=0) as client:
        login_count = 0

        def modem_post(url, *, json, headers, timeout):
            nonlocal login_count
            login_count += 1
            if json["Login"]["Action"] == "request":
                return Mock(status_code=200, text=mock_modem_responses["challenge_response"])
            challenge = jsonlib.loads(mock_modem_responses["challenge_response"])["LoginResponse"]
            key = hmac.new((challenge["PublicKey"] + "test").encode(), challenge["Challenge"].encode(), "md5")
            cookie = f'uid={challenge["Cookie"]}; PrivateKey={key.hexdigest().upper()}'
            result = "SUCCESS" if headers.get("Cookie") == cookie else "FAILED"
            return Mock(status_code=200, text=jsonlib.dumps({"LoginResponse": {"LoginResult": result}}))

        monkeypatch.setattr(client.session, "post", modem_post)
        assert client.authenticate()
        assert login_count == 2


def test_http_error_without_response_keeps_status(monkeypatch):
    """An HTTPError with no response should preserve the status in its message."""
    handler = HNAPRequestHandler(Mock(), "https://192.168.100.1", max_retries=0)
    monkeypatch.setattr(handler, "_make_raw_request", Mock(side_effect=requests.HTTPError("HTTP 401")))
    with pytest.raises(ArrisHTTPError) as error:
        handler.make_request_with_retry("Login", {})
    assert error.value.status_code == 401


def test_raw_header_bytes_are_decoded():
    """PreparedRequest allows byte-valued headers; their repr is not HTTP syntax."""
    request = requests.Request("POST", "https://192.168.100.1/HNAP1/", headers={"X-Test": b"value"}).prepare()
    raw = ArrisCompatibleHTTPAdapter()._build_raw_http_request(request, "192.168.100.1", "/HNAP1/")
    assert "X-Test: value\r\n" in raw
    assert "b'value'" not in raw


def test_md5_firmware_uses_md5_for_credentials_and_tokens():
    """Older S33 firmware needs MD5 consistently across the entire HNAP flow."""
    auth = HNAPAuthenticator("admin", "test", hmac_algorithm="md5")
    key = hmac.new(b"publictest", b"challenge", hashlib.md5).hexdigest().upper()
    login = auth.compute_credentials("challenge", "public")
    assert auth.private_key == key
    assert login == hmac.new(key.encode(), b"challenge", hashlib.md5).hexdigest().upper()
    message = b'123"http://purenetworks.com/HNAP1/Login"'
    expected = hmac.new(key.encode(), message, hashlib.md5).hexdigest().upper()
    assert auth.generate_auth_token("Login", 123) == f"{expected} 123"


def test_monitor_reuses_client_and_stops_on_partial_data(monkeypatch, capsys):
    """A partial sample ends the run instead of retrying or creating more logins."""
    from arris_modem_status.cli.monitor import poll
    from arris_modem_status.exceptions import ArrisOperationError

    complete = {
        "_performance": {"requests_successful": 4, "requests_total": 4},
        "downstream_channels": [Mock()],
        "upstream_channels": [Mock()],
    }
    partial = dict(complete, _performance={"requests_successful": 3, "requests_total": 4})
    client = Mock()
    client.get_status.side_effect = [complete, partial]
    sleep = Mock()
    monkeypatch.setattr("arris_modem_status.cli.monitor.time.sleep", sleep)
    monkeypatch.setattr("arris_modem_status.cli.monitor.format_channel_data_for_display", lambda _: {"sample": 1})
    with pytest.raises(ArrisOperationError, match="Incomplete"):
        poll(client, samples=10, interval=900)
    assert client.get_status.call_count == 2
    assert all(call.kwargs == {"include_logs": False} for call in client.get_status.call_args_list)
    sleep.assert_called_once_with(900)
    assert capsys.readouterr().out == '{"sample": 1}\n'


def test_status_can_skip_unsupported_event_logs(mock_modem_responses, monkeypatch):
    """The conservative monitor must actually omit event-log requests."""
    from arris_modem_status import ArrisModemStatusClient

    with ArrisModemStatusClient(password="test", enable_instrumentation=False) as client:
        client.authenticated = True
        client.private_key = "test"
        client.uid_cookie = "test"
        post = Mock(return_value=Mock(status_code=200, text=mock_modem_responses["complete_status"]))
        monkeypatch.setattr(client.session, "post", post)
        monkeypatch.setattr("arris_modem_status.client.main.time.sleep", lambda _: None)
        status = client.get_status(include_logs=False)
        assert status["_performance"]["requests_total"] == 4
        assert post.call_count == 4
        assert all(
            "GetCustomerStatusLog" not in call.kwargs["json"]["GetMultipleHNAPs"] for call in post.call_args_list
        )


def test_monitor_auth_failure_does_not_retry(monkeypatch, capsys):
    """The entry point configures conservative defaults and never repeats login."""
    from arris_modem_status.cli.monitor import main
    from arris_modem_status.exceptions import ArrisAuthenticationError

    client = Mock()
    client.get_status.side_effect = ArrisAuthenticationError("Invalid credentials")
    context = Mock()
    context.__enter__ = Mock(return_value=client)
    context.__exit__ = Mock(return_value=False)
    factory = Mock(return_value=context)
    monkeypatch.setattr("arris_modem_status.cli.monitor.ArrisModemStatusClient", factory)
    monkeypatch.setattr("arris_modem_status.cli.monitor.getpass", lambda _: "local-test-password")
    assert main(["--hmac-algorithm", "md5", "--samples", "3"]) == 1
    client.get_status.assert_called_once_with(include_logs=False)
    assert factory.call_args.kwargs["max_retries"] == 0
    assert factory.call_args.kwargs["concurrent"] is False
    assert factory.call_args.kwargs["enable_instrumentation"] is False
    assert factory.call_args.kwargs["hmac_algorithm"] == "md5"
    assert factory.call_args.kwargs["host"] == "192.168.100.1"
    assert "Stopped:" in capsys.readouterr().err
