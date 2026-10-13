"""Regressions for authentication and unattended monitoring."""

import hashlib
import hmac
import json
from unittest.mock import Mock

import pytest

from arris_modem_status import ArrisModemStatusClient
from arris_modem_status.cli.args import create_parser
from arris_modem_status.cli.main import create_client
from arris_modem_status.exceptions import ArrisAuthenticationError


def test_login_request_has_signed_auth_header(mock_modem_responses, monkeypatch):
    """Both phases of login must carry a correctly signed HNAP_AUTH header."""
    monkeypatch.setattr("arris_modem_status.client.auth.time.time", lambda: 1234567890)
    with ArrisModemStatusClient(password="test", enable_instrumentation=False) as client:
        post = Mock(
            side_effect=[
                Mock(status_code=200, text=mock_modem_responses["challenge_response"]),
                Mock(status_code=200, text=mock_modem_responses["login_success"]),
            ]
        )
        monkeypatch.setattr(client.session, "post", post)
        assert client.authenticate()
        token = post.call_args_list[1].kwargs["headers"].get("HNAP_AUTH")
        message = '1234567890000"http://purenetworks.com/HNAP1/Login"'
        expected = hmac.new(client.private_key.encode(), message.encode(), hashlib.sha256).hexdigest().upper()
        assert token == f"{expected} 1234567890000"


@pytest.mark.parametrize(
    "response",
    [
        {"LoginResponse": {"LoginResult": "FAILED", "Cookie": "session"}},
        {"LoginResponse": {"LoginResult": "FAILED", "Message": "not successful"}},
        {"LoginResponse": {"LoginResult": "FAILED", "OtherResult": "OK"}},
        {"OtherResponse": {"LoginResult": "SUCCESS"}},
        {"LoginResponse": None},
        {"LoginResponse": {"LoginResult": None}},
        [],
    ],
)
def test_failed_login_cannot_be_accepted(response, mock_modem_responses, monkeypatch):
    """Unrelated text and field names must not turn a failed login into success."""
    with ArrisModemStatusClient(password="test", enable_instrumentation=False) as client:
        monkeypatch.setattr(
            client.session,
            "post",
            Mock(
                side_effect=[
                    Mock(status_code=200, text=mock_modem_responses["challenge_response"]),
                    Mock(status_code=200, text=json.dumps(response)),
                ]
            ),
        )
        with pytest.raises(ArrisAuthenticationError):
            client.authenticate()
        assert not client.authenticated


def test_failed_reauthentication_clears_previous_session(mock_modem_responses, monkeypatch):
    """A new challenge uses the pre-login key and failed login clears auth state."""
    with ArrisModemStatusClient(password="test", enable_instrumentation=False) as client:
        post = Mock(
            side_effect=[
                Mock(status_code=200, text=mock_modem_responses["challenge_response"]),
                Mock(status_code=200, text=mock_modem_responses["login_success"]),
                Mock(status_code=200, text=mock_modem_responses["challenge_response"]),
                Mock(status_code=200, text=mock_modem_responses["login_failure"]),
            ]
        )
        monkeypatch.setattr(client.session, "post", post)
        assert client.authenticate()
        with pytest.raises(ArrisAuthenticationError):
            client.authenticate()
        assert not client.authenticated
        token = post.call_args_list[2].kwargs["headers"]["HNAP_AUTH"]
        digest, timestamp = token.split()
        message = f'{timestamp}"http://purenetworks.com/HNAP1/Login"'
        expected = hmac.new(b"withoutloginkey", message.encode(), hashlib.sha256).hexdigest().upper()
        assert digest == expected


def test_repeated_status_polls_reuse_authenticated_session(mock_modem_responses, monkeypatch):
    """A persistent monitoring client should log in only once across polls."""
    monkeypatch.setattr("arris_modem_status.client.main.time.sleep", lambda _: None)
    with ArrisModemStatusClient(password="test", enable_instrumentation=False) as client:
        post = Mock(
            side_effect=[
                Mock(status_code=200, text=mock_modem_responses["challenge_response"]),
                Mock(status_code=200, text=mock_modem_responses["login_success"]),
                *[Mock(status_code=200, text=mock_modem_responses["complete_status"]) for _ in range(10)],
            ]
        )
        monkeypatch.setattr(client.session, "post", post)
        for _ in range(2):
            status = client.get_status()
            assert len(status["downstream_channels"]) == 3
            assert status["_performance"]["requests_successful"] == 5
        assert post.call_count == 12
        assert sum("Login" in call.kwargs["json"] for call in post.call_args_list) == 2


@pytest.mark.parametrize("timeout", [1, 60])
def test_cli_honors_request_timeout(timeout):
    """Users must be able to increase read timeout and bound connection timeout."""
    args = create_parser().parse_args(["--password", "test", "--timeout", str(timeout)])
    client_class = Mock()
    create_client(args, client_class)
    assert client_class.call_args.kwargs["timeout"] == (min(2, timeout), timeout)


def test_missing_password_file_keeps_stdout_clean(tmp_path, capsys):
    """Diagnostics must not corrupt the JSON output stream."""
    args = create_parser().parse_args(["--password-file", str(tmp_path / "missing")])
    with pytest.raises(SystemExit):
        create_client(args, Mock())
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "does not exist" in captured.err
