"""Safety regressions for ambiguous logins and credential-safe diagnostics."""

import json
import logging
import socket
from unittest.mock import MagicMock, Mock

import pytest
import requests

from arris_modem_status import ArrisModemStatusClient
from arris_modem_status.cli.args import create_parser, parse_args
from arris_modem_status.cli.main import create_client
from arris_modem_status.cli.monitor import main as monitor_main
from arris_modem_status.client.auth import HNAPAuthenticator
from arris_modem_status.client.http import HNAPRequestHandler
from arris_modem_status.exceptions import (
    ArrisAuthenticationError,
    ArrisConnectionError,
    ArrisHTTPError,
    ArrisParsingError,
    ArrisTimeoutError,
)


def test_automated_tests_block_unmocked_network():
    """Protect the real modem even when an old test patches the wrong function."""
    with socket.socket() as connection, pytest.raises(pytest.fail.Exception, match="Network I/O"):
        connection.connect(("127.0.0.1", 9))


@pytest.mark.parametrize(
    ("error", "expected"),
    [
        (requests.exceptions.ConnectTimeout(), ArrisTimeoutError),
        (requests.exceptions.ConnectionError(), ArrisConnectionError),
    ],
)
def test_login_transport_failure_is_never_retried(error, expected):
    """Status retries must not silently replay a possibly processed login POST."""
    session = Mock()
    session.post.side_effect = error
    handler = HNAPRequestHandler(session, "https://192.168.100.1:443", max_retries=3, base_backoff=0)
    with pytest.raises(expected):
        handler.make_request_with_retry("Login", {"Login": {"Action": "login"}})
    session.post.assert_called_once()


def test_hnap_post_does_not_follow_redirects(monkeypatch):
    """A 307 redirect must not transparently replay credentials at another URL."""
    redirect = requests.Response()
    redirect.status_code = 307
    redirect.headers["Location"] = "https://192.0.2.1/another-login"
    redirect.url = "https://192.0.2.1/HNAP1/"
    redirect._content = b""
    success = requests.Response()
    success.status_code = 200
    success._content = b'{"LoginResponse":{"LoginResult":"OK"}}'
    with requests.Session() as session:
        session.trust_env = False
        responses = iter([redirect, success])

        def respond(request, **kwargs):
            response = next(responses)
            response.request = request
            return response

        send = Mock(side_effect=respond)
        monkeypatch.setattr(session.get_adapter("https://192.0.2.1"), "send", send)
        handler = HNAPRequestHandler(session, "https://192.0.2.1", max_retries=3)
        with pytest.raises(ArrisAuthenticationError, match="redirected"):
            handler.make_request_with_retry("Login", {"Login": {"Action": "login"}})
        send.assert_called_once()
        assert send.call_args.args[0].url == "https://192.0.2.1/HNAP1/"


def test_debug_arguments_do_not_expose_password(monkeypatch, caplog):
    """Debug mode must not serialize the secret-bearing argparse Namespace."""
    secret = "Synthetic$@!DoNotLog"
    monkeypatch.setattr("sys.argv", ["arris-modem-status", "--password", secret])
    with caplog.at_level(logging.DEBUG, logger="arris_modem_status.cli.args"):
        args = parse_args()
    assert args.password == secret
    assert secret not in caplog.text


def test_rejected_login_blocks_automatic_further_logins(mock_modem_responses, monkeypatch):
    """Catching a failed poll must not let the next poll replay bad credentials."""
    with ArrisModemStatusClient(password="synthetic", max_retries=0) as client:
        post = Mock(
            side_effect=[
                Mock(status_code=200, text=mock_modem_responses["challenge_response"]),
                Mock(status_code=200, text=mock_modem_responses["login_failure"]),
            ]
        )
        monkeypatch.setattr(client.session, "post", post)
        for _ in range(2):
            with pytest.raises(ArrisAuthenticationError):
                client.get_status(include_logs=False)
        assert post.call_count == 2
        assert not client.authenticated
        assert client.private_key is None
        assert client.uid_cookie is None


def test_uncertain_login_is_not_replayed_on_next_poll(mock_modem_responses, monkeypatch):
    """A login read timeout may mean the modem already processed the credentials."""
    with ArrisModemStatusClient(password="synthetic", max_retries=3) as client:
        post = Mock(
            side_effect=[
                Mock(status_code=200, text=mock_modem_responses["challenge_response"]),
                requests.exceptions.ReadTimeout(),
            ]
        )
        monkeypatch.setattr(client.session, "post", post)
        with pytest.raises(ArrisTimeoutError):
            client.get_status(include_logs=False)
        with pytest.raises(ArrisAuthenticationError):
            client.get_status(include_logs=False)
        assert post.call_count == 2
        assert client.private_key is None
        assert client.uid_cookie is None


@pytest.mark.parametrize("status", [401, 403])
@pytest.mark.parametrize("concurrent", [False, True])
def test_denied_session_stops_polling_without_relogin(status, concurrent, monkeypatch):
    """An authorization denial must stop the batch and invalidate cached secrets."""
    with ArrisModemStatusClient(password="synthetic", max_retries=0, concurrent=concurrent, max_workers=1) as client:
        client.authenticated = True
        client.private_key = "synthetic-key"
        client.uid_cookie = "synthetic-cookie"
        post = Mock(return_value=Mock(status_code=status, text="denied"))
        monkeypatch.setattr(client.session, "post", post)
        for _ in range(2):
            with pytest.raises(ArrisAuthenticationError):
                client.get_status(include_logs=False)
        post.assert_called_once()
        assert not client.authenticated
        assert client.private_key is None
        assert client.uid_cookie is None


def test_malformed_challenge_error_does_not_expose_cookie():
    """A malformed response must not put a session cookie into displayed details."""
    secret = "synthetic-session-cookie-do-not-display"
    auth = HNAPAuthenticator("admin", "synthetic")
    with pytest.raises(ArrisParsingError) as error:
        auth.parse_challenge_response('{"LoginResponse":{"Cookie":"' + secret + '"}}')
    assert secret not in str(error.value)


def test_login_failure_error_does_not_expose_response_secrets(mock_modem_responses, monkeypatch):
    """Report the login outcome while keeping other response fields private."""
    secret = "synthetic-session-cookie-do-not-display"
    with ArrisModemStatusClient(password="synthetic", max_retries=0) as client:
        post = Mock(
            side_effect=[
                Mock(status_code=200, text=mock_modem_responses["challenge_response"]),
                Mock(status_code=200, text='{"LoginResponse":{"LoginResult":"FAILED","Cookie":"' + secret + '"}}'),
            ]
        )
        monkeypatch.setattr(client.session, "post", post)
        with pytest.raises(ArrisAuthenticationError) as error:
            client.authenticate()
        assert secret not in str(error.value)
        assert error.value.details["login_result"] == "FAILED"


@pytest.mark.parametrize("raised_http_error", [False, True])
def test_login_http_error_does_not_expose_response_body(raised_http_error):
    """Non-200 authentication responses are private too, including error bodies."""
    secret = "synthetic-session-cookie-do-not-display"
    response = requests.Response()
    response.status_code = 500
    response._content = secret.encode()
    session = Mock()
    if raised_http_error:
        session.post.side_effect = requests.exceptions.HTTPError("HTTP 500", response=response)
    else:
        session.post.return_value = response
    handler = HNAPRequestHandler(session, "https://192.0.2.1:443", max_retries=3)
    with pytest.raises(ArrisHTTPError) as error:
        handler.make_request_with_retry("Login", {"Login": {"Action": "login"}})
    assert error.value.status_code == 500
    assert secret not in str(error.value)
    session.post.assert_called_once()


def test_monitor_timeout_guidance_is_about_connectivity(monkeypatch, capsys):
    """A page timeout should not ask the user to change a proven password."""
    factory = MagicMock()
    factory.return_value.__enter__.return_value.get_status.side_effect = ArrisTimeoutError("page timed out")
    monkeypatch.setattr("arris_modem_status.cli.monitor.ArrisModemStatusClient", factory)
    monkeypatch.setattr("arris_modem_status.cli.monitor.getpass", lambda _: "synthetic")
    assert monitor_main(["--hmac-algorithm", "md5"]) == 1
    output = capsys.readouterr().err
    assert "credentials" not in output
    assert "connectivity" in output.lower()


@pytest.mark.parametrize(
    ("error", "expected"),
    [(requests.exceptions.Timeout(), ArrisTimeoutError), (requests.exceptions.ConnectionError(), ArrisConnectionError)],
)
def test_serial_poll_stops_when_connection_is_lost(error, expected, monkeypatch):
    """A broken connection must not waste the rest of the status-query batch."""
    with ArrisModemStatusClient(password="synthetic", max_retries=0) as client:
        client.authenticated = True
        client.private_key = "synthetic-key"
        client.uid_cookie = "synthetic-cookie"
        post = Mock(side_effect=error)
        monkeypatch.setattr(client.session, "post", post)
        with pytest.raises(expected):
            client.get_status(include_logs=False)
        post.assert_called_once()
        assert client.authenticated  # Preserve the session; do not force a new login.


def test_channel_only_sample_batches_both_directions(mock_modem_responses, monkeypatch):
    """Signal-only sampling must avoid all optional metadata and log requests."""
    body = json.loads(mock_modem_responses["complete_status"])["GetMultipleHNAPsResponse"]
    names = {"GetCustomerStatusDownstreamChannelInfo", "GetCustomerStatusUpstreamChannelInfo"}
    response = json.dumps({"GetMultipleHNAPsResponse": {name + "Response": body[name + "Response"] for name in names}})
    with ArrisModemStatusClient(password="synthetic", max_retries=0, enable_instrumentation=False) as client:
        client.authenticated = True
        client.private_key = "synthetic-key"
        client.uid_cookie = "synthetic-cookie"
        post = Mock(return_value=Mock(status_code=200, text=response))
        monkeypatch.setattr(client.session, "post", post)
        sample = client.get_status(channels_only=True)
        post.assert_called_once()
        assert set(post.call_args.kwargs["json"]["GetMultipleHNAPs"]) == names
        assert sample["_performance"]["requests_total"] == 1
        assert len(sample["downstream_channels"]) == 3
        assert len(sample["upstream_channels"]) == 3


def test_standard_cli_can_select_the_firmware_algorithm():
    """The standard entry point must expose MD5 too, rather than silently using SHA256."""
    args = create_parser().parse_args(
        [
            "--password",
            "synthetic",
            "--hmac-algorithm",
            "md5",
            "--relaxed-http",
            "--channels-only",
        ]
    )
    factory = Mock()
    create_client(args, factory)
    assert factory.call_args.kwargs["hmac_algorithm"] == "md5"
    assert factory.call_args.kwargs["relaxed_http"] is True
    assert args.channels_only is True
