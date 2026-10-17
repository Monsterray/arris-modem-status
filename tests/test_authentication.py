"""Offline regressions for modem authentication and protocol validation."""

import hashlib
import hmac
import json
import json as jsonlib
from unittest.mock import Mock

import pytest

from arris_modem_status import ArrisModemStatusClient
from arris_modem_status.client.auth import HNAPAuthenticator
from arris_modem_status.exceptions import ArrisAuthenticationError, ArrisConfigurationError, ArrisParsingError


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
        assert client._generate_hnap_auth_token("Login", 1234567890000) == token


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


def test_md5_login_sends_browser_session_cookies(mock_modem_responses, monkeypatch):
    """The modem browser sends both cookies before the second login POST."""
    from arris_modem_status import ArrisModemStatusClient

    with ArrisModemStatusClient(password="test", hmac_algorithm="md5", max_retries=0) as client:
        login_count = 0

        def modem_post(url, *, json, headers, timeout, allow_redirects):
            nonlocal login_count
            assert not allow_redirects
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


@pytest.mark.parametrize("algorithm", ["sha1", "MD5", ""])
def test_unknown_hash_algorithm_is_rejected(algorithm):
    with pytest.raises(ArrisConfigurationError, match="sha256 or md5"):
        HNAPAuthenticator("admin", "synthetic", algorithm)


@pytest.mark.parametrize("change", [{"Challenge": ""}, {"PublicKey": 1}, {"Cookie": []}])
def test_challenge_fields_are_validated_without_response_dumps(change):
    response = {"Challenge": "synthetic-challenge", "PublicKey": "synthetic-public", "Cookie": "synthetic-cookie"}
    response.update(change)
    with pytest.raises(ArrisParsingError) as error:
        HNAPAuthenticator("admin", "synthetic").parse_challenge_response(json.dumps({"LoginResponse": response}))
    assert "synthetic-cookie" not in str(error.value)
