"""Lock down the HTTP path that authenticated successfully on the physical S33v2."""

from unittest.mock import Mock

import pytest
import requests
from requests.adapters import HTTPAdapter

from arris_modem_status import ArrisModemStatusClient
from arris_modem_status.exceptions import ArrisHTTPError, ArrisTimeoutError
from arris_modem_status.http_compatibility import ArrisCompatibleHTTPAdapter


def test_standard_browser_transport_is_default():
    """Use normal HTTP with no hidden retries or proxy settings for the local modem."""
    with ArrisModemStatusClient(password="synthetic", hmac_algorithm="md5", max_retries=0) as client:
        adapter = client.session.get_adapter(client.base_url)
        assert type(adapter) is HTTPAdapter
        assert adapter.max_retries.total == 0
        assert not client.session.trust_env
        assert client.session.headers["User-Agent"] == "Mozilla/5.0"
        assert client.session.headers["Origin"] == "https://192.168.100.1"
        assert client.session.headers["X-Requested-With"] == "XMLHttpRequest"


def test_legacy_transport_remains_explicit():
    """Firmware with malformed responses can opt into the previous transport."""
    with ArrisModemStatusClient(password="synthetic", relaxed_http=True) as client:
        assert isinstance(client.session.get_adapter(client.base_url), ArrisCompatibleHTTPAdapter)


def test_login_page_loaded_before_challenge(mock_modem_responses, monkeypatch, mock_login_page):
    """Authentication must seed cookies using the public login page before posting."""
    with ArrisModemStatusClient(password="synthetic", hmac_algorithm="md5", max_retries=0) as client:
        responses = iter([mock_modem_responses["challenge_response"], mock_modem_responses["login_success"]])

        def post(*args, **kwargs):
            assert mock_login_page.call_count == 1
            return Mock(status_code=200, text=next(responses))

        monkeypatch.setattr(client.session, "post", post)
        assert client.authenticate()
        mock_login_page.assert_called_once_with(
            f"{client.base_url}/Login.html", timeout=client.timeout, allow_redirects=False
        )


def test_unavailable_login_page_prevents_login_attempt(monkeypatch):
    """Do not submit credentials if the public login page cannot be loaded."""
    with ArrisModemStatusClient(password="synthetic", max_retries=0) as client:
        monkeypatch.setattr(client.session, "get", Mock(return_value=Mock(status_code=503)))
        post = Mock()
        monkeypatch.setattr(client.session, "post", post)
        with pytest.raises(ArrisHTTPError):
            client.authenticate()
        post.assert_not_called()


def test_login_page_timeout_is_not_a_credential_failure(monkeypatch):
    """A connection timeout occurs before credentials are sent and retains its type."""
    with ArrisModemStatusClient(password="synthetic", max_retries=0) as client:
        monkeypatch.setattr(client.session, "get", Mock(side_effect=requests.exceptions.ConnectTimeout()))
        post = Mock()
        monkeypatch.setattr(client.session, "post", post)
        with pytest.raises(ArrisTimeoutError, match="no login was attempted"):
            client.authenticate()
        post.assert_not_called()
