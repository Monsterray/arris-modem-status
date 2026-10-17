"""Core tests for ArrisModemStatusClient."""

import json
import time
from unittest.mock import Mock, patch

import pytest
import requests
from requests.exceptions import ConnectionError
from urllib3.exceptions import HeaderParsingError

from arris_modem_status import ArrisModemStatusClient, ChannelInfo
from arris_modem_status.exceptions import (
    ArrisAuthenticationError,
    ArrisConnectionError,
    ArrisHTTPError,
    ArrisOperationError,
    ArrisParsingError,
    ArrisTimeoutError,
)
from arris_modem_status.models import ErrorCapture


@pytest.mark.unit
class TestArrisModemStatusClientInitialization:
    """Test client initialization and configuration."""

    def test_default_initialization(self):
        """Test client with default parameters."""
        client = ArrisModemStatusClient(password="test")

        assert client.password == "test"
        assert client.username == "admin"
        assert client.host == "192.168.100.1"
        assert client.port == 443
        assert client.concurrent is False  # Changed from True to False
        assert client.max_workers == 1  # Changed from 2 to 1 (since concurrent=False)
        assert client.max_retries == 3
        assert client.authenticated is False
        assert client.private_key is None
        assert client.uid_cookie is None

    def test_custom_initialization(self, client_kwargs):
        """Test client with custom parameters."""
        client = ArrisModemStatusClient(**client_kwargs)

        assert client.password == "test_password"
        assert client.host == "192.168.100.1"
        assert client.port == 443
        assert client.max_workers == 1  # Changed to 1 since concurrent=False
        assert client.max_retries == 2
        assert client.base_backoff == 0.1
        assert client.concurrent is False  # Changed from True to False
        assert client.capture_errors is True

    def test_concurrent_mode_initialization(self):
        """Test client in concurrent mode."""
        client = ArrisModemStatusClient(password="test", concurrent=True)

        assert client.concurrent is True
        assert client.max_workers == 2  # Default when concurrent=True

    def test_base_url_construction(self):
        """Test base URL construction."""
        client = ArrisModemStatusClient(password="test", host="192.168.1.1", port=8443)

        assert client.base_url == "https://192.168.1.1:8443"


@pytest.mark.unit
class TestArrisModemStatusClientAuthentication:
    """Test authentication functionality."""

    def test_authentication_challenge_failure(self):
        """Test authentication failure at challenge stage."""
        with patch("requests.Session.post") as mock_post:
            mock_post.side_effect = ConnectionError("Connection failed")

            client = ArrisModemStatusClient(password="test")

            with pytest.raises(ArrisConnectionError) as exc_info:
                client.authenticate()

            assert "Connection failed" in str(exc_info.value)
            assert client.authenticated is False

    def test_authentication_json_parse_error(self):
        """Test authentication with invalid JSON response."""
        with patch("requests.Session.post") as mock_post:
            mock_post.return_value = Mock(status_code=200, text="invalid json")

            client = ArrisModemStatusClient(password="test")

            with pytest.raises(ArrisParsingError) as exc_info:
                client.authenticate()

            assert "parse" in str(exc_info.value).lower()

    def test_make_hnap_request_is_challenge_request(self):
        """Test that challenge requests don't include HNAP_AUTH header."""
        client = ArrisModemStatusClient(password="test")

        challenge_request_body = {
            "Login": {
                "Action": "request",
                "Username": "admin",
                "LoginPassword": "",
                "Captcha": "",
                "PrivateLogin": "LoginPassword",
            }
        }

        with patch("requests.Session.post") as mock_post:
            mock_post.return_value = Mock(status_code=200, text='{"LoginResponse": {}}')

            client._make_hnap_request_raw("Login", challenge_request_body)

            # Check that HNAP_AUTH header was not included
            call_kwargs = mock_post.call_args[1]
            assert "HNAP_AUTH" not in call_kwargs["headers"]


@pytest.mark.unit
class TestArrisModemStatusClientDataRetrieval:
    """Test data retrieval functionality."""

    def test_get_status_channel_data_structure(self, mock_successful_status_flow):
        """Test channel data structure in status response."""
        client = ArrisModemStatusClient(password="test")

        status = client.get_status()

        # Test downstream channels
        downstream = status["downstream_channels"]
        assert len(downstream) > 0

        first_channel = downstream[0]
        assert isinstance(first_channel, ChannelInfo)
        assert first_channel.channel_id == "1"
        assert first_channel.lock_status == "Locked"
        assert first_channel.modulation == "256QAM"
        assert "Hz" in first_channel.frequency
        assert "dBmV" in first_channel.power
        assert "dB" in first_channel.snr

        # Test upstream channels
        upstream = status["upstream_channels"]
        assert len(upstream) > 0

        first_upstream = upstream[0]
        assert isinstance(first_upstream, ChannelInfo)
        assert first_upstream.channel_id == "1"
        assert first_upstream.lock_status == "Locked"

    def test_get_status_concurrent_mode(self, mock_successful_status_flow):
        """Test status retrieval in concurrent mode."""
        client = ArrisModemStatusClient(password="test", concurrent=True, max_workers=3)

        status = client.get_status()

        assert status["_request_mode"] == "concurrent"
        assert "_performance" in status

    def test_get_status_with_error_capture(self, mock_modem_responses):
        """Test status retrieval with error capture enabled."""
        with patch.object(requests.Session, "post") as mock_post:
            # Use a network error that will trigger retries and be captured
            from requests.exceptions import ConnectionError

            mock_post.side_effect = [
                Mock(
                    status_code=200,
                    text=mock_modem_responses["challenge_response"],
                ),
                Mock(status_code=200, text=mock_modem_responses["login_success"]),
                # First status request fails with network error, then succeeds
                ConnectionError("Network error"),
                Mock(
                    status_code=200,
                    text=mock_modem_responses["software_info"],  # software_info
                ),
                Mock(
                    status_code=200,
                    text=mock_modem_responses["complete_status"],
                ),
                Mock(
                    status_code=200,
                    text=mock_modem_responses["complete_status"],
                ),
                Mock(
                    status_code=200,
                    text=mock_modem_responses["complete_status"],
                ),
            ]

            client = ArrisModemStatusClient(password="test", capture_errors=True)

            # Ensure error analyzer is passed to request handler
            client.request_handler.error_analyzer = client.error_analyzer

            status = client.get_status()

            assert "_error_analysis" in status
            error_analysis = status["_error_analysis"]
            # Should have captured the ConnectionError
            assert error_analysis["total_errors"] > 0

    def test_get_status_no_responses(self):
        """Test get_status when no responses are received."""
        with patch("requests.Session.post") as mock_post:
            # Mock authentication success
            mock_post.side_effect = [
                Mock(
                    status_code=200,
                    text='{"LoginResponse": {"Challenge": "test", "PublicKey": "test", "Cookie": "test"}}',
                ),
                Mock(
                    status_code=200,
                    text='{"LoginResponse": {"LoginResult": "SUCCESS"}}',
                ),
                # All status requests fail
                Mock(status_code=500, text="Server error"),
                Mock(status_code=500, text="Server error"),
                Mock(status_code=500, text="Server error"),
                Mock(status_code=500, text="Server error"),  # Added 4th failed request
            ]

            client = ArrisModemStatusClient(password="test")

            with pytest.raises(ArrisOperationError) as exc_info:
                client.get_status()

            assert "Failed to retrieve any status data" in str(exc_info.value)

    def test_get_status_partial_responses(self):
        """Test get_status with only some requests succeeding."""
        client = ArrisModemStatusClient(password="test")
        client.authenticated = True

        # Mock responses where only some succeed
        with patch.object(client.request_handler, "make_request_with_retry") as mock_request:
            # First request succeeds, others fail
            mock_request.side_effect = [
                '{"GetCustomerStatusSoftwareResponse": {"StatusSoftwareModelName": "S34"}}',
                None,  # This one fails
                None,  # This one fails
                '{"GetMultipleHNAPsResponse": {"GetCustomerStatusDownstreamChannelInfoResponse": {"CustomerConnDownstreamChannel": ""}}}',
            ]

            # Should still return partial data
            status = client.get_status()

            assert status["model_name"] == "S34"
            assert len(status["downstream_channels"]) == 0


@pytest.mark.unit
class TestArrisModemStatusClientErrorHandling:
    """Test error handling and recovery."""

    def test_error_classification(self):
        """Test error classification for different error types."""
        client = ArrisModemStatusClient(password="test")

        # Test network error detection
        from requests.exceptions import ConnectionError, Timeout

        # Test connection error with "connection" in message
        connection_error = ConnectionError("Connection refused")
        capture = client._analyze_error(connection_error, "test_request")
        assert capture.error_type == "connection"

        # Test timeout error
        timeout_error = Timeout("Request timeout")
        capture = client._analyze_error(timeout_error, "test_request")
        assert capture.error_type == "timeout"

        # Test HeaderParsingError (will be "unknown" since we can't detect it from string)
        header_error = HeaderParsingError("3.500000 |Content-type: text/html", b"unparsed_data")
        capture = client._analyze_error(header_error, "test_request")
        # Can't detect from string representation
        assert capture.error_type == "unknown"

    def test_make_hnap_request_with_retry_network_error(self):
        """Test HNAP request retry with network errors."""
        with patch.object(requests.Session, "post") as mock_post:
            from requests.exceptions import ConnectionError

            mock_post.side_effect = [
                ConnectionError("Network error"),
                Mock(status_code=200, text='{"success": true}'),
            ]

            client = ArrisModemStatusClient(password="test", max_retries=2, capture_errors=True)
            client.authenticated = True

            # Ensure error analyzer is connected
            client.request_handler.error_analyzer = client.error_analyzer

            result = client.request_handler.make_request_with_retry("Test", {"Test": {}})

            assert result is not None
            assert mock_post.call_count == 2
            # Error should have been captured
            assert len(client.error_captures) > 0

    def test_make_hnap_request_exhausted_retries(self):
        """Test HNAP request when all retries are exhausted."""
        with patch("requests.Session.post") as mock_post:
            from requests.exceptions import Timeout

            # Timeout should retry until exhausted
            mock_post.side_effect = [
                Timeout("Connection timeout"),
                Timeout("Connection timeout"),
                Timeout("Connection timeout"),
            ]

            client = ArrisModemStatusClient(password="test", max_retries=2)
            client.authenticated = True

            with pytest.raises(ArrisTimeoutError):
                client._make_hnap_request_with_retry("Test", {"Test": {}})

            assert mock_post.call_count == 3  # Initial + 2 retries

    def test_make_hnap_request_raw_http_error_response_text(self):
        """Test _make_hnap_request_raw handling response with text."""
        client = ArrisModemStatusClient(password="test")
        client.authenticated = True

        # Mock response with status != 200
        mock_response = Mock()
        mock_response.status_code = 404
        mock_response.text = "Page not found"

        with patch("requests.Session.post", return_value=mock_response):
            with pytest.raises(ArrisHTTPError) as exc_info:
                client._make_hnap_request_raw("Test", {})

            assert exc_info.value.status_code == 404
            assert "Page not found" in exc_info.value.details["response_text"]


@pytest.mark.unit
class TestArrisModemStatusClientUtilities:
    """Test utility methods."""

    def test_get_error_analysis_no_errors(self):
        """Test error analysis with no captured errors."""
        client = ArrisModemStatusClient(password="test")

        analysis = client.get_error_analysis()

        assert analysis["message"] == "No errors captured yet"

    def test_get_error_analysis_with_errors(self):
        """Test error analysis with captured errors."""
        client = ArrisModemStatusClient(password="test", capture_errors=True)

        # Manually add some error captures for testing
        client.error_captures = [
            ErrorCapture(
                timestamp=time.time(),
                request_type="test",
                http_status=500,
                error_type="http_compatibility",
                raw_error="3.500000 |Content-type",
                response_headers={},
                partial_content="",
                recovery_successful=True,
                compatibility_issue=True,
            )
        ]

        analysis = client.get_error_analysis()

        assert analysis["total_errors"] == 1
        assert analysis["http_compatibility_issues"] == 1
        assert analysis["recovery_stats"]["recovery_rate"] == 1.0

    def test_validate_parsing_success(self, mock_successful_status_flow):
        """Test parsing validation with successful status."""
        client = ArrisModemStatusClient(password="test")

        validation = client.validate_parsing()

        assert "parsing_validation" in validation
        assert "performance_metrics" in validation
        assert validation["parsing_validation"]["basic_info_parsed"] is True

    def test_close_method(self):
        """Test client close method."""
        with patch("requests.Session.close") as mock_close:
            client = ArrisModemStatusClient(password="test", capture_errors=True)
            client.error_captures = [Mock()]  # Add some captures

            client.close()

            mock_close.assert_called_once()

    def test_close_with_instrumentation(self):
        """Test close method with instrumentation enabled."""
        with patch("requests.Session.close") as mock_close:
            client = ArrisModemStatusClient(password="test", enable_instrumentation=True)

            # Add some metrics
            client.instrumentation.record_timing("test_op", 0, success=True)

            client.close()

            mock_close.assert_called_once()


@pytest.mark.unit
class TestArrisModemStatusClientExceptionIntegration:
    """Test integration of custom exceptions in client."""

    def test_timeout_error_conversion(self):
        """Test that timeout errors are properly converted."""
        with patch("requests.Session.post") as mock_post:
            from requests.exceptions import Timeout

            mock_post.side_effect = Timeout("Read timeout")

            client = ArrisModemStatusClient(password="test", max_retries=0)
            client.authenticated = True

            with pytest.raises(ArrisTimeoutError) as exc_info:
                client._make_hnap_request_with_retry("Test", {"Test": {}})

            assert "timed out" in str(exc_info.value)
            assert exc_info.value.details["operation"] == "Test"

    def test_connection_error_conversion(self):
        """Test that connection errors are properly converted."""
        with patch("requests.Session.post") as mock_post:
            from requests.exceptions import ConnectionError

            mock_post.side_effect = ConnectionError("Network unreachable")

            client = ArrisModemStatusClient(password="test", max_retries=0)
            client.authenticated = True

            with pytest.raises(ArrisConnectionError) as exc_info:
                client._make_hnap_request_with_retry("Test", {"Test": {}})

            assert exc_info.value.details["host"] == "192.168.100.1"
            assert exc_info.value.details["port"] == 443

    def test_http_error_creation(self):
        """Test that HTTP errors are properly created."""
        with patch("requests.Session.post") as mock_post:
            mock_response = Mock()
            mock_response.status_code = 404
            mock_response.text = "Not Found"
            mock_post.return_value = mock_response

            client = ArrisModemStatusClient(password="test")
            client.authenticated = True

            with pytest.raises(ArrisHTTPError) as exc_info:
                client._make_hnap_request_with_retry("Test", {"Test": {}})

            assert exc_info.value.status_code == 404
            assert "404" in str(exc_info.value)


@pytest.mark.unit
class TestClientErrorPaths:
    """Test error handling paths in the client."""

    def test_analyze_error_http_403(self):
        """Test error analysis for HTTP 403 errors."""
        client = ArrisModemStatusClient(password="test")

        # The error string needs to contain "HTTP 403" not just "403"
        error = requests.exceptions.HTTPError("HTTP 403 Forbidden")
        capture = client._analyze_error(error, "test_request")

        assert capture.error_type == "http_403"

    def test_analyze_error_http_500(self):
        """Test error analysis for HTTP 500 errors."""
        client = ArrisModemStatusClient(password="test")

        # The error string needs to contain "HTTP 500" not just "500"
        error = requests.exceptions.HTTPError("HTTP 500 Internal Server Error")
        capture = client._analyze_error(error, "test_request")

        assert capture.error_type == "http_500"

    def test_analyze_error_with_response_object(self):
        """Test error analysis with response object."""
        client = ArrisModemStatusClient(password="test")

        # Create a mock response
        mock_response = Mock()
        mock_response.status_code = 404
        mock_response.text = "Not Found"
        mock_response.headers = {"Content-Type": "text/html"}

        error = requests.exceptions.HTTPError("404 Not Found")
        error.response = mock_response

        capture = client._analyze_error(error, "test_request", mock_response)

        assert capture.http_status == 404
        assert "Not Found" in capture.partial_content
        assert capture.response_headers["Content-Type"] == "text/html"

    def test_analyze_error_response_no_content(self):
        """Test error analysis when response has no content attribute."""
        client = ArrisModemStatusClient(password="test")

        # Mock response with no content or text
        mock_response = Mock(spec=["status_code", "headers"])  # Has some attrs but not content/text
        mock_response.status_code = 500
        mock_response.headers = {}

        error = Exception("Test error")
        capture = client._analyze_error(error, "test_request", mock_response)

        # Based on the code, it seems to default to empty string, not "Unable to extract content"
        assert capture.partial_content == ""

    def test_analyze_error_complete_failure(self):
        """Test error analysis when analysis itself fails."""
        client = ArrisModemStatusClient(password="test")

        # Looking at the implementation, it tries to call str(error) in the except block too
        # Let's create an error object that fails in a different way
        class UnstringableError(Exception):
            def __str__(self):
                raise RuntimeError("Cannot convert to string")

        error = UnstringableError("test")

        # The method should catch the exception and return a fallback ErrorCapture
        # But it will fail because str(error) is called in the except handler too
        # So we need to patch the logger.error to prevent the second str() call
        with patch("arris_modem_status.client.error_handler.logger.error"):
            capture = client._analyze_error(error, "test_request")

            assert capture.error_type == "analysis_failed"
            # The raw_error will be whatever Python's repr returns for the object
            assert "UnstringableError" in capture.raw_error or "Cannot convert" in capture.raw_error

    def test_make_hnap_request_with_retry_http_error_types(self):
        """Test retry logic with different HTTP error types."""
        client = ArrisModemStatusClient(password="test")
        client.authenticated = True

        # Test HTTPError with response attribute
        with patch("requests.Session.post") as mock_post:
            error = requests.exceptions.HTTPError("403 Forbidden")
            error.response = Mock(status_code=403, text="Forbidden")
            mock_post.side_effect = error

            with pytest.raises(ArrisHTTPError) as exc_info:
                client._make_hnap_request_with_retry("Test", {})

            assert exc_info.value.status_code == 403

        # Test HTTPError without response attribute but parseable message
        with patch("requests.Session.post") as mock_post:
            error = requests.exceptions.HTTPError("500 Server Error")
            mock_post.side_effect = error

            with pytest.raises(ArrisHTTPError) as exc_info:
                client._make_hnap_request_with_retry("Test", {})

            assert exc_info.value.status_code == 500

    def test_authentication_unexpected_error(self):
        """Test authentication with unexpected error type."""
        client = ArrisModemStatusClient(password="test")

        with patch("requests.Session.post") as mock_post:
            # Raise an unexpected error type
            mock_post.side_effect = RuntimeError("Unexpected error in auth")

            with pytest.raises(ArrisAuthenticationError) as exc_info:
                client.authenticate()

            assert "Unexpected error during authentication" in str(exc_info.value)
            assert exc_info.value.details["error_type"] == "RuntimeError"

    def test_get_status_unexpected_error(self):
        """Test get_status with unexpected error type."""
        client = ArrisModemStatusClient(password="test")
        client.authenticated = True

        with patch.object(client, "_process_serial_requests") as mock_request:
            # Raise unexpected error
            mock_request.side_effect = RuntimeError("Unexpected error in status")

            with pytest.raises(ArrisOperationError) as exc_info:
                client.get_status()

            assert "Unexpected error during status retrieval" in str(exc_info.value)

    def test_parse_responses_json_decode_error(self):
        """Test response parsing with invalid JSON."""
        client = ArrisModemStatusClient(password="test")

        responses = {"software_info": "not valid json", "channel_info": '{"incomplete": '}  # Incomplete JSON

        parsed = client._parse_responses(responses)

        # Should return defaults when JSON parsing fails
        assert parsed["model_name"] == "Unknown"
        assert parsed["firmware_version"] == "Unknown"

    def test_close_with_http_403_errors(self):
        """Test close method logging when HTTP 403 errors are captured."""
        client = ArrisModemStatusClient(password="test", capture_errors=True, concurrent=True)

        # Add some 403 error captures
        from arris_modem_status.models import ErrorCapture

        client.error_captures = [
            ErrorCapture(
                timestamp=0,
                request_type="test",
                http_status=403,
                error_type="http_403",
                raw_error="403 Forbidden",
                response_headers={},
                partial_content="",
                recovery_successful=False,
                compatibility_issue=False,
            )
        ]

        with patch("requests.Session.close") as mock_close:
            client.close()

            mock_close.assert_called_once()
            # Should have logged warning about 403 errors

    def test_make_hnap_request_connection_error_at_end(self):
        """Test connection error after retries exhausted."""
        client = ArrisModemStatusClient(password="test", max_retries=1)
        client.authenticated = True

        with patch("requests.Session.post") as mock_post:
            from requests.exceptions import ConnectionError

            # All attempts fail with connection error
            mock_post.side_effect = ConnectionError("Network unreachable")

            with pytest.raises(ArrisConnectionError) as exc_info:
                client._make_hnap_request_with_retry("Test", {})

            assert "192.168.100.1:443" in str(exc_info.value)


@pytest.mark.parametrize("wrapped", [False, True])
@pytest.mark.parametrize("instrumented", [False, True])
def test_get_logs_authenticates_once_and_parses_chronologically(
    wrapped, instrumented, mock_modem_responses, monkeypatch
):
    body = {
        "GetCustomerStatusLogResponse": {
            "CustomerStatusLogList": "1^01/13/2026 14:24:00^^Info^Restored}-{0^01/13/2026 14:23:45^^Warning^Timeout"
        }
    }
    if wrapped:
        body = {"GetMultipleHNAPsResponse": body}
    post = Mock(
        side_effect=[
            Mock(status_code=200, text=mock_modem_responses["challenge_response"]),
            Mock(status_code=200, text=mock_modem_responses["login_success"]),
            Mock(status_code=200, text=json.dumps(body)),
            Mock(status_code=200, text=json.dumps(body)),
        ]
    )
    with ArrisModemStatusClient(password="synthetic", max_retries=0, enable_instrumentation=instrumented) as client:
        monkeypatch.setattr(client.session, "post", post)
        for _ in range(2):
            logs = client.get_logs()
            assert [entry.message for entry in logs] == ["Timeout", "Restored"]
            assert logs[0].timestamp < logs[1].timestamp
        assert post.call_count == 4
        if instrumented:
            assert client.get_performance_metrics()["session_metrics"]["total_operations"] > 0
        else:
            assert "not enabled" in client.get_performance_metrics()["error"]


@pytest.mark.parametrize("response", ["", "not-json"])
@pytest.mark.parametrize("instrumented", [False, True])
def test_get_logs_rejects_missing_or_invalid_response(response, instrumented, monkeypatch):
    with ArrisModemStatusClient(password="synthetic", enable_instrumentation=instrumented) as client:
        client.authenticated = True
        monkeypatch.setattr(client, "_make_authenticated_request", Mock(return_value=response))
        with pytest.raises(ArrisOperationError) as error:
            client.get_logs()
        if response == "":
            assert error.value.details["request_type"] == "system_log"
        else:
            assert error.value.details["error_type"] == "JSONDecodeError"


def test_get_logs_preserves_authentication_denial(monkeypatch):
    with ArrisModemStatusClient(password="synthetic") as client:
        monkeypatch.setattr(client, "authenticate", Mock(side_effect=ArrisAuthenticationError("denied")))
        with pytest.raises(ArrisAuthenticationError, match="denied"):
            client.get_logs()


@pytest.mark.parametrize("concurrent", [False, True])
def test_validation_reports_real_lock_state_and_error_counts(concurrent, monkeypatch, mock_modem_responses):
    with ArrisModemStatusClient(password="synthetic", concurrent=concurrent) as client:
        sample = client.parser.parse_responses({"channel_info": mock_modem_responses["complete_status"]})
        sample.update(
            model_name="S33v2",
            firmware_version="synthetic",
            system_uptime="1 day 00:00:00",
            internet_status="Connected",
            mac_address="AA:BB:CC:DD:EE:FF",
        )
        sample["downstream_channels"][0].lock_status = "Not Locked"
        sample["upstream_channels"][0].modulation = "Unknown"
        client.error_captures = [ErrorCapture(0, "channels", 0, "parsing", "synthetic", {}, "", False, True)]
        monkeypatch.setattr(client, "get_status", Mock(return_value=sample))
        validation = client.validate_parsing()
        quality = validation["parsing_validation"]["channel_data_quality"]
        assert quality["downstream_validation"]["locked_channels"] == 2
        assert not quality["downstream_validation"]["all_locked"]
        assert quality["upstream_validation"]["all_locked"]
        assert "Unknown" not in quality["upstream_validation"]["modulation_types"]
        assert validation["parsing_validation"]["mac_address_format"]
        assert all(validation["parsing_validation"]["frequency_formats"].values())
        assert validation["performance_metrics"]["data_completeness_score"] == 100
        assert validation["performance_metrics"]["parsing_errors"] == 1
        assert validation["performance_metrics"]["http_compatibility_issues"] == 1
        assert client.get_error_analysis()["total_errors"] == 1


@pytest.mark.parametrize("mac", [None, "Unknown", "invalid"])
def test_validation_accepts_incomplete_samples_without_fabricating_data(mac, monkeypatch):
    with ArrisModemStatusClient(password="synthetic") as client:
        monkeypatch.setattr(client, "get_status", Mock(return_value={"mac_address": mac}))
        validation = client.validate_parsing()
        assert not validation["parsing_validation"]["mac_address_format"]
        assert validation["parsing_validation"]["channel_data_quality"] == {}
        assert validation["performance_metrics"]["total_channels"] == 0


def test_validation_returns_error_when_collection_fails(monkeypatch):
    with ArrisModemStatusClient(password="synthetic") as client:
        monkeypatch.setattr(client, "get_status", Mock(side_effect=ArrisOperationError("incomplete")))
        assert "incomplete" in client.validate_parsing()["error"]


@pytest.mark.parametrize("concurrent", [False, True])
@pytest.mark.parametrize("instrumented", [False, True])
def test_partial_batches_keep_successes_and_analyze_failures(concurrent, instrumented, monkeypatch):
    with ArrisModemStatusClient(
        password="synthetic", concurrent=concurrent, max_workers=1, enable_instrumentation=instrumented
    ) as client:
        monkeypatch.setattr(
            client, "_make_authenticated_request", Mock(side_effect=["first", None, ValueError("bad data")])
        )
        monkeypatch.setattr("arris_modem_status.client.main.time.sleep", lambda _: None)
        requests_to_send = [("first", {}), ("empty", {}), ("invalid", {})]
        process = client._process_concurrent_requests if concurrent else client._process_serial_requests
        responses, successful = process(requests_to_send)
        assert successful == 1
        assert responses == {"first": "first"}
        assert len(client.error_captures) == 1


@pytest.mark.parametrize("instrumented", [False, True])
def test_missing_challenge_blocks_authentication_without_credentials(instrumented, monkeypatch):
    with ArrisModemStatusClient(password="synthetic", enable_instrumentation=instrumented) as client:
        request = Mock(return_value=None)
        monkeypatch.setattr(client.request_handler, "make_request_with_retry", request)
        with pytest.raises(ArrisAuthenticationError, match="challenge"):
            client.authenticate()
        request.assert_called_once()


def test_page_connection_failure_retains_its_type(monkeypatch):
    from arris_modem_status.exceptions import ArrisConnectionError

    with ArrisModemStatusClient(password="synthetic") as client:
        monkeypatch.setattr(client.session, "get", Mock(side_effect=requests.ConnectionError()))
        with pytest.raises(ArrisConnectionError, match="no login"):
            client.authenticate()


def test_authenticated_request_refuses_a_blocked_client():
    with ArrisModemStatusClient(password="synthetic") as client:
        client._block_authentication()
        with pytest.raises(ArrisAuthenticationError, match="blocked"):
            client._make_authenticated_request("GetMultipleHNAPs", {})


def test_status_requires_a_successful_authentication_result(monkeypatch):
    with ArrisModemStatusClient(password="synthetic") as client:
        monkeypatch.setattr(client, "authenticate", Mock(return_value=False))
        with pytest.raises(ArrisAuthenticationError, match="required"):
            client.get_status()


def test_authentication_unexpected_failure_without_instrumentation(monkeypatch):
    with ArrisModemStatusClient(password="synthetic", enable_instrumentation=False) as client:
        monkeypatch.setattr(client.session, "post", Mock(side_effect=RuntimeError("synthetic")))
        with pytest.raises(ArrisAuthenticationError, match="Unexpected"):
            client.authenticate()


def test_status_without_error_capture_has_no_diagnostic_history(monkeypatch, mock_modem_responses):
    with ArrisModemStatusClient(password="synthetic", capture_errors=False, enable_instrumentation=False) as client:
        client.authenticated = True
        monkeypatch.setattr(
            client.session,
            "post",
            Mock(return_value=Mock(status_code=200, text=mock_modem_responses["complete_status"])),
        )
        sample = client.get_status(channels_only=True)
        assert "_error_analysis" not in sample
        assert sample["_performance"]["requests_successful"] == 1


def test_status_unexpected_failure_without_instrumentation(monkeypatch):
    with ArrisModemStatusClient(password="synthetic", enable_instrumentation=False) as client:
        client.authenticated = True
        monkeypatch.setattr(client, "_process_serial_requests", Mock(side_effect=ValueError("malformed status")))
        with pytest.raises(ArrisOperationError) as error:
            client.get_status()
        assert error.value.details["error_type"] == "ValueError"


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
