"""Failure injection at public transport and diagnostic boundaries, without I/O."""

import socket
from unittest.mock import Mock

import pytest
import requests

from arris_modem_status.client.error_handler import ErrorAnalyzer
from arris_modem_status.client.http import HNAPRequestHandler
from arris_modem_status.exceptions import (
    ArrisAuthenticationError,
    ArrisConnectionError,
    ArrisHTTPError,
    ArrisTimeoutError,
    wrap_connection_error,
)
from arris_modem_status.http_compatibility import ArrisCompatibleHTTPAdapter
from arris_modem_status.instrumentation import PerformanceInstrumentation


@pytest.mark.parametrize("repr_fails", [False, True])
def test_error_analyzer_survives_unprintable_errors(repr_fails):
    class BrokenMessageError(Exception):
        def __str__(self):
            raise ValueError("broken string conversion")

        def __repr__(self):
            if repr_fails:
                raise ValueError("broken repr conversion")
            return "safe diagnostic"

    capture = ErrorAnalyzer().analyze_error(BrokenMessageError(), "status")
    assert capture.error_type == "unknown"
    assert capture.raw_error == ("<BrokenMessageError instance>" if repr_fails else "safe diagnostic")


@pytest.mark.parametrize("content_mode", ["bytes", "absent", "broken"])
def test_error_analyzer_falls_back_when_response_decoding_fails(content_mode):
    class BrokenResponse:
        status_code = 500

        def __init__(self):
            self.headers = {}

        @property
        def text(self):
            raise UnicodeError("bad decoding")

        @property
        def content(self):
            if content_mode == "absent":
                raise AttributeError("no content")
            if content_mode == "broken":
                raise ValueError("bad bytes")
            return b"safe fallback"

    capture = ErrorAnalyzer().analyze_error(ValueError("synthetic"), "status", BrokenResponse())
    assert capture.http_status == 500
    assert capture.partial_content == ("b'safe fallback'" if content_mode == "bytes" else "Unable to extract content")


def test_error_analyzer_handles_broken_headers_and_can_clear_history():
    class BrokenHeaders:
        status_code = 500
        text = "body"

        @property
        def headers(self):
            raise ValueError("bad headers")

    analyzer = ErrorAnalyzer()
    capture = analyzer.analyze_error(ValueError("synthetic"), "status", BrokenHeaders())
    assert capture.response_headers == {}
    analyzer.clear_captures()
    assert analyzer.get_error_analysis() == {"message": "No errors captured yet"}


def test_error_analysis_aggregates_mixed_recoveries():
    analyzer = ErrorAnalyzer()
    analyzer.analyze_error(ValueError("HTTP 403"), "status").recovery_successful = True
    analyzer.analyze_error(ValueError("HeaderParsingError"), "status")
    report = analyzer.get_error_analysis()
    assert report["total_errors"] == 2
    assert report["recovery_stats"] == {"total_recoveries": 1, "recovery_rate": 0.5}
    assert report["http_compatibility_issues"] == 1
    assert len(report["patterns"]) == 3
    assert report["timeline"][0]["recovered"]


def test_disabled_error_history_still_returns_diagnostics():
    analyzer = ErrorAnalyzer(capture_errors=False)
    capture = analyzer.analyze_error(ValueError("timeout"), "status")
    assert capture.error_type == "timeout"
    assert analyzer.error_captures == []


def test_diagnostic_history_storage_failure_does_not_escape():
    class FullHistory(list):
        def append(self, value):
            raise MemoryError("synthetic history capacity failure")

    analyzer = ErrorAnalyzer()
    analyzer.error_captures = FullHistory()
    capture = analyzer.analyze_error(ValueError("synthetic-secret"), "status")
    assert capture.error_type == "analysis_failed"
    assert "synthetic-secret" not in capture.raw_error


@pytest.mark.parametrize("error", [requests.Timeout(), requests.ReadTimeout()])
def test_status_timeout_retries_even_without_message(error, monkeypatch):
    session = Mock()
    session.post.side_effect = [error, Mock(status_code=200, text="recovered")]
    monkeypatch.setattr("arris_modem_status.client.http.time.sleep", lambda _: None)
    handler = HNAPRequestHandler(session, "https://192.0.2.1:443", max_retries=1)
    assert handler.make_request_with_retry("GetMultipleHNAPs", {}) == "recovered"
    assert session.post.call_count == 2


@pytest.mark.parametrize("status", [401, 403])
def test_raised_http_auth_denial_is_not_treated_as_optional_data(status):
    response = requests.Response()
    response.status_code = status
    response._content = b"denied"
    session = Mock()
    session.post.side_effect = requests.HTTPError("denied", response=response)
    handler = HNAPRequestHandler(session, "https://192.0.2.1:443", max_retries=3)
    with pytest.raises(ArrisAuthenticationError):
        handler.make_request_with_retry("GetMultipleHNAPs", {}, authenticated=True)
    session.post.assert_called_once()


@pytest.mark.parametrize("with_response", [False, True])
@pytest.mark.parametrize("status", [404, 500])
def test_optional_unauthenticated_http_errors_return_no_data(with_response, status):
    session = Mock()
    if with_response:
        response = requests.Response()
        response.status_code = status
        response._content = b"unsupported"
        error = requests.HTTPError(f"HTTP {status}", response=response)
    else:
        error = requests.HTTPError(f"HTTP {status}")
    session.post.side_effect = error
    handler = HNAPRequestHandler(session, "https://192.0.2.1:443", max_retries=0)
    assert handler.make_request_with_retry("GetMultipleHNAPs", {}) is None


@pytest.mark.parametrize("error", [requests.RequestException("network unavailable"), ValueError("unexpected")])
@pytest.mark.parametrize("capture_fails", [False, True])
def test_optional_error_capture_does_not_change_request_outcome(error, capture_fails, monkeypatch):
    session = Mock()
    session.post.side_effect = error
    handler = HNAPRequestHandler(session, "https://192.0.2.1:443", max_retries=0)
    handler.error_analyzer = Mock()
    if capture_fails:
        handler.error_analyzer.analyze_error.side_effect = RuntimeError("diagnostic failure")
    assert handler.make_request_with_retry("GetMultipleHNAPs", {}) is None
    handler.error_analyzer.analyze_error.assert_called_once()


def test_http_error_preserves_status_when_response_body_is_absent():
    response = Mock(status_code=502, text=None)
    session = Mock()
    session.post.side_effect = requests.HTTPError("bad gateway", response=response)
    with pytest.raises(ArrisHTTPError) as error:
        HNAPRequestHandler(session, "https://192.0.2.1:443").make_request_with_retry("Other", {})
    assert error.value.status_code == 502


@pytest.mark.parametrize("error", [requests.exceptions.InvalidURL("invalid URL"), requests.HTTPError("no status")])
def test_non_network_request_errors_are_not_retried(error):
    session = Mock()
    session.post.side_effect = error
    with pytest.raises(type(error)):
        HNAPRequestHandler(session, "https://192.0.2.1:443").make_request_with_retry("Other", {})
    session.post.assert_called_once()


def test_additional_headers_and_cookie_without_optional_private_key():
    session = Mock()
    session.post.return_value = Mock(status_code=200, text="ok")
    handler = HNAPRequestHandler(session, "https://192.0.2.1:443")
    assert (
        handler.make_request_with_retry(
            "Other", {}, extra_headers={"X-Test": "value"}, authenticated=True, uid_cookie="synthetic"
        )
        == "ok"
    )
    headers = session.post.call_args.kwargs["headers"]
    assert headers["Cookie"] == "uid=synthetic"
    assert headers["X-Test"] == "value"


@pytest.mark.parametrize(("attempt", "delay"), [(0, 0.5), (5, 10), (20, 10)])
def test_backoff_can_be_deterministic_and_stays_capped(attempt, delay):
    handler = HNAPRequestHandler(Mock(), "https://192.0.2.1:443")
    assert handler._exponential_backoff(attempt, jitter=False) == delay


@pytest.mark.parametrize("error", [socket.timeout(), ConnectionRefusedError()])
def test_connection_wrapper_preserves_failure_kind(error):
    wrapped = wrap_connection_error(error, "192.0.2.1", 443)
    assert isinstance(wrapped, ArrisTimeoutError if isinstance(error, socket.timeout) else ArrisConnectionError)
    assert wrapped.details["host"] == "192.0.2.1"


@pytest.mark.parametrize("instrumented", [False, True])
@pytest.mark.parametrize("hnap", [False, True])
def test_adapter_records_failed_standard_and_legacy_requests(instrumented, hnap, monkeypatch):
    metrics = PerformanceInstrumentation() if instrumented else None
    adapter = ArrisCompatibleHTTPAdapter(instrumentation=metrics)
    request = requests.Request("GET", "https://192.0.2.1/" + ("HNAP1/" if hnap else "Login.html")).prepare()
    if hnap:
        monkeypatch.setattr(adapter, "_raw_socket_request", Mock(side_effect=ValueError("bad raw response")))
    else:
        monkeypatch.setattr(requests.adapters.HTTPAdapter, "send", Mock(side_effect=ValueError("bad response")))
    with pytest.raises(ValueError, match="bad"):
        adapter.send(request)
    if metrics:
        assert metrics.get_performance_summary()["session_metrics"]["failed_operations"] == 1


@pytest.mark.parametrize("failure", [OSError("offline"), RuntimeError("unexpected")])
def test_raw_socket_errors_are_wrapped_and_sockets_close(failure, monkeypatch):
    raw_socket = Mock()
    raw_socket.connect.side_effect = failure
    raw_socket.close.side_effect = OSError("already closed")
    monkeypatch.setattr(socket, "socket", Mock(return_value=raw_socket))
    request = requests.Request("GET", "http://192.0.2.1/HNAP1/").prepare()
    with pytest.raises(ArrisConnectionError):
        ArrisCompatibleHTTPAdapter()._raw_socket_request(request)
    assert raw_socket.close.call_count >= 1


def test_tolerant_response_skips_nonstandard_headers():
    request = requests.Request("GET", "http://192.0.2.1/HNAP1/").prepare()
    response = ArrisCompatibleHTTPAdapter()._parse_response_tolerantly(
        b"HTTP/1.1\r\nNon-standard header\r\n \r\nX-Value: kept\r\n\r\nbody", request
    )
    assert response.status_code == 200
    assert response.headers["X-Value"] == "kept"
    assert response.content == b"body"


def test_raw_receive_tolerates_content_length_without_colon():
    raw = b"HTTP/1.1 200 OK\r\nContent-Length invalid\r\nX-Test: kept\r\n\r\nbody"
    connection = Mock()
    connection.recv.side_effect = [raw, b""]
    assert ArrisCompatibleHTTPAdapter()._receive_response_tolerantly(connection) == raw
