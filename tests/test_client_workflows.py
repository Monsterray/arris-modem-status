"""Offline client workflows for logs, validation, and failed request batches."""

import json
from unittest.mock import Mock

import pytest
import requests

from arris_modem_status import ArrisModemStatusClient
from arris_modem_status.exceptions import ArrisAuthenticationError, ArrisOperationError
from arris_modem_status.models import ErrorCapture


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
