"""Offline CLI, protocol validation, and malformed-data boundaries."""

import json
import runpy
from unittest.mock import MagicMock, Mock

import pytest

from arris_modem_status.cli.args import create_parser
from arris_modem_status.cli.formatters import print_summary_to_stderr
from arris_modem_status.cli.main import create_client
from arris_modem_status.cli.main import main as cli_main
from arris_modem_status.cli.monitor import main as monitor_main
from arris_modem_status.client.auth import HNAPAuthenticator
from arris_modem_status.client.parser import HNAPResponseParser
from arris_modem_status.exceptions import ArrisConfigurationError, ArrisParsingError
from arris_modem_status.instrumentation import PerformanceInstrumentation
from arris_modem_status.models import ChannelInfo


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


def test_module_entrypoint_exposes_help_without_network(monkeypatch, capsys):
    monkeypatch.setattr("sys.argv", ["arris-modem-status", "--help"])
    with pytest.raises(SystemExit) as result:
        runpy.run_module("arris_modem_status.cli", run_name="__main__")
    assert result.value.code == 0
    assert "--hmac-algorithm" in capsys.readouterr().out


@pytest.mark.parametrize("arguments", [["--samples", "0"], ["--interval", "899"]])
def test_monitor_rejects_unbounded_or_aggressive_sampling(arguments):
    with pytest.raises(SystemExit) as error:
        monitor_main(["--hmac-algorithm", "md5", *arguments])
    assert error.value.code == 2


@pytest.mark.parametrize("content", [b"", b"\xff"])
def test_monitor_rejects_invalid_password_files_before_network(content, tmp_path, capsys):
    path = tmp_path / "password"
    path.write_bytes(content)
    if not content:
        with pytest.raises(SystemExit) as error:
            monitor_main(["--hmac-algorithm", "md5", "--password-file", str(path)])
        assert error.value.code == 2
    else:
        assert monitor_main(["--hmac-algorithm", "md5", "--password-file", str(path)]) == 1
    assert capsys.readouterr().out == ""


def test_monitor_handles_ctrl_c_without_traceback(monkeypatch, capsys):
    monkeypatch.setattr("arris_modem_status.cli.monitor.getpass", Mock(side_effect=KeyboardInterrupt()))
    assert monitor_main(["--hmac-algorithm", "md5"]) == 130
    assert capsys.readouterr().err == "Monitoring stopped.\n"


def test_monitor_handles_file_io_failure_and_sample_error(monkeypatch, tmp_path, capsys):
    assert monitor_main(["--hmac-algorithm", "md5", "--password-file", str(tmp_path / "missing")]) == 1
    factory = MagicMock()
    from arris_modem_status.exceptions import ArrisOperationError

    factory.return_value.__enter__.return_value.get_status.side_effect = ArrisOperationError("incomplete")
    monkeypatch.setattr("arris_modem_status.cli.monitor.ArrisModemStatusClient", factory)
    monkeypatch.setattr("arris_modem_status.cli.monitor.getpass", lambda _: "synthetic")
    assert monitor_main(["--hmac-algorithm", "md5"]) == 1
    assert capsys.readouterr().out == ""


def test_interactive_standard_cli_uses_hidden_prompt(monkeypatch):
    monkeypatch.delenv("ARRIS_PW", raising=False)
    monkeypatch.setattr("arris_modem_status.cli.main.os.isatty", lambda _: True)
    prompt = Mock(return_value="synthetic$@!")
    monkeypatch.setattr("arris_modem_status.cli.main.getpass", prompt)
    factory = Mock()
    create_client(create_parser().parse_args([]), factory)
    prompt.assert_called_once()
    assert factory.call_args.kwargs["password"] == "synthetic$@!"


def test_complete_summary_includes_time_and_concurrent_diagnostics(capsys):
    channel = ChannelInfo("1", "549000000", "0", "40", "256QAM", "Locked")
    status = {
        "system_uptime-seconds": 86400,
        "mac_address": "AA:BB:CC:DD:EE:FF",
        "current_system_time-ISO8601": "2026-01-13T00:00:00",
        "downstream_channels": [channel],
        "_request_mode": "concurrent",
        "_error_analysis": {"error_types": {"http_403": 1}},
    }
    print_summary_to_stderr(status)
    output = capsys.readouterr()
    assert not output.out
    assert "Uptime (days): 1.0" in output.err
    assert "Current Time (ISO)" in output.err
    assert "PARALLEL" in output.err
    assert "HTTP 403 Errors: 1" in output.err


@pytest.mark.parametrize("bad_response", ["null", "[]", '{"GetMultipleHNAPsResponse":[]}'])
def test_malformed_metadata_does_not_discard_other_valid_responses(bad_response, mock_modem_responses):
    sample = HNAPResponseParser().parse_responses(
        {"software_info": bad_response, "channel_info": mock_modem_responses["complete_status"]}
    )
    assert len(sample["downstream_channels"]) == 3
    assert sample["model_name"] == "Unknown"


def test_parser_handles_empty_software_and_missing_startup_fields():
    sample = HNAPResponseParser().parse_responses({"software_info": "{}", "startup_connection": "{}"})
    assert sample["model_name"] == "Unknown"
    assert not sample["channel_data_available"]


def test_bad_channel_and_log_data_fail_without_raising(monkeypatch):
    parser = HNAPResponseParser()
    assert parser._parse_channel_string(123, "downstream") == []
    assert parser._parse_logs(123) == []
    monkeypatch.setattr("time.time", lambda: 100)
    logs = parser._parse_logs("}-{0^invalid^^Warning^Synthetic")
    assert len(logs) == 1
    assert logs[0].timestamp == 100


def test_startup_fields_and_unknown_response_kinds():
    startup = {
        "GetMultipleHNAPsResponse": {
            "GetCustomerStatusStartupSequenceResponse": {
                "CustomerConnDSFreq": "549000000",
                "CustomerConnDSComment": "Locked",
                "CustomerConnConnectivityStatus": "OK",
                "CustomerConnBootStatus": "OK",
                "CustomerConnConfigurationFileStatus": "OK",
                "CustomerConnSecurityStatus": "Enabled",
            }
        }
    }
    sample = HNAPResponseParser().parse_responses({"startup_connection": json.dumps(startup), "unsupported_kind": "{}"})
    assert sample["downstream_frequency"] == "549000000"
    assert sample["connectivity_status"] == sample["boot_status"] == "OK"
    assert sample["security_status"] == "Enabled"


def test_performance_summary_handles_zero_elapsed_time(monkeypatch):
    monkeypatch.setattr("time.time", lambda: 100)
    metrics = PerformanceInstrumentation()
    metrics.record_timing("authentication_complete", 98.5)
    report = metrics.get_performance_summary()
    assert report["session_metrics"]["total_session_time"] == 0
    assert report["response_time_percentiles"]["p50"] == 1.5
    assert "Perfect reliability: 0% error rate" in report["performance_insights"]


def test_performance_summary_does_not_alert_on_small_error_rate(monkeypatch):
    now = [100]
    monkeypatch.setattr("time.time", lambda: now[0])
    metrics = PerformanceInstrumentation()
    for index in range(20):
        metrics.record_timing("status", 99, success=index > 0)
    now[0] = 120
    report = metrics.get_performance_summary()
    assert report["session_metrics"]["failed_operations"] == 1
    assert not any("throughput" in insight or "error rate" in insight for insight in report["performance_insights"])


def test_cli_reports_connection_loss_after_successful_preflight(monkeypatch, capsys):
    from arris_modem_status.exceptions import ArrisConnectionError

    monkeypatch.setattr("sys.argv", ["arris-modem-status", "--password", "synthetic", "--quick-check"])
    monkeypatch.setattr("arris_modem_status.cli.main.setup_logging", Mock(return_value=None))
    monkeypatch.setattr("arris_modem_status.cli.main.quick_connectivity_check", Mock(return_value=(True, None)))
    factory = MagicMock()
    factory.return_value.get_status.side_effect = ArrisConnectionError("connection lost after preflight")
    assert cli_main(factory) == 1
    output = capsys.readouterr()
    assert output.out == ""
    assert "connection lost after preflight" in output.err
