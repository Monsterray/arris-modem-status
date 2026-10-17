"""CLI arguments, output, preflight checks, credential input, and failure handling."""

import argparse
import logging
import runpy
import socket
from io import StringIO
from unittest.mock import MagicMock, Mock, patch

import pytest

from arris_modem_status.cli.args import create_parser, parse_args, validate_args
from arris_modem_status.cli.connectivity import (
    get_optimal_timeouts,
    print_connectivity_troubleshooting,
    quick_connectivity_check,
)
from arris_modem_status.cli.formatters import (
    format_channel_data_for_display,
    format_json_output,
    print_error_suggestions,
    print_summary_to_stderr,
)
from arris_modem_status.cli.logging_setup import get_logger, setup_logging
from arris_modem_status.cli.main import create_client, main, perform_connectivity_check
from arris_modem_status.exceptions import (
    ArrisAuthenticationError,
    ArrisConfigurationError,
    ArrisConnectionError,
    ArrisModemError,
    ArrisOperationError,
    ArrisTimeoutError,
)
from arris_modem_status.models import ChannelInfo

pytestmark = pytest.mark.cli


@pytest.mark.unit
@pytest.mark.cli
class TestCLIArgs:
    """Test argument parsing module."""

    def test_parse_all_args(self):
        """Test parsing with all arguments."""
        parser = create_parser()
        args = parser.parse_args(
            [
                "--password",
                "test123",
                "--host",
                "192.168.1.1",
                "--port",
                "8443",
                "--username",
                "user",
                "--debug",
                "--quiet",
                "--timeout",
                "60",
                "--workers",
                "4",
                "--retries",
                "5",
                "--serial",  # deprecated but still parsed
                "--parallel",  # new flag
                "--quick-check",
            ]
        )

        assert args.password == "test123"
        assert args.host == "192.168.1.1"
        assert args.port == 8443
        assert args.username == "user"
        assert args.debug is True
        assert args.quiet is True
        assert args.timeout == 60
        assert args.workers == 4
        assert args.retries == 5
        assert args.serial is True  # deprecated
        assert args.parallel is True  # new flag
        assert args.quick_check is True

    @patch("sys.argv", ["arris-modem-status", "--password", "test123"])
    def test_parse_args_integration(self):
        """Test parse_args function with command line arguments."""
        args = parse_args()
        assert args.password == "test123"
        assert args.host == "192.168.100.1"
        assert args.parallel is False  # default


@pytest.mark.unit
@pytest.mark.cli
class TestCLIConnectivity:
    """Test connectivity module."""

    def test_get_optimal_timeouts_local(self):
        """Test optimal timeout calculation for local addresses."""
        local_addresses = [
            "192.168.1.1",
            "10.0.0.1",
            "172.16.0.1",
            "localhost",
            "127.0.0.1",
        ]

        for addr in local_addresses:
            connect_timeout, read_timeout = get_optimal_timeouts(addr)
            assert connect_timeout == 2
            assert read_timeout == 8

    def test_get_optimal_timeouts_remote(self):
        """Test optimal timeout calculation for remote addresses."""
        remote_addresses = ["8.8.8.8", "example.com", "1.1.1.1"]

        for addr in remote_addresses:
            connect_timeout, read_timeout = get_optimal_timeouts(addr)
            assert connect_timeout == 5
            assert read_timeout == 15


@pytest.mark.unit
@pytest.mark.cli
class TestCLIFormatters:
    """Test formatting module."""

    def test_format_channel_data_for_display(self):
        """Test channel data formatting."""
        # Create mock channel objects
        mock_channel = Mock()
        mock_channel.channel_id = "1"
        mock_channel.frequency = "549000000 Hz"
        mock_channel.power = "0.6 dBmV"
        mock_channel.snr = "39.0 dB"
        mock_channel.modulation = "256QAM"
        mock_channel.lock_status = "Locked"
        mock_channel.corrected_errors = "15"
        mock_channel.uncorrected_errors = "0"
        mock_channel.channel_type = "downstream"

        status = {
            "downstream_channels": [mock_channel],
            "upstream_channels": [],
        }

        formatted = format_channel_data_for_display(status)

        assert len(formatted["downstream_channels"]) == 1
        channel_dict = formatted["downstream_channels"][0]
        assert channel_dict["channel_id"] == "1"
        assert channel_dict["frequency"] == "549000000 Hz"
        assert channel_dict["power"] == "0.6 dBmV"

    def test_format_json_output(self):
        """Test JSON output formatting."""
        status = {"model_name": "S34", "internet_status": "Connected"}

        args = argparse.Namespace(
            host="192.168.100.1",
            workers=2,
            retries=3,
            timeout=30,
            parallel=False,  # Changed from serial to parallel
        )

        json_output = format_json_output(status, args, 1.5, True)

        assert json_output["model_name"] == "S34"
        assert json_output["internet_status"] == "Connected"
        assert json_output["query_host"] == "192.168.100.1"
        assert json_output["elapsed_time"] == 1.5
        assert json_output["configuration"]["max_workers"] == 2
        assert json_output["configuration"]["concurrent_mode"] is False  # Based on parallel=False
        assert json_output["configuration"]["quick_check_performed"] is True

    def test_print_summary_to_stderr(self, capsys):
        """Test summary output to stderr."""
        mock_channel = Mock()
        mock_channel.channel_id = "1"
        mock_channel.frequency = "549000000 Hz"
        mock_channel.power = "0.6 dBmV"
        mock_channel.snr = "39.0 dB"
        mock_channel.corrected_errors = "15"
        mock_channel.uncorrected_errors = "0"

        status = {
            "model_name": "S34",
            "firmware_version": "AT01.01.010.042324_S3.04.735",
            "hardware_version": "1.0",
            "system_uptime": "7 days 14:23:56",
            "internet_status": "Connected",
            "connection_status": "Allowed",
            "mac_address": "AA:BB:CC:DD:EE:FF",
            "downstream_channels": [mock_channel],
            "upstream_channels": [],
            "channel_data_available": True,
        }

        print_summary_to_stderr(status)

        captured = capsys.readouterr()
        assert "ARRIS MODEM STATUS SUMMARY" in captured.err
        assert "Model: S34" in captured.err
        assert "Firmware: AT01.01.010.042324_S3.04.735" in captured.err
        assert "Uptime: 7 days 14:23:56" in captured.err
        assert "Internet: Connected" in captured.err
        assert "MAC Address: AA:BB:CC:DD:EE:FF" in captured.err

    def test_print_error_suggestions_normal(self, capsys):
        """Test error suggestions in normal mode."""
        print_error_suggestions(debug=False)

        captured = capsys.readouterr()
        assert "Troubleshooting suggestions:" in captured.err
        assert "Try with --debug" in captured.err

    @patch("traceback.print_exc")
    def test_print_error_suggestions_debug(self, mock_traceback, capsys):
        """Test error suggestions in debug mode."""
        print_error_suggestions(debug=True)

        mock_traceback.assert_called_once()


@pytest.mark.integration
@pytest.mark.cli
class TestCLIMainIntegration:
    """Test main orchestration module with the new testable structure."""

    def test_main_connectivity_check_failed(self):
        """Test main execution with failed connectivity check."""
        with (
            patch("sys.argv", ["arris-modem-status", "--password", "test123", "--quick-check"]),
            patch("arris_modem_status.cli.main.quick_connectivity_check") as mock_quick_check,
        ):
            # Mock the connectivity check to fail
            mock_quick_check.return_value = (False, "Connection timeout")

            stderr_capture = StringIO()

            with patch("sys.stderr", stderr_capture):
                # Execute main - no need to pass client_class since connectivity fails first
                result = main()

            assert result == 1
            stderr_output = stderr_capture.getvalue()
            assert "Connection timeout" in stderr_output

    def test_main_keyboard_interrupt(self):
        """Test handling of keyboard interrupt."""
        # Create a mock client class that raises KeyboardInterrupt
        MockClientClass = Mock()
        MockClientClass.side_effect = KeyboardInterrupt()

        with patch("sys.argv", ["arris-modem-status", "--password", "test123"]):
            stderr_capture = StringIO()

            with patch("sys.stderr", stderr_capture):
                result = main(client_class=MockClientClass)

            assert result == 1
            stderr_output = stderr_capture.getvalue()
            assert "Operation cancelled by user" in stderr_output

    def test_main_configuration_error(self):
        """Test main execution with configuration error."""
        with patch("sys.argv", ["arris-modem-status", "--password", "test123", "--port", "0"]):
            stderr_capture = StringIO()

            with patch("sys.stderr", stderr_capture):
                result = main()

            assert result == 1
            stderr_output = stderr_capture.getvalue()
            assert "Configuration error" in stderr_output
            assert "Run with --help" in stderr_output


@pytest.mark.unit
@pytest.mark.cli
class TestCLIHelperFunctions:
    """Test the new helper functions."""

    def test_perform_connectivity_check_not_requested(self):
        """Test perform_connectivity_check when not requested."""
        args = argparse.Namespace(quick_check=False)

        result = perform_connectivity_check(args)
        assert result is True

    def test_perform_connectivity_check_success(self):
        """Test perform_connectivity_check when successful."""
        args = argparse.Namespace(quick_check=True, host="192.168.100.1", port=443)

        with patch("arris_modem_status.cli.main.quick_connectivity_check") as mock_check:
            mock_check.return_value = (True, None)

            result = perform_connectivity_check(args)
            assert result is True


@pytest.mark.unit
@pytest.mark.cli
class TestCLIEdgeCases:
    """Test edge cases in CLI modules."""

    def test_formatters_with_error_analysis_http_403(self):
        """Test summary formatting with HTTP 403 errors in error analysis."""
        mock_channel = Mock()
        mock_channel.channel_id = "1"
        mock_channel.frequency = "549000000 Hz"
        mock_channel.power = "0.6 dBmV"
        mock_channel.snr = "39.0 dB"
        mock_channel.corrected_errors = "15"
        mock_channel.uncorrected_errors = "0"

        status = {
            "model_name": "S34",
            "internet_status": "Connected",
            "downstream_channels": [mock_channel],
            "upstream_channels": [],
            "_error_analysis": {
                "total_errors": 5,
                "recovery_rate": 0.6,
                "http_compatibility_issues": 0,
                "error_types": {"http_403": 3, "timeout": 2},
            },
        }

        with patch("sys.stderr", StringIO()) as mock_stderr:
            print_summary_to_stderr(status)

            output = mock_stderr.getvalue()
            assert "HTTP 403 Errors: 3" in output
            assert "modem rejected concurrent requests" in output

    def test_formatters_with_no_channel_data(self):
        """Test formatting when channel data is completely missing."""
        status = {
            "model_name": "S34",
            "internet_status": "Connected",
            # No channel data at all
        }

        formatted = format_channel_data_for_display(status)

        # Should handle missing channel data gracefully
        assert "downstream_channels" not in formatted
        assert "upstream_channels" not in formatted

    def test_formatters_with_unknown_values(self):
        """Test summary formatting with all unknown values."""
        status = {
            # All values are "Unknown"
            "model_name": "Unknown",
            "firmware_version": "Unknown",
            "hardware_version": "Unknown",
            "system_uptime": "Unknown",
            "internet_status": "Unknown",
            "downstream_frequency": "Unknown",
            "mac_address": "Unknown",
            "downstream_channels": [],
            "upstream_channels": [],
        }

        with patch("sys.stderr", StringIO()) as mock_stderr:
            print_summary_to_stderr(status)

            output = mock_stderr.getvalue()
            # Should still print summary even with unknown values
            assert "Model: Unknown" in output
            assert "Firmware: Unknown" in output
            # Should skip sections with unknown values
            assert "Downstream Status:" not in output  # Skipped because frequency is Unknown
            assert "System Information:" not in output  # Skipped because MAC is Unknown

    def test_formatters_error_analysis_no_403(self):
        """Test error analysis formatting without HTTP 403 errors."""
        from arris_modem_status.cli.formatters import print_summary_to_stderr

        status = {
            "model_name": "S34",
            "downstream_channels": [],
            "upstream_channels": [],
            "_error_analysis": {
                "total_errors": 3,
                "recovery_rate": 0.66,
                "http_compatibility_issues": 1,
                "error_types": {"timeout": 2, "http_compatibility": 1},
            },
        }

        with patch("sys.stderr", StringIO()) as mock_stderr:
            print_summary_to_stderr(status)

            output = mock_stderr.getvalue()
            # Should show error analysis but not 403 warning
            assert "Error Analysis:" in output
            assert "HTTP 403" not in output


@pytest.mark.unit
@pytest.mark.cli
class TestFormattersCoverage:
    """Test formatters module edge cases for coverage."""

    def test_print_summary_with_downstream_frequency_known(self):
        """Test summary with known downstream frequency to trigger that section."""
        status = {
            "model_name": "S34",
            "internet_status": "Connected",
            "downstream_frequency": "549000000 Hz",  # Known value, not "Unknown"
            "downstream_comment": "Locked",
            "mac_address": "AA:BB:CC:DD:EE:FF",  # Known MAC
            "serial_number": "ABCD12345",
            "current_system_time": "2023-01-01 12:00:00",
            "downstream_channels": [],
            "upstream_channels": [],
        }

        with patch("sys.stderr", StringIO()) as mock_stderr:
            print_summary_to_stderr(status)

            output = mock_stderr.getvalue()
            # Should include downstream status section
            assert "Downstream Status:" in output
            assert "Frequency: 549000000 Hz" in output
            assert "Comment: Locked" in output
            # Should include system info section
            assert "System Information:" in output
            assert "MAC Address: AA:BB:CC:DD:EE:FF" in output


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


def test_module_entrypoint_exposes_help_without_network(monkeypatch, capsys):
    monkeypatch.setattr("sys.argv", ["arris-modem-status", "--help"])
    with pytest.raises(SystemExit) as result:
        runpy.run_module("arris_modem_status.cli", run_name="__main__")
    assert result.value.code == 0
    assert "--hmac-algorithm" in capsys.readouterr().out


def test_interactive_standard_cli_uses_hidden_prompt(monkeypatch):
    monkeypatch.delenv("ARRIS_PW", raising=False)
    monkeypatch.setattr("sys.stdout.isatty", lambda: True)
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


def test_cli_reports_connection_loss_after_successful_preflight(monkeypatch, capsys):
    from arris_modem_status.exceptions import ArrisConnectionError

    monkeypatch.setattr("sys.argv", ["arris-modem-status", "--password", "synthetic", "--quick-check"])
    monkeypatch.setattr("arris_modem_status.cli.main.setup_logging", Mock(return_value=None))
    monkeypatch.setattr("arris_modem_status.cli.main.quick_connectivity_check", Mock(return_value=(True, None)))
    factory = MagicMock()
    factory.return_value.get_status.side_effect = ArrisConnectionError("connection lost after preflight")
    assert main(factory) == 1
    output = capsys.readouterr()
    assert output.out == ""
    assert "connection lost after preflight" in output.err


@pytest.mark.parametrize(
    ("parameter", "value", "message"),
    [
        ("timeout", 0, "Timeout must"),
        ("workers", 0, "Workers must"),
        ("retries", -1, "Retries cannot"),
        ("port", 70000, "Port must"),
    ],
)
def test_invalid_arguments_report_the_offending_value(parameter, value, message):
    args = create_parser().parse_args(["--password", "synthetic"])
    setattr(args, parameter, value)
    with pytest.raises(ArrisConfigurationError, match=message) as error:
        validate_args(args)
    assert error.value.details["parameter"] == parameter
    assert error.value.details["value"] == value


@pytest.mark.parametrize(
    ("failure", "message"),
    [
        (None, None),
        (socket.timeout(), "timeout"),
        (ConnectionRefusedError(), "refused"),
        (socket.gaierror(), "DNS"),
        (OSError("Network is down"), "Network is down"),
    ],
)
def test_preflight_preserves_connection_failure_kind(failure, message, monkeypatch):
    connect = MagicMock(side_effect=failure)
    monkeypatch.setattr("socket.create_connection", connect)
    reachable, diagnostic = quick_connectivity_check("192.168.100.1", 443, 2)
    assert reachable is (failure is None)
    if failure is None:
        assert diagnostic is None
    else:
        assert message in diagnostic
    connect.assert_called_once_with(("192.168.100.1", 443), timeout=2)


@pytest.mark.parametrize(
    ("error", "suggestion"),
    [
        ("Connection timeout", "ping 192.168.100.1"),
        ("Connection refused", "--port 80"),
        ("DNS resolution failed", "Use IP address instead"),
        ("Other network error", "Network connectivity issue"),
    ],
)
def test_preflight_troubleshooting_matches_failure(error, suggestion, capsys):
    print_connectivity_troubleshooting("192.168.100.1", 443, error)
    output = capsys.readouterr()
    assert output.out == ""
    assert "TROUBLESHOOTING" in output.err
    assert suggestion in output.err


@pytest.mark.parametrize(
    ("error", "flags", "message", "suggestion"),
    [
        (ArrisAuthenticationError("Invalid password"), [], "Authentication error", "verify your password"),
        (ArrisTimeoutError("Request timed out"), [], "Timeout error", "--timeout"),
        (ArrisConnectionError("Cannot reach modem"), [], "Connection error", "TROUBLESHOOTING"),
        (ArrisOperationError("No data"), ["--parallel"], "Operation error", "removing --parallel"),
        (ArrisOperationError("No data"), [], "Operation error", "--retries"),
        (ArrisModemError("Synthetic failure"), [], "Synthetic failure", "Troubleshooting suggestions"),
        (RuntimeError("Connection timeout"), [], "Connection timeout", "TROUBLESHOOTING"),
        (ValueError("Invalid configuration"), [], "Invalid configuration", "Troubleshooting suggestions"),
    ],
)
def test_main_failure_keeps_stdout_clean_and_reports_action(error, flags, message, suggestion, monkeypatch, capsys):
    factory = MagicMock()
    factory.return_value.get_status.side_effect = error
    monkeypatch.setattr("sys.argv", ["arris-modem-status", "--password", "synthetic", *flags])
    assert main(client_class=factory) == 1
    output = capsys.readouterr()
    assert output.out == ""
    assert message in output.err
    assert suggestion in output.err
    factory.return_value.get_status.assert_called_once()


@pytest.mark.parametrize("debug", [False, True])
def test_logging_levels_and_optional_file(debug, tmp_path):
    path = tmp_path / "diagnostic.log"
    setup_logging(debug=debug, log_file=str(path) if debug else None)
    logger = get_logger("collector-test")
    logger.info("Synthetic event")
    assert logging.getLogger().level == (logging.DEBUG if debug else logging.INFO)
    assert logging.getLogger("urllib3").level == (logging.DEBUG if debug else logging.WARNING)
    if debug:
        assert "Synthetic event" in path.read_text()


@pytest.mark.parametrize(("flags", "default_factory"), [(["--serial"], False), (["--parallel"], True)])
def test_client_factory_wires_cli_options(flags, default_factory, monkeypatch):
    args = create_parser().parse_args(["--password", "synthetic", *flags])
    factory = Mock()
    if default_factory:
        monkeypatch.setattr("arris_modem_status.cli.main.ArrisModemStatusClient", factory)
    client = create_client(args) if default_factory else create_client(args, factory)
    assert client is factory.return_value
    factory.assert_called_once_with(
        host="192.168.100.1",
        port=443,
        username="admin",
        password="synthetic",
        concurrent="--parallel" in flags,
        max_workers=args.workers,
        max_retries=args.retries,
        timeout=(2, args.timeout),
        hmac_algorithm="sha256",
        relaxed_http=False,
        network_interface=None,
    )


def test_missing_password_exits_before_creating_client(monkeypatch, capsys):
    monkeypatch.delenv("ARRIS_PW", raising=False)
    factory = Mock()
    with pytest.raises(SystemExit) as error:
        create_client(create_parser().parse_args([]), factory)
    assert error.value.code == 1
    factory.assert_not_called()
    output = capsys.readouterr()
    assert output.out == ""
    assert "Missing password" in output.err
