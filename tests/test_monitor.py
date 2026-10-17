"""Conservative monitoring limits, partial samples, and terminal failures."""

from unittest.mock import MagicMock, Mock

import pytest

from arris_modem_status.cli.monitor import main as monitor_main


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
    assert all(
        call.kwargs == {"include_logs": False, "channels_only": False} for call in client.get_status.call_args_list
    )
    sleep.assert_called_once_with(900)
    assert capsys.readouterr().out == '{"sample": 1}\n'


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
    client.get_status.assert_called_once_with(include_logs=False, channels_only=False)
    assert factory.call_args.kwargs["max_retries"] == 0
    assert factory.call_args.kwargs["concurrent"] is False
    assert factory.call_args.kwargs["enable_instrumentation"] is False
    assert factory.call_args.kwargs["hmac_algorithm"] == "md5"
    assert factory.call_args.kwargs["host"] == "192.168.100.1"
    assert "Stopped:" in capsys.readouterr().err


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
