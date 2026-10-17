"""Keep explicit modem interface selection scoped to the client's sockets."""

import socket
import sys
from unittest.mock import MagicMock, Mock

import pytest

from arris_modem_status import ArrisModemStatusClient
from arris_modem_status.cli.args import create_parser
from arris_modem_status.cli.connectivity import quick_connectivity_check
from arris_modem_status.cli.main import create_client, perform_connectivity_check
from arris_modem_status.cli.monitor import main as monitor_main
from arris_modem_status.exceptions import ArrisConfigurationError
from arris_modem_status.http_compatibility import get_interface_socket_option


def test_macos_interface_is_applied_to_connection_pool(monkeypatch):
    """macOS must bind modem sockets to the selected LAN rather than the VPN default."""
    monkeypatch.setattr(sys, "platform", "darwin")
    lookup = Mock(return_value=5)
    monkeypatch.setattr(socket, "if_nametoindex", lookup)
    with ArrisModemStatusClient(password="synthetic", network_interface="en0") as client:
        adapter = client.session.get_adapter(client.base_url)
        pool = adapter.poolmanager.connection_from_url(client.base_url)
        assert (socket.IPPROTO_IP, 25, 5) in pool.conn_kw["socket_options"]
        assert adapter.max_retries.total == 0
        assert not client.session.trust_env
    lookup.assert_called_once_with("en0")


def test_interface_selection_cannot_be_silently_ignored_by_legacy_transport():
    """The raw socket transport must refuse an interface it cannot honor."""
    with pytest.raises(ArrisConfigurationError, match="standard HTTP"):
        ArrisModemStatusClient(password="synthetic", network_interface="en0", relaxed_http=True)


def test_unknown_interface_fails_before_network_io(monkeypatch):
    """A typo must not fall back to the default route and submit credentials there."""
    monkeypatch.setattr(socket, "if_nametoindex", Mock(side_effect=OSError("unknown interface")))
    with pytest.raises(ArrisConfigurationError, match="interface"):
        ArrisModemStatusClient(password="synthetic", network_interface="invalid0")


def test_standard_cli_passes_interface_to_client():
    """Both public entry points must make explicit interface selection available."""
    args = create_parser().parse_args(["--password", "synthetic", "--interface", "en0"])
    factory = Mock()
    create_client(args, factory)
    assert factory.call_args.kwargs["network_interface"] == "en0"


def test_linux_interface_option(monkeypatch):
    """Linux uses device binding instead of the Darwin socket option."""
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setattr(socket, "if_nametoindex", lambda _: 5)
    monkeypatch.setattr(socket, "SO_BINDTODEVICE", 25, raising=False)
    assert get_interface_socket_option("eth0") == (socket.SOL_SOCKET, 25, b"eth0\0")


def test_unsupported_interface_binding_fails_explicitly(monkeypatch):
    """An unsupported OS must never silently submit credentials on its default route."""
    monkeypatch.setattr(sys, "platform", "freebsd13")
    monkeypatch.setattr(socket, "if_nametoindex", lambda _: 5)
    with pytest.raises(ArrisConfigurationError, match="macOS and Linux"):
        get_interface_socket_option("em0")


def test_linux_without_device_binding_fails_explicitly(monkeypatch):
    """An unusual Python build must not silently ignore the requested interface."""
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setattr(socket, "if_nametoindex", lambda _: 5)
    monkeypatch.setattr(socket, "SO_BINDTODEVICE", None, raising=False)
    with pytest.raises(ArrisConfigurationError, match="unavailable"):
        get_interface_socket_option("eth0")


def test_quick_check_binds_the_same_interface(monkeypatch):
    """The optional preflight must not use the broken VPN path ahead of a bound client."""
    monkeypatch.setattr(sys, "platform", "darwin")
    monkeypatch.setattr(socket, "if_nametoindex", lambda _: 5)
    factory = MagicMock()
    connection = factory.return_value.__enter__.return_value
    monkeypatch.setattr(socket, "socket", factory)
    assert quick_connectivity_check("192.168.100.1", network_interface="en0") == (True, None)
    connection.setsockopt.assert_called_once_with(socket.IPPROTO_IP, 25, 5)
    connection.connect.assert_called_once_with(("192.168.100.1", 443))


def test_cli_preflight_receives_interface(monkeypatch):
    """The standard CLI must route both preflight and data through the selected LAN."""
    args = create_parser().parse_args(["--interface", "en0", "--quick-check"])
    check = Mock(return_value=(True, None))
    monkeypatch.setattr("arris_modem_status.cli.main.quick_connectivity_check", check)
    assert perform_connectivity_check(args)
    check.assert_called_once_with(args.host, args.port, timeout=2.0, network_interface="en0")


def test_monitor_receives_interface(monkeypatch):
    """The conservative entry point must honor the same explicit interface."""
    factory = MagicMock()
    monkeypatch.setattr("arris_modem_status.cli.monitor.ArrisModemStatusClient", factory)
    monkeypatch.setattr("arris_modem_status.cli.monitor.getpass", lambda _: "synthetic")
    monkeypatch.setattr("arris_modem_status.cli.monitor.poll", Mock())
    assert monitor_main(["--hmac-algorithm", "md5", "--interface", "en0"]) == 0
    assert factory.call_args.kwargs["network_interface"] == "en0"
