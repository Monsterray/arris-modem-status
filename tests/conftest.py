import json
import logging
from unittest.mock import Mock, patch

import pytest


@pytest.fixture(autouse=True)
def block_network_connections(monkeypatch):
    """Automated tests must never contact a physical modem or external service."""

    def denied(*args, **kwargs):
        pytest.fail("Network I/O is forbidden in automated tests; mock the transport")

    monkeypatch.setattr("socket.socket.connect", denied)
    monkeypatch.setattr("socket.socket.connect_ex", denied)
    monkeypatch.setattr("socket.getaddrinfo", denied)


@pytest.fixture(autouse=True)
def mock_login_page(monkeypatch):
    """Keep authentication unit tests offline while simulating the public login page."""
    get = Mock(return_value=Mock(status_code=200))
    monkeypatch.setattr("requests.Session.get", get)
    return get


@pytest.fixture
def mock_modem_responses():
    """Fixture providing comprehensive mock modem responses."""
    return {
        "challenge_response": json.dumps(
            {
                "LoginResponse": {
                    "Challenge": "a1b2c3d4e5f6789012345678901234567890abcd",
                    "PublicKey": "fedcba9876543210abcdef1234567890fedcba98",
                    "Cookie": "12345678-abcd-4321-9876-fedcba987654",
                    "LoginResult": "SUCCESS",
                }
            }
        ),
        "login_success": json.dumps({"LoginResponse": {"LoginResult": "SUCCESS"}}),
        "login_failure": json.dumps({"LoginResponse": {"LoginResult": "FAILED"}}),
        "software_info": json.dumps(
            {
                "GetMultipleHNAPsResponse": {
                    "GetCustomerStatusSoftwareResponse": {
                        "StatusSoftwareModelName": "S34",
                        "StatusSoftwareSfVer": "AT01.01.010.042324_S3.04.735",
                        "StatusSoftwareHdVer": "1.0",
                        "CustomerConnSystemUpTime": "7 days 14:23:56",
                        "StatusSoftwareMac": "AA:BB:CC:DD:EE:FF",
                        "StatusSoftwareSerialNumber": "ABCD12345678",
                    }
                }
            }
        ),
        "complete_status": json.dumps(
            {
                "GetMultipleHNAPsResponse": {
                    "GetCustomerStatusDownstreamChannelInfoResponse": {
                        "CustomerConnDownstreamChannel": (
                            "1^Locked^256QAM^6^549000000^0.6^39.0^15^0|+|"
                            "2^Locked^256QAM^7^555000000^1.2^38.5^20^1|+|"
                            "3^Locked^256QAM^^561000000^-0.2^37.8^25^2"
                        )
                    },
                    "GetCustomerStatusUpstreamChannelInfoResponse": {
                        "CustomerConnUpstreamChannel": (
                            "1^Locked^SC-QAM^3^6400000^30600000^46.5|+|"
                            "2^Locked^SC-QAM^1^6400000^23700000^45.2|+|"
                            "3^Locked^OFDMA^6^44000000^25000000^44.8"
                        )
                    },
                    "GetCustomerStatusConnectionInfoResponse": {
                        "StatusSoftwareModelName": "S34",
                        "CustomerCurSystemTime": "07/31/2025 14:23:56",
                        "CustomerConnNetworkAccess": "Allowed",
                    },
                    "GetInternetConnectionStatusResponse": {"InternetConnection": "Connected"},
                    "GetArrisRegisterInfoResponse": {
                        "MacAddress": "AA:BB:CC:DD:EE:FF",
                        "SerialNumber": "ABCD12345678",
                    },
                }
            }
        ),
        "empty_channels": json.dumps(
            {
                "GetMultipleHNAPsResponse": {
                    "GetCustomerStatusDownstreamChannelInfoResponse": {"CustomerConnDownstreamChannel": ""},
                    "GetCustomerStatusUpstreamChannelInfoResponse": {"CustomerConnUpstreamChannel": ""},
                }
            }
        ),
    }


@pytest.fixture
def mock_successful_status_flow(mock_modem_responses):
    """Mock successful complete status flow."""
    with patch("requests.Session.post") as mock_post:
        # Auth flow followed by all five status requests, including event logs.
        mock_post.side_effect = [
            Mock(
                status_code=200,
                text=mock_modem_responses["challenge_response"],
            ),
            Mock(status_code=200, text=mock_modem_responses["login_success"]),
            Mock(status_code=200, text=mock_modem_responses["software_info"]),  # software_info
            Mock(status_code=200, text=mock_modem_responses["complete_status"]),  # startup_connection
            Mock(status_code=200, text=mock_modem_responses["complete_status"]),  # internet_register
            Mock(status_code=200, text=mock_modem_responses["complete_status"]),  # channel_info
            Mock(status_code=200, text='{"GetCustomerStatusLogResponse": {"CustomerStatusLogList": ""}}'),
        ]
        yield mock_post


@pytest.fixture
def sample_channel_data():
    """Sample channel data for testing."""
    return {
        "downstream": "1^Locked^256QAM^^549000000^0.6^39.0^15^0",
        "upstream": "1^Locked^SC-QAM^^^30600000^46.5",
        "malformed": "1^Locked",  # Not enough fields
        "empty": "",
    }


@pytest.fixture
def client_kwargs():
    """Default client kwargs for testing."""
    return {
        "password": "test_password",
        "host": "192.168.100.1",
        "port": 443,
        "username": "admin",
        "concurrent": False,  # Changed to False as new default
        "max_workers": 2,
        "max_retries": 2,
        "base_backoff": 0.1,
        "capture_errors": True,
        "timeout": (3, 12),
        "enable_instrumentation": True,
    }


@pytest.fixture(autouse=True)
def preserve_cli_logging():
    """Restore handlers before pytest closes the CLI's captured stderr stream."""
    root = logging.getLogger()
    handlers, level = root.handlers[:], root.level
    yield
    for handler in root.handlers[:]:
        if handler not in handlers:
            root.removeHandler(handler)
            handler.close()
    root.handlers = handlers
    root.setLevel(level)
