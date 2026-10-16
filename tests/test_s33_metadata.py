"""S33v2 metadata uses different HNAP sources from newer firmware."""

import json
from unittest.mock import Mock

import pytest

from arris_modem_status import ArrisModemStatusClient
from arris_modem_status.client.parser import HNAPResponseParser


@pytest.mark.parametrize("reverse", [False, True])
@pytest.mark.parametrize(("uptime", "seconds"), [("2 days 1h:2m:3s", 176523), ("0 day(s) 0h:0m:0s", 0)])
def test_uptime_from_connection_info_survives_missing_software_uptime(reverse, uptime, seconds):
    """The S33v2 connection response provides uptime even when software info omits it."""
    responses = {
        "software_info": json.dumps(
            {"GetMultipleHNAPsResponse": {"GetCustomerStatusSoftwareResponse": {"StatusSoftwareModelName": "S33v2"}}}
        ),
        "startup_connection": json.dumps(
            {
                "GetMultipleHNAPsResponse": {
                    "GetCustomerStatusConnectionInfoResponse": {"CustomerConnSystemUpTime": uptime}
                }
            }
        ),
    }
    if reverse:
        responses = dict(reversed(list(responses.items())))
    sample = HNAPResponseParser().parse_responses(responses)
    assert sample["system_uptime"] == uptime
    assert sample["system_uptime-seconds"] == seconds


def test_s33_internet_status_from_device_status():
    """The actual browser reads internet status from GetArrisDeviceStatusResponse."""
    response = {"GetMultipleHNAPsResponse": {"GetArrisDeviceStatusResponse": {"InternetConnection": "Connected"}}}
    sample = HNAPResponseParser().parse_responses({"internet_register": json.dumps(response)})
    assert sample["internet_status"] == "Connected"


def test_s33_device_status_is_batched_with_existing_queries(monkeypatch, mock_modem_responses):
    """Fetching the supported S33 status method must not add another HTTP request."""
    with ArrisModemStatusClient(password="synthetic", max_retries=0, enable_instrumentation=False) as client:
        client.authenticated = True
        client.private_key = "synthetic-key"
        client.uid_cookie = "synthetic-uid"
        post = Mock(return_value=Mock(status_code=200, text=mock_modem_responses["complete_status"]))
        monkeypatch.setattr(client.session, "post", post)
        monkeypatch.setattr("arris_modem_status.client.main.time.sleep", lambda _: None)
        sample = client.get_status(include_logs=False)
        assert sample["_performance"]["requests_total"] == post.call_count == 4
        assert any("GetArrisDeviceStatus" in call.kwargs["json"]["GetMultipleHNAPs"] for call in post.call_args_list)
