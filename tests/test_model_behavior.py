"""Boundary checks for the public signal, error, and performance models."""

from dataclasses import replace

import pytest

from arris_modem_status.models import ChannelInfo, ErrorCapture, LogEntry, TimingMetrics


@pytest.fixture
def channel():
    """A healthy downstream channel, with explicit units added by the model."""
    return ChannelInfo("1", "549000000", "0", "40", "256QAM", "Locked", channel_type="downstream")


@pytest.mark.parametrize(
    ("duration", "category"),
    [
        (0, "excellent"),
        (0.099, "excellent"),
        (0.1, "good"),
        (0.499, "good"),
        (0.5, "acceptable"),
        (1.999, "acceptable"),
        (2, "poor"),
    ],
)
def test_timing_categories_and_units(duration, category):
    metrics = TimingMetrics("status", 10, 10 + duration, duration, True)
    assert metrics.duration_ms == duration * 1000
    assert metrics.get_performance_category() == category
    assert metrics.is_slow(500) == (duration > 0.5)
    assert not metrics.required_retries()
    assert not metrics.is_large_response()
    assert replace(metrics, retry_count=1, response_size=10241).required_retries()
    assert replace(metrics, response_size=10241).is_large_response()
    assert not replace(metrics, response_size=10240).is_large_response()


@pytest.mark.parametrize(
    ("error_type", "status", "compatibility", "retryable", "delay", "critical"),
    [
        ("timeout", 0, False, True, 2, False),
        ("connection", 0, False, True, 1, True),
        ("http_500", 500, False, True, 1, False),
        ("busy", 429, False, True, 5, False),
        ("http_compatibility", 0, True, True, 0.5, True),
        ("http_403", 403, False, False, 1, True),
        ("unknown", 400, False, False, 1, False),
    ],
)
def test_error_recovery_contract(error_type, status, compatibility, retryable, delay, critical):
    error = ErrorCapture(1, "authentication", status, error_type, "synthetic", {}, "", False, compatibility)
    assert error.is_retryable() is retryable
    assert error.get_retry_delay() == delay
    assert error.get_retry_delay(attempt=2) == delay * 2
    assert error.get_retry_delay(attempt=20) == 30
    assert error.is_critical() is critical
    if error_type == "connection":
        assert not replace(error, recovery_successful=True).is_critical()
    if error_type == "http_403":
        assert not replace(error, request_type="channels").is_critical()


@pytest.mark.parametrize(("status", "locked"), [("Locked", True), ("Unlocked", False), ("Not Locked", False)])
def test_lock_status_is_not_a_substring_match(channel, status, locked):
    assert replace(channel, lock_status=status).is_locked() is locked


@pytest.mark.parametrize(
    ("corrected", "uncorrected", "total"),
    [(None, None, 0), ("0", "0", 0), ("123", "4", 127), ("invalid", "2", 2), ("3", "invalid", 3)],
)
def test_channel_counters_keep_valid_values(channel, corrected, uncorrected, total):
    current = replace(channel, corrected_errors=corrected, uncorrected_errors=uncorrected)
    assert current.get_total_errors() == total
    assert current.has_errors() is (total > 0)


def test_numeric_channel_values_and_unavailable_snr(channel):
    assert channel.frequency == "549000000 Hz"
    assert channel.power == "0 dBmV"
    assert channel.snr == "40 dB"
    assert replace(channel, snr="").snr == ""
    assert replace(channel, snr="invalid").snr == "invalid"
    assert channel.get_power_numeric() == 0
    assert channel.get_snr_numeric() == 40
    assert channel.get_frequency_mhz() == 549
    assert channel.is_power_in_range()
    assert not replace(channel, power="11").is_power_in_range()
    assert replace(channel, power="11").is_power_in_range(10, 12)
    assert not replace(channel, power="invalid").is_power_in_range()
    with pytest.raises(ValueError, match="not available"):
        replace(channel, snr="N/A").get_snr_numeric()


@pytest.mark.parametrize(
    ("changes", "quality", "attention"),
    [
        ({}, "excellent", False),
        ({"lock_status": "Unlocked"}, "critical", True),
        ({"uncorrected_errors": "1"}, "critical", True),
        ({"uncorrected_errors": "0"}, "excellent", False),
        ({"power": "invalid", "uncorrected_errors": "1"}, "unknown", True),
        ({"power": "invalid"}, "unknown", False),
        ({"power": "8", "snr": "32"}, "good", False),
        ({"power": "11", "snr": "29"}, "acceptable", False),
        ({"power": "11", "snr": "29", "corrected_errors": "101"}, "poor", True),
        ({"corrected_errors": "1001"}, "good", True),
        ({"corrected_errors": "100"}, "excellent", False),
        ({"corrected_errors": "101"}, "excellent", False),
        ({"snr": "N/A", "channel_type": "upstream"}, "excellent", False),
        ({"snr": "invalid", "corrected_errors": "invalid", "uncorrected_errors": "invalid"}, "excellent", False),
    ],
)
def test_signal_quality_and_attention_boundaries(channel, changes, quality, attention):
    current = replace(channel, **changes)
    assert current.get_signal_quality() == quality
    assert current.needs_attention() is attention


def test_log_display_and_age_use_stable_time(monkeypatch):
    log = LogEntry(0, "Info", "Synthetic event")
    assert log.format_for_display() == "[01/01/1970 00:00:00] Info: Synthetic event"
    monkeypatch.setattr("time.time", lambda: 12.5)
    assert log.get_age_seconds() == 12.5
