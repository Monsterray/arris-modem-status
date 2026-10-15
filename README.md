# arris-modem-status 🚀

## Monsterray fork

This fork fixes reproducible authentication and CLI bugs: signed login requests,
exact login-result validation, cleared authentication state before reauthentication,
honored request timeouts, and password-file errors on stderr. Regression tests also
verify that repeated status polls reuse the authenticated client session.

Install the fixes from the working branch:

```bash
python -m pip install 'git+https://github.com/Monsterray/arris-modem-status.git@fix/authentication-and-cli'
arris-modem-status --password-file /path/to/modem-password --quiet --timeout 30
```

The remaining type-check errors are also fixed. HNAP authentication now supports
explicit `md5` and `sha256` firmware variants; SHA256 remains the library default.
The firmware test results below are inherited from upstream. A controlled S33v2
login with MD5, standard HTTP, and browser-style headers returned `LoginResult: OK`.
Full status sampling and long-running modem stability remain unverified: subsequent
anonymous login-page requests timed out before any login POST was sent.

The client now uses standard HTTP by default, loads the public login page to seed
cookies, and sends browser-style headers. `relaxed_http=True` in Python or the
monitor's `--relaxed-http` option selects legacy raw-socket parsing for firmware
that requires it. HTTP adapters do not perform hidden retries; the conservative
monitor also sets request-handler retries to zero.

See [the source comparison and improvement roadmap](docs/monitoring-research.md)
for the nine repositories reviewed, pinned source references, and hardware-test limits.
See [testing results and remaining hardware checks](docs/testing.md) for the
compatibility matrix, package validation, and reproducible regression commands.

### Conservative S33v2 sampling

Open `https://192.168.100.1/Login.html` from a computer behind your router. Confirm
the password with the modem's normal interface before using the script. Determine
the hash algorithm by inspecting the public `js/Login.js` and `js/SOAP/SOAPAction.js`
scripts: `hex_hmac_md5` means `md5`; `hex_hmac_sha256` means `sha256`. Firmware varies,
so do not discover the algorithm by repeatedly attempting logins. A reported S33v2
used MD5 and became stable after session-handling fixes in another monitor
([report and follow-up](https://github.com/solentlabs/cable_modem_monitor/issues/117)).

For MD5 firmware, collect one sample with a locally prompted password:

```bash
python -m arris_modem_status.cli.monitor --host 192.168.100.1 --hmac-algorithm md5 > modem-sample.jsonl
```

After confirming successful data collection, a bounded monitoring run is:

```bash
python -m arris_modem_status.cli.monitor --host 192.168.100.1 --hmac-algorithm md5 --samples 3 --interval 900 > modem-samples.jsonl
```

The monitor defaults to one sample and enforces at least 15 minutes between samples.
It reuses one authenticated client, sends serial requests, disables request retries
and performance-history accumulation, skips event-log queries, and exits on a failed
or incomplete sample. It does not automatically reauthenticate or reboot the modem.
If the session expires, stop and investigate before starting a new run. Ctrl-C stops
sampling. An optional `--password-file` reads the first line of a local credential
file; protect that file with owner-only permissions.

For lower-load signal collection, add `--channels-only`. It fetches downstream
and upstream channels together in one status request instead of four; software,
startup, registration, and event-log queries are omitted. Fields supplied only by
those metadata queries may show `Unknown` in this mode.

```bash
python -m arris_modem_status.cli.monitor --hmac-algorithm md5 --password-file modem_pass --channels-only
```

The standard `arris-modem-status` entry point also supports `--hmac-algorithm`,
`--channels-only`, and `--relaxed-http`. Confirm the firmware's hash algorithm
before using either entry point; the standard CLI retains SHA256 as its default.

Login POSTs are attempted once even when status retries are configured. HNAP
redirects are refused. A rejected session, malformed challenge, or uncertain login
result blocks further authentication on that client and discards its session keys
and cookies. After checking the modem, explicitly create a new client to proceed;
do not wrap authentication failure in an automatic process-restart loop. A status
connection failure preserves the existing session and stops the query batch.
In concurrent mode, queued work is cancelled; requests already in flight may finish.

Authentication errors report recognized outcome codes instead of response bodies
that might contain session secrets. Connectivity errors give connectivity guidance.
The automated test suite blocks unmocked TCP connections and DNS lookups, so it
cannot query the physical modem accidentally.

Passwords are literal Unicode text: `$`, `@`, `!`, quotes, backslashes, and leading
or trailing spaces are preserved. At the interactive password prompt, type the
password exactly as it is; do not add shell quotes or escape characters. UTF-8
password files preserve spaces and punctuation and remove only the first line's
line ending. The first-line format does not represent multiline passwords.
Avoid placing passwords directly in shell commands, where the shell can expand
characters before Python receives them and may save them in command history.

Run only one collector and leave other modem scrapers disabled during validation.
Separate CLI invocations each create a new login session, so avoid scheduling them
as frequent cron jobs. Increasing the interval is a conservative choice, not a
guarantee against firmware crashes. Check uptime and connection stability before
extending the monitoring period.

### Offline browser-login comparison

For future firmware-specific login failures, save one successful browser login's
Network capture as a HAR file and keep it local. HAR files can contain session
credentials; do not upload or commit the raw capture. Compare it without sending
any modem requests:

```bash
python -m arris_modem_status.cli.compare_login --har /path/to/browser-login.har --hmac-algorithm md5
```

The command prompts for the password locally and outputs only whether the browser
login succeeded and whether the password hash, signatures, and cookies match.
No credential values are printed. Independent test vectors generated by the modem's
actual MD5 JavaScript verify punctuation, Unicode, spaces, and long HMAC keys.

[![Quality Check](https://github.com/csmarshall/arris-modem-status/actions/workflows/quality-check.yml/badge.svg)](https://github.com/csmarshall/arris-modem-status/actions/workflows/quality-check.yml)
[![codecov](https://codecov.io/gh/csmarshall/arris-modem-status/branch/main/graph/badge.svg)](https://codecov.io/gh/csmarshall/arris-modem-status)
[![PyPI version](https://badge.fury.io/py/arris-modem-status.svg)](https://badge.fury.io/py/arris-modem-status)
[![Python versions](https://img.shields.io/pypi/pyversions/arris-modem-status.svg)](https://pypi.org/project/arris-modem-status/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Buy Me A Coffee](https://img.shields.io/badge/Buy%20Me%20A%20Coffee-support-yellow?logo=buy-me-a-coffee)](https://www.buymeacoffee.com/cs_marshall)

I got tired of logging into my Arris cable modem's clunky web interface just to check signal levels. So, with the help of AI (Claude), I reverse-engineered the modem's API and built this Python library!

## What's This Thing Do? 🤔

It grabs **ALL** the juicy details from your Arris S34 (and likely S33/SB8200) cable modem:
- 📊 Signal levels, SNR, error counts
- 🌊 Downstream/upstream channel info
- 🔧 Model name, firmware version, hardware version
- ⏰ System uptime (e.g., "27 day(s) 10h:12m:37s")
- 🔒 Boot status, security status, connectivity state
- ⚡ And it's FAST (< 2 seconds in serial mode)

## Quick Start 🏃‍♂️

```bash
# Install the latest version (v1.0.3)
pip install arris-modem-status

# Check your modem (serial mode by default for reliability)
arris-modem-status --password YOUR_PASSWORD

# Get JSON for your monitoring setup
arris-modem-status --password YOUR_PASSWORD --quiet | jq

# Use parallel mode if your modem supports it (30% faster but may fail)
arris-modem-status --password YOUR_PASSWORD --parallel
```

## Python Usage 🐍

```python
from arris_modem_status import ArrisModemStatusClient

# Serial mode by default (recommended)
with ArrisModemStatusClient(password="YOUR_PASSWORD") as client:
    status = client.get_status()

    print(f"Modem: {status['model_name']}")
    print(f"Firmware: {status['firmware_version']}")
    print(f"Uptime: {status['system_uptime']}")

    # Check signal levels
    for channel in status['downstream_channels']:
        print(f"Channel {channel.channel_id}: {channel.power} / SNR: {channel.snr}")

# Use concurrent mode if your modem handles it well
with ArrisModemStatusClient(password="YOUR_PASSWORD", concurrent=True) as client:
    status = client.get_status()  # ~30% faster but may get HTTP 403 errors
```

## Serial vs Parallel Mode ⚠️

**DEFAULT: Serial mode** - Requests are made one at a time. Slower but much more reliable.

Many Arris modems have buggy HNAP implementations that return HTTP 403 errors when handling concurrent requests. This causes inconsistent data like:
- Sometimes getting model name, sometimes not
- Missing internet status randomly
- Partial channel information

If you want to try parallel mode for speed (at your own risk):
```bash
arris-modem-status --password YOUR_PASSWORD --parallel
```

## Complete Data Retrieved 📦

The library retrieves **ALL** available modem information, but the output format differs depending on how you use it:

### Command Line Interface Output

When using the CLI, you get both human-readable summaries (to stderr) and structured JSON (to stdout):

**Human-readable summary (stderr):**
```
============================================================
ARRIS MODEM STATUS SUMMARY
============================================================
Model: S34
Hardware Version: 1.0
Firmware: AT01.01.010.042324_S3.04.735
Uptime: 27 day(s) 10h:12m:37s
Uptime (days): 27.4
Connection Status:
  Internet: Connected
  Network Access: Allowed
  Boot Status: OK
  Security: Enabled (BPI+)
Downstream Status:
  Frequency: 549000000 Hz
  Comment: Locked
System Information:
  MAC Address: 01:23:45:67:89:AB
  Serial Number: 000000000000000
  Current Time: 07/30/2025 23:31:23
  Current Time (ISO): 2025-07-30T23:31:23
Channel Summary:
  Downstream Channels: 32
  Upstream Channels: 8
  Channel Data Available: true
  Sample Channel: ID 1, 549000000 Hz, 0.6 dBmV, SNR 39.0 dB, Errors: 15/0
============================================================
```

**JSON output (stdout) with CLI metadata:**
```json
{
  "model_name": "S34",
  "hardware_version": "1.0",
  "firmware_version": "AT01.01.010.042324_S3.04.735",
  "system_uptime": "31 day(s) 03h:42m:48s",
  "system_uptime-seconds": 2691768.0,
  "current_system_time": "08/03/2025 17:02:43",
  "current_system_time-ISO8601": "2025-08-03T17:02:43",
  "mac_address": "01:23:45:67:89:AB",
  "serial_number": "000000000000000",
  "internet_status": "Connected",
  "network_access": "Allowed",
  "boot_status": "OK",
  "boot_comment": "Operational",
  "configuration_file_status": "OK",
  "security_status": "Enabled",
  "security_comment": "BPI+",
  "downstream_frequency": "549000000 Hz",
  "downstream_comment": "Locked",
  "downstream_channels": [
    {
      "channel_id": "1",
      "frequency": "549000000 Hz",
      "power": "0.6 dBmV",
      "snr": "39.0 dB",
      "modulation": "256QAM",
      "lock_status": "Locked",
      "corrected_errors": "15",
      "uncorrected_errors": "0",
      "channel_type": "downstream"
    }
  ],
  "upstream_channels": [
    {
      "channel_id": "1",
      "frequency": "30600000 Hz",
      "power": "46.5 dBmV",
      "snr": "N/A",
      "modulation": "SC-QAM",
      "lock_status": "Locked",
      "channel_type": "upstream"
    }
  ],
  "query_timestamp": "2025-08-03T15:30:45",
  "query_host": "192.168.100.1",
  "client_version": "1.0.0",
  "elapsed_time": 1.85,
  "configuration": {
    "max_workers": 2,
    "max_retries": 3,
    "timeout": [5, 15],
    "concurrent_mode": false,
    "http_compatibility": true,
    "quick_check_performed": false
  }
}
```

### Python Library Output

When using the Python library directly, you get a cleaner dictionary focused on modem data:

```python
from arris_modem_status import ArrisModemStatusClient

with ArrisModemStatusClient(password="your_password") as client:
    status = client.get_status()
    print(status)
```

**Returns:**
```python
{
  'model_name': 'S34',
  'hardware_version': '1.0',
  'firmware_version': 'AT01.01.010.042324_S3.04.735',
  'system_uptime': '31 day(s) 03h:42m:48s',
  'system_uptime-datetime': datetime.timedelta(days=31, seconds=13368), # Python datetime.timedelta object
  'system_uptime-seconds': 2691768.0,  # Automatically parsed
  'current_system_time': '08/03/2025 17:02:43',
  'current_system_time-ISO8601': '2025-08-03T17:02:43',  # Auto-formatted
  'current_system_time-datetime': datetime.datetime(2025, 8, 3, 17, 2, 43),  # Python datetime.datetime object
  'mac_address': '01:23:45:67:89:AB',
  'serial_number': '000000000000000',
  'internet_status': 'Connected',
  'network_access': 'Allowed',
  'boot_status': 'OK',
  'boot_comment': 'Operational',
  'connectivity_status': 'OK',
  'connectivity_comment': 'Operational',
  'configuration_file_status': 'OK',
  'security_status': 'Enabled',
  'security_comment': 'BPI+',
  'downstream_frequency': '549000000 Hz',
  'downstream_comment': 'Locked',
  'downstream_channels': [
    ChannelInfo(
      channel_id='1',
      frequency='549000000 Hz',
      power='0.6 dBmV',
      snr='39.0 dB',
      modulation='256QAM',
      lock_status='Locked',
      corrected_errors='15',
      uncorrected_errors='0',
      channel_type='downstream'
    )  # ... more channels
  ],
  'upstream_channels': [
    ChannelInfo(
      channel_id='1',
      frequency='30600000 Hz',
      power='46.5 dBmV',
      snr='N/A',
      modulation='SC-QAM',
      lock_status='Locked',
      channel_type='upstream'
    )  # ... more channels
  ],
  'channel_data_available': True,
  '_request_mode': 'serial',  # Internal metadata
  '_performance': {
    'total_time': 1.85,
    'requests_successful': 4,
    'requests_total': 4,
    'mode': 'serial'
  }
}
```

### Key Differences

| Feature | CLI Output | Python Library |
|---------|------------|----------------|
| **Human Summary** | ✅ Printed to stderr | ❌ Not included |
| **CLI Metadata** | ✅ Query info, host, version | ❌ Not included |
| **Channel Objects** | ❌ Serialized to dicts | ✅ Rich ChannelInfo objects |
| **Time Parsing** | ✅ Enhanced fields | ✅ Enhanced fields |
| **Performance Data** | ✅ Configuration details | ✅ Basic timing info |
| **Monitoring Ready** | ✅ JSON with metadata | ✅ Python objects |

Both formats include automatically parsed time fields (like `system_uptime-seconds`) and enhanced data, but the CLI adds operational metadata while the Python library provides rich objects for programmatic use.

## The Cool Technical Bits 🤓

I spent way too much time figuring out:
- 🔐 The HNAP authentication (challenge-response with HMAC-SHA256)
- 🏎️ Why concurrent requests fail (modem firmware bugs causing HTTP 403)
- 🛡️ HTTP compatibility quirks (urllib3 is... picky)
- 📦 Complete HNAP request mapping (including the missing GetCustomerStatusSoftware!)
- 🐛 Why data was inconsistent (partial request failures in concurrent mode)

## Monitoring Integration 📈

Perfect for Grafana, Prometheus, or any monitoring stack:

```python
# Quick Prometheus exporter example
from prometheus_client import Gauge
downstream_power = Gauge('arris_downstream_power_dbmv', 'Power', ['channel'])

# Update metrics
for ch in status['downstream_channels']:
    downstream_power.labels(channel=ch.channel_id).set(float(ch.power.split()[0]))
```

## Disclaimer

This is an unofficial library not affiliated with ARRIS® or CommScope, Inc. ARRIS® is a registered trademark of CommScope, Inc.

This is a personal project provided as-is under the MIT license.

## Is my modem supported? ☎️

**Tested Models & Firmware:**

<!-- IMPORTANT: Update firmware versions here and in FIRMWARE_COMPATIBILITY.md when compatibility changes -->
- ✅ **Arris S34** - Firmware `AT01.01.010.042324_S3.04.735` (tested 2025-10-17)
- ⚠️ **Arris S33** - Firmware `AT01.01.018.042324_S3.03.735` (tested 2026-01-16)
- ⚠️ **Arris SB8200** - Likely compatible (not yet tested)

See [FIRMWARE_COMPATIBILITY.md](FIRMWARE_COMPATIBILITY.md) for detailed firmware version tracking and known protocol changes.

**Note**: Firmware updates can change authentication behavior or protocol requirements. If you encounter issues after a firmware update, please:
1. Check [FIRMWARE_COMPATIBILITY.md](FIRMWARE_COMPATIBILITY.md) for your firmware version
2. Open an issue with your firmware version and error details
3. Optionally provide a HAR capture (see debugging section above)

I'm open to helping to triage issues with different firmware versions or models!


## Debugging Protocol Issues 🔍

If you encounter authentication errors like `"LoginResult": "RELOAD"`, here's how we debug them using browser comparison:

### The RELOAD Bug Fix (October 2025)

**Problem**: Python client was getting `"LoginResult": "RELOAD"` instead of authentication challenge on first connection.

**Debugging Process**:

1. **Capture browser behavior** using Firefox Developer Tools:
   - Network tab → HAR export during successful login
   - Captured both regular and private browsing sessions

2. **Use enhanced_deep_capture.py** (in `debug_tools/`) for detailed analysis:
   ```bash
   python debug_tools/enhanced_deep_capture.py --password YOUR_PASSWORD
   ```
   This creates:
   - `deep_capture.har` - Complete network capture
   - `deep_capture.json` - Structured data with cookie timeline

3. **Compare browser vs Python client**:
   - Browser sent `HNAP_AUTH` header on challenge request ✅
   - Python client did NOT send `HNAP_AUTH` on challenge request ❌

4. **Analyzed JavaScript source** from captured HAR files:
   ```javascript
   var PrivateKey=$.cookie('PrivateKey');
   if(PrivateKey == null) PrivateKey = "withoutloginkey"; // Fallback!
   var auth = hex_hmac_sha256(PrivateKey, current_time.toString()+URI);
   ajaxObj.setHeader("HNAP_AUTH", auth + " " + current_time);
   ```

5. **Root cause**: Modem requires `HNAP_AUTH` header on ALL requests, even initial challenge. Browser uses `"withoutloginkey"` as fallback when no PrivateKey exists.

6. **The fix**:
   - Generate `HNAP_AUTH` token before challenge request (using "withoutloginkey")
   - Send token with challenge request to match browser behavior
   - Modified `arris_modem_status/client/main.py` and `arris_modem_status/client/http.py`

### General Debugging Tips

For similar protocol issues:

1. **Browser HAR Export**: Capture working browser session (Firefox DevTools → Network → Save as HAR)
2. **Compare Headers**: Look at request headers, especially `HNAP_AUTH`, `SOAPAction`, cookies
3. **Check JavaScript**: Extract and read modem's JavaScript files from HAR to understand client-side logic
4. **Use deep_capture.py**: Automated browser capture with cookie/storage timeline
5. **Test Incrementally**: Make one change at a time and verify with `--debug` flag

The key is comparing what the browser does vs what the Python client does, header by header.

## Found a Bug? Want a Feature? 🐛

Open an issue! PRs welcome! The codebase is pretty clean thanks to the AI helping me follow best practices.

## The Story 📖

I started this because I'm obsessive about my internet connection quality (aren't we all?). After discovering the modem had an API, I went down a rabbit hole of reverse engineering with Claude as my copilot.

Fun discoveries:
- The modem returns the same data in multiple HNAP responses (redundancy FTW)
- Many modems can't handle concurrent requests (firmware bugs)
- The missing firmware version was in GetCustomerStatusSoftware all along
- Serial mode is more reliable than parallel for most modems

## Requirements 📋

- Python 3.9+
- An Arris S34 (and likely S33/SB8200) cable modem
- The admin password [by default the last 8 digits of your modem's serial number](https://arris.my.salesforce-sites.com/consumers/articles/Knowledge/S33-Web-Manager-Access/?l=en_US&fs=RelatedArticle)
- Patience if your modem hates concurrent requests

## License 📄

MIT - Use it, modify it, monitoring-ify it!

---

Built with 🧠 + 🤖 by Charles Marshall | [GitHub](https://github.com/csmarshall)
