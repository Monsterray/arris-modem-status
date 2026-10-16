# Validation: 2026-10-15

## Completed checks

| Environment | Result |
| --- | --- |
| Python 3.9.25, clean temporary environment | 495 tests pass |
| Python 3.10.22, clean temporary environment | 495 tests pass |
| Python 3.11.15, clean temporary environment | 495 tests pass |
| Python 3.12.13, clean temporary environment | 495 tests pass |
| Python 3.13.14, clean temporary environment | 495 tests pass |
| Python 3.14.7, development environment | 495 tests pass; 99.80% branch-inclusive coverage |
| Extracted source archive, Python 3.11.15 | 495 tests pass |
| Installed wheel outside the checkout, Python 3.13.14 | Standard CLI, monitor, and offline comparison help work |
| Wheel and source metadata | `twine check` passes |
| Distribution contents | No `modem_pass`, HAR, or JSONL paths; source archive includes test fixtures and browser vectors |
| Ruff, Black, mypy | Pass; mypy checks 21 source modules |
| Bandit | No medium/high findings; two existing low-severity findings |
| Docstrings | 98% coverage |

The prepared-request tests replace the HTTP adapter, keeping the actual Requests
request preparation, client authentication, parser, monitor, and CLI output. They
verify signatures, both session cookies, literal Unicode/punctuation/spaces in a
password file, complete JSON output, and one persistent login across three channel
samples. TCP and DNS remain blocked by the shared test fixture.

These checks reproduced and fixed:

- A field-complete challenge with a failed or unknown result could still trigger a
  credential POST. The challenge result is now checked before deriving credentials.
- Logs returned inside `GetMultipleHNAPsResponse` were silently discarded. Wrapped
  and direct log responses now use the same parser.
- CLI JSON reported an eight-second timeout even when requests used sixty seconds.
  Its metadata now follows the timeout calculation used to create the client.
- Source distributions included tests but omitted `conftest.py` and the browser
  vectors, preventing those tests from running. The manifest now includes them.

Reproduce the focused checks without contacting a modem:

```bash
python -m pytest tests/test_end_to_end.py --no-cov
python -m pytest
python -m build
python -m twine check dist/*
```

The CI workflow includes the working branch as a push trigger, retains its
Python 3.9–3.13 matrix, and builds/tests the source distribution on Python 3.11.
All six Python versions above were tested locally on macOS. Hosted Linux results
remain unverified: GitHub lists no registered workflows for this fork, despite
Actions being enabled and the workflow files existing on both branches. An explicit
dispatch of `quality-check.yml` returned HTTP 404. No hosted run was observed.

## Connection diagnosis and live sample

The failing path was reproduced before authentication: `route -n get
192.168.100.1` selected `utun7`, and a TCP connection to port 443 timed out after
three seconds. The physical LAN default uses `en0` through `192.168.8.1`.

A controlled change isolated the cause: the same anonymous HTTPS request bound
with `curl --interface en0` returned HTTP 200 (TCP connection about 7 ms, TLS about
86 ms). The project's interface-bound session also returned HTTP 200. No system
route, VPN configuration, credential, or modem setting was changed.

One live MD5 collection through `en0` then returned `LoginResult: OK`, all four
status responses, 34 downstream channels, and four upstream channels. It sent one
challenge, one credential POST, and four serial status POSTs, with no retries.
The device reported S33v2 firmware `TB01.03.001.11_051722_212.S3`. A local sample was
saved with owner-only permissions and remains ignored by Git.

The first live sample exposed two unknown metadata fields. Offline regressions
now verify that uptime comes from `GetCustomerStatusConnectionInfoResponse`, with
both supported days/time notations and zero uptime preserved, and internet status can come from
`GetArrisDeviceStatusResponse`. The latter is added to an existing request batch,
without adding an HTTP request. A second finite live sample, at least 900 seconds
after the first, verified both corrected values: uptime and its parsed seconds
were available, and internet status was `Connected`. Authentication and all four
status requests succeeded again with the same 34/4 channel counts and no retries.

The SDK's `network_interface` and both CLIs' `--interface` bind only the collector's
sockets. The optional CLI preflight uses the same binding. Invalid interfaces,
unsupported runtime binding, and the legacy raw-socket transport fail explicitly.
The default remains normal system routing. macOS IPv4 binding was verified live;
Linux device binding has offline coverage only.

## Coverage and completion

The full offline suite now passes 495 tests under the configured 99% coverage gate.

| Measurement | Verified result |
| --- | --- |
| Combined line and branch coverage | 99.80% |
| Executable statements | 1,876 / 1,876; 100% |
| Branch outcomes | 577 / 582; 99.14% |
| Required combined coverage | 99%, raised from 80% |

No coverage exclusion rules were added or changed. Five branch outcomes remain:
optional missing preflight error text, the zero-count guard after a nonempty error
history, cleanup when the session is already absent, and empty duration/operation
guards in instrumentation. These remain in the measured source.

The added checks cover signal/error/performance model boundaries, actual client
log retrieval and validation, malformed firmware and HAR inputs, redacted CLI
failures, HTTP error policy, raw-socket cleanup, and diagnostic storage failures.
They found and fixed:

- `get_logs()` passed a dictionary to the raw log-string parser, losing all logs;
  it now extracts the payload and the shared parser returns chronological entries.
- Substring lock checks treated `Not Locked` as locked; channel validation now uses
  the shared exact lock-state predicate.
- Empty-message timeout exceptions bypassed configured status retries. Typed
  timeouts now participate; login requests still never retry.
- Raised HTTP 401/403 exceptions could bypass the authenticated denial policy;
  the same stop policy now applies to returned responses and raised exceptions.
- Malformed metadata could discard otherwise usable channel responses; malformed
  HAR login objects could prevent offline comparison of a later valid flow.
- Log-retrieval errors now preserve their original structured operation details.

HTTP failure classification was consolidated to remove duplicate, unreachable
handling while retaining response redaction and conservative login behavior.
The test suite continues to block real TCP/DNS. No live modem request or real
password-file read was needed for this coverage pass. Passing simulated tests
does not establish sustained hardware stability.

## Hardware verification still required

The anonymous runtime timeouts are now explained by the VPN route. Two finite
status/channel samples and the corrected metadata are verified. These were separate
clients, not a sustained session test. Remaining acceptance work is:

1. Run three samples at least 900 seconds apart on one client. Confirm one login,
   unchanged session identity, complete samples, and no modem uptime reset or
   connectivity disruption.
2. Observe a longer bounded run across normal session expiry before claiming
   sustained stability. Stop on denial or uncertain login; do not trigger reboots,
   credential retries, or automatic process restarts.

Simulated passing tests establish client behavior, not firmware stability.
