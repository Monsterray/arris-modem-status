# Validation: 2026-10-15

## Read-only router validation: 2026-10-17

446 offline cases pass on Python 3.10.22 and 3.14.7; the modem coverage gate is
unchanged. The additions verify both reviewed GUI asset versions, rejection of
unknown assets before login, safe API phase/code errors, shell-free settings
capture, preservation of auth-policy flags while removing credentials, and keeping
settings when an optional metadata read is denied.

Authenticated LuCI status reads and a broad UCI settings capture succeeded on the
hardware. Shell/file permissions are separate and some optional reads were denied.
GUI asset compatibility was updated after static review of the newly served
public bundles; authenticated GUI and SSH collection remain unconfirmed pending
local credential verification. Private captures and the configuration assessment
stay in ignored `router-data/`, outside Git and distributions. No setting changes,
speed tests, package installations, or modem operations were performed in this pass.

## Flint 2 additions: 2026-10-16

The suite now passes **442 cases** on Python 3.10.22 and 3.14.7 with pytest 9.1.1: the existing
412 modem cases plus 30 focused optional-router cases. The modem package retains
100% line and 99.76% combined coverage; that coverage measurement does not include
the checkout's router scripts. Their tests cover encrypted storage, hidden input,
firmware-specific GUI hashes, LuCI sessions/command calls, denial handling,
redaction, and bounded benchmark construction. All TCP/DNS remain blocked in pytest.
Ruff, Black, mypy, and the expanded Bandit check pass with no medium/high findings.
One reviewed Bandit suppression marks the intentional SSH command execution;
commands are fixed internally and dynamic device names are validated and quoted.

The Mac's exact router runtime dependency set passes `pip-audit` without exceptions.
Auditing the old Python 3.9 environment identified Requests/urllib3/pytest advisories
whose fixes require Python 3.10+. The optional `flint2` extra now requires patched
HTTP versions and therefore Python 3.10+; modern test dependencies also require
patched pytest. CI retains modem-only Python 3.9 checks, skips optional router tests
there, and supplies a fresh private pytest base directory. The earlier 30 router
cases ran on 3.9 before those dependency minimums were tightened.
The pytest upgrade exposed an unused asyncio plugin resolving to an incompatible
older release. There are no async tests or runtime code, so the plugin and its
configuration were removed rather than adding a new compatibility constraint.

The environment matrix below records the earlier modem-only run. The router
tools have not been authenticated against the hardware yet. See
[Flint 2 testing](flint2-testing.md) for the setup observations and live-test limits.

## Completed checks

| Environment | Result |
| --- | --- |
| Python 3.9.25, clean temporary environment | 412 tests pass |
| Python 3.10.22, clean temporary environment | 412 tests pass |
| Python 3.11.15, clean temporary environment | 412 tests pass |
| Python 3.12.13, clean temporary environment | 412 tests pass |
| Python 3.13.14, clean temporary environment | 412 tests pass |
| Python 3.14.7, development environment | 412 tests pass; 99.76% branch-inclusive coverage |
| Extracted source archive, Python 3.11.15 | 412 tests pass |
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

## Consolidated offline suite

The suite now has 412 cases across 18 test files, down from 495 cases and 32
`test_*.py` files. Test/support Python code shrank from 7,394 to 5,352 lines
(2,042 removed). Removed duplicate creation/import checks, mock-only assertions,
unused mock utilities and runner, empty test packages, and wall-clock speed checks.
Retained distinct input boundaries and the regression checks for reported bugs.
Equivalent CLI argument, connectivity, and error cases share parameterized tests;
catch-all supplemental files were folded into their feature's tests.

| Behavior | Tests to run with `--no-cov` for a focused check |
| --- | --- |
| HNAP signatures, browser comparison, password preservation | `test_authentication.py`, `test_browser_login_comparison.py`, `test_password_characters.py` |
| Login replay prevention, session failure, transport, VPN binding | `test_reliability_guards.py`, `test_browser_transport.py`, `test_http_compatibility.py`, `test_interface_binding.py` |
| Real request preparation and complete CLI/monitor output | `test_end_to_end.py` |
| Client collection, logs, channel/time/metadata parsing | `test_arris_client_core.py`, `test_log_parsing.py`, `test_channel_parsing.py`, `test_time_parsing.py`, `test_s33_metadata.py` |
| CLI/monitor limits and failures | `test_cli.py`, `test_monitor.py` |
| Model boundaries, metrics, and diagnostic failures | `test_model_behavior.py`, `test_performance_instrumentation.py`, `test_failure_boundaries.py` |

Consolidation exposed a CLI failure when no password was supplied with stdout
captured by a Python caller: `fileno()` raised `UnsupportedOperation` instead of
reporting the missing password. The CLI now uses the stream's `isatty()` method;
its regression test checks exit code, clean stdout, and no client construction.
The interactive prompt still has a separate check. Logging cleanup is shared
across all tests, and the successful status fixture now includes all five status
responses rather than quietly exhausting its response list on the final request.

Combined coverage changed from 99.80% to 99.76% after removing a synthetic
raw-handler `None`-return check. Line coverage remains 100%, the gate remains 99%,
and no coverage configuration was changed to accommodate consolidation. The suite
remains offline; this work did not contact the modem or read the password file.

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

The full offline suite now passes 412 tests under the configured 99% coverage gate.

| Measurement | Verified result |
| --- | --- |
| Combined line and branch coverage | 99.76% |
| Executable statements | 1,876 / 1,876; 100% |
| Branch outcomes | 576 / 582; 98.97% |
| Required combined coverage | 99%, raised from 80% |

No coverage exclusion rules were added or changed. Six branch outcomes remain:
optional missing preflight error text, the zero-count guard after a nonempty error
history, cleanup when the session is already absent, and empty duration/operation
guards in instrumentation, plus the internal raw-handler `None` retry path.
These remain in the measured source.

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
