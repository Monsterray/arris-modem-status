# Validation: 2026-10-15

## Completed checks

| Environment | Result |
| --- | --- |
| Python 3.9.25, clean temporary environment | 338 tests pass |
| Python 3.10.22, clean temporary environment | 338 tests pass |
| Python 3.11.15, clean temporary environment | 338 tests pass |
| Python 3.12.13, clean temporary environment | 338 tests pass |
| Python 3.13.14, clean temporary environment | 338 tests pass |
| Python 3.14.7, development environment | 338 tests pass; 83.23% branch-inclusive coverage |
| Extracted source archive, Python 3.11.15 | 338 tests pass |
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

## Hardware verification still required

A single anonymous GET to `https://192.168.100.1/Login.html` timed out connecting
from the execution runtime on 2026-10-15. No challenge or credential POST was sent.
The user previously reported that the page opens in a browser. The runtime/browser
reachability difference remains unresolved; this is not evidence of a bad password
or an offline modem.

One controlled authentication succeeded earlier. Full live data retrieval and
long-running stability remain unverified. When access is restored:

1. Collect one finite sample using the known MD5 profile, serial requests, and zero
   retries. Confirm expected channels and required metadata; do not restart on an
   authentication failure.
2. Run three samples at least 900 seconds apart on one client. Confirm one login,
   unchanged session identity, complete samples, and no modem uptime reset or
   connectivity disruption.
3. Observe a longer bounded run across normal session expiry before claiming
   sustained stability. Stop on denial or uncertain login; do not trigger reboots,
   credential retries, or automatic process restarts.

Simulated passing tests establish client behavior, not firmware stability.
