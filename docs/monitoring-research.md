# S33v2 authentication and monitoring research

Research date: 2026-10-13. This is a source comparison, controlled hardware-test record, and ranked work plan. One authentication succeeded; full sampling and long-running stability remain unverified. Public repositories were cloned to `/tmp/arris-research`; source links below pin the inspected commits. The repository research made no modem login attempts. Subsequently, the user authorized using a local credential file; test processes read it internally without displaying or inspecting its contents. No raw user sample output was included in the report.

## Controlled hardware result after the source review

A single controlled MD5 challenge/login using a normal `requests.Session`, a GET of
`Login.html`, and browser-style headers returned HTTP 200 and `LoginResult: OK` for
both phases. The process read the authorized local credential file internally and
reported only status codes and outcome flags. This establishes that the credential
file and MD5 derivation worked in that configuration at that time. It does not prove
whether transport, initial cookies, headers, or earlier password entry explains the
prior failure; those variables were not isolated individually.

The fork now defaults to standard HTTP, seeds the public login page, matches those
headers, disables adapter-level retries, and retains raw-socket parsing as an explicit
`relaxed_http=True` / monitor `--relaxed-http` option. The library's request handler
still controls configured retries; conservative monitoring keeps those at zero.

A subsequent attempt to obtain a full sample could not complete. A request-level
probe showed `ConnectTimeout` while loading the public login page, with **zero login
POSTs sent**. Anonymous GET-only checks then timed out with both a plain Session and
the project Session. This is a current reachability/web-service problem, not evidence
of another rejected credential. Live login testing was stopped; no reset or reboot
was issued. An ordinary external HTTPS request subsequently returned HTTP 200, so internet connectivity to that endpoint remained available. Web-interface recovery still needs confirmation.
A complete authenticated data sample and sustained monitoring remain acceptance work.

## What the failure establishes

The supplied output establishes that the modem returned `LoginResult: FAILED` during login. It does **not** establish whether the cause is the supplied credential, a browser/script request difference, a session collision, or firmware behavior. Adding the `PrivateKey` cookie corrected a documented browser mismatch but did not resolve the reported failure. Test counts alone cannot establish successful authentication on this physical modem.

The strongest external reference for this exact hardware is Cable Modem Monitor's S33v2 capture and issue #117, rather than S33v3 code. Its current catalog explicitly selects MD5 for v2; v3 is a separate profile. The issue maintainer confirmed the v2 capture's MD5 protocol after an earlier SHA256 hypothesis. Sources: [S33v2 catalog](https://github.com/solentlabs/cable_modem_monitor/blob/1be083961acfc8f33fcacd9f621e9b9e2919cae7/packages/cable_modem_monitor_catalog/solentlabs/cable_modem_monitor_catalog/modems/arris/s33v2/modem.yaml), [capture confirmation](https://github.com/solentlabs/cable_modem_monitor/issues/117#issuecomment-3977539812).

## Authentication that should match the browser

The following wire shape is the best supported S33v2 baseline, derived from the current S33v2 catalog and shared HNAP implementation:

1. POST JSON to `/HNAP1/` with action `Login`, `Action: request`, username, empty `LoginPassword` and `Captcha`, and **literal** `PrivateLogin: LoginPassword`.
2. Sign the challenge request with `withoutloginkey`. `SOAPAction` is the quoted string `"http://purenetworks.com/HNAP1/Login"`; those quotes also participate in the HMAC input.
3. Read nonempty `Challenge`, `PublicKey`, and `Cookie` fields.
4. Calculate uppercase `PrivateKey = HMAC-MD5(key=PublicKey + password, message=Challenge)`. Calculate uppercase `LoginPassword = HMAC-MD5(key=PrivateKey, message=Challenge)`.
5. Send `uid` and `PrivateKey` cookies and the same request fields with `Action: login` and the derived `LoginPassword`. Sign this request with the derived private key.
6. `HNAP_AUTH` is uppercase HMAC of `timestamp + quoted SOAPAction`, followed by a space and the same timestamp. Timestamp is epoch milliseconds modulo 2,000,000,000,000.
7. Recognize `OK` and `OK_CHANGED` as success; distinguish `FAILED`, `LOCKUP`, `REBOOT`, `RELOAD`, and unexpected/missing results. Never consider a parsed JSON body alone proof of success.

Sources: [HNAP handshake and result classification](https://github.com/solentlabs/cable_modem_monitor/blob/1be083961acfc8f33fcacd9f621e9b9e2919cae7/packages/cable_modem_monitor_core/solentlabs/cable_modem_monitor_core/auth/hnap.py), [signing primitives](https://github.com/solentlabs/cable_modem_monitor/blob/1be083961acfc8f33fcacd9f621e9b9e2919cae7/packages/cable_modem_monitor_core/solentlabs/cable_modem_monitor_core/protocol/hnap.py).

### Passwords and encoding

All inspected modern Python/C# HNAP clients concatenate the unescaped password with `PublicKey` and hash UTF-8 bytes; there is no shell escaping, URL encoding, or base64 step in this HNAP derivation. `$@!` requires no special treatment at a hidden local prompt. Preserve spaces and avoid Unicode normalization. The browser-generated HMAC is the authoritative oracle for less common Unicode, rather than assuming every JavaScript hash library handles strings alike. Sources: [MD5 UTF-8 derivation](https://github.com/sarabveer/cable-modem-stats/blob/7d520f88c9dfc7eb922f11444c6e7dc7e2d2ce83/src/arris_stats_s33.py), [DOCSight derivation](https://github.com/itsDNNS/docsight/blob/c5a93f44b5b2388ba261b7b31c6cb453bf123fd7/app/drivers/surfboard.py).

The previously fetched, public firmware files are local evidence, not links to publicly hosted firmware: `/tmp/arris-s33-login.js` reads the input's `.value` without trimming; `/tmp/arris-s33-login.html` gives `loginWAP` **maxlength=15**. That is a UI constraint, not evidence of a 15-character server limit. A password entered into the browser may therefore differ from a longer value sent by Python. Do not silently truncate, reject special characters, or change the user's password. First establish whether the same credential succeeds in this browser UI and whether its length exceeds that UI limit, without collecting the password itself.

The parent investigation executed the actual fetched `/tmp/arris-s33-hmac-md5.js` against synthetic punctuation, space, Unicode and long-key vectors and reported agreement with Python; synthetic results are in `/tmp/arris-browser-test-vectors.json`. This supports hash parity for those inputs only, not live credential correctness.

### Sessions, concurrency, lockout

Cookie persistence and connection persistence are different. Keep the derived key and `uid` together for the same authenticated session, and avoid fresh logins at every sample. Session invalidation after an error must clear both state and cookies. A timeout after sending login leaves an unknown outcome; replaying that login can add load even if the first request was processed.

The S33v2 crash thread is evidence that excessive logins are a real concern. Session reuse was repaired, but a later run had 22 successful reuses and still saw a reboot; the root cause was not proven by that observation. After additional cookie/session fixes the reporter observed two days of stable operation and accepted final diagnostics. This is useful field evidence, not a guarantee for another firmware or polling rate. Sources: [reuse did not alone eliminate reboot](https://github.com/solentlabs/cable_modem_monitor/issues/117#issuecomment-3992399276), [stable field report](https://github.com/solentlabs/cable_modem_monitor/issues/117#issuecomment-4185413407), [final diagnostics accepted](https://github.com/solentlabs/cable_modem_monitor/issues/117#issuecomment-4218425717).

DOCSight's driver docstring asserts one concurrent login tracked by source IP, while the S33v2 thread's maintainer explicitly said S33 was not a single-active-session device. These claims conflict and are not direct evidence for this user's firmware. Isolate testing to one collector and close other management sessions to reduce variables; do not describe a source-IP restriction as the known cause of `FAILED`. Sources: [DOCSight session assertion](https://github.com/itsDNNS/docsight/blob/c5a93f44b5b2388ba261b7b31c6cb453bf123fd7/app/drivers/surfboard.py), [S33 session statement](https://github.com/solentlabs/cable_modem_monitor/issues/117#issuecomment-3970155696).

## Repository comparisons

| Project | Applicability and strongest lesson | Behavior to avoid copying without validation |
|---|---|---|
| Cable Modem Monitor | Captured S33v2 MD5 profile, HAR fixtures, distinct login outcomes, cached session context, Home Assistant integration | Broad recovery policies and a large multi-modem architecture are unnecessary for a focused collector |
| cable-modem-stats | S33 MD5 client, batched downstream/upstream request, credential reuse, InfluxDB/Grafana | Its `PrivateLogin` carries plaintext password; browser-exact references use the literal string instead |
| arrismonitor | Small MD5 client with Requests session and both cookies; InfluxDB 2 output | Seconds timestamp and unquoted SOAPAction differ from browser; main ignores login return and defaults to 30-second polling |
| S33v3-monitor | SHA256 v3 client; Docker, event deduplication, InfluxDB and ready Grafana dashboards | Reauthenticates every poll; phase-2 request omits the derived key argument so its header uses the default pre-auth key |
| NetworkOptimizer | S33/S34 browser headers, login-page seeding, per-device session cache, malformed-header fallback | Tries SHA256 then MD5 after rejection; source-available BSL licensing limits copying into an MIT fork |
| arris-modem-status upstream | Python library, typed models, CLI, error capture and firmware compatibility work | SHA256-only upstream derivation is not a v2 profile; extensive fallback/retry layers need a single conservative path |
| DOCSight | Mature SURFboard driver plus signal history, outage correlation, case reports and redacted exports | Algorithm trial login, transport retry and reauthentication recovery add live attempts; not evidence of safe v2 rates |
| mluis7/cable_modem_stats | Older TG862-style HTML/octet monitor using shell, XPath and RRDTool | No S33 HNAP login; downstream traffic counters must not be assumed available on S33 |
| twstokes/arris-scrape | Older unauthenticated HTML scraping plus Grafana/InfluxDB layout and offline parser debugging | Authentication is explicitly left to implement; not an S33v2 login reference |

### Exact inspected sources and useful differences

- **Cable Modem Monitor:** [authentication](https://github.com/solentlabs/cable_modem_monitor/blob/1be083961acfc8f33fcacd9f621e9b9e2919cae7/packages/cable_modem_monitor_core/solentlabs/cable_modem_monitor_core/auth/hnap.py); [signatures](https://github.com/solentlabs/cable_modem_monitor/blob/1be083961acfc8f33fcacd9f621e9b9e2919cae7/packages/cable_modem_monitor_core/solentlabs/cable_modem_monitor_core/protocol/hnap.py); [v2 parser](https://github.com/solentlabs/cable_modem_monitor/blob/1be083961acfc8f33fcacd9f621e9b9e2919cae7/packages/cable_modem_monitor_catalog/solentlabs/cable_modem_monitor_catalog/modems/arris/s33v2/parser.yaml); [polling policy](https://github.com/solentlabs/cable_modem_monitor/blob/1be083961acfc8f33fcacd9f621e9b9e2919cae7/packages/cable_modem_monitor_core/docs/RUNTIME_POLLING_SPEC.md). The parser separates QAM/OFDM and QAM/OFDMA, preserves per-channel errors and uses API uptime; useful fixture-driven compatibility design.
- **cable-modem-stats:** [S33 source](https://github.com/sarabveer/cable-modem-stats/blob/7d520f88c9dfc7eb922f11444c6e7dc7e2d2ce83/src/arris_stats_s33.py); [loop and exports](https://github.com/sarabveer/cable-modem-stats/blob/7d520f88c9dfc7eb922f11444c6e7dc7e2d2ce83/src/__main__.py); [dashboard](https://github.com/sarabveer/cable-modem-stats/blob/7d520f88c9dfc7eb922f11444c6e7dc7e2d2ce83/grafana/new_grafana.json). Stores credentials outside the loop; default authentication and data errors stop the process. One data request batches both channel directions. This is a better load-reduction pattern than separate calls.
- **arrismonitor:** [client](https://github.com/nickdepinet/arrismonitor/blob/c8f2d8cb5e2978f1da347fb9d9793a2e21cffb9a/src/arris_client.py); [loop](https://github.com/nickdepinet/arrismonitor/blob/c8f2d8cb5e2978f1da347fb9d9793a2e21cffb9a/src/main.py); [InfluxDB output](https://github.com/nickdepinet/arrismonitor/blob/c8f2d8cb5e2978f1da347fb9d9793a2e21cffb9a/src/influx_handler.py). Login once and reuse cookies is useful; missing timeouts and unchecked login results make it unsuitable as a correctness oracle for our failure.
- **S33v3-monitor:** [collector](https://github.com/nickmccollum/S33v3-monitor/blob/ddd8429d4a18ad2f88bf2997610224746d430cb9/modem_stack/collector/collector.py); [deployment and features](https://github.com/nickmccollum/S33v3-monitor/blob/ddd8429d4a18ad2f88bf2997610224746d430cb9/README.md). Its login helper defaults to `withoutloginkey`; phase 2 does not override that argument even after computing the private key. This is a source discrepancy, not a live test. SHA256 applies to its v3 target, not proof that this v2 should switch.
- **NetworkOptimizer:** [provider](https://github.com/Ozark-Connect/NetworkOptimizer/blob/8cca00ee114f16626c203f954144a680cf9067ee/src/NetworkOptimizer.Web/Services/CableModemProviders/ArrisSurfboardHnapProvider.cs); [BSL 1.1 license](https://github.com/Ozark-Connect/NetworkOptimizer/blob/8cca00ee114f16626c203f954144a680cf9067ee/LICENSE). It sends `Referer: /Login.html` and `X-Requested-With: XMLHttpRequest` for login, seeds cookies with GET Login.html, probes device status, validates cached sessions, and handles malformed data-response headers. Seed/probe relevance to our firmware remains unverified. Its license names a 2028-01-01 Apache change date; treat it as a wire reference rather than copied MIT code.
- **arris-modem-status upstream:** [auth](https://github.com/csmarshall/arris-modem-status/blob/b0b682490994e5c94513d8fcc1b322668e51916a/arris_modem_status/client/auth.py); [HTTP handling](https://github.com/csmarshall/arris-modem-status/blob/b0b682490994e5c94513d8fcc1b322668e51916a/arris_modem_status/client/http.py); [formatters](https://github.com/csmarshall/arris-modem-status/blob/b0b682490994e5c94513d8fcc1b322668e51916a/arris_modem_status/cli/formatters.py). Both token and credential derivation hardcode SHA256 at the inspected upstream revision. Compare upstream behavior separately from our already modified fork.
- **DOCSight:** [SURFboard driver](https://github.com/itsDNNS/docsight/blob/c5a93f44b5b2388ba261b7b31c6cb453bf123fd7/app/drivers/surfboard.py); [channel normalization](https://github.com/itsDNNS/docsight/blob/c5a93f44b5b2388ba261b7b31c6cb453bf123fd7/app/drivers/formats/surfboard.py); [product features](https://github.com/itsDNNS/docsight/blob/c5a93f44b5b2388ba261b7b31c6cb453bf123fd7/README.md). Keep its durable data and correlation ideas. Its detection is operational trial of phase 2, not passive JavaScript discovery despite a summary claiming challenge-based detection. Do not copy trial-login behavior into conservative mode.
- **Older tools:** [TG862 applicability](https://github.com/mluis7/cable_modem_stats/blob/3ff407cd642102e62bd045d7eba7c174c75260cf/README.md); [HTML-only setup](https://github.com/twstokes/arris-scrape/blob/5b94f8acce4d258b8982d0261d975a839d5853de/README.md); [HTML parser](https://github.com/twstokes/arris-scrape/blob/5b94f8acce4d258b8982d0261d975a839d5853de/scraper/targets/arris_modem.py). Dashboard concepts are transferable; their authentication assumptions are not.

## Work completed during this investigation

The fork now contains an **offline** `arris_modem_status.cli.compare_login` command. It prompts for the password locally and compares a captured browser login with the Python derivation, header signature and cookie checks. It sends no network requests and emits only comparison results, not credentials, hashes or cookie values. Browser-independent synthetic fixtures live in `tests/browser_hnap_vectors.json`; dedicated comparison tests cover this path. This implementation gives the next diagnosis step a reproducible artifact. It does not itself establish browser success. Separately, the controlled standard-HTTP hardware test above authenticated successfully.

The intended next evidence is one locally captured **successful** browser session, compared offline using the same password input route as the monitor. Keep the original capture local; raw HAR may contain session credentials even when ordinary HTTP Cookie headers are removed.

## Reuse and license scope

Inspecting protocol behavior does not mean code should be copied wholesale. The inspected [arris-modem-status MIT license](https://github.com/csmarshall/arris-modem-status/blob/b0b682490994e5c94513d8fcc1b322668e51916a/LICENSE), [Cable Modem Monitor MIT license](https://github.com/solentlabs/cable_modem_monitor/blob/1be083961acfc8f33fcacd9f621e9b9e2919cae7/LICENSE), [arrismonitor MIT license](https://github.com/nickdepinet/arrismonitor/blob/c8f2d8cb5e2978f1da347fb9d9793a2e21cffb9a/LICENSE), [DOCSight MIT license](https://github.com/itsDNNS/docsight/blob/c5a93f44b5b2388ba261b7b31c6cb453bf123fd7/LICENSE), and [arris-scrape MIT license](https://github.com/twstokes/arris-scrape/blob/5b94f8acce4d258b8982d0261d975a839d5853de/LICENSE) provide reusable references with their copyright notices preserved. [mluis7's license](https://github.com/mluis7/cable_modem_stats/blob/3ff407cd642102e62bd045d7eba7c174c75260cf/LICENSE) is GPLv3; this report uses its monitoring concepts rather than incorporating its code. NetworkOptimizer is BSL1.1 as described above. No root license file was found in the inspected [cable-modem-stats tree](https://github.com/sarabveer/cable-modem-stats/tree/7d520f88c9dfc7eb922f11444c6e7dc7e2d2ce83) or [S33v3-monitor tree](https://github.com/nickmccollum/S33v3-monitor/tree/ddd8429d4a18ad2f88bf2997610224746d430cb9); this is a reuse limitation, not a judgment on the protocol observations.

The older HTML/octet tools were assessed because they were in the search results, and excluded as S33 authentication references. SNMP, automatic modem reboots, password resets, firmware replacement and speed tests are outside this login diagnosis: none provides evidence for the specific HNAP `FAILED` response.

## Ranked improvement plan

### P0: Establish why this login fails

1. Keep live login attempts paused while diagnosing. Establish browser success, the exact selected firmware/algorithm, username and password-input route without exposing the credential. If browser login also fails, the next task is credential or firmware lockout diagnosis, not more Python guesses.
2. Maintain and extend the newly added offline browser-parity fixtures from this firmware: challenge fields, fixed timestamp, synthetic password, derived key, login hash, quoted action, JSON keys, and both cookies. Test the prepared outgoing Requests request, not only helper outputs. Reuse the captured JavaScript vectors to cover punctuation, spaces, Unicode and long HMAC keys.
3. Add a redacted, no-login discovery command that reports publicly exposed firmware, script algorithm, transport and password field constraints. It must never invent a server password limit from HTML `maxlength`.
4. If browser succeeds and offline parity passes but script still fails, capture a single browser request locally and compare field presence, literal values, header spelling/quotes, referer, cookie scope/duplicates, redirects and transport. Never publish raw HAR, derived private key, HNAP_AUTH or challenge material. Make one evidence-backed change at a time; no MD5/SHA256 brute-force fallback.

Acceptance: a browser-parity test passes and one authorized live sample authenticates, with no retry or redundant login. Until then label S33v2 live support unverified.

### P1: Make monitoring gentle and observable

Keep one client/session per modem, sequential requests, one batched status read where firmware supports it, bounded samples and a conservative interval. Stop on `FAILED`, lockout/reboot tokens, unknown login responses, missing required data or ambiguous login transport failure. Distinguish stale session from rejected credential without immediate login loops. Expose request count, login count, elapsed sample time and stop reason in redacted diagnostics. A lock against overlapping collectors on the same host is useful only if overlap is actually possible; do not imply it stops collectors on other machines.

Acceptance: offline repeated-sample tests show one login, stable keys/cookies and no retries; a deliberately bounded live run verifies these properties. Longer-term stability requires soak observation across this firmware's session expiry and modem reboot, not faster polling.

### P2: Preserve useful data accurately

Normalize frequency/power/SNR with explicit units; preserve lock state, modulation, channel identity and raw unknown values. Keep QAM and OFDM counters separate. Compute error **deltas/rates** only after checking elapsed time, uptime reset and channel identity change; retain missing values as null rather than zero. Track modem uptime separately from collector time, so reboots and lost samples are visible. Deduplicate logs using stable observed fields and never make missing firmware log support a fatal channel-reading error.

Acceptance: realistic fixtures cover channel changes, counter resets, missing fields, OFDM/OFDMA and differing firmware representations.

### P3: Connect existing dashboards

Keep JSONL as the durable interchange format and add a versioned sample schema with firmware/profile, UTC timestamp, duration and completeness. Then add one thin exporter selected by actual user needs: InfluxDB line protocol for existing Grafana layouts, or a text metrics endpoint if Prometheus is already deployed. Keep database failures separate from modem authentication. Provide an example dashboard for power/SNR, uncorrectable deltas, uptime/reboots and collector failure rate, with freshness gaps rather than drawing zero signals during outages.

Use Home Assistant or DOCSight integration as optional consumers rather than duplicating a broad dashboard application inside this collector. Add alerts only after reliable samples exist; configurable sustained thresholds are more useful than alarming on one unverified sample.

### P4: Maintain compatibility with evidence

Document model/hardware/firmware and ISP combinations actually tested, alongside the transport, hash algorithm and sanitized fixture provenance. Retain MD5/SHA256 profiles but select them from firmware evidence or explicit configuration. Keep readable release notes and CI for protocol vectors, parsers, CLI JSON and type checking. Avoid generic protocol plugins, transport workarounds or secret-rich debug dumps until a reproducible device issue demands them.

## Reliability pass: 2026-10-14

The user reported the browser page opens. A bounded probe from the execution runtime
still timed out loading the public login page, before any challenge or credential POST.
A direct TCP check to port 443 and anonymous curl probes to HTTP/HTTPS also timed out.
This does not establish that the user's browser is failing or that the modem is down;
the browser/runtime access difference remains unresolved. No further credential
submissions were made during this pass.

Reproducible offline cases led to these implemented safeguards:

- HNAP login requests never retry, regardless of the configured status retry limit.
- HNAP redirects cannot replay a POST at a different URL.
- Rejected or uncertain authentication is latched until a new client is created;
  private keys and session cookies are cleared.
- An authenticated HTTP 401/403 response stops the batch instead of being silently
  treated as an optional missing field. This is a conservative denial policy, not
  proof that every 403 means session expiry.
- Serial queries stop on connection loss while retaining the valid cached session.
  Queued concurrent work is cancelled; already-running requests may complete.
- Authentication diagnostics omit cookie-bearing response bodies and unknown raw
  login-result strings; debug arguments omit passwords.
- The monitor distinguishes connectivity from authentication failures.
- `channels_only=True` / `--channels-only` selects the existing combined downstream
  and upstream request, reducing status-query count from four to one. Metadata may
  be unavailable in this mode. It is explicit selection, not an automatic fallback.
- The ordinary CLI now exposes firmware hash and transport selection, matching the
  monitor's explicit configuration.
- Automated tests refuse unmocked TCP connections and DNS lookups. An inherited test
  patched an obsolete helper; its mock was corrected to exercise the actual path.

The channel-only protocol shape and failure policies have offline regression coverage.
A complete live sample and long-running modem stability remain unverified.

## Commit inventory

| Repository | Inspected commit |
|---|---|
| [Ozark-Connect/NetworkOptimizer](https://github.com/Ozark-Connect/NetworkOptimizer/tree/8cca00ee114f16626c203f954144a680cf9067ee) | `8cca00ee114f16626c203f954144a680cf9067ee` |
| [csmarshall/arris-modem-status](https://github.com/csmarshall/arris-modem-status/tree/b0b682490994e5c94513d8fcc1b322668e51916a) | `b0b682490994e5c94513d8fcc1b322668e51916a` |
| [itsDNNS/docsight](https://github.com/itsDNNS/docsight/tree/c5a93f44b5b2388ba261b7b31c6cb453bf123fd7) | `c5a93f44b5b2388ba261b7b31c6cb453bf123fd7` |
| [mluis7/cable_modem_stats](https://github.com/mluis7/cable_modem_stats/tree/3ff407cd642102e62bd045d7eba7c174c75260cf) | `3ff407cd642102e62bd045d7eba7c174c75260cf` |
| [nickdepinet/arrismonitor](https://github.com/nickdepinet/arrismonitor/tree/c8f2d8cb5e2978f1da347fb9d9793a2e21cffb9a) | `c8f2d8cb5e2978f1da347fb9d9793a2e21cffb9a` |
| [nickmccollum/S33v3-monitor](https://github.com/nickmccollum/S33v3-monitor/tree/ddd8429d4a18ad2f88bf2997610224746d430cb9) | `ddd8429d4a18ad2f88bf2997610224746d430cb9` |
| [sarabveer/cable-modem-stats](https://github.com/sarabveer/cable-modem-stats/tree/7d520f88c9dfc7eb922f11444c6e7dc7e2d2ce83) | `7d520f88c9dfc7eb922f11444c6e7dc7e2d2ce83` |
| [solentlabs/cable_modem_monitor](https://github.com/solentlabs/cable_modem_monitor/tree/1be083961acfc8f33fcacd9f621e9b9e2919cae7) | `1be083961acfc8f33fcacd9f621e9b9e2919cae7` |
| [twstokes/arris-scrape](https://github.com/twstokes/arris-scrape/tree/5b94f8acce4d258b8982d0261d975a839d5853de) | `5b94f8acce4d258b8982d0261d975a839d5853de` |
