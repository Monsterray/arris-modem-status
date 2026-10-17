# Flint 2 collection and router-side benchmarks

These tools live in this checkout and the source archive. They read the GL.iNet
web panel and LuCI through the APIs used by those interfaces; they are not screen
scrapers. The optional speed runner executes fixed diagnostic/transfer commands on
the router. It does not change router settings, install software, reboot, or reset.

## Setup on this Mac

```bash
cd "/Users/monsterray/Documents/Hardware Development/arris-modem-status"
source .venv/bin/activate
python -m pip install -e '.[flint2]'
```

Use **Python 3.10 or later** for the Flint 2 tools; this Mac's `.venv` uses 3.14.
Their HTTP dependency minimums select patched versions that no longer support
Python 3.9. The modem library retains its separate Python 3.9 compatibility.

The optional libraries are already installed in this checkout's `.venv`. They are
separate from the modem library's normal runtime dependencies.

The credential directory is:

```text
/Users/monsterray/Documents/Hardware Development/arris-modem-status/.secrets/flint2/
    gui.enc
    luci.enc
    ssh.enc       # optional SSH alternative
```

The helper creates directories with mode 700 and encrypted files with mode 600.
Both `.secrets/` and `router-data/` are Git-ignored. Do not create router-password
files in the repository root or reuse the existing modem password file for the
router. The modem credentials have not been read or changed by this setup.

Run these commands yourself in Terminal. Passwords are entered through a hidden
prompt and never appear in command arguments, shell history, script output, or a
plaintext intermediate file:

```bash
python -m scripts.flint2_credentials store gui
python -m scripts.flint2_credentials store luci
```

Default username is `root`; `--username` can select another account. Default
origins are `https://192.168.8.1` for GL.iNet and
`https://192.168.8.1:8443` for LuCI. Network sockets bind to `en0` on this Mac;
`--interface` selects another interface if required.

The helper observes the public certificate, then asks you to independently verify
and paste its SHA-256 fingerprint **before** prompting for the password. In
Firefox, inspect the site's certificate in the connection/certificate viewer and
compare its SHA-256 fingerprint. Merely probing and copying a fingerprint does
not independently establish that it belongs to your router. A previously verified
fingerprint may instead be supplied with `--fingerprint`.

Observed public fingerprints on 2026-10-16, without authentication:

| Interface | Certificate SHA-256 |
| --- | --- |
| GL.iNet, port 443 | `d0fc669141694fa32e381d9c5c65d735130c15fa172e6e232a08e403e3e71e8a` |
| LuCI, port 8443 | `ebf79c8d12eb7c1614d0fe93cc567ba684ce7ae5f2615c51f4a7abd9051fc529` |

These are observations, not permanent factory identities. Certificate changes
require a fresh independent check; the tools never silently accept a replacement.
Use `store ... --replace` only for an intentional credential/pin update. Replacement
retires the old profile's encryption key, so old encrypted backups need their old
Keychain entries if they are to remain decryptable.

## Encryption, hashing, and password characters

The files contain authenticated **Fernet encryption**, using a fresh random key
for each profile. The key is stored separately in **macOS Keychain** under service
`com.monsterray.flint2.collector`; it is not placed beside the encrypted file. The
code explicitly selects the native Keychain backend and has no plaintext-backend
fallback. Keychain may ask you to authorize the expected local Python interpreter.
The collector decrypts in memory; there is no CLI command that prints the password.
An unlocked or compromised user session can still access credentials it is
permitted to retrieve; these files do not make an untrusted computer safe.

A **hash** is one-way. Hashing a stored password would prevent the collector from
recovering it for login. Do not hash or shell-escape a password before entering it.
The GUI's required challenge-response hash is generated internally from the exact
input; that protocol operation is separate from storage encryption. A certificate
fingerprint is also a hash, but identifies the server's public certificate.

If you want a checksum of an *encrypted* file for comparison:

```bash
shasum -a 256 .secrets/flint2/gui.enc
```

A checksum is not encryption or proof of origin. Fernet already verifies the
ciphertext's authentication tag when decrypting it. Losing both the encryption key
and its Keychain backup means the file cannot be recovered; re-enter the password.

Literal ASCII `$@!`, quotes, backslashes, and leading/trailing spaces are supported.
Do not add shell quotes when typing at the hidden prompt. The encrypted store and
LuCI/SSH paths preserve Unicode. The installed GL.iNet frontend has a verified
non-ASCII Unix-crypt mismatch, so this GUI adapter rejects non-ASCII before a login
POST rather than guessing or risking repeated failures. See the independent
browser-derived vectors and evidence in [API research](flint2-api-research.md).

## Pull status from both interfaces

```bash
python -m scripts.flint2_collect gui
python -m scripts.flint2_collect luci
```

Each command performs one login flow and a finite set of status reads. The GL.iNet
collector reads `system.get_info` and `system.get_status`. LuCI supplies system
board/uptime/load, network interfaces, and network-device details where permitted;
port speed/duplex availability depends on its installed modules and ACLs.

Both use HTTPS certificate pins, no proxy environment, no HTTP redirects or login
retries, and no automatic reauthentication. Only optional missing methods produce
an unavailable marker; an authentication/permission/connection failure stops the
batch. The GUI additionally checks the installed public login bundle hashes and
stops before login if firmware assets change. Updating firmware may require
reviewing and updating that adapter.

Snapshots go to `router-data/gui-*.json` and `router-data/luci-*.json`. They are
redacted JSON with owner-only permissions; **diagnostic reports are not encrypted**
like the credential files. Treat them as private because they can contain network
addresses, device names, hardware identifiers, and counters. Console output gives
the saved path, rather than dumping the response.

## Capture installed settings without a shell

```bash
python -m scripts.flint2_audit
```

This uses one LuCI login to list configuration filenames and read their UCI
values, together with the usual status snapshot. It never invokes a shell,
changes settings, or starts a speed test. Credentials are redacted before writing
an owner-only `router-data/settings-*.json` report. Authentication policy flags
such as `PasswordAuth=on` remain visible, while password values are removed.
This is a settings inventory for review, not a restorable backup containing keys.

The report's `complete` field refers to completing its configuration inventory;
the `unavailable` section records optional reads that could not be collected.
An optional denied firmware-file read does not discard a successful settings
capture. Command execution is a separate permission and may be denied even when
status and UCI reads work. The current GUI adapter recognizes two reviewed asset
pairs selected from the public page; unknown paths or modified hashes still stop
before login. RPC rejections show only the phase and numeric code, never raw bodies.

## Router-origin speed tests

The default transport reuses one authenticated LuCI session and its existing
`file.exec` permission. If that method is unavailable or denied, the run stops;
it does not change ACLs or switch transports. Router firmware controls rpcd's
execution timeout; each transfer additionally has a 60-second curl limit.
Interrupting the local client does not prove remote cancellation: an already
started transfer may continue until its own limit. Do not immediately rerun it.

The baseline uses existing router `curl`, BusyBox `dd`, `ubus`, `ip`, and `ping`.
It downloads generated data from Cloudflare and uploads generated zeros; it never
uploads a local file or router configuration. Default routing can traverse a VPN.
Uploads stream generated bytes with an exact Content-Length, avoiding an
upload-sized memory buffer on the router.
`--route wan` requests binding only the test transfers to the detected WAN device;
it does not edit routes or relax a VPN kill switch, and existing rules may block
it. The result labels the chosen route and includes pre/post router state.

```bash
python -m scripts.flint2_speedtest --route wan
```

The default three runs request **768 MiB download plus 48 MiB upload** if all
transfers complete. They may temporarily occupy the connection and count against
your Comcast allowance. Use `--runs 1` for a smaller initial check. A short transfer
may not reach steady 2 Gb/s throughput; `--download-mib 1024 --runs 1` requests a
larger single download when useful. All counts, time, and output are bounded.

The JSON report records per-transfer Mbps, bytes/time, remote server address,
connection/TLS timing, idle ping, WAN state, routing snapshot, and system/CPU
counters before and after. Idle ping follows the router's default route and is
labeled separately from WAN-bound transfers; it may traverse a VPN.

This is a single-connection transfer benchmark, **not** an official Comcast speed
test, a multi-connection capacity certification,
or a bufferbloat grade. Router CPU, VPN policy, SQM/QoS, and the remote server can
limit it. Compare against a wired client when assessing actual forwarding.

### Optional SSH transport

SSH port 22 refused the anonymous connection during setup. No service was enabled.
If you already use SSH on a different port, or intentionally configure LAN-only
SSH later, it can be used as an alternative. Keep WAN SSH administration disabled.

```bash
python -m scripts.flint2_credentials store ssh --ssh-port 22
python -m scripts.flint2_speedtest --via ssh --route wan
```

Verify the observed SSH SHA-256 host-key fingerprint against an independently
trusted record or router console before storing the profile. The runner verifies
that host key before its single password-authentication attempt. No SSH password
is put into a process argument, environment variable, or `sshpass` command.

## Verification and remaining live checks

The public GL.iNet and LuCI login pages were reached without credentials; matching
HTTPS pins succeeded and deliberately wrong pins failed before HTTP data was sent.
The installed public JavaScript was inspected to verify the GL authentication
algorithm and derive independent synthetic-password vectors. No real router
password was supplied, no authenticated collection or speed test has run, and no
router/modem settings have been changed by this setup.

A separate **Mac-origin**, one-MiB generated upload verified the streaming POST
format against Cloudflare: HTTP 200 with exactly 1,048,576 bytes uploaded. This
was an endpoint compatibility check, not a router speed measurement. See
[the focused speed-test research](flint2-speedtest-research.md) for protocol and
measurement limits.

Offline checks use synthetic credentials, real authenticated encryption, mocked
Keychain, and mocked network/SSH transports. They cover storage permissions,
tampering, profile binding, literal characters, browser-derived hashes, restricted
status reads, redirects, authentication failures, redaction, host-key mismatch, and
bounded transfer construction. Run them without contacting hardware:

```bash
python -m pytest tests/test_flint2_tools.py --no-cov
```

The exact installed Mac router runtime dependency stack passed `pip-audit` with
no known findings and no vulnerability exceptions. The older Python 3.9 test
environment has upstream dependency advisories without 3.9-compatible fixes;
it is retained for modem compatibility, not recommended for these router tools.
