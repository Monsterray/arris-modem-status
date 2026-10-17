# Flint 2 GUI compatibility profile (2026-10-17)

Static comparison only. No router request, login attempt, or credential access was performed. The current anonymous public assets were supplied as pinned local files; hashes were recomputed before inspection.

## Current pinned assets

| File | SHA-256 |
|---|---|
| `/tmp/flint2-public-ui-20261017/app.ab987315.js` | `a27c83299c4119cd91f9e00643712de574fe30010cea89fa053bcd7957795a24` |
| `/tmp/flint2-public-ui-20261017/gl-sdk4-ui-login.common.js` | `daf28cab39b96b3baf6067ea5bd5615c215741e36514aa0e993583768d86e72a` |

The preceding local snapshot has `app.js` SHA-256 `7f932af072e305dbeca23bd33a941fa4cd1e556c46421bf9aebc5fb479162e3a` and `login.js` SHA-256 `bb2f6ef79c8fc95f6fc18bdf4d43883aea318d8b39a29d549583acbb079a235d`; these were the hashes pinned in `scripts/flint2_collect.py` at the start of this review. Both current bundles differ, so the collector's asset pin will fail closed until deliberately reviewed and updated. Current app bundle name is `app.ab987315.js`; update its URL path along with its hash if the entry HTML confirms that path.

## Login derivation observed in current UI

In `gl-sdk4-ui-login.common.js`, the login handler destructures `alg`, `nonce`, and `salt` from the `challenge` result, calls `$up.crypt(password, "$" + alg + "$" + salt + "$")`, then calls `$getHash(username + ":" + cipher + ":" + nonce)`. It sends `login({username, hash})`. It does not read `hash-method`, `count`, or `rounds` from the challenge.

The current app's `d714` module defines `$getHash` as Node-style `createHash("sha256").update(value, "utf8").digest("hex")`; thus the outer digest is lowercase hexadecimal SHA-256. The embedded crypt module supports algorithms 1, 5, and 6; its setting parser clamps explicit `rounds=` values to 1,000–999,999,999 and defaults algorithm 1 to 1,000 rounds and algorithms 5/6 to 5,000 rounds. The login handler always constructs a setting without `rounds=`, so its effective defaults are MD5-crypt 1,000, SHA-256-crypt 5,000, or SHA-512-crypt 5,000 rounds. This agrees with the adapter's explicit 5,000-round Passlib configuration for algorithms 5/6 and default MD5-crypt behavior.

Compatibility note: the UI ignores additional challenge fields; the collector deliberately rejects fields outside `alg`, `salt`, `nonce`, and optional `hash-method`. This is a stricter fail-closed policy, not evidence that the firmware challenge response has exactly those fields. Also, the UI does not consult `hash-method`; the collector only accepts its own absent/default or explicit `sha256` value.

## RPC transport and session

The current app transport creates JSON-RPC 2.0 requests with incrementing numeric IDs and POSTs them to `/rpc`. For method `call`, it replaces the first element of the parameter array with the `Admin-Token` cookie value (or empty string). The wire shape for an authenticated module call is therefore `params: [sid, module, method, args]`. No request signature is added. Login helpers call `challenge` and `login` as ordinary methods with object params `{username}` and `{username, hash}` respectively. The login view's `alive` check sends `{sid: Admin-Token-or-empty}`. The login result is handled by the UI and stored as the `Admin-Token` cookie; subsequent calls use that cookie as the real session ID.

This matches the adapter's `/rpc` JSON-RPC transport, challenge/login object params, four-element authenticated `call`, and use of the returned `sid` as both `Admin-Token` header and cookie. The UI itself replaces the `call` sid from its cookie; sending the real sid directly, as the adapter does, is wire-compatible. The adapter's response validation and narrow read allowlist are additional client-side safeguards, not UI protocol requirements.

## Existing adapter impact

- Keep the observed derivation: Unix-crypt from `$<alg>$<salt>$`, then `SHA256(UTF8(username + ":" + crypt + ":" + nonce))` as lowercase hex. The current GUI confirms this formula.
- Keep algorithm support limited to 1/5/6 and the current explicit SHA-crypt default of 5,000 rounds. The login UI supplies no rounds override.
- Preserve the current strict challenge validation and ASCII-only password gate as conservative compatibility limits. The UI's crypt implementation has known non-ASCII differences from standard libraries documented in `flint2-api-research.md`.
- Refresh the GUI asset pins before a future authenticated GUI collection: the old app/login hashes in `scripts/flint2_collect.py` do not match these supplied current assets. Confirm the served app path from the current anonymous index before changing that constant; no production code was edited here.
- RPC/session protocol shape needs no change based on these bundles. The current static evidence does not verify actual challenge response values, login success/result shape on this firmware, session lifetime, or authenticated RPC permissions.

## Evidence locations

- Current login flow and hash call: `gl-sdk4-ui-login.common.js`, near the `handleLogin` implementation (`challenge({username})`, crypt setting, `$getHash`, and `login({username, hash})`).
- Current outer digest: `app.ab987315.js`, module `d714` (`createHash("sha256")...digest("hex")`).
- Current crypt defaults and rounds parser: `app.ab987315.js`, module exporting `crypt`; defaults are `1e3` for algorithm 1 and `5e3` otherwise, with explicit rounds clamped to 1,000–999,999,999.
- Current JSON-RPC/session handling: `app.ab987315.js`, `$rpcRequest` implementation; `/rpc` POST, `jsonrpc: "2.0"`, incrementing ID, and replacement of `call` parameter zero from `Admin-Token`.
- Adapter comparison: `scripts/flint2_collect.py`, `login_hash`, `authenticate_gui`, and `read`.
- Prior context and known non-ASCII limitation: `docs/flint2-api-research.md`.

## Adapter update after review

The parent verified that the current public index serves `/js/app.ab987315.js`. The adapter now selects one of the two explicitly reviewed app/login pairs from that index and validates both hashes before authentication. Unknown paths, ambiguous matches, and modified bundles still stop before login. Offline workflow tests cover both versions and rejection of unknown paths or changed content. Authenticated live collection remains a separate check; no credential or session value is included in this note.
