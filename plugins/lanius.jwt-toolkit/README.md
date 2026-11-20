# JWT Toolkit

An independent Lanius SDK implementation inspired by Burp's JWT Editor and
JSON Web Tokens extensions. Requires Lanius SDK 1.7 (message-view tabs).

## What it does

- **JWT tab** beside Pretty/Raw/Hex. It decodes every token found in the
  request or response (headers, cookies, URL query, body) and shows timestamps
  and offline findings. In the Replay and Fuzzer editors the tab is editable:
  change the `[HEADER]` / `[PAYLOAD]` JSON and choose a `[SIGNING]` mode:
  `keep`, `strip`, `none`, `hs256`, `hs384`, `hs512` (with
  `secret: text`, `base64:...` or `hex:...`). Unedited segments are kept
  byte-for-byte, and `Content-Length` is corrected when the body changes. If
  the HMAC secret is in the built-in dictionary it is pre-filled.
- **Passive check** (no traffic): `alg: none`, guessable HS* secret
  (dictionary plus the *Extra HMAC secrets* setting), missing/long-lived
  `exp`, `jku`/`x5u`/`jwk`/`x5c`/`kid` headers, sensitive-looking claims,
  tokens in URLs, JWT cookies without `HttpOnly`/`Secure`.
- **Codec** `JWT (decode)` for the Decoder.

Not covered: active attacks (the plugin sends no traffic), RS256→HS256 key
confusion, and `jku`/`jwk` injection.

The plugin uses only the Python standard library and sends no requests.
