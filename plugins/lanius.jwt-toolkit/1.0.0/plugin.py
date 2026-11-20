"""JWT detection, editing, and vulnerability checks.

* A **JWT** message-view tab decodes every token found in a request or response
  and, in Replay/Fuzzer editors, re-encodes edited header/payload JSON with the
  chosen signing mode.
* A passive check reports weak tokens (alg none, guessable HMAC secrets, missing
  or long expiry, key-source headers, tokens in URLs, cookie flags) offline.

The plugin never sends requests and uses only the Python standard library.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import re
import time
from collections.abc import Mapping
from typing import Any
from urllib.parse import parse_qsl, urlsplit

from lanius_sdk import PluginContext, ScanIssue, SettingDefinition


JWT_PATTERN = re.compile(
    r"eyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{2,}\.[A-Za-z0-9_-]*"
)
MAX_TOKENS = 20
MAX_TOKEN_LENGTH = 16_384
BODY_LIMIT = 32_768
HMAC_DIGESTS = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}
SENSITIVE_CLAIM = re.compile(
    r"(?:pass(?:word|wd)?|pwd|secret|api[_-]?key|private|ssn|credit|card[_-]?number|cvv)",
    re.IGNORECASE,
)
COMMON_SECRETS = (
    "", "secret", "password", "123456", "12345678", "1234567890", "changeme",
    "jwt", "jwtsecret", "jwt-secret", "jwt_secret", "jwtkey", "jwt_key",
    "your-256-bit-secret", "your-secret-key", "your_secret_key", "your-secret",
    "your_jwt_secret", "supersecret", "super-secret", "super_secret",
    "super-secret-key", "supersecretkey", "secretkey", "secret-key", "secret_key",
    "SECRET_KEY", "mysecret", "my-secret", "my_secret", "mysecretkey", "key",
    "mykey", "private", "admin", "administrator", "root", "test", "testing",
    "default", "demo", "dev", "development", "prod", "production", "staging",
    "token", "auth", "hmac", "HS256", "HS384", "HS512", "s3cr3t", "secret123",
    "password123", "passw0rd", "letmein", "qwerty", "topsecret", "top-secret",
    "shhhhh", "keyboard cat", "null", "undefined", "none", "example", "changeit",
    "a-string-secret-at-least-256-bits-long", "django-insecure", "express-secret",
    "your-super-secret-jwt-token-with-at-least-32-characters-long",
    "this is a secret", "thisisasecret", "ThisIsASecret", "S3cr3tK3y",
)


# --------------------------------------------------------------------------
# Encoding helpers


def b64url_decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def b64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _json_segment(value: Any) -> str:
    return b64url_encode(
        json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    )


class Token:
    """One decoded JWT; keeps the original segments so unedited ones survive."""

    __slots__ = ("raw", "header_segment", "payload_segment", "signature_segment",
                 "header", "payload", "location")

    def __init__(self, raw: str, header: dict, payload: dict, location: str = "") -> None:
        self.raw = raw
        self.header_segment, self.payload_segment, self.signature_segment = raw.split(".")
        self.header = header
        self.payload = payload
        self.location = location

    @property
    def algorithm(self) -> str:
        return str(self.header.get("alg", ""))

    @property
    def signing_input(self) -> bytes:
        return f"{self.header_segment}.{self.payload_segment}".encode("ascii")


def parse_token(raw: str, location: str = "") -> Token | None:
    if len(raw) > MAX_TOKEN_LENGTH:
        return None
    parts = raw.split(".")
    if len(parts) != 3:
        return None
    try:
        header = json.loads(b64url_decode(parts[0]).decode("utf-8"))
        payload = json.loads(b64url_decode(parts[1]).decode("utf-8"))
    except (ValueError, binascii.Error):
        return None
    if not isinstance(header, dict) or not isinstance(payload, dict):
        return None
    return Token(raw, header, payload, location)


def find_tokens(text: str, location: str = "") -> list[Token]:
    found: list[Token] = []
    seen: set[str] = set()
    for match in JWT_PATTERN.finditer(text or ""):
        raw = match.group(0)
        if raw in seen:
            continue
        token = parse_token(raw, location)
        if token is not None:
            seen.add(raw)
            found.append(token)
            if len(found) >= MAX_TOKENS:
                break
    return found


def sign_hmac(algorithm: str, signing_input: bytes, secret: bytes) -> str:
    digest = HMAC_DIGESTS[algorithm.upper()]
    return b64url_encode(hmac.new(secret, signing_input, digest).digest())


def build_token(header: Any, payload: Any, signature: str = "") -> str:
    return f"{_json_segment(header)}.{_json_segment(payload)}.{signature}"


def crack_secret(token: Token, extra: tuple[str, ...] = ()) -> str | None:
    """Offline dictionary check of an HMAC token; returns the secret or None."""

    algorithm = token.algorithm.upper()
    if algorithm not in HMAC_DIGESTS or not token.signature_segment:
        return None
    try:
        expected = b64url_decode(token.signature_segment)
    except (ValueError, binascii.Error):
        return None
    digest = HMAC_DIGESTS[algorithm]
    for candidate in (*extra, *COMMON_SECRETS):
        actual = hmac.new(candidate.encode("utf-8"), token.signing_input, digest).digest()
        if hmac.compare_digest(actual, expected):
            return candidate
    return None


# --------------------------------------------------------------------------
# Static analysis


def _lifetime(payload: Mapping[str, Any]) -> float | None:
    try:
        exp, iat = float(payload["exp"]), float(payload["iat"])
    except (KeyError, TypeError, ValueError):
        return None
    return exp - iat


def analyze_token(
    token: Token,
    *,
    max_lifetime_hours: float = 24.0,
    extra_secrets: tuple[str, ...] = (),
    crack: bool = True,
) -> list[dict[str, Any]]:
    """Return ``{check, title, severity, confidence, detail, remediation}`` dicts."""

    findings: list[dict[str, Any]] = []

    def add(check: str, title: str, severity: str, confidence: str,
            detail: str, remediation: str) -> None:
        findings.append({
            "check": check, "title": title, "severity": severity,
            "confidence": confidence, "detail": detail, "remediation": remediation,
        })

    algorithm = token.algorithm
    if algorithm.lower() in {"none", ""}:
        add(
            "alg-none", "JWT uses the 'none' algorithm", "high", "certain",
            "The token header declares alg " + repr(algorithm) + ", so it carries no "
            "signature. Anyone can forge claims if the server accepts it.",
            "Reject unsigned tokens and pin the accepted algorithms server-side.",
        )
    elif crack and (secret := crack_secret(token, extra_secrets)) is not None:
        add(
            "weak-secret", "JWT signed with a guessable HMAC secret", "critical", "certain",
            f"The {algorithm} signature verifies with the dictionary secret "
            f"{secret!r}. Anyone can forge arbitrary tokens.",
            "Rotate to a random secret of at least 256 bits (or an asymmetric key) "
            "and invalidate all tokens signed with the weak one.",
        )

    if "exp" not in token.payload:
        add(
            "no-expiry", "JWT has no expiry claim", "low", "firm",
            "The payload has no 'exp' claim, so a stolen token stays valid until "
            "the signing key is rotated.",
            "Issue short-lived tokens with an 'exp' claim and validate it.",
        )
    else:
        lifetime = _lifetime(token.payload)
        if lifetime is not None and lifetime > max_lifetime_hours * 3600:
            add(
                "long-lived", "JWT has a long lifetime", "low", "firm",
                f"exp - iat is {lifetime / 3600:.1f} hours "
                f"(threshold {max_lifetime_hours:g} hours).",
                "Use short-lived access tokens and a revocable refresh mechanism.",
            )

    for name in ("jku", "x5u", "jwk", "x5c"):
        if name in token.header:
            add(
                f"key-source-{name}", f"JWT header carries a key source ({name})",
                "low", "tentative",
                f"The header contains {name!r}. If the server trusts it to locate the "
                "verification key, an attacker can supply their own key or URL.",
                "Ignore key-source headers from tokens; resolve keys from a fixed "
                "server-side set.",
            )
    if "kid" in token.header:
        add(
            "kid-present", "JWT header carries a 'kid' value", "info", "tentative",
            f"kid is {str(token.header['kid'])[:80]!r}. If it is used in a file path "
            "or database lookup it may be injectable (path traversal, SQL injection).",
            "Treat kid as an opaque identifier and look it up in a fixed key map.",
        )

    sensitive = sorted(
        str(name) for name in token.payload if SENSITIVE_CLAIM.search(str(name))
    )
    if sensitive:
        add(
            "sensitive-claims", "JWT payload contains sensitive-looking claims",
            "medium", "tentative",
            "JWT payloads are only base64url encoded, not encrypted. Claims: "
            + ", ".join(sensitive[:10]) + ".",
            "Keep secrets out of tokens, or use JWE if confidentiality is required.",
        )
    return findings


# --------------------------------------------------------------------------
# Request / response scanning


def _headers(snapshot: Mapping[str, Any], side: str) -> list[tuple[str, str]]:
    result = []
    for item in snapshot.get(f"{side}_headers") or ():
        if isinstance(item, (list, tuple)) and len(item) == 2:
            result.append((str(item[0]), str(item[1])))
    return result


def snapshot_tokens(snapshot: Mapping[str, Any]) -> list[Token]:
    """Every JWT in a captured exchange, tagged with where it was found."""

    tokens: list[Token] = []
    for side in ("request", "response"):
        for name, value in _headers(snapshot, side):
            for token in find_tokens(value, f"{side} header {name}"):
                tokens.append(token)
        body = str(snapshot.get(f"{side}_body") or "")[:BODY_LIMIT]
        for token in find_tokens(body, f"{side} body"):
            tokens.append(token)
    query = str(snapshot.get("query") or "")
    for name, value in parse_qsl(query[:BODY_LIMIT], keep_blank_values=True):
        for token in find_tokens(value, f"URL query {name}"):
            tokens.append(token)
    return tokens[:MAX_TOKENS]


def _cookie_findings(snapshot: Mapping[str, Any]) -> list[ScanIssue]:
    issues: list[ScanIssue] = []
    https = str(snapshot.get("scheme") or "").lower() == "https"
    for name, value in _headers(snapshot, "response"):
        if name.lower() != "set-cookie" or not find_tokens(value):
            continue
        cookie = value.split("=", 1)[0].strip()
        attributes = {part.strip().lower().split("=", 1)[0] for part in value.split(";")[1:]}
        missing = [flag for flag, ok in (
            ("HttpOnly", "httponly" in attributes),
            ("Secure", "secure" in attributes or not https),
        ) if not ok]
        if missing:
            issues.append(ScanIssue(
                title="JWT cookie missing " + " and ".join(missing),
                severity="low", confidence="firm",
                detail=f"Cookie {cookie!r} carries a JWT but lacks: {', '.join(missing)}.",
                remediation="Set HttpOnly and Secure (and a suitable SameSite) on "
                            "cookies that hold tokens.",
                parameter=cookie,
                evidence={"cookie": cookie, "missing": missing},
                fingerprint=f"jwt:cookie-flags:{snapshot.get('host')}:{cookie}",
            ))
    return issues


def analyze_snapshot(
    snapshot: Mapping[str, Any],
    *,
    max_lifetime_hours: float = 24.0,
    extra_secrets: tuple[str, ...] = (),
    crack: bool = True,
) -> list[ScanIssue]:
    if snapshot.get("status_code") is None or snapshot.get("error"):
        return []
    issues: list[ScanIssue] = []
    host = str(snapshot.get("host") or "")
    for token in snapshot_tokens(snapshot):
        for item in analyze_token(
            token, max_lifetime_hours=max_lifetime_hours,
            extra_secrets=extra_secrets, crack=crack,
        ):
            issues.append(ScanIssue(
                title=item["title"], severity=item["severity"],
                confidence=item["confidence"],
                detail=f"{item['detail']} (found in {token.location})",
                remediation=item["remediation"],
                parameter=token.location,
                evidence={"alg": token.algorithm, "location": token.location,
                          "claims": sorted(map(str, token.payload))[:20]},
                fingerprint=f"jwt:{item['check']}:{host}:{token.location}",
            ))
        if token.location.startswith("URL query"):
            issues.append(ScanIssue(
                title="JWT sent in the URL query string",
                severity="medium", confidence="firm",
                detail="Tokens in URLs leak through server logs, browser history "
                       f"and Referer headers (found in {token.location}).",
                remediation="Send tokens in the Authorization header or an "
                            "HttpOnly cookie instead.",
                parameter=token.location,
                evidence={"location": token.location},
                fingerprint=f"jwt:in-url:{host}:{token.location}",
            ))
    issues.extend(_cookie_findings(snapshot))
    return issues


# --------------------------------------------------------------------------
# Message view: render / apply

SIGNING_MODES = ("keep", "strip", "none", "hs256", "hs384", "hs512")
_SECTION = re.compile(r"^\[(HEADER|PAYLOAD|SIGNING)\]\s*$")
_TOKEN_MARK = re.compile(r"^===\s*TOKEN\s+(\d+)\b.*$")


def render_view(message: Mapping[str, Any], options: Mapping[str, Any]) -> str | None:
    raw = str(message.get("raw") or "")
    tokens = find_tokens(raw)
    if not tokens:
        return None
    editable = bool(message.get("editable"))
    lines = [
        "# JWT Toolkit",
        "# Edit the JSON under [HEADER] / [PAYLOAD], pick a mode under [SIGNING].",
        "#   mode: keep (original signature) | strip (empty) | none (alg none) "
        "| hs256 | hs384 | hs512",
        "#   secret: plain text, or base64:<...> / hex:<...>",
        "# Lines starting with '#' are ignored. Unedited segments are kept byte-for-byte.",
    ]
    if not editable:
        lines.append("# (read-only here; open the request in Replay or Fuzzer to edit)")
    for index, token in enumerate(tokens, 1):
        lines += ["", f"=== TOKEN {index} of {len(tokens)} ===",
                  f"# alg: {token.algorithm or '-'}   signature: "
                  f"{len(token.signature_segment)} chars"]
        now = time.time()
        for claim in ("iat", "nbf", "exp"):
            try:
                value = float(token.payload[claim])
            except (KeyError, TypeError, ValueError):
                continue
            stamp = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(value))
            note = ""
            if claim == "exp":
                note = "  (EXPIRED)" if value < now else "  (valid)"
            lines.append(f"# {claim}: {stamp}{note}")
        for item in analyze_token(
            token, max_lifetime_hours=float(options.get("max_lifetime_hours") or 24),
            extra_secrets=options.get("extra_secrets") or (),
        ):
            lines.append(f"# [{item['severity']}] {item['title']}")
        lines += [
            "[HEADER]", json.dumps(token.header, indent=2, ensure_ascii=False),
            "[PAYLOAD]", json.dumps(token.payload, indent=2, ensure_ascii=False),
            "[SIGNING]", "mode: keep", "secret: ",
        ]
        if secret := crack_secret(token, options.get("extra_secrets") or ()):
            lines[-1] = f"secret: {secret}"
            lines[-2] = f"mode: {token.algorithm.lower()}"
    return "\n".join(lines) + "\n"


def _parse_edit(text: str) -> list[dict[str, Any]]:
    blocks: list[dict[str, Any]] = []
    section: str | None = None
    for line in text.replace("\r\n", "\n").split("\n"):
        mark = _TOKEN_MARK.match(line)
        if mark:
            blocks.append({"HEADER": [], "PAYLOAD": [], "SIGNING": []})
            section = None
            continue
        if not blocks or line.lstrip().startswith("#"):
            continue
        heading = _SECTION.match(line.strip())
        if heading:
            section = heading.group(1)
        elif section:
            blocks[-1][section].append(line)
    return blocks


def _secret_bytes(text: str) -> bytes:
    text = text.strip("\r\n")
    if text.startswith("base64:"):
        return base64.b64decode(text[7:].strip() + "===")
    if text.startswith("hex:"):
        return bytes.fromhex(text[4:].strip())
    return text.encode("utf-8")


def apply_edit(text: str, message: Mapping[str, Any]) -> str:
    raw = str(message["raw"])
    tokens = find_tokens(raw)
    blocks = _parse_edit(text)
    if len(blocks) != len(tokens):
        raise ValueError(
            f"Expected {len(tokens)} '=== TOKEN n ===' sections, found {len(blocks)}"
        )
    result = raw
    for index, (token, block) in enumerate(zip(tokens, blocks), 1):
        try:
            header = json.loads("\n".join(block["HEADER"]))
            payload = json.loads("\n".join(block["PAYLOAD"]))
        except ValueError as exc:
            raise ValueError(f"Token {index}: invalid JSON ({exc})") from exc
        if not isinstance(header, dict) or not isinstance(payload, dict):
            raise ValueError(f"Token {index}: header and payload must be JSON objects")
        settings: dict[str, str] = {}
        for line in block["SIGNING"]:
            name, separator, value = line.partition(":")
            if separator:
                key = name.strip().lower()
                if key == "secret":
                    settings[key] = value[1:] if value.startswith(" ") else value
                else:
                    settings[key] = value.strip()
        mode = settings.get("mode", "keep").lower()
        if mode not in SIGNING_MODES:
            raise ValueError(f"Token {index}: unknown signing mode {mode!r}")

        header_segment = token.header_segment if header == token.header else _json_segment(header)
        payload_segment = token.payload_segment if payload == token.payload else _json_segment(payload)
        if mode == "none":
            if str(header.get("alg", "")).lower() != "none":
                header = {**header, "alg": "none"}
                header_segment = _json_segment(header)
            signature = ""
        elif mode == "strip":
            signature = ""
        elif mode == "keep":
            signature = token.signature_segment
        else:
            if str(header.get("alg", "")).upper() != mode.upper():
                header = {**header, "alg": mode.upper()}
                header_segment = _json_segment(header)
            try:
                secret = _secret_bytes(settings.get("secret", ""))
            except ValueError as exc:
                raise ValueError(f"Token {index}: bad secret encoding") from exc
            signature = sign_hmac(
                mode, f"{header_segment}.{payload_segment}".encode("ascii"), secret
            )
        new_raw = f"{header_segment}.{payload_segment}.{signature}"
        result = result.replace(token.raw, new_raw)
    return _fix_content_length(raw, result)


def _fix_content_length(original: str, edited: str) -> str:
    if original == edited:
        return edited
    for mark in ("\r\n\r\n", "\n\n"):
        index = edited.find(mark)
        if index >= 0:
            head, body = edited[:index], edited[index + len(mark):]
            break
    else:
        return edited
    pattern = re.compile(r"^(content-length:\s*)\d+\s*$", re.IGNORECASE | re.MULTILINE)
    if not pattern.search(head):
        return edited
    head = pattern.sub(lambda m: f"{m.group(1)}{len(body.encode('utf-8'))}", head, count=1)
    return head + mark + body


# --------------------------------------------------------------------------
# Codec / MCP helpers


def decode_text(value: str) -> str:
    tokens = find_tokens(value)
    if not tokens:
        raise ValueError("No JWT found")
    return "\n\n".join(
        json.dumps({"header": t.header, "payload": t.payload,
                    "signature": t.signature_segment}, indent=2, ensure_ascii=False)
        for t in tokens
    )


def activate(context: PluginContext) -> None:
    context.settings.define(
        SettingDefinition(
            "max_lifetime_hours", "Maximum token lifetime (hours)",
            kind="number", default=24.0,
            description="Report tokens whose exp - iat is longer than this.",
        ),
        SettingDefinition(
            "extra_secrets", "Extra HMAC secrets to try",
            kind="string", default="",
            description="Comma-separated candidates added to the built-in dictionary.",
        ),
        SettingDefinition(
            "crack_secrets", "Check HMAC secrets offline",
            kind="boolean", default=True,
            description="Try a small built-in dictionary against captured HS* tokens.",
        ),
    )

    def options() -> dict[str, Any]:
        extras = tuple(
            item.strip() for item in str(context.settings.get("extra_secrets") or "").split(",")
            if item.strip()
        )
        return {
            "max_lifetime_hours": float(context.settings.get("max_lifetime_hours") or 24.0),
            "extra_secrets": extras,
        }

    def passive(snapshot: Mapping[str, Any]) -> list[ScanIssue]:
        return analyze_snapshot(
            snapshot, crack=bool(context.settings.get("crack_secrets")), **options(),
        )

    context.message_views.register(
        "jwt", "JWT",
        lambda message: render_view(message, options()),
        apply=apply_edit,
        description="Decode, edit and re-sign JSON Web Tokens found in the message.",
    )
    context.scanner.register_passive(
        "jwt-analysis", "JWT analysis", passive,
        description="Checks captured JWTs offline without sending traffic.",
    )
    context.codecs.register("jwt", "JWT (decode)", decode=decode_text)
    context.log.info("JWT Toolkit registered")
