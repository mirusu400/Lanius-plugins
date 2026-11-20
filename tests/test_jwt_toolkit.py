from __future__ import annotations

import pytest

from app.plugin_registry import ContributionRegistry
from conftest import load_plugin

plugin = load_plugin("lanius.jwt-toolkit")


def _hs256(payload: dict, secret: str = "secret", header: dict | None = None) -> str:
    header = header or {"alg": "HS256", "typ": "JWT"}
    h, p = plugin._json_segment(header), plugin._json_segment(payload)
    return f"{h}.{p}.{plugin.sign_hmac('HS256', f'{h}.{p}'.encode(), secret.encode())}"


def test_parse_and_find_tokens_ignores_non_jwt() -> None:
    token = _hs256({"sub": "a"})
    found = plugin.find_tokens(f"Authorization: Bearer {token}; x=eyJhbGci.bad.sig")
    assert [t.raw for t in found] == [token]
    assert found[0].algorithm == "HS256"


def test_crack_and_static_findings() -> None:
    weak = plugin.parse_token(_hs256({"sub": "a", "password": "x"}))
    checks = {f["check"] for f in plugin.analyze_token(weak)}
    assert {"weak-secret", "no-expiry", "sensitive-claims"} <= checks
    strong = plugin.parse_token(_hs256({"exp": 2, "iat": 1}, secret="x" * 40))
    assert {f["check"] for f in plugin.analyze_token(strong)} == set()
    none = plugin.parse_token(plugin.build_token({"alg": "none"}, {"exp": 1, "iat": 0}))
    assert "alg-none" in {f["check"] for f in plugin.analyze_token(none)}


def test_passive_reports_url_token_and_cookie_flags() -> None:
    token = _hs256({"exp": 2, "iat": 1}, secret="y" * 40)
    issues = plugin.analyze_snapshot({
        "status_code": 200, "scheme": "https", "host": "a.test",
        "query": f"t={token}",
        "request_headers": [], "request_body": "",
        "response_headers": [("Set-Cookie", f"s={token}; Path=/")],
        "response_body": "",
    })
    titles = {i.title for i in issues}
    assert "JWT sent in the URL query string" in titles
    assert "JWT cookie missing HttpOnly and Secure" in titles


def _message(token: str, *, editable: bool = True) -> dict:
    body = '{"a":1}'
    raw = (
        f"GET /x HTTP/1.1\r\nHost: a.test\r\nAuthorization: Bearer {token}\r\n"
        f"Content-Length: {len(body)}\r\n\r\n{body}"
    )
    return {"raw": raw, "editable": editable}


def test_view_renders_and_apply_resigns_and_roundtrips() -> None:
    token = _hs256({"sub": "user"})
    message = _message(token)
    text = plugin.render_view(message, {})
    assert "[PAYLOAD]" in text and '"sub": "user"' in text
    assert "mode: hs256" in text and "secret: secret" in text  # cracked, pre-filled

    # Untouched view + keep signature is a no-op.
    assert plugin.apply_edit(text.replace("mode: hs256", "mode: keep"), message) == message["raw"]

    edited = text.replace('"user"', '"admin"')
    out = plugin.apply_edit(edited, message)
    new = plugin.find_tokens(out)[0]
    assert new.payload["sub"] == "admin"
    assert new.signature_segment == plugin.sign_hmac(
        "HS256", new.signing_input, b"secret"
    )

    none = plugin.apply_edit(text.replace("mode: hs256", "mode: none"), message)
    forged = plugin.find_tokens(none)[0]
    assert forged.header["alg"] == "none" and forged.signature_segment == ""


def test_apply_rejects_bad_input_and_view_skips_plain_messages() -> None:
    token = _hs256({"sub": "u"})
    message = _message(token)
    text = plugin.render_view(message, {})
    with pytest.raises(ValueError, match="invalid JSON"):
        plugin.apply_edit(text.replace('"sub"', "sub"), message)
    with pytest.raises(ValueError, match="unknown signing mode"):
        plugin.apply_edit(text.replace("mode: hs256", "mode: rot13"), message)
    assert plugin.render_view({"raw": "GET / HTTP/1.1\r\n\r\n"}, {}) is None


def test_apply_fixes_content_length_for_body_tokens() -> None:
    token = _hs256({"sub": "u"})
    body = f'{{"t":"{token}"}}'
    raw = f"POST /x HTTP/1.1\r\nContent-Length: {len(body)}\r\n\r\n{body}"
    message = {"raw": raw, "editable": True}
    text = plugin.render_view(message, {}).replace("mode: hs256", "mode: none")
    out = plugin.apply_edit(text, message)
    head, _, new_body = out.partition("\r\n\r\n")
    assert f"Content-Length: {len(new_body.encode())}" in head


def test_registers_with_sdk() -> None:
    registry = ContributionRegistry(None)
    plugin.activate(registry.context("lanius.jwt-toolkit"))
    counts = registry.counts("lanius.jwt-toolkit")
    assert counts["passive_scanners"] == 1 and counts["active_scanners"] == 0
    assert counts["codecs"] == 1 and counts["settings"] == 3
    registry.dispose_owner("lanius.jwt-toolkit")
