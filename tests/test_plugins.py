from __future__ import annotations

from urllib.parse import parse_qs, urlsplit

from app.plugin_registry import ContributionRegistry
from mitmproxy.test import tflow

from conftest import load_plugin


def test_security_headers_reports_only_applicable_findings() -> None:
    plugin = load_plugin("lanius.security-headers")
    issues = plugin.analyze(
        {
            "status_code": 200,
            "scheme": "https",
            "response_headers": [("Content-Type", "text/html; charset=utf-8")],
        }
    )
    assert {issue.parameter for issue in issues} == {
        "content-security-policy",
        "strict-transport-security",
        "x-content-type-options",
    }

    protected = plugin.analyze(
        {
            "status_code": 200,
            "scheme": "https",
            "response_headers": [
                ("Content-Type", "text/html"),
                ("Content-Security-Policy", "default-src 'self'"),
                ("Strict-Transport-Security", "max-age=31536000"),
                ("X-Content-Type-Options", "nosniff"),
            ],
        }
    )
    assert protected == []


def test_security_headers_registers_with_scanner_sdk() -> None:
    plugin = load_plugin("lanius.security-headers")
    registry = ContributionRegistry(None)
    plugin.activate(registry.context("lanius.security-headers"))
    checks = registry.scan_handlers("passive_scanners")
    assert [check.id for check in checks] == [
        "lanius.security-headers.missing-security-headers"
    ]
    assert registry.counts("lanius.security-headers") == {
        "actions": 0,
        "codecs": 0,
        "payload_generators": 0,
        "payload_processors": 0,
        "settings": 3,
        "passive_scanners": 1,
        "active_scanners": 0,
    }
    registry.dispose_owner("lanius.security-headers")


def test_request_randomizer_reuses_each_value_within_one_request() -> None:
    plugin = load_plugin("lanius.request-randomizer")
    registry = ContributionRegistry(None)
    addon = plugin.activate(registry.context("lanius.request-randomizer"))
    flow = tflow.tflow()
    flow.request.path = "/items/#RANDOMNUM#?again=#RANDOMNUM#&id=#UUID#"
    flow.request.headers["X-Trace"] = "#RANDOM#:#RANDOM#"
    flow.request.content = b"number=#RANDOMNUM#"

    addon.request(flow)

    assert b"#RANDOM" not in flow.request.content
    parsed = urlsplit(flow.request.path)
    path_number = parsed.path.rsplit("/", 1)[1]
    query_number = parse_qs(parsed.query)["again"][0]
    body_number = flow.request.content.decode().split("=", 1)[1]
    assert path_number == query_number == body_number
    assert len(path_number) == 8 and path_number.isdigit()
    first, second = flow.request.headers["X-Trace"].split(":")
    assert first == second and len(first) == 16
    assert addon.stats({}) == {
        "requests_changed": 1,
        "placeholders_replaced": 6,
    }
    registry.dispose_owner("lanius.request-randomizer")
