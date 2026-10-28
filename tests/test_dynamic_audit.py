from __future__ import annotations

import pytest

from app.db.store import FlowRecord, FlowStore
from app.plugin_registry import ContributionRegistry
from lanius_sdk import InsertionPoint

from conftest import load_plugin


def _response(
    body: str = "<html>baseline</html>",
    *,
    status: int = 200,
    headers: list[tuple[str, str]] | None = None,
):
    return {
        "status_code": status,
        "response_headers": headers or [("Content-Type", "text/html; charset=utf-8")],
        "response_body": body,
        "error": None,
    }


class Settings:
    def __init__(self, **changes):
        self.values = {
            "allow_unsafe_methods": False,
            "check_sqli": True,
            "check_xss": True,
            "check_ssti": True,
            "check_redirect": True,
        }
        self.values.update(changes)

    def get(self, key):
        return self.values[key]


class Context:
    def __init__(self, **settings):
        self.settings = Settings(**settings)


@pytest.mark.asyncio
async def test_dynamic_checks_confirm_sqli_html_injection_and_ssti() -> None:
    plugin = load_plugin("lanius.dynamic-audit")

    class Scan:
        insertion_point = InsertionPoint("query:0", "query", "q", "hello")
        request = {
            "url": "https://example.test/search?q=hello",
            "method": "GET",
            **_response(),
        }

        def __init__(self):
            self.sent = []

        async def send(self, payload):
            self.sent.append(payload)
            if payload == "hello'":
                return _response("You have an error in your SQL syntax near quote")
            if "<lanius-scan" in payload:
                return _response(f"<html>{payload}</html>")
            if "{{7*7}}" in payload:
                return _response(f"<html>{payload.replace('{{7*7}}', '49')}</html>")
            if "{{8*8}}" in payload:
                return _response(f"<html>{payload.replace('{{8*8}}', '64')}</html>")
            return _response()

    scan = Scan()
    issues = await plugin.dynamic_audit(scan, Context())

    assert {issue.title for issue in issues} == {
        "Possible error-based SQL injection",
        "Potential reflected XSS (HTML injection)",
        "Possible server-side template injection",
    }
    assert all(issue.parameter == "q" for issue in issues)
    assert "hello''" in scan.sent
    assert len(scan.sent) == 6


@pytest.mark.asyncio
async def test_redirect_check_uses_location_without_following_it() -> None:
    plugin = load_plugin("lanius.dynamic-audit")

    class Scan:
        insertion_point = InsertionPoint("query:0", "query", "next", "/home")
        request = {
            "url": "https://example.test/login?next=/home",
            "method": "GET",
            **_response(body="baseline"),
        }

        async def send(self, payload):
            if payload == "https://lanius.invalid/dynamic-audit":
                return _response(
                    "",
                    status=302,
                    headers=[("Location", payload), ("Content-Type", "text/plain")],
                )
            return _response(body="baseline")

    issues = await plugin.dynamic_audit(
        Scan(),
        Context(check_sqli=False, check_xss=False, check_ssti=False),
    )
    assert [(issue.title, issue.confidence) for issue in issues] == [
        ("Possible open redirect", "firm")
    ]


@pytest.mark.asyncio
async def test_dynamic_audit_skips_unstable_and_unsafe_requests() -> None:
    plugin = load_plugin("lanius.dynamic-audit")

    class Scan:
        insertion_point = InsertionPoint("form:0", "form", "name", "Alice")
        request = {
            "url": "https://example.test/profile",
            "method": "POST",
            **_response(),
        }

        def __init__(self):
            self.calls = 0

        async def send(self, _payload):
            self.calls += 1
            return _response("changed")

    unsafe = Scan()
    assert await plugin.dynamic_audit(unsafe, Context()) == []
    assert unsafe.calls == 0

    unstable = Scan()
    assert await plugin.dynamic_audit(
        unstable, Context(allow_unsafe_methods=True)
    ) == []
    assert unstable.calls == 1


@pytest.mark.asyncio
async def test_target_action_selects_distinct_in_scope_domain_flows(tmp_path) -> None:
    plugin = load_plugin("lanius.dynamic-audit")
    store = FlowStore(tmp_path / "project.sqlite")

    def add(
        flow_id: str,
        *,
        host: str = "example.test",
        method: str = "GET",
        path: str = "/search",
        query: str = "q=one",
        source: str = "proxy",
    ) -> None:
        store.upsert(FlowRecord(
            id=flow_id,
            scheme="https",
            host=host,
            port=443,
            method=method,
            path=path,
            query=query,
            source=source,
            status_code=200,
            response_headers=[("Content-Type", "text/html")],
            response_body=b"ok",
        ))

    add("search-one")
    add("search-duplicate", query="q=two")
    add("view", path="/view", query="page=1")
    add("replay", path="/replay", source="replay")
    add("post", method="POST", path="/submit")
    add("outside", host="outside.test")

    registry = ContributionRegistry(
        store,
        scope_predicate=lambda _scheme, host, _port, _path: host == "example.test",
    )
    plugin.activate(registry.context("lanius.dynamic-audit"))
    started = []

    class Job:
        def __init__(self, flow_id):
            self.flow_id = flow_id

        def as_dict(self):
            return {
                "id": f"job-{self.flow_id}",
                "flow_id": self.flow_id,
                "check_ids": ["lanius.dynamic-audit.dynamic-audit"],
                "status": "pending",
            }

    async def start(flow_id, *, check_ids, concurrency, requests_per_second):
        started.append((flow_id, check_ids, concurrency, requests_per_second))
        return Job(flow_id)

    registry.active_scan_start = start
    result = await registry.invoke_action(
        "lanius.dynamic-audit.scan-domain",
        {
            "location": "target",
            "target": {"scheme": "https", "host": "example.test", "port": 443},
        },
    )

    selected_ids = {item[0] for item in started}
    assert selected_ids in (
        {"search-one", "view"},
        {"search-duplicate", "view"},
    )
    assert all(item[1] == ["lanius.dynamic-audit.dynamic-audit"] for item in started)
    assert all(item[2] == 1 for item in started)
    assert sum(item[3] for item in started) == pytest.approx(4.0)
    assert result["flow_count"] == 2
    assert len(result["jobs"]) == 2
    store.close()


@pytest.mark.asyncio
async def test_target_action_refuses_domain_without_eligible_scope_history(tmp_path) -> None:
    plugin = load_plugin("lanius.dynamic-audit")
    store = FlowStore(tmp_path / "project.sqlite")
    registry = ContributionRegistry(store, scope_predicate=lambda *_args: False)
    plugin.activate(registry.context("lanius.dynamic-audit"))

    with pytest.raises(ValueError, match="No eligible in-scope"):
        await registry.invoke_action(
            "lanius.dynamic-audit.scan-domain",
            {
                "location": "target",
                "target": {"scheme": "https", "host": "example.test", "port": 443},
            },
        )
    store.close()
