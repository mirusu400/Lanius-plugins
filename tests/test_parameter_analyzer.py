from __future__ import annotations

import pytest
from mitmproxy.test import tutils

from app.addons.capture import flow_to_record
from app.addons.scanner import ScannerAddon
from app.db.store import FlowRecord, FlowStore
from app.events import EventBroker
from app.plugin_registry import ContributionRegistry
from lanius_sdk import InsertionPoint

from conftest import load_plugin


def _snapshot(**changes):
    value = {
        "flow_id": "flow-1", "host": "example.test", "path": "/profile",
        "query": "q=needle&token=abcdef123456", "request_headers": [
            ("Cookie", "session=secret123; theme=dark"),
            ("Content-Type", "application/x-www-form-urlencoded"),
        ],
        "request_body": "name=Alice&empty=",
        "response_body": "You searched for needle and Alice",
    }
    value.update(changes)
    return value


def test_history_analysis_groups_inputs_and_masks_secret_examples() -> None:
    plugin = load_plugin("lanius.parameter-analyzer")
    observations = plugin.analyze_flow(_snapshot(), set())
    by_key = {(item["kind"], item["name"]): item for item in observations}

    assert by_key[("query", "q")]["reflected"] is True
    assert by_key[("query", "token")]["example"] == "<redacted>"
    assert by_key[("cookie", "session")]["example"] == "<redacted>"
    assert by_key[("cookie", "theme")]["example"] == "dark"
    assert by_key[("form", "name")]["reflected"] is True
    assert by_key[("form", "empty")]["format"] == "empty"
    assert plugin.analyze_flow(_snapshot(), {"q"})[0]["name"] != "q"


def test_json_and_xml_values_are_bounded_and_parsed() -> None:
    plugin = load_plugin("lanius.parameter-analyzer")
    json_items = plugin.analyze_flow(_snapshot(
        request_headers=[("Content-Type", "application/json")],
        request_body='{"user":{"name":"Alice"},"roles":["admin"]}',
    ), set())
    assert {item["name"] for item in json_items if item["kind"] == "json"} == {
        "user.name", "roles[0]",
    }
    xml_items = plugin.analyze_flow(_snapshot(
        request_headers=[("Content-Type", "application/xml")],
        request_body='<root><name>Alice</name></root>',
    ), set())
    assert any(item["kind"] == "xml" and item["name"] == "name" for item in xml_items)
    blocked = plugin.analyze_flow(_snapshot(
        request_headers=[("Content-Type", "application/xml")],
        request_body='<!DOCTYPE x [<!ENTITY a "secret">]><root>&a;</root>',
    ), set())
    assert not any(item["kind"] == "xml" for item in blocked)


@pytest.mark.asyncio
async def test_history_action_reads_only_in_scope_project_flows(tmp_path) -> None:
    plugin = load_plugin("lanius.parameter-analyzer")
    store = FlowStore(tmp_path / "project.sqlite")
    for flow_id, host in (("inside", "example.test"), ("outside", "other.test")):
        store.upsert(FlowRecord(
            id=flow_id, scheme="https", host=host, port=443, path="/profile",
            query="q=needle", response_body=b"needle", status_code=200,
        ))
    store.upsert(FlowRecord(
        id="probe", scheme="https", host="example.test", port=443,
        path="/profile", query="debug=probe", source="replay", status_code=200,
    ))
    registry = ContributionRegistry(
        store,
        scope_predicate=lambda _scheme, host, _port, _path: host == "example.test",
    )
    plugin.activate(registry.context("lanius.parameter-analyzer"))

    result = await registry.invoke_action(
        "lanius.parameter-analyzer.analyze-page", {"location": "plugin"},
    )
    assert result["flows"] == 2
    assert result["analyzed_flows"] == 1
    assert len(result["observations"]) == 1
    assert result["observations"][0]["flow_id"] == "inside"
    active = registry.scan_handlers("active_scanners")
    assert len(active) == 1 and active[0].metadata["request_level"] is True
    store.close()


@pytest.mark.asyncio
async def test_miner_requires_repeatable_change_and_skips_generic_reflection() -> None:
    plugin = load_plugin("lanius.parameter-analyzer")

    class Settings:
        values = {"extra_names": "", "max_names": 1, "probe_cookies": False}

        def get(self, key):
            return self.values[key]

    class Context:
        settings = Settings()

    class Scan:
        insertion_point = InsertionPoint("request:0", "request", "request", "")
        request = _snapshot(query="", request_headers=[], request_body="")

        def __init__(self):
            self.calls = []

        async def send_with(self, kind=None, name="", value=""):
            self.calls.append((kind, name, value))
            if kind == "query" and name == "debug":
                return {"status_code": 201, "response_headers": [], "response_body": "changed"}
            if kind == "header" and name == "X-Debug":
                return {"status_code": 200, "response_headers": [], "response_body": f"base {value}"}
            return {"status_code": 200, "response_headers": [], "response_body": "base "}

    scan = Scan()
    issues = await plugin.mine(scan, Context())
    assert [(item.parameter, item.confidence) for item in issues] == [("debug", "firm")]
    assert len([call for call in scan.calls if call[1] == "debug"]) == 2
    assert len([call for call in scan.calls if call[1] == "X-Debug"]) == 1


@pytest.mark.asyncio
async def test_history_action_starts_bounded_scan_and_saves_issue(tmp_path) -> None:
    plugin = load_plugin("lanius.parameter-analyzer")
    store = FlowStore(tmp_path / "project.sqlite")
    store.upsert(FlowRecord(
        id="flow-1", scheme="https", host="example.test", port=443,
        path="/profile", status_code=200, response_body=b"base",
    ))
    registry = ContributionRegistry(store)
    plugin.activate(registry.context("lanius.parameter-analyzer"))
    registry.set_setting("lanius.parameter-analyzer", "max_names", 1)

    class Replay:
        auto_decompress = True

        def __init__(self):
            self.sent = []

        async def send(self, flow):
            self.sent.append(flow)
            status = 201 if "debug=" in flow.request.pretty_url else 200
            flow.response = tutils.tresp(status_code=status, content=b"base")
            return flow_to_record(flow)

    replay = Replay()
    scanner = ScannerAddon(registry, store, EventBroker(), replay)
    registry.active_scan_start = scanner.start_active
    job = await registry.invoke_action(
        "lanius.parameter-analyzer.mine",
        {"location": "history", "flow_id": "flow-1"},
    )
    await scanner._job_tasks[job["id"]]

    assert job["check_ids"] == ["lanius.parameter-analyzer.hidden-inputs"]
    assert len(replay.sent) == 5  # two controls, two confirmations, one header probe
    issues = store.list_issues()
    assert len(issues) == 1
    assert issues[0]["parameter"] == "debug"
    assert issues[0]["scan_mode"] == "active"
    store.close()
