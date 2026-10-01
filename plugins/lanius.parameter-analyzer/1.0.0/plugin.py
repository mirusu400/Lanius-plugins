"""Analyze observed parameters and explicitly probe for hidden inputs.

This is an independent Lanius SDK implementation. No sockets, external
services, or engine-internal modules are used by the plugin.
"""

from __future__ import annotations

import base64
import hashlib
import html
import json
import re
import secrets
from collections.abc import Mapping
from difflib import SequenceMatcher
from typing import Any
from urllib.parse import parse_qsl, unquote_plus
from xml.etree import ElementTree

from lanius_sdk import PluginContext, ScanIssue, SettingDefinition

DEFAULT_NAMES = (
    "debug", "trace", "admin", "preview", "test", "format", "callback",
    "jsonp", "lang", "locale", "sort", "order", "limit", "page_size",
    "include", "fields", "expand", "verbose", "source", "redirect",
    "next", "return", "cache", "nocache", "api_version",
)
HEADER_NAMES = (
    "X-Debug", "X-Trace", "X-Preview", "X-Original-URL",
    "X-Rewrite-URL", "X-HTTP-Method-Override", "X-Requested-With",
)
SECRET_NAME = re.compile(
    r"(?:pass(?:word)?|secret|token|sess(?:ion)?|auth|api[_-]?key|credential|jwt)",
    re.IGNORECASE,
)
HASH_LENGTHS = {32: "MD5-like hex", 40: "SHA-1-like hex", 56: "SHA-224-like hex",
                64: "SHA-256-like hex", 128: "SHA-512-like hex"}
MAX_INPUTS_PER_FLOW = 50


def _headers(snapshot: Mapping[str, Any], side: str) -> list[tuple[str, str]]:
    result = []
    for item in snapshot.get(f"{side}_headers") or ():
        if isinstance(item, (list, tuple)) and len(item) == 2:
            result.append((str(item[0]), str(item[1])))
    return result


def _header(headers: list[tuple[str, str]], name: str) -> str:
    return next((value for key, value in headers if key.lower() == name), "")


def _json_values(value: Any, prefix: str = "", depth: int = 0):
    if depth > 4:
        return
    if isinstance(value, dict):
        for key, nested in list(value.items())[:100]:
            path = f"{prefix}.{key}" if prefix else str(key)
            yield from _json_values(nested, path, depth + 1)
    elif isinstance(value, list):
        for index, nested in enumerate(value[:20]):
            yield from _json_values(nested, f"{prefix}[{index}]", depth + 1)
    elif prefix and value is not None:
        yield prefix, str(value).lower() if isinstance(value, bool) else str(value)


def _xml_values(body: str):
    if "<!DOCTYPE" in body.upper() or "<!ENTITY" in body.upper():
        return
    try:
        root = ElementTree.fromstring(body)
    except ElementTree.ParseError:
        return
    for element in root.iter():
        if element.text and element.text.strip() and len(element) == 0:
            yield element.tag.rsplit("}", 1)[-1], element.text.strip()
        for key, value in element.attrib.items():
            yield f"{element.tag.rsplit('}', 1)[-1]}@{key}", value


def _inputs(snapshot: Mapping[str, Any]):
    for name, value in parse_qsl(str(snapshot.get("query") or "")[:32768], keep_blank_values=True):
        yield "query", name, value
    headers = _headers(snapshot, "request")
    for key, value in headers:
        if key.lower() == "cookie":
            for item in value.split(";"):
                if "=" in item:
                    name, cookie_value = item.strip().split("=", 1)
                    yield "cookie", name, cookie_value
    content_type = _header(headers, "content-type").lower()
    body = str(snapshot.get("request_body") or "")[:65536]
    if "application/x-www-form-urlencoded" in content_type:
        for name, value in parse_qsl(body, keep_blank_values=True):
            yield "form", name, value
    elif "json" in content_type:
        try:
            value = json.loads(body)
        except ValueError:
            return
        for name, item in _json_values(value):
            yield "json", name, item
    elif "xml" in content_type:
        for name, value in _xml_values(body):
            yield "xml", name, value


def _format(value: str) -> tuple[str, bool]:
    if not value:
        return "empty", False
    if re.fullmatch(r"-?\d+(?:\.\d+)?", value):
        return "number", False
    if value.lower() in {"true", "false"}:
        return "boolean", False
    if re.fullmatch(r"[0-9a-fA-F-]{36}", value) and value.count("-") == 4:
        return "UUID-like", False
    if re.fullmatch(r"[0-9a-fA-F]+", value) and len(value) in HASH_LENGTHS:
        return HASH_LENGTHS[len(value)], False
    if re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", value):
        return "email", False
    if "%" in value and unquote_plus(value) != value:
        return "URL encoded", True
    if len(value) >= 8 and re.fullmatch(r"[A-Za-z0-9_+/=-]+", value):
        try:
            decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
            if decoded and all(31 < byte < 127 or byte in (9, 10, 13) for byte in decoded):
                return "Base64-like", True
        except ValueError:
            pass
    return "text", False


def _reflected(value: str, response: str) -> bool:
    if len(value) < 4 or not response:
        return False
    candidates = {value, unquote_plus(value), html.escape(value, quote=True)}
    return any(len(candidate) >= 4 and candidate in response for candidate in candidates)


def analyze_flow(snapshot: Mapping[str, Any], ignored: set[str]) -> list[dict[str, Any]]:
    """Return bounded, privacy-conscious observations for one captured flow."""
    response = str(snapshot.get("response_body") or "")[:65536]
    seen: set[tuple[str, str, str]] = set()
    result = []
    for kind, name, value in _inputs(snapshot):
        if not name or name.lower() in ignored or len(name) > 160:
            continue
        identity = (kind, name, value)
        if identity in seen:
            continue
        seen.add(identity)
        sensitive = bool(SECRET_NAME.search(name)) or len(value) > 96
        value_format, decodable = _format(value)
        path = str(snapshot.get("path") or "/")
        result.append({
            "host": str(snapshot.get("host") or "")[:255],
            "path_hash": hashlib.sha256(path.encode()).hexdigest()[:16],
            "flow_id": str(snapshot.get("flow_id") or "")[:64],
            "kind": kind,
            "name": name,
            "value_hash": hashlib.sha256(value.encode()).hexdigest()[:16],
            "example": "<redacted>" if sensitive else value[:64],
            "format": value_format,
            "decodable": decodable,
            "secret": sensitive,
            "reflected": _reflected(value, response),
        })
        if len(result) >= MAX_INPUTS_PER_FLOW:
            break
    return result


def _response_signature(snapshot: Mapping[str, Any], marker: str = "") -> tuple[int, str, str, str]:
    headers = _headers(snapshot, "response")
    body = str(snapshot.get("response_body") or "")[:8192]
    if marker:
        body = body.replace(marker, "")
    return (
        int(snapshot.get("status_code") or 0),
        _header(headers, "location"),
        _header(headers, "content-type").split(";", 1)[0].lower(),
        body,
    )


def _difference(control_a: Mapping[str, Any], control_b: Mapping[str, Any],
                probe: Mapping[str, Any], marker: str) -> str | None:
    base_a = _response_signature(control_a)
    base_b = _response_signature(control_b)
    candidate = _response_signature(probe, marker)
    # Dynamic baselines should not be presented as a reliable discovery.
    if base_a[:3] != base_b[:3]:
        return None
    if candidate[0] != base_a[0]:
        return "status"
    if candidate[1] != base_a[1]:
        return "redirect"
    if candidate[2] != base_a[2]:
        return "content_type"
    # Generic "echo all inputs" endpoints are not evidence that a name is
    # recognized. A reflected marker alone must not produce a finding.
    if marker and marker in str(probe.get("response_body") or ""):
        return None
    baseline_similarity = SequenceMatcher(None, base_a[3], base_b[3]).ratio()
    if baseline_similarity < 0.97:
        return None
    similarity = SequenceMatcher(None, base_a[3], candidate[3]).ratio()
    if similarity < 0.85 and similarity < baseline_similarity - 0.1:
        return "body"
    return None


async def mine(scan, context: PluginContext) -> list[ScanIssue]:
    """Probe candidate names through the host's rate-limited Replay sender."""
    if scan.insertion_point.kind != "request":
        return []
    request = scan.request
    headers = _headers(request, "request")
    content_type = _header(headers, "content-type").lower()
    existing = {(kind, name.lower()) for kind, name, _value in _inputs(request)}
    existing.update(("header", name.lower()) for name, _value in headers)
    extra = str(context.settings.get("extra_names") or "")
    custom = tuple(name.strip() for name in extra.split(",") if name.strip())
    max_names = max(1, min(int(context.settings.get("max_names") or 25), 50))
    kinds = ["query", "header", "cookie"]
    if "application/x-www-form-urlencoded" in content_type:
        kinds.append("form")
    if "json" in content_type:
        try:
            if isinstance(json.loads(str(request.get("request_body") or "")), dict):
                kinds.append("json")
        except ValueError:
            pass
    if not context.settings.get("probe_cookies"):
        kinds.remove("cookie")
    control_a = await scan.send_with()
    control_b = await scan.send_with()
    issues: list[ScanIssue] = []
    for kind in kinds:
        names = (*HEADER_NAMES, *custom) if kind == "header" else (*DEFAULT_NAMES, *custom)
        tested: set[str] = set()
        for name in names:
            if len(tested) >= max_names:
                break
            normalized = name.lower()
            if normalized in tested or (kind, normalized) in existing:
                continue
            if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]{0,99}", name):
                continue
            if kind == "header" and "." in name:
                continue
            tested.add(normalized)
            marker = "lanius" + secrets.token_hex(5)
            try:
                first = await scan.send_with(kind, name, marker)
            except Exception as exc:
                # The host request budget is a job limit, so stop cleanly on
                # exhaustion rather than turning every remaining input into an error.
                if "request limit" in str(exc):
                    return issues
                raise
            reason = _difference(control_a, control_b, first, marker)
            if reason is None:
                continue
            second_marker = "lanius" + secrets.token_hex(5)
            second = await scan.send_with(kind, name, second_marker)
            if _difference(control_a, control_b, second, second_marker) != reason:
                continue
            issues.append(ScanIssue(
                title=f"Possible hidden {kind} input: {name}",
                severity="info",
                confidence="firm" if reason in {"status", "redirect", "content_type"} else "tentative",
                detail=(
                    f"Adding the {kind} input {name!r} changed the response in "
                    f"two probes ({reason}). Confirm its behavior manually before "
                    "treating it as a security issue."
                ),
                parameter=name,
                evidence={
                    "kind": kind, "difference": reason,
                    "baseline_status": control_a.get("status_code"),
                    "probe_status": first.get("status_code"),
                },
                fingerprint=f"{kind}:{normalized}",
            ))
    return issues


def activate(context: PluginContext) -> None:
    context.settings.define(
        SettingDefinition("ignore_names", "Ignored parameter names", default="__VIEWSTATE,__EVENTVALIDATION",
                          description="Comma-separated names excluded from History analysis."),
        SettingDefinition("extra_names", "Extra names to probe", default="",
                          description="Comma-separated candidate names added to the built-in list."),
        SettingDefinition("max_names", "Maximum names per input type", kind="integer", default=25,
                          description="Up to 50 names per type. Every probe uses the active scan job budget."),
        SettingDefinition("probe_cookies", "Probe cookie names", kind="boolean", default=False,
                          description="Include cookie inputs in explicitly started active scans."),
    )

    def analyze_page(event: Mapping[str, Any]) -> dict[str, Any]:
        ignored = {name.strip().lower() for name in str(context.settings.get("ignore_names") or "").split(",")}
        page = context.flows.page(
            limit=20,
            cursor=event.get("cursor") if isinstance(event.get("cursor"), str) else None,
            anchor=event.get("anchor") if isinstance(event.get("anchor"), int) else None,
            in_scope_only=True,
            body_limit=65536,
        )
        observations = []
        analyzed_flows = 0
        for flow in page["items"]:
            if flow.get("source") == "replay":
                continue
            analyzed_flows += 1
            observations.extend(analyze_flow(flow, ignored))
        return {
            "observations": observations,
            "flows": len(page["items"]),
            "analyzed_flows": analyzed_flows,
            "anchor": page["anchor"],
            "next_cursor": page["next_cursor"],
            "has_more": page["has_more"],
        }

    async def start_mining(event: Mapping[str, Any]) -> Mapping[str, Any]:
        flow_id = str(event.get("flow_id") or "").strip()
        if not flow_id:
            raise ValueError("Select a captured HTTP flow before starting parameter mining")
        return await context.scanner.start("hidden-inputs", flow_id)

    context.actions.register("analyze-page", "Analyze History page", analyze_page,
                             locations=("plugin",))
    context.actions.register("mine", "Find hidden parameters", start_mining,
                             locations=("plugin", "history", "flow", "request"))
    context.scanner.register_active("hidden-inputs", "Hidden parameter discovery",
                                    lambda scan: mine(scan, context), request_level=True,
                                    description="Explicitly probes candidate query, header, cookie, and body names.")
    context.log.info("Parameter Analyzer actions and active check registered")
