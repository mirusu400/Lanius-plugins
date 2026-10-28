"""Bounded, explicitly started dynamic checks for captured web inputs.

All probes use Lanius's active scanner sender. The plugin does not open sockets,
follow redirects, or execute an external scanner.
"""

from __future__ import annotations

import asyncio
import json
import re
import secrets
from collections.abc import Mapping
from difflib import SequenceMatcher
from typing import Any
from urllib.parse import parse_qsl, urljoin, urlsplit

from lanius_sdk import PluginContext, ScanIssue, SettingDefinition


BODY_LIMIT = 65_536
COMPARISON_BODY_LIMIT = 32_768
MAX_HISTORY_PAGES = 20
SAFE_METHODS = {"GET", "HEAD"}
ACTIVE_INPUT_KINDS = {"query", "form", "json"}
SENSITIVE_NAME = re.compile(
    r"(?:pass(?:word)?|secret|token|sess(?:ion)?|auth|api[_-]?key|csrf|xsrf|credential)",
    re.IGNORECASE,
)
REDIRECT_NAME = re.compile(
    r"(?:^|[_-])(?:url|uri|redirect|return|next|continue|dest(?:ination)?|"
    r"callback|goto|target)(?:$|[_-])",
    re.IGNORECASE,
)
SQL_ERRORS = (
    ("mysql", re.compile(
        r"(?:you have an error in your sql syntax|warning.{0,40}mysql|"
        r"mysql_(?:query|fetch|num)|mysqli?::)", re.IGNORECASE | re.DOTALL,
    )),
    ("postgresql", re.compile(
        r"(?:postgresql.{0,30}error|pg_(?:query|exec)|unterminated quoted "
        r"string|syntax error at or near)", re.IGNORECASE | re.DOTALL,
    )),
    ("microsoft-sql-server", re.compile(
        r"(?:unclosed quotation mark after the character string|microsoft ole db "
        r"provider for sql server|sqlserverexception|system\.data\.sqlclient)",
        re.IGNORECASE | re.DOTALL,
    )),
    ("oracle", re.compile(
        r"(?:ora-\d{5}|oracle error|quoted string not properly terminated)",
        re.IGNORECASE,
    )),
    ("sqlite", re.compile(
        r"(?:sqlite(?:3)?\.(?:operationalerror|databaseerror)|sqlite error|"
        r"unrecognized token.{0,40}[\"'])", re.IGNORECASE | re.DOTALL,
    )),
)


def _headers(snapshot: Mapping[str, Any], side: str = "response") -> list[tuple[str, str]]:
    result = []
    for item in snapshot.get(f"{side}_headers") or ():
        if isinstance(item, (list, tuple)) and len(item) == 2:
            result.append((str(item[0]), str(item[1])))
    return result


def _header(snapshot: Mapping[str, Any], name: str, side: str = "response") -> str:
    wanted = name.lower()
    return next(
        (value for key, value in _headers(snapshot, side) if key.lower() == wanted),
        "",
    )


def _body(snapshot: Mapping[str, Any]) -> str:
    return str(snapshot.get("response_body") or "")[:COMPARISON_BODY_LIMIT]


def _similarity(first: Mapping[str, Any], second: Mapping[str, Any]) -> float:
    left = _body(first)
    right = _body(second)
    if left == right:
        return 1.0
    if not left or not right:
        return 0.0
    return SequenceMatcher(None, left, right).ratio()


def _same_metadata(first: Mapping[str, Any], second: Mapping[str, Any]) -> bool:
    return (
        first.get("status_code") == second.get("status_code")
        and _header(first, "location") == _header(second, "location")
        and _header(first, "content-type").split(";", 1)[0].lower()
        == _header(second, "content-type").split(";", 1)[0].lower()
    )


def _stable(first: Mapping[str, Any], second: Mapping[str, Any]) -> bool:
    if first.get("error") or second.get("error"):
        return False
    if first.get("status_code") is None or not _same_metadata(first, second):
        return False
    return _similarity(first, second) >= 0.90


def _resembles(first: Mapping[str, Any], second: Mapping[str, Any]) -> bool:
    return _same_metadata(first, second) and _similarity(first, second) >= 0.88


def _new_sql_error(
    baseline: Mapping[str, Any], candidate: Mapping[str, Any]
) -> str | None:
    before = _body(baseline)
    after = _body(candidate)
    for family, pattern in SQL_ERRORS:
        if pattern.search(after) and not pattern.search(before):
            return family
    return None


def _content_is_html(snapshot: Mapping[str, Any]) -> bool:
    content_type = _header(snapshot, "content-type").lower()
    return any(item in content_type for item in (
        "text/html", "application/xhtml+xml", "image/svg+xml",
    ))


def _redirects_to_canary(snapshot: Mapping[str, Any], request_url: str) -> bool:
    location = _header(snapshot, "location")
    if not location:
        return False
    try:
        return urlsplit(urljoin(request_url, location)).hostname == "lanius.invalid"
    except ValueError:
        return False


async def dynamic_audit(scan: Any, context: PluginContext) -> list[ScanIssue]:
    """Run non-destructive differential probes against one insertion point."""

    point = scan.insertion_point
    if point.kind not in ACTIVE_INPUT_KINDS or SENSITIVE_NAME.search(point.name):
        return []
    method = str(scan.request.get("method") or "GET").upper()
    if method not in SAFE_METHODS and not context.settings.get("allow_unsafe_methods"):
        return []

    issues: list[ScanIssue] = []
    base_value = str(point.base_value or "")
    try:
        control = await scan.send(base_value)
        if not _stable(scan.request, control):
            return []

        if context.settings.get("check_sqli"):
            quote_probe = await scan.send(base_value + "'")
            family = _new_sql_error(control, quote_probe)
            if family:
                escaped_probe = await scan.send(base_value + "''")
                if (
                    _new_sql_error(control, escaped_probe) != family
                    and _resembles(control, escaped_probe)
                ):
                    issues.append(ScanIssue(
                        title="Possible error-based SQL injection",
                        severity="medium",
                        confidence="firm",
                        detail=(
                            f"Adding one quote to the {point.kind} input {point.name!r} "
                            f"introduced a {family} error signature, while a doubled quote "
                            "returned to the baseline response shape."
                        ),
                        remediation=(
                            "Use parameterized queries and keep untrusted input out of SQL "
                            "syntax. Suppress database error details in HTTP responses."
                        ),
                        parameter=point.name,
                        evidence={
                            "kind": point.kind,
                            "database_family": family,
                            "baseline_status": control.get("status_code"),
                            "probe_status": quote_probe.get("status_code"),
                        },
                        fingerprint=f"sqli:{point.kind}:{point.name.lower()}",
                    ))

        if context.settings.get("check_xss") and _content_is_html(control):
            token = "lanius" + secrets.token_hex(6)
            fragment = f'{token}<lanius-scan data-check="{token}">'
            reflected = await scan.send(fragment)
            if fragment in _body(reflected) and fragment not in _body(control):
                issues.append(ScanIssue(
                    title="Potential reflected XSS (HTML injection)",
                    severity="low",
                    confidence="tentative",
                    detail=(
                        f"A unique HTML canary supplied through the {point.kind} input "
                        f"{point.name!r} was returned without HTML encoding. The reflection "
                        "context must be reviewed before treating this as executable XSS."
                    ),
                    remediation=(
                        "Apply context-appropriate output encoding and avoid inserting "
                        "untrusted values into executable HTML, script, style, or URL contexts."
                    ),
                    parameter=point.name,
                    evidence={
                        "kind": point.kind,
                        "content_type": _header(reflected, "content-type")[:160],
                        "probe_status": reflected.get("status_code"),
                    },
                    fingerprint=f"xss:{point.kind}:{point.name.lower()}",
                ))

        if context.settings.get("check_ssti"):
            token = "lanius" + secrets.token_hex(6)
            first_payload = f"{token}{{{{7*7}}}}end"
            first_result = f"{token}49end"
            first = await scan.send(first_payload)
            if first_result in _body(first) and first_result not in _body(control):
                second_payload = f"{token}{{{{8*8}}}}end"
                second_result = f"{token}64end"
                second = await scan.send(second_payload)
                if second_result in _body(second):
                    issues.append(ScanIssue(
                        title="Possible server-side template injection",
                        severity="high",
                        confidence="firm",
                        detail=(
                            f"Two arithmetic template expressions supplied through the "
                            f"{point.kind} input {point.name!r} were evaluated to their "
                            "expected results. No command-execution payload was sent."
                        ),
                        remediation=(
                            "Do not concatenate untrusted input into template source. Pass "
                            "it only as template data and use the template engine's sandbox."
                        ),
                        parameter=point.name,
                        evidence={
                            "kind": point.kind,
                            "expressions": ["7*7", "8*8"],
                            "probe_status": first.get("status_code"),
                        },
                        fingerprint=f"ssti:{point.kind}:{point.name.lower()}",
                    ))

        if context.settings.get("check_redirect") and REDIRECT_NAME.search(point.name):
            canary = "https://lanius.invalid/dynamic-audit"
            redirect = await scan.send(canary)
            if _redirects_to_canary(redirect, str(scan.request.get("url") or "")):
                issues.append(ScanIssue(
                    title="Possible open redirect",
                    severity="medium",
                    confidence="firm",
                    detail=(
                        f"The {point.kind} input {point.name!r} controlled the response "
                        "Location header and redirected to the reserved lanius.invalid host."
                    ),
                    remediation=(
                        "Use server-side identifiers or an allowlist of local destinations. "
                        "Reject absolute URLs and scheme-relative external destinations."
                    ),
                    parameter=point.name,
                    evidence={
                        "kind": point.kind,
                        "status": redirect.get("status_code"),
                        "location_host": "lanius.invalid",
                    },
                    fingerprint=f"redirect:{point.kind}:{point.name.lower()}",
                ))
    except Exception as exc:
        if "request limit" in str(exc).lower():
            return issues
        raise
    return issues


def _effective_port(scheme: str, value: Any) -> int | None:
    if value is None:
        return 443 if scheme == "https" else 80 if scheme == "http" else None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _input_names(snapshot: Mapping[str, Any]) -> list[tuple[str, str]]:
    result = [("query", name) for name, _value in parse_qsl(
        str(snapshot.get("query") or "")[:32_768], keep_blank_values=True
    )]
    content_type = _header(snapshot, "content-type", "request").lower()
    body = str(snapshot.get("request_body") or "")[:BODY_LIMIT]
    if "application/x-www-form-urlencoded" in content_type:
        result.extend(
            ("form", name)
            for name, _value in parse_qsl(body, keep_blank_values=True)
        )
    elif "json" in content_type:
        try:
            parsed = json.loads(body)
        except ValueError:
            parsed = None
        if isinstance(parsed, dict):
            result.extend(
                ("json", str(name)) for name, value in parsed.items()
                if isinstance(value, (str, int, float, bool)) or value is None
            )
    return [item for item in result if item[1] and not SENSITIVE_NAME.search(item[1])]


def select_domain_flows(
    context: PluginContext,
    target: Mapping[str, Any],
    *,
    limit: int,
    allow_unsafe_methods: bool,
) -> list[Mapping[str, Any]]:
    """Pick recent, distinct, in-scope request shapes for one site."""

    scheme = str(target.get("scheme") or "").lower()
    host = str(target.get("host") or "").strip().lower()
    port = _effective_port(scheme, target.get("port"))
    if scheme not in {"http", "https"} or not host or port is None:
        raise ValueError("The selected Target row does not identify an HTTP site")

    selected: list[Mapping[str, Any]] = []
    signatures: set[tuple[Any, ...]] = set()
    cursor: str | None = None
    anchor: int | None = None
    for _page_number in range(MAX_HISTORY_PAGES):
        page = context.flows.page(
            limit=100,
            cursor=cursor,
            anchor=anchor,
            in_scope_only=True,
            body_limit=BODY_LIMIT,
        )
        if anchor is None:
            anchor = page.get("anchor")
        for flow in page["items"]:
            method = str(flow.get("method") or "GET").upper()
            names = _input_names(flow)
            if (
                str(flow.get("scheme") or "").lower() != scheme
                or str(flow.get("host") or "").lower() != host
                or _effective_port(scheme, flow.get("port")) != port
                or flow.get("source") == "replay"
                or flow.get("status_code") is None
                or flow.get("error")
                or (method not in SAFE_METHODS and not allow_unsafe_methods)
                or not names
            ):
                continue
            signature = (
                method,
                str(flow.get("path") or "/"),
                tuple(sorted(set(names))),
            )
            if signature in signatures:
                continue
            signatures.add(signature)
            selected.append(flow)
            if len(selected) >= limit:
                return selected
        if not page.get("has_more") or not page.get("next_cursor"):
            break
        cursor = str(page["next_cursor"])
    return selected


def activate(context: PluginContext) -> None:
    context.settings.define(
        SettingDefinition(
            "max_flows", "Maximum request shapes per domain",
            kind="integer", default=8,
            description="Scan at most 1-20 recent, distinct captured request shapes.",
        ),
        SettingDefinition(
            "total_requests_per_second", "Approximate domain request rate",
            kind="number", default=4.0,
            description=(
                "Shared approximately across the jobs started for one domain (0.1-20)."
            ),
        ),
        SettingDefinition(
            "allow_unsafe_methods", "Scan non-idempotent methods",
            kind="boolean", default=False,
            description=(
                "Include captured POST, PUT, PATCH, and DELETE requests. "
                "Disabled by default."
            ),
        ),
        SettingDefinition(
            "check_sqli", "Check error-based SQL injection",
            kind="boolean", default=True,
        ),
        SettingDefinition(
            "check_xss", "Check reflected HTML injection",
            kind="boolean", default=True,
        ),
        SettingDefinition(
            "check_ssti", "Check template expression evaluation",
            kind="boolean", default=True,
        ),
        SettingDefinition(
            "check_redirect", "Check open redirects",
            kind="boolean", default=True,
        ),
    )

    async def start_domain_scan(event: Mapping[str, Any]) -> Mapping[str, Any]:
        target = event.get("target")
        if not isinstance(target, Mapping):
            raise ValueError("Right-click a domain in Target to start Dynamic Audit")
        max_flows = max(1, min(int(context.settings.get("max_flows") or 8), 20))
        allow_unsafe = bool(context.settings.get("allow_unsafe_methods"))
        flows = await asyncio.to_thread(
            select_domain_flows,
            context,
            target,
            limit=max_flows,
            allow_unsafe_methods=allow_unsafe,
        )
        if not flows:
            raise ValueError(
                "No eligible in-scope captured requests were found for this domain. "
                "Capture a GET/HEAD request with query, form, or JSON inputs first."
            )
        total_rate = max(
            0.1,
            min(float(context.settings.get("total_requests_per_second") or 4.0), 20.0),
        )
        per_job_rate = max(0.1, total_rate / len(flows))
        jobs = []
        for flow in flows:
            jobs.append(await context.scanner.start(
                "dynamic-audit",
                str(flow["flow_id"]),
                concurrency=1,
                requests_per_second=per_job_rate,
            ))
        first = jobs[0]
        return {
            **first,
            "domain": {
                "scheme": str(target.get("scheme")),
                "host": str(target.get("host")),
                "port": target.get("port"),
            },
            "flow_count": len(flows),
            "jobs": jobs,
        }

    context.actions.register(
        "scan-domain",
        "Dynamic scan domain",
        start_domain_scan,
        locations=("target",),
        description="Scan representative captured inputs for this in-scope domain.",
    )
    context.scanner.register_active(
        "dynamic-audit",
        "Dynamic input audit",
        lambda scan: dynamic_audit(scan, context),
        description=(
            "Checks captured query, form, and JSON inputs for SQL error behavior, "
            "raw HTML reflection, template evaluation, and open redirects."
        ),
    )
    context.log.info("Dynamic Audit domain action and active check registered")
