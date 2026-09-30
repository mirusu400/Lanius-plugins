"""Passive checks for missing HTTP response security headers."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from lanius_sdk import PluginContext, ScanIssue, SettingDefinition


def _headers(snapshot: Mapping[str, Any]) -> dict[str, list[str]]:
    values: dict[str, list[str]] = {}
    for item in snapshot.get("response_headers") or ():
        if not isinstance(item, (list, tuple)) or len(item) != 2:
            continue
        name, value = item
        values.setdefault(str(name).lower(), []).append(str(value))
    return values


def analyze(
    snapshot: Mapping[str, Any],
    *,
    check_csp: bool = True,
    check_hsts: bool = True,
    check_nosniff: bool = True,
) -> list[ScanIssue]:
    """Return findings without issuing any additional requests."""

    if snapshot.get("status_code") is None or snapshot.get("error"):
        return []

    headers = _headers(snapshot)
    content_type = ",".join(headers.get("content-type", ())).lower()
    is_html = "text/html" in content_type or "application/xhtml+xml" in content_type
    issues: list[ScanIssue] = []

    if check_csp and is_html and "content-security-policy" not in headers:
        issues.append(
            ScanIssue(
                title="Content Security Policy header missing",
                severity="low",
                confidence="firm",
                detail=(
                    "The HTML response does not include a Content-Security-Policy "
                    "header, so the browser has no response-defined allowlist for "
                    "scripts and other active content."
                ),
                remediation=(
                    "Deploy a restrictive Content-Security-Policy. Start in "
                    "report-only mode if the application needs a staged rollout."
                ),
                parameter="content-security-policy",
                evidence={"header": "content-security-policy", "present": False},
            )
        )

    if (
        check_hsts
        and str(snapshot.get("scheme") or "").lower() == "https"
        and "strict-transport-security" not in headers
    ):
        issues.append(
            ScanIssue(
                title="HTTP Strict Transport Security header missing",
                severity="low",
                confidence="firm",
                detail=(
                    "The HTTPS response does not include Strict-Transport-Security, "
                    "so a browser may still attempt a future connection over HTTP."
                ),
                remediation=(
                    "Return Strict-Transport-Security on HTTPS responses with an "
                    "appropriate max-age after confirming all required subdomains "
                    "support HTTPS."
                ),
                parameter="strict-transport-security",
                evidence={"header": "strict-transport-security", "present": False},
            )
        )

    if check_nosniff and "x-content-type-options" not in headers:
        issues.append(
            ScanIssue(
                title="X-Content-Type-Options header missing",
                severity="info",
                confidence="firm",
                detail=(
                    "The response does not set X-Content-Type-Options: nosniff, "
                    "which can allow browsers to reinterpret some response types."
                ),
                remediation="Return X-Content-Type-Options: nosniff.",
                parameter="x-content-type-options",
                evidence={"header": "x-content-type-options", "present": False},
            )
        )

    return issues


def activate(context: PluginContext) -> None:
    context.settings.define(
        SettingDefinition(
            "check_csp",
            "Check Content-Security-Policy",
            kind="boolean",
            default=True,
            description="Report HTML responses that do not define a CSP.",
        ),
        SettingDefinition(
            "check_hsts",
            "Check Strict-Transport-Security",
            kind="boolean",
            default=True,
            description="Report HTTPS responses that do not define HSTS.",
        ),
        SettingDefinition(
            "check_nosniff",
            "Check X-Content-Type-Options",
            kind="boolean",
            default=True,
            description="Report responses that do not disable MIME sniffing.",
        ),
    )

    def check(snapshot: Mapping[str, Any]) -> list[ScanIssue]:
        return analyze(
            snapshot,
            check_csp=bool(context.settings.get("check_csp")),
            check_hsts=bool(context.settings.get("check_hsts")),
            check_nosniff=bool(context.settings.get("check_nosniff")),
        )

    context.scanner.register_passive(
        "missing-security-headers",
        "Missing security headers",
        check,
        description="Checks captured responses without sending additional traffic.",
    )
    context.log.info("Security Headers passive checks registered")

