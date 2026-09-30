"""Replace explicit request placeholders with fresh values."""

from __future__ import annotations

import secrets
import string
import uuid
from collections.abc import Mapping
from typing import Any

from lanius_sdk import PluginContext, SettingDefinition
from mitmproxy import http

_ALPHANUMERIC = string.ascii_letters + string.digits
_DIGITS = string.digits
_SKIPPED_HEADERS = {b"content-length", b"transfer-encoding"}


def _bounded_length(value: Any, default: int) -> int:
    if isinstance(value, bool):
        return default
    try:
        return max(1, min(128, int(value)))
    except (TypeError, ValueError):
        return default


def make_replacements(random_length: int, number_length: int) -> dict[bytes, bytes]:
    return {
        b"#RANDOM#": "".join(
            secrets.choice(_ALPHANUMERIC) for _ in range(random_length)
        ).encode("ascii"),
        b"#RANDOMNUM#": "".join(
            secrets.choice(_DIGITS) for _ in range(number_length)
        ).encode("ascii"),
        b"#UUID#": str(uuid.uuid4()).encode("ascii"),
    }


def replace_bytes(value: bytes, replacements: Mapping[bytes, bytes]) -> tuple[bytes, int]:
    total = 0
    for marker, replacement in replacements.items():
        count = value.count(marker)
        if count:
            value = value.replace(marker, replacement)
            total += count
    return value, total


class RequestRandomizer:
    def __init__(self, context: PluginContext) -> None:
        self.context = context
        self.requests_changed = 0
        self.placeholders_replaced = 0

    def request(self, flow: http.HTTPFlow) -> None:
        random_length = _bounded_length(
            self.context.settings.get("random_length"), 16
        )
        number_length = _bounded_length(
            self.context.settings.get("number_length"), 8
        )
        replacements = make_replacements(random_length, number_length)
        changed = 0

        path, count = replace_bytes(flow.request.path.encode("utf-8"), replacements)
        if count:
            flow.request.path = path.decode("utf-8")
            changed += count

        fields: list[tuple[bytes, bytes]] = []
        for name, value in flow.request.headers.fields:
            if name.lower() in _SKIPPED_HEADERS:
                fields.append((name, value))
                continue
            replaced, count = replace_bytes(value, replacements)
            fields.append((name, replaced))
            changed += count
        flow.request.headers.fields = tuple(fields)

        body, count = replace_bytes(flow.request.content or b"", replacements)
        if count:
            flow.request.content = body
            changed += count

        if not changed:
            return
        self.requests_changed += 1
        self.placeholders_replaced += changed
        if self.context.settings.get("log_replacements"):
            self.context.log.info(
                "replaced %d placeholder(s) in %s %s",
                changed,
                flow.request.method,
                flow.request.pretty_url,
            )

    def stats(self, _payload: Mapping[str, Any]) -> dict[str, int]:
        return {
            "requests_changed": self.requests_changed,
            "placeholders_replaced": self.placeholders_replaced,
        }

    def reset(self, _payload: Mapping[str, Any]) -> dict[str, int]:
        self.requests_changed = 0
        self.placeholders_replaced = 0
        self.context.log.info("Request Randomizer statistics reset")
        return self.stats(_payload)


def activate(context: PluginContext) -> RequestRandomizer:
    context.settings.define(
        SettingDefinition(
            "random_length",
            "Alphanumeric length",
            kind="integer",
            default=16,
            description="Length used for #RANDOM# (clamped to 1-128).",
        ),
        SettingDefinition(
            "number_length",
            "Numeric length",
            kind="integer",
            default=8,
            description="Length used for #RANDOMNUM# (clamped to 1-128).",
        ),
        SettingDefinition(
            "log_replacements",
            "Log replacements",
            kind="boolean",
            default=False,
            description="Write one plugin log entry when a request is changed.",
        ),
    )
    addon = RequestRandomizer(context)
    context.actions.register(
        "stats",
        "Read Request Randomizer statistics",
        addon.stats,
        locations=("global",),
    )
    context.actions.register(
        "reset",
        "Reset Request Randomizer statistics",
        addon.reset,
        locations=("global",),
    )
    context.log.info("Request Randomizer activated")
    return addon

