from __future__ import annotations

import base64
import gzip
import struct

import pytest

from app.plugin_registry import ContributionRegistry

from conftest import load_plugin

plugin = load_plugin("lanius.protobuf-editor")

# 1: varint 150, 2: string "testing", 3: message { 1: varint 1, 2: string "hi" },
# 4: fixed32 0x3f800000 (1.0), 5: bytes 00ff
SAMPLE = bytes.fromhex(
    "0896011207" + b"testing".hex() + "1a060801120268" + "69" + "2500" + "00803f" + "2a0200ff"
)


def _message(body: str, content_type: str, extra: str = "", *, editable=True) -> dict:
    head = (
        f"POST /svc HTTP/1.1\r\nHost: a.test\r\nContent-Type: {content_type}\r\n{extra}"
        f"Content-Length: {len(body)}\r\n\r\n"
    )
    raw = head + body
    headers = [[k, v] for k, v in (l.split(": ", 1) for l in head.split("\r\n")[1:] if ": " in l)]
    return {"raw": raw, "body": body, "headers": headers, "editable": editable,
            "side": "request", "location": "replay"}


def test_wire_roundtrip_and_inference() -> None:
    fields = plugin.parse_message(SAMPLE)
    assert [(f.number, f.kind) for f in fields] == [
        (1, "varint"), (2, "string"), (3, "message"), (4, "fixed32"), (5, "bytes")]
    assert plugin.encode_message(fields) == SAMPLE
    text = "\n".join(plugin.fields_to_text(fields))
    assert "3: message {" in text and "# float 1" in text
    again = plugin.text_to_fields(list(enumerate(text.split("\n"), 1)))
    assert plugin.encode_message(again) == SAMPLE


def test_strict_parser_rejects_garbage() -> None:
    for bad in (b"\x08", b"\x0a\x05ab", b"\x0b\x01", b"\x00\x01"):
        with pytest.raises(plugin.ProtobufError):
            plugin.parse_message(bad)


def test_text_errors_name_the_line() -> None:
    with pytest.raises(plugin.ProtobufError, match="line 2"):
        plugin.text_to_fields([(1, "1: varint 1"), (2, "2: string nope")])
    with pytest.raises(plugin.ProtobufError, match="closing"):
        plugin.text_to_fields([(1, "1: message {")])
    with pytest.raises(plugin.ProtobufError, match="32 bits"):
        plugin.text_to_fields([(1, "1: fixed32 4294967296")])


def test_raw_binary_body_edit_updates_content_length() -> None:
    message = _message(SAMPLE.decode("latin-1"), "application/x-protobuf")
    text = plugin.render_view(message)
    assert 'string "testing"' in text
    assert plugin.apply_edit(text, message) == message["raw"]

    out = plugin.apply_edit(text.replace("varint 150", "varint 99999").replace('"testing"', '"x"'), message)
    head, _, body = out.partition("\r\n\r\n")
    data = body.encode("latin-1")
    assert f"Content-Length: {len(data)}" in head
    fields = plugin.parse_message(data)
    assert fields[0].value == 99999 and fields[1].value == "x"


def test_base64_body_is_detected_and_reencoded() -> None:
    body = base64.b64encode(SAMPLE).decode()
    message = _message(body, "application/json")
    text = plugin.render_view(message)
    assert "format: base64" in text
    out = plugin.apply_edit(text.replace("varint 150", "varint 1"), message)
    new_body = out.partition("\r\n\r\n")[2]
    assert plugin.parse_message(base64.b64decode(new_body))[0].value == 1
    assert plugin.render_view(_message("hello world, not protobuf", "text/plain")) is None
    assert plugin.render_view(_message('{"a":1}', "application/json")) is None


def test_grpc_frames_gzip_and_trailers() -> None:
    plain = struct.pack(">BI", 0, len(SAMPLE)) + SAMPLE
    packed = gzip.compress(SAMPLE, mtime=0)
    zipped = struct.pack(">BI", 1, len(packed)) + packed
    body = (plain + zipped).decode("latin-1")
    message = _message(body, "application/grpc", "grpc-encoding: gzip\r\n")
    text = plugin.render_view(message)
    assert text.count("=== FRAME") == 2 and "gzip" in text
    out = plugin.apply_edit(text.replace('"testing"', '"changed"'), message)
    data = out.partition("\r\n\r\n")[2].encode("latin-1")
    first_len = struct.unpack(">I", data[1:5])[0]
    assert b"changed" in data[5:5 + first_len]
    second = data[5 + first_len:]
    assert second[0] == 1 and b"changed" in gzip.decompress(second[5:])

    with pytest.raises(plugin.ProtobufError, match="Expected 2"):
        plugin.apply_edit("=== FRAME 1 flags=0 ===\n1: varint 1\n", message)


def test_grpc_web_text() -> None:
    frame = struct.pack(">BI", 0, len(SAMPLE)) + SAMPLE
    message = _message(base64.b64encode(frame).decode(), "application/grpc-web-text")
    text = plugin.render_view(message)
    out = plugin.apply_edit(text.replace("varint 150", "varint 7"), message)
    data = base64.b64decode(out.partition("\r\n\r\n")[2])
    assert plugin.parse_message(data[5:])[0].value == 7


def test_binary_output_requires_a_byte_exact_content_type() -> None:
    body = base64.b64encode(SAMPLE).decode()
    message = _message(body, "text/plain")
    assert plugin.render_view(message) is not None  # base64 text is fine
    raw_message = _message(SAMPLE.decode("latin-1"), "application/octet-stream")
    assert plugin.render_view(raw_message) is None


def test_codec_and_registration() -> None:
    encoded = plugin.encode_text(plugin.decode_text(SAMPLE.hex()))
    assert base64.b64decode(encoded) == SAMPLE
    assert plugin.decode_text(encoded) == plugin.decode_text(SAMPLE.hex())
    registry = ContributionRegistry(None)
    plugin.activate(registry.context("lanius.protobuf-editor"))
    counts = registry.counts("lanius.protobuf-editor")
    assert counts["codecs"] == 1 and counts["message_views"] == 1
    registry.dispose_owner("lanius.protobuf-editor")
