"""Schema-less Protocol Buffers viewer and editor.

A **Protobuf** message-view tab decodes request and response bodies that carry
protobuf data: raw ``application/x-protobuf`` bodies, gRPC and gRPC-web frames
(binary or ``grpc-web-text`` base64), and bodies that are entirely base64 (or
base64url) protobuf. Without a ``.proto`` file field types are inferred, so the
text view lists ``number: type value`` lines that can be edited, added to, and
removed. In Replay, Fuzzer and Intercept the tab re-encodes the edited text,
rebuilding gRPC frame lengths, base64, and ``Content-Length``.

Binary bodies are only byte-exact through Lanius's Raw text when the
Content-Type is a protobuf/gRPC type (Lanius reads those one byte per
character). The plugin sends no requests and uses only the standard library.
"""

from __future__ import annotations

import base64
import binascii
import gzip
import json
import re
import struct
from collections.abc import Mapping
from typing import Any


MAX_DEPTH = 12
MAX_FIELDS = 20_000
MAX_FRAMES = 200
MAX_BODY = 8 * 1024 * 1024

BINARY_TYPE = re.compile(
    r"^\s*application/(?:(?:x-)?(?:google-)?protobuf|vnd\.google\.protobuf"
    r"|grpc(?:-web)?(?:\+proto)?|[\w.+-]+\+protobuf)\s*(?:;|$)",
    re.IGNORECASE,
)
BASE64_BODY = re.compile(r"^[A-Za-z0-9+/_-]{8,}={0,2}$")
TYPES = ("varint", "fixed32", "fixed64", "string", "bytes", "message")


class ProtobufError(ValueError):
    """The text or bytes are not valid for this editor."""


# --------------------------------------------------------------------------
# Wire format


def read_varint(data: bytes, pos: int) -> tuple[int, int]:
    result = shift = 0
    while True:
        if pos >= len(data) or shift > 63:
            raise ProtobufError("truncated or oversized varint")
        byte = data[pos]
        pos += 1
        result |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return result, pos
        shift += 7


def write_varint(value: int) -> bytes:
    if not 0 <= value < 1 << 64:
        raise ProtobufError(f"varint {value} is outside 0..2^64-1")
    out = bytearray()
    while value > 0x7F:
        out.append((value & 0x7F) | 0x80)
        value >>= 7
    out.append(value)
    return bytes(out)


class Field:
    """One decoded field. ``value`` is an int, str, bytes, or list[Field]."""

    __slots__ = ("number", "kind", "value")

    def __init__(self, number: int, kind: str, value: Any) -> None:
        self.number = number
        self.kind = kind
        self.value = value


def _printable(text: str) -> bool:
    return all(char.isprintable() or char in "\n\r\t" for char in text)


def parse_message(data: bytes, depth: int = 0, budget: list[int] | None = None) -> list[Field]:
    """Strictly decode ``data``; raises ProtobufError unless every byte is a field."""

    budget = budget if budget is not None else [MAX_FIELDS]
    fields: list[Field] = []
    pos = 0
    while pos < len(data):
        budget[0] -= 1
        if budget[0] < 0:
            raise ProtobufError("too many fields")
        tag, pos = read_varint(data, pos)
        number, wire = tag >> 3, tag & 7
        if number < 1 or number >= 1 << 29:
            raise ProtobufError("invalid field number")
        if wire == 0:
            value, pos = read_varint(data, pos)
            fields.append(Field(number, "varint", value))
        elif wire == 1:
            if pos + 8 > len(data):
                raise ProtobufError("truncated fixed64")
            fields.append(Field(number, "fixed64", struct.unpack_from("<Q", data, pos)[0]))
            pos += 8
        elif wire == 5:
            if pos + 4 > len(data):
                raise ProtobufError("truncated fixed32")
            fields.append(Field(number, "fixed32", struct.unpack_from("<I", data, pos)[0]))
            pos += 4
        elif wire == 2:
            length, pos = read_varint(data, pos)
            if pos + length > len(data):
                raise ProtobufError("truncated length-delimited field")
            fields.append(_classify(number, data[pos:pos + length], depth, budget))
            pos += length
        else:
            raise ProtobufError(f"unsupported wire type {wire}")
    return fields


def _classify(number: int, chunk: bytes, depth: int, budget: list[int]) -> Field:
    if not chunk:
        return Field(number, "string", "")
    text: str | None
    try:
        text = chunk.decode("utf-8")
    except UnicodeDecodeError:
        text = None
    if text is not None and _printable(text):
        return Field(number, "string", text)
    if depth < MAX_DEPTH:
        try:
            return Field(number, "message", parse_message(chunk, depth + 1, budget))
        except ProtobufError:
            pass
    if text is not None:
        return Field(number, "string", text)
    return Field(number, "bytes", chunk)


def encode_message(fields: list[Field]) -> bytes:
    out = bytearray()
    for field in fields:
        if field.kind == "varint":
            out += write_varint(field.number << 3) + write_varint(field.value)
        elif field.kind == "fixed64":
            out += write_varint(field.number << 3 | 1) + struct.pack("<Q", field.value)
        elif field.kind == "fixed32":
            out += write_varint(field.number << 3 | 5) + struct.pack("<I", field.value)
        else:
            if field.kind == "string":
                payload = field.value.encode("utf-8")
            elif field.kind == "bytes":
                payload = bytes(field.value)
            else:
                payload = encode_message(field.value)
            out += write_varint(field.number << 3 | 2) + write_varint(len(payload)) + payload
    return bytes(out)


# --------------------------------------------------------------------------
# Text form


def _comment(field: Field) -> str:
    if field.kind == "fixed32":
        return f"  # float {struct.unpack('<f', struct.pack('<I', field.value))[0]:.9g}"
    if field.kind == "fixed64":
        return f"  # double {struct.unpack('<d', struct.pack('<Q', field.value))[0]:.17g}"
    if field.kind == "varint" and field.value >= 1 << 63:
        return f"  # int64 {field.value - (1 << 64)}"
    return ""


def fields_to_text(fields: list[Field], indent: int = 0) -> list[str]:
    pad = "  " * indent
    lines: list[str] = []
    for field in fields:
        head = f"{pad}{field.number}: {field.kind}"
        if field.kind == "message":
            lines.append(f"{head} {{")
            lines += fields_to_text(field.value, indent + 1)
            lines.append(f"{pad}}}")
        elif field.kind == "string":
            lines.append(f"{head} {json.dumps(field.value, ensure_ascii=False)}")
        elif field.kind == "bytes":
            lines.append(f"{head} hex:{field.value.hex()}")
        else:
            lines.append(f"{head} {field.value}{_comment(field)}")
    return lines


_LINE = re.compile(r"^(\d+)\s*:\s*(\w+)\s*(.*)$")


def text_to_fields(lines: list[tuple[int, str]]) -> list[Field]:
    """Parse numbered ``(line_no, text)`` pairs of one message body."""

    stack: list[list[Field]] = [[]]
    for number, line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line == "}":
            if len(stack) == 1:
                raise ProtobufError(f"line {number}: unmatched '}}'")
            stack.pop()
            continue
        match = _LINE.match(line)
        if not match:
            raise ProtobufError(f"line {number}: expected 'number: type value'")
        field_number, kind, rest = int(match.group(1)), match.group(2), match.group(3).strip()
        if not 1 <= field_number < 1 << 29:
            raise ProtobufError(f"line {number}: field number out of range")
        if kind not in TYPES:
            raise ProtobufError(f"line {number}: unknown type {kind!r}")
        try:
            if kind == "message":
                if rest.split("#")[0].strip() != "{":
                    raise ProtobufError(f"line {number}: message needs '{{'")
                child: list[Field] = []
                stack[-1].append(Field(field_number, "message", child))
                stack.append(child)
                continue
            if kind == "string":
                try:
                    value, _end = json.JSONDecoder().raw_decode(rest)
                except ValueError as exc:
                    raise ProtobufError(f"line {number}: string must be JSON-quoted") from exc
                if not isinstance(value, str):
                    raise ProtobufError(f"line {number}: string must be JSON-quoted")
            elif kind == "bytes":
                token = rest.split("#")[0].strip()
                if token.startswith("hex:"):
                    value = bytes.fromhex(token[4:].strip())
                elif token.startswith("base64:"):
                    value = base64.b64decode(token[7:].strip() + "===")
                else:
                    raise ProtobufError(f"line {number}: bytes need hex:... or base64:...")
            else:
                token = rest.split("#")[0].strip()
                lowered = token.lower()
                value = {"true": 1, "false": 0}.get(lowered)
                if value is None:
                    value = int(token, 0)
                bits = 32 if kind == "fixed32" else 64
                if value < 0:
                    value += 1 << bits
                if not 0 <= value < 1 << bits:
                    raise ProtobufError(f"line {number}: value does not fit {bits} bits")
        except (ValueError, binascii.Error) as exc:
            if isinstance(exc, ProtobufError):
                raise
            raise ProtobufError(f"line {number}: invalid {kind} value") from exc
        stack[-1].append(Field(field_number, kind, value))
    if len(stack) != 1:
        raise ProtobufError("missing closing '}'")
    return stack[0]


# --------------------------------------------------------------------------
# Body wrappers: raw, base64, gRPC frames


class Frame:
    __slots__ = ("flags", "data", "gzipped", "opaque")

    def __init__(self, flags: int, data: bytes, gzipped: bool = False, opaque: bool = False) -> None:
        self.flags, self.data, self.gzipped, self.opaque = flags, data, gzipped, opaque


class Body:
    """A protobuf payload and the wrapper needed to put it back into a body."""

    def __init__(self, kind: str, frames: list[Frame], pad: bool = True) -> None:
        self.kind = kind  # raw | base64 | base64url | grpc | grpc-web-text
        self.frames = frames
        self.pad = pad


def _content_type(headers: list[list[str]]) -> str:
    return next((v for k, v in headers if k.lower() == "content-type"), "")


def _decode_b64(text: str) -> tuple[bytes, str]:
    """Decode base64/base64url (possibly several padded chunks) strictly."""

    text = "".join(text.split())
    if not text:
        raise ProtobufError("empty base64")
    variant = "base64url" if re.search(r"[-_]", text) else "base64"
    if re.search(r"[+/]", text) and variant == "base64url":
        raise ProtobufError("mixed base64 alphabets")
    decoder = base64.urlsafe_b64decode if variant == "base64url" else base64.b64decode
    out = b""
    for chunk in re.findall(r"[^=]+=*", text):
        body = chunk.rstrip("=")
        try:
            out += decoder(body + "=" * (-len(body) % 4))
        except (binascii.Error, ValueError) as exc:
            raise ProtobufError("invalid base64") from exc
    return out, variant


def _frames(data: bytes, allow_gzip: bool) -> list[Frame]:
    frames: list[Frame] = []
    pos = 0
    while pos < len(data):
        if pos + 5 > len(data) or len(frames) >= MAX_FRAMES:
            raise ProtobufError("not a valid gRPC frame sequence")
        flags = data[pos]
        (length,) = struct.unpack_from(">I", data, pos + 1)
        pos += 5
        if pos + length > len(data) or flags & 0x7E:
            raise ProtobufError("not a valid gRPC frame sequence")
        chunk = data[pos:pos + length]
        pos += length
        if flags & 0x80:  # gRPC-web trailers are HTTP/1 header text
            frames.append(Frame(flags, chunk, opaque=True))
        elif flags & 1:
            try:
                if not allow_gzip:
                    raise OSError
                frames.append(Frame(flags, gzip.decompress(chunk), gzipped=True))
            except (OSError, EOFError):
                frames.append(Frame(flags, chunk, opaque=True))
        else:
            frames.append(Frame(flags, chunk))
    if not frames:
        raise ProtobufError("empty gRPC body")
    return frames


def _body_bytes(body: str) -> bytes:
    try:
        return body.encode("latin-1")
    except UnicodeEncodeError:
        return body.encode("utf-8")


def unwrap(headers: list[list[str]], body: str) -> Body | None:
    """Find the protobuf payload in a message body, or None."""

    if not body or len(body) > MAX_BODY:
        return None
    content_type = _content_type(headers)
    lowered = content_type.lower()
    gzip_ok = any(k.lower() == "grpc-encoding" and "gzip" in v.lower() for k, v in headers)
    try:
        if "grpc" in lowered:
            if "grpc-web-text" in lowered:
                data, _variant = _decode_b64(body)
                return Body("grpc-web-text", _frames(data, gzip_ok))
            return Body("grpc", _frames(_body_bytes(body), gzip_ok))
        if BINARY_TYPE.match(content_type):
            data = _body_bytes(body)
            parse_message(data)
            return Body("raw", [Frame(0, data)])
        stripped = body.strip()
        if BASE64_BODY.match(stripped):
            data, variant = _decode_b64(stripped)
            if data and parse_message(data):
                return Body(variant, [Frame(0, data)], pad=stripped.endswith("="))
    except ProtobufError:
        return None
    return None


def wrap(body: Body) -> str:
    """The body text for ``body``'s frames (inverse of :func:`unwrap`)."""

    if body.kind in ("raw", "base64", "base64url"):
        data = body.frames[0].data
        if body.kind == "raw":
            return data.decode("latin-1")
        encoded = (base64.urlsafe_b64encode if body.kind == "base64url" else base64.b64encode)(data)
        text = encoded.decode("ascii")
        return text if body.pad else text.rstrip("=")
    out = bytearray()
    for frame in body.frames:
        data = frame.data
        if frame.gzipped:
            data = gzip.compress(data, mtime=0)
        out += struct.pack(">BI", frame.flags, len(data)) + data
    if body.kind == "grpc-web-text":
        return base64.b64encode(bytes(out)).decode("ascii")
    return bytes(out).decode("latin-1")


# --------------------------------------------------------------------------
# Message view


_FRAME_MARK = re.compile(r"^===\s*FRAME\s+(\d+)\b(.*)===\s*$")


def _split(message: Mapping[str, Any]) -> tuple[str, str]:
    raw, body = str(message["raw"]), str(message.get("body") or "")
    return raw[: len(raw) - len(body)], body


def render_view(message: Mapping[str, Any]) -> str | None:
    head, body_text = _split(message)
    body = unwrap(message.get("headers") or [], body_text)
    if body is None:
        return None
    lines = [
        "# Protobuf Editor",
        f"# format: {body.kind}. No schema: field types are inferred and may be wrong.",
        "# Lines: 'number: type value'. Types: varint, fixed32, fixed64, string "
        '(JSON-quoted), bytes (hex:... or base64:...), message { ... }.',
        "# Repeated fields are repeated lines. Lines starting with '#' are ignored.",
    ]
    if message.get("body_truncated"):
        lines.append("# WARNING: the body is a truncated preview; do not apply edits.")
    if not message.get("editable"):
        lines.append("# (read-only here; open the request in Replay or Fuzzer to edit)")
    for index, frame in enumerate(body.frames, 1):
        lines.append("")
        lines.append(
            f"=== FRAME {index} flags={frame.flags}"
            + (" gzip" if frame.gzipped else "") + (" opaque" if frame.opaque else "") + " ==="
        )
        if frame.opaque:
            lines.append(f"hex:{frame.data.hex()}")
        else:
            lines += fields_to_text(parse_message(frame.data))
    return "\n".join(lines) + "\n"


def apply_edit(text: str, message: Mapping[str, Any]) -> str:
    raw = str(message["raw"])
    head, body_text = _split(message)
    body = unwrap(message.get("headers") or [], body_text)
    if body is None:
        raise ProtobufError("The message body no longer contains protobuf data")
    if text == render_view({**message, "editable": True}):
        return raw

    blocks: list[tuple[str, list[tuple[int, str]]]] = []
    for number, line in enumerate(text.replace("\r\n", "\n").split("\n"), 1):
        mark = _FRAME_MARK.match(line.strip())
        if mark:
            blocks.append((mark.group(2), []))
        elif blocks:
            blocks[-1][1].append((number, line))
    if len(blocks) != len(body.frames):
        raise ProtobufError(
            f"Expected {len(body.frames)} '=== FRAME n ===' sections, found {len(blocks)}"
        )
    for frame, (info, lines) in zip(body.frames, blocks):
        flags = re.search(r"flags=(\d+)", info)
        if flags:
            frame.flags = int(flags.group(1)) & 0xFF
        if frame.opaque:
            content = "".join(l.strip() for _n, l in lines if l.strip() and not l.strip().startswith("#"))
            if not content.startswith("hex:"):
                raise ProtobufError("opaque frames must be a single 'hex:...' line")
            try:
                frame.data = bytes.fromhex(content[4:])
            except ValueError as exc:
                raise ProtobufError("invalid hex in opaque frame") from exc
        else:
            frame.data = encode_message(text_to_fields(lines))

    new_body = wrap(body)
    if not BINARY_TYPE.match(_content_type(message.get("headers") or [])) and any(
        ord(char) > 0x7F for char in new_body
    ):
        raise ProtobufError(
            "Binary output needs a protobuf/gRPC Content-Type (e.g. "
            "application/x-protobuf) so Lanius sends it byte for byte"
        )
    return _with_content_length(head, new_body)


def _with_content_length(head: str, body: str) -> str:
    pattern = re.compile(r"^(content-length:[ \t]*)\d+[ \t]*(?=\r?$)", re.IGNORECASE | re.MULTILINE)
    if pattern.search(head):
        head = pattern.sub(lambda m: f"{m.group(1)}{len(body.encode('latin-1', 'replace'))}", head, count=1)
    return head + body


# --------------------------------------------------------------------------
# Codec


def decode_text(value: str) -> str:
    stripped = value.strip()
    try:
        data = bytes.fromhex(stripped.replace(" ", "")) if re.fullmatch(r"(?:[0-9a-fA-F]{2}\s*)+", stripped) else _decode_b64(stripped)[0]
        return "\n".join(fields_to_text(parse_message(data))) + "\n"
    except ProtobufError as exc:
        raise ValueError(str(exc)) from exc


def encode_text(value: str) -> str:
    try:
        fields = text_to_fields(list(enumerate(value.replace("\r\n", "\n").split("\n"), 1)))
    except ProtobufError as exc:
        raise ValueError(str(exc)) from exc
    return base64.b64encode(encode_message(fields)).decode("ascii")


def activate(context: Any) -> None:
    context.message_views.register(
        "protobuf", "Protobuf", render_view, apply=apply_edit,
        description="Decode and edit protobuf, gRPC, and base64 protobuf bodies.",
    )
    context.codecs.register(
        "protobuf", "Protobuf (base64 or hex)", encode=encode_text, decode=decode_text,
    )
    context.log.info("Protobuf Editor registered")
