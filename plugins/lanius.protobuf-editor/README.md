# Protobuf Editor

Schema-less Protocol Buffers viewer/editor for Lanius, in the spirit of Burp's
Protobuf Decoder extensions. Requires Lanius SDK 1.7 (message-view tabs).

The **Protobuf** tab appears beside Pretty/Raw/Hex and recognises:

- raw bodies with a protobuf Content-Type (`application/x-protobuf`,
  `application/protobuf`, `application/vnd.google.protobuf`, `*+protobuf`);
- gRPC and gRPC-web frames (`application/grpc*`), including `grpc-web-text`
  base64 and `grpc-encoding: gzip` frames, one `=== FRAME n ===` section each;
- bodies that are entirely base64 / base64url and decode to valid protobuf.

Without a `.proto`, types are inferred; a length-delimited field is shown as a
`string` when it is printable UTF-8, else a nested `message` when it parses
cleanly, else `bytes`. Text lines look like:

```
1: varint 150
2: string "testing"
3: message {
  1: varint 1
}
4: fixed32 1065353216   # float 1
5: bytes hex:00ff
```

Edit, add, remove, or reorder lines in Replay, Fuzzer, or Intercept; the tab
re-encodes the payload and fixes gRPC frame lengths, base64, and
`Content-Length`. An unedited view returns the original message untouched.
A **Protobuf (base64 or hex)** codec is also available in the Decoder.

## Byte-exactness

Lanius's Raw editor is text. Binary protobuf/gRPC bodies only survive a Replay
round trip when Lanius reads them one byte per character, which it does for
protobuf/gRPC Content-Types from the release that adds that rule to
`app/charset.py`. On an older Lanius, use base64-wrapped payloads. Binary output
under any other Content-Type is refused rather than silently corrupted.

Not supported: groups (wire types 3/4), `.proto` field names, packed-repeated
detection (shown as `bytes`), and non-gzip gRPC compression (the frame is shown
as opaque hex). The plugin sends no requests and uses only the standard library.
