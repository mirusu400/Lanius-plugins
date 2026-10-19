"""Ordered, project-owned evidence collections shared by the UI and HTTP MCP."""
from __future__ import annotations

import base64
import hashlib
import json
import re
import threading
import uuid
from datetime import datetime, timezone
from typing import Any

from lanius_sdk import PluginContext

MAX_FLOWS = 500
MAX_EXCHANGES = 500
MAX_BATCH = 100
MAX_CAPTURE_BYTES = 16 * 1024 * 1024
CHUNK = 128 * 1024
SECRET = re.compile(
    r"authorization|cookie|api[-_]?key|token|secret|password|passwd|credential|signature"
    r"|(?:^|[-_])(?:auth|key|session|sid|otp|sig|validation)(?:$|[-_])", re.I,
)


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def text(value: str, name: str, limit: int, *, required: bool = False) -> str:
    if not isinstance(value, str) or len(value) > limit or (required and not value.strip()):
        raise ValueError(f"{name} must be {'non-empty ' if required else ''}text of at most {limit} characters")
    return value.strip() if required else value


class Flows:
    def __init__(self, context: PluginContext):
        self.context = context
        self.lock = threading.RLock()

    def _key(self, collection_id: str) -> str:
        if not isinstance(collection_id, str) or not re.fullmatch(r"[a-f0-9]{32}", collection_id):
            raise ValueError("Invalid Flow ID")
        return f"flow.{collection_id}"

    def _flow(self, collection_id: str) -> dict:
        flow = self.context.storage.get(self._key(collection_id))
        if flow is None:
            raise ValueError("Flow not found")
        return flow

    @staticmethod
    def _prefix(collection_id: str, exchange_id: str) -> str:
        return f"exchange.{collection_id}.{hashlib.sha256(exchange_id.encode()).hexdigest()}"

    def _snapshot(self, collection_id: str, entry: dict) -> dict:
        prefix = self._prefix(collection_id, entry['exchange_id'])
        chunks = [self.context.storage.get(f"{prefix}.{index}") for index in range(entry['chunks'])]
        if any(chunk is None for chunk in chunks):
            raise ValueError("Saved exchange snapshot is incomplete")
        return json.loads(''.join(chunks))

    @staticmethod
    def _ids(exchange_ids: list[str] | None) -> list[str]:
        if exchange_ids is None:
            return []
        if not isinstance(exchange_ids, list) or len(exchange_ids) > MAX_BATCH:
            raise ValueError(f"Provide at most {MAX_BATCH} exchange IDs per call")
        values = [text(value, 'Exchange ID', 128, required=True) for value in exchange_ids]
        return list(dict.fromkeys(values))

    def _capture(self, flow: dict, exchange_ids: list[str], note: str, source: str) -> tuple[dict, int]:
        existing = {entry['exchange_id'] for entry in flow['entries']}
        additions = [value for value in self._ids(exchange_ids) if value not in existing]
        if len(flow['entries']) + len(additions) > MAX_EXCHANGES:
            raise ValueError(f"A Flow supports at most {MAX_EXCHANGES} exchanges")
        values = {}
        total = 0
        for exchange_id in additions:
            # Explicit selection is allowed outside scope, as in History itself.
            snapshot = dict(self.context.flows.get(exchange_id, in_scope_only=False))
            total += snapshot['request_captured_bytes'] + snapshot['response_captured_bytes']
            if total > MAX_CAPTURE_BYTES:
                raise ValueError("Selected bodies exceed 16 MiB; add exchanges in smaller batches")
            encoded = json.dumps(snapshot, ensure_ascii=True, separators=(',', ':'))
            chunks = [encoded[start:start + CHUNK] for start in range(0, len(encoded), CHUNK)]
            prefix = self._prefix(flow['collection_id'], exchange_id)
            values.update({f"{prefix}.{index}": chunk for index, chunk in enumerate(chunks)})
            host = snapshot.get('host') or ''
            port = snapshot.get('port')
            scheme = snapshot.get('scheme') or 'http'
            if ':' in host and not host.startswith('['):
                host = f'[{host}]'
            authority = host if port is None or (scheme, port) in {('http', 80), ('https', 443)} else f'{host}:{port}'
            url = f"{scheme}://{authority}{snapshot.get('path') or '/'}"
            if snapshot.get('query'):
                url += '?' + snapshot['query']
            flow['entries'].append({
                'exchange_id': exchange_id, 'chunks': len(chunks), 'note': note,
                'added_at': now(), 'source': source,
                'method': snapshot.get('method') or 'GET', 'url': url[:1024],
                'status_code': snapshot.get('status_code'),
                'response_present': snapshot['response_present'],
                'body_omitted': bool(snapshot.get('request_body_omitted') or snapshot.get('response_body_omitted')),
            })
        return values, len(additions)

    @staticmethod
    def _public(flow: dict) -> dict:
        return {**{key: value for key, value in flow.items() if key != 'entries'},
                'count': len(flow['entries'])}

    def list_flows(self, query: str = '', offset: int = 0, limit: int = 50) -> dict:
        """Search saved Flow titles/descriptions. Returns metadata without captured bodies."""
        text(query, 'Search', 500)
        if type(offset) is not int or offset < 0 or type(limit) is not int or not 1 <= limit <= 100:
            raise ValueError('Invalid pagination (limit 1–100)')
        with self.lock:
            flows = [self._flow(value) for value in self.context.storage.get('index', [])]
            matches = [{**self._public(flow), 'description': flow['description'][:240]} for flow in flows
                       if query.casefold() in (flow['title'] + ' ' + flow['description'] + ' ' + flow['collection_id']).casefold()]
            matches.sort(key=lambda item: item['updated_at'], reverse=True)
            return {'items': matches[offset:offset + limit], 'total': len(matches),
                    'has_more': offset + limit < len(matches)}

    def create_flow(self, title: str, description: str = '', exchange_ids: list[str] | None = None) -> dict:
        """Create a Flow and atomically save ordered exchange IDs as evidence snapshots."""
        return self._create(title, description, exchange_ids, 'mcp')

    def _create(self, title: str, description: str, exchange_ids: list[str] | None, source: str) -> dict:
        text(title, 'Title', 200, required=True)
        text(description, 'Description', 20000)
        ids = self._ids(exchange_ids)
        with self.lock:
            index = self.context.storage.get('index', [])
            if len(index) >= MAX_FLOWS:
                raise ValueError(f"At most {MAX_FLOWS} Flows are supported")
            collection_id = uuid.uuid4().hex
            flow = {'collection_id': collection_id, 'title': title.strip(), 'description': description,
                    'created_at': now(), 'updated_at': now(), 'entries': []}
            values, _ = self._capture(flow, ids, '', source)
            values.update({'index': [*index, collection_id], self._key(collection_id): flow})
            self.context.storage.batch(values)
            return self._public(flow)

    def get_flow(self, collection_id: str, offset: int = 0, limit: int = 50, reveal_secrets: bool = False) -> dict:
        """Read a Flow's description, ordered evidence summaries and notes (paged)."""
        if type(offset) is not int or offset < 0 or type(limit) is not int or not 1 <= limit <= 50:
            raise ValueError('Invalid pagination (limit 1–50)')
        with self.lock:
            flow = self._flow(collection_id)
            return {**self._public(flow), 'entries': [
                {key: (value.split('?')[0] + '?<redacted>' if key == 'url' and '?' in value and not reveal_secrets else value)
                 for key, value in entry.items() if key != 'chunks'}
                for entry in flow['entries'][offset:offset + limit]],
                'has_more': offset + limit < len(flow['entries'])}

    def add_exchanges(self, collection_id: str, exchange_ids: list[str], note: str = '') -> dict:
        """Atomically append explicitly selected exchanges. Existing IDs are skipped; order is retained."""
        return self._add(collection_id, exchange_ids, note, 'mcp')

    def _add(self, collection_id: str, exchange_ids: list[str], note: str, source: str) -> dict:
        text(note, 'Note', 2000)
        with self.lock:
            ids = self._ids(exchange_ids)
            if not ids:
                raise ValueError("Provide at least one exchange ID")
            flow = self._flow(collection_id)
            values, added = self._capture(flow, ids, note, source)
            flow['updated_at'] = now()
            values[self._key(collection_id)] = flow
            self.context.storage.batch(values)
            return {**self._public(flow), 'added': added}

    def update_flow(self, collection_id: str, title: str | None = None, description: str | None = None) -> dict:
        """Update a saved Flow's title or investigation notes."""
        with self.lock:
            flow = self._flow(collection_id)
            if title is not None:
                flow['title'] = text(title, 'Title', 200, required=True)
            if description is not None:
                flow['description'] = text(description, 'Description', 20000)
            flow['updated_at'] = now()
            self.context.storage.batch({self._key(collection_id): flow})
            return self._public(flow)

    def update_exchange(self, collection_id: str, exchange_id: str, note: str = '', position: int | None = None) -> dict:
        """Update an evidence note and optionally move the exchange to a zero-based position."""
        text(note, 'Note', 2000)
        with self.lock:
            flow = self._flow(collection_id)
            entry = next((entry for entry in flow['entries'] if entry['exchange_id'] == exchange_id), None)
            if entry is None:
                raise ValueError('Exchange not found in Flow')
            if position is not None and (type(position) is not int or not 0 <= position < len(flow['entries'])):
                raise ValueError('Position is outside the Flow')
            entry['note'] = note
            if position is not None:
                flow['entries'].remove(entry)
                flow['entries'].insert(position, entry)
            flow['updated_at'] = now()
            self.context.storage.batch({self._key(collection_id): flow})
            return self._public(flow)

    def remove_exchanges(self, collection_id: str, exchange_ids: list[str]) -> dict:
        """Remove membership and saved snapshots from this Flow only; History is untouched."""
        ids = self._ids(exchange_ids)
        with self.lock:
            flow = self._flow(collection_id)
            removed = [entry for entry in flow['entries'] if entry['exchange_id'] in ids]
            delete = [f"{self._prefix(collection_id, entry['exchange_id'])}.{index}"
                      for entry in removed for index in range(entry['chunks'])]
            flow['entries'] = [entry for entry in flow['entries'] if entry['exchange_id'] not in ids]
            flow['updated_at'] = now()
            self.context.storage.batch({self._key(collection_id): flow}, delete=delete)
            return {**self._public(flow), 'removed': len(removed)}

    def delete_flow(self, collection_id: str) -> dict:
        """Delete a Flow and its saved snapshots. Captured History is untouched."""
        with self.lock:
            flow = self._flow(collection_id)
            delete = [self._key(collection_id)] + [
                f"{self._prefix(collection_id, entry['exchange_id'])}.{index}"
                for entry in flow['entries'] for index in range(entry['chunks'])]
            self.context.storage.batch({'index': [value for value in self.context.storage.get('index', [])
                                                  if value != collection_id]}, delete=delete)
            return {'deleted': collection_id}

    def get_exchange(self, collection_id: str, exchange_id: str, reveal_secrets: bool = False) -> dict:
        """Read saved evidence. Sensitive headers are masked; bodies require explicit reveal_secrets=true.

        Text previews cover the first 16 KiB of each captured body. Binary/compressed originals
        remain saved locally. Without reveal_secrets, request query strings are also hidden.
        """
        with self.lock:
            flow = self._flow(collection_id)
            entry = next((entry for entry in flow['entries'] if entry['exchange_id'] == exchange_id), None)
            if entry is None:
                raise ValueError('Exchange not found in Flow')
            snapshot = self._snapshot(collection_id, entry)
            snapshot.pop('request_body_base64', None)
            snapshot.pop('response_body_base64', None)
            if not reveal_secrets:
                snapshot['query'] = '<redacted>' if snapshot.get('query') else ''
                for side in ('request', 'response'):
                    snapshot[f'{side}_headers'] = [[name, '<redacted>' if SECRET.search(name) else value]
                                                    for name, value in snapshot.get(f'{side}_headers') or []]
                    snapshot[f'{side}_body'] = '<redacted>'
            return {'exchange_id': exchange_id, 'note': entry['note'], 'snapshot': snapshot,
                    'redacted': not reveal_secrets}

    def body_chunk(self, collection_id: str, exchange_id: str, side: str, offset: int = 0) -> dict:
        if side not in ('request', 'response') or type(offset) is not int or offset < 0:
            raise ValueError('Invalid body side or byte offset')
        with self.lock:
            flow = self._flow(collection_id)
            entry = next((entry for entry in flow['entries'] if entry['exchange_id'] == exchange_id), None)
            if entry is None:
                raise ValueError('Exchange not found in Flow')
            snapshot = self._snapshot(collection_id, entry)
            raw = base64.b64decode(snapshot.get(f'{side}_body_base64') or '')
            chunk = raw[offset:offset + 65536]
            return {'base64': base64.b64encode(chunk).decode(), 'offset': offset,
                    'next_offset': offset + len(chunk), 'total': len(raw),
                    'has_more': offset + len(chunk) < len(raw)}


def activate(context: PluginContext) -> None:
    service = Flows(context)
    def choose(event):
        ids = event.get('flow_ids') or [event.get('flow_id')]
        ids = service._ids(ids)
        if not ids:
            raise ValueError('Select a captured HTTP exchange')
        return {'ui': {'view': 'flow', 'mode': 'dialog', 'context': {'exchange_ids': ids}}}

    context.actions.register('add-to-flow', 'Add to Flow…', choose,
                             locations=('history', 'flow', 'request', 'response'))
    def ui(event):
        operation = event.get('operation')
        args = event.get('args') or {}
        operations = {
            'list': service.list_flows, 'get': service.get_flow, 'update': service.update_flow,
            'update_exchange': service.update_exchange, 'remove': service.remove_exchanges,
            'delete': service.delete_flow, 'exchange': service.get_exchange, 'body': service.body_chunk,
            'create': lambda **kw: service._create(source='manual', **kw),
            'add': lambda **kw: service._add(source='manual', **kw),
        }
        if operation not in operations:
            raise ValueError('Unknown Flow operation')
        return operations[operation](**args)
    context.actions.register('ui', 'Flow workspace', ui, locations=('plugin',))
    for name in ('list_flows', 'get_flow', 'get_exchange', 'create_flow', 'add_exchanges',
                 'update_flow', 'update_exchange', 'remove_exchanges', 'delete_flow'):
        context.mcp.register_tool(name, getattr(service, name), read_only=name.startswith(('list_', 'get_')))
    context.log.info('Additional Flow workspace and MCP tools registered')
