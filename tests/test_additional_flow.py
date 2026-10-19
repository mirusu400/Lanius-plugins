from __future__ import annotations

import base64
import concurrent.futures
import json
from types import SimpleNamespace

import pytest

from app.db.store import FlowRecord, FlowStore
from app.mcp import build_server
from app.plugin_registry import ContributionRegistry
from lanius_sdk import PluginApiError

from conftest import load_plugin

PLUGIN = 'lanius.additional-flow'


@pytest.fixture()
def runtime(tmp_path):
    store = FlowStore(tmp_path / 'project.sqlite')
    for index in range(6):
        store.upsert(FlowRecord(
            id=f'e{index}', scheme='https', host='example.test', port=443,
            method='POST', path='/account', query='token=secret',
            request_headers=[('Authorization', 'Bearer secret'), ('X-Custom-Password', 'private-value'), ('Content-Type', 'application/octet-stream')],
            request_body=b'\x00\xff\xfe' * 90000 if index == 0 else b'request',
            response_headers=[('Set-Cookie', 'session=secret'), ('X-Trace', 'trace')],
            response_body=b'response\x00\xff', status_code=200,
        ))
    registry = ContributionRegistry(store)
    context = registry.context(PLUGIN)
    plugin = load_plugin(PLUGIN)
    service = plugin.Flows(context)
    plugin.activate(context)
    yield service, registry, store
    registry.dispose_owner(PLUGIN)
    store.close()


def test_order_deduplication_notes_and_independent_membership(runtime):
    service, _, _ = runtime
    flow = service.create_flow('Account takeover', exchange_ids=['e2', 'e1', 'e2'])
    cid = flow['collection_id']
    assert flow['count'] == 2
    assert service.add_exchanges(cid, ['e1', 'e0'])['added'] == 1
    service.update_exchange(cid, 'e0', 'Proof of access', 0)
    evidence = service.get_flow(cid)
    assert [entry['exchange_id'] for entry in evidence['entries']] == ['e0', 'e2', 'e1']
    assert evidence['entries'][0]['note'] == 'Proof of access'
    assert 'secret' not in evidence['entries'][0]['url']
    second = service.create_flow('Other investigation', exchange_ids=['e0'])['collection_id']
    service.remove_exchanges(cid, ['e0'])
    assert service.get_exchange(second, 'e0')['snapshot']['status_code'] == 200


def test_binary_snapshots_survive_history_deletion_and_restart(runtime):
    service, registry, store = runtime
    cid = service.create_flow('Binary evidence', exchange_ids=['e0'])['collection_id']
    expected = store.get('e0').request_body
    store.delete('e0')
    registry.dispose_owner(PLUGIN)
    reopened = FlowStore(store.path)
    restored = load_plugin(PLUGIN).Flows(ContributionRegistry(reopened).context(PLUGIN))
    parts = []
    offset = 0
    while True:
        chunk = restored.body_chunk(cid, 'e0', 'request', offset)
        parts.append(base64.b64decode(chunk['base64']))
        offset = chunk['next_offset']
        if not chunk['has_more']:
            break
    assert b''.join(parts) == expected
    assert restored.get_exchange(cid, 'e0', True)['snapshot']['request_preview_truncated']
    assert any(PLUGIN in key for key in store.all_settings())
    imported = FlowStore(store.path + '.imported')
    imported.import_project({'settings': store.all_settings()})
    imported_service = load_plugin(PLUGIN).Flows(ContributionRegistry(imported).context(PLUGIN))
    assert imported_service.get_flow(cid)['count'] == 1
    assert imported_service.body_chunk(cid, 'e0', 'response')['base64'] == base64.b64encode(b'response\x00\xff').decode()
    imported.close()
    reopened.close()


def test_atomic_missing_id_and_storage_failure(runtime):
    service, _, store = runtime
    cid = service.create_flow('Evidence')['collection_id']
    before = service.context.storage.get('index')
    with pytest.raises(PluginApiError, match='not found'):
        service.add_exchanges(cid, ['e0', 'missing'])
    assert service.get_flow(cid)['count'] == 0
    assert service.context.storage.get('index') == before
    # A database failure rolls back snapshot chunks as well as collection metadata.
    store._conn.execute("CREATE TRIGGER reject_flow BEFORE INSERT ON settings WHEN NEW.key LIKE '%/flow.%' BEGIN SELECT RAISE(ABORT, 'simulated failure'); END")
    with pytest.raises(Exception, match='simulated failure'):
        service.add_exchanges(cid, ['e0'])
    assert service.get_flow(cid)['count'] == 0
    assert store._conn.execute("SELECT count(*) FROM settings WHERE key LIKE '%/exchange.%'").fetchone()[0] == 0


def test_concurrent_ui_mcp_updates_do_not_lose_entries(runtime):
    service, _, _ = runtime
    cid = service.create_flow('Concurrent')['collection_id']
    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
        list(pool.map(lambda i: service.add_exchanges(cid, [f'e{i}']), range(6)))
    assert service.get_flow(cid)['count'] == 6
    assert len({item['exchange_id'] for item in service.get_flow(cid)['entries']}) == 6


def test_delete_cleans_chunks_without_deleting_history(runtime):
    service, _, store = runtime
    cid = service.create_flow('Delete me', exchange_ids=['e0', 'e1'])['collection_id']
    service.delete_flow(cid)
    assert service.list_flows()['total'] == 0
    assert store.get('e0') is not None
    assert store._conn.execute("SELECT count(*) FROM settings WHERE key LIKE '%/exchange.%'").fetchone()[0] == 0


def test_redaction_and_explicit_body_reveal(runtime):
    service, _, _ = runtime
    cid = service.create_flow('Secrets', exchange_ids=['e1'])['collection_id']
    masked = json.dumps(service.get_exchange(cid, 'e1'))
    assert 'Bearer secret' not in masked
    assert 'private-value' not in masked
    assert 'session=secret' not in masked
    assert 'request"' not in masked
    assert 'token=secret' not in masked
    revealed = service.get_exchange(cid, 'e1', True)['snapshot']
    assert revealed['request_headers'][0][1] == 'Bearer secret'
    assert revealed['request_body'] == 'request'
    assert 'request_body_base64' not in revealed


def test_validation_and_empty_or_omitted_response(runtime):
    service, _, store = runtime
    with pytest.raises(ValueError, match='Title'):
        service.create_flow(' ')
    cid = service.create_flow('Validation')['collection_id']
    for ids in [['e1'] * 101, [None], 'e1']:
        with pytest.raises(ValueError):
            service.add_exchanges(cid, ids)
    store.upsert(FlowRecord(id='incomplete', request_body_omitted=True))
    service.add_exchanges(cid, ['incomplete'])
    snapshot = service.get_exchange(cid, 'incomplete', True)['snapshot']
    assert snapshot['request_body_omitted'] is True
    assert snapshot['response_present'] is False
    with pytest.raises(ValueError, match='Position'):
        service.update_exchange(cid, 'incomplete', position=7)
    with pytest.raises(ValueError, match='pagination'):
        service.get_flow(cid, limit=10000)


@pytest.mark.asyncio
async def test_ui_menu_and_mcp_use_same_project_data(runtime):
    _, registry, store = runtime
    selected = await registry.invoke_action(PLUGIN + '.add-to-flow', {'location': 'response', 'flow_id': 'e1'})
    assert selected == {'ui': {'view': 'flow', 'mode': 'dialog', 'context': {'exchange_ids': ['e1']}}}
    created = await registry.invoke_action(PLUGIN + '.ui', {'location': 'plugin', 'operation': 'create', 'args': {
        'title': 'Manual finding', 'description': 'Evidence', 'exchange_ids': ['e1'],
    }})
    engine = SimpleNamespace(plugins=SimpleNamespace(registry=registry), broker=None)
    server = build_server(store, engine)
    tools = {tool.name: tool for tool in await server.list_tools()}
    assert len([name for name in tools if name.startswith(PLUGIN + '.')]) == 9
    assert tools[PLUGIN + '.get_flow'].annotations.read_only_hint
    assert not tools[PLUGIN + '.add_exchanges'].annotations.read_only_hint
    def payload(result):
        return result.structured_content or json.loads(result.content[0].text)
    result = payload(await server.call_tool(PLUGIN + '.add_exchanges', {
        'collection_id': created['collection_id'], 'exchange_ids': ['e2', 'e3'], 'note': 'Agent evidence',
    }))
    assert result['added'] == 2
    read = await registry.invoke_action(PLUGIN + '.ui', {'location': 'plugin', 'operation': 'get', 'args': {
        'collection_id': created['collection_id'],
    }})
    assert [entry['source'] for entry in read['entries']] == ['manual', 'mcp', 'mcp']
    registry.dispose_owner(PLUGIN)
    assert not any(tool.name.startswith(PLUGIN + '.') for tool in await server.list_tools())
    await server.close_plugin_tools()
