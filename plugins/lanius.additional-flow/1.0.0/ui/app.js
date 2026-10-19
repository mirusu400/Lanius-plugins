const plugin = 'lanius.additional-flow';
const $ = (selector) => document.querySelector(selector);
const pending = new Map();
let requestId = 0;
let collections = [];
let flow = null;
let exchange = null;
let selectedId = null;
let selection = [];
let busy = false;
let listGeneration = 0;
let detailGeneration = 0;
let moreFlows = false;
let listLoaded = false;
let searchTimer;
function rpc(method, params = {}) {
  const id = `flow-${++requestId}`;
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => { pending.delete(id); reject(new Error('The engine did not respond. Refresh and try again.')); }, 35000);
    pending.set(id, { resolve, reject, timer });
    parent.postMessage({ type: 'lanius.request', plugin, id, method, params }, '*');
  });
}
window.addEventListener('message', (event) => {
  if (event.source !== parent || event.data?.type !== 'lanius.response') return;
  const handler = pending.get(event.data.id);
  if (!handler) return;
  pending.delete(event.data.id);
  clearTimeout(handler.timer);
  if (event.data.error) handler.reject(new Error(event.data.error));
  else handler.resolve(event.data.result);
});
const action = (operation, args = {}) => rpc('actions.invoke', {
  action: `${plugin}.ui`, context: { location: 'plugin', operation, args },
});
function status(message, error = false) { $('#status').textContent = message; $('#status').classList.toggle('error', error); }
async function run(work) {
  if (busy) return;
  busy = true;
  const controls = [...document.querySelectorAll('button')];
  const disabled = controls.map((button) => button.disabled);
  controls.forEach((button) => { button.disabled = true; });
  try { await work(); } catch (error) { status(error.message, true); }
  finally { busy = false; controls.forEach((button, index) => { if (button.isConnected) button.disabled = disabled[index]; }); syncMoves(); }
}
function button(label, callback, className = '') {
  const node = document.createElement('button'); node.textContent = label; node.className = className;
  node.addEventListener('click', () => { if (!busy) callback(); }); return node;
}
function renderCollections() {
  const body = $('#collections'); body.replaceChildren();
  for (const item of collections) {
    const node = button('', () => void run(() => openFlow(item.collection_id)), `collection${flow?.collection_id === item.collection_id ? ' active' : ''}`);
    const title = document.createElement('strong'); title.textContent = item.title;
    const count = document.createElement('small'); count.textContent = `${item.count} exchange${item.count === 1 ? '' : 's'} · ${new Date(item.updated_at).toLocaleDateString()}`;
    node.append(title, count); body.append(node);
  }
  if (!collections.length) body.textContent = 'No Flows yet.';
  $('#more-flows').hidden = !moreFlows;
  const picker = $('#picker-list'); picker.replaceChildren();
  for (const item of collections) {
    picker.append(button(`${item.title}  ·  ${item.count} steps`, () => void run(async () => {
      const result = await action('add', { collection_id: item.collection_id, exchange_ids: selection, note: '' });
      status(`Added ${result.added} exchange(s) to ${item.title}.`); await rpc('ui.close');
    })));
  }
  if (!collections.length) picker.textContent = 'No matching Flows. Create one below.';
  if (selection.length && moreFlows) picker.append(button('Load more Flows', () => void run(() => loadCollections(true))));
}
async function loadCollections(append = false) {
  const generation = ++listGeneration;
  const query = (selection.length ? $('#picker-search') : $('#search')).value;
  const page = await action('list', { query, offset: append ? collections.length : 0, limit: 50 });
  if (generation !== listGeneration) return;
  if (!append && listLoaded && JSON.stringify(collections) === JSON.stringify(page.items) && moreFlows === page.has_more) return;
  listLoaded = true;
  collections = append ? [...collections, ...page.items] : page.items;
  moreFlows = page.has_more; renderCollections();
  const current = collections.find((item) => item.collection_id === flow?.collection_id);
  if (current && current.updated_at !== flow.updated_at) status('This Flow changed. Refresh to load saved updates; current drafts are kept.');
}
async function openFlow(id) {
  detailGeneration++;
  const data = await action('get', { collection_id: id, limit: 50, reveal_secrets: true });
  while (data.has_more) {
    const next = await action('get', { collection_id: id, offset: data.entries.length, limit: 50, reveal_secrets: true });
    if (next.updated_at !== data.updated_at) throw new Error('Flow changed while loading. Refresh and try again.');
    data.entries.push(...next.entries); data.has_more = next.has_more;
  }
  flow = data; exchange = null; selectedId = null;
  $('#empty').hidden = true; $('#flow').hidden = false;
  $('#title').value = flow.title; $('#description').value = flow.description;
  $('#flow-id').textContent = flow.collection_id;
  $('#count').textContent = `${flow.count} saved exchange(s)`;
  $('#exchange').hidden = true; $('#detail-empty').hidden = false;
  renderCollections(); renderEntries();
}
function renderEntries() {
  const body = $('#entries'); body.replaceChildren();
  flow.entries.forEach((entry, index) => {
    const node = button('', () => void run(() => openExchange(entry.exchange_id)), `entry${selectedId === entry.exchange_id ? ' active' : ''}`);
    const method = document.createElement('span'); method.className = 'method'; method.textContent = `${index + 1}. ${entry.method}  ${entry.status_code ?? '—'}`;
    const url = document.createElement('span'); url.className = 'url'; url.textContent = entry.url;
    const info = document.createElement('small'); info.textContent = entry.note || `${entry.source} · ${entry.exchange_id}`;
    node.append(method, url, info); body.append(node);
  });
  if (!flow.entries.length) body.textContent = 'Add captured exchanges from a context menu or paste their IDs above.';
}
function message(snapshot, side) {
  const start = side === 'request'
    ? `${snapshot.method || 'GET'} ${snapshot.path || '/'}${snapshot.query ? '?' + snapshot.query : ''} ${snapshot.http_version || 'HTTP/1.1'}`
    : snapshot.response_present ? `${snapshot.http_version || 'HTTP/1.1'} ${snapshot.status_code ?? ''} ${snapshot.reason ?? ''}` : 'No response was captured.';
  const headers = (snapshot[`${side}_headers`] || []).map(([name, value]) => `${name}: ${value}`).join('\n');
  let body = snapshot[`${side}_body`] || '';
  if (snapshot[`${side}_body_omitted`]) body = '[Body was omitted by capture settings.]';
  else if (snapshot[`${side}_preview_truncated`]) body += '\n\n[Preview limited to the first 16 KiB. Download the captured body for all bytes.]';
  return `${start}\n${headers}\n\n${body}`;
}
async function openExchange(id) {
  const generation = ++detailGeneration;
  const data = await action('exchange', { collection_id: flow.collection_id, exchange_id: id, reveal_secrets: true });
  if (generation !== detailGeneration) return;
  selectedId = id; exchange = data;
  $('#exchange').hidden = false; $('#detail-empty').hidden = true;
  $('#detail-title').textContent = `Step ${flow.entries.findIndex((entry) => entry.exchange_id === id) + 1} · ${data.snapshot.method || 'GET'}`;
  $('#note').value = data.note;
  $('#request').textContent = message(data.snapshot, 'request');
  $('#response').textContent = message(data.snapshot, 'response');
  $('#capture-status').textContent = 'Saved independently of History. Previews show captured bytes without decompression; downloads preserve binary and compressed bodies.';
  for (const side of ['request', 'response']) $('#download-' + side).disabled = Boolean(data.snapshot[`${side}_body_omitted`]) || (side === 'response' && !data.snapshot.response_present);
  renderEntries(); syncMoves();
}
function syncMoves() {
  if (!flow || !selectedId) return;
  const index = flow.entries.findIndex((entry) => entry.exchange_id === selectedId);
  $('#up').disabled = index <= 0; $('#down').disabled = index === flow.entries.length - 1;
  if (exchange) for (const side of ['request', 'response']) $('#download-' + side).disabled = Boolean(exchange.snapshot[`${side}_body_omitted`]) || (side === 'response' && !exchange.snapshot.response_present);
}
async function refreshFlow(id = selectedId) {
  const collectionId = flow.collection_id;
  await openFlow(collectionId); if (id && flow.entries.some((entry) => entry.exchange_id === id)) await openExchange(id);
  await loadCollections();
}
async function confirm(title, detail) {
  const dialog = $('#confirm-dialog'); $('#confirm-title').textContent = title; $('#confirm-text').textContent = detail;
  return new Promise((resolve) => { dialog.addEventListener('close', () => resolve(dialog.returnValue === 'confirm'), { once: true }); dialog.showModal(); });
}
$('#refresh').addEventListener('click', () => void run(async () => { await loadCollections(); if (flow && !selection.length) await refreshFlow(); status('Up to date.'); }));
$('#more-flows').addEventListener('click', () => void run(() => loadCollections(true)));
for (const id of ['search', 'picker-search']) $('#' + id).addEventListener('input', () => { clearTimeout(searchTimer); searchTimer = setTimeout(() => { void loadCollections().catch((error) => status(error.message, true)); }, 250); });
$('#new').addEventListener('click', () => { $('#create-dialog').showModal(); $('#new-title').focus(); });
$('#cancel-create').addEventListener('click', () => $('#create-dialog').close());
$('#create-form').addEventListener('submit', (event) => { event.preventDefault(); void run(async () => {
  const data = await action('create', { title: $('#new-title').value, description: $('#new-description').value, exchange_ids: [] });
  $('#create-dialog').close(); $('#create-form').reset(); await loadCollections(); await openFlow(data.collection_id); status('Flow created.');
}); });
$('#picker-create').addEventListener('submit', (event) => { event.preventDefault(); void run(async () => {
  await action('create', { title: $('#picker-title').value, description: '', exchange_ids: selection }); status('Flow created and evidence saved.'); await rpc('ui.close');
}); });
$('#save').addEventListener('click', () => void run(async () => {
  const saved = await action('update', { collection_id: flow.collection_id, title: $('#title').value, description: $('#description').value }); Object.assign(flow, saved); await loadCollections(); status('Flow details saved.');
}));
$('#copy-id').addEventListener('click', () => void run(async () => {
  await rpc('clipboard.write', { text: flow.collection_id }); status('Flow ID copied.');
}));
$('#add-ids').addEventListener('click', () => void run(async () => {
  const ids = $('#exchange-ids').value.split(/[\s,]+/).filter(Boolean);
  if (!ids.length) throw new Error('Enter at least one captured exchange ID.');
  const result = await action('add', { collection_id: flow.collection_id, exchange_ids: ids, note: '' });
  $('#exchange-ids').value = ''; await refreshFlow(); status(`Added ${result.added} exchange(s).`);
}));
$('#save-note').addEventListener('click', () => void run(async () => {
  await action('update_exchange', { collection_id: flow.collection_id, exchange_id: selectedId, note: $('#note').value }); await refreshFlow(); status('Step note saved.');
}));
for (const [id, direction] of [['up', -1], ['down', 1]]) $('#' + id).addEventListener('click', () => void run(async () => {
  const position = flow.entries.findIndex((entry) => entry.exchange_id === selectedId) + direction;
  await action('update_exchange', { collection_id: flow.collection_id, exchange_id: selectedId, note: $('#note').value, position }); await refreshFlow(); status('Evidence order saved.');
}));
$('#remove').addEventListener('click', async () => {
  if (await confirm('Remove this step?', 'Its saved snapshot will be removed from this Flow. Captured History and other Flows are kept.')) void run(async () => {
    await action('remove', { collection_id: flow.collection_id, exchange_ids: [selectedId] }); await refreshFlow(null); status('Step removed.');
  });
});
$('#delete-flow').addEventListener('click', async () => {
  if (await confirm('Delete this Flow?', 'This deletes its notes and saved evidence. Captured History and other Flows are kept.')) void run(async () => {
    await action('delete', { collection_id: flow.collection_id }); flow = null; exchange = null; selectedId = null;
    $('#flow').hidden = true; $('#empty').hidden = false; await loadCollections(); status('Flow deleted.');
  });
});
for (const side of ['request', 'response']) $('#download-' + side).addEventListener('click', () => void run(async () => {
  const parts = []; let offset = 0;
  while (true) {
    const chunk = await action('body', { collection_id: flow.collection_id, exchange_id: selectedId, side, offset });
    const raw = atob(chunk.base64); parts.push(Uint8Array.from(raw, (char) => char.charCodeAt(0)));
    if (!chunk.has_more) break; offset = chunk.next_offset;
  }
  const url = URL.createObjectURL(new Blob(parts, { type: 'application/octet-stream' }));
  const anchor = document.createElement('a'); anchor.href = url; anchor.download = `${selectedId}-${side}.bin`; anchor.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000); status('Captured body downloaded.');
}));
async function init() {
  const context = await rpc('context.get'); selection = context.exchange_ids || [];
  if (selection.length) {
    $('#picker').hidden = false; $('#workspace').hidden = true; $('.toolbar').hidden = true;
    $('#selection-summary').textContent = `${selection.length} selected request/response pair(s). Existing members will be skipped.`;
  }
  await loadCollections();
}
void init().catch((error) => status(error.message, true));
// Visible workspaces update their list after agent changes without replacing editor drafts.
setInterval(() => { if (!busy && !document.hidden && !selection.length) void loadCollections().catch(() => undefined); }, 5000);
