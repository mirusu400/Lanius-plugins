const plugin = 'lanius.parameter-analyzer';
const MAX_FLOWS = 2000;
let requestId = 0;
let generation = 0;
let groups = new Map();
const pending = new Map();
const $ = (selector) => document.querySelector(selector);

function rpc(method, params = {}) {
  const id = `parameter-analyzer-${++requestId}`;
  return new Promise((resolve, reject) => {
    pending.set(id, { resolve, reject });
    parent.postMessage({ type: 'lanius.request', plugin, id, method, params }, '*');
  });
}

window.addEventListener('message', (event) => {
  const message = event.data;
  if (!message || message.type !== 'lanius.response') return;
  const handler = pending.get(message.id);
  if (!handler) return;
  pending.delete(message.id);
  if (message.error) handler.reject(new Error(message.error));
  else handler.resolve(message.result);
});

function action(name, context = {}) {
  return rpc('actions.invoke', {
    action: `${plugin}.${name}`,
    context: { location: 'plugin', ...context },
  });
}

function addObservation(item) {
  const key = JSON.stringify([item.host, item.kind, item.name]);
  let group = groups.get(key);
  if (!group) {
    group = {
      host: item.host, kind: item.kind, name: item.name,
      flows: new Set(), paths: new Set(), values: new Set(), reflected: new Set(),
      formats: new Set(), example: item.example, flowId: item.flow_id, secret: item.secret,
    };
    groups.set(key, group);
  }
  group.flows.add(item.flow_id);
  group.paths.add(item.path_hash);
  group.values.add(item.value_hash);
  if (item.reflected) group.reflected.add(item.flow_id);
  group.formats.add(item.format);
  if (item.secret) {
    group.secret = true;
    group.example = '<redacted>';
  }
}

function cell(row, value, className = '') {
  const element = document.createElement('td');
  element.textContent = String(value);
  if (className) element.className = className;
  row.appendChild(element);
}

function render() {
  const filter = $('#search').value.trim().toLowerCase();
  const body = $('#rows');
  body.replaceChildren();
  const matches = [...groups.values()].filter((group) =>
    `${group.host} ${group.kind} ${group.name}`.toLowerCase().includes(filter));
  matches.sort((left, right) =>
    right.reflected.size - left.reflected.size ||
    right.flows.size - left.flows.size ||
    left.name.localeCompare(right.name));
  for (const group of matches.slice(0, 500)) {
    const row = document.createElement('tr');
    cell(row, group.host);
    cell(row, group.kind);
    cell(row, group.name, group.secret ? 'secret' : '');
    cell(row, group.flows.size, 'number');
    cell(row, group.paths.size, 'number');
    cell(row, group.values.size, 'number');
    cell(row, `${Math.round(group.reflected.size / group.flows.size * 100)}%`, 'number');
    cell(row, [...group.formats].slice(0, 3).join(', '));
    cell(row, group.example);
    cell(row, group.flowId, 'muted');
    body.appendChild(row);
  }
  return { matches: matches.length, displayed: Math.min(matches.length, 500) };
}

async function analyze() {
  const current = ++generation;
  groups = new Map();
  $('#analyze').disabled = true;
  $('#cancel').disabled = false;
  $('#error').textContent = '';
  let cursor = null;
  let anchor = null;
  let flows = 0;
  let analyzedFlows = 0;
  try {
    while (current === generation && flows < MAX_FLOWS) {
      const page = await action('analyze-page', { cursor, anchor });
      if (current !== generation) break;
      anchor = page.anchor;
      cursor = page.next_cursor;
      flows += page.flows;
      analyzedFlows += page.analyzed_flows;
      for (const item of page.observations) addObservation(item);
      const shown = render();
      $('#status').textContent = `${analyzedFlows} captured flows analyzed · ${flows} History items checked · ${groups.size} parameter groups · ${shown.displayed} shown`;
      if (!page.has_more || !cursor || page.flows === 0) break;
    }
    if (current === generation && flows >= MAX_FLOWS) {
      $('#status').textContent += ` · stopped at ${MAX_FLOWS} flows`;
    }
  } catch (error) {
    if (current === generation) $('#error').textContent = String(error);
  } finally {
    if (current === generation) {
      $('#analyze').disabled = false;
      $('#cancel').disabled = true;
    }
  }
}

$('#analyze').addEventListener('click', () => void analyze());
$('#cancel').addEventListener('click', () => {
  generation += 1;
  $('#analyze').disabled = false;
  $('#cancel').disabled = true;
  $('#status').textContent += ' · cancelled';
});
$('#search').addEventListener('input', () => { render(); });
$('#mine').addEventListener('click', async () => {
  const flowId = $('#flow-id').value.trim();
  if (!flowId) {
    $('#mine-status').textContent = 'Enter a captured flow ID.';
    return;
  }
  $('#mine').disabled = true;
  try {
    const job = await action('mine', { flow_id: flowId });
    $('#mine-status').textContent = `Started job ${job.id} for ${flowId}. View progress and findings in Issues.`;
  } catch (error) {
    $('#mine-status').textContent = String(error);
  } finally {
    $('#mine').disabled = false;
  }
});
