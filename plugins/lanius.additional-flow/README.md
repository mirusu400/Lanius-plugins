# Additional Flow

Collect related HTTP request/response pairs into an ordered investigation Flow.
The **Flow** workspace tab, **Add to Flow…** context action, and HTTP MCP tools
share the same project data. Version **1.1.0** requires **Lanius SDK 1.5**. The Flow tab uses the main
application's shared controls, palette, and typography, and follows theme/font
changes live without replacing unsaved drafts. Version 1.0.0 remains available
for SDK 1.4 hosts.

## Use

Install and enable the plugin. Open **Flow** and create a collection, or
right-click a captured exchange in Proxy History, Target, or request/response
details and choose **Plugin actions → Add to Flow…**. Search for an existing
Flow by title or ID, or create one in the picker. Request and response menus
always save the complete captured pair.

Each Flow has a generated ID, title, investigation notes, and an ordered list
of evidence. Select a step to inspect the saved messages, add step notes,
move it up/down, or remove it. You can also paste captured exchange IDs into
the workspace to add evidence in bulk. The same exchange can belong to several
Flows. Repeated additions to one Flow skip existing IDs without replacing their
snapshot or notes. Refresh loads the current saved state; the list refreshes
periodically after agent edits without replacing editor drafts.

## MCP

Use the engine's existing **HTTP MCP** connection from Settings → AI agents.
The standalone stdio server does not load plugin tools. Tool names are prefixed
with `lanius.additional-flow.`:

- `create_flow(title, description="", exchange_ids=null)`
- `list_flows(query="", offset=0, limit=50)`
- `get_flow(collection_id, offset=0, limit=50, reveal_secrets=false)`
- `add_exchanges(collection_id, exchange_ids, note="")`
- `get_exchange(collection_id, exchange_id, reveal_secrets=false)`
- `update_flow(collection_id, title=null, description=null)`
- `update_exchange(collection_id, exchange_id, note="", position=null)`
- `remove_exchanges(collection_id, exchange_ids)`
- `delete_flow(collection_id)`

Example agent call after investigating with Lanius's built-in History/Replay tools:

```json
{
  "title": "Account ownership bypass",
  "description": "Baseline login, changed account ID, then verified access.",
  "exchange_ids": ["captured-login-id", "captured-probe-id", "captured-verification-id"]
}
```

`collection_id` identifies a saved Flow; `exchange_id` is the existing captured
HTTP `flow_id`. IDs must be supplied explicitly; the plugin does not infer
related traffic. `position` is zero-based. Additions are all-or-nothing: an
unknown ID or storage error leaves both metadata and snapshots unchanged.

Default MCP evidence reads mask sensitive headers, query strings, and bodies.
`reveal_secrets=true` explicitly returns captured headers, query strings and
bounded text previews. Flow titles, descriptions and step notes are authored
data and are returned as written. The UI intentionally displays captured
secrets as the regular HTTP inspector does. Raw binary bodies stay local and
can be downloaded from the UI. No separate MCP server or outbound connection
is created.

## Persistence and limits

Snapshots store original headers and exact captured body bytes, including
binary and compressed data, as chunked JSON in project plugin storage. They
survive History deletion, plugin reload, application restart, and project
export/import. Removing a step or Flow deletes its saved snapshots, leaving
History and other Flows intact.

- Up to 500 Flows per project and 500 exchanges per Flow.
- Up to 100 IDs and 16 MiB of combined captured bodies per addition/create call.
  Larger batches fail explicitly; add smaller groups separately.
- Message text previews cover the first 16 KiB of each body without
  decompression. Download preserves all saved bytes.
- Bodies omitted by Lanius capture settings cannot be recovered; their omission
  is displayed. Pending/failed exchanges retain an explicit absent-response flag.
  A snapshot records the state at addition time and does not update automatically.
- Notes are limited to 20,000 characters per Flow and 2,000 per step. Metadata
  retains the SDK's 1 MiB per-value bound; exceeding it fails atomically.
- Disabling or suspending the plugin removes its tabs, menus and MCP tools.
  Stored project data remains. Lockdown Mode and safe mode suspend execution.

Permissions: `actions.invoke` for the owned UI bridge, `clipboard.write` for
copying Flow IDs, and `ui.downloads` for
local captured-body downloads. The trusted Python backend opens no sockets.
