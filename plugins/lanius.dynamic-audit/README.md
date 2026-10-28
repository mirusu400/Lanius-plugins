# Dynamic Audit

Dynamic Audit adds **Dynamic scan domain** to the context menu of top-level
sites in Lanius Target. It selects recent, distinct captured request shapes for
the chosen site and starts one bounded active-scan job for each selection.

The first release checks query, form, and top-level JSON inputs for:

- new database error signatures with quote/escaped-quote confirmation;
- unique HTML canaries returned without output encoding;
- two harmless arithmetic template expressions evaluated by the server; and
- redirect-like inputs that control `Location` to the reserved
  `lanius.invalid` host.

Only in-scope captured flows are eligible. Replay-generated traffic, failed
responses, sensitive-looking parameter names, and duplicate request shapes are
excluded. GET and HEAD are the default methods; scanning POST, PUT, PATCH, and
DELETE requires an explicit plugin setting because replaying them may repeat a
state change. A fresh unchanged control must still resemble the captured
response before any probes run.

All requests pass through Lanius's active scanner and Replay sender, so project
scope egress, Lockdown Mode, cancellation, job request budgets, and issue
deduplication apply. The plugin does not open its own connection, follow a
redirect, invoke an external binary, send time-delay probes, or attempt command
execution. Raw HTML reflection is reported as a tentative XSS lead rather than
as confirmed script execution.
