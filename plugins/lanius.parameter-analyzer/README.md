# Parameter Analyzer

An independent Lanius SDK implementation inspired by Burp's
[Paramalyzer](https://jgillam.github.io/burp-paramalyzer/) and
[Param Miner](https://portswigger.net/burp/documentation/desktop/testing-workflow/analyzing/hidden-inputs).

The **Parameter Analyzer** plugin view reads captured, in-scope HTTP History on
demand and excludes Replay-generated probe traffic. It groups query, cookie,
form, JSON, and XML inputs by host and name,
and shows request counts, unique paths and values, value formats, examples, and
possible response reflection. Sensitive-looking examples are masked. Reflection
is a manual testing lead, not an XSS finding. The view analyzes up to 2,000
flows per run, with the SDK capping each body at 65,536 characters, each page at 20
flows, and each flow at 50 inputs.

The **Find hidden parameters** History action, or the view's flow-ID control,
starts an active scan for that captured request. It tries built-in and
user-configured query, header, form, and top-level JSON names. Cookie probes
are opt-in. Two baseline requests are used to suppress unstable responses;
each apparent change is verified with a second probe. Only confirmed response
differences are reported as informational Issues, and the original request
target cannot be changed by the plugin. The scanner's shared request budget,
rate limit, cancellation, Replay routing, and scope egress rules apply.

This plugin never opens its own network connection or contacts an external
service. History analysis sends no requests. Active requests occur only after
the user explicitly starts mining. Lanius suspends plugin execution in
Lockdown Mode.

The plugin requires Lanius SDK 1.2. It does not include Paramalyzer's secrets
hunting, session cookie analysis, or full Param Miner's cache-key tests.
