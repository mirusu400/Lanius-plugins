# Security Headers

Passive checks for missing browser security headers. The first release checks
HTML responses for Content-Security-Policy, HTTPS responses for
Strict-Transport-Security, and all successful responses for
X-Content-Type-Options.

The design is inspired by PortSwigger's passive scan check worked example, but
is an independent implementation against the Lanius SDK.

