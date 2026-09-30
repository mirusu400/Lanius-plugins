# Request Randomizer

Replaces explicit placeholders in outgoing requests:

- `#RANDOM#` becomes an alphanumeric value.
- `#RANDOMNUM#` becomes a numeric value.
- `#UUID#` becomes a UUID v4.

Each placeholder kind receives one value per request, so repeated occurrences
stay correlated. The plugin only modifies requests containing these explicit
markers and performs no network access of its own.

The idea is inspired by the Burp BApp Store's Request Randomizer extension,
but this is an independent implementation against the Lanius SDK.

