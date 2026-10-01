# Lanius Plugins

The source and signed distribution catalogue for official Lanius plugins.
GitHub Pages serves the signed `index.json`, trust bootstrap, and immutable
`.lanius-plugin` archives generated from this repository.

## Catalogue

- Site: <https://mirusu400.github.io/Lanius-plugins/>
- Catalogue: <https://mirusu400.github.io/Lanius-plugins/index.json>
- Trust bootstrap: <https://mirusu400.github.io/Lanius-plugins/bootstrap.json>

The bootstrap contains the pinned catalogue public key and the trusted package
public key. Private Ed25519 keys are stored only as GitHub Actions secrets.
The same public values are versioned in
[`registry/public-keys.json`](registry/public-keys.json) so a secret mismatch
fails the deployment instead of publishing with an unexpected trust root.

## Included plugins

### Security Headers

Passively reports missing Content-Security-Policy,
Strict-Transport-Security, and X-Content-Type-Options headers without sending
new traffic. It is inspired by PortSwigger's
[passive scan check example](https://portswigger.net/burp/documentation/desktop/extend-burp/custom-scan-checks/creating/passive-worked-example).

### Parameter Analyzer

Analyzes captured parameters and response reflection in a plugin view, and
explicitly probes candidate hidden inputs through Lanius's bounded active
scanner. Inspired by [Paramalyzer](https://jgillam.github.io/burp-paramalyzer/)
and [Param Miner](https://portswigger.net/burp/documentation/desktop/testing-workflow/analyzing/hidden-inputs).

### Request Randomizer

Replaces `#RANDOM#`, `#RANDOMNUM#`, and `#UUID#` markers in outgoing requests.
It is inspired by the Burp BApp Store's
[Request Randomizer](https://portswigger.net/bappstore/36d6d7e35dac489b976c2f120ce34ae2).

All three plugins are independent Lanius SDK implementations and make no
outbound connections of their own. Parameter Analyzer's active probes use
the host's explicitly started scanner and Replay path.

## Repository layout

```text
plugins/<plugin-id>/<version>/  immutable source releases
registry/revoked.json           signed revocation inputs
tools/build_catalogue.py        validator, packager, and signer
site/                            static catalogue landing page
dist/                            generated Pages artifact (not committed)
```

Source manifests contain SHA-256 hashes but no signatures. On `main`, GitHub
Actions verifies the plugins against the current Lanius SDK, signs each package
manifest, builds deterministic ZIP archives, signs the catalogue, and deploys
the result to Pages. Before deployment it verifies the existing live catalogue
signature and refuses to remove or alter metadata for a published version.

See [CONTRIBUTING.md](CONTRIBUTING.md) for the release workflow and
[SECURITY.md](SECURITY.md) for vulnerability reporting.
