# Security policy

Plugin packages execute trusted Python in the Lanius engine process. Review the
source before enabling a plugin and only install packages whose signing key you
trust.

Report vulnerabilities privately through this repository's GitHub Security
Advisories. Include the plugin ID, affected versions, impact, and reproduction
steps. Compromised releases are retained for auditability and added to the
signed revocation list so Lanius refuses to load them.

