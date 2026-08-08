# Key Facts

This file contains non-sensitive project facts and configuration references.

Never store passwords, API keys, authentication tokens, private keys, certificates, or other secret values here.

## Synology Package

- Reconfiguration intentionally pauses automatic renewal until Apply succeeds.
- Synology ACME-DNS defaults recursive propagation checks to `1.1.1.1`; the resolver is user-configurable and does not invalidate the applied-certificate hash.
- Do not expose a next-renewal time by parsing logs, estimating a window, or decoding CertMagic metadata; wait for a direct CertMagic API for the active selected time.
- Project decisions are recorded in `decisions.md`.
