# Synology Package

This directory contains the DSM package scaffold for DNSACME.

The Go integration remains in the root `main` package so the package commands
reuse the existing provider registry, configuration validation, and ACME runtime
without maintaining a second executable or provider catalog.

The package intentionally uses DSM's classic package app integration:

- `spk/ui/config` registers the app and loads `DNSACME.js` as the DSM AppWindow implementation.
- `spk/ui/api.cgi` calls `dnsacme synology api-cgi`, so the UI stays under DSM's web origin and does not need a separate frontend build or a public API port.
- `spk/scripts/start-stop-status` runs the long-lived renewal process and reloads
  CertMagic when a newly applied configuration changes the persisted hash.

Build a package from the repository root:

```sh
task synology
```

It builds the common DSM targets: Go `amd64` with `GOAMD64=v2` maps to DSM
`x86_64`, while Go `arm64` maps to DSM `aarch64`. Each SPK advertises only the
architecture of the binary it contains.
