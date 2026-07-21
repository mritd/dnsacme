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

This is the lightweight first-party builder and remains the source of the SPKs
uploaded by the repository release workflow.

The first-party build intentionally produces only the common DSM targets: Go
`amd64` with `GOAMD64=v1` maps to DSM `x86_64`, while Go `arm64` maps to DSM
`aarch64`. Each SPK advertises only the architecture of the binary it contains.

Package upgrades always preserve configuration, certificates, and logs. The
uninstall wizard preserves them by default as well, and clears them only when
the user explicitly selects the delete option.

The SynoCommunity recipe can build additional packages from source for
Go-supported 32-bit architectures. Verify that the Synology-tagged root package
remains portable to `386`, ARMv5, ARMv7, `amd64` with `GOAMD64=v1`, and `arm64`
with:

```sh
task synology-arch-check
```

This check uses temporary outputs and does not add SPKs or binaries to the
repository `build` directory.

To reproduce a SynoCommunity package with its official build environment, use
an external spksrc checkout that contains `spk/dnsacme`:

```sh
SPKSRC_DIR=~/github/spksrc task synology-spksrc -- arch-x64-7.2
```

This optional task requires Docker, builds the DNSACME version declared by the
external checkout's recipe, and writes the result under `$SPKSRC_DIR/packages`.
Set `SPKSRC_IMAGE` to override the default SynoCommunity container image. The
task is not part of `release-build` and does not replace the first-party release
packaging flow.
