# Issues and Work Log

Ticket-related work can be recorded here using concise dated entries.

## Entry Format

### YYYY-MM-DD - ISSUE-ID: Brief description

- **Status**: Completed, In Progress, or Blocked
- **Description**: Short summary
- **URL**: Link to the source issue when available
- **Notes**: Important implementation context

### 2026-08-08 - #105: ACME-DNS delegated challenge support

- **Status**: In Progress
- **Description**: Route CertMagic presentation and propagation checks through the registered ACME-DNS full domain.
- **URL**: https://github.com/mritd/dnsacme/issues/105
- **Notes**: `OverrideDomain` support is implemented. A dedicated CNAME delegation preflight remains separate follow-up work.

### 2026-10-28 - #113: AWS Route 53 DNS provider

- **Status**: Completed
- **Description**: Add `route53` provider backed by `github.com/libdns/route53` v1.6.2 (build tag `route53 || !slim`).
- **URL**: https://github.com/mritd/dnsacme/issues/113
- **Notes**: Long-term static access keys are required; session tokens are intentionally unsupported since STS credentials expire before renewal. Upstream calls `log.Fatalf` when AWS config loading fails (still possible via invalid `AWS_*` env such as a missing `AWS_PROFILE`), so `newRoute53` preloads the config with the same options and returns an error. `WaitForRoute53Sync` is left off: its waiter gives up after one 30s poll and duplicates CertMagic authoritative-NS propagation checks. The Synology UI needs no change because non-ACME-DNS provider fields are rendered from backend metadata. Region defaults to `us-east-1`; hosted zone ID is optional. The AWS SDK adds about 5 MB to the default binary.
- **Verification**: `go vet ./...`; `go test` with default, `synology`, `slim`, and `slim,route53` tags; fake-credential smoke call returned a 403 error, and `AWS_PROFILE=missing` now returns a constructor error instead of exiting. No real AWS issuance has been run.

### 2026-11-26 - Go 1.27 and dependency upgrades

- **Status**: Completed
- **Description**: Bump `go.mod` minimum Go version from `1.26.0` to `1.27.0` and upgrade direct AWS/Route53 dependencies plus `golang.org/x/*` base modules.
- **Notes**: Upgraded `aws-sdk-go-v2/config` (`v1.33.22`), `aws-sdk-go-v2/credentials` (`v1.21.4`), `libdns/route53` (`v1.6.3`), AWS SDK v2 transitive modules, and `golang.org/x/{crypto,net,sys,text}`. Kept unrelated indirect modules (`hcloud-go/v2`, `prometheus/*`, `pflag v1.0.10`) unchanged to avoid extra binary footprint and `--help` format drift.
- **Verification**: `go mod verify`; `go build`, `go vet`, and `go test -race` passed for both default and `-tags synology` builds; verified `dnsacme --help` boolean flag formatting matches README.
