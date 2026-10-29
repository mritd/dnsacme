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

### 2026-10-29 - #111: Synology TOTP and trusted-device authentication

- **Status**: In Progress
- **Description**: Add explicit OTP enrollment, private trusted-device persistence, daily authentication checks, DSM notifications and recoverable renewal deployment failures.
- **URL**: https://github.com/mritd/dnsacme/issues/111
- **Notes**: Authentication state is separate from certificate configuration. Reauthentication does not enter reconfiguration or invalidate a successful Apply. Real DSM enrollment and renewal deployment verification remain pending.
- **Verification**: Default and Synology Go tests, Synology race tests and vet, JavaScript syntax and authentication-dialog behavior checks passed. AMD64 and ARM64 SPKs build successfully. Authentication, revoked-device, failed-import and redaction tests also passed as a Linux AMD64 test binary on a DS918+ running DSM 7.3.2, using simulated DSM HTTP responses; this is not yet a live OTP/import test.
- **Device upgrade**: Upgraded the DS918+ from package `1.0.9-2` to test package `1.0.9-13` (UI build 118) after a private backup. Configuration checksum and `0600` permissions were preserved, the daemon runs as the package account, and the installed binary SHA-256 matches the tested SPK. Live OTP enrollment remains pending.
