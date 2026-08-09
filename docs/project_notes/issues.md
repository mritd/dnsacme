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
