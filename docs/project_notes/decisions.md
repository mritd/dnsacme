# Architectural Decisions

### ADR-001: Reconfiguration Intentionally Suspends Renewal (2026-08-07)

**Context:**

- Selecting reconfiguration is an explicit user decision to replace the active certificate or DNS settings.
- Continuing renewal with the previous settings after that decision would contradict the user's intent.
- A user may close the wizard or leave configuration incomplete after entering reconfiguration mode.

**Decision:**

- Entering reconfiguration persists `Reconfiguring = true`.
- The daemon and active renewal monitor stop renewal while reconfiguration is active.
- Closing or abandoning the wizard does not resume renewal automatically.
- Only a successful Apply clears the reconfiguration state and enables renewal for the newly applied configuration.

**Alternatives Considered:**

- Continue renewing with the previously applied configuration until new settings are saved. Rejected because it acts against the user's explicit choice to reconfigure.
- Resume renewal when the wizard closes. Rejected because closing may also represent an interrupted or intentionally postponed reconfiguration.

**Consequences:**

- Renewal behavior follows the user's explicit reconfiguration choice.
- An abandoned reconfiguration remains paused until the user returns and completes Apply.
- The UI should make the paused state and the requirement to complete Apply clear.

### ADR-002: ACME-DNS Uses a Configurable Recursive Resolver (2026-08-07)

**Context:**

- ACME-DNS may publish the correct delegated TXT value while the NAS system resolver still serves a cached answer during CertMagic propagation checks.
- Resolver selection changes challenge observation, but it does not change certificate identity or the certificate already deployed to DSM.

**Decision:**

- Synology ACME-DNS configurations store `dns.resolvers`, defaulting missing or empty values to `1.1.1.1`.
- Only ACME-DNS passes the configured resolver list to CertMagic. Other providers continue using the system resolver.
- Resolver values are excluded from `ConfigHash`, so resolver-only changes preserve `LastApply` and the renewal gate.
- A separate `RenewalRuntimeKey` includes effective ACME-DNS resolvers so a running renewal manager reloads after a resolver-only save.

**Consequences:**

- Existing package configurations remain renewal-compatible after upgrade.
- Users on networks that block Cloudflare DNS must select a reachable recursive resolver in the UI.
- Resolver validation occurs before ACME work and accepts IP addresses with optional numeric ports.

### ADR-003: Provider Drafts Are Page-Local and Selected on Save (2026-08-07)

**Context:**

- Provider fields are rebuilt whenever the provider selector changes.
- Users may compare providers or temporarily switch away from ACME-DNS before clicking Next.
- Persisting every selector change would turn page exploration into configuration mutation and complicate conflict handling.

**Decision:**

- The UI owns one `providerDrafts` map keyed by provider name for the lifetime of the page.
- Dynamic provider fields are captured into their draft before they are destroyed, and asynchronous provider results merge into the same draft.
- Clicking Next submits only the currently selected provider and its draft. Drafts for unselected providers remain browser-local and are not written to the package configuration.

**Consequences:**

- Switching providers no longer discards unsaved fields or ACME-DNS registration results.
- The persisted configuration keeps its existing single-provider schema and compatibility behavior.
- Reloading or closing the page still discards drafts that were never saved with Next.

### ADR-004: Do Not Infer or Decode the Next Renewal Time (2026-08-07)

**Context:**

- CertMagic logs an ARI `selected_time`, but does not expose the currently persisted value through a direct high-level API.
- Reading it would require parsing logs or depending on CertMagic's certificate metadata representation.

**Decision:**

- The Synology summary does not display a next-renewal time while CertMagic lacks a direct API for the active selected time.
- DNSACME will not estimate the value, parse it from logs, or decode CertMagic's internal metadata solely for presentation.

**Alternatives Considered:**

- Parse the latest `selected_time` log field. Rejected because logs are not authoritative state and may be missing, rotated, or stale.
- Read CertMagic's stored certificate metadata through its storage types. Rejected because the required high-level value is not exposed directly and the UI feature does not justify coupling DNSACME to that representation.

**Consequences:**

- The deployed summary leaves the next-renewal slot absent rather than showing a potentially stale or inferred value.
- This decision may be revisited if CertMagic adds a direct API for the active selected renewal time.

### ADR-005: Multiple Domains Use Named DNS Credentials and One DSM Certificate Each (2026-11-01)

**Context:**

- Users need several domains whose DNS zones live at different providers or provider accounts.
- CertMagic `ManageSync` manages one certificate per identifier and cannot issue a SAN certificate.
- Existing single-provider configs must keep their `ConfigHash` so upgrades do not suspend renewal (see ADR-001).

**Decision:**

- `dns.credentials` holds named provider accounts and `dns.assignments` maps each domain to one of them; unassigned domains use the first credential.
- `dns.provider`, `dns.config`, and `dns.resolvers` always mirror the first credential. A lone credential is folded back into that legacy shape, and `ConfigHash` omits the multi-account fields when empty.
- A routing `acmez.Solver` dispatches each DNS-01 challenge to a per-credential `certmagic.DNS01Solver`, so ACME-DNS override domains and resolvers stay per account (extends ADR-002).
- Each domain is imported into DSM as its own certificate named `<description> <domain>`; only the first domain may become DSM's default. A single domain keeps the bare description.
- Domains sharing an `_acme-challenge` record (apex and wildcard) must use the same credential.

**Alternatives Considered:**

- One SAN certificate for all domains. Rejected because CertMagic's management API is per identifier, and bypassing it would lose its renewal handling.
- Treating the legacy fields as a separate "default" account beside the list. Rejected because two sources of truth complicate secret merging and hashing.

**Consequences:**

- Upgrading single-domain configs is transparent; adding a second domain or credential changes the hash and requires Apply.
- Renamed credentials keep redacted secrets through a request-only `previousName`.
- Users serving several domains from DSM assign the per-domain certificates to services in DSM.

