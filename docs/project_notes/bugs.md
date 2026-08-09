# Bug Log

Resolved bugs and their prevention notes are recorded here.

## Entry Format

### YYYY-MM-DD - Brief description

- **Issue**: What went wrong
- **Root Cause**: Why it happened
- **Solution**: How it was fixed
- **Prevention**: How to avoid recurrence

### 2026-08-07 - Failed certificate task left the Synology UI stale

- **Issue**: A completed Test or Apply failure could leave the UI showing an in-progress state and omit the latest log lines.
- **Root Cause**: Failure reconciliation rebuilt dynamic provider fields through `loadAll`. ExtJS attempted to align a validation icon while an ACME-DNS field was being destroyed, threw from `alignErrorIcon`, and aborted UI settlement. HTTP 400 responses also bypassed the success callback that decoded the CGI JSON envelope.
- **Solution**: Decode failed CGI envelopes in the AJAX failure callback, settle authoritative task failures locally, refresh logs without rebuilding the form, clear validation state before dynamic destruction, and restore dynamic fields to `msgTarget: "qtip"` after their parent container applies defaults during `add` or `insert`.
- **Prevention**: Keep long-action completion independent from form hydration, preserve failure response data, and test both that failure settlement avoids provider reconstruction and that dynamically inserted fields cannot retain side error icons.

### 2026-08-07 - Provider switching discarded a completed ACME-DNS registration

- **Issue**: If the user switched away from ACME-DNS while registration was in flight, the returned one-time account credentials disappeared.
- **Root Cause**: The registration callback only hydrated the currently rendered provider fields. After a provider switch, those fields no longer had ACME-DNS keys and no durable page-local draft received the response.
- **Solution**: Use one page-local `providerDrafts` map for every provider. Dynamic fields are captured before switching, registration responses merge through the same draft API, and save submits only the selected provider's draft. A reconstructed registration button also reflects the in-flight disabled state.
- **Prevention**: Dynamic components are views over page-level draft state. Async results that outlive those components must update the draft owner before touching the current component instance, with provider-switch and selected-provider-save regression guards.

### 2026-08-07 - HTTP 0 reconciliation accepted historical success

- **Issue**: After a long Test or Apply returned HTTP 0, the UI could report the new action as successful using a previous successful operation record.
- **Root Cause**: Status reconciliation checked only the derived `testPassed` or `canRenew` boolean. Those values can remain true when the current action never started, is still running, or failed after an earlier success.
- **Solution**: Capture a fingerprint of the relevant operation record after the pre-action save and before the action POST. Reconciliation accepts success only when `success`, `at`, or `message` changed and the new operation explicitly succeeded. An unchanged record is settled as a transport failure without reusing its historical message.
- **Prevention**: Any fallback that reconciles a mutation after an ambiguous transport result must prove that authoritative state changed after the mutation began; a historical aggregate boolean is not proof of completion.

### 2026-08-08 - ACME-DNS failed before updating the delegated TXT record

- **Issue**: A delegated ACME-DNS challenge could fail with `could not determine zone` before the ACME-DNS account received an update request.
- **Root Cause**: The ACME-DNS issuer passed custom recursive resolvers to CertMagic but did not set `DNSManager.OverrideDomain`. CertMagic therefore ran generic SOA zone discovery against the original `_acme-challenge` name before calling the libdns provider.
- **Solution**: For ACME-DNS only, normalize the saved `ACMEDNS_FULLDOMAIN` and pass it as CertMagic's override domain. Empty CLI values retain the previous generic behavior.
- **Prevention**: Delegated DNS providers must explicitly connect their persisted delegation target to the solver's presentation and propagation-check target, with tests covering provider scoping and empty-value compatibility.
