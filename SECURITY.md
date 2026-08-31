# Security Posture — blueeconomy-maritime-intelligence

Phase 11 security audit (branch `phase11/security`).

## Controls verified
- **Secrets**: working-tree scan clean.
- **AuthN/Z**: all `/v1/` routes behind `requireAuthentication`; feed-source registration/revocation/key-rotation with provenance; classification-ladder clearance enforced in the API layer.
- **Injection**: parameterized pgx; no string-built SQL.
- **RLS**: schema is national ISR data with no tenant_id dimension — tenant RLS not applicable; isolation is classification/clearance-based by doctrine (same as geo-service notes). Documented to record the review.

## Fixes this phase
- None required; posture confirmed by audit.

## Residuals
- ISR data is national-security classified: keep namespace-level segregation (gitops `isr` namespace, restricted PSA) as the hard boundary.
- Run `govulncheck` in CI with network access.
