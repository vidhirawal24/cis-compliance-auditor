# E15-E19 / SEC implementation evidence

The original 88-ID register is retained as the Phase 0 scope baseline. This phase adds evidence rather than declaring all product features complete.

| Scope | Phase 2 evidence | Remaining product gate |
|---|---|---|
| E15 / SEC-01,02,03 | JWT/JWKS, role matrix, backend membership checks, live tenant and browser-role RLS tests | Deployed-user and all future domain endpoint authorization tests |
| E16 / SEC-02 | Signed aal checks, privileged-operation denial, MFA status endpoint | Real Supabase enrollment/challenge/recovery flows with test identities |
| E17 / SEC-04 | Reference-only API/DB, exact-path OpenBao worker connector, secret-redaction tests | Actual vault deployment, AppRole provisioning/rotation and authorized worker dispatch |
| E18 / SEC-06,08 | Existing read-only collector contract and fail-closed mock retained; approval identity gates added | Real collector zero-write and approved hardening integration tests |
| E19 / SEC-12 | Attributed successful actions, denial categories/request IDs, append-controlled DB grants | Cryptographic chaining/signing and full application-wide event coverage |
| SEC-05 | Fixed HTTPS Auth/OpenBao origins, no redirects, default certificate verification | Deployed CA/network/proxy and device SSH/TLS verification |
| SEC-07,11 | No device secret payload persistence; sanitized errors and audit records | Evidence encryption/retention purge and signed manifests in later evidence phase |
| SEC-09 | Existing dependency lock reused; lint and tests run | Supply-chain scans and deployment image validation |
| SEC-10 | Shared database rate limiter, bounded auth/provider timeouts, fail-closed provider outages | Full queue fault injection and production capacity tests |

Phase 2 implementation is present; the end-to-end product features remain PARTIAL until the remaining gates are validated. Seed roles are the six canonical definitions in `packages/contracts/v1/permissions.json`; no synthetic accounts are provisioned into Supabase Auth.
