# Blockers, assumptions and security risks

No blocker removes a feature. Product status remains UNTESTED until acceptance evidence exists.

| ID | Type / state | Decision or missing evidence | Owner / exit evidence |
|---|---|---|---|
| B01 | Integration gate OPEN | All three owners must agree to the exact v1 digest, including normalized fact structure, coverage and proposed routes | Mandar/Apoorva/Vidhi review records in freeze.json |
| B02 | Source gap OPEN | Standalone original hackathon PS not supplied; PRD M01-M38 retained in full | Team compares original PS against 38 extracted rows |
| B03 | Release dependency OPEN | Benchmark licenses, exact edition/profile mapping and distribution rights unverified | Mandar: authorized source/rights register; no bundled CIS content |
| B04 | Lab dependency OPEN | No authorized device/VM inventory, firmware, vendor credentials or lab access supplied | Vidhi: per-version collector/parser/simulator/remediation compatibility evidence |
| B05 | Foundation dependency OPEN | No Supabase project/deployment policy, OpenBao deployment, tenant bootstrap, production signing keys | Mandar: Phase 1 configuration and negative isolation tests |
| B06 | Integration gate OPEN | Blank workspace lacks Git repo, remote, teammates or CI project | Team provisions shared repo; branch feat/mandar-core; apply ownership checks |
| B07 | Runtime validation OPEN | Production dependency compatibility, Linux tools, Docker, OR-Tools/Batfish/Ansible/WeasyPrint not validated | Later phase lockfiles + integration results, not library-install claims |
| A01 | Resolved source identity | DOC-20261029-WA0004 (1).pdf is Final Tech Stack v3.0 based on cover and all 13 pages | Source manifest |
| A02 | Proposed wire rule | X-Org-ID selects tenant; scopes are backend verified; first owner provisioned out of band | ADR 0001/0002; Phase 1 tests |
| A03 | Proposed scoring | Coverage includes pending/manual/error/not-assessed, excludes confirmed NA; zero denominator null | ADR 0003; cross-team review |
| A04 | Proposed migration ownership | Alembic DDL, Supabase RLS/grants/storage; one ordered release manifest | Domain map; validate migration ordering in Phase 1 |
| A05 | Proposed request policy | 24h request dedup retention plus durable action checkpoint dedup; limit 100 page items | ADR 0001/0004; workload testing later |
| A06 | Contract scope | Opaque worker capabilities and platform strings do not imply support; version compatibility is separate | Capabilities schema and future compatibility registry |

| Risk | Required mitigation | Validation gate |
|---|---|---|
| Cross-tenant data/storage/Realtime leakage | Membership + scoped predicates + RLS; private signed artifacts | Two-tenant negative integration tests |
| Parser/command injection or secret leakage | Safe parsers, limits, redaction, allowlisted templates, OpenBao pointers | Malformed input/secret/log tests; no raw command wire input |
| SSRF / unauthorized discovery | Approved ranges/targets, DNS and redirect checks | Out-of-scope and metadata-address tests |
| False compliance / unsupported versions | Six statuses; evidence-required automated results; compatibility matrix | Version-specific positive, failure and unknown tests |
| Approval race / stale configuration | Atomic plan digest, target lock, precheck/approval expiry and fresh baseline | Stale plan, self-approval and concurrent execution tests |
| Lockout or irreversible write | Backup, management access constraints, staged rollout and manual recovery | Authorized lab failure/recovery tests |
| Model overclaim | Explicit verdict/coverage and mandatory live postchecks | Prediction vs measured behavior tests |
| Queue outage / ambiguous write result | Transactional outbox, bounded retry, durable checkpoint, reconciliation | Kill/timeout/duplicate-message fault injection |
| Evidence tampering / misleading reports | Signed manifest, hash chain, canonical scores and four-format reconciliation | Signature verifier and export reconciliation |
| Legal/source mismatch | Exact version/profile/rights registry, original PS comparison | Release review, no silent feature deletion |
