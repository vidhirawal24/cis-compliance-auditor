# Vidhi Device Engine Phase Completion Audit

Audit date: 2026-10-30  
Branch reviewed: `feat/vidhi-device` at `cb9443a`  
Scope: `services/device-engine` and `docs/device`; no other developer branch was merged or modified.

## Executive conclusion

Vidhi's workstream is a substantial, deterministic, offline-first SDK, but it does not satisfy the guide's live-lab exit gates. The package has strong fixture, parser, negative-path, and safety-gate coverage. It does not provide general live multi-vendor collection, an official CIS benchmark mapping engine, production remediation, Batfish integration, or live post-change service verification. All vendor claims must therefore remain fixture- or mock-qualified.

## Authoritative material reviewed

- `CISGuard_360_Complete_PRD_v1.pdf` (21 pages): complete 88-feature register and acceptance requirements.
- `CISGuard_360_Final_Tech_Stack_v3.pdf` (13 pages): intended collectors, simulation, remediation, security, and deployment stack.
- `CISGuard_360_Vidhi_Parallel_Development_Guide.pdf` (15 pages): Phase 0-11 tasks and ownership.
- Existing `docs/device` phase results, matrices, handoff documents, fixtures, source, and tests.

Unavailable: Mandar's `packages/contracts/v1`, Mandar's worker/backend, Apoorva's frontend, licensed vendor labs, supported Windows/Linux lab VMs, OpenSCAP executable and pinned ComplianceAsCode content, a Batfish service/snapshot corpus, GNS3/EVE-NG evidence, production credential providers, and live approval infrastructure.

PDF text was extracted with `pypdf`; Poppler rendering was unavailable. This audit did not alter the source PDFs.

## Phase findings

| Phase | Required outcome | Verified implementation | Status |
|---|---|---|---|
| 0 | contracts, platform/fixture matrix, read-only boundary | Provisional `FactsEnvelope`, adapter interfaces, coverage and adapter docs | PARTIAL - frozen shared contract absent |
| 1 | installable SDK, CLI, registry, normalization, golden fixtures | Package, module CLI, typed models, fixture replay, evidence hashes | FIXTURE VERIFIED ONLY |
| 2 | Windows 11/Server 2019 collectors and evidence mapping | Offline fixtures; local PowerShell; WinRM guarded and mock-tested | PARTIAL - no target lab and no per-CIS-control mapping |
| 3 | Ubuntu/RHEL collectors plus OpenSCAP/CaC | Offline fixtures; local/SSH collectors; XCCDF parser; guarded runner | PARTIAL - no Linux lab, `oscap`, pinned content, or CIS mapping |
| 4 | FortiOS, ASA/FTD, Check Point live adapters | Offline normalized captures; ASA SSH path mock-tested | PARTIAL - FortiOS/FMC/Check Point live APIs blocked |
| 5 | Sophos, PAN-OS, Cisco router/switch adapters | Vendor-shaped offline parsers and synthetic fixtures | PARTIAL - live transports absent; NX-OS unsupported |
| 6 | M20-M33 deterministic predicates and offline import | 21 bounded predicates, typed unknown semantics, sanitized imports | PARTIAL - primarily Cisco-shaped and not official CIS mapping |
| 7 | catalog, dry run, backup/recovery | Cisco preview templates, candidate binding, backup/recovery specifications | PARTIAL - preview-only; no lab-proven rollback |
| 8 | Batfish/custom simulation and safety contracts | Three bounded custom effects and safety contracts | PARTIAL - Batfish explicitly unsupported; no real topology service |
| 9 | approved execution and staged recovery | Injected-dependency coordinator tested with fake executor | PARTIAL - production templates and CLI writes remain blocked |
| 10 | independent re-collection, active probes, drift/evidence | Provider-driven verification, normalized diff, drift events | PARTIAL - no built-in live TCP/SSH/HTTP provider |
| 11 | full matrix, packaging, contract handoff | Wheel exists; isolated wheel evidence documented; 267-test audited suite | PARTIAL - no vendor labs or `contracts/v1` contract tests |

## 88-feature ownership reconciliation

Vidhi is primary owner for M01-M12, M14-M15, M20-M33, M37, E05, E10, E21-E22, E24-E25, and I11-I13, I15-I16. Current evidence supports partial implementation for those IDs, not end-to-end completion. M13, M16-M19, M34-M36, M38; E01-E04, E06-E09, E11-E20, E23, E26-E30; and I01-I10, I14, I17-I20 are interface/review dependencies owned by Mandar or Apoorva and cannot be marked complete in this checkout.

## Placeholder and incomplete-boundary findings

- `operations.candidates()` is an intentional typed `NOT_IMPLEMENTED` boundary even though lower-level preview candidate generation exists.
- `operations.execute()` always returns `LIVE_WRITE_BLOCKED`; this is a safety boundary, not production execution support.
- `operations.verify()` requires injected providers; the bare CLI is unavailable.
- Batfish returns `UNSUPPORTED`; no `pybatfish` snapshot/service integration exists.
- FortiOS, FMC, and Check Point live API entries are explicitly blocked by unverified endpoint contracts.
- PAN-OS, Sophos, router, and switch paths are offline parser/replay only.
- No hard-coded compliance score or fake live success was found. Synthetic values are labeled as fixtures.
- Broad exception handling found in collector boundaries is converted into structured/redacted errors; the suite exercises representative failure paths.

## Repair performed

The `capabilities` output incorrectly reported `fixture_tests: false` for eight firewall/network families despite corresponding corpora and tests. The metadata now reports fixture coverage for every listed family while retaining `live_lab_tests: false`; a CLI regression test enforces both properties. No support level was upgraded.

## Final assessment

The engine is suitable for controlled offline integration and further lab validation. It is not ready for production live collection or remediation. Integration may proceed only with explicit synthetic/offline provenance, provisional-schema handling, and Mandar-owned policy, authorization, persistence, and secrets boundaries.
