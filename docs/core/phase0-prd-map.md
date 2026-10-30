# Mandar Phase 0: source audit and contract proposal

Prepared 29 October 2026. Scope: source audit, ownership, interfaces, security decisions and contract validation. This is not a completed application.

## Source audit

Read all 21 pages of `CISGuard_360_Complete_PRD_v1.pdf` and all 13 pages of the supplied `DOC-20261029-WA0004 (1).pdf`. The latter's cover identifies it as **CISGuard 360 Final Tech Stack v3.0**, the required stack reference. No replacement upload is needed. SHA-256 identities, page counts and full text extractions are in [sources/manifest.json](sources/manifest.json). The two pasted Mandar playbook excerpts supply ownership, contract wiring and Phase 0 deliverables. Embedded later-phase instructions are reference material, not authorization to implement those phases.

PRD functional behavior and final stack take precedence for product scope. The team playbook takes precedence for integration names. The standalone original hackathon problem statement is not supplied: all 38 mandatory entries are preserved exactly from the PRD, but independent comparison with that original source remains open (B02).

## Scope retained

- M01-M38: 38 mandatory features. Windows 11 Enterprise/standalone, Server 2019, Ubuntu 20.04/22.04, RHEL 8/9, Fortinet, Cisco firewall, Check Point, Sophos, Palo Alto, Cisco routers/switches; collection, rule engine, all network control categories, GUI, findings, scoring and four exports.
- E01-E30: 30 enhancements, including operations, Auth/MFA/RLS, evidence, approval, recovery and integrations.
- I01-I20: 20 innovations, including deterministic graph reasoning, OR-Tools planning, simulation, safety, dual verification and proof.

[Machine-readable register](feature-register.json) retains each exact requirement and acceptance criterion with PRD page, domain, RACI, stable acceptance ID and status. [Readable RACI](feature-raci.md) and [CSV](feature-raci.csv) cover all 88. All product statuses are **UNTESTED**. A passing contract test is not product acceptance evidence.

## Reference-to-deliverable map

| Reference | Required treatment | Phase 0 artifact |
|---|---|---|
| PRD pp3-5, 6-9 | Preserve scope, statuses, score | Register; models; scoring ADR |
| PRD pp10-13 | Workflows, modular policies, normalization | Domain map; evidence/worker schemas |
| PRD pp14-15 | Graph, solver, simulation, safe execution, verification | Plan/simulation/approval/proof schemas; safety ADR |
| PRD pp16-18 | Security, data, API, operational targets | Permissions; OpenAPI; tenant/security ADR |
| PRD pp19-21 | Acceptance, sequencing, risks | Register acceptance IDs; blocker log; handoff |
| Stack pp1-4, 8-10 | FastAPI/Python, Supabase, queues, secrets, reports | Domain map; dependency and migration decisions |
| Stack pp5-7 | Platform boundaries, policy/graph/planner tools | Typed device port; exact compatibility retained |
| Stack pp11-13 | Tooling checklists, 88 scope, honest evidence | Engineering checklists; handoff and tests |

## Ownership and repository rules

Mandar may edit only `apps/api/`, `packages/contracts/`, `infra/`, `docs/core/`. Apoorva owns `apps/web/` and `docs/frontend/`. Vidhi owns `services/device-engine/` and `docs/device/`. No teammate modules are created or edited. `packages/contracts/v1/` is the **single canonical contract path**; the playbook's shortened `contracts/v1` means this path. Do not create a second schema tree.

The initial workspace had no files or Git repository. No Git repository/remote or branch was invented. When the team establishes the repository, Mandar's intended branch is `feat/mandar-core`; branch creation and PR workflow remain an integration step.

Changes to contracts require recorded review from all three owners. The snapshot is version 1.0.0 **PROPOSED**, structurally validated and ready for independent development review; it is not falsely recorded as team-approved. See [schema and route diff](schema-route-diff.md) and [freeze record](../../packages/contracts/v1/freeze.json).

## Exit gate

Produced: full source audit, 88-row register/RACI, backend domain/data map, Pydantic wire types, generated OpenAPI and JSON Schemas, synthetic wire examples, a fail-closed development port, ADRs, blockers and reproducible contract tests. Final test results are in [phase0-validation.md](phase0-validation.md).

Pending external gates: three-owner contract agreement, original PS comparison, benchmark rights and authorized version-specific lab inventory. Phase 1 implementation is not part of this request.
