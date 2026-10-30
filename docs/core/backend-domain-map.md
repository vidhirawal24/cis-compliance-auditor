# Backend domain and data map

All paths below are planned modules under `apps/api/`, not claims of implementation. Every persisted tenant row has `org_id`, tenant-scoped uniqueness and composite tenant foreign keys. Tables are logical designs; there are no migrations or deployed RLS policies in Phase 0.

| Domain / planned module | Logical entities | Mandar responsibility | Boundary / feature IDs |
|---|---|---|---|
| identity | organizations, organization_members, role_bindings, access_audit | Supabase JWT/JWKS, membership, MFA, backend RBAC, RLS | E15-E16; browser Auth UX belongs to Apoorva |
| inventory | assets, asset_groups, tags, sites, credential_references | Scope registration, asset lifecycle, filtering | E01-E03, E08-E10; discovery/collection belongs to Vidhi |
| policy | benchmark_packs, policy_rules, rule_versions, policy_overrides, manual_reviews, exceptions | Versioned allowlisted evaluation, rights metadata, applicability, overrides | M16-M33, E11-E14, E20, I19-I20 |
| orchestration | scan_jobs, scan_targets, schedules, worker_heartbeats | Celery/Redis/Beat, outbox, scoped retries and concurrency | M12-M15, E04, E08-E10, E18; device port only |
| results | audit_results, findings | Canonical expected/observed status and scores | M35-M37; never accept browser-computed scores |
| history | config_snapshots, audit_events | Drift and comparable trends | E05-E07, E19; original audit never rewritten |
| intelligence | asset_edges, asset_dependencies, network_facts, risk_scenarios, risk_evidence | NetworkX typed evidence graph and deterministic correlation | E13, I01-I05, I17; no invented paths |
| planning | remediation_plans, remediation_actions | OR-Tools CP-SAT, alternatives, conflict/dependency constraints | I06-I10; vendor actions provided by Vidhi |
| safety | safety_contracts, simulation_runs, prechecks | Store contracts, snapshots, model limitations and authorization gates | E22-E24, I11-I15; simulator/recovery adapters belong to Vidhi |
| approvals | approvals, execution_events | Immutable plan hash, separation of duties, server-controlled transitions | E21, E23-E24, I14-I15; no browser executable command field |
| verification | verification_runs | Fresh collection, compliance plus requested service checks | E25, I16-I17; device probes belong to Vidhi |
| reporting | reports, audit_evidence, proof_manifests | PDF/HTML/CSV/JSON from canonical results; signed proof | M38, E28, I18 |
| integrations | notifications, integrations | Tenant-scoped deliveries, bounded retries, idempotent tickets | E26-E27, E30 |

Naming aliases are intentional: PRD `audit_jobs` -> `scan_jobs`, `security_relationships` -> `asset_edges`, `policy_exceptions` -> `exceptions`. These are one logical entity each, not parallel stores.

## Data flow and isolation

Validated Supabase JWT -> selected organization membership/permissions -> resource-specific authorization -> transactional job + outbox -> scoped Celery worker -> typed device-engine port -> evidence validation -> canonical policy results -> scores/risk/plans -> reviewed simulation/precheck/approval -> eligible worker -> fresh dual verification -> reports/proof.

Workers recheck tenant, target identity, grant expiry and cancellation before device I/O. Only eligible workers resolve OpenBao credential references. Redis task input is not an authority source. WebSocket/Realtime subscriptions must enforce the same tenant/resource policies; channel names alone never authorize access.

Storage buckets: `audit-evidence`, `config-snapshots`, `device-backups`, `generated-reports`, all private. Internal object location uses `private://bucket/org_uuid/object_uuid`; endpoint signing verifies tenant access and never exposes storage service credentials. No unencrypted raw snapshot enters API responses.

## Read-only baseline and later implementation

FastAPI, Uvicorn, SQLAlchemy, psycopg, Alembic, Supabase Auth/Storage/Realtime, Celery/Redis, OpenBao, PyJWT/cryptography/HTTPX are foundation choices from the source. Phase 0 installs only contract-validation tools. NetworkX, OR-Tools, OPA, Jinja2/WeasyPrint and observability tooling remain later-phase dependencies. No vendor collectors, frontend pages, database services or runtime LLM/AI/ML modules are included.

Alembic owns application DDL; Supabase SQL migrations own Auth integration, RLS/storage policies and grants. A release manifest orders them, with no overlapping ownership of a table definition. Transactional outbox prevents queue publication without committed job metadata. Workers use bounded retries only for retryable collection failures; uncertain device writes must enter recovery rather than blind replay.

## Acceptance targets retained

PRD targets remain unmeasured: 1,000 registered assets, p95 under 1 second for ordinary paginated API reads in a documented environment, isolated per-device failures, retention/deletion, tenant security, log redaction and frontend accessibility. Phase 0 tests validate interfaces, not these runtime targets.
