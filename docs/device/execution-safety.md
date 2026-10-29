# Execution safety

The provisional `ExecutionRequest` binds org/asset/action/plan IDs, candidate/template/version,
target identity, current evidence, simulation, approval expiry/scope, and idempotency key.
An injected trusted verifier is required; a browser flag, hash, or signature string is not proof.

Prechecks require approval, fresh matching identity/evidence, exact template, backup readiness,
simulation binding and service-preservation coverage, secrets, lock and journal. Missing or
unknown dependencies block. Timeout/partial outcomes require reconciliation and are never retried.
