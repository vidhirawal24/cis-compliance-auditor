# ADR 0004: Workers, simulation and controlled changes

Status: proposed. References: PRD pp14-15; stack pp7-8; playbook state enums.

Mandatory auditing operates independently of graph, planner, simulation and hardening availability. CollectionCommand is always read_only=true. The backend constructs scoped worker messages after authorization; browser bodies cannot select an execution template's raw arguments. Vetted templates bind firmware, capability and validated parameter references. Worker schema validation is not permission to execute.

Collection results are COLLECTED, PARTIAL, UNSUPPORTED or ERROR with honest provenance/errors. Match job/scan/org/asset correlation to the dispatched command before accepting any result. Job envelope states are QUEUED -> RUNNING -> SUCCEEDED/PARTIAL/FAILED/CANCELLED. A timed-out worker cannot overwrite a terminal result; retries are linked attempts and preserve prior evidence. Persist deadlines, per-tenant concurrency, vendor rate limits and outbox events.

Planner outcomes are FEASIBLE, UNSAT, UNSUPPORTED, INSUFFICIENT_EVIDENCE. UNSAT includes violated constraints and no executable actions. Simulation outcomes remain SAFE_IN_MODEL, VIOLATES_CONTRACT, UNSUPPORTED, INSUFFICIENT_EVIDENCE. SAFE_IN_MODEL is a prediction, not proof of live safety. Unknown coverage of any mandatory safety contract blocks automatic execution.

Normal change transitions: DRAFT -> SIMULATED -> PRECHECKED -> PENDING_APPROVAL -> APPROVED -> EXECUTING -> VERIFYING -> VERIFIED. Validation/preparation failures can terminate as FAILED. Execution or verification failures go to FAILED, ROLLED_BACK or NEEDS_MANUAL_RECOVERY based on measured recovery outcome. Do not report ROLLED_BACK merely because rollback was attempted. A terminal state is immutable; retries create a new linked change. Simulation rejection stays DRAFT with recorded failure or ends FAILED; it does not advance.

Before dispatch and again at execution: verify active authorization and aal2, tenant and exact asset identity/version, approved immutable plan hash, baseline config freshness, unexpired approval, independent approver, precheck freshness, backup integrity, recovery plan, model coverage and mandatory contracts. Any changed target/config/template/plan invalidates approval. Server-controlled states cannot be patched by clients. A worker execution result may report VERIFYING but cannot declare VERIFIED.

Execution uses per-asset locking, checkpoints and idempotent action identities. Stop later staged batches after a failed/unverified canary. An unknown write outcome requires reconciliation/manual recovery, not generic retry. This v1 automatic execution contract requires backup evidence and explicit recovery; irreversible/manual-only operations stay outside automatic dispatch until their workflow is reviewed.

Verification requires fresh post-change collection, relevant compliance checks and all requested real service checks. VERIFIED requires every required check PASS and evidence, matched to the requested check set; absence is not a pass. Validate evidence timestamp against execution completion at runtime. Proof dossier binds original failure, source hashes, benchmark release, plan/approval, simulation, actor identities, execution events, fresh results, residual risk and signed manifest.

The mock port has no live I/O. It returns UNSUPPORTED for collection and raises for execution/verification. No successful simulated device operation is used to claim implementation.
