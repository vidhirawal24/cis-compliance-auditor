# Mandar contract compatibility

## Official status: BLOCKED

`packages/contracts/v1/` is absent in this checkout. There are no shared schemas, fixtures, or
examples to validate. Local Pydantic models are provisional compatibility models, not approved
Mandar contracts.

| Required area | Local model/interface | Official compatibility |
|---|---|---|
| Facts envelope, UTC evidence and structured errors | `FactsEnvelope`, `EvidenceReference`, `CanonicalError` | BLOCKED: shared schema absent |
| Status enums | `AssessmentStatus`, `SimulationVerdict`, `ExecutionState` | BLOCKED: shared enum registry absent |
| Simulation | `SimulationInput`, `SimulationResult` | BLOCKED: shared simulation schema absent |
| Execution | `ExecutionRequest`, `ExecutionResult` | BLOCKED: ActionEnvelope absent |
| Verification | `VerificationRequest`, `VerificationResult` | BLOCKED: proof/verification schema absent |

Mandar must publish versioned models and fixtures covering UUIDs, UTC timestamps, evidence,
retryable errors, platform/version identity, status enums, and JSON serialization. Vidhi must then
add direct validation tests without changing shared contracts.
