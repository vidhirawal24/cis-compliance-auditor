# Phase 8 results

Phase 8 adds a fixture-tested, no-write custom what-if model for the three Phase 7 Cisco preview templates. I11-I13 remain partial. There is no live firmware validation, execution authorization, or real service verification.

The model binds org/asset, evidence hashes, candidate hash, and exact contract/topology document
hashes. Contract version remains part of the bound contract document. It returns per-contract
outcomes with an explicit scope. Aggregate precedence is violation, unsupported, insufficient
evidence, then safe in model.

Phase-8 closeout corrected two unsafe inferences: an unchanged candidate now evaluates an
explicitly modeled unaffected path rather than becoming unsupported, and path membership alone
does not prove availability. A shutdown can prove loss of an explicitly `modeled_available`
path; alternate paths and actual service availability remain unknown.
