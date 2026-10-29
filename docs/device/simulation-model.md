# Simulation model

Supported custom effects are local IOS HTTP state, VTY timeout bound, and shutdown of an
interface in an explicitly supplied, `modeled_available` topology path. Baseline facts are not
mutated. NAT, routing, stateful behavior, authentication, application policy, vendor
inheritance, and unknown topology are not guessed.

`local_http_disabled` and `vty_timeout_max` report `desired_configuration` and set
`service_preservation_evaluated` false. They do not establish HTTP/SSH management continuity.
`path_available` reports `modeled_service_path` only when the supplied path explicitly says it
is modeled available. This is bounded model evidence, not end-to-end reachability.

`SAFE_IN_MODEL` is not real service verification, execution approval, or a live safety guarantee. Batfish is an import-safe optional boundary only; selecting it returns `UNSUPPORTED` when no configured service exists and never silently invokes the custom model.
