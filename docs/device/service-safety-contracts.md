# Service safety contracts

Contracts are explicit, versioned inputs and must be supplied with their canonical
`contracts_hash`; supplied topology must likewise carry `topology_hash`. Supported kinds are
`local_http_disabled`, `vty_timeout_max`, and `path_available`. A local setting contract is not
end-to-end reachability. Path contracts require explicit topology paths, interfaces, and
`modeled_available: true` before availability can be concluded.

Verdicts are `SAFE_IN_MODEL`, `VIOLATES_CONTRACT`, `UNSUPPORTED`, and `INSUFFICIENT_EVIDENCE`. A known violation is retained even if other contracts are unknown. No contracts never produces a safe verdict.
