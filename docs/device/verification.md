# Verification

`verify_post_fix` requires an injected trusted recollection provider and binds fresh facts to the
requested org, asset and vendor. Reused/stale evidence is unknown. Configuration-control and
service-contract status are independent; both must pass required nonempty sets for `PASS`.
Synthetic provenance remains synthetic and cannot claim live post-fix verification.

Caller-supplied outcome dictionaries are compatibility input only and always remain `UNKNOWN`.
Only an injected `OutcomeProvider` bound to org/asset/change and fresh evidence hashes can produce
a verification pass. `phase9_verifier_adapter` blocks Phase-9 rollout for failed or unknown
independent results, and also blocks synthetic PASS results from production authorization. Live
TCP/HTTP/HTTPS/SSH probes are unavailable, not prohibited in principle.

No TCP, HTTP(S), or SSH transport is enabled by default. Future providers must authorize target
and scope, record vantage, validate TLS/host keys, bound time/size/retries, and avoid redirects.
