# Mandar integration checklist

- [ ] Install the non-editable `cisguard-device` wheel on Python 3.11+.
- [ ] Supply explicit offline fixture/capture paths; fixture corpora are external resources.
- [ ] Ingest `FactsEnvelope` evidence hashes and UTC timestamps without treating unknown as pass.
- [ ] Call Cisco-only `evaluate_device(envelope, policy)` only for IOS/IOS-XE bounded facts.
- [ ] Persist Mandar-owned findings, CIS mapping, exceptions, scores and policy versions.
- [ ] Consume preview candidates/simulation as no-write evidence, never approval.
- [ ] Supply trusted approval, vault/cipher, locks/journal, transport, recovery and verification providers.
- [ ] Display synthetic, preview-only, unsupported and unknown states directly.
