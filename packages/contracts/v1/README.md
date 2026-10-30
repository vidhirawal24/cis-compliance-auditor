# CISGuard 360 v1 contract proposal

Owner: Mandar. Consumers: Apoorva web and Vidhi device engine. Version 1.0.0, review status in `freeze.json`.

- `models.py`: Pydantic v2 wire types and semantic invariants.
- `json-schemas/`: self-contained generated JSON Schema 2020-12 documents.
- `openapi.yaml`: generated OpenAPI 3.1 HTTP contract, not deployed handlers.
- `route_catalog.py`: operation types, permissions and stable feature tags.
- `permissions.json`: proposed auth role matrix and mandatory constraints.
- `examples/`: explicitly synthetic, offline-only wire fixtures.
- `freeze.json`: exact proposed snapshot digest; reviews pending.

Read `docs/core/schema-route-diff.md` and ADRs before implementation. Consumers must enforce semantic invariants as well as JSON Schema shape. Backend authorization remains necessary even for a well-formed worker message. Version field, timestamps and IDs are canonical. No secrets or free-form browser executable commands belong in messages.

Run instructions are in `infra/README.md`; acceptance evidence is in `docs/core/phase0-validation.md`. Runtime product coverage is not established by these tests.
