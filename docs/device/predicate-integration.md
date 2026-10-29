# Mandar Integration Guide: Network Predicates & Offline Import

This guide describes how Mandar's central policy and orchestration engine integrates with `cisguard_device` Phase 6 capabilities without duplicating logic or violating evaluation boundaries.

## Evaluation Boundary & Ownership

| Responsibility | Device Engine (`cisguard_device`) | Mandar / Central Policy Engine |
|---|---|---|
| Offline snapshot import | **Owns** (validates size, sanitizes secrets, parses format) | Calls import API or passes offline files |
| Device facts extraction | **Owns** (CLI text parsing, structured ACL normalization) | Consumes `FactsEnvelope` |
| Low-level predicate evaluation | **Owns** (deterministic evaluation of M20–M33 checks) | Supplies `NetworkControlPolicy` parameters |
| Benchmark rule mapping | Provides candidate check ID (`DEV-Mxx-NNN`) | **Owns** (maps internal checks to official CIS benchmark numbers) |
| Central policy packs & baselines | Accepts typed policy thresholds | **Owns** (tenant baselines, exceptions, overrides) |
| Scoring & compliance percent | **Forbidden** (does not calculate percentages) | **Owns** (scoring algorithms, rollups, reports) |
| Finding persistence & audit trail | Emits structured `PredicateResult` | **Owns** (database persistence, finding lifecycle) |

---

## Public SDK Imports

Mandar imports the required models and functions directly from the top-level package:

```python
from cisguard_device import (
    # Models
    AssessmentStatus,
    FactsEnvelope,
    PredicateResult,
    NetworkControlPolicy,
    OfflineImportMetadata,
    EvidenceProvenance,
    # Evaluator & Importer
    evaluate_network_controls,
    evaluate_device,
    import_offline_file,
    SUPPORTED_SOURCE_TYPES,
    SOURCE_TYPE_PLATFORMS,
)
```

---

## Standard Integration Flow

### 1. Ingest Offline Configuration

```python
from pathlib import Path
from uuid import UUID
from datetime import datetime, timezone
from cisguard_device import import_offline_file, OfflineImportMetadata, EvidenceProvenance

metadata = OfflineImportMetadata(
    source_type="cisco_ios_running_config",
    platform="cisco_router",
    org_id=UUID("11111111-1111-4111-8111-111111111111"),
    asset_id=UUID("22222222-2222-4222-8222-222222222222"),
    capture_timestamp=datetime.now(timezone.utc),
    provenance=EvidenceProvenance.USER_SUPPLIED_CAPTURE,
    completeness="complete",
)

envelope = import_offline_file(
    path=Path("/path/to/running-config.txt"),
    metadata=metadata,
    operational_path=Path("/path/to/show-output.txt"), # Optional
)
```

### 2. Evaluate Network Controls

```python
from cisguard_device import evaluate_network_controls, NetworkControlPolicy

policy = NetworkControlPolicy(
    session_timeout_seconds=300,
    sensitive_ports=[22, 23, 80, 443, 3389],
    required_vlans=["10", "20"],
    designated_unused_ports=["GigabitEthernet1/0/2"],
)

results: list[PredicateResult] = evaluate_network_controls(envelope, policy)
for r in results:
    print(f"[{r.status.value}] {r.check_id} ({r.feature_id}): {r.explanation}")
```

---

## Result Types and Examples

### Example: PASS (`DEV-M20-001`)
```json
{
  "check_id": "DEV-M20-001",
  "feature_id": "E05",
  "status": "PASS",
  "actual": {
    "telnet_enabled": false,
    "vty_transport_evidence": ["ssh", "ssh"]
  },
  "expected": {
    "telnet_enabled": false
  },
  "explanation": "All configured VTY lines restrict transport input to SSH; Telnet is not permitted.",
  "error_code": null,
  "remediation": null,
  "limitations": [
    "Configured VTY transport restrict is not proof that no Telnet service is reachable.",
    "AUX port and console Telnet sessions are not evaluated."
  ]
}
```

### Example: FAIL (`DEV-M21-003`)
```json
{
  "check_id": "DEV-M21-003",
  "feature_id": "E05",
  "status": "FAIL",
  "actual": {
    "vty_lines": [
      {"name": "0 4", "login_method": "local", "key_authentication_configured": null}
    ]
  },
  "expected": {
    "login_method": "key_authentication"
  },
  "explanation": "'login local' is configured on one or more VTY lines, indicating password-based authentication rather than key-only authentication.",
  "error_code": null,
  "remediation": "Configure AAA with key-based authentication method and use 'login authentication <method>' on VTY lines. Remove 'login local' from lines requiring key-only access."
}
```

### Example: NOT_ASSESSED (`DEV-M32-002`)
```json
{
  "check_id": "DEV-M32-002",
  "feature_id": "E08",
  "status": "NOT_ASSESSED",
  "actual": {
    "synchronized": null
  },
  "expected": {
    "ntp_synchronized": true
  },
  "explanation": "NTP synchronization status unknown; operational output ('show ntp status') was not collected or did not contain synchronization evidence.",
  "error_code": "INSUFFICIENT_EVIDENCE",
  "remediation": null
}
```
