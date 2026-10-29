# Offline Device Snapshot Import (E10)

This document specifies the offline device import subsystem implemented in `cisguard_device.offline_import`.

## Purpose and Scope

The offline import engine allows users and automation workflows to ingest offline configuration exports, tech-support dumps, API captures, or firewall XML exports safely into canonical `FactsEnvelope` models without contacting physical network devices or requiring live credentials.

## Supported Source Types and Target Platforms

| Source Type (`source_type`) | Target Platforms (`platform`) | Expected Input Format |
|---|---|---|
| `cisco_ios_running_config` | `cisco_router`, `cisco_switch` | Plain text Cisco IOS / IOS-XE configuration. Optional operational `show` output via `--operational` or `operational_path`. |
| `panos_xml` | `palo_alto_panos` | XML export from Palo Alto PAN-OS 10.2 / 11.0. |
| `sophos_xml` | `sophos_firewall` | XML export from Sophos Firewall API 1905.2. |
| `windows_capture_json` | `windows_11_enterprise`, `windows_11_standalone`, `windows_server_2019` | JSON structure adhering to Phase 2 Windows collected schema. |
| `linux_capture_json` | `ubuntu_20_04_lts`, `ubuntu_22_04_lts`, `rhel_8`, `rhel_9` | JSON structure adhering to Phase 3 Linux collected schema. |
| `firewall_capture_json` | `fortinet_fortios`, `cisco_asa`, `cisco_ftd`, `check_point` | JSON structure adhering to Phase 4 firewall collected capture format. |

---

## Import Metadata (`OfflineImportMetadata`)

To prevent ambiguous provenance or untracked state, every import requires strict metadata:

```python
class OfflineImportMetadata(StrictModel):
    source_type: str
    platform: str
    org_id: UUID
    asset_id: UUID
    capture_timestamp: datetime | None = None
    provenance: EvidenceProvenance = EvidenceProvenance.USER_SUPPLIED_CAPTURE
    completeness: Literal["complete", "partial", "unknown"]
    collector_version: str = "0.1.0"
    model: str | None = None
```

### Constraints & Rules:
1. **Provenance Enforcement:** `provenance` cannot be set to `LIVE_COLLECTION`. Offline imports must specify either `USER_SUPPLIED_CAPTURE` or `SYNTHETIC_FIXTURE`.
2. **Mandatory Completeness:** `completeness` has **no default**. Callers must explicitly declare whether the snapshot is `complete`, `partial`, or `unknown`.
3. **Capture Timestamp Integrity:**
   - If `capture_timestamp` is provided, it must be an aware ISO-8601 UTC timestamp and is preserved verbatim in `collected_at`.
   - If `capture_timestamp` is `None` (omitted), the import engine assigns a fixed sentinel epoch (`2000-01-01T00:00:00Z`) and records a canonical warning error `CAPTURE_TIMESTAMP_UNKNOWN`.
   - **Crucial Rule:** The import time is never used as the capture timestamp, avoiding false-freshness claims.
4. **Input Size Boundaries:** File size is validated against `max_bytes` (default 4 MiB). Empty files (0 bytes) or values $\le 0$ are rejected with `INVALID_SIZE_LIMIT` or `FILE_EMPTY`.

---

## Secret Sanitization & Privacy

The offline import engine automatically cleanses sensitive parameters before producing the `FactsEnvelope`:
- Passwords, cryptographic pre-shared keys, private keys, hashes, and authorization tokens are redacted or omitted.
- SNMP community strings: Communities are stripped from `snmp.communities` or set to `"<redacted>"`. Default name presence (`public`, `private`) is evaluated as a boolean flag without ever exposing the raw string value.
- Raw sensitive configuration text is not stored in the final structured facts dictionary.

---

## Encrypted Storage Dependency

The `FactsEnvelope` produced by `import_offline_file` is an in-memory or localized transport object. In accordance with the CISGuard 360 architecture:
- Long-term persistence, tenant isolation, and encrypted storage of raw device snapshots are owned centrally by Mandar's persistence and policy pipeline.
- Local disk caches and artifacts generated during evaluation must be maintained within access-controlled directories.
