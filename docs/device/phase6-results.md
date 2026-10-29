# Phase 6 Results: Network Predicates & Offline Import

## Overview

Phase 6 implements evidence-aware, deterministic device-specific predicates for mandatory network controls (M20–M33) and a secure, validated offline import engine (E10).

The evaluation boundary strictly preserves Mandar's ownership of central policy packs, benchmark mapping, applicability filtering, scoring, and persistence. The `cisguard_device` package evaluates device facts deterministically to produce candidate evidence and predicate results (`PredicateResult`), and safely imports offline device snapshots (`import_offline_file`).

## Implementation Summary

### 1. Offline Import Engine (E10)
- **Module:** `cisguard_device.offline_import`
- **Supported Source Types:**
  - `cisco_ios_running_config` (Cisco router and Cisco managed switch)
  - `panos_xml` (Palo Alto PAN-OS)
  - `sophos_xml` (Sophos Firewall)
  - `windows_capture_json` (Windows 11 Enterprise/Standalone, Windows Server 2019)
  - `linux_capture_json` (Ubuntu 20.04/22.04 LTS, RHEL 8/9)
  - `firewall_capture_json` (Fortinet FortiOS, Cisco ASA, Cisco FTD/FMC, Check Point)
- **Safety & Sanitization:**
  - Input size validated against configurable limit (default 4 MiB, rejects ≤ 0).
  - Strict metadata validation via `OfflineImportMetadata`.
  - Disallows `live_collection` provenance for offline imports.
  - Requires explicit `completeness` (`complete`, `partial`, `unknown`).
  - Redacts sensitive attributes (passwords, secrets, hashes, community strings, raw configs).
  - Superseded: see `phase6-corrections.md` for explicit unknown source-capture time and labelled import-time provenance.

### 2. Network Predicate Evaluators (M20–M33)
- **Module:** `cisguard_device.network_predicates`
- **Check IDs Implemented:** 21 distinct checks (`DEV-M20-001` through `DEV-M33-004`).
- **Feature Groups:**
  - **Management Controls (M20–M21, Feature E05):**
    - `DEV-M20-001`: Telnet disabled across all VTY lines. Complete VTY range (0–15) verified.
    - `DEV-M21-001`: HTTP server disabled (`no ip http server`).
    - `DEV-M21-002`: SSH version 2 configured.
    - `DEV-M21-003`: SSH key-only authentication configured (rejects `login local` and password methods).
    - `DEV-M21-004`: VTY session timeout within organizationally supplied threshold (`session_timeout_seconds`).
  - **ACL & Firewall Controls (M22–M25, Feature E06):**
    - `DEV-M22-001`: Absence of broadly permissive rules (`permit ip any any`) in bound ACLs.
    - `DEV-M23-001`: Absence of broad sensitive-port exposures (ports 22, 23, 80, 443, 3389).
    - `DEV-M24-001`: ACL rule shadowing detection with full match-set containment.
    - `DEV-M25-001`: Default-deny policy verification on bound interfaces.
  - **Switch Security Controls (M26–M30, Feature E07):**
    - `DEV-M26-001`: Designated-unused ports administratively shut down.
    - `DEV-M27-001`: Port security enabled on applicable access switch ports.
    - `DEV-M28-001`: DHCP snooping enabled and active on required VLANs.
    - `DEV-M29-001`: Dynamic ARP Inspection (DAI) active on required VLANs.
    - `DEV-M30-001`: VLAN 1 not utilized for active management addressing.
  - **Telemetry Controls (M31–M33, Feature E08):**
    - `DEV-M31-001`: Remote syslog server configured.
    - `DEV-M32-001`: NTP servers configured.
    - `DEV-M32-002`: Operational NTP synchronization verified ('Clock is synchronized').
    - `DEV-M33-001`: SNMPv3 user configured.
    - `DEV-M33-002`: Insecure SNMPv1/v2c communities absent.
    - `DEV-M33-003`: Default community strings (`public`, `private`) absent. Community strings never logged or exposed.
    - `DEV-M33-004`: SNMPv3 user configured with `authPriv` mode where observable.

### 3. Partial Capture Downgrade & Honesty
- Any capture with `completeness in {"partial", "unknown"}` automatically downgrades absence-of-bad-setting claims from `PASS` to `NOT_ASSESSED` with `error_code="INCOMPLETE_CAPTURE"`.
- A missing fact or unverified state produces `NOT_ASSESSED` with a structured `error_code`, never an assumed `PASS`.

### 4. CLI Extensions
- `offline-import` (alias `network-import`): Imports device configuration text or JSON snapshot into a `FactsEnvelope`.
- `evaluate_device` (alias `network-evaluate`): Evaluates a `FactsEnvelope` against typed `NetworkControlPolicy` JSON. Exits 0 on completion even when findings contain FAILs.
- `capabilities`: Updated to report `PHASE6_PARTIAL` for `cisco_router` and `cisco_managed_switch`.

## Test and Quality Status

> **Correctness supersession:** The historical E05/E06/E07/E08 feature-group labels,
> fixed VTY 0–15 assertion, and `login local` FAIL statement above are superseded by
> `phase6-corrections.md`. The actual predicate map is M20–M33, and the full corrected
> suite result is 244 passed.

- **Core Phase 6 / Replay Tests:** 137 passed in test suite.
- **`tests/test_network_predicates.py`:** 83 passed. Parameterized PASS, FAIL, NOT_ASSESSED, NOT_APPLICABLE for all 21 checks, plus edge cases for ACL shadowing, non-contiguous wildcards, complexity limits, and NAT/IPv6 blockers.
- **`tests/test_offline_import.py`:** 21 passed. Tested size limits, secret scrubbing, platform mismatches, sentinel timestamps, and partial capture downgrades.
- **`tests/test_cli.py`:** 13 passed. Tested capabilities, self-test, imports, evaluations, and unsupported operation rejection.
- **`tests/test_remaining_devices.py`:** 17 passed. Tested parser outputs, structured ACLs, secret redaction, and missing source error handling.
- **Linter:** `ruff check src/ tests/` passed with 0 errors.
- **Diff hygiene:** `git diff --check` passed with 0 errors.
