# BaselineGuard Phase 4 Review: Policy Library, Overrides, Exceptions & Manual Audits

- **Author:** Apoorva (Frontend Owner)
- **Branch:** `feat/apoorva-web`
- **Product:** BaselineGuard
- **Tagline:** “audit every device against CIS benchmarks. Know what’s wrong, why, and how to fix it.”
- **Verification Date:** 2026-10-29

---

## 1. Feature ID Mapping & Implementation Status

| Feature ID | Scope Description | Status | Implementation Details & Test Evidence |
|------------|-------------------|--------|----------------------------------------|
| **M17** | Policy Library Display & Versioning | **DONE** | Displays versioned CIS benchmark packs (`cis-cisco-ios-v4`, `cis-windows-11-v3`) with publisher attribution, total rule counts, platform family badges, and Profile Level badges. Tested in `phase4.test.tsx` (Test 01). |
| **M18** | Benchmark Values vs. Org Overrides | **DONE** | Control detail modal and table compare official CIS benchmark expected values with organization-specific customized thresholds. Tested in `phase4.test.tsx` (Test 02). |
| **M19** | Custom Baseline Overrides & Conflict Prevention | **DONE** | Schema-validated override creation (`policyOverrideFormSchema`) with mandatory control ID, target value, and at least 10 chars rationale. Tested in `phase4.test.tsx` (Test 05). |
| **E11** | Profile Level 1 vs Level 2 Filtering | **DONE** | Interactive profile level toggle (`ALL`, `LEVEL_1`, `LEVEL_2`) dynamically filters rules according to enterprise hardening posture. Tested in `phase4.test.tsx` (Test 03). |
| **E12** | Human Attestation & Manual Review Queue | **DONE** | Queue for human-verified controls (`PENDING`, `ATTESTED_PASS`, `ATTESTED_FAIL`). Sign-off workflow enforces mandatory evidence artifact URI and reviewer notes. Tested in `phase4.test.tsx` (Test 08). |
| **E14** | Time-Boxed Policy Exceptions with Expiry | **DONE** | Operational exceptions with countdown badges and status filters (`ALL`, `ACTIVE`, `EXPIRED`). Tested in `phase4.test.tsx` (Test 06). |
| **E20** | Benchmark Version Diff & Upgrade Impact | **DONE** | Rule-by-rule diffing (+added, -deprecated, ~modified) with predicted compliance delta (-3.8%) and affected device count (4). Tested in `phase4.test.tsx` (Test 10). |
| **I19** | Zero Fabricated Upgrades / Honest Missing-Data State | **DONE** | Displays explicit missing-data notice for packs without upgrade history; zero fabricated diffs or synthetic breaking changes. Tested in `phase4.test.tsx` (Test 10). |

---

## 2. Core Architectural & Security Invariants Verified

1. **Non-Negotiable Exception Invariant (E14)**:
   - Creating or applying a policy exception attaches an operational tolerance overlay to the target finding.
   - It **NEVER** turns a failed finding (`FAIL`) into a `PASS` and never deletes the underlying finding.
   - Tested and verified in `phase4.test.tsx` (Test 07).

2. **Role-Based Authorization Separation**:
   - Read-only auditors (`AUDITOR`, `VIEWER`) cannot create overrides or request exceptions; action buttons are disabled with explicit "Read-Only Auditor Mode" indicators.
   - Privileged mutations are restricted to `OWNER`, `ADMIN`, and `APPROVER` personas.
   - Tested and verified in `phase4.test.tsx` (Test 09).

3. **Mandatory Evidence for Human Attestation (E12)**:
   - Controls requiring physical inspection or external audit validation (e.g., physical locks, tamper seals, SOC2 certificates) require an immutable evidence artifact URI (e.g., `supabase://...`).
   - Sign-off without an evidence URI is blocked with strict validation feedback.
   - Tested and verified in `phase4.test.tsx` (Test 08).

4. **Zero AI/LLM Hallucination & Synthetic Data Labeling**:
   - Zero runtime AI/ML/LLM APIs or paid auditing services.
   - All benchmark rules are synthetic demonstration models clearly labeled `DEMO` with zero reproduction of copyrighted CIS publication texts.

---

## 3. Test & Verification Summary

- **TypeScript Compilation (`tsc --noEmit`)**: 0 errors across all workspace files.
- **Vitest Test Suite**: 61/61 tests passing across 8 test suites.
  - `src/test/phase4.test.tsx`: 10/10 tests passed.
  - `src/test/phase3.test.tsx`: 11/11 tests passed.
  - `src/test/routes.test.tsx`: 19/19 tests passed.
  - `src/test/assets_phase2.test.tsx`: 6/6 tests passed.
  - `src/test/auth_phase2.test.tsx`: 5/5 tests passed.
  - `src/test/orgs_phase2.test.tsx`: 3/3 tests passed.
  - `src/test/navigation.test.tsx`: 3/3 tests passed.
  - `src/test/states.test.tsx`: 4/4 tests passed.
- **Production Build (`vite build`)**: Transformed 2519 modules; build completed cleanly in 8.52s.
- **Git Whitespace & Diff Check (`git diff --check`)**: Clean, 0 whitespace violations.
