# BaselineGuard Phase 5 Review: Security Graph & Cross-Layer Risk Screens

- **Author:** Apoorva (Frontend Owner)
- **Branch:** `feat/apoorva-web`
- **Product:** BaselineGuard
- **Tagline:** “audit every device against CIS benchmarks. Know what’s wrong, why, and how to fix it.”
- **Verification Date:** 2026-10-29

---

## 1. Feature ID Mapping & Implementation Status

| Feature ID | Scope Description | Status | Implementation Details & Test Evidence |
|------------|-------------------|--------|----------------------------------------|
| **I01** | Interactive Security Graph Canvas & Accessible Fallback | **DONE** | Interactive Cytoscape.js canvas rendering 15 typed nodes (`asset`, `subnet`, `interface`, `service`, `finding`) and 13 evidence-backed directed edges (`routes_to`, `allows`, `violates`, `listens_on`). Includes zoom, pan, fit-to-viewport, node selection, evidence drill-down drawer, and a keyboard-accessible table view fallback. Tested in `phase5.test.tsx` (Tests 01, 02, 03, 06, 07). |
| **I02** | Cross-Device Correlated Risk Scenarios | **DONE** | Correlates findings across perimeter, network, and application layers into unified attack scenarios with source finding tags, affected assets, and risk severity scores. Tested in `phase5.test.tsx` (Test 05). |
| **I03** | Interactive Path Explorer & Reachability Tracing | **DONE** | Directed Dijkstra path tracing between selectable source and target nodes with active path highlighting (`path-active`), hop-by-hop traversal breakdown, and clear path controls. Tested in `phase5.test.tsx` (Test 08). |
| **I04** | Root-Cause Causal Sequence & Business Impact | **DONE** | Displays ordered multi-hop causal sequence timelines explaining lateral movement progression, alongside concrete business impact narratives and confidence ratings. Tested in `phase5.test.tsx` (Test 05). |
| **I05** | Missing Topology & Model Uncertainty Disclaimers | **DONE** | Displays topology coverage percentage (95% COVERAGE), explicit uncertainty notices for unassessed subnets (`10.200.0.0/16`), and strict invariant that unsupported reachability paths are NEVER reported as verified. Tested in `phase5.test.tsx` (Tests 04, 08). |

---

## 2. Core Architectural & Security Invariants Verified

1. **Uncertainty & Incomplete Topology Invariant (I05)**:
   - Partial or unobserved network segments are explicitly demarcated as conditional.
   - For example, subnet `10.200.0.0/16` is flagged with a warning banner: *"Unassessed subnet segments are marked conditional; lateral movement risk may be understated until all switches and subnets complete baseline audits."*
   - Tested and verified in `phase5.test.tsx` (Test 04).

2. **Strict Non-Fabrication of Traversable Paths (I03, I05)**:
   - When no verified directed traversal path exists under current firewall rules, the path explorer outputs: *"No verified traversal path exists between {source} and {target} under current firewall rules and topology."*
   - It **NEVER** fabricates or presents an unproven reachability hypothesis as a verified path.
   - Tested and verified in `phase5.test.tsx` (Test 08).

3. **Full Keyboard & Screen-Reader Accessibility Fallback (I01)**:
   - The interactive canvas includes a one-click toggle to `Accessible Table View (I01)`.
   - The table view provides complete tabular inspection of all Topology Nodes and Evidence-Backed Relationship Edges with accessible ARIA labels, semantic tables, and deterministic "Locate in Graph" actions.
   - Tested and verified in `phase5.test.tsx` (Tests 02, 06).

4. **Zero AI/LLM Runtime Hallucination**:
   - Zero runtime AI/ML/LLM APIs, zero third-party graph subscriptions, and zero client-side fabricated topology inferences.
   - Graph models and risk correlation chains are deterministic and backed by verified audit findings.

---

## 3. Test & Verification Summary

- **TypeScript Compilation (`tsc --noEmit`)**: 0 errors across all workspace files.
- **Vitest Test Suite**: 69/69 tests passing across 9 test suites.
  - `src/test/phase5.test.tsx`: 8/8 tests passed.
  - `src/test/phase4.test.tsx`: 10/10 tests passed.
  - `src/test/phase3.test.tsx`: 11/11 tests passed.
  - `src/test/routes.test.tsx`: 19/19 tests passed.
  - `src/test/assets_phase2.test.tsx`: 6/6 tests passed.
  - `src/test/auth_phase2.test.tsx`: 5/5 tests passed.
  - `src/test/orgs_phase2.test.tsx`: 3/3 tests passed.
  - `src/test/navigation.test.tsx`: 3/3 tests passed.
  - `src/test/states.test.tsx`: 4/4 tests passed.
- **Production Build (`vite build`)**: Clean production bundle generated in 9.96s (`dist/index.html`, `dist/assets/`).
- **Git Whitespace & Diff Check (`git diff --check`)**: Clean, 0 whitespace violations.
