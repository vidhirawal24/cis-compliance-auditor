# CISGuard device-engine final handoff

## Install and smoke test

```powershell
cd services\device-engine
.\.venv\Scripts\python.exe -m pip install --upgrade build
.\.venv\Scripts\python.exe -m build
py -m venv .wheel-smoke
.\.wheel-smoke\Scripts\python.exe -m pip install dist\cisguard_device-0.1.0-py3-none-any.whl
.\.wheel-smoke\Scripts\python.exe -m cisguard_device self-test
.\.wheel-smoke\Scripts\python.exe -m cisguard_device offline-compare --before fixtures\cisco_ios\secure\expected.json --after fixtures\cisco_ios\weak\expected.json
```

Editable development install is `pip install -e ".[dev]"`; production core is Pydantic-only.
Use `constraints.txt` for the owned, narrow dependency range. Python 3.11+ is declared; no other
OS/Python combination is claimed tested.

At the Phase-11/pre-push review, wheel build and isolated wheel smoke validation were blocked
because the local `build` module was absent and the environment disallowed dependency download.
No wheel path or installation claim is made until an approved offline wheelhouse or local build
tool is supplied.

## Verified wheel evidence (Phase 11 closeout)

On 2026-10-30, `cisguard_device-0.1.0-py3-none-any.whl` was built and installed non-editably
into the fresh `services/device-engine/.wheel-test` environment. From `C:\`, its module CLI
(`python -m cisguard_device`) produced help and a successful `self-test`; `sys.path` did not
contain the source `src` directory. The installed package includes
`scripts/windows_collect.ps1` and `scripts/linux_collect.py`.

No console-script entry point is declared in `pyproject.toml`; the supported installed CLI is
therefore `python -m cisguard_device`. Fixture corpora are deliberately external test resources,
not wheel package data: an installed-wheel fixture replay requires an explicit supplied fixture
path and must remain labeled synthetic/offline.

## Public flow and boundaries

Import `collect_fixture`, `evaluate_device`, `generate_candidates`, `simulate_what_if`,
`verify_post_fix`, `compare_normalized_facts`, and `execute_coordinated` from `cisguard_device`.
The supported flow is offline collection → bounded Cisco predicate evaluation → preview-only
candidate → custom simulation. `execute` returns `LIVE_WRITE_BLOCKED`; verification pass requires
injected trusted recollection/outcome providers. Evidence hashes are exact artifact hashes and
timestamps are UTC; unknown and partial evidence remain explicit.

CLI success is exit 0; structured machine errors exit 2; unavailable boundaries exit 3. Apoorva
must display preview-only, unknown, unsupported and synthetic provenance directly, not as secure.

## Ownership and limits

Mandar owns policy/CIS mapping, approvals, providers, persistence, alerting, storage, cipher/vault,
and any live transport. The 88 feature IDs are not complete: device-engine has only bounded partial
coverage described in `coverage-matrix.md`. OpenSCAP/ComplianceAsCode versions are absent here;
authorized content, mapping and distribution permissions remain required decisions.

Real evidence: a non-elevated Windows 11 Home diagnostic collection was validated outside the IDE
sandbox. Audit and secedit sources required unavailable privileges/elevation and remain unassessed;
this does not validate Windows 11 Enterprise benchmark applicability.

Run `python -m pytest`, `python -m ruff check .`, and `git diff --check` before review.

## Mandar MVP integration status

An isolated consumer smoke test validates the offline Cisco switch fixture flow through normalized
facts, M20-M33 predicate evidence, preview candidate, custom simulation and synthetic verification
JSON serialization. It is not Mandar worker integration. Actual worker integration and official
contract compatibility are BLOCKED because `packages/contracts/v1/` and an available worker are
absent in this checkout. See `MANDAR_INTEGRATION_HANDOFF.md` and
`MANDAR_CONTRACT_COMPATIBILITY.md`.
