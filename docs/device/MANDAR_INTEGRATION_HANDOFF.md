# Mandar integration handoff

Install core package on Python 3.11+ with `pip install cisguard_device-0.1.0-py3-none-any.whl`.
Use the installed module CLI: `python -m cisguard_device`; no console-script entry point exists.

Public imports: `FactsEnvelope`, `NetworkControlPolicy`, `evaluate_device`,
`generate_candidates`, `preview_dry_run`, `SimulationInput`, `simulate_what_if`,
`verify_post_fix`, `compare_normalized_facts`, and `execute_coordinated`.

Optional dependencies: `pywinrm` for WinRM and `paramiko` for SSH; neither is core-imported.
Environment variables are only development remote-collector inputs: `CISGUARD_WINRM_USERNAME`,
`CISGUARD_WINRM_PASSWORD`, `CISGUARD_SSH_USERNAME`, `CISGUARD_SSH_PASSWORD`, and
`CISGUARD_SSH_KEY_FILE`. Production must inject Mandar secret providers instead.

CLI machine success is 0; structured invalid-input errors are 2; unavailable boundaries are 3.
The offline MVP flow is collection -> normalized facts -> Cisco M20-M33 predicate evidence ->
preview candidate -> custom simulation -> synthetic/offline drift. FastAPI/Celery workers should
invoke SDK functions in a worker process with explicit JSON payload validation; no live transport
or write provider is included.

Contract compatibility is BLOCKED until Mandar adds `packages/contracts/v1`; see
`MANDAR_CONTRACT_COMPATIBILITY.md`.
