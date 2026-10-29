# CISGuard device engine

Independently installable Phase-1 device SDK for deterministic synthetic fixture replay
and canonical normalization. It has no API, database, Redis, credentials, live network
transport, device write path, CIS policy evaluation, findings, or scoring.

The Cisco IOS parser is deliberately bounded to the included synthetic fixtures. It is
not evidence that Cisco routers or switches are supported.

## Install and test on Windows PowerShell

```powershell
cd C:\cis-compliance-auditor\services\device-engine
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
.\.venv\Scripts\python.exe -m pytest
.\.venv\Scripts\python.exe -m ruff check .
```

Core fixture replay requires only Pydantic. Optional dependencies are declared but not
needed or imported for fixture operation:

```powershell
# Install only when a later authorized phase needs them.
.\.venv\Scripts\python.exe -m pip install -e ".[network]"
.\.venv\Scripts\python.exe -m pip install -e ".[parsing]"
# Or both groups:
.\.venv\Scripts\python.exe -m pip install -e ".[phase1]"
```

Installing those libraries does not establish vendor support.

Optional authorized WinRM transport uses `pywinrm` and is not needed for offline or
local collection:

```powershell
.\.venv\Scripts\python.exe -m pip install -e ".[windows-remote]"
.\.venv\Scripts\python.exe -m pip install -e ".[linux-remote]"
```

## CLI

```powershell
.\.venv\Scripts\python.exe -m cisguard_device --help
.\.venv\Scripts\python.exe -m cisguard_device capabilities
.\.venv\Scripts\python.exe -m cisguard_device self-test

.\.venv\Scripts\python.exe -m cisguard_device probe --fixture fixtures\cisco_ios\secure\manifest.json
.\.venv\Scripts\python.exe -m cisguard_device collect --fixture fixtures\cisco_ios\secure\manifest.json
.\.venv\Scripts\python.exe -m cisguard_device collect --fixture fixtures\cisco_ios\weak\manifest.json
.\.venv\Scripts\python.exe -m cisguard_device collect --fixture fixtures\cisco_ios\unknown\manifest.json

# Phase-2 synthetic Windows captures (work on non-Windows hosts)
.\.venv\Scripts\python.exe -m cisguard_device windows-probe `
  --fixture fixtures\windows\windows11_enterprise_secure\manifest.json
.\.venv\Scripts\python.exe -m cisguard_device windows-collect --transport offline `
  --fixture fixtures\windows\windows11_enterprise_secure\manifest.json
.\.venv\Scripts\python.exe -m cisguard_device windows-collect --transport offline `
  --fixture fixtures\windows\windows11_standalone_weak\manifest.json
.\.venv\Scripts\python.exe -m cisguard_device windows-collect --transport offline `
  --fixture fixtures\windows\server2019_unknown\manifest.json
```

Explicit local collection—never run by tests and never auto-elevated:

```powershell
.\.venv\Scripts\python.exe -m cisguard_device windows-collect --transport local `
  --org-id 11111111-1111-4111-8111-111111111111 `
  --asset-id 22222222-2222-4222-8222-222222222222 `
  --model local-windows-host --timeout 120
```

Authorized WinRM requires an HTTPS endpoint, valid server certificate, the optional
dependency, and credentials supplied by a `SecretProvider`. The development CLI
provider reads `CISGUARD_WINRM_USERNAME` and `CISGUARD_WINRM_PASSWORD` from its process
environment; production integration should inject Mandar's OpenBao-backed provider.
Passwords are never CLI arguments or logged.

## Phase-3 Linux and OpenSCAP

Offline replay works on Windows and does not require Linux, SSH or OpenSCAP:

```powershell
.\.venv\Scripts\python.exe -m cisguard_device linux-collect --transport offline `
  --fixture fixtures\linux\ubuntu2004_secure\manifest.json
.\.venv\Scripts\python.exe -m cisguard_device linux-collect --transport offline `
  --fixture fixtures\linux\ubuntu2204_secure\manifest.json
.\.venv\Scripts\python.exe -m cisguard_device linux-collect --transport offline `
  --fixture fixtures\linux\rhel8_secure\manifest.json
.\.venv\Scripts\python.exe -m cisguard_device linux-collect --transport offline `
  --fixture fixtures\linux\rhel9_secure\manifest.json

.\.venv\Scripts\python.exe -m cisguard_device scap-ingest --synthetic `
  --input fixtures\openscap\synthetic-results.xml
```

Explicit local collection requires a supported Linux host and Python 3.11. It never
uses sudo:

```bash
python -m cisguard_device linux-collect --transport local \
  --org-id 11111111-1111-4111-8111-111111111111 \
  --asset-id 22222222-2222-4222-8222-222222222222 --timeout 120
```

Authorized SSH requires Paramiko, a populated `known_hosts` file, Python 3.11 on the
target, and credentials from an injected secret provider or runtime environment. Unknown
host keys are rejected; passwords are never CLI arguments.

```bash
python -m cisguard_device linux-collect --transport ssh \
  --target authorized-linux.example --port 22 --known-hosts /secure/known_hosts \
  --org-id 11111111-1111-4111-8111-111111111111 \
  --asset-id 22222222-2222-4222-8222-222222222222
```

Explicit local OpenSCAP assessment requires preinstalled `oscap`, locally supplied
compatible content, a profile present in that content, and an existing owned output
directory. It never adds `--remediate`:

```bash
python -m cisguard_device scap-run --content /authorized/content.xml \
  --profile authorized_profile_id --output ./owned-output/results.xml \
  --platform rhel_9 --timeout 900
```

`candidates`, `execute`, and `verify` are typed unavailable boundaries. `simulate` is an
offline Phase-8 boundary: it accepts one explicit JSON input and an explicit backend choice;
it has no transport or write path.
`execute` always returns `LIVE_WRITE_BLOCKED` in Phase 1.

Successful commands emit one JSON document on stdout. Failed machine commands also emit
one structured JSON error on stdout, put a short diagnostic on stderr, and exit nonzero.
Argparse help remains human-readable.

## Phase-8 offline simulation

```powershell
.\.venv\Scripts\python.exe -m cisguard_device simulate `
  --input .\simulation-input.json --backend custom
.\.venv\Scripts\python.exe -m cisguard_device simulate `
  --input .\simulation-input.json --backend batfish
```

The input contains a `FactsEnvelope`, a content-bound `RemediationCandidate`, contracts and
their canonical `contracts_hash`; topology, when present, must include its `topology_hash`.
`custom` evaluates only three bounded effects: disable local HTTP, set VTY timeout, and
shutdown an interface on explicitly available modeled paths. `batfish` deliberately returns
`UNSUPPORTED` until a real snapshot/service integration exists; it never falls back to custom.

## Phase 9 execution safety

The CLI `execute` remains `LIVE_WRITE_BLOCKED`. The importable coordinator is fake-device-tested
only and requires injected approval, fresh collection, backup, simulation, secrets, durable
lock/journal, executor, and independent verifier. Preview-only catalog templates stay blocked.

## Offline verification comparison

```powershell
.\.venv\Scripts\python.exe -m cisguard_device offline-compare --before fixtures\cisco_ios\secure\expected.json --after fixtures\cisco_ios\weak\expected.json
```

This is an offline fact comparison only, never live post-fix verification. Live TCP/HTTP/SSH
probes remain unavailable pending authorized provider integrations.

## Fixture semantics

Each manifest is explicitly synthetic and declares scope, illustrative (unvalidated)
version, expected normalized JSON, and capability expectations. The runner validates
platform selection and rejects path traversal, missing files, invalid UTF-8, empty
input, malformed manifests, and inputs over the configurable default 1 MiB limit.

SHA-256 is computed over exact source bytes before decoding. Normalized facts retain
line references. VTY blocks remain separate. Configuration presence does not prove
operational state: NTP synchronization, syslog reachability, effective exposure, and
SSH key authentication remain unknown.

## Phase 4 firewall replay

`firewall-probe` and `firewall-collect --transport offline` replay synthetic FortiOS,
Cisco ASA, Cisco FTD/FMC, and Check Point Management captures. Live compatibility is
not claimed; ASA's fixed SSH SDK path is mock-tested only. See the device documentation.

## Phase 5 vendor-shaped replay

Use the existing editable virtualenv; no `PYTHONPATH` is required:

```powershell
.\.venv\Scripts\python.exe -m cisguard_device device-collect --transport offline `
  --fixture fixtures\remaining\sophos_firewall\secure\manifest.json
.\.venv\Scripts\python.exe -m cisguard_device device-collect --transport offline `
  --fixture fixtures\remaining\palo_alto_panos\secure\manifest.json
.\.venv\Scripts\python.exe -m cisguard_device device-collect --transport offline `
  --fixture fixtures\remaining\cisco_router\secure\manifest.json
.\.venv\Scripts\python.exe -m cisguard_device device-collect --transport offline `
  --fixture fixtures\remaining\cisco_switch\secure\manifest.json
```

These parse bounded raw XML or IOS/IOS-XE text sources. Live transport, Panorama, and
NX-OS are unsupported; no fixture is silently substituted.

## Phase 7 preparation

`.\.venv\Scripts\python.exe -m cisguard_device remediation-catalog` lists fixture-tested,
no-write Cisco preview templates. Candidate generation, backup handling, and recovery
specifications are SDK preparation only; execution and recovery execution remain blocked.

## Phase 6 network predicates & offline snapshot import

Phase 6 implements deterministic predicate evaluation for M20–M33 network controls and
safe offline import of configuration exports:

```powershell
# Offline import of a Cisco IOS running configuration
.\.venv\Scripts\python.exe -m cisguard_device network-import `
  --file fixtures\network\import_cisco\running-config.txt `
  --source-type cisco_ios_running_config `
  --platform cisco_router `
  --org-id 11111111-1111-4111-8111-111111111111 `
  --asset-id 22222222-2222-4222-8222-222222222222 `
  --completeness complete `
  --capture-timestamp 2026-10-29T00:00:00Z

# Evaluate device controls against typed policy
.\.venv\Scripts\python.exe -m cisguard_device network-evaluate `
  --fixture fixtures\network\cisco_router_secure\manifest.json `
  --policy-json '{"session_timeout_seconds": 300}'
```

All 21 predicate results (`DEV-M20-001` through `DEV-M33-004`) return typed `PredicateResult`
objects. Mandar's central policy engine remains responsible for official CIS benchmark
rule mapping, policy packs, scoring, and persistence.
