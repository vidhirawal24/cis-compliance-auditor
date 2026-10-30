# Phase 0 validation environment

Python **3.12.14** was used for local contract validation on Windows. This compatibility check covers only the Phase 0 tools; the final service dependency matrix still needs Linux integration tests. Exact installed transitive versions are recorded in `phase0-requirements.lock.txt`; no production collector/LLM dependency is installed.

From the repository root in PowerShell:

```powershell
py -3.12 -m venv infra/.venv-phase0
& infra/.venv-phase0/Scripts/python.exe -m pip install -r infra/phase0-requirements.lock.txt
& infra/.venv-phase0/Scripts/python.exe packages/contracts/v1/generate.py --check
& infra/.venv-phase0/Scripts/python.exe -m pytest -q -o cache_dir=apps/api/.pytest_cache apps/api/tests
```

On Linux, use `python3.12` and `infra/.venv-phase0/bin/python` with the same arguments. The lock was tested on Windows only. If `py` is unavailable, use an installed Python 3.12 executable. Virtual environment and caches are ignored within owned folders.

To intentionally edit a proposed contract, change models/route catalog, regenerate, inspect the diff, rebuild examples, refresh the **proposed** digest, then validate:

```powershell
& infra/.venv-phase0/Scripts/python.exe packages/contracts/v1/generate.py
& infra/.venv-phase0/Scripts/python.exe packages/contracts/v1/build_examples.py
& infra/.venv-phase0/Scripts/python.exe packages/contracts/v1/snapshot.py
```

Do not refresh snapshots to conceal an incompatible change after approval. `snapshot.py` refuses to overwrite a reviewed freeze record. All three owners must review contract evolution.

Source extraction is optional and separate: `docs/core/extract_sources.py --prd <source.pdf> --stack <source.pdf>` uses the bundled PDF runtime's pypdf/pdfplumber. Normal contract validation uses checked-in register data and requires no PDF tooling or network. No production credentials are needed.

Future infrastructure: Supabase DB/Auth/Storage/Realtime, OpenBao and Redis/Celery; Alembic application schema and Supabase RLS/grants follow the domain map. No Docker stack, migrations, credentials or running service is represented as complete in this phase.
