# Mandar API boundary: Phase 0 only

This folder currently contains the typed device port and contract tests. It is not a FastAPI server and has no database or vendor connection.

The canonical models live only in `packages/contracts/v1/models.py`. Tests configure that path explicitly. Production package/import setup is a Phase 1 responsibility; do not copy the models into this folder or import Vidhi's implementation directly.

`MockDeviceEngine` returns UNSUPPORTED for collection and refuses simulation, execution and verification. Replace it through `DeviceEnginePort` only after shared contract review and consumer validation. Always validate worker result scope/correlation against the dispatch.
