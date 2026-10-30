"""Record a proposed snapshot. Never manufactures teammate sign-off."""
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def main():
    target = ROOT / "freeze.json"
    if target.exists():
        previous = json.loads(target.read_text())
        if previous["status"] != "PROPOSED" or any(r["status"] != "PENDING" for r in previous["reviews"].values()):
            raise SystemExit("Reviewed snapshots require explicit governance review before replacement")
    files = sorted(["models.py","route_catalog.py","permissions.json","openapi.yaml"] +
                   [p.relative_to(ROOT).as_posix() for folder in ("json-schemas","examples") for p in (ROOT/folder).glob("*.json")])
    digest = hashlib.sha256()
    for name in files:
        digest.update(name.encode()+b"\0"+(ROOT/name).read_bytes()+b"\0")
    record = {"schema_version":"1.0.0","status":"PROPOSED","prepared_on":"2026-10-29",
              "prepared_for":"Mandar Phase 0", "sha256":digest.hexdigest(),"files":files,
              "reviews":{person:{"status":"PENDING","review_reference":None,"reviewed_at":None} for person in ["Mandar","Apoorva","Vidhi"]}}
    target.write_text(json.dumps(record,indent=2)+"\n",encoding="utf-8")
    print("Recorded proposed contract digest:",digest.hexdigest())


if __name__ == "__main__":
    main()
