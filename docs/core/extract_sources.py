"""Rebuild the source audit using pypdf/pdfplumber (development tooling only)."""
import argparse
import csv
import hashlib
import json
import re
from pathlib import Path

import pdfplumber
from pypdf import PdfReader

HERE = Path(__file__).resolve().parent


def ownership(fid):
    prefix, number = fid[0], int(fid[1:])
    if prefix == "M":
        if number <= 12 or number in (14, 15):
            return "collection", "Vidhi", ["Vidhi", "Mandar"], ["Apoorva"]
        if number == 34:
            return "dashboard", "Apoorva", ["Apoorva", "Mandar"], ["Vidhi"]
        if number in (13,):
            return "orchestration", "Mandar", ["Mandar", "Vidhi", "Apoorva"], []
        if number <= 33:
            return "policy", "Mandar", ["Mandar", "Vidhi"], ["Apoorva"]
        if number == 38:
            return "reporting", "Mandar", ["Mandar", "Apoorva"], ["Vidhi"]
        return "results", "Mandar", ["Mandar", "Apoorva", "Vidhi"], []
    if prefix == "E":
        domains = {1:"inventory",2:"collection",3:"inventory",4:"orchestration",5:"history",6:"evidence",7:"history",8:"orchestration",9:"orchestration",10:"collection",11:"policy",12:"policy",13:"risk",14:"policy",15:"identity",16:"identity",17:"secrets",18:"orchestration",19:"evidence",20:"policy",21:"hardening",22:"simulation",23:"approvals",24:"recovery",25:"verification",26:"integrations",27:"integrations",28:"reporting",29:"dashboard",30:"integrations"}
        domain = domains[number]
        owner = "Apoorva" if number == 29 else "Vidhi" if number in (2, 24) else "Mandar"
        workers = [owner]
        for person in ["Mandar", "Apoorva"] + (["Vidhi"] if number in (2,5,6,9,10,17,18,21,22,24,25) else []):
            if person not in workers:
                workers.append(person)
        return domain, owner, workers, [p for p in ["Mandar","Apoorva","Vidhi"] if p not in workers]
    domain = "risk" if number <= 5 or number == 17 else "planning" if number <= 10 else "simulation" if number in (11,13) else "approvals" if number in (12,14,15) else "verification" if number == 16 else "evidence" if number == 18 else "policy"
    owner = "Vidhi" if number in (11,16) else "Mandar"
    return domain, owner, [owner] + [p for p in ["Mandar","Apoorva","Vidhi"] if p != owner], []


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--prd", type=Path, required=True)
    parser.add_argument("--stack", type=Path, required=True)
    args = parser.parse_args()
    source_dir = HERE / "sources"
    source_dir.mkdir(exist_ok=True)
    manifest = []
    for kind, path in [("prd", args.prd), ("stack", args.stack)]:
        reader = PdfReader(path)
        text = "\n\n".join(f"--- PAGE {i+1} ---\n{p.extract_text()}" for i,p in enumerate(reader.pages))
        (source_dir / f"{kind}.txt").write_text(text, encoding="utf-8")
        manifest.append({"kind":kind, "supplied_filename":path.name, "page_count":len(reader.pages),
                         "sha256":hashlib.sha256(path.read_bytes()).hexdigest(),
                         "extracted_text":f"sources/{kind}.txt", "reviewed_pages":list(range(1,len(reader.pages)+1))})
    (source_dir / "manifest.json").write_text(json.dumps(manifest,indent=2)+"\n",encoding="utf-8")
    rows = []
    with pdfplumber.open(args.prd) as pdf:
        for page_number, page in enumerate(pdf.pages, 1):
            for table in page.extract_tables():
                for cells in table:
                    if cells and re.fullmatch(r"[MEI]\d{2}", cells[0] or ""):
                        fid, title, requirement, acceptance = [re.sub(r"\s+", " ", c or "").strip() for c in cells]
                        domain, accountable, responsible, consulted = ownership(fid)
                        rows.append({"id":fid,"title":title,"requirement":requirement,"acceptance_evidence":acceptance,
                                     "prd_page":page_number,"domain":domain,"accountable":accountable,
                                     "responsible":responsible,"consulted":consulted,"informed":[],
                                     "status":"UNTESTED", "phase0_status":"DONE", "evidence":[],
                                     "acceptance_test_id":f"AC-{fid}",
                                     "phase0_test":"apps/api/tests/test_contracts.py::test_feature_register"})
    expected = {f"{p}{n:02}" for p, limit in [("M",38),("E",30),("I",20)] for n in range(1,limit+1)}
    assert len(rows) == 88 and {r["id"] for r in rows} == expected
    (HERE / "feature-register.json").write_text(json.dumps(rows,indent=2,ensure_ascii=False)+"\n",encoding="utf-8")
    with (HERE / "feature-raci.csv").open("w",encoding="utf-8",newline="") as stream:
        writer = csv.writer(stream)
        writer.writerow(["ID","Feature","Domain","Accountable","Responsible","Consulted","Informed","Product status","PRD page","Acceptance test"])
        for r in rows:
            writer.writerow([r["id"],r["title"],r["domain"],r["accountable"],", ".join(r["responsible"]),", ".join(r["consulted"]),", ".join(r["informed"]),r["status"],r["prd_page"],r["acceptance_test_id"]])
    lines = ["# 88-feature ownership and source map", "", "Source: supplied PRD v1, pages 6-9. All source requirement and acceptance text is retained in `feature-register.json`.", "", "One accountable owner per feature; shared responsibility never grants permission to edit another owner's folders. R/A/C/I assignments are proposed for team review. Everyone is R or C where relevant; an empty I column is intentional. Product status UNTESTED means no product acceptance claim. Phase 0 DONE means only source registration is complete.", "", "| ID | Feature | Domain | A | R | C | Product status | Source |", "|---|---|---|---|---|---|---|---|"]
    for r in rows:
        lines.append(f"| {r['id']} | {r['title']} | {r['domain']} | {r['accountable']} | {', '.join(r['responsible'])} | {', '.join(r['consulted']) or '-'} | UNTESTED | PRD p{r['prd_page']} |")
    (HERE / "feature-raci.md").write_text("\n".join(lines)+"\n",encoding="utf-8")
    print(f"Extracted {len(rows)} exact feature rows and both complete PDFs")


if __name__ == "__main__":
    main()
