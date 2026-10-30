"""Generate deterministic JSON Schema/OpenAPI from the single Pydantic source."""
import argparse
import inspect
import json
import re
from pathlib import Path

import yaml

import models
from route_catalog import ROUTES

ROOT = Path(__file__).resolve().parent


def exported_models():
    return {name: cls for name, cls in vars(models).items()
            if inspect.isclass(cls) and issubclass(cls, models.WireModel)
            and cls.__module__ == models.__name__
            and name not in {"WireModel", "Versioned", "Scoped", "Envelope", "Page"}}


def generate_outputs():
    outputs = {}
    components = {}
    for name, cls in sorted(exported_models().items()):
        schema = cls.model_json_schema(mode="validation")
        schema["$schema"] = "https://json-schema.org/draft/2020-12/schema"
        outputs[f"json-schemas/{name}.schema.json"] = json.dumps(schema, indent=2, sort_keys=True) + "\n"
        schema.pop("$schema")
        definitions = schema.pop("$defs", {})
        for key, value in {**definitions, name: schema}.items():
            rewritten = json.loads(json.dumps(value).replace("#/$defs/", "#/components/schemas/"))
            if key in components and components[key] != rewritten:
                raise ValueError(f"Conflicting schema: {key}")
            components[key] = rewritten
    spec = {
        "openapi": "3.1.0",
        "info": {"title": "CISGuard 360 contract proposal", "version": "1.0.0",
                 "description": "Phase 0 specification. Not a deployed API. Three-owner approval pending."},
        "servers": [{"url": "/api/v1"}],
        "security": [{"SupabaseBearer": []}],
        "paths": {},
        "components": {"securitySchemes": {"SupabaseBearer": {"type": "http", "scheme": "bearer", "bearerFormat": "JWT"}},
                       "schemas": dict(sorted(components.items()))},
    }
    for method, path, request, response, many, permission, features in ROUTES:
        params = [{"name": "X-Org-ID", "in": "header", "required": True,
                   "description": "Selected tenant; validate active membership. Never trust as authorization.",
                   "schema": {"type": "string", "format": "uuid"}}]
        for p in re.findall(r"{([^}]+)}", path):
            params.append({"name": p, "in": "path", "required": True, "schema": {"type": "string", "format": "uuid"}})
        if many:
            params.extend([
                {"name": "cursor", "in": "query", "schema": {"type": "string", "maxLength": 2048}},
                {"name": "limit", "in": "query", "schema": {"type": "integer", "minimum": 1, "maximum": 100, "default": 50}},
            ])
        filters = {"/assets": {"tag": "string", "platform": "string", "owner_id": "uuid"},
                   "/findings": {"scan_id": "uuid", "asset_id": "uuid", "status": "AssessmentStatus", "severity": "severity", "control_id": "string", "policy_pack_id": "uuid"},
                   "/trends": {"policy_version": "string", "profile": "string"},
                   "/policies/{policy_pack_id}/diff": {"from_version": "string", "to_version": "string"}}
        for field, kind in filters.get(path, {}).items():
            if method != "GET":
                continue
            schema = ({"$ref": "#/components/schemas/AssessmentStatus"} if kind == "AssessmentStatus" else
                      {"type": "string", "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW"]} if kind == "severity" else
                      {"type": "string", "format": "uuid"} if kind == "uuid" else {"type": "string", "maxLength": 256})
            params.append({"name": field, "in": "query", "required": path.endswith("/diff"), "schema": schema})
        if method != "GET":
            params.append({"name": "Idempotency-Key", "in": "header", "required": True, "schema": {"type": "string", "format": "uuid"}})
        data = {"$ref": f"#/components/schemas/{response}"}
        if many:
            data = {"type": "object", "additionalProperties": False, "required": ["items", "next_cursor"],
                    "properties": {"items": {"type": "array", "items": data}, "next_cursor": {"type": ["string", "null"]}}}
        envelope = {"type": "object", "additionalProperties": False, "required": ["schema_version", "data", "meta"],
                    "properties": {"schema_version": {"const": "1.0.0", "type": "string"}, "data": data,
                                   "meta": {"$ref": "#/components/schemas/Meta"}}}
        status = "202" if response == "JobReceipt" or (method == "POST" and response in {"Scan", "Change"}) else "201" if method == "POST" else "200"
        responses = {status: {"description": "Accepted job" if status == "202" else "Success",
                              "content": {"application/json": {"schema": envelope}}}}
        for code, description in {"401": "Invalid authentication", "403": "Permission or MFA denied", "404": "Not found in authorized scope", "409": "Conflict or safety gate", "422": "Invalid request", "429": "Rate limited", "503": "Dependency unavailable"}.items():
            responses[code] = {"description": description, "content": {"application/json": {"schema": {"$ref": "#/components/schemas/APIError"}}}}
        operation = {"operationId": method.lower() + "_" + re.sub(r"[^a-z0-9]+", "_", path.lower()).strip("_"),
                     "summary": f"{method} {path}", "parameters": params, "responses": responses,
                     "x-permission": permission, "x-feature-ids": features,
                     "x-tenant-enforcement": "backend membership + resource scope + RLS",
                     "x-implementation-status": "UNTESTED"}
        if request:
            operation["requestBody"] = {"required": True, "content": {"application/json": {"schema": {"$ref": f"#/components/schemas/{request}"}}}}
        spec["paths"].setdefault(path, {})[method.lower()] = operation
    outputs["openapi.yaml"] = yaml.safe_dump(spec, sort_keys=False, allow_unicode=False)
    return outputs


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    stale = []
    for relative, content in generate_outputs().items():
        path = ROOT / relative
        if args.check:
            if not path.exists() or path.read_text(encoding="utf-8") != content:
                stale.append(relative)
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8", newline="\n")
    if stale:
        raise SystemExit("Stale generated contracts: " + ", ".join(stale))
    print("Contracts match models" if args.check else "Generated contracts")


if __name__ == "__main__":
    main()
