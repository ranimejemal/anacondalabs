"""
AegisLab - OpenAPI / Swagger Parser
=====================================
Parses an imported OpenAPI 3.x or Swagger 2.0 JSON/YAML file into a flat list
of EndpointSpec objects the scanner can test. Falls back gracefully on
malformed specs (skips bad entries rather than crashing the whole import).
"""

from __future__ import annotations

import json
from typing import Any

import yaml

from models import EndpointSpec, HttpMethod

VALID_METHODS = {"get", "post", "put", "patch", "delete"}


def load_spec(raw_text: str) -> dict:
    """Accepts raw JSON or YAML text and returns a parsed dict."""
    raw_text = raw_text.strip()
    if raw_text.startswith("{"):
        return json.loads(raw_text)
    return yaml.safe_load(raw_text)


def _is_auth_required(operation: dict, global_security: list) -> bool:
    if "security" in operation:
        return len(operation["security"]) > 0
    return len(global_security) > 0


def _sample_body(schema: dict, components: dict, _depth: int = 0) -> dict | None:
    """Builds a minimal sample request body from a JSON schema (best-effort, depth-limited)."""
    if _depth > 4 or not isinstance(schema, dict):
        return None
    if "$ref" in schema:
        ref_name = schema["$ref"].split("/")[-1]
        resolved = components.get(ref_name, {})
        return _sample_body(resolved, components, _depth + 1)

    if schema.get("type") == "object" or "properties" in schema:
        out = {}
        for prop, prop_schema in (schema.get("properties") or {}).items():
            out[prop] = _sample_value(prop_schema, components, _depth + 1)
        return out
    return None


def _sample_value(schema: dict, components: dict, depth: int) -> Any:
    if not isinstance(schema, dict):
        return "sample"
    if "$ref" in schema:
        ref_name = schema["$ref"].split("/")[-1]
        return _sample_body(components.get(ref_name, {}), components, depth + 1)
    t = schema.get("type", "string")
    if t == "string":
        return schema.get("example", "sample_string")
    if t == "integer" or t == "number":
        return schema.get("example", 1)
    if t == "boolean":
        return schema.get("example", True)
    if t == "array":
        return [_sample_value(schema.get("items", {}), components, depth + 1)]
    if t == "object":
        return _sample_body(schema, components, depth + 1) or {}
    return "sample"


def parse_openapi(spec: dict) -> list[EndpointSpec]:
    """Flattens an OpenAPI/Swagger spec's `paths` into EndpointSpec objects."""
    endpoints: list[EndpointSpec] = []
    paths = spec.get("paths", {})
    global_security = spec.get("security", [])

    # OpenAPI 3 components vs Swagger 2 definitions
    components = {}
    if "components" in spec:
        components = spec["components"].get("schemas", {})
    elif "definitions" in spec:
        components = spec["definitions"]

    for path, methods in paths.items():
        if not isinstance(methods, dict):
            continue
        for method, operation in methods.items():
            method_lower = method.lower()
            if method_lower not in VALID_METHODS or not isinstance(operation, dict):
                continue

            params = []
            for p in operation.get("parameters", []):
                if isinstance(p, dict) and "name" in p:
                    params.append(p["name"])

            body_sample = None
            request_body = operation.get("requestBody", {})
            content = request_body.get("content", {}) if isinstance(request_body, dict) else {}
            json_content = content.get("application/json", {})
            if json_content.get("schema"):
                body_sample = _sample_body(json_content["schema"], components)
            elif method_lower in ("post", "put", "patch"):
                # Swagger 2 style: body param
                for p in operation.get("parameters", []):
                    if isinstance(p, dict) and p.get("in") == "body":
                        body_sample = _sample_body(p.get("schema", {}), components)

            try:
                endpoints.append(EndpointSpec(
                    path=path,
                    method=HttpMethod(method_lower.upper()),
                    requires_auth=_is_auth_required(operation, global_security),
                    description=operation.get("summary", operation.get("description", "")),
                    params=params,
                    request_body_sample=body_sample,
                    tags=operation.get("tags", []),
                ))
            except Exception:
                # Skip malformed operation entries rather than aborting the whole import
                continue

    return endpoints
