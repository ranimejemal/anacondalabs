"""
AegisLab — integration test for inventory_tests.py (API9:2023 Improper
Inventory Management), run against a small purpose-built FastAPI app rather
than examples/mock_vulnerable_api.py, so the shared example (and its
documented, reproducible report numbers in README §6) stay untouched.

Spins the app up with uvicorn in a background thread for the duration of
this test module, same pattern as test_scan_modules_integration.py.
"""
import threading
import time

import httpx
import pytest
import uvicorn
from fastapi import Body, FastAPI

from api_client import SafeApiClient
from models import EndpointSpec, ScanConfig
from tests.inventory_tests import InventoryTests

MOCK_PORT = 9912
MOCK_BASE_URL = f"http://127.0.0.1:{MOCK_PORT}"

_mock_app = FastAPI()


@_mock_app.get("/api/v1/users")
async def v1_users():
    """The 'zombie' sibling of the declared /api/v2/users endpoint below."""
    return {"users": []}


@_mock_app.get("/api/v2/users")
async def v2_users():
    return {"users": []}


@_mock_app.get("/actuator/env")
async def actuator_env():
    """Deliberately-exposed config-leak endpoint, undeclared in any spec."""
    return {"DB_PASSWORD": "hunter2", "profiles": {"active": "prod"}}


@_mock_app.post("/graphql")
async def graphql(payload: dict = Body(...)):
    if "__schema" in payload.get("query", ""):
        return {"data": {"__schema": {"types": [{"name": "Query"}, {"name": "User"}]}}}
    return {"data": {}}


@pytest.fixture(scope="module")
def mock_api_server():
    config = uvicorn.Config(_mock_app, host="127.0.0.1", port=MOCK_PORT, log_level="warning")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()

    for _ in range(50):
        try:
            httpx.get(f"{MOCK_BASE_URL}/api/v2/users", timeout=0.5)
            break
        except httpx.RequestError:
            time.sleep(0.1)
    else:
        raise RuntimeError("inventory_tests mock app did not come up in time")

    yield MOCK_BASE_URL

    server.should_exit = True
    thread.join(timeout=5)


@pytest.fixture
def api_client(mock_api_server):
    client = SafeApiClient(base_url=mock_api_server, requests_per_second=20)
    yield client


@pytest.mark.asyncio
async def test_finds_undeclared_zombie_version(mock_api_server, api_client):
    config = ScanConfig(base_url=mock_api_server, confirm_authorized=True)
    module = InventoryTests(api_client, config)
    endpoints = [EndpointSpec(path="/api/v2/users", method="GET")]

    findings = await module.run(endpoints)
    await api_client.close()

    version_findings = [f for f in findings if f.evidence.get("probed_path") == "/api/v1/users"]
    assert version_findings, "expected inventory_tests to catch the live but undeclared /api/v1/users sibling"
    finding = version_findings[0]
    assert finding.severity == "MEDIUM"
    assert finding.owasp_category.startswith("API9:2023")


@pytest.mark.asyncio
async def test_finds_exposed_actuator_env(mock_api_server, api_client):
    config = ScanConfig(base_url=mock_api_server, confirm_authorized=True)
    module = InventoryTests(api_client, config)

    findings = await module.run([])
    await api_client.close()

    env_findings = [f for f in findings if f.endpoint == "/actuator/env"]
    assert env_findings, "expected inventory_tests to catch the exposed /actuator/env endpoint"
    assert env_findings[0].severity == "HIGH"


@pytest.mark.asyncio
async def test_finds_graphql_introspection(mock_api_server, api_client):
    config = ScanConfig(base_url=mock_api_server, confirm_authorized=True)
    module = InventoryTests(api_client, config)

    findings = await module.run([])
    await api_client.close()

    gql_findings = [f for f in findings if f.endpoint == "/graphql"]
    assert gql_findings, "expected inventory_tests to catch open GraphQL introspection"
    assert gql_findings[0].severity == "HIGH"
    assert gql_findings[0].evidence["type_count"] == 2


@pytest.mark.asyncio
async def test_declared_paths_are_never_flagged(mock_api_server, api_client):
    """Anything already in the imported spec — even a path that would
    otherwise match a discovery probe or a version-sibling check — must be
    skipped: it's known, intentional inventory, not a gap."""
    config = ScanConfig(base_url=mock_api_server, confirm_authorized=True)
    module = InventoryTests(api_client, config)
    endpoints = [
        EndpointSpec(path="/api/v1/users", method="GET"),
        EndpointSpec(path="/api/v2/users", method="GET"),
    ]

    findings = await module.run(endpoints)
    await api_client.close()

    version_findings = [f for f in findings if f.test_module == "inventory_tests" and "/api/v" in f.endpoint]
    assert version_findings == []
