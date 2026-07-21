import asyncio
import json
import httpx
import websockets

BACKEND = "http://127.0.0.1:8765"


async def main():
    async with httpx.AsyncClient() as client:
        config = {
            "base_url": "http://127.0.0.1:9000",
            "bearer_token": "fake.test.token",
            "confirm_authorized": True,
            "requests_per_second": 15,
            "endpoints": [
                {"path": "/users/{id}", "method": "GET", "requires_auth": True},
                {"path": "/auth/login", "method": "POST", "requires_auth": False,
                 "request_body_sample": {"email": "test@example.com", "password": "x"}},
                {"path": "/search", "method": "GET", "requires_auth": False, "params": ["q"]},
                {"path": "/admin/dashboard", "method": "GET", "requires_auth": True, "tags": ["admin"]},
            ],
        }

        resp = await client.post(f"{BACKEND}/api/scan/start", json={"config": config})
        resp.raise_for_status()
        scan_id = resp.json()["scan_id"]
        print("scan_id:", scan_id)

        async with websockets.connect(f"ws://127.0.0.1:8765/ws/scan/{scan_id}") as ws:
            while True:
                msg = json.loads(await ws.recv())
                if msg.get("status") == "finished":
                    result = msg["result"]
                    print(f"\nFINAL — score={result['security_score']} findings={len(result['vulnerabilities'])}")
                    break
                print(f"  [{msg['status']:9}] {msg['module']:25} {msg.get('message','')}")

        # test report-path endpoint
        r2 = await client.get(f"{BACKEND}/api/scan/{scan_id}/report-path", params={"format": "json"})
        print("\nreport-path (json):", r2.json())
        r3 = await client.get(f"{BACKEND}/api/scan/{scan_id}/report-path", params={"format": "pdf"})
        print("report-path (pdf):", r3.json())

        # test direct download endpoint
        r4 = await client.get(f"{BACKEND}/api/scan/{scan_id}/report", params={"format": "json"})
        print("\ndirect download status:", r4.status_code, "bytes:", len(r4.content))

asyncio.run(main())
