"""
AegisLab - mock_vulnerable_api.py
====================================
A tiny, deliberately-vulnerable FastAPI app used ONLY to validate AegisLab
itself end-to-end and to produce the "example scan output" referenced in
the README. Do NOT deploy this anywhere reachable — it is wide open by
design so AegisLab's detectors have something real to find.

Run:  python mock_vulnerable_api.py   (serves on http://127.0.0.1:9000)
"""

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, HTMLResponse

app = FastAPI()

USERS_DB = {
    "1": {"id": "1", "email": "alice@example.com", "password_hash": "5f4dcc3b5aa765d61d8327deb882cf99", "role": "user", "__v": 3},
    "2": {"id": "2", "email": "bob@example.com", "password_hash": "098f6bcd4621d373cade4e832627b4f6", "role": "user", "__v": 1},
}


@app.middleware("http")
async def add_insecure_cors_and_fingerprint(request: Request, call_next):
    response = await call_next(request)
    # Intentionally bad CORS + fingerprinting headers for demo purposes
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Credentials"] = "true"
    response.headers["X-Powered-By"] = "Express/4.17.1"
    return response


@app.get("/users/{user_id}")
async def get_user(user_id: str):
    # VULNERABLE: no auth check, no ownership check (BOLA), leaks password_hash
    user = USERS_DB.get(user_id, {"id": user_id, "email": "unknown@example.com",
                                   "password_hash": "n/a", "role": "user", "__v": 0})
    return user


@app.post("/auth/login")
async def login(payload: dict):
    email = payload.get("email", "")
    # VULNERABLE: distinguishable error messages leak account existence
    if "nonexistent" in email or "aegislab_nonexistent" in email:
        return JSONResponse(status_code=404, content={"error": "User not found"})
    return JSONResponse(status_code=401, content={"error": "Incorrect password for this account"})


@app.get("/search")
async def search(q: str = ""):
    # VULNERABLE: reflected XSS (no escaping) + fake SQL error on a quote
    if "'" in q:
        return HTMLResponse(
            "<html><body>Error: you have an error in your sql syntax near '" + q + "'</body></html>",
            status_code=500,
        )
    return HTMLResponse(f"<html><body>Results for: {q}</body></html>")


@app.get("/admin/dashboard")
async def admin_dashboard():
    # VULNERABLE: no role check at all — any caller, even unauthenticated, can reach this
    return {"revenue": 184320, "active_users": 5021, "internal_notes": "Q3 churn target 4%"}


@app.post("/users")
async def create_user(payload: dict):
    # VULNERABLE: mass assignment — binds the raw request body directly onto
    # the stored record instead of allowlisting name/email only, so a client
    # can set "role" (or any other field) despite it never being part of the
    # documented signup form.
    new_id = str(len(USERS_DB) + 1)
    record = {"id": new_id, "role": "user"}  # default, but...
    record.update(payload)  # ...blindly overwritten by whatever the client sent
    USERS_DB[new_id] = record
    return record


@app.post("/fetch-avatar")
async def fetch_avatar(payload: dict):
    # VULNERABLE: SSRF — fetches whatever URL the client provides, server-side,
    # with no allowlist or private-range check at all.
    #
    # The 169.254.169.254 branch below simulates what a REAL server hosted on
    # AWS would leak if this bug existed there (the actual cloud metadata
    # service only responds to instances running inside that cloud, so a
    # canned response here keeps the demo deterministic on any machine).
    url = payload.get("avatar_url", "")
    if not url:
        return JSONResponse(status_code=400, content={"error": "avatar_url required"})
    if url.startswith("http://169.254.169.254"):
        return JSONResponse(status_code=200, content={
            "fetched_bytes": 812,
            "body_preview": "ami-id\ninstance-id\ninstance-action\niam/security-credentials/\nlocal-ipv4\npublic-keys/",
        })
    import httpx
    try:
        async with httpx.AsyncClient(timeout=3) as client:
            resp = await client.get(url)
        return JSONResponse(status_code=200, content={"fetched_bytes": len(resp.content), "body_preview": resp.text[:500]})
    except Exception as e:
        # Still leaks that an outbound request was attempted at all
        return JSONResponse(status_code=200, content={"fetched_bytes": 0, "error": str(e)})


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=9000)
