"""
AegisLab - main.py
====================
FastAPI backend that the Electron frontend talks to over localhost.

Endpoints:
  POST   /api/openapi/parse      -> parse an uploaded OpenAPI/Swagger file into endpoints
  POST   /api/scan/start         -> start a new scan (returns scan_id immediately)
  GET    /api/scan/{id}          -> poll current status/result (fallback if WS unavailable)
  WS     /ws/scan/{id}           -> real-time progress stream
  GET    /api/scan/{id}/report   -> download JSON or PDF report
  GET    /api/health             -> liveness check for the Electron splash screen

Run with:  uvicorn main:app --host 127.0.0.1 --port 8765
"""

from __future__ import annotations

import asyncio
import time
import uuid
from pathlib import Path

from dotenv import load_dotenv
load_dotenv(Path(__file__).resolve().parent / ".env")  # backend/.env, see .env.example

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, UploadFile, File, Depends, Request, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, HTMLResponse
from pydantic import BaseModel

from models import ScanConfig, ScanResult, EndpointSpec
from openapi_parser import load_spec, parse_openapi
from scanner import run_scan, AuthorizationRequiredError
from report_generator import export_json, export_pdf
from scoring import compute_score
from static_scanner import scan_zip, ZipRejectedError
from supabase_auth import (
    get_current_user,
    get_current_premium_user,
    AuthedUser,
    set_premium_status,
    find_user_id_by_stripe_customer,
    get_stripe_customer_id,
)
import ai_remediation
import stripe_billing
import github_integration
import re
import zipfile
import shutil
import logging
import traceback
import uuid
from logging.handlers import RotatingFileHandler

# ---------------------------------------------------------------------------
# Crash / error logging (Sprint 5 Day 7)
# ---------------------------------------------------------------------------
# Separate from main.js's raw stdout/stderr capture of the whole process —
# this is a structured, timestamped, rotating app log specifically for
# unhandled exceptions during request handling, so "the app crashed" reports
# come with an actual traceback instead of just "something went wrong."
LOG_DIR = Path(__file__).resolve().parent.parent / "logs"
LOG_DIR.mkdir(exist_ok=True)

logger = logging.getLogger("aegislab")
logger.setLevel(logging.INFO)
_file_handler = RotatingFileHandler(LOG_DIR / "backend_app.log", maxBytes=2_000_000, backupCount=3)
_file_handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
logger.addHandler(_file_handler)

app = FastAPI(title="AegisLab Security Engine", version="1.0.0")

# The Electron renderer loads from file:// (Origin: "null" in Chromium) or,
# in dev, http://localhost — allow only those, NOT "*". This backend binds
# to 127.0.0.1 only, but that alone doesn't stop a malicious page open in
# the user's REAL browser from using JS fetch() against it — an
# Access-Control-Allow-Origin: * response is readable cross-origin by any
# website, which would let an attacker's page silently drive scans (or,
# now that GitHub import/AI endpoints exist, exchange OAuth codes or read
# scan results) through the user's own already-running AegisLab instance.
# Restricting to the app's actual origins closes that off while changing
# nothing for the real Electron app.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["null"],
    allow_origin_regex=r"^https?://(localhost|127\.0\.0\.1)(:\d+)?$",
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    """Any exception that isn't already a handled HTTPException lands here.
    Logs the full traceback server-side with a short reference id, but
    returns only that id to the client — never leaks internals (file paths,
    library versions, etc.) into an API response."""
    error_id = uuid.uuid4().hex[:8]
    logger.error(
        "Unhandled exception [%s] on %s %s\n%s",
        error_id, request.method, request.url.path, traceback.format_exc(),
    )
    return JSONResponse(
        status_code=500,
        content={"detail": f"Something went wrong on AegisLab's side (reference: {error_id}). Check logs/backend_app.log for details."},
    )


REPORTS_DIR = Path(__file__).resolve().parent.parent / "reports_output"
REPORTS_DIR.mkdir(exist_ok=True)

# In-memory scan store. Fine for a single-user desktop app; swap for sqlite
# if you need scan history to survive an app restart.
_scans: dict[str, dict] = {}


class ScanStartRequest(BaseModel):
    config: ScanConfig


class OpenApiParseRequest(BaseModel):
    raw_text: str


@app.get("/api/health")
async def health():
    return {"status": "ok", "service": "AegisLab Security Engine"}


@app.post("/api/openapi/parse")
async def parse_openapi_endpoint(payload: OpenApiParseRequest):
    try:
        spec = load_spec(payload.raw_text)
        endpoints = parse_openapi(spec)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Could not parse spec: {e}")
    return {"endpoint_count": len(endpoints), "endpoints": [e.model_dump() for e in endpoints]}


@app.post("/api/openapi/upload")
async def upload_openapi(file: UploadFile = File(...)):
    try:
        raw = (await file.read()).decode("utf-8")
        spec = load_spec(raw)
        endpoints = parse_openapi(spec)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Could not parse uploaded spec: {e}")
    return {"endpoint_count": len(endpoints), "endpoints": [e.model_dump() for e in endpoints]}


@app.post("/api/scan/start")
async def start_scan(req: ScanStartRequest):
    if not req.config.confirm_authorized:
        raise HTTPException(
            status_code=403,
            detail="You must confirm you own or are authorized to test this API before scanning.",
        )
    if not req.config.endpoints:
        raise HTTPException(status_code=400, detail="No endpoints to test — import an OpenAPI spec or add endpoints manually.")

    scan_id = str(uuid.uuid4())
    queue: asyncio.Queue = asyncio.Queue()
    _scans[scan_id] = {"queue": queue, "result": None, "status": "running"}

    async def runner():
        try:
            async for item in run_scan(scan_id, req.config):
                if isinstance(item, ScanResult):
                    _scans[scan_id]["result"] = item
                    _scans[scan_id]["status"] = item.status
                else:
                    await queue.put(item.model_dump())
        except AuthorizationRequiredError as e:
            _scans[scan_id]["status"] = "failed"
            await queue.put({"status": "error", "message": str(e), "percent": 0,
                              "module": "scanner", "scan_id": scan_id, "findings_so_far": 0})
        finally:
            await queue.put(None)  # sentinel: stream is done

    asyncio.create_task(runner())
    return {"scan_id": scan_id}


@app.get("/api/scan/{scan_id}")
async def get_scan(scan_id: str):
    entry = _scans.get(scan_id)
    if not entry:
        raise HTTPException(status_code=404, detail="Unknown scan_id")
    result: ScanResult | None = entry["result"]
    return {
        "status": entry["status"],
        "result": result.model_dump() if result else None,
    }


@app.websocket("/ws/scan/{scan_id}")
async def scan_progress_ws(websocket: WebSocket, scan_id: str):
    await websocket.accept()
    entry = _scans.get(scan_id)
    if not entry:
        await websocket.send_json({"status": "error", "message": "Unknown scan_id"})
        await websocket.close()
        return

    queue: asyncio.Queue = entry["queue"]
    try:
        while True:
            item = await queue.get()
            if item is None:
                result: ScanResult | None = entry["result"]
                await websocket.send_json({
                    "status": "finished",
                    "result": result.model_dump() if result else None,
                })
                break
            await websocket.send_json(item)
    except WebSocketDisconnect:
        pass
    finally:
        try:
            await websocket.close()
        except Exception:
            pass


@app.get("/api/scan/{scan_id}/report")
async def get_report(scan_id: str, format: str = "json"):
    entry = _scans.get(scan_id)
    if not entry or not entry["result"]:
        raise HTTPException(status_code=404, detail="Scan not found or not yet complete")

    result: ScanResult = entry["result"]
    timestamp = int(time.time())

    if format == "json":
        path = REPORTS_DIR / f"aegislab_report_{scan_id[:8]}_{timestamp}.json"
        export_json(result, path)
        return FileResponse(path, media_type="application/json", filename=path.name)
    elif format == "pdf":
        path = REPORTS_DIR / f"aegislab_report_{scan_id[:8]}_{timestamp}.pdf"
        export_pdf(result, path)
        return FileResponse(path, media_type="application/pdf", filename=path.name)
    else:
        raise HTTPException(status_code=400, detail="format must be 'json' or 'pdf'")


@app.get("/api/scan/{scan_id}/report-path")
async def get_report_path(scan_id: str, format: str = "json"):
    """
    Generates the report on disk and returns its absolute path + filename,
    so the Electron main process can drive a native 'Save As' dialog without
    shuttling large binary blobs back through HTTP/CSP.
    """
    entry = _scans.get(scan_id)
    if not entry or not entry["result"]:
        raise HTTPException(status_code=404, detail="Scan not found or not yet complete")

    result: ScanResult = entry["result"]
    timestamp = int(time.time())

    if format == "json":
        path = REPORTS_DIR / f"aegislab_report_{scan_id[:8]}_{timestamp}.json"
        export_json(result, path)
    elif format == "pdf":
        path = REPORTS_DIR / f"aegislab_report_{scan_id[:8]}_{timestamp}.pdf"
        export_pdf(result, path)
    else:
        raise HTTPException(status_code=400, detail="format must be 'json' or 'pdf'")

    return {"path": str(path.resolve()), "filename": path.name}


UPLOADS_DIR = Path(__file__).resolve().parent.parent / "uploads_tmp"
UPLOADS_DIR.mkdir(exist_ok=True)

MAX_UPLOAD_BYTES = 200 * 1024 * 1024  # matches static_scanner.extractor's cap

# In-memory store for static scan results, keyed by scan_id — same pattern as _scans.
_static_scans: dict[str, ScanResult] = {}
# Keeps the ORIGINAL uploaded source zip on disk per scan_id (instead of
# deleting it immediately) so premium AI auto-fix can later read the actual
# file content and write back a patched copy. Cleared on backend restart —
# fine for a single-user desktop app; swap for a TTL-based cleanup job if
# this is ever deployed multi-tenant.
_static_scan_zips: dict[str, Path] = {}


def _run_static_scan_and_store(upload_path: Path, source_label: str) -> dict:
    """Shared tail end of both static-scan entry points (a direct .zip
    upload, and a GitHub repo import): runs the SAST scanner, scores it,
    stores the ScanResult + the on-disk zip (for later AI auto-fix), and
    returns the exact response shape the frontend renders either way."""
    try:
        scan_output = scan_zip(str(upload_path))
    except ZipRejectedError as e:
        upload_path.unlink(missing_ok=True)
        raise HTTPException(status_code=400, detail=str(e))

    scan_id = str(uuid.uuid4())
    score, breakdown = compute_score(scan_output["findings"])
    result = ScanResult(
        scan_id=scan_id,
        base_url=source_label,
        started_at=time.time(),
        finished_at=time.time(),
        status="completed",
        vulnerabilities=scan_output["findings"],
        security_score=score,
        score_breakdown=breakdown,
        endpoints_tested=scan_output["files_scanned"],
        modules_run=["static_secret_scan"] + [f"static_{f}_config" for f in scan_output["frameworks_detected"] if f in ("express", "nestjs")],
    )
    _static_scans[scan_id] = result
    _static_scan_zips[scan_id] = upload_path  # kept on disk for AI auto-fix

    return {
        "scan_id": scan_id,
        "frameworks_detected": scan_output["frameworks_detected"],
        "files_scanned": scan_output["files_scanned"],
        "result": result.model_dump(),
    }


@app.post("/api/static-scan/upload")
async def static_scan_upload(file: UploadFile = File(...)):
    """
    Accepts a .zip of a developer's source tree and runs the static (SAST)
    scanner against it: secret/credential leakage detection + framework-
    specific config checks (Express/NestJS). Never executes anything from
    the uploaded archive — every file is read as plain text only.
    """
    if not file.filename.lower().endswith(".zip"):
        raise HTTPException(status_code=400, detail="Please upload a .zip archive of your source code.")

    upload_path = UPLOADS_DIR / f"{uuid.uuid4()}.zip"
    size = 0
    with open(upload_path, "wb") as out:
        while chunk := await file.read(1024 * 1024):
            size += len(chunk)
            if size > MAX_UPLOAD_BYTES:
                upload_path.unlink(missing_ok=True)
                raise HTTPException(status_code=413, detail="Archive exceeds the 200MB upload limit.")
            out.write(chunk)

    return _run_static_scan_and_store(upload_path, f"(static scan: {file.filename})")


class GithubExchangeRequest(BaseModel):
    code: str
    state: str


class GithubImportRequest(BaseModel):
    access_token: str
    owner: str
    repo: str
    ref: str | None = None


@app.get("/api/github/oauth/authorize-url")
async def github_authorize_url():
    """Returns the full GitHub OAuth consent URL (with a fresh CSRF state)
    for the Electron main process to open in the system browser."""
    return {"url": github_integration.build_authorize_url()}


@app.post("/api/github/oauth/exchange")
async def github_oauth_exchange(req: GithubExchangeRequest):
    """Exchanges the authorization code GitHub redirected back with (via
    the aegislab:// deep link) for an access token. GITHUB_CLIENT_SECRET
    never leaves this process — the Electron app only ever sees the
    resulting access_token."""
    return await github_integration.exchange_code_for_token(req.code, req.state)


@app.get("/api/github/repos")
async def github_repos(x_github_token: str = Header(..., alias="X-GitHub-Token")):
    return {"repos": await github_integration.list_user_repos(x_github_token)}


@app.post("/api/github/import")
async def github_import(req: GithubImportRequest):
    """Downloads the given repo (or ref) from GitHub as a zip and runs it
    through the exact same static-scan pipeline as /api/static-scan/upload
    (see _run_static_scan_and_store), so the frontend renders the result
    with no separate code path."""
    zip_bytes = await github_integration.download_repo_zip(req.access_token, req.owner, req.repo, req.ref)
    upload_path = UPLOADS_DIR / f"{uuid.uuid4()}.zip"
    upload_path.write_bytes(zip_bytes)
    label = f"(GitHub import: {req.owner}/{req.repo}{'@' + req.ref if req.ref else ''})"
    return _run_static_scan_and_store(upload_path, label)


@app.get("/api/static-scan/{scan_id}/report-path")
async def static_scan_report_path(scan_id: str, format: str = "json"):
    result = _static_scans.get(scan_id)
    if not result:
        raise HTTPException(status_code=404, detail="Unknown static scan_id")

    timestamp = int(time.time())
    if format == "json":
        path = REPORTS_DIR / f"aegislab_static_report_{scan_id[:8]}_{timestamp}.json"
        export_json(result, path)
    elif format == "pdf":
        path = REPORTS_DIR / f"aegislab_static_report_{scan_id[:8]}_{timestamp}.pdf"
        export_pdf(result, path)
    else:
        raise HTTPException(status_code=400, detail="format must be 'json' or 'pdf'")

    return {"path": str(path.resolve()), "filename": path.name}


# ---------------------------------------------------------------------------
# Authentication + AI remediation (Supabase + Anthropic)
# ---------------------------------------------------------------------------

class FindingPayload(BaseModel):
    issue: str
    severity: str
    endpoint: str = ""
    method: str = "GET"
    recommendation: str = ""


class AutoFixRequest(BaseModel):
    scan_id: str
    finding: FindingPayload


def _extract_filename_from_endpoint(endpoint: str) -> str | None:
    """Static findings encode the source file either as a bare relative path
    ('src/app.js') or, for route-level findings, as 'METHOD /path (file.js:12)'.
    Pulls a usable relative filename out of either shape."""
    m = re.search(r"\(([^()]+?):\d+\)", endpoint)
    if m:
        return m.group(1)
    if endpoint and not endpoint.startswith("(") and " " not in endpoint and "." in endpoint:
        return endpoint
    return None


def _rewrite_zip_entry(zip_path: Path, target_name: str, new_content: str) -> None:
    """Rewrites exactly one entry's content inside zip_path in place. The
    zipfile module can't edit an entry directly, so this writes a fresh
    archive and swaps it in — shared by the single-finding and bulk
    auto-fix endpoints below."""
    tmp_path = zip_path.with_suffix(".tmp.zip")
    with zipfile.ZipFile(zip_path, "r") as zin, zipfile.ZipFile(tmp_path, "w", zipfile.ZIP_DEFLATED) as zout:
        for item in zin.infolist():
            data = new_content.encode("utf-8") if item.filename == target_name else zin.read(item.filename)
            zout.writestr(item, data)
    tmp_path.replace(zip_path)


@app.get("/api/me")
async def get_me(user: AuthedUser = Depends(get_current_user)):
    """Lets the frontend show 'Signed in as ... (Premium)' and decide which
    AI button (manual suggestion vs auto-apply) to render."""
    return {"id": user.id, "email": user.email, "is_premium": user.is_premium}


# ---------------------------------------------------------------------------
# Billing (Sprint 3) — Stripe Checkout happens in the system browser, never
# embedded in the Electron window (see stripe_billing.py's module docstring
# for why). The webhook is the only thing that ever flips is_premium.
# ---------------------------------------------------------------------------

@app.post("/api/billing/checkout")
async def billing_checkout(user: AuthedUser = Depends(get_current_user)):
    """Returns a Stripe Checkout URL for the signed-in user to upgrade.
    The frontend opens this via shell.openExternal, not an in-app webview."""
    if user.is_premium:
        raise HTTPException(status_code=400, detail="This account is already premium.")
    url = await stripe_billing.create_checkout_session(user.id, user.email or "")
    return {"url": url}


@app.post("/api/billing/portal")
async def billing_portal(user: AuthedUser = Depends(get_current_user)):
    """Returns a Stripe customer portal URL so the user can update their
    card or cancel — no custom billing UI needed on our side."""
    customer_id = await get_stripe_customer_id(user.id)
    if not customer_id:
        raise HTTPException(status_code=400, detail="No billing account found yet — upgrade to premium first.")
    url = await stripe_billing.create_portal_session(customer_id)
    return {"url": url}


@app.post("/api/billing/webhook")
async def billing_webhook(request: Request):
    """Stripe calls this directly (not the Electron app), so there's no
    Supabase auth here — trust comes entirely from the verified signature."""
    payload = await request.body()
    sig_header = request.headers.get("stripe-signature", "")
    event = stripe_billing.verify_webhook_signature(payload, sig_header)

    event_type = event.get("type", "")
    obj = event.get("data", {}).get("object", {})

    if event_type == "checkout.session.completed":
        user_id = obj.get("client_reference_id") or (obj.get("metadata") or {}).get("user_id")
        if user_id:
            await set_premium_status(
                user_id,
                is_premium=True,
                stripe_customer_id=obj.get("customer"),
                stripe_subscription_id=obj.get("subscription"),
            )

    elif event_type == "customer.subscription.deleted":
        # The one and only event that revokes access — see stripe_billing.py
        # for why payment failures / cancel-at-period-end don't trigger this.
        customer_id = obj.get("customer")
        user_id = await find_user_id_by_stripe_customer(customer_id) if customer_id else None
        if user_id:
            await set_premium_status(user_id, is_premium=False)

    # Other event types (invoice.payment_failed, subscription.updated with
    # cancel_at_period_end=true, etc.) are intentionally no-ops: Stripe's
    # own retry/grace-period handling covers them, and premium stays active
    # until subscription.deleted actually fires.

    return {"received": True}


@app.get("/billing/success", response_class=HTMLResponse)
async def billing_success():
    return _billing_redirect_page(
        "Payment received 🎉",
        "You can close this tab and return to AegisLab — your account will update automatically within a few seconds.",
    )


@app.get("/billing/cancel", response_class=HTMLResponse)
async def billing_cancel():
    return _billing_redirect_page(
        "Checkout cancelled",
        "No charge was made. You can close this tab and return to AegisLab any time to try again.",
    )


def _billing_redirect_page(title: str, message: str) -> str:
    return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>AegisLab</title>
<style>
  body {{ font-family: -apple-system, system-ui, sans-serif; background:#0f0f12; color:#eee;
         display:flex; align-items:center; justify-content:center; height:100vh; margin:0; }}
  .card {{ text-align:center; max-width:420px; padding:32px; }}
  h1 {{ font-size:20px; margin-bottom:12px; }}
  p {{ color:#aaa; line-height:1.5; }}
</style></head>
<body><div class="card"><h1>{title}</h1><p>{message}</p></div></body></html>"""


@app.post("/api/ai/suggest")
async def ai_suggest(finding: FindingPayload, user: AuthedUser = Depends(get_current_user)):
    """Free + premium: a real Claude-generated fix as copy/paste text. The
    user applies it to their own codebase manually; nothing is written here."""
    ai_remediation.check_rate_limit(user.id, "suggest", ai_remediation.SUGGEST_DAILY_LIMIT)
    return await ai_remediation.generate_suggestion(finding.model_dump())


@app.post("/api/ai/auto-fix")
async def ai_auto_fix(req: AutoFixRequest, user: AuthedUser = Depends(get_current_premium_user)):
    """Premium only: locates the relevant file inside the user's originally
    uploaded source zip, asks Claude for the corrected file content, and
    returns a patched copy of the zip ready to download."""
    ai_remediation.check_rate_limit(user.id, "auto_fix", ai_remediation.AUTOFIX_DAILY_LIMIT)
    zip_path = _static_scan_zips.get(req.scan_id)
    if not zip_path or not zip_path.exists():
        raise HTTPException(
            status_code=404,
            detail="The original uploaded source for this scan is no longer available — re-run the static scan and try again.",
        )

    filename = _extract_filename_from_endpoint(req.finding.endpoint)
    if not filename:
        raise HTTPException(
            status_code=400,
            detail="This finding isn't tied to one specific file (it's project-wide), so it can't be auto-patched. Use the manual AI suggestion instead.",
        )

    with zipfile.ZipFile(zip_path, "r") as zf:
        names = zf.namelist()
        matches = [n for n in names if n == filename or n.endswith("/" + filename)]
        if not matches:
            raise HTTPException(status_code=404, detail=f"Could not find '{filename}' inside the uploaded archive.")
        target_name = matches[0]
        try:
            original_content = zf.read(target_name).decode("utf-8")
        except UnicodeDecodeError:
            raise HTTPException(status_code=400, detail="That file isn't plain text — automatic patching only supports source files.")

    patched_content = await ai_remediation.generate_file_patch(
        req.finding.model_dump(), filename, original_content
    )

    timestamp = int(time.time())
    out_path = REPORTS_DIR / f"aegislab_autofix_{req.scan_id[:8]}_{timestamp}.zip"
    shutil.copyfile(zip_path, out_path)
    _rewrite_zip_entry(out_path, target_name, patched_content)

    return {
        "path": str(out_path.resolve()),
        "filename": out_path.name,
        "patched_file": filename,
        "ai_explanation": f"Patched {filename} for: {req.finding.issue}",
    }


class FixAllRequest(BaseModel):
    scan_id: str


@app.post("/api/ai/fix-all")
async def ai_fix_all(req: FixAllRequest, user: AuthedUser = Depends(get_current_user)):
    """Bulk version of the two endpoints above: walks EVERY finding in the
    given scan (not just the Top 5 Priority Fixes panel), and for each one
    either applies a full file patch (premium, static scans, when the
    finding maps to one resolvable source file) or falls back to a text
    suggestion (free tier, live/DAST scans, or a finding with no single
    file to patch) — same underlying Anthropic calls as the per-finding
    buttons, just looped, and still metered by the existing daily rate
    limits rather than bypassing them for a batch: once the cap is hit,
    remaining findings are reported as skipped instead of silently
    dropped or erroring the whole batch out.
    """
    result = _static_scans.get(req.scan_id)
    is_static = result is not None
    if result is None:
        entry = _scans.get(req.scan_id)
        result = entry["result"] if entry else None
    if result is None:
        raise HTTPException(status_code=404, detail="Unknown scan_id, or the live scan hasn't finished yet.")

    findings = result.vulnerabilities
    if not findings:
        return {"fixed": [], "skipped_rate_limited": 0, "output_zip": None}

    zip_path = _static_scan_zips.get(req.scan_id) if is_static else None
    can_patch = bool(is_static and zip_path and zip_path.exists() and user.is_premium)

    out_path = None
    zin_names: list[str] = []
    patched_names: set[str] = set()
    if can_patch:
        timestamp = int(time.time())
        out_path = REPORTS_DIR / f"aegislab_fixall_{req.scan_id[:8]}_{timestamp}.zip"
        shutil.copyfile(zip_path, out_path)
        with zipfile.ZipFile(out_path, "r") as zin:
            zin_names = zin.namelist()

    fixed: list[dict] = []
    skipped_rate_limited = 0

    for finding in findings:
        filename = _extract_filename_from_endpoint(finding.endpoint) if can_patch else None
        target_name = None
        if filename:
            matches = [n for n in zin_names if n == filename or n.endswith("/" + filename)]
            target_name = matches[0] if matches else None
        already_patched = target_name is not None and target_name in patched_names
        will_patch = target_name is not None and not already_patched

        kind_limit = "auto_fix" if will_patch else "suggest"
        limit = ai_remediation.AUTOFIX_DAILY_LIMIT if will_patch else ai_remediation.SUGGEST_DAILY_LIMIT
        try:
            ai_remediation.check_rate_limit(user.id, kind_limit, limit)
        except HTTPException:
            skipped_rate_limited += 1
            continue

        finding_dict = finding.to_report_dict()
        try:
            if will_patch:
                with zipfile.ZipFile(out_path, "r") as zcur:
                    original_content = zcur.read(target_name).decode("utf-8")
                patched_content = await ai_remediation.generate_file_patch(finding_dict, filename, original_content)
                _rewrite_zip_entry(out_path, target_name, patched_content)
                patched_names.add(target_name)
                fixed.append({"id": finding.id, "issue": finding.issue, "kind": "patch", "file": filename})
            else:
                suggestion = await ai_remediation.generate_suggestion(finding_dict)
                fixed.append({
                    "id": finding.id, "issue": finding.issue, "kind": "suggestion",
                    "ai_suggestion": suggestion["ai_suggestion"],
                    "already_patched_this_file": already_patched,
                })
        except HTTPException as e:
            fixed.append({"id": finding.id, "issue": finding.issue, "kind": "error", "error": e.detail})

    return {
        "fixed": fixed,
        "skipped_rate_limited": skipped_rate_limited,
        "output_zip": {"path": str(out_path.resolve()), "filename": out_path.name} if (out_path and patched_names) else None,
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="127.0.0.1", port=8765, reload=False)
