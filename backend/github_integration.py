"""
AegisLab - github_integration.py
===================================
GitHub "Connect account" OAuth flow (Authorization Code flow, desktop-app
variant): lets a user link their GitHub account so they can pick a
repository to import instead of manually uploading a .zip.

Required environment variables (see backend/.env.example):
  GITHUB_CLIENT_ID           - from a GitHub OAuth App you register yourself
                                (github.com/settings/developers -> New OAuth
                                App). Not secret by itself.
  GITHUB_CLIENT_SECRET       - secret, server-side only, never leaves this
                                process (never sent to the Electron renderer
                                or written to any frontend file).
  GITHUB_OAUTH_REDIRECT_URI  - defaults to aegislab://oauth/callback, the
                                custom protocol the Electron app registers
                                (see frontend/main.js) to receive the
                                redirect from GitHub's consent screen.

Nothing here executes or imports anything from a picked repo — it's
downloaded as a zip archive and handed to the SAME static-scanner pipeline
that already safely handles an arbitrary user-uploaded zip (zip-slip /
zip-bomb protected, every file read as plain text only — see
static_scanner/extractor.py), never treated as trusted code.
"""

from __future__ import annotations

import os
import secrets
import time

import httpx
from fastapi import HTTPException

GITHUB_CLIENT_ID = os.environ.get("GITHUB_CLIENT_ID", "")
GITHUB_CLIENT_SECRET = os.environ.get("GITHUB_CLIENT_SECRET", "")
GITHUB_OAUTH_REDIRECT_URI = os.environ.get("GITHUB_OAUTH_REDIRECT_URI", "aegislab://oauth/callback")
GITHUB_SCOPE = "repo read:user"

AUTHORIZE_URL = "https://github.com/login/oauth/authorize"
TOKEN_URL = "https://github.com/login/oauth/access_token"
API_BASE = "https://api.github.com"

# In-memory CSRF state store: state -> issued_at. AegisLab's backend is a
# single-user desktop process (same assumption ai_remediation.py's rate
# limiter makes), so this doesn't need to survive a restart — an
# unknown/expired state is simply rejected and the user re-clicks
# "Connect GitHub" to get a fresh one.
_STATE_TTL_SECONDS = 600
_pending_states: dict[str, float] = {}


def _require_configured():
    if not GITHUB_CLIENT_ID or not GITHUB_CLIENT_SECRET:
        raise HTTPException(
            status_code=503,
            detail=(
                "GitHub integration isn't configured on this install. Set GITHUB_CLIENT_ID and "
                "GITHUB_CLIENT_SECRET (see backend/.env.example) and restart the backend."
            ),
        )


def _prune_expired_states() -> None:
    cutoff = time.time() - _STATE_TTL_SECONDS
    for s in [s for s, ts in _pending_states.items() if ts < cutoff]:
        _pending_states.pop(s, None)


def _consume_state(state: str) -> None:
    _prune_expired_states()
    if not state or _pending_states.pop(state, None) is None:
        raise HTTPException(
            status_code=400,
            detail="This GitHub sign-in link has expired or was already used. Click 'Connect GitHub' again.",
        )


def build_authorize_url() -> str:
    """Issues a fresh CSRF state and returns the full GitHub authorize URL
    to open in the system browser."""
    _require_configured()
    _prune_expired_states()
    state = secrets.token_urlsafe(24)
    _pending_states[state] = time.time()
    query = httpx.QueryParams({
        "client_id": GITHUB_CLIENT_ID,
        "redirect_uri": GITHUB_OAUTH_REDIRECT_URI,
        "scope": GITHUB_SCOPE,
        "state": state,
        "allow_signup": "false",
    })
    return f"{AUTHORIZE_URL}?{query}"


async def exchange_code_for_token(code: str, state: str) -> dict:
    """Returns {access_token, login, avatar_url}. Consumes (and validates)
    the CSRF state issued by build_authorize_url — raises 400 if it's
    missing, unknown, or already used."""
    _require_configured()
    _consume_state(state)

    try:
        async with httpx.AsyncClient(timeout=20) as client:
            resp = await client.post(
                TOKEN_URL,
                headers={"Accept": "application/json"},
                data={
                    "client_id": GITHUB_CLIENT_ID,
                    "client_secret": GITHUB_CLIENT_SECRET,
                    "code": code,
                    "redirect_uri": GITHUB_OAUTH_REDIRECT_URI,
                },
            )
    except httpx.TimeoutException:
        raise HTTPException(status_code=504, detail="GitHub's OAuth token endpoint timed out. Try again.")
    except httpx.RequestError as e:
        raise HTTPException(status_code=502, detail=f"Couldn't reach GitHub — check your connection. ({type(e).__name__})")

    if resp.status_code != 200:
        raise HTTPException(status_code=502, detail=f"GitHub token exchange failed: {resp.text[:300]}")

    data = resp.json()
    if "error" in data:
        raise HTTPException(
            status_code=400,
            detail=f"GitHub rejected the sign-in: {data.get('error_description', data['error'])}",
        )
    access_token = data.get("access_token")
    if not access_token:
        raise HTTPException(status_code=502, detail="GitHub's token response was missing an access token.")

    user = await _get(access_token, "/user")
    return {"access_token": access_token, "login": user.get("login"), "avatar_url": user.get("avatar_url")}


async def _get(access_token: str, path: str, params: dict | None = None) -> dict:
    try:
        async with httpx.AsyncClient(timeout=20) as client:
            resp = await client.get(
                f"{API_BASE}{path}",
                headers=_api_headers(access_token),
                params=params,
            )
    except httpx.TimeoutException:
        raise HTTPException(status_code=504, detail="GitHub API request timed out. Try again.")
    except httpx.RequestError as e:
        raise HTTPException(status_code=502, detail=f"Couldn't reach GitHub — check your connection. ({type(e).__name__})")
    return _handle_api_response(resp)


def _api_headers(access_token: str) -> dict:
    return {
        "Authorization": f"Bearer {access_token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }


def _handle_api_response(resp: httpx.Response) -> dict:
    if resp.status_code == 401:
        raise HTTPException(status_code=401, detail="Your GitHub connection has expired or been revoked. Reconnect from the sidebar.")
    if resp.status_code == 403 and "rate limit" in resp.text.lower():
        raise HTTPException(status_code=429, detail="GitHub API rate limit hit. Wait a bit and try again.")
    if resp.status_code >= 400:
        raise HTTPException(status_code=502, detail=f"GitHub API request failed: {resp.text[:300]}")
    return resp.json()


MAX_REPOS = 300


async def list_user_repos(access_token: str) -> list[dict]:
    """Repos the user owns or collaborates on, most-recently-updated first,
    trimmed to the fields the repo picker actually needs."""
    repos: list[dict] = []
    page = 1
    async with httpx.AsyncClient(timeout=20) as client:
        while len(repos) < MAX_REPOS:
            try:
                resp = await client.get(
                    f"{API_BASE}/user/repos",
                    headers=_api_headers(access_token),
                    params={"per_page": 100, "page": page, "sort": "updated", "affiliation": "owner,collaborator"},
                )
            except httpx.TimeoutException:
                raise HTTPException(status_code=504, detail="GitHub API request timed out. Try again.")
            except httpx.RequestError as e:
                raise HTTPException(status_code=502, detail=f"Couldn't reach GitHub — check your connection. ({type(e).__name__})")

            batch = _handle_api_response(resp)
            if not isinstance(batch, list) or not batch:
                break
            repos.extend(batch)
            if len(batch) < 100:
                break
            page += 1

    return [
        {
            "full_name": r["full_name"],
            "private": r.get("private", False),
            "default_branch": r.get("default_branch", "main"),
            "description": r.get("description") or "",
            "updated_at": r.get("updated_at"),
        }
        for r in repos[:MAX_REPOS]
    ]


MAX_REPO_ZIP_BYTES = 200 * 1024 * 1024  # matches static_scanner's own upload cap


async def download_repo_zip(access_token: str, owner: str, repo: str, ref: str | None = None) -> bytes:
    """Downloads a repo (a specific ref, or its default branch) as a zip via
    GitHub's archive endpoint — works for private repos too, since the
    token is sent as a normal Bearer credential. The returned bytes are
    handed to the existing static-scan zip pipeline unchanged."""
    path = f"/repos/{owner}/{repo}/zipball" + (f"/{ref}" if ref else "")
    try:
        async with httpx.AsyncClient(timeout=60, follow_redirects=True) as client:
            resp = await client.get(f"{API_BASE}{path}", headers=_api_headers(access_token))
    except httpx.TimeoutException:
        raise HTTPException(status_code=504, detail="Downloading the repository from GitHub timed out. Try again.")
    except httpx.RequestError as e:
        raise HTTPException(status_code=502, detail=f"Couldn't reach GitHub — check your connection. ({type(e).__name__})")

    if resp.status_code == 404:
        ref_suffix = f"@{ref}" if ref else ""
        raise HTTPException(status_code=404, detail=f"Repository or ref not found: {owner}/{repo}{ref_suffix}")
    if resp.status_code == 401:
        raise HTTPException(status_code=401, detail="Your GitHub connection has expired or been revoked. Reconnect from the sidebar.")
    if resp.status_code >= 400:
        raise HTTPException(status_code=502, detail=f"Downloading the repository from GitHub failed: {resp.text[:300]}")
    if len(resp.content) > MAX_REPO_ZIP_BYTES:
        raise HTTPException(status_code=413, detail="Repository archive exceeds the 200MB scan limit.")
    return resp.content
