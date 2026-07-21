"""
AegisLab - ai_remediation.py
==============================
Real AI-generated fixes via the Anthropic API, layered on top of (not
replacing) the static remediation.js rule set on the frontend. Two modes:

  generate_suggestion()  -> free-tier-eligible. Returns an explanation +
                             code suggestion as TEXT. Nothing is written
                             to disk. The user copy/pastes it themselves.

  generate_file_patch()  -> premium-only. Given the user's actual uploaded
                             source file, asks Claude to return the FULL
                             corrected file content, which the caller then
                             writes back into a patched copy of their zip.

Required environment variable: ANTHROPIC_API_KEY (see backend/.env.example)
"""

from __future__ import annotations

import os
import time
from collections import defaultdict
from datetime import datetime, timezone

import httpx
from fastapi import HTTPException

ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "")
ANTHROPIC_MODEL = os.environ.get("ANTHROPIC_MODEL", "claude-sonnet-4-6")
ANTHROPIC_URL = "https://api.anthropic.com/v1/messages"


# ---------------------------------------------------------------------------
# Rate limiting
# ---------------------------------------------------------------------------
# AegisLab's backend is a single local process per install (not a shared
# multi-tenant server), so a simple in-memory per-user daily counter is the
# right amount of complexity here — it resets if the backend restarts, which
# is fine: the threat model is "a single account can't run unbounded
# Anthropic spend during normal use," not defending a shared production API.
#
# Limits are per calendar day (UTC) and per user id, separately for the two
# AI endpoints since auto-fix is far more expensive (whole-file, 4000 tokens)
# than a text suggestion (1200 tokens).
SUGGEST_DAILY_LIMIT = int(os.environ.get("AI_SUGGEST_DAILY_LIMIT", "40"))
AUTOFIX_DAILY_LIMIT = int(os.environ.get("AI_AUTOFIX_DAILY_LIMIT", "15"))

# user_id -> {"suggest": (date_str, count), "auto_fix": (date_str, count)}
_usage: dict[str, dict[str, tuple[str, int]]] = defaultdict(dict)


def _today() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def check_rate_limit(user_id: str, kind: str, limit: int) -> None:
    """Raises 429 if this user has hit their daily cap for this endpoint kind.
    Otherwise increments the counter. Call this AFTER auth has already
    resolved the user, so an invalid/expired token can't consume quota."""
    today = _today()
    date_str, count = _usage[user_id].get(kind, (today, 0))
    if date_str != today:
        date_str, count = today, 0
    if count >= limit:
        raise HTTPException(
            status_code=429,
            detail=(
                f"Daily AI limit reached ({limit} requests for this feature today). "
                "Resets at midnight UTC. This cap protects your account from unexpected "
                "API costs if a token is ever leaked or reused."
            ),
        )
    _usage[user_id][kind] = (date_str, count + 1)


def _require_configured():
    if not ANTHROPIC_API_KEY:
        raise HTTPException(
            status_code=503,
            detail="AI suggestions aren't configured on this install. Set ANTHROPIC_API_KEY (see backend/.env.example) and restart the backend.",
        )


async def _call_claude(system: str, user_msg: str, max_tokens: int = 1200) -> str:
    _require_configured()
    try:
        async with httpx.AsyncClient(timeout=60) as client:
            resp = await client.post(
                ANTHROPIC_URL,
                headers={
                    "x-api-key": ANTHROPIC_API_KEY,
                    "anthropic-version": "2023-06-01",
                    "content-type": "application/json",
                },
                json={
                    "model": ANTHROPIC_MODEL,
                    "max_tokens": max_tokens,
                    "system": system,
                    "messages": [{"role": "user", "content": user_msg}],
                },
            )
    except httpx.TimeoutException:
        raise HTTPException(
            status_code=504,
            detail="The AI request timed out after 60s. Anthropic's API may be slow right now — try again in a moment.",
        )
    except httpx.RequestError as e:
        # DNS failure, connection refused, no network, etc.
        raise HTTPException(
            status_code=502,
            detail=f"Couldn't reach the AI service — check your internet connection and try again. ({type(e).__name__})",
        )

    if resp.status_code == 401:
        raise HTTPException(
            status_code=503,
            detail="AI suggestions are misconfigured on this install: ANTHROPIC_API_KEY was rejected as invalid. Check backend/.env.",
        )
    if resp.status_code == 429:
        raise HTTPException(
            status_code=429,
            detail="Anthropic's API rate limit was hit for this account. Wait a minute and try again.",
        )
    if resp.status_code >= 500:
        raise HTTPException(
            status_code=502,
            detail="Anthropic's API is temporarily unavailable. Try again shortly.",
        )
    if resp.status_code != 200:
        raise HTTPException(status_code=502, detail=f"AI request failed: {resp.text[:300]}")

    try:
        data = resp.json()
        parts = [b["text"] for b in data.get("content", []) if b.get("type") == "text"]
    except (ValueError, KeyError, TypeError):
        raise HTTPException(status_code=502, detail="AI service returned an unexpected response format. Try again.")

    text = "\n".join(parts).strip()
    if not text:
        raise HTTPException(status_code=502, detail="AI service returned an empty response. Try again.")
    return text


SUGGEST_SYSTEM = (
    "You are a senior application security engineer. Given one vulnerability "
    "finding from an API security scanner, explain the risk in 1-2 sentences "
    "and then give a concrete, minimal code fix the developer can paste into "
    "their own codebase. Always wrap the fix in a fenced code block with a "
    "language tag. Be specific to the framework if it's mentioned or "
    "inferable from the finding; otherwise default to plain Express/Node.js. "
    "Do not pad your answer with disclaimers or generic security advice."
)


async def generate_suggestion(finding: dict) -> dict:
    """Free + premium tier: text-only AI suggestion, nothing written to disk."""
    user_msg = (
        f"Finding: {finding.get('issue')}\n"
        f"Severity: {finding.get('severity')}\n"
        f"Endpoint: {finding.get('method', 'GET')} {finding.get('endpoint', '')}\n"
        f"Scanner's generic recommendation: {finding.get('recommendation', '')}\n\n"
        "Give me the specific fix."
    )
    text = await _call_claude(SUGGEST_SYSTEM, user_msg)
    return {"finding": finding.get("issue"), "ai_suggestion": text}


PATCH_SYSTEM = (
    "You are a senior application security engineer doing an automated code "
    "fix. You will be given one vulnerability finding and the full contents "
    "of the source file responsible. Return ONLY the complete corrected file "
    "content, with the minimal change needed to fix the specific finding — "
    "preserve everything else in the file exactly as-is (formatting, unrelated "
    "code, comments). Do not wrap your answer in a code fence, do not add "
    "commentary before or after — output must be the raw file content only, "
    "ready to be written straight to disk."
)


async def generate_file_patch(finding: dict, filename: str, file_content: str) -> str:
    """Premium tier only: returns the full corrected file content."""
    if len(file_content) > 60_000:
        raise HTTPException(status_code=413, detail="That source file is too large for automatic AI patching (60KB limit). Use the manual AI suggestion instead.")

    user_msg = (
        f"Finding: {finding.get('issue')}\n"
        f"Severity: {finding.get('severity')}\n"
        f"Scanner's generic recommendation: {finding.get('recommendation', '')}\n\n"
        f"File: {filename}\n"
        "----- FILE CONTENT START -----\n"
        f"{file_content}\n"
        "----- FILE CONTENT END -----\n"
    )
    return await _call_claude(PATCH_SYSTEM, user_msg, max_tokens=4000)
