"""
AegisLab - supabase_auth.py
=============================
Server-side verification of Supabase-issued access tokens, and a premium
entitlement check. Deliberately does NOT trust anything the frontend claims
about the user (e.g. "I'm premium") — every check round-trips to Supabase.

Required environment variables (see .env.example):
  SUPABASE_URL                 e.g. https://xxxxx.supabase.co
  SUPABASE_ANON_KEY             public anon key (used to validate user tokens)
  SUPABASE_SERVICE_ROLE_KEY     secret service-role key (server-side only,
                                 NEVER ship this to the Electron frontend)

Expected Supabase schema (run once in the Supabase SQL editor):

  create table public.profiles (
    id uuid references auth.users on delete cascade primary key,
    is_premium boolean not null default false,
    created_at timestamptz not null default now()
  );

  -- auto-create a free-tier profile row whenever a new user signs up
  create or replace function public.handle_new_user()
  returns trigger as $$
  begin
    insert into public.profiles (id, is_premium) values (new.id, false);
    return new;
  end;
  $$ language plpgsql security definer;

  create trigger on_auth_user_created
    after insert on auth.users
    for each row execute procedure public.handle_new_user();

  alter table public.profiles enable row level security;
  create policy "Users can read their own profile"
    on public.profiles for select using (auth.uid() = id);

To make a user premium (e.g. after a Stripe webhook fires), from your
backend/admin tooling run, using the service role key:
  update public.profiles set is_premium = true where id = '<user-uuid>';
"""

from __future__ import annotations

import os
from dataclasses import dataclass

import httpx
from fastapi import Header, HTTPException

SUPABASE_URL = os.environ.get("SUPABASE_URL", "").rstrip("/")
SUPABASE_ANON_KEY = os.environ.get("SUPABASE_ANON_KEY", "")
SUPABASE_SERVICE_ROLE_KEY = os.environ.get("SUPABASE_SERVICE_ROLE_KEY", "")

# See get_current_user()'s docstring below for what this does and how to
# reverse it. Defaults to false (normal paid gating) if unset.
PREMIUM_FREE_FOR_ALL = os.environ.get("AEGISLAB_PREMIUM_FREE_FOR_ALL", "false").lower() == "true"

_SUPABASE_CONFIGURED = bool(SUPABASE_URL and SUPABASE_ANON_KEY and SUPABASE_SERVICE_ROLE_KEY)


@dataclass
class AuthedUser:
    id: str
    email: str | None
    is_premium: bool


def _require_configured():
    if not _SUPABASE_CONFIGURED:
        raise HTTPException(
            status_code=503,
            detail=(
                "AI features aren't configured on this install. "
                "Set SUPABASE_URL, SUPABASE_ANON_KEY, and SUPABASE_SERVICE_ROLE_KEY "
                "(see backend/.env.example) and restart the backend."
            ),
        )


async def _fetch_supabase_user(access_token: str) -> dict:
    """Validates the token by asking Supabase Auth who it belongs to.
    A forged or expired token simply gets rejected by Supabase itself."""
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(
                f"{SUPABASE_URL}/auth/v1/user",
                headers={
                    "Authorization": f"Bearer {access_token}",
                    "apikey": SUPABASE_ANON_KEY,
                },
            )
    except httpx.TimeoutException:
        raise HTTPException(status_code=504, detail="Sign-in check timed out — Supabase may be slow right now. Try again.")
    except httpx.RequestError:
        raise HTTPException(status_code=502, detail="Couldn't reach the sign-in service — check your internet connection.")
    if resp.status_code != 200:
        raise HTTPException(status_code=401, detail="Invalid or expired session — please sign in again.")
    return resp.json()


async def _fetch_is_premium(user_id: str) -> bool:
    """Looks up the profiles row using the SERVICE ROLE key (server-side
    only) so a client can never spoof their own premium flag. Fails closed
    (treats the user as non-premium) on any lookup problem, network issue
    included — never grants premium as a side effect of an error."""
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(
                f"{SUPABASE_URL}/rest/v1/profiles",
                params={"id": f"eq.{user_id}", "select": "is_premium"},
                headers={
                    "Authorization": f"Bearer {SUPABASE_SERVICE_ROLE_KEY}",
                    "apikey": SUPABASE_SERVICE_ROLE_KEY,
                },
            )
    except httpx.RequestError:
        return False
    if resp.status_code != 200:
        return False
    rows = resp.json()
    return bool(rows and rows[0].get("is_premium"))


async def get_current_user(authorization: str | None = Header(default=None)) -> AuthedUser:
    """FastAPI dependency: requires ANY authenticated Supabase user (free or
    premium). Use this for endpoints like /api/ai/suggest."""
    _require_configured()
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Sign in required for AI suggestions.")
    token = authorization.split(" ", 1)[1].strip()

    user = await _fetch_supabase_user(token)
    # PREMIUM_FREE_FOR_ALL (Sprint 3 launch decision): premium is temporarily
    # free for every signed-in user while pricing isn't finalized. This is
    # the single point is_premium gets resolved, so it stays consistent
    # everywhere — the /api/me badge, the auto-fix gate, all of it — without
    # touching the Stripe integration itself (checkout/webhook/portal code
    # is untouched and ready to go the moment this flag flips back to
    # false). To start charging again: set AEGISLAB_PREMIUM_FREE_FOR_ALL=false
    # (or unset it) in backend/.env and restart.
    if PREMIUM_FREE_FOR_ALL:
        is_premium = True
    else:
        is_premium = await _fetch_is_premium(user["id"])
    return AuthedUser(id=user["id"], email=user.get("email"), is_premium=is_premium)


async def get_current_premium_user(authorization: str | None = Header(default=None)) -> AuthedUser:
    """FastAPI dependency: requires an authenticated user AND is_premium=true.
    Use this for endpoints like /api/ai/auto-fix."""
    user = await get_current_user(authorization)
    if not user.is_premium:
        raise HTTPException(
            status_code=402,
            detail="Auto-apply fixes is a premium feature. Free accounts get AI suggestions as copy/paste text.",
        )
    return user


# ---------------------------------------------------------------------------
# Service-role writes for the Stripe webhook (backend/stripe_billing.py).
# These are the ONLY place is_premium is ever set — never trust a client
# request to flip its own flag, only a verified Stripe webhook event.
# ---------------------------------------------------------------------------

async def _patch_profile(user_id: str, fields: dict) -> None:
    _require_configured()
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.patch(
                f"{SUPABASE_URL}/rest/v1/profiles",
                params={"id": f"eq.{user_id}"},
                headers={
                    "Authorization": f"Bearer {SUPABASE_SERVICE_ROLE_KEY}",
                    "apikey": SUPABASE_SERVICE_ROLE_KEY,
                    "Content-Type": "application/json",
                    "Prefer": "return=minimal",
                },
                json=fields,
            )
    except httpx.RequestError as e:
        raise HTTPException(status_code=502, detail=f"Couldn't reach Supabase to update the account. ({type(e).__name__})")
    if resp.status_code >= 300:
        raise HTTPException(status_code=502, detail=f"Supabase rejected the profile update: {resp.text[:300]}")


async def set_premium_status(user_id: str, is_premium: bool, stripe_customer_id: str | None = None, stripe_subscription_id: str | None = None) -> None:
    fields: dict = {"is_premium": is_premium}
    if stripe_customer_id is not None:
        fields["stripe_customer_id"] = stripe_customer_id
    if stripe_subscription_id is not None:
        fields["stripe_subscription_id"] = stripe_subscription_id
    await _patch_profile(user_id, fields)


async def find_user_id_by_stripe_customer(stripe_customer_id: str) -> str | None:
    """Used when a webhook event only carries a Stripe customer id (e.g.
    customer.subscription.deleted), not our own user_id metadata."""
    _require_configured()
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(
                f"{SUPABASE_URL}/rest/v1/profiles",
                params={"stripe_customer_id": f"eq.{stripe_customer_id}", "select": "id"},
                headers={
                    "Authorization": f"Bearer {SUPABASE_SERVICE_ROLE_KEY}",
                    "apikey": SUPABASE_SERVICE_ROLE_KEY,
                },
            )
    except httpx.RequestError:
        return None
    if resp.status_code != 200:
        return None
    rows = resp.json()
    return rows[0]["id"] if rows else None


async def get_stripe_customer_id(user_id: str) -> str | None:
    """Used by /api/billing/portal to find which Stripe customer to open
    the portal session for."""
    _require_configured()
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(
                f"{SUPABASE_URL}/rest/v1/profiles",
                params={"id": f"eq.{user_id}", "select": "stripe_customer_id"},
                headers={
                    "Authorization": f"Bearer {SUPABASE_SERVICE_ROLE_KEY}",
                    "apikey": SUPABASE_SERVICE_ROLE_KEY,
                },
            )
    except httpx.RequestError:
        return None
    if resp.status_code != 200:
        return None
    rows = resp.json()
    return rows[0].get("stripe_customer_id") if rows else None
