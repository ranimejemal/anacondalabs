"""
AegisLab - stripe_billing.py
=============================
Self-serve premium upgrades via Stripe Checkout (Sprint 3).

Design choices, and why:

- Raw httpx calls to Stripe's REST API, not the `stripe` Python SDK. This
  matches the rest of the backend (ai_remediation.py, supabase_auth.py both
  do the same for Anthropic/Supabase) rather than mixing conventions, and
  keeps requirements.txt from growing for a handful of endpoints.

- Checkout happens in the user's SYSTEM BROWSER (Electron shell.openExternal
  from main.js), never embedded in the Electron window. This is deliberate:
  embedding a card-entry form inside the app would pull AegisLab into PCI
  DSS SAQ A-EP/D scope. Redirecting to Stripe-hosted Checkout keeps it at
  SAQ A (the trivial tier) since card data never touches our code at all.

- The webhook is the ONLY source of truth for is_premium. The frontend
  never sets premium status directly, and the checkout redirect back into
  the app is treated as "maybe done, go check" — not as proof of payment.
  A user closing the browser tab early, or Stripe retrying a webhook, can't
  desync this: /api/me always reflects whatever Supabase currently has.

- Grace-period policy (Day 8): premium stays active until the subscription
  actually ends. Stripe only fires `customer.subscription.deleted` when
  that happens for real — whether the user cancelled immediately or it's a
  cancel-at-period-end that just reached its end date. So the ONLY event
  that revokes access is `customer.subscription.deleted`; a payment
  failure or a "will cancel at period end" flag is not, by itself, cause to
  cut the user off mid-cycle. Stripe's own retry schedule (Smart Retries)
  handles chasing failed payments before it ever gets to that point.
"""

from __future__ import annotations

import hmac
import hashlib
import os
import time

import httpx
from fastapi import HTTPException

STRIPE_SECRET_KEY = os.environ.get("STRIPE_SECRET_KEY", "")
STRIPE_PRICE_ID = os.environ.get("STRIPE_PRICE_ID", "")
STRIPE_WEBHOOK_SECRET = os.environ.get("STRIPE_WEBHOOK_SECRET", "")
# Where Stripe Checkout redirects back to after success/cancel. These are
# served by the local backend itself (see main.py's /billing/success and
# /billing/cancel routes) since the backend is already running on the
# user's own machine at this point — no public hosting needed.
BACKEND_PUBLIC_BASE = os.environ.get("AEGISLAB_BACKEND_BASE_URL", "http://127.0.0.1:8765")

STRIPE_API_BASE = "https://api.stripe.com/v1"

_CONFIGURED = bool(STRIPE_SECRET_KEY and STRIPE_PRICE_ID)


def _require_configured() -> None:
    if not _CONFIGURED:
        raise HTTPException(
            status_code=503,
            detail="Billing isn't configured on this install: set STRIPE_SECRET_KEY and STRIPE_PRICE_ID in backend/.env.",
        )


async def _stripe_post(path: str, form_data: dict) -> dict:
    """Stripe's API takes application/x-www-form-urlencoded, including for
    nested fields (line_items[0][price]=...). httpx's `data=` param handles
    flat dicts fine; nested list/dict values are pre-flattened by callers
    below into Stripe's bracket notation."""
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.post(
                f"{STRIPE_API_BASE}/{path}",
                data=form_data,
                auth=(STRIPE_SECRET_KEY, ""),  # HTTP Basic auth, password blank — Stripe's convention
            )
    except httpx.TimeoutException:
        raise HTTPException(status_code=504, detail="Stripe took too long to respond. Try again in a moment.")
    except httpx.RequestError as e:
        raise HTTPException(status_code=502, detail=f"Couldn't reach Stripe — check your internet connection. ({type(e).__name__})")

    if resp.status_code >= 400:
        try:
            err = resp.json().get("error", {}).get("message", resp.text[:300])
        except ValueError:
            err = resp.text[:300]
        raise HTTPException(status_code=502, detail=f"Stripe error: {err}")
    return resp.json()


async def create_checkout_session(user_id: str, email: str) -> str:
    """Creates a Stripe Checkout session for a subscription upgrade and
    returns the hosted checkout URL to open in the system browser."""
    _require_configured()
    data = await _stripe_post(
        "checkout/sessions",
        {
            "mode": "subscription",
            "line_items[0][price]": STRIPE_PRICE_ID,
            "line_items[0][quantity]": "1",
            "client_reference_id": user_id,
            "customer_email": email,
            "success_url": f"{BACKEND_PUBLIC_BASE}/billing/success",
            "cancel_url": f"{BACKEND_PUBLIC_BASE}/billing/cancel",
            # lets the webhook find the customer id even if the session
            # object itself isn't re-fetched
            "metadata[user_id]": user_id,
        },
    )
    return data["url"]


async def create_portal_session(stripe_customer_id: str) -> str:
    """Returns a Stripe-hosted billing portal URL so the user can update
    their card or cancel without AegisLab building any of that itself."""
    _require_configured()
    data = await _stripe_post(
        "billing_portal/sessions",
        {
            "customer": stripe_customer_id,
            "return_url": f"{BACKEND_PUBLIC_BASE}/billing/success",
        },
    )
    return data["url"]


def verify_webhook_signature(payload: bytes, sig_header: str, tolerance_seconds: int = 300) -> dict:
    """Verifies Stripe's webhook signature by hand (Stripe's documented
    scheme) rather than pulling in the SDK just for this. Raises 400 on any
    failure — malformed header, bad signature, or a timestamp outside the
    tolerance window (replay protection)."""
    if not STRIPE_WEBHOOK_SECRET:
        raise HTTPException(status_code=503, detail="Billing isn't configured: STRIPE_WEBHOOK_SECRET is missing.")
    if not sig_header:
        raise HTTPException(status_code=400, detail="Missing Stripe-Signature header.")

    parts = dict(kv.split("=", 1) for kv in sig_header.split(",") if "=" in kv)
    timestamp = parts.get("t")
    signature = parts.get("v1")
    if not timestamp or not signature:
        raise HTTPException(status_code=400, detail="Malformed Stripe-Signature header.")

    if abs(time.time() - int(timestamp)) > tolerance_seconds:
        raise HTTPException(status_code=400, detail="Webhook timestamp outside tolerance — possible replay.")

    signed_payload = f"{timestamp}.{payload.decode('utf-8')}"
    expected = hmac.new(STRIPE_WEBHOOK_SECRET.encode(), signed_payload.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, signature):
        raise HTTPException(status_code=400, detail="Webhook signature verification failed.")

    import json
    return json.loads(payload)
